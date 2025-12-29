// SPDX-License-Identifier: GPL-2.0

//! ALU instruction verification
//!
//! This module implements comprehensive verification of BPF ALU and ALU64 instructions,
//! including MOV, arithmetic operations, bitwise operations, and shifts.
//!
//! Corresponds to check_alu_op() in Linux kernel verifier.c (lines 15744-16200)

use alloc::format;

use crate::bounds::tnum::Tnum;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Address space cast offset value
pub const BPF_ADDR_SPACE_CAST: i16 = 1;

/// DEF_NOT_SUBREG marker - indicates a 64-bit definition
pub const DEF_NOT_SUBREG: u32 = 0;

/// Check ALU operation (BPF_ALU or BPF_ALU64 class)
///
/// This is the main entry point for ALU instruction verification.
/// It handles:
/// - BPF_END (byte swap)
/// - BPF_NEG (negation)
/// - BPF_MOV (register/immediate move)
/// - All other ALU operations (ADD, SUB, MUL, DIV, etc.)
pub fn check_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let class = insn.class();
    let opcode = insn.code & 0xf0;
    let _src_type = insn.code & 0x08; // BPF_K or BPF_X
    let is_64bit = class == BPF_ALU64;

    let dst_reg = insn.dst_reg as usize;
    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(dst_reg as u8));
    }

    match opcode {
        BPF_END | BPF_NEG => check_end_neg_op(state, insn, insn_idx, is_64bit),
        BPF_MOV => check_mov_op(state, insn, insn_idx, is_64bit, allow_ptr_leaks),
        op if op > BPF_END => Err(VerifierError::InvalidInstruction(insn_idx)),
        _ => check_arithmetic_op(state, insn, insn_idx, is_64bit, allow_ptr_leaks),
    }?;

    // Final bounds sanity check
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?;
    reg_bounds_sanity_check(dst, "alu")
}

/// Check BPF_END (byte swap) and BPF_NEG (negation) operations
fn check_end_neg_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    is_64bit: bool,
) -> Result<()> {
    let opcode = insn.code & 0xf0;
    let dst_reg = insn.dst_reg as usize;

    // Validate reserved fields
    if opcode == BPF_NEG {
        // NEG: src must be K, src_reg=0, off=0, imm=0
        if (insn.code & 0x08) != BPF_K || insn.src_reg != 0 || insn.off != 0 || insn.imm != 0 {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
    } else {
        // END (byte swap): src_reg=0, off=0, imm must be 16/32/64
        if insn.src_reg != 0
            || insn.off != 0
            || !matches!(insn.imm, 16 | 32 | 64)
            || (is_64bit && (insn.code & 0x08) != BPF_TO_LE)
        {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
    }

    // Check source operand (dst is used as source for these ops)
    check_reg_arg(state, dst_reg, true)?;

    // Pointer arithmetic not allowed
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?;
    if dst.is_pointer() {
        return Err(VerifierError::InvalidPointerArithmetic(format!(
            "R{} pointer arithmetic prohibited",
            dst_reg
        )));
    }

    // Handle the operation
    if opcode == BPF_NEG {
        if dst.reg_type == BpfRegType::ScalarValue {
            // For scalar, compute negation bounds
            adjust_neg_bounds(state, dst_reg, is_64bit)?;
        } else {
            // For non-scalar, mark as unknown
            mark_reg_unknown(state, dst_reg, is_64bit);
        }
    } else {
        // BPF_END - byte swap, result is unknown within the swap size
        let swap_bits = insn.imm as u32;
        let max_val = if swap_bits == 64 {
            u64::MAX
        } else {
            (1u64 << swap_bits) - 1
        };

        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.reg_type = BpfRegType::ScalarValue;
            dst.var_off = Tnum::unknown();
            dst.umin_value = 0;
            dst.umax_value = max_val;
            dst.smin_value = 0;
            dst.smax_value = max_val as i64;
            if !is_64bit {
                dst.subreg_def = insn_idx as u32 + 1;
            }
        }
    }

    Ok(())
}

/// Check BPF_MOV operation (register or immediate move)
fn check_mov_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    is_64bit: bool,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    if src_type == BPF_X {
        // Register move: validate reserved fields
        if is_64bit {
            if insn.off == BPF_ADDR_SPACE_CAST {
                // Address space cast - special handling
                if insn.imm != 1 && insn.imm != (1 << 16) {
                    return Err(VerifierError::InvalidInstruction(insn_idx));
                }
                // Would check for arena here
            } else if insn.off != 0 && insn.off != 8 && insn.off != 16 && insn.off != 32 {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }
            if insn.imm != 0 && insn.off != BPF_ADDR_SPACE_CAST {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }
        } else {
            // ALU (32-bit): off must be 0, 8, or 16; imm must be 0
            if (insn.off != 0 && insn.off != 8 && insn.off != 16) || insn.imm != 0 {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }
        }

        // Check source register
        check_reg_arg(state, src_reg, true)?;
        check_reg_arg(state, dst_reg, false)?;

        // Get source state
        let src_state = state
            .reg(src_reg)
            .ok_or(VerifierError::Internal("no src register".into()))?
            .clone();

        if is_64bit {
            if insn.off == BPF_ADDR_SPACE_CAST && insn.imm != 0 {
                // Address space cast
                mark_reg_unknown(state, dst_reg, true);
                if insn.imm == 1 {
                    // Cast from as(1) to as(0) - result is PTR_TO_ARENA
                    if let Some(dst) = state.reg_mut(dst_reg) {
                        dst.reg_type = BpfRegType::PtrToArena;
                        dst.subreg_def = insn_idx as u32 + 1;
                    }
                }
            } else if insn.off == 0 {
                // Simple 64-bit move: R1 = R2
                copy_register_state(state, dst_reg, &src_state)?;
                if let Some(dst) = state.reg_mut(dst_reg) {
                    dst.subreg_def = DEF_NOT_SUBREG;
                }
            } else {
                // Sign-extend move: R1 = (s8/s16/s32)R2
                if src_state.is_pointer() {
                    return Err(VerifierError::InvalidPointerArithmetic(format!(
                        "R{} sign-extension part of pointer",
                        src_reg
                    )));
                }
                if src_state.reg_type == BpfRegType::ScalarValue {
                    let sign_bits = insn.off as u32;
                    let no_sext = src_state.umax_value < (1u64 << (sign_bits - 1));

                    copy_register_state(state, dst_reg, &src_state)?;
                    if !no_sext {
                        if let Some(dst) = state.reg_mut(dst_reg) {
                            dst.id = 0;
                        }
                    }
                    coerce_reg_to_size_sx(state, dst_reg, (sign_bits / 8) as usize)?;
                    if let Some(dst) = state.reg_mut(dst_reg) {
                        dst.subreg_def = DEF_NOT_SUBREG;
                    }
                } else {
                    mark_reg_unknown(state, dst_reg, true);
                }
            }
        } else {
            // 32-bit move: R1 = (u32)R2
            if src_state.is_pointer() {
                if !allow_ptr_leaks {
                    return Err(VerifierError::InvalidPointerArithmetic(format!(
                        "R{} partial copy of pointer",
                        src_reg
                    )));
                }
                mark_reg_unknown(state, dst_reg, false);
            } else if src_state.reg_type == BpfRegType::ScalarValue {
                if insn.off == 0 {
                    // Simple 32-bit move
                    let is_src_u32 = get_reg_width(&src_state) <= 32;
                    copy_register_state(state, dst_reg, &src_state)?;
                    if !is_src_u32 {
                        if let Some(dst) = state.reg_mut(dst_reg) {
                            dst.id = 0;
                        }
                    }
                    if let Some(dst) = state.reg_mut(dst_reg) {
                        dst.subreg_def = insn_idx as u32 + 1;
                    }
                } else {
                    // Sign-extend 32-bit: W1 = (s8/s16)W2
                    let sign_bits = insn.off as u32;
                    let no_sext = src_state.umax_value < (1u64 << (sign_bits - 1));

                    copy_register_state(state, dst_reg, &src_state)?;
                    if !no_sext {
                        if let Some(dst) = state.reg_mut(dst_reg) {
                            dst.id = 0;
                        }
                    }
                    if let Some(dst) = state.reg_mut(dst_reg) {
                        dst.subreg_def = insn_idx as u32 + 1;
                    }
                    coerce_subreg_to_size_sx(state, dst_reg, (sign_bits / 8) as usize)?;
                }
                // Zero-extend to 64-bit
                zext_32_to_64(state, dst_reg)?;
            } else {
                mark_reg_unknown(state, dst_reg, false);
                zext_32_to_64(state, dst_reg)?;
            }
        }
    } else {
        // Immediate move: R = imm
        if insn.src_reg != 0 || insn.off != 0 {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }

        check_reg_arg(state, dst_reg, false)?;

        // Set destination to the immediate value
        mark_reg_unknown(state, dst_reg, is_64bit);
        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.reg_type = BpfRegType::ScalarValue;
            if is_64bit {
                dst.mark_known(insn.imm as i64 as u64);
            } else {
                dst.mark_known(insn.imm as u32 as u64);
                dst.subreg_def = insn_idx as u32 + 1;
            }
        }
    }

    Ok(())
}

/// Check arithmetic ALU operations (ADD, SUB, MUL, DIV, etc.)
fn check_arithmetic_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    is_64bit: bool,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let opcode = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Validate reserved fields
    if src_type == BPF_X {
        // For signed div/mod, off can be 1
        let off_ok = insn.off == 0 || (insn.off == 1 && matches!(opcode, BPF_DIV | BPF_MOD));
        if insn.imm != 0 || !off_ok {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
        check_reg_arg(state, src_reg, true)?;
    } else {
        if insn.src_reg != 0 {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
        let off_ok = insn.off == 0 || (insn.off == 1 && matches!(opcode, BPF_DIV | BPF_MOD));
        if !off_ok {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
    }

    // Check destination register as source (it's read and written)
    check_reg_arg(state, dst_reg, true)?;

    // Check for division by zero (immediate case)
    if matches!(opcode, BPF_DIV | BPF_MOD) && src_type == BPF_K && insn.imm == 0 {
        return Err(VerifierError::DivisionByZero);
    }

    // Check shift amount validity (immediate case)
    if matches!(opcode, BPF_LSH | BPF_RSH | BPF_ARSH) && src_type == BPF_K {
        let size = if is_64bit { 64 } else { 32 };
        if insn.imm < 0 || insn.imm >= size {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }
    }

    // Get destination state
    let dst_state = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?
        .clone();

    // Handle pointer arithmetic
    if dst_state.is_pointer() {
        return adjust_ptr_min_max_vals(state, insn, insn_idx, &dst_state, allow_ptr_leaks);
    }

    // Handle scalar arithmetic
    adjust_reg_min_max_vals(state, insn, insn_idx, is_64bit)
}

/// Adjust bounds for pointer arithmetic (ADD/SUB only)
///
/// This implements the kernel's adjust_ptr_min_max_vals() which handles
/// pointer arithmetic with proper bounds tracking.
fn adjust_ptr_min_max_vals(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    _insn_idx: usize,
    dst_state: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let opcode = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Only ADD and SUB allowed on pointers
    if !matches!(opcode, BPF_ADD | BPF_SUB) {
        if !allow_ptr_leaks {
            return Err(VerifierError::InvalidPointerArithmetic(
                "only ADD and SUB allowed on pointers".into(),
            ));
        }
        mark_reg_unknown(state, dst_reg, true);
        return Ok(());
    }

    // Get the scalar operand
    let (scalar_state, ptr_is_dst) = if src_type == BPF_X {
        let src_state = state
            .reg(src_reg)
            .ok_or(VerifierError::Internal("no src register".into()))?
            .clone();

        if src_state.is_pointer() {
            // ptr - ptr = scalar (pointer difference)
            if opcode == BPF_SUB {
                return handle_ptr_sub_ptr(state, dst_reg, dst_state, &src_state, allow_ptr_leaks);
            }
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot add pointer to pointer".into(),
            ));
        }
        (src_state, true)
    } else {
        let mut imm_state = BpfRegState::new_scalar_unknown(false);
        imm_state.mark_known(insn.imm as i64 as u64);
        (imm_state, true)
    };

    // Check scalar is valid for pointer arithmetic
    if scalar_state.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::InvalidPointerArithmetic(
            "scalar operand expected".into(),
        ));
    }

    // Check for forbidden pointer types
    check_ptr_arith_allowed(dst_state, allow_ptr_leaks)?;

    // Get the pointer and scalar bounds
    let ptr_reg = dst_state;
    let off_reg = &scalar_state;

    // Check for potential overflow/underflow
    let bounds = OffsetBounds {
        smin_ptr: ptr_reg.smin_value,
        smax_ptr: ptr_reg.smax_value,
        smin_off: off_reg.smin_value,
        smax_off: off_reg.smax_value,
        umin_off: off_reg.umin_value,
        umax_off: off_reg.umax_value,
    };

    // Compute new bounds
    let (new_smin, new_smax, new_umin, new_umax, new_off, new_var_off) = if opcode == BPF_ADD {
        compute_ptr_add_bounds(ptr_reg, off_reg, &bounds)
    } else {
        compute_ptr_sub_bounds(ptr_reg, off_reg, &bounds, ptr_is_dst)
    };

    // Update destination register
    if let Some(dst) = state.reg_mut(dst_reg) {
        *dst = ptr_reg.clone();

        dst.off = new_off;
        dst.var_off = new_var_off;
        dst.smin_value = new_smin;
        dst.smax_value = new_smax;
        dst.umin_value = new_umin;
        dst.umax_value = new_umax;

        // Sync 32-bit bounds
        dst.u32_min_value = new_umin as u32;
        dst.u32_max_value = new_umax.min(u32::MAX as u64) as u32;
        dst.s32_min_value = new_smin.max(i32::MIN as i64) as i32;
        dst.s32_max_value = new_smax.min(i32::MAX as i64) as i32;

        // Clear ID since bounds changed
        dst.id = 0;

        // Validate the resulting pointer
        validate_ptr_bounds(dst)?;
    }

    Ok(())
}

/// Handle pointer - pointer subtraction
fn handle_ptr_sub_ptr(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    dst_state: &BpfRegState,
    src_state: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    // Both pointers must be of the same type
    if dst_state.reg_type != src_state.reg_type && !allow_ptr_leaks {
        return Err(VerifierError::InvalidPointerArithmetic(
            "pointer subtraction requires same pointer types".into(),
        ));
    }

    // For packet pointers, they should have the same base
    if matches!(
        dst_state.reg_type,
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta
    ) && dst_state.id != src_state.id
        && dst_state.id != 0
        && src_state.id != 0
    {
        return Err(VerifierError::InvalidPointerArithmetic(
            "packet pointer subtraction requires same packet".into(),
        ));
    }

    // Result is a scalar (the difference)
    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.reg_type = BpfRegType::ScalarValue;
        dst.type_flags = BpfTypeFlag::empty();

        // If both have constant offsets, compute exactly
        if dst_state.var_off.is_const() && src_state.var_off.is_const() {
            let diff = (dst_state.off as i64 + dst_state.var_off.value as i64)
                - (src_state.off as i64 + src_state.var_off.value as i64);
            dst.mark_known(diff as u64);
        } else {
            // Variable offsets - compute bounds
            let dst_min = dst_state.smin_value + dst_state.off as i64;
            let dst_max = dst_state.smax_value + dst_state.off as i64;
            let src_min = src_state.smin_value + src_state.off as i64;
            let src_max = src_state.smax_value + src_state.off as i64;

            dst.smin_value = dst_min.saturating_sub(src_max);
            dst.smax_value = dst_max.saturating_sub(src_min);
            dst.umin_value = 0; // Can't determine unsigned bounds for difference
            dst.umax_value = u64::MAX;
            dst.var_off = Tnum::unknown();
            dst.off = 0;
        }
    }

    Ok(())
}

/// Check if pointer arithmetic is allowed for this pointer type
fn check_ptr_arith_allowed(ptr_reg: &BpfRegState, allow_ptr_leaks: bool) -> Result<()> {
    match ptr_reg.reg_type {
        BpfRegType::PtrToCtx => {
            // Context pointers cannot have variable offsets
            if !ptr_reg.var_off.is_const() {
                return Err(VerifierError::InvalidPointerArithmetic(
                    "variable offset on context pointer".into(),
                ));
            }
        }
        BpfRegType::PtrToPacketEnd => {
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot do arithmetic on packet_end pointer".into(),
            ));
        }
        BpfRegType::ConstPtrToMap => {
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot do arithmetic on map pointer".into(),
            ));
        }
        BpfRegType::PtrToFlowKeys => {
            if !allow_ptr_leaks {
                return Err(VerifierError::InvalidPointerArithmetic(
                    "cannot do arithmetic on flow keys pointer".into(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Offset bounds for pointer arithmetic
struct OffsetBounds {
    smin_ptr: i64,
    smax_ptr: i64,
    smin_off: i64,
    smax_off: i64,
    umin_off: u64,
    umax_off: u64,
}

/// Compute bounds for pointer + scalar
fn compute_ptr_add_bounds(
    ptr_reg: &BpfRegState,
    off_reg: &BpfRegState,
    bounds: &OffsetBounds,
) -> (i64, i64, u64, u64, i32, Tnum) {
    // Check for constant offset
    if off_reg.is_const() {
        let off = off_reg.const_value() as i64;
        let new_off = ptr_reg.off.saturating_add(off as i32);
        return (
            bounds.smin_ptr,
            bounds.smax_ptr,
            ptr_reg.umin_value,
            ptr_reg.umax_value,
            new_off,
            ptr_reg.var_off,
        );
    }

    // Variable offset - update var_off and bounds
    let new_var_off = ptr_reg.var_off.add(off_reg.var_off);

    // Check for overflow in signed addition
    let (new_smin, smin_of) = bounds.smin_ptr.overflowing_add(bounds.smin_off);
    let (new_smax, smax_of) = bounds.smax_ptr.overflowing_add(bounds.smax_off);

    let (new_smin, new_smax) = if smin_of || smax_of {
        (i64::MIN, i64::MAX)
    } else {
        (new_smin, new_smax)
    };

    // Unsigned bounds
    let (new_umin, umin_of) = ptr_reg.umin_value.overflowing_add(bounds.umin_off);
    let (new_umax, umax_of) = ptr_reg.umax_value.overflowing_add(bounds.umax_off);

    let (new_umin, new_umax) = if umin_of || umax_of {
        (0, u64::MAX)
    } else {
        (new_umin, new_umax)
    };

    (
        new_smin,
        new_smax,
        new_umin,
        new_umax,
        ptr_reg.off,
        new_var_off,
    )
}

/// Compute bounds for pointer - scalar
fn compute_ptr_sub_bounds(
    ptr_reg: &BpfRegState,
    off_reg: &BpfRegState,
    bounds: &OffsetBounds,
    ptr_is_dst: bool,
) -> (i64, i64, u64, u64, i32, Tnum) {
    if !ptr_is_dst {
        // scalar - ptr is not allowed, handled earlier
        return (i64::MIN, i64::MAX, 0, u64::MAX, 0, Tnum::unknown());
    }

    // Check for constant offset
    if off_reg.is_const() {
        let off = off_reg.const_value() as i64;
        let new_off = ptr_reg.off.saturating_sub(off as i32);
        return (
            bounds.smin_ptr,
            bounds.smax_ptr,
            ptr_reg.umin_value,
            ptr_reg.umax_value,
            new_off,
            ptr_reg.var_off,
        );
    }

    // Variable offset - update var_off and bounds
    let new_var_off = ptr_reg.var_off.sub(off_reg.var_off);

    // Signed bounds: ptr - off
    // min = ptr_min - off_max, max = ptr_max - off_min
    let (new_smin, smin_of) = bounds.smin_ptr.overflowing_sub(bounds.smax_off);
    let (new_smax, smax_of) = bounds.smax_ptr.overflowing_sub(bounds.smin_off);

    let (new_smin, new_smax) = if smin_of || smax_of {
        (i64::MIN, i64::MAX)
    } else {
        (new_smin, new_smax)
    };

    // Unsigned bounds
    let new_umin = ptr_reg.umin_value.saturating_sub(bounds.umax_off);
    let new_umax = if ptr_reg.umax_value >= bounds.umin_off && bounds.umin_off != 0 {
        ptr_reg.umax_value - bounds.umin_off
    } else {
        u64::MAX
    };

    (
        new_smin,
        new_smax,
        new_umin,
        new_umax,
        ptr_reg.off,
        new_var_off,
    )
}

/// Validate that pointer bounds are sane after arithmetic
fn validate_ptr_bounds(reg: &BpfRegState) -> Result<()> {
    // Check for stack pointer bounds
    if reg.reg_type == BpfRegType::PtrToStack {
        let max_off = reg.off as i64 + reg.smax_value;
        let min_off = reg.off as i64 + reg.smin_value;

        if max_off > 0 {
            return Err(VerifierError::InvalidPointerArithmetic(format!(
                "stack pointer offset {} exceeds frame",
                max_off
            )));
        }
        if min_off < -(MAX_BPF_STACK as i64) {
            return Err(VerifierError::InvalidPointerArithmetic(format!(
                "stack pointer offset {} below stack limit",
                min_off
            )));
        }
    }

    // Check for map value bounds
    if reg.reg_type == BpfRegType::PtrToMapValue {
        if let Some(ref map_info) = reg.map_ptr {
            let max_off = reg.off as i64 + reg.smax_value;
            if max_off > map_info.value_size as i64 {
                return Err(VerifierError::InvalidPointerArithmetic(format!(
                    "map value access {} exceeds value_size {}",
                    max_off, map_info.value_size
                )));
            }
        }
    }

    Ok(())
}

/// Adjust bounds for scalar ALU operations
fn adjust_reg_min_max_vals(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    is_64bit: bool,
) -> Result<()> {
    let opcode = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;

    // Get source value
    let src_state = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        state
            .reg(src_reg)
            .ok_or(VerifierError::Internal("no src register".into()))?
            .clone()
    } else {
        let mut imm_state = BpfRegState::new_scalar_unknown(false);
        imm_state.mark_known(insn.imm as i64 as u64);
        imm_state
    };

    let dst_state = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?
        .clone();

    // Compute result
    let result = adjust_scalar_min_max_vals(&dst_state, &src_state, opcode, is_64bit)?;

    // Update destination
    if let Some(dst) = state.reg_mut(dst_reg) {
        *dst = result;
        if !is_64bit {
            dst.subreg_def = insn_idx as u32 + 1;
            zext_32_to_64_inplace(dst);
        }
    }

    Ok(())
}

/// Compute scalar ALU result with bounds tracking
fn adjust_scalar_min_max_vals(
    dst: &BpfRegState,
    src: &BpfRegState,
    opcode: u8,
    is_64bit: bool,
) -> Result<BpfRegState> {
    let mut result = dst.clone();
    result.reg_type = BpfRegType::ScalarValue;

    // If both are known constants, compute exactly
    if dst.is_const() && src.is_const() {
        let d = dst.const_value();
        let s = src.const_value();
        let val = compute_alu_const(d, s, opcode, is_64bit)?;
        result.mark_known(val);
        return Ok(result);
    }

    // Otherwise, compute bounds
    match opcode {
        BPF_ADD => scalar_add(&mut result, dst, src, is_64bit),
        BPF_SUB => scalar_sub(&mut result, dst, src, is_64bit),
        BPF_MUL => scalar_mul(&mut result, dst, src, is_64bit),
        BPF_DIV => scalar_div(&mut result, dst, src, is_64bit)?,
        BPF_MOD => scalar_mod(&mut result, dst, src, is_64bit)?,
        BPF_OR => scalar_or(&mut result, dst, src),
        BPF_AND => scalar_and(&mut result, dst, src),
        BPF_XOR => scalar_xor(&mut result, dst, src),
        BPF_LSH => scalar_lsh(&mut result, dst, src, is_64bit)?,
        BPF_RSH => scalar_rsh(&mut result, dst, src, is_64bit)?,
        BPF_ARSH => scalar_arsh(&mut result, dst, src, is_64bit)?,
        _ => {
            result.mark_unknown(false);
        }
    }

    result.sync_bounds();
    Ok(result)
}

/// Compute constant ALU operation
fn compute_alu_const(d: u64, s: u64, opcode: u8, is_64bit: bool) -> Result<u64> {
    let (d, s) = if is_64bit {
        (d, s)
    } else {
        (d as u32 as u64, s as u32 as u64)
    };

    let val = match opcode {
        BPF_ADD => d.wrapping_add(s),
        BPF_SUB => d.wrapping_sub(s),
        BPF_MUL => d.wrapping_mul(s),
        BPF_DIV => {
            if s == 0 {
                return Err(VerifierError::DivisionByZero);
            }
            d / s
        }
        BPF_MOD => {
            if s == 0 {
                return Err(VerifierError::DivisionByZero);
            }
            d % s
        }
        BPF_OR => d | s,
        BPF_AND => d & s,
        BPF_XOR => d ^ s,
        BPF_LSH => {
            let shift = if is_64bit { s & 63 } else { s & 31 };
            d << shift
        }
        BPF_RSH => {
            let shift = if is_64bit { s & 63 } else { s & 31 };
            d >> shift
        }
        BPF_ARSH => {
            let shift = if is_64bit { s & 63 } else { s & 31 };
            if is_64bit {
                ((d as i64) >> shift) as u64
            } else {
                ((d as i32) >> shift) as u32 as u64
            }
        }
        BPF_NEG => (-(d as i64)) as u64,
        _ => d,
    };

    Ok(if is_64bit { val } else { val as u32 as u64 })
}

// ============================================================================
// Scalar bounds computation for each operation
// ============================================================================

fn scalar_add(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState, _is_64: bool) {
    result.var_off = dst.var_off.add(src.var_off);

    // Unsigned bounds
    let (umin, umin_of) = dst.umin_value.overflowing_add(src.umin_value);
    let (umax, umax_of) = dst.umax_value.overflowing_add(src.umax_value);
    if umin_of || umax_of {
        result.umin_value = 0;
        result.umax_value = u64::MAX;
    } else {
        result.umin_value = umin;
        result.umax_value = umax;
    }

    // Signed bounds
    let (smin, smin_of) = dst.smin_value.overflowing_add(src.smin_value);
    let (smax, smax_of) = dst.smax_value.overflowing_add(src.smax_value);
    if smin_of || smax_of {
        result.smin_value = i64::MIN;
        result.smax_value = i64::MAX;
    } else {
        result.smin_value = smin;
        result.smax_value = smax;
    }
}

fn scalar_sub(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState, _is_64: bool) {
    result.var_off = dst.var_off.sub(src.var_off);

    // Unsigned: dst.min - src.max, dst.max - src.min
    if dst.umin_value >= src.umax_value {
        result.umin_value = dst.umin_value - src.umax_value;
    } else {
        result.umin_value = 0;
    }
    if dst.umax_value >= src.umin_value {
        result.umax_value = dst.umax_value - src.umin_value;
    } else {
        result.umax_value = u64::MAX;
    }

    // Signed
    let (smin, smin_of) = dst.smin_value.overflowing_sub(src.smax_value);
    let (smax, smax_of) = dst.smax_value.overflowing_sub(src.smin_value);
    if smin_of || smax_of {
        result.smin_value = i64::MIN;
        result.smax_value = i64::MAX;
    } else {
        result.smin_value = smin;
        result.smax_value = smax;
    }
}

fn scalar_mul(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState, _is_64: bool) {
    result.var_off = dst.var_off.mul(src.var_off);

    // Multiplication can overflow easily, be conservative
    let (umax, overflow) = dst.umax_value.overflowing_mul(src.umax_value);
    if overflow {
        result.umin_value = 0;
        result.umax_value = u64::MAX;
        result.smin_value = i64::MIN;
        result.smax_value = i64::MAX;
    } else {
        result.umin_value = dst.umin_value.saturating_mul(src.umin_value);
        result.umax_value = umax;
        // Signed multiplication is complex, be conservative
        result.smin_value = i64::MIN;
        result.smax_value = i64::MAX;
    }
}

fn scalar_div(
    result: &mut BpfRegState,
    dst: &BpfRegState,
    src: &BpfRegState,
    _is_64: bool,
) -> Result<()> {
    // Check for possible division by zero
    if src.umin_value == 0 {
        // Division by zero is possible - this should have been caught earlier
        // for constant case, but for variable we mark as unknown
    }

    if src.is_const() && src.const_value() != 0 {
        let s = src.const_value();
        result.umin_value = dst.umin_value / s;
        result.umax_value = dst.umax_value / s;
        result.var_off = Tnum::range(result.umin_value, result.umax_value);
    } else {
        // Variable divisor - result is very imprecise
        result.umin_value = 0;
        result.umax_value = dst.umax_value;
        result.var_off = Tnum::unknown();
    }

    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
    Ok(())
}

fn scalar_mod(
    result: &mut BpfRegState,
    dst: &BpfRegState,
    src: &BpfRegState,
    _is_64: bool,
) -> Result<()> {
    if src.is_const() && src.const_value() != 0 {
        let s = src.const_value();
        // x % s is always in [0, s-1]
        result.umin_value = 0;
        result.umax_value = (s - 1).min(dst.umax_value);
        result.var_off = Tnum::range(0, result.umax_value);
    } else if src.umin_value > 0 {
        result.umin_value = 0;
        result.umax_value = (src.umax_value - 1).min(dst.umax_value);
        result.var_off = Tnum::unknown();
    } else {
        result.mark_unknown(false);
    }

    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
    Ok(())
}

fn scalar_or(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState) {
    result.var_off = dst.var_off | src.var_off;
    // OR can only increase value
    result.umin_value = dst.umin_value | src.umin_value;
    result.umax_value = dst.umax_value | src.umax_value;
    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
}

fn scalar_and(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState) {
    result.var_off = dst.var_off & src.var_off;
    // AND can only decrease value
    result.umin_value = 0;
    result.umax_value = dst.umax_value.min(src.umax_value);
    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
}

fn scalar_xor(result: &mut BpfRegState, dst: &BpfRegState, src: &BpfRegState) {
    result.var_off = dst.var_off ^ src.var_off;
    // XOR bounds are imprecise
    result.umin_value = 0;
    result.umax_value = dst.umax_value | src.umax_value;
    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
}

fn scalar_lsh(
    result: &mut BpfRegState,
    dst: &BpfRegState,
    src: &BpfRegState,
    is_64: bool,
) -> Result<()> {
    let max_shift = if is_64 { 63 } else { 31 };

    if src.is_const() {
        let shift = src.const_value() & max_shift as u64;
        result.var_off = dst.var_off.lsh(shift as u8);
        result.umin_value = dst.umin_value << shift;
        result.umax_value = dst.umax_value << shift;
    } else if src.umax_value <= max_shift as u64 {
        // Variable shift within valid range
        result.umin_value = dst.umin_value << src.umin_value;
        result.umax_value = dst.umax_value << src.umax_value;
        result.var_off = Tnum::unknown();
    } else {
        result.mark_unknown(false);
    }

    result.smin_value = i64::MIN;
    result.smax_value = i64::MAX;
    Ok(())
}

fn scalar_rsh(
    result: &mut BpfRegState,
    dst: &BpfRegState,
    src: &BpfRegState,
    is_64: bool,
) -> Result<()> {
    let max_shift = if is_64 { 63 } else { 31 };

    if src.is_const() {
        let shift = src.const_value() & max_shift as u64;
        result.var_off = dst.var_off.rsh(shift as u8);
        result.umin_value = dst.umin_value >> shift;
        result.umax_value = dst.umax_value >> shift;
        result.smin_value = 0;
        result.smax_value = result.umax_value as i64;
    } else {
        // Logical right shift with variable amount
        result.umin_value = dst.umin_value >> src.umax_value.min(max_shift as u64);
        result.umax_value = dst.umax_value >> src.umin_value.min(max_shift as u64);
        result.var_off = Tnum::range(result.umin_value, result.umax_value);
        result.smin_value = 0;
        result.smax_value = result.umax_value as i64;
    }

    Ok(())
}

fn scalar_arsh(
    result: &mut BpfRegState,
    dst: &BpfRegState,
    src: &BpfRegState,
    is_64: bool,
) -> Result<()> {
    let max_shift = if is_64 { 63 } else { 31 };

    if src.is_const() {
        let shift = src.const_value() & max_shift as u64;
        result.var_off = dst.var_off.arsh(shift as u8);
        result.smin_value = dst.smin_value >> shift;
        result.smax_value = dst.smax_value >> shift;
        if result.smin_value >= 0 {
            result.umin_value = result.smin_value as u64;
            result.umax_value = result.smax_value as u64;
        } else {
            result.umin_value = 0;
            result.umax_value = u64::MAX;
        }
    } else {
        result.mark_unknown(false);
    }

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

/// Check register argument validity
fn check_reg_arg(state: &BpfVerifierState, regno: usize, is_src: bool) -> Result<()> {
    if regno >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(regno as u8));
    }

    let reg = state
        .reg(regno)
        .ok_or(VerifierError::Internal("failed to get register".into()))?;

    if is_src && reg.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(regno as u8));
    }

    Ok(())
}

/// Mark a register as unknown scalar
fn mark_reg_unknown(state: &mut BpfVerifierState, regno: usize, is_64bit: bool) {
    if let Some(reg) = state.reg_mut(regno) {
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_unknown(false);
        if !is_64bit {
            reg.subreg_def = 1;
        }
    }
}

/// Copy register state
fn copy_register_state(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    src: &BpfRegState,
) -> Result<()> {
    if let Some(dst) = state.reg_mut(dst_reg) {
        *dst = src.clone();
        Ok(())
    } else {
        Err(VerifierError::Internal("no dst register".into()))
    }
}

/// Get register width in bits
fn get_reg_width(reg: &BpfRegState) -> u32 {
    if reg.umax_value <= u32::MAX as u64 {
        32
    } else {
        64
    }
}

/// Coerce register to sign-extended size
fn coerce_reg_to_size_sx(state: &mut BpfVerifierState, regno: usize, bytes: usize) -> Result<()> {
    if let Some(reg) = state.reg_mut(regno) {
        let bits = bytes * 8;
        let sign_bit = 1u64 << (bits - 1);
        let mask = (1u64 << bits) - 1;

        if reg.is_const() {
            let val = reg.const_value();
            let truncated = val & mask;
            let sign_extended = if truncated & sign_bit != 0 {
                truncated | !mask
            } else {
                truncated
            };
            reg.mark_known(sign_extended);
        } else {
            // Conservative: just mark as unknown
            reg.mark_unknown(false);
        }
    }
    Ok(())
}

/// Coerce subreg to sign-extended size
fn coerce_subreg_to_size_sx(
    state: &mut BpfVerifierState,
    regno: usize,
    bytes: usize,
) -> Result<()> {
    // For 32-bit operations, similar to coerce_reg_to_size_sx
    coerce_reg_to_size_sx(state, regno, bytes)
}

/// Zero-extend 32-bit value to 64-bit
fn zext_32_to_64(state: &mut BpfVerifierState, regno: usize) -> Result<()> {
    if let Some(reg) = state.reg_mut(regno) {
        zext_32_to_64_inplace(reg);
    }
    Ok(())
}

/// Zero-extend 32-bit value to 64-bit (in-place)
fn zext_32_to_64_inplace(reg: &mut BpfRegState) {
    reg.umax_value = reg.umax_value.min(u32::MAX as u64);
    reg.umin_value = reg.umin_value.min(u32::MAX as u64);
    if reg.smax_value < 0 || reg.smax_value > u32::MAX as i64 {
        reg.smax_value = u32::MAX as i64;
    }
    if reg.smin_value < 0 {
        reg.smin_value = 0;
    }
    reg.var_off = Tnum::new(
        reg.var_off.value & 0xFFFF_FFFF,
        reg.var_off.mask & 0xFFFF_FFFF,
    );
}

/// Adjust bounds for NEG operation
fn adjust_neg_bounds(state: &mut BpfVerifierState, regno: usize, is_64bit: bool) -> Result<()> {
    if let Some(reg) = state.reg_mut(regno) {
        if reg.is_const() {
            let val = reg.const_value();
            reg.mark_known((-(val as i64)) as u64);
        } else {
            // NEG inverts the sign
            let new_smin = -reg.smax_value;
            let new_smax = -reg.smin_value;
            reg.smin_value = new_smin;
            reg.smax_value = new_smax;
            // Unsigned bounds become imprecise
            reg.umin_value = 0;
            reg.umax_value = if is_64bit { u64::MAX } else { u32::MAX as u64 };
            reg.var_off = Tnum::unknown();
        }
        if !is_64bit {
            zext_32_to_64_inplace(reg);
        }
    }
    Ok(())
}

/// Sanity check bounds after ALU operation
fn reg_bounds_sanity_check(reg: &BpfRegState, _context: &str) -> Result<()> {
    // Check that bounds are sane
    if reg.umin_value > reg.umax_value {
        return Err(VerifierError::Internal("umin > umax after ALU op".into()));
    }
    if reg.smin_value > reg.smax_value {
        return Err(VerifierError::Internal("smin > smax after ALU op".into()));
    }
    if reg.u32_min_value > reg.u32_max_value {
        return Err(VerifierError::Internal(
            "u32_min > u32_max after ALU op".into(),
        ));
    }
    if reg.s32_min_value > reg.s32_max_value {
        return Err(VerifierError::Internal(
            "s32_min > s32_max after ALU op".into(),
        ));
    }
    Ok(())
}
