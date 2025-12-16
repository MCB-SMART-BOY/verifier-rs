// SPDX-License-Identifier: GPL-2.0

//! Load and store instruction verification
//!
//! This module implements verification for BPF_LDX and BPF_STX instructions,
//! handling memory loads, stores, and atomic operations.
//!
//! Corresponds to check_load_mem() and check_store_reg() in Linux kernel verifier.c

use alloc::format;

use crate::bounds::tnum::Tnum;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::mem::memory::check_mem_access;
use crate::state::reg_state::BpfRegState;
use crate::state::spill_fill::{SpillFillTracker, StackReadResult};
use crate::state::verifier_state::BpfVerifierState;

/// Parameters for setting load result in destination register.
struct LoadResultParams<'a> {
    src: &'a BpfRegState,
    off: i32,
    size: u32,
    loaded_type: BpfRegType,
    is_ldsx: bool,
}

/// Check a memory load instruction (BPF_LDX)
///
/// This verifies that:
/// 1. Source register is a valid pointer
/// 2. Memory access is within bounds
/// 3. Destination register gets the right type
pub fn check_load_mem(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    is_ldsx: bool, // Sign-extending load
    _check_write_mark: bool,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let size = bpf_size_to_bytes(insn.size());

    if dst_reg >= MAX_BPF_REG || src_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Validate reserved fields for BPF_MEM mode
    if insn.mode() == BPF_MEM && insn.imm != 0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Check source register is valid and readable
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
        .clone();

    if src.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(src_reg as u8));
    }

    // Source must be a pointer
    if !src.is_pointer() && !src.is_null() {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "R{} is not a pointer for load",
            src_reg
        )));
    }

    // Check memory access permissions and bounds
    let loaded_type = check_mem_access(
        state,
        &src,
        insn.off as i32,
        size,
        false, // read
        false,
    )?;

    // Set destination register based on loaded value
    let params = LoadResultParams {
        src: &src,
        off: insn.off as i32,
        size,
        loaded_type,
        is_ldsx,
    };
    set_load_result(state, dst_reg, &params)?;

    // Mark destination as written
    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.live.written = true;
        // For 32-bit loads, mark subreg_def
        if size < 8 {
            dst.subreg_def = insn_idx as u32 + 1;
        }
    }

    Ok(())
}

/// Check a memory store instruction (BPF_STX)
///
/// This verifies that:
/// 1. Destination register is a valid pointer
/// 2. Source register is initialized
/// 3. Memory access is within bounds and writable
/// 4. Pointer stores are allowed (if storing a pointer)
pub fn check_store_reg(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let size = bpf_size_to_bytes(insn.size());

    if dst_reg >= MAX_BPF_REG || src_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Validate reserved fields
    if insn.mode() != BPF_MEM || insn.imm != 0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Check destination register (the pointer)
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
        .clone();

    if dst.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(dst_reg as u8));
    }

    if !dst.is_pointer() {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "R{} is not a pointer for store",
            dst_reg
        )));
    }

    // Check source register
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
        .clone();

    if src.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(src_reg as u8));
    }

    // Check for pointer leaks in unprivileged mode
    if !allow_ptr_leaks && src.is_pointer() {
        check_pointer_store_allowed(&dst, &src)?;
    }

    // Check memory access permissions and bounds
    check_mem_access(
        state,
        &dst,
        insn.off as i32,
        size,
        true, // write
        allow_ptr_leaks,
    )?;

    // Update stack state if storing to stack
    if dst.reg_type == BpfRegType::PtrToStack {
        update_stack_on_store(state, &dst, insn.off as i32, size, &src)?;
    }

    Ok(())
}

/// Check an immediate store instruction (BPF_ST)
///
/// This stores an immediate value to memory.
pub fn check_store_imm(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let size = bpf_size_to_bytes(insn.size());

    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Validate reserved fields
    if insn.mode() != BPF_MEM || insn.src_reg != 0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Check destination register (the pointer)
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
        .clone();

    if dst.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(dst_reg as u8));
    }

    if !dst.is_pointer() {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "R{} is not a pointer for store",
            dst_reg
        )));
    }

    // Check memory access permissions and bounds
    check_mem_access(
        state,
        &dst,
        insn.off as i32,
        size,
        true, // write
        false,
    )?;

    // Update stack state if storing to stack
    if dst.reg_type == BpfRegType::PtrToStack {
        let mut imm_reg = BpfRegState::new_scalar_unknown(false);
        imm_reg.mark_known(insn.imm as i64 as u64);
        update_stack_on_store(state, &dst, insn.off as i32, size, &imm_reg)?;
    }

    Ok(())
}

/// Set the destination register after a load
fn set_load_result(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    params: &LoadResultParams<'_>,
) -> Result<()> {
    // For stack loads, we need to call fill_reg before borrowing dst mutably
    // to avoid borrow conflicts
    let stack_fill_result = if params.loaded_type == BpfRegType::PtrToStack {
        let stack_off = params.src.off + params.off;
        Some(SpillFillTracker::fill_reg(state, stack_off, params.size as usize)?)
    } else {
        None
    };

    let dst = state
        .reg_mut(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

    // Most loads result in scalar values
    dst.reg_type = BpfRegType::ScalarValue;
    dst.id = 0;
    dst.off = 0;

    match params.loaded_type {
        BpfRegType::ScalarValue => {
            // Loading a scalar - set bounds based on size
            if params.is_ldsx {
                // Sign-extending load
                set_signed_bounds_from_size(dst, params.size);
            } else {
                // Zero-extending load
                set_unsigned_bounds_from_size(dst, params.size);
            }
        }
        BpfRegType::PtrToStack => {
            // Loading a spilled register from stack - use pre-fetched result
            let fill_result = match stack_fill_result {
                Some(r) => r,
                None => {
                    // Default to initialized scalar if no fill result
                    if params.is_ldsx {
                        set_signed_bounds_from_size(dst, params.size);
                    } else {
                        set_unsigned_bounds_from_size(dst, params.size);
                    }
                    return Ok(());
                }
            };
            let stack_off = params.src.off + params.off;

            match fill_result {
                StackReadResult::SpilledReg(spilled) => {
                    // Restore the spilled register with full precision
                    *dst = spilled;
                    // Clear precision flag - will be set by precision tracking if needed
                    dst.precise = false;
                }
                StackReadResult::Zero => {
                    // Stack slot contains zero
                    dst.mark_known(0);
                    if params.size < 8 {
                        set_unsigned_bounds_from_size(dst, params.size);
                    }
                }
                StackReadResult::Initialized => {
                    // Initialized but not a full spill - unknown scalar with size bounds
                    if params.is_ldsx {
                        set_signed_bounds_from_size(dst, params.size);
                    } else {
                        set_unsigned_bounds_from_size(dst, params.size);
                    }
                }
                StackReadResult::Uninitialized => {
                    // This should have been caught by check_mem_access
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "reading uninitialized stack at offset {}",
                        stack_off
                    )));
                }
                StackReadResult::Dynptr(_) | StackReadResult::Iterator(_) => {
                    // Special slots - should not be read directly
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot read special stack slot directly".into(),
                    ));
                }
            }
        }
        BpfRegType::PtrToMapValue => {
            // Loading from map value - might be a kptr
            // For now, treat as scalar
            set_unsigned_bounds_from_size(dst, params.size);
        }
        _ => {
            // Default: unknown scalar
            dst.mark_unknown(false);
        }
    }

    Ok(())
}

/// Set bounds for unsigned load
fn set_unsigned_bounds_from_size(reg: &mut BpfRegState, size: u32) {
    reg.var_off = Tnum::unknown();

    match size {
        1 => {
            reg.umin_value = 0;
            reg.umax_value = 0xFF;
            reg.smin_value = 0;
            reg.smax_value = 0xFF;
        }
        2 => {
            reg.umin_value = 0;
            reg.umax_value = 0xFFFF;
            reg.smin_value = 0;
            reg.smax_value = 0xFFFF;
        }
        4 => {
            reg.umin_value = 0;
            reg.umax_value = 0xFFFF_FFFF;
            reg.smin_value = 0;
            reg.smax_value = 0xFFFF_FFFF;
        }
        8 => {
            reg.umin_value = 0;
            reg.umax_value = u64::MAX;
            reg.smin_value = i64::MIN;
            reg.smax_value = i64::MAX;
        }
        _ => reg.mark_unknown(false),
    }

    // Update 32-bit bounds
    reg.u32_min_value = reg.umin_value as u32;
    reg.u32_max_value = (reg.umax_value.min(u32::MAX as u64)) as u32;
    reg.s32_min_value = (reg.smin_value.max(i32::MIN as i64)) as i32;
    reg.s32_max_value = (reg.smax_value.min(i32::MAX as i64)) as i32;
}

/// Set bounds for signed load (LDSX)
fn set_signed_bounds_from_size(reg: &mut BpfRegState, size: u32) {
    reg.var_off = Tnum::unknown();

    match size {
        1 => {
            // s8: -128 to 127
            reg.smin_value = -128;
            reg.smax_value = 127;
            reg.umin_value = 0;
            reg.umax_value = u64::MAX; // Could be negative
        }
        2 => {
            // s16: -32768 to 32767
            reg.smin_value = -32768;
            reg.smax_value = 32767;
            reg.umin_value = 0;
            reg.umax_value = u64::MAX;
        }
        4 => {
            // s32: -2^31 to 2^31-1
            reg.smin_value = i32::MIN as i64;
            reg.smax_value = i32::MAX as i64;
            reg.umin_value = 0;
            reg.umax_value = u64::MAX;
        }
        8 => {
            reg.smin_value = i64::MIN;
            reg.smax_value = i64::MAX;
            reg.umin_value = 0;
            reg.umax_value = u64::MAX;
        }
        _ => reg.mark_unknown(false),
    }

    // Update 32-bit bounds
    reg.u32_min_value = 0;
    reg.u32_max_value = u32::MAX;
    reg.s32_min_value = i32::MIN;
    reg.s32_max_value = i32::MAX;
}

/// Check if storing a pointer is allowed
fn check_pointer_store_allowed(dst: &BpfRegState, _src: &BpfRegState) -> Result<()> {
    // Stack is always OK for pointer stores (spilling)
    if dst.reg_type == BpfRegType::PtrToStack {
        return Ok(());
    }

    // Map values can store pointers if they have kptr fields
    if dst.reg_type == BpfRegType::PtrToMapValue {
        // Would need to check BTF for kptr fields here
        // For now, reject unless we can verify it's a kptr slot
        return Err(VerifierError::InvalidPointerArithmetic(
            "cannot store pointer to map value without kptr field".into(),
        ));
    }

    // Arena memory allows pointer stores
    if dst.reg_type == BpfRegType::PtrToArena {
        return Ok(());
    }

    Err(VerifierError::InvalidPointerArithmetic(format!(
        "pointer stores not allowed to {:?}",
        dst.reg_type
    )))
}

/// Update stack state after a store
fn update_stack_on_store(
    state: &mut BpfVerifierState,
    dst: &BpfRegState,
    off: i32,
    size: u32,
    src: &BpfRegState,
) -> Result<()> {
    let stack_off = -(dst.off + off);

    if stack_off <= 0 {
        return Err(VerifierError::StackOutOfBounds(dst.off + off));
    }

    // Ensure stack is allocated to this depth
    let func = state
        .cur_func_mut()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    if stack_off as usize > func.stack.allocated_stack {
        func.stack.grow(stack_off as usize)?;
    }

    // Determine what kind of data we're storing
    if src.is_pointer() && size == 8 {
        // Spilling a pointer - would mark as spilled register
        // This allows the pointer to be restored later
        // For now, just ensure stack is allocated
    } else {
        // Storing a scalar or partial value
        // Would mark slots as containing scalar/misc data
    }

    Ok(())
}

/// Convert BPF size code to bytes
pub fn bpf_size_to_bytes(size_code: u8) -> u32 {
    match size_code {
        0 => 4, // BPF_W (32-bit)
        1 => 2, // BPF_H (16-bit)
        2 => 1, // BPF_B (8-bit)
        3 => 8, // BPF_DW (64-bit)
        _ => 0,
    }
}
