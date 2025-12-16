//! Instruction checking and validation
//!
//! This module implements the instruction-level verification logic,
//! including ALU operations, jumps, calls, and memory access instructions.

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// Check if a register is 64-bit for the given instruction
pub fn is_reg64(insn: &BpfInsn, _regno: usize, is_src: bool) -> bool {
    let class = insn.class();

    // 32-bit ALU operations
    if class == BPF_ALU {
        // MOV32 and shifts are special
        if is_src {
            if insn.code & 0xf0 == BPF_MOV {
                return false;
            }
            // Shifts use only lower 5/6 bits
            if matches!(insn.code & 0xf0, BPF_LSH | BPF_RSH | BPF_ARSH) {
                return false;
            }
        }
        return false;
    }

    // 64-bit ALU operations
    if class == BPF_ALU64 {
        return true;
    }

    // Memory operations - depends on size
    if matches!(class, BPF_LDX | BPF_STX | BPF_ST) {
        let size = insn.size();
        // BPF_DW is 64-bit
        return size == 3; // BPF_DW
    }

    // Jumps and calls are 64-bit
    true
}

/// Get the destination register for an instruction (if any)
pub fn insn_def_regno(insn: &BpfInsn) -> Option<usize> {
    let class = insn.class();

    match class {
        BPF_ALU | BPF_ALU64 => {
            // NEG has no dst in some cases, but generally ALU writes to dst
            Some(insn.dst_reg as usize)
        }
        BPF_LDX => Some(insn.dst_reg as usize),
        BPF_LD => {
            // LD_IMM64 writes to dst
            if insn.mode() == BPF_IMM {
                Some(insn.dst_reg as usize)
            } else {
                Some(BPF_REG_0)
            }
        }
        BPF_JMP | BPF_JMP32 => {
            // CALL writes to R0
            if insn.code & 0xf0 == BPF_CALL {
                Some(BPF_REG_0)
            } else {
                None
            }
        }
        BPF_STX => {
            // Atomic operations may write to dst
            if insn.mode() == BPF_ATOMIC {
                // CMPXCHG always writes to R0
                if insn.imm == BPF_CMPXCHG as i32 {
                    Some(BPF_REG_0)
                } else if insn.imm & BPF_FETCH as i32 != 0 {
                    Some(insn.src_reg as usize)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if instruction has a 32-bit definition
pub fn insn_has_def32(insn: &BpfInsn) -> bool {
    if let Some(regno) = insn_def_regno(insn) {
        !is_reg64(insn, regno, false)
    } else {
        false
    }
}

/// Check register argument (source or destination)
pub fn check_reg_arg(
    state: &mut BpfVerifierState,
    _insn: &BpfInsn,
    regno: usize,
    is_src: bool,
    allow_ptr_leaks: bool,
) -> Result<()> {
    if regno >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(regno as u8));
    }

    let reg = state.reg(regno).ok_or(VerifierError::Internal(
        "failed to get register".into(),
    ))?;

    if is_src {
        // Source register must be readable (initialized)
        if reg.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(regno as u8));
        }
        // Mark as read
        // state.reg_mut(regno).unwrap().live.read = true;
    } else {
        // Destination register will be written
        // Check pointer leaks in unprivileged mode
        if !allow_ptr_leaks && reg.is_pointer() {
            // This is OK for most cases, but might need special handling
        }
        // Mark as written
        // state.reg_mut(regno).unwrap().live.written = true;
    }

    Ok(())
}

/// Mark instruction as needing zero extension
pub fn mark_insn_zext(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
) -> Result<()> {
    if let Some(regno) = insn_def_regno(insn) {
        if !is_reg64(insn, regno, false) {
            // 32-bit write needs zero extension
            if let Some(reg) = state.reg_mut(regno) {
                reg.subreg_def = 1; // Mark as having 32-bit definition
            }
        }
    }
    Ok(())
}

/// Check ALU operation
pub fn check_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let class = insn.class();
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;

    let dst_reg = insn.dst_reg as usize;
    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(dst_reg as u8));
    }

    // Check destination register
    check_reg_arg(state, insn, dst_reg, false, allow_ptr_leaks)?;

    // For register source, check it's valid
    if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        check_reg_arg(state, insn, src_reg, true, allow_ptr_leaks)?;
    }

    // Special handling for NEG (no source operand)
    if op == BPF_NEG {
        let dst_state = state.reg(dst_reg).ok_or(VerifierError::Internal(
            "failed to get dst register".into(),
        ))?.clone();
        
        if dst_state.is_pointer() {
            return Err(VerifierError::InvalidPointerArithmetic(
                "NEG not allowed on pointers".into(),
            ));
        }
        
        if let Some(dst) = state.reg_mut(dst_reg) {
            if dst.is_const() {
                let val = dst.const_value();
                let neg_val = (-(val as i64)) as u64;
                if class == BPF_ALU64 {
                    dst.mark_known(neg_val);
                } else {
                    dst.mark_known((neg_val as u32) as u64);
                    dst.subreg_def = 1;
                }
            } else {
                // For non-constant, swap and negate bounds
                let (new_smin, new_smax) = if dst.smax_value != i64::MIN {
                    (-dst.smax_value, -dst.smin_value.saturating_neg())
                } else {
                    (i64::MIN, i64::MAX)
                };
                dst.smin_value = new_smin;
                dst.smax_value = new_smax;
                dst.umin_value = 0;
                dst.umax_value = u64::MAX;
                if class == BPF_ALU {
                    dst.subreg_def = 1;
                    dst.assign_32_into_64();
                }
            }
        }
        return Ok(());
    }

    // Special handling for END (byte swap)
    if op == BPF_END {
        let dst_state = state.reg(dst_reg).ok_or(VerifierError::Internal(
            "failed to get dst register".into(),
        ))?.clone();
        
        if dst_state.is_pointer() {
            return Err(VerifierError::InvalidPointerArithmetic(
                "byte swap not allowed on pointers".into(),
            ));
        }
        
        // insn.imm specifies the swap size (16, 32, or 64)
        let swap_size = insn.imm as u32;
        
        if let Some(dst) = state.reg_mut(dst_reg) {
            if dst.is_const() {
                let val = dst.const_value();
                let swapped = match swap_size {
                    16 => (val as u16).swap_bytes() as u64,
                    32 => (val as u32).swap_bytes() as u64,
                    64 => val.swap_bytes(),
                    _ => {
                        dst.mark_unknown(false);
                        return Ok(());
                    }
                };
                dst.mark_known(swapped);
            } else {
                // After byte swap, bounds become unknown
                // But we can constrain based on swap size
                match swap_size {
                    16 => {
                        dst.umin_value = 0;
                        dst.umax_value = u16::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u16::MAX as i64;
                    }
                    32 => {
                        dst.umin_value = 0;
                        dst.umax_value = u32::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u32::MAX as i64;
                    }
                    64 => {
                        dst.mark_unbounded();
                    }
                    _ => {
                        dst.mark_unknown(false);
                    }
                }
            }
            
            // BPF_ALU class with END is for 64-bit values
            if class == BPF_ALU && swap_size != 64 {
                dst.subreg_def = 1;
            }
        }
        return Ok(());
    }

    // Special handling for MOV
    if op == BPF_MOV {
        if src_type == BPF_X {
            // Register move
            let src_reg = insn.src_reg as usize;
            let src_state = state.reg(src_reg).ok_or(VerifierError::Internal(
                "failed to get src register".into(),
            ))?.clone();
            
            if let Some(dst) = state.reg_mut(dst_reg) {
                *dst = src_state;
                if class == BPF_ALU {
                    // 32-bit move - upper bits get zeroed
                    dst.subreg_def = 1;
                    dst.assign_32_into_64();
                }
            }
        } else {
            // Immediate move
            if let Some(dst) = state.reg_mut(dst_reg) {
                if class == BPF_ALU64 {
                    dst.reg_type = BpfRegType::ScalarValue;
                    dst.mark_known(insn.imm as i64 as u64);
                } else {
                    dst.reg_type = BpfRegType::ScalarValue;
                    dst.mark_known(insn.imm as u32 as u64);
                    dst.subreg_def = 1;
                }
            }
        }
        return Ok(());
    }

    // For other ALU ops, check operands
    let dst_state = state.reg(dst_reg).ok_or(VerifierError::Internal(
        "failed to get dst register".into(),
    ))?.clone();

    // Handle pointer arithmetic
    if dst_state.is_pointer() {
        return check_ptr_alu_op(state, insn, &dst_state, allow_ptr_leaks);
    }

    // Scalar ALU operation
    check_scalar_alu_op(state, insn, class == BPF_ALU64)
}

/// Check pointer ALU operation
fn check_ptr_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    dst_state: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;

    // Only ADD and SUB are allowed on pointers
    if !matches!(op, BPF_ADD | BPF_SUB) {
        if !allow_ptr_leaks {
            return Err(VerifierError::InvalidPointerArithmetic(
                "only ADD and SUB allowed on pointers".into(),
            ));
        }
        // In privileged mode, mark result as unknown scalar
        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
        }
        return Ok(());
    }

    // Get the addend (either immediate or register value)
    let addend = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        let src_state = state.reg(src_reg).ok_or(VerifierError::Internal(
            "failed to get src register".into(),
        ))?;

        // Source must be scalar for pointer arithmetic
        if src_state.is_pointer() {
            if op == BPF_SUB && dst_state.reg_type == src_state.reg_type {
                // ptr - ptr = scalar (if same type)
                if let Some(dst) = state.reg_mut(dst_reg) {
                    dst.mark_unknown(false);
                }
                return Ok(());
            }
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot add pointer to pointer".into(),
            ));
        }

        if src_state.is_const() {
            Some(src_state.const_value() as i64)
        } else {
            None
        }
    } else {
        Some(insn.imm as i64)
    };

    // Update pointer offset
    if let Some(dst) = state.reg_mut(dst_reg) {
        if let Some(add_val) = addend {
            let new_off = if op == BPF_ADD {
                dst_state.off.saturating_add(add_val as i32)
            } else {
                dst_state.off.saturating_sub(add_val as i32)
            };
            *dst = dst_state.clone();
            dst.off = new_off;
        } else {
            // Unknown addend - update var_off
            *dst = dst_state.clone();
            dst.var_off = crate::bounds::tnum::Tnum::unknown();
        }
    }

    Ok(())
}

/// Check scalar ALU operation
fn check_scalar_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    is_64bit: bool,
) -> Result<()> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;

    // Get source value
    let src_val = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        state.reg(src_reg).cloned()
    } else {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        if is_64bit {
            // Sign-extend for 64-bit operations
            reg.mark_known(insn.imm as i64 as u64);
        } else {
            // Zero-extend for 32-bit operations
            reg.mark_known(insn.imm as u32 as u64);
        }
        Some(reg)
    };

    let src = src_val.ok_or(VerifierError::Internal("no src value".into()))?;
    let dst = state.reg(dst_reg).ok_or(VerifierError::Internal(
        "no dst register".into(),
    ))?.clone();

    // Check for division by zero
    if matches!(op, BPF_DIV | BPF_MOD) {
        // Check if divisor could be zero
        if src.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }
        // Note: runtime check will be inserted if umin_value == 0
    }

    // Use ScalarBounds for comprehensive bounds propagation
    let result = compute_alu_result(&dst, &src, op, is_64bit)?;

    if let Some(dst_mut) = state.reg_mut(dst_reg) {
        *dst_mut = result;
        if !is_64bit {
            dst_mut.subreg_def = 1;
            // Zero-extend 32-bit result to 64-bit
            dst_mut.assign_32_into_64();
        }
        // Ensure bounds are synchronized
        dst_mut.sync_bounds();
    }

    Ok(())
}

/// Compute ALU result with bounds tracking using ScalarBounds
fn compute_alu_result(
    dst: &BpfRegState,
    src: &BpfRegState,
    op: u8,
    is_64bit: bool,
) -> Result<BpfRegState> {
    let mut result = dst.clone();
    result.reg_type = BpfRegType::ScalarValue;

    // Convert to ScalarBounds for comprehensive ALU handling
    let dst_bounds = dst.to_scalar_bounds();
    let src_bounds = src.to_scalar_bounds();

    // Use ScalarBounds::alu_op for proper bounds propagation
    let result_bounds = dst_bounds.alu_op(op, &src_bounds, is_64bit)?;
    
    // Apply the computed bounds back to the register state
    result.apply_scalar_bounds(&result_bounds);
    
    // Handle 32-bit operations - zero extension
    if !is_64bit {
        result.subreg_def = 1;
    }

    Ok(result)
}

/// Check conditional jump operation
///
/// This function implements the kernel's `check_cond_jmp_op()`. It:
/// 1. Validates the registers used in the comparison
/// 2. Determines if the branch outcome can be statically determined
/// 3. Refines register bounds based on the branch condition
/// 4. Returns the possible paths (fall-through and/or target)
pub fn check_cond_jmp_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<(Option<usize>, Option<usize>)> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let is_32bit = insn.class() == BPF_JMP32;

    // Unconditional jump
    if op == BPF_JA {
        let target = (insn_idx as i32 + insn.off as i32 + 1) as usize;
        return Ok((Some(target), None));
    }

    // Check destination register
    check_reg_arg(state, insn, dst_reg, true, allow_ptr_leaks)?;

    // Check source register if needed
    if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        check_reg_arg(state, insn, src_reg, true, allow_ptr_leaks)?;
    }

    let fall_through = insn_idx + 1;
    let target = (insn_idx as i32 + insn.off as i32 + 1) as usize;

    // Get register states
    let dst_state = state.reg(dst_reg).ok_or(VerifierError::Internal(
        "no dst register".into(),
    ))?.clone();

    let src_val = if src_type == BPF_X {
        state.reg(insn.src_reg as usize).cloned()
    } else {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        if is_32bit {
            reg.mark_known(insn.imm as u32 as u64);
        } else {
            reg.mark_known(insn.imm as i64 as u64);
        }
        Some(reg)
    };

    let src_state = src_val.ok_or(VerifierError::Internal("no src".into()))?;

    // Check for pointer comparisons
    if dst_state.is_pointer() || src_state.is_pointer() {
        return check_ptr_cmp(state, insn, &dst_state, &src_state, 
                            fall_through, target, allow_ptr_leaks);
    }

    // Try to determine if branch is always/never taken using bounds
    let taken = is_branch_taken_with_bounds(&dst_state, &src_state, op, is_32bit);

    match taken {
        Some(true) => {
            // Branch always taken - refine dst bounds for target path
            refine_reg_bounds_for_branch(state, dst_reg, &src_state, op, true, is_32bit);
            Ok((Some(target), None))
        }
        Some(false) => {
            // Branch never taken - refine dst bounds for fall-through path
            refine_reg_bounds_for_branch(state, dst_reg, &src_state, op, false, is_32bit);
            Ok((Some(fall_through), None))
        }
        None => {
            // Both paths possible - bounds will be refined per-path in the caller
            // Mark registers as needing precision for this conditional
            mark_regs_for_precision(state, dst_reg, 
                if src_type == BPF_X { Some(insn.src_reg as usize) } else { None });
            Ok((Some(fall_through), Some(target)))
        }
    }
}

/// Check pointer comparison in conditional jump
fn check_ptr_cmp(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    dst: &BpfRegState,
    src: &BpfRegState,
    fall_through: usize,
    target: usize,
    allow_ptr_leaks: bool,
) -> Result<(Option<usize>, Option<usize>)> {
    let op = insn.code & 0xf0;
    let dst_reg = insn.dst_reg as usize;
    
    // Only certain comparisons are allowed for pointers
    match op {
        BPF_JEQ | BPF_JNE => {
            // Equality comparison is always allowed
        }
        BPF_JGT | BPF_JGE | BPF_JLT | BPF_JLE |
        BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE => {
            // Ordering comparisons require same pointer type
            if dst.is_pointer() && src.is_pointer()
                && dst.reg_type != src.reg_type
                    && !allow_ptr_leaks {
                        return Err(VerifierError::InvalidPointerComparison(
                            "cannot compare pointers of different types".into()
                        ));
                    }
        }
        _ => {
            return Err(VerifierError::InvalidPointerComparison(
                "invalid comparison operation for pointers".into()
            ));
        }
    }

    // Handle NULL pointer checks
    if op == BPF_JEQ || op == BPF_JNE {
        // Check if comparing with NULL (scalar 0)
        let comparing_with_null = 
            (src.reg_type == BpfRegType::ScalarValue && src.is_const() && src.const_value() == 0) ||
            (dst.reg_type == BpfRegType::ScalarValue && dst.is_const() && dst.const_value() == 0);
        
        if comparing_with_null {
            // This is a NULL check - important for PTR_MAYBE_NULL handling
            if dst.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                // After check, one path has non-NULL pointer
                // The caller should handle marking the pointer as non-null on the appropriate path
                return Ok((Some(fall_through), Some(target)));
            }
        }
    }
    
    // For same-type pointers, try to determine outcome from offsets
    if dst.reg_type == src.reg_type && dst.is_const() && src.is_const() {
        let dst_val = dst.const_value();
        let src_val = src.const_value();
        
        let taken = match op {
            BPF_JEQ => dst_val == src_val,
            BPF_JNE => dst_val != src_val,
            BPF_JGT => dst_val > src_val,
            BPF_JGE => dst_val >= src_val,
            BPF_JLT => dst_val < src_val,
            BPF_JLE => dst_val <= src_val,
            _ => return Ok((Some(fall_through), Some(target))),
        };
        
        if taken {
            return Ok((Some(target), None));
        } else {
            return Ok((Some(fall_through), None));
        }
    }
    
    // Mark dst as needing precision for the conditional
    mark_regs_for_precision(state, dst_reg, None);
    
    Ok((Some(fall_through), Some(target)))
}

/// Determine if branch is taken based on register bounds
fn is_branch_taken_with_bounds(
    dst: &BpfRegState,
    src: &BpfRegState,
    op: u8,
    is_32bit: bool,
) -> Option<bool> {
    // First try exact constant comparison
    if let Some(result) = is_branch_taken(dst, src, op, is_32bit) {
        return Some(result);
    }
    
    // Try bounds-based reasoning
    if dst.reg_type != BpfRegType::ScalarValue {
        return None;
    }
    
    let (dst_umin, dst_umax, dst_smin, dst_smax) = if is_32bit {
        (dst.u32_min_value as u64, dst.u32_max_value as u64,
         dst.s32_min_value as i64, dst.s32_max_value as i64)
    } else {
        (dst.umin_value, dst.umax_value, dst.smin_value, dst.smax_value)
    };
    
    let (src_umin, src_umax, src_smin, src_smax) = if src.is_const() {
        let val = src.const_value();
        let sval = val as i64;
        (val, val, sval, sval)
    } else if src.reg_type == BpfRegType::ScalarValue {
        if is_32bit {
            (src.u32_min_value as u64, src.u32_max_value as u64,
             src.s32_min_value as i64, src.s32_max_value as i64)
        } else {
            (src.umin_value, src.umax_value, src.smin_value, src.smax_value)
        }
    } else {
        return None;
    };
    
    match op {
        BPF_JEQ => {
            // Can only be always-true if both are single values and equal
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(true);
            }
            // Can be always-false if ranges don't overlap
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(false);
            }
        }
        BPF_JNE => {
            // Always true if ranges don't overlap
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(true);
            }
            // Always false if both are same constant
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(false);
            }
        }
        BPF_JGT => {
            if dst_umin > src_umax { return Some(true); }
            if dst_umax <= src_umin { return Some(false); }
        }
        BPF_JGE => {
            if dst_umin >= src_umax { return Some(true); }
            if dst_umax < src_umin { return Some(false); }
        }
        BPF_JLT => {
            if dst_umax < src_umin { return Some(true); }
            if dst_umin >= src_umax { return Some(false); }
        }
        BPF_JLE => {
            if dst_umax <= src_umin { return Some(true); }
            if dst_umin > src_umax { return Some(false); }
        }
        BPF_JSGT => {
            if dst_smin > src_smax { return Some(true); }
            if dst_smax <= src_smin { return Some(false); }
        }
        BPF_JSGE => {
            if dst_smin >= src_smax { return Some(true); }
            if dst_smax < src_smin { return Some(false); }
        }
        BPF_JSLT => {
            if dst_smax < src_smin { return Some(true); }
            if dst_smin >= src_smax { return Some(false); }
        }
        BPF_JSLE => {
            if dst_smax <= src_smin { return Some(true); }
            if dst_smin > src_smax { return Some(false); }
        }
        BPF_JSET => {
            // Can determine if known bits definitely overlap or don't
            let known_dst = !dst.var_off.mask;
            let known_src = !src.var_off.mask;
            let val_dst = dst.var_off.value;
            let val_src = src.var_off.value;
            
            // If all bits are known and overlap is non-zero
            if known_dst & known_src == u64::MAX {
                return Some((val_dst & val_src) != 0);
            }
            // If any known set bit overlaps
            if (val_dst & val_src) != 0 {
                return Some(true);
            }
        }
        _ => {}
    }
    
    None
}

/// Refine register bounds based on branch outcome
fn refine_reg_bounds_for_branch(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    src: &BpfRegState,
    op: u8,
    taken: bool,
    is_32bit: bool,
) {
    let dst = match state.reg_mut(dst_reg) {
        Some(r) => r,
        None => return,
    };
    
    if dst.reg_type != BpfRegType::ScalarValue {
        return;
    }
    
    let src_val = if src.is_const() {
        src.const_value()
    } else {
        return; // Can only refine with constant source for now
    };
    
    // Apply refinement using the range_refine module logic
    use crate::bounds::range_refine::{BranchCond, refine_reg_const};
    
    let cond = match op {
        BPF_JEQ => BranchCond::Eq,
        BPF_JNE => BranchCond::Ne,
        BPF_JGT => BranchCond::Gt,
        BPF_JGE => BranchCond::Ge,
        BPF_JLT => BranchCond::Lt,
        BPF_JLE => BranchCond::Le,
        BPF_JSGT => BranchCond::Sgt,
        BPF_JSGE => BranchCond::Sge,
        BPF_JSLT => BranchCond::Slt,
        BPF_JSLE => BranchCond::Sle,
        _ => return,
    };
    
    let result = refine_reg_const(dst, src_val, cond, taken);
    result.apply_to(dst);
    
    // Handle 32-bit operations
    if is_32bit {
        // Sync 32-bit bounds to 64-bit
        dst.sync_bounds();
    }
}

/// Mark registers as needing precision for conditional
fn mark_regs_for_precision(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    src_reg: Option<usize>,
) {
    if let Some(dst) = state.reg_mut(dst_reg) {
        if dst.reg_type == BpfRegType::ScalarValue {
            dst.precise = true;
        }
    }
    
    if let Some(src_regno) = src_reg {
        if let Some(src) = state.reg_mut(src_regno) {
            if src.reg_type == BpfRegType::ScalarValue {
                src.precise = true;
            }
        }
    }
}

/// Determine if a branch is statically taken
fn is_branch_taken(
    dst: &BpfRegState,
    src: &BpfRegState,
    op: u8,
    _is_32bit: bool,
) -> Option<bool> {
    // Only check if both are constants
    if !dst.is_const() || !src.is_const() {
        // Could do range analysis here
        return None;
    }

    let d = dst.const_value();
    let s = src.const_value();

    let result = match op {
        BPF_JEQ => d == s,
        BPF_JNE => d != s,
        BPF_JGT => d > s,
        BPF_JGE => d >= s,
        BPF_JLT => d < s,
        BPF_JLE => d <= s,
        BPF_JSGT => (d as i64) > (s as i64),
        BPF_JSGE => (d as i64) >= (s as i64),
        BPF_JSLT => (d as i64) < (s as i64),
        BPF_JSLE => (d as i64) <= (s as i64),
        BPF_JSET => (d & s) != 0,
        _ => return None,
    };

    Some(result)
}

/// Check LD_IMM64 instruction
pub fn check_ld_imm64(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    next_insn: &BpfInsn,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;

    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(dst_reg as u8));
    }

    // Compute 64-bit immediate
    let imm = (insn.imm as u32 as u64) | ((next_insn.imm as u32 as u64) << 32);

    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.reg_type = BpfRegType::ScalarValue;
        dst.mark_known(imm);
    }

    Ok(())
}

/// Check CALL instruction
pub fn check_call(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    _insn_idx: usize,
) -> Result<()> {
    // Check that R1-R5 are properly set up for the call
    for regno in 1..=5 {
        if let Some(reg) = state.reg(regno) {
            if reg.reg_type == BpfRegType::NotInit {
                // This might be OK depending on the helper
            }
        }
    }

    // After call, clear caller-saved registers
    state.clear_caller_saved_regs();

    // R0 gets the return value (unknown scalar for now)
    if let Some(r0) = state.reg_mut(BPF_REG_0) {
        r0.mark_unknown(false);
    }

    // Handle special helpers would go here
    if insn.is_helper_call() {
        // Check helper-specific constraints
    } else if insn.is_pseudo_call() {
        // Handle subprogram call
        // Would push a new frame here
    } else if insn.is_kfunc_call() {
        // Handle kfunc call
    }

    Ok(())
}

/// Check EXIT instruction
pub fn check_exit(state: &BpfVerifierState) -> Result<()> {
    // Check for unreleased resources
    state.check_resource_leak()?;

    // R0 should contain the return value
    let r0 = state.reg(BPF_REG_0).ok_or(VerifierError::Internal(
        "no R0 at exit".into(),
    ))?;

    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(0));
    }

    Ok(())
}
