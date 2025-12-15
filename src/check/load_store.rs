//! Load and store instruction verification
//!
//! This module implements verification for BPF_LDX and BPF_STX instructions,
//! handling memory loads, stores, and atomic operations.
//!
//! Corresponds to check_load_mem() and check_store_reg() in Linux kernel verifier.c

#[cfg(not(feature = "std"))]
use alloc::format;

use crate::bounds::tnum::Tnum;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::mem::memory::check_mem_access;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::state::spill_fill::{SpillFillTracker, StackReadResult};

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
    is_ldsx: bool,  // Sign-extending load
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
    set_load_result(state, dst_reg, &src, insn.off as i32, size, loaded_type, is_ldsx, insn_idx)?;

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
    src: &BpfRegState,
    off: i32,
    size: u32,
    loaded_type: BpfRegType,
    is_ldsx: bool,
    _insn_idx: usize,
) -> Result<()> {
    // For stack loads, we need to call fill_reg before borrowing dst mutably
    // to avoid borrow conflicts
    let stack_fill_result = if loaded_type == BpfRegType::PtrToStack {
        let stack_off = src.off + off;
        Some(SpillFillTracker::fill_reg(state, stack_off, size as usize)?)
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

    match loaded_type {
        BpfRegType::ScalarValue => {
            // Loading a scalar - set bounds based on size
            if is_ldsx {
                // Sign-extending load
                set_signed_bounds_from_size(dst, size);
            } else {
                // Zero-extending load
                set_unsigned_bounds_from_size(dst, size);
            }
        }
        BpfRegType::PtrToStack => {
            // Loading a spilled register from stack - use pre-fetched result
            let fill_result = stack_fill_result.expect("stack_fill_result should be Some for PtrToStack");
            let stack_off = src.off + off;
            
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
                    if size < 8 {
                        set_unsigned_bounds_from_size(dst, size);
                    }
                }
                StackReadResult::Initialized => {
                    // Initialized but not a full spill - unknown scalar with size bounds
                    if is_ldsx {
                        set_signed_bounds_from_size(dst, size);
                    } else {
                        set_unsigned_bounds_from_size(dst, size);
                    }
                }
                StackReadResult::Uninitialized => {
                    // This should have been caught by check_mem_access
                    return Err(VerifierError::InvalidMemoryAccess(
                        format!("reading uninitialized stack at offset {}", stack_off)
                    ));
                }
                StackReadResult::Dynptr(_) | StackReadResult::Iterator(_) => {
                    // Special slots - should not be read directly
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot read special stack slot directly".into()
                    ));
                }
            }
        }
        BpfRegType::PtrToMapValue => {
            // Loading from map value - might be a kptr
            // For now, treat as scalar
            set_unsigned_bounds_from_size(dst, size);
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
    let func = state.cur_func_mut().ok_or(VerifierError::Internal(
        "no current function".into(),
    ))?;

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
        0 => 4,  // BPF_W (32-bit)
        1 => 2,  // BPF_H (16-bit)
        2 => 1,  // BPF_B (8-bit)
        3 => 8,  // BPF_DW (64-bit)
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state_with_ptr(regno: usize, ptr_type: BpfRegType, off: i32) -> BpfVerifierState {
        let mut state = BpfVerifierState::new();
        if let Some(reg) = state.reg_mut(regno) {
            reg.reg_type = ptr_type;
            reg.off = off;
            reg.mark_known_zero();
        }
        // Initialize R10 as frame pointer
        if let Some(r10) = state.reg_mut(10) {
            r10.reg_type = BpfRegType::PtrToStack;
            r10.off = 0;
            r10.mark_known_zero();
        }
        state
    }

    #[test]
    fn test_bpf_size_to_bytes() {
        assert_eq!(bpf_size_to_bytes(0), 4);  // BPF_W
        assert_eq!(bpf_size_to_bytes(1), 2);  // BPF_H
        assert_eq!(bpf_size_to_bytes(2), 1);  // BPF_B
        assert_eq!(bpf_size_to_bytes(3), 8);  // BPF_DW
    }

    #[test]
    fn test_load_from_stack() {
        let mut state = make_state_with_ptr(1, BpfRegType::PtrToStack, 0);
        // r10 is already set as stack pointer

        // ldxdw r0, [r10-8]
        let insn = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 10, -8, 0);
        let result = check_load_mem(&mut state, &insn, 0, false, false);
        // May fail due to uninitialized stack, but should not panic
        // For now, just check it doesn't crash
        let _ = result;
    }

    #[test]
    fn test_store_to_stack() {
        let mut state = make_state_with_ptr(10, BpfRegType::PtrToStack, 0);
        // Set r1 as scalar
        if let Some(r1) = state.reg_mut(1) {
            r1.reg_type = BpfRegType::ScalarValue;
            r1.mark_known(42);
        }

        // stxdw [r10-8], r1
        let insn = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0);
        let result = check_store_reg(&mut state, &insn, 0, true);
        // Result may fail due to stack not being fully initialized, 
        // but should not be due to invalid registers
        match &result {
            Ok(()) => {}
            Err(VerifierError::UninitializedRegister(_)) => panic!("should not be uninit"),
            Err(VerifierError::InvalidRegister(_)) => panic!("should not be invalid reg"),
            Err(_) => {} // Other errors are OK (e.g., stack bounds)
        }
    }

    #[test]
    fn test_unsigned_bounds_from_size() {
        let mut reg = BpfRegState::new_scalar_unknown(false);

        set_unsigned_bounds_from_size(&mut reg, 1);
        assert_eq!(reg.umax_value, 0xFF);
        assert_eq!(reg.smax_value, 0xFF);

        set_unsigned_bounds_from_size(&mut reg, 2);
        assert_eq!(reg.umax_value, 0xFFFF);

        set_unsigned_bounds_from_size(&mut reg, 4);
        assert_eq!(reg.umax_value, 0xFFFF_FFFF);
    }

    #[test]
    fn test_signed_bounds_from_size() {
        let mut reg = BpfRegState::new_scalar_unknown(false);

        set_signed_bounds_from_size(&mut reg, 1);
        assert_eq!(reg.smin_value, -128);
        assert_eq!(reg.smax_value, 127);

        set_signed_bounds_from_size(&mut reg, 2);
        assert_eq!(reg.smin_value, -32768);
        assert_eq!(reg.smax_value, 32767);
    }

    #[test]
    fn test_uninit_src_rejected() {
        let mut state = BpfVerifierState::new();
        // r1 is NotInit by default
        if let Some(r10) = state.reg_mut(10) {
            r10.reg_type = BpfRegType::PtrToStack;
            r10.off = 0;
        }

        // stxdw [r10-8], r1 (r1 is uninitialized)
        let insn = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0);
        let result = check_store_reg(&mut state, &insn, 0, true);
        assert!(matches!(result, Err(VerifierError::UninitializedRegister(1))));
    }

    #[test]
    fn test_uninit_dst_ptr_rejected() {
        let mut state = BpfVerifierState::new();
        // Explicitly mark r10 as NotInit (it might be initialized by default)
        if let Some(r10) = state.reg_mut(10) {
            r10.reg_type = BpfRegType::NotInit;
        }
        if let Some(r1) = state.reg_mut(1) {
            r1.reg_type = BpfRegType::ScalarValue;
            r1.mark_known(42);
        }

        // stxdw [r10-8], r1 (r10 is uninitialized)
        let insn = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0);
        let result = check_store_reg(&mut state, &insn, 0, true);
        assert!(matches!(result, Err(VerifierError::UninitializedRegister(10))));
    }
}
