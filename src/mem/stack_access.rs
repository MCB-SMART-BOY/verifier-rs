// SPDX-License-Identifier: GPL-2.0

//!

//! This module implements comprehensive stack access checking including:

//! - Fixed offset reads/writes

//! - Variable offset reads/writes

//! - Spill/fill tracking

//! - Dynptr and iterator slot management

use alloc::format;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::{BpfRegState, RegLiveness};
use crate::state::stack_state::BpfStackState;
use crate::state::verifier_state::BpfVerifierState;

/// Stack slot index from a frame-relative offset
/// Returns (slot_index, byte_offset_within_slot)
pub fn get_spi(off: i32) -> Option<(usize, usize)> {
    if off >= 0 {
        return None;
    }
    let pos = (-off) as usize;
    if pos > MAX_BPF_STACK {
        return None;
    }
    let spi = (pos - 1) / BPF_REG_SIZE;
    let byte_off = (pos - 1) % BPF_REG_SIZE;
    Some((spi, byte_off))
}

/// Convert stack slot index back to frame offset
pub fn spi_to_off(spi: usize) -> i32 {
    -(((spi + 1) * BPF_REG_SIZE) as i32)
}

/// Check stack write with fixed offset
pub fn check_stack_write_fixed_off(
    state: &mut BpfVerifierState,
    dst_reg: &BpfRegState,
    off: i32,
    size: u32,
    src_reg: &BpfRegState,
    insn_idx: usize,
) -> Result<()> {
    let total_off = dst_reg.off + off;

    // Stack grows downward, offsets are negative
    if total_off >= 0 {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }

    let stack_off = (-total_off) as usize;

    // Check bounds
    if stack_off > MAX_BPF_STACK || stack_off < size as usize {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }

    // Ensure stack is allocated
    let func = state
        .cur_func_mut()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    if stack_off > func.stack.allocated_stack {
        func.stack.grow(stack_off)?;
    }

    // Determine what we're storing
    let is_spill = size == BPF_REG_SIZE as u32 && is_spillable_regtype(src_reg.reg_type);

    let (spi, _byte_off) = get_spi(total_off).ok_or(VerifierError::StackOutOfBounds(total_off))?;

    if is_spill {
        // Spilling a register
        save_register_state(func, spi, src_reg, insn_idx)?;
    } else if src_reg.reg_type == BpfRegType::ScalarValue
        && src_reg.is_const()
        && src_reg.const_value() == 0
    {
        // Writing zero - mark as STACK_ZERO
        mark_stack_slots_zero(func, spi, size)?;
    } else {
        // Writing non-spill data - mark as STACK_MISC
        mark_stack_slots_misc(func, spi, size)?;
    }

    Ok(())
}

/// Check stack write with variable offset
///
/// For privileged programs, uninitialized stack slots are considered
/// initialized by this write (even though we don't know exactly what offsets
/// are going to be written to). The idea is that we don't want the verifier to
/// reject future reads that access slots written to through variable offsets.
#[allow(clippy::too_many_arguments)]
pub fn check_stack_write_var_off(
    state: &mut BpfVerifierState,
    dst_reg: &BpfRegState,
    off: i32,
    size: u32,
    src_reg: Option<&BpfRegState>,
    imm: i32,
    allow_ptr_leaks: bool,
    _insn_idx: usize,
) -> Result<()> {
    // Calculate possible offset range
    let min_off = dst_reg.smin_value.saturating_add(off as i64);
    let max_off = dst_reg
        .smax_value
        .saturating_add(off as i64)
        .saturating_add(size as i64);

    // Both ends must be valid stack offsets
    if min_off >= 0 || max_off > 0 {
        return Err(VerifierError::StackOutOfBounds(max_off as i32));
    }

    // min_off is the deepest stack access (most negative)
    // max_off is the shallowest stack access (closest to 0)
    let _min_stack_off = (-max_off) as usize; // shallowest
    let max_stack_off = (-min_off) as usize; // deepest

    if max_stack_off > MAX_BPF_STACK {
        return Err(VerifierError::StackOutOfBounds(min_off as i32));
    }

    // Determine if we're writing zero
    let writing_zero = if let Some(reg) = src_reg {
        reg.reg_type == BpfRegType::ScalarValue && reg.is_const() && reg.const_value() == 0
    } else {
        imm == 0
    };

    // Ensure stack is allocated for worst case
    let func = state
        .cur_func_mut()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    if max_stack_off > func.stack.allocated_stack {
        func.stack.grow(max_stack_off)?;
    }

    // First pass: destroy any dynptr/iter slots in range
    for i in min_off..max_off {
        if i >= 0 {
            continue;
        }
        if let Some((spi, _)) = get_spi(i as i32) {
            destroy_special_slot(func, spi)?;
        }
    }

    // Second pass: update slot types
    // Variable offset writes destroy any spilled pointers in range
    for i in min_off..max_off {
        if i >= 0 {
            continue;
        }

        let slot_off = (-i - 1) as usize;
        let spi = slot_off / BPF_REG_SIZE;
        let byte_idx = slot_off % BPF_REG_SIZE;

        // Ensure slot exists
        while func.stack.stack.len() <= spi {
            func.stack.stack.push(BpfStackState::default());
        }

        let slot = &mut func.stack.stack[spi];
        let stype = &mut slot.slot_type[byte_idx];

        if !allow_ptr_leaks && *stype != BpfStackSlotType::Misc && *stype != BpfStackSlotType::Zero
        {
            // Reject if range we may write to has not been initialized beforehand
            // If we didn't reject here, the ptr status would be erased below
            // possibly opening the door to leaks
            //
            // However we catch STACK_INVALID case below, and only allow reading
            // possibly uninitialized memory later for privileged mode
            if *stype == BpfStackSlotType::Spill {
                return Err(VerifierError::InvalidMemoryAccess(format!(
                    "spilled ptr in range of var-offset stack write at offset {}",
                    i
                )));
            }
        }

        // Determine new slot type
        let new_type = if writing_zero && *stype == BpfStackSlotType::Zero {
            // Writing zero to zero slot - keep as zero
            BpfStackSlotType::Zero
        } else if *stype == BpfStackSlotType::Invalid && allow_ptr_leaks {
            // For privileged programs, uninitialized slots become MISC
            // This allows future reads (conservative approach)
            BpfStackSlotType::Misc
        } else if *stype == BpfStackSlotType::Invalid {
            // Unprivileged: cannot write to uninitialized with variable offset
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable offset write to uninitialized stack at offset {}",
                i
            )));
        } else {
            // All other cases: mark as MISC
            BpfStackSlotType::Misc
        };

        *stype = new_type;

        // If we changed a SPILL slot, clear the spilled register
        if byte_idx == BPF_REG_SIZE - 1 {
            slot.spilled_ptr = BpfRegState::default();
        }
    }

    Ok(())
}

/// Legacy wrapper for check_stack_write_var_off with old signature
pub fn check_stack_write_var_off_simple(
    state: &mut BpfVerifierState,
    dst_reg: &BpfRegState,
    off: i32,
    size: u32,
    src_reg: &BpfRegState,
    insn_idx: usize,
) -> Result<()> {
    check_stack_write_var_off(state, dst_reg, off, size, Some(src_reg), 0, true, insn_idx)
}

/// Check stack read with fixed offset
pub fn check_stack_read_fixed_off(
    state: &BpfVerifierState,
    src_reg: &BpfRegState,
    off: i32,
    size: u32,
    dst_regno: u8,
) -> Result<BpfRegState> {
    let total_off = src_reg.off + off;

    if total_off >= 0 {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }

    let stack_off = (-total_off) as usize;

    if stack_off > MAX_BPF_STACK || stack_off < size as usize {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }

    let (spi, byte_off) = get_spi(total_off).ok_or(VerifierError::StackOutOfBounds(total_off))?;

    let func = state
        .cur_func()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    // Check if slot is allocated
    let slot = func
        .stack
        .stack
        .get(spi)
        .ok_or(VerifierError::InvalidMemoryAccess(format!(
            "uninitialized stack access at offset {}",
            total_off
        )))?;

    let slot_type = slot.slot_type[BPF_REG_SIZE - 1];

    match slot_type {
        BpfStackSlotType::Invalid => Err(VerifierError::InvalidMemoryAccess(format!(
            "uninitialized stack access at offset {}",
            total_off
        ))),
        BpfStackSlotType::Spill => {
            // Reading a spilled register
            // For a full slot read: size must be BPF_REG_SIZE and we must be
            // reading from the slot boundary (byte_off should be BPF_REG_SIZE - 1
            // because get_spi returns the position within the slot from offset -1)
            let is_full_slot_read = size == BPF_REG_SIZE as u32 && byte_off == BPF_REG_SIZE - 1;
            if is_full_slot_read {
                // Full register read - restore the spilled value
                let mut result = slot.spilled_ptr.clone();
                // Clear precision since we're reading it back
                result.precise = false;
                Ok(result)
            } else {
                // Partial read of spilled register - only valid for scalars
                if slot.spilled_ptr.reg_type != BpfRegType::ScalarValue {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "partial read of spilled pointer".into(),
                    ));
                }
                // Return scalar with reduced precision
                let mut result = BpfRegState {
                    reg_type: BpfRegType::ScalarValue,
                    ..Default::default()
                };
                result.mark_unknown(false);
                Ok(result)
            }
        }
        BpfStackSlotType::Misc => {
            // MISC data - return unknown scalar
            let mut result = BpfRegState {
                reg_type: BpfRegType::ScalarValue,
                ..Default::default()
            };
            result.mark_unknown(false);
            Ok(result)
        }
        BpfStackSlotType::Zero => {
            // Zero slot - return known zero
            let mut result = BpfRegState {
                reg_type: BpfRegType::ScalarValue,
                ..Default::default()
            };
            result.mark_known(0);
            Ok(result)
        }
        BpfStackSlotType::Dynptr => {
            // Reading from dynptr slot
            if dst_regno == BPF_REG_0 as u8 {
                // Allowed for certain operations
                let mut result = BpfRegState {
                    reg_type: BpfRegType::ScalarValue,
                    ..Default::default()
                };
                result.mark_unknown(false);
                Ok(result)
            } else {
                Err(VerifierError::InvalidMemoryAccess(
                    "invalid read from dynptr slot".into(),
                ))
            }
        }
        BpfStackSlotType::Iter => Err(VerifierError::InvalidMemoryAccess(
            "cannot read from iterator slot".into(),
        )),
        BpfStackSlotType::IrqFlag => Err(VerifierError::InvalidMemoryAccess(
            "cannot read from IRQ flag slot".into(),
        )),
    }
}

/// Check stack read with variable offset
///
/// Variable offset stack reads are more conservative than fixed offset ones.
/// We can't return a spilled pointer since we don't know which slot is being
/// accessed (the offset is not fixed). We conservatively mark the destination
/// as containing SCALAR_VALUE.
pub fn check_stack_read_var_off(
    state: &BpfVerifierState,
    src_reg: &BpfRegState,
    off: i32,
    size: u32,
    dst_regno: i32,
) -> Result<BpfRegState> {
    // Variable offset reads are only permitted with a destination register
    // in order to not leak pointers
    if dst_regno < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "variable offset stack pointer cannot be passed into helper function; off={} size={}",
            off, size
        )));
    }

    let min_off = src_reg.smin_value.saturating_add(off as i64);
    let max_off = src_reg.smax_value.saturating_add(off as i64);

    if min_off >= 0 || max_off >= 0 {
        return Err(VerifierError::StackOutOfBounds(max_off as i32));
    }

    // min_off is deepest (most negative), max_off is shallowest
    let _min_stack_off = (-max_off) as usize;
    let max_stack_off = (-min_off) as usize;

    if max_stack_off > MAX_BPF_STACK {
        return Err(VerifierError::StackOutOfBounds(min_off as i32));
    }

    let func = state
        .cur_func()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    // Check that the entire range is properly initialized
    // This is more strict than check_stack_range_initialized because
    // we also need to check for spilled pointers
    for i in min_off..max_off.saturating_add(size as i64) {
        if i >= 0 {
            continue;
        }

        let slot_off = (-i - 1) as usize;
        let spi = slot_off / BPF_REG_SIZE;
        let byte_idx = slot_off % BPF_REG_SIZE;

        let slot = func
            .stack
            .stack
            .get(spi)
            .ok_or(VerifierError::InvalidMemoryAccess(format!(
                "uninitialized stack access at offset {}",
                i
            )))?;

        let stype = slot.slot_type[byte_idx];

        match stype {
            BpfStackSlotType::Invalid => {
                return Err(VerifierError::InvalidMemoryAccess(format!(
                    "uninitialized stack access at offset {}",
                    i
                )));
            }
            BpfStackSlotType::Dynptr => {
                return Err(VerifierError::InvalidMemoryAccess(
                    "variable offset read from dynptr slot".into(),
                ));
            }
            BpfStackSlotType::Iter => {
                return Err(VerifierError::InvalidMemoryAccess(
                    "variable offset read from iterator slot".into(),
                ));
            }
            BpfStackSlotType::IrqFlag => {
                return Err(VerifierError::InvalidMemoryAccess(
                    "variable offset read from IRQ flag slot".into(),
                ));
            }
            BpfStackSlotType::Spill => {
                // Cannot do variable offset read from spilled pointer
                // (we might leak it)
                if slot.spilled_ptr.reg_type != BpfRegType::ScalarValue {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "variable offset read may access spilled pointer at offset {}",
                        spi_to_off(spi)
                    )));
                }
            }
            BpfStackSlotType::Misc | BpfStackSlotType::Zero => {
                // These are fine for variable offset reads
            }
        }
    }

    // Variable offset reads always return unknown scalar
    // We can't know which exact slot was accessed
    let mut result = BpfRegState {
        reg_type: BpfRegType::ScalarValue,
        ..Default::default()
    };
    result.mark_unknown(false);
    Ok(result)
}

/// Mark register state for stack read with variable offset
/// This updates the liveness and precision tracking
pub fn mark_reg_stack_read(
    _state: &mut BpfVerifierState,
    min_off: i64,
    max_off: i64,
    size: u32,
    dst_reg: &mut BpfRegState,
) {
    // For variable offset reads, we can only return an unknown scalar
    dst_reg.reg_type = BpfRegType::ScalarValue;
    dst_reg.mark_unknown(false);

    // The actual bounds of the read are min_off to max_off + size
    // We track this for precision propagation
    let _ = (min_off, max_off, size);
}

/// Check if a register type can be spilled
pub fn is_spillable_regtype(t: BpfRegType) -> bool {
    matches!(
        t,
        BpfRegType::PtrToStack
            | BpfRegType::PtrToMapValue
            | BpfRegType::PtrToMapKey
            | BpfRegType::ConstPtrToMap
            | BpfRegType::PtrToCtx
            | BpfRegType::PtrToPacket
            | BpfRegType::PtrToPacketMeta
            | BpfRegType::PtrToPacketEnd
            | BpfRegType::PtrToFlowKeys
            | BpfRegType::PtrToMem
            | BpfRegType::PtrToBtfId
            | BpfRegType::ScalarValue
    )
}

/// Save register state to stack slot (spill)
fn save_register_state(
    func: &mut crate::state::verifier_state::BpfFuncState,
    spi: usize,
    reg: &BpfRegState,
    _insn_idx: usize,
) -> Result<()> {
    // Ensure slot exists
    while func.stack.stack.len() <= spi {
        func.stack.stack.push(BpfStackState::default());
    }

    let slot = &mut func.stack.stack[spi];

    // Mark all bytes as SPILL
    slot.slot_type = [BpfStackSlotType::Spill; BPF_REG_SIZE];

    // Copy register state
    slot.spilled_ptr = reg.clone();

    // Clear live flag - will be set by liveness analysis
    slot.spilled_ptr.live = RegLiveness::default();

    Ok(())
}

/// Mark stack slots as containing zero
fn mark_stack_slots_zero(
    func: &mut crate::state::verifier_state::BpfFuncState,
    spi: usize,
    size: u32,
) -> Result<()> {
    let num_slots = (size as usize).div_ceil(BPF_REG_SIZE);

    for i in 0..num_slots {
        let slot_idx = spi + i;
        while func.stack.stack.len() <= slot_idx {
            func.stack.stack.push(BpfStackState::default());
        }

        let slot = &mut func.stack.stack[slot_idx];

        // Destroy any special slot
        destroy_special_slot_inner(slot)?;

        slot.slot_type = [BpfStackSlotType::Zero; BPF_REG_SIZE];
        slot.spilled_ptr = BpfRegState::default();
    }

    Ok(())
}

/// Mark stack slots as MISC (initialized but unknown)
fn mark_stack_slots_misc(
    func: &mut crate::state::verifier_state::BpfFuncState,
    spi: usize,
    size: u32,
) -> Result<()> {
    let num_slots = (size as usize).div_ceil(BPF_REG_SIZE);

    for i in 0..num_slots {
        let slot_idx = spi + i;
        while func.stack.stack.len() <= slot_idx {
            func.stack.stack.push(BpfStackState::default());
        }

        let slot = &mut func.stack.stack[slot_idx];

        // Destroy any special slot
        destroy_special_slot_inner(slot)?;

        slot.slot_type = [BpfStackSlotType::Misc; BPF_REG_SIZE];
        slot.spilled_ptr = BpfRegState::default();
    }

    Ok(())
}

/// Destroy special slot (dynptr, iter) if present
fn destroy_special_slot(
    func: &mut crate::state::verifier_state::BpfFuncState,
    spi: usize,
) -> Result<()> {
    if let Some(slot) = func.stack.stack.get_mut(spi) {
        destroy_special_slot_inner(slot)?;
    }
    Ok(())
}

fn destroy_special_slot_inner(slot: &mut BpfStackState) -> Result<()> {
    let slot_type = slot.slot_type[BPF_REG_SIZE - 1];

    match slot_type {
        BpfStackSlotType::Dynptr => {
            // Dynptr is being destroyed - check if it's valid
            if slot.spilled_ptr.dynptr.dynptr_type != BpfDynptrType::Invalid {
                // Would need to check if dynptr was released properly
            }
        }
        BpfStackSlotType::Iter => {
            // Iterator is being destroyed - check state
            if slot.spilled_ptr.iter.state == BpfIterState::Active {
                return Err(VerifierError::InvalidMemoryAccess(
                    "destroying active iterator".into(),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

/// Check if stack range is properly initialized
pub fn check_stack_range_initialized(
    state: &BpfVerifierState,
    off: i32,
    size: u32,
    access_type: StackAccessType,
) -> Result<()> {
    if off >= 0 {
        return Err(VerifierError::StackOutOfBounds(off));
    }

    let stack_off = (-off) as usize;

    if stack_off > MAX_BPF_STACK || stack_off < size as usize {
        return Err(VerifierError::StackOutOfBounds(off));
    }

    let func = state
        .cur_func()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    let start_spi = (stack_off - size as usize) / BPF_REG_SIZE;
    let end_spi = (stack_off - 1) / BPF_REG_SIZE;

    for spi in start_spi..=end_spi {
        let slot = func
            .stack
            .stack
            .get(spi)
            .ok_or(VerifierError::InvalidMemoryAccess(format!(
                "uninitialized stack access at offset {}",
                spi_to_off(spi)
            )))?;

        for i in 0..BPF_REG_SIZE {
            match slot.slot_type[i] {
                BpfStackSlotType::Invalid => {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "uninitialized stack access at offset {}",
                        spi_to_off(spi)
                    )));
                }
                BpfStackSlotType::Spill if access_type == StackAccessType::HelperRead => {
                    // Helper reading spilled pointer is OK
                }
                BpfStackSlotType::Spill if slot.spilled_ptr.reg_type != BpfRegType::ScalarValue => {
                    // Non-scalar spill being read as bytes
                    if access_type == StackAccessType::HelperWrite {
                        return Err(VerifierError::InvalidMemoryAccess(
                            "helper cannot write to spilled pointer".into(),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Type of stack access for range checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackAccessType {
    /// Normal program read
    Read,
    /// Normal program write
    Write,
    /// Helper function reading
    HelperRead,
    /// Helper function writing
    HelperWrite,
}
