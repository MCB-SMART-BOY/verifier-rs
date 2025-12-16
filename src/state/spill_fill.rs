//! Register spill and fill tracking for stack operations.
//!
//! This module implements precise tracking of register values when they are
//! spilled to the stack and restored (filled) back to registers. This is
//! critical for maintaining precision through function calls and around
//! complex control flow.

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::{BpfStackState, get_spi};
use crate::state::verifier_state::BpfVerifierState;

/// Result of a stack read operation.
#[derive(Debug, Clone)]
pub enum StackReadResult {
    /// Successfully read a spilled register with full precision.
    SpilledReg(BpfRegState),
    /// Read initialized but imprecise data (scalar unknown).
    Initialized,
    /// Read zeroed data.
    Zero,
    /// Read uninitialized data (error).
    Uninitialized,
    /// Read a dynptr slot.
    Dynptr(BpfRegState),
    /// Read an iterator slot.
    Iterator(BpfRegState),
}

/// Spill/fill tracking context.
pub struct SpillFillTracker;

impl SpillFillTracker {
    /// Spill a register to the stack.
    ///
    /// This preserves the full register state including bounds and tnum
    /// so it can be precisely restored later.
    pub fn spill_reg(
        state: &mut BpfVerifierState,
        stack_off: i32,
        reg: &BpfRegState,
        size: usize,
    ) -> Result<()> {
        // Stack offset must be negative and aligned
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        // Grow stack if needed
        if abs_off > func.stack.allocated_stack {
            func.stack.grow(abs_off)?;
        }

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let slot = &mut func.stack.stack[spi];

        // Check for overlapping special slots
        if slot.is_special() {
            let slot_type = slot.get_type();
            match slot_type {
                BpfStackSlotType::Dynptr => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite dynptr slot".into(),
                    ));
                }
                BpfStackSlotType::Iter => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite iterator slot".into(),
                    ));
                }
                BpfStackSlotType::IrqFlag => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite IRQ flag slot".into(),
                    ));
                }
                _ => {}
            }
        }

        if size == BPF_REG_SIZE {
            // Full 64-bit spill - preserve full precision
            slot.mark_spill(reg);
        } else {
            // Partial write - mark affected bytes as misc
            Self::mark_partial_write(slot, stack_off, size);
        }

        Ok(())
    }

    /// Fill (restore) a register from the stack.
    ///
    /// Returns the register state if a full spill was found,
    /// otherwise returns appropriate result for partial/unknown data.
    pub fn fill_reg(
        state: &BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<StackReadResult> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state.cur_func().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            // Reading from unallocated stack
            return Ok(StackReadResult::Uninitialized);
        }

        let slot = &func.stack.stack[spi];
        let slot_type = slot.get_type();

        // Check slot types
        match slot_type {
            BpfStackSlotType::Spill => {
                if size == BPF_REG_SIZE && slot.is_spilled_scalar_reg64() {
                    // Full 64-bit read of a spilled register - restore with precision
                    Ok(StackReadResult::SpilledReg(slot.spilled_ptr.clone()))
                } else if size == BPF_REG_SIZE {
                    // Full read but not a scalar - still restore
                    Ok(StackReadResult::SpilledReg(slot.spilled_ptr.clone()))
                } else {
                    // Partial read of a spill - loses precision
                    Ok(StackReadResult::Initialized)
                }
            }
            BpfStackSlotType::Zero => {
                Ok(StackReadResult::Zero)
            }
            BpfStackSlotType::Misc => {
                // Initialized but unknown value
                Ok(StackReadResult::Initialized)
            }
            BpfStackSlotType::Invalid => {
                // Reading uninitialized data
                Ok(StackReadResult::Uninitialized)
            }
            BpfStackSlotType::Dynptr => {
                Ok(StackReadResult::Dynptr(slot.spilled_ptr.clone()))
            }
            BpfStackSlotType::Iter => {
                Ok(StackReadResult::Iterator(slot.spilled_ptr.clone()))
            }
            BpfStackSlotType::IrqFlag => {
                Err(VerifierError::InvalidMemoryAccess(
                    "cannot read IRQ flag directly".into(),
                ))
            }
        }
    }

    /// Check if a stack range is readable.
    pub fn check_stack_read(
        state: &BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<bool> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state.cur_func().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        // For stack access at offset -8 with size 8, we check the slot at SPI 0
        // The slot covers bytes at offsets -8 through -1
        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Ok(false); // Unallocated
        }

        let slot = &func.stack.stack[spi];

        // Check that all bytes in the range are initialized
        // For a full 8-byte read at the slot boundary, check all slot bytes
        if size == BPF_REG_SIZE {
            for i in 0..BPF_REG_SIZE {
                if slot.slot_type[i] == BpfStackSlotType::Invalid {
                    return Ok(false);
                }
            }
        } else {
            // Partial read - check specific bytes
            let start_byte = ((-stack_off - 1) as usize) % BPF_REG_SIZE;
            for i in 0..size {
                let byte_idx = (start_byte + BPF_REG_SIZE - i) % BPF_REG_SIZE;
                if byte_idx < BPF_REG_SIZE && slot.slot_type[byte_idx] == BpfStackSlotType::Invalid {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check if a stack range is writable (no special slots).
    pub fn check_stack_write(
        state: &BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<bool> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state.cur_func().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        // Check for special slots that cannot be overwritten
        for i in 0..size {
            let byte_off = stack_off - i as i32;
            let Some(spi) = get_spi(byte_off) else { continue; };

            if spi < func.stack.stack.len() {
                let slot = &func.stack.stack[spi];
                let slot_type = slot.get_type();

                match slot_type {
                    BpfStackSlotType::Dynptr
                    | BpfStackSlotType::Iter
                    | BpfStackSlotType::IrqFlag => {
                        return Ok(false);
                    }
                    _ => {}
                }
            }
        }

        Ok(true)
    }

    /// Mark a partial write (destroys existing spill precision).
    fn mark_partial_write(slot: &mut BpfStackState, off: i32, size: usize) {
        let start_byte = ((-off - 1) as usize) % BPF_REG_SIZE;

        for i in 0..size {
            let byte_idx = (start_byte + i) % BPF_REG_SIZE;
            if byte_idx < BPF_REG_SIZE {
                slot.slot_type[byte_idx] = BpfStackSlotType::Misc;
            }
        }

        // If we've partially overwritten a spill, it's no longer a valid spill
        let mut has_spill = false;
        let mut has_other = false;
        for i in 0..BPF_REG_SIZE {
            if slot.slot_type[i] == BpfStackSlotType::Spill {
                has_spill = true;
            } else if slot.slot_type[i] != BpfStackSlotType::Invalid {
                has_other = true;
            }
        }

        if has_spill && has_other {
            // Partially destroyed spill - convert all spill bytes to misc
            for i in 0..BPF_REG_SIZE {
                if slot.slot_type[i] == BpfStackSlotType::Spill {
                    slot.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
    }

    /// Store a zero value to the stack.
    pub fn store_zero(
        state: &mut BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<()> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        // Grow stack if needed
        if abs_off > func.stack.allocated_stack {
            func.stack.grow(abs_off)?;
        }

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let _slot = &mut func.stack.stack[spi];

        // Check for special slots
        if !Self::check_stack_write(state, stack_off, size)? {
            // Re-borrow for the actual write
            let func = state.cur_func_mut().ok_or(VerifierError::Internal(
                "no current function".into(),
            ))?;
            let slot = &mut func.stack.stack[spi];

            if slot.get_type() == BpfStackSlotType::Dynptr
                || slot.get_type() == BpfStackSlotType::Iter
                || slot.get_type() == BpfStackSlotType::IrqFlag
            {
                return Err(VerifierError::InvalidMemoryAccess(
                    "cannot overwrite special stack slot with zero".into(),
                ));
            }
        }

        // Re-borrow for the actual write
        let func = state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;
        let slot = &mut func.stack.stack[spi];

        if size == BPF_REG_SIZE {
            slot.mark_zero_full();
        } else {
            let start_byte = ((-stack_off - 1) as usize) % BPF_REG_SIZE;
            for i in 0..size {
                let byte_idx = (start_byte + i) % BPF_REG_SIZE;
                if byte_idx < BPF_REG_SIZE {
                    slot.slot_type[byte_idx] = BpfStackSlotType::Zero;
                }
            }
        }

        Ok(())
    }

    /// Scrub a spilled register (convert to misc when callee-saved).
    pub fn scrub_spill(
        state: &mut BpfVerifierState,
        stack_off: i32,
    ) -> Result<()> {
        if stack_off >= 0 {
            return Ok(());
        }

        let func = state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi < func.stack.stack.len() {
            let slot = &mut func.stack.stack[spi];
            if slot.is_spilled_reg() {
                slot.mark_misc_full();
            }
        }

        Ok(())
    }
}

/// Apply a fill operation result to a destination register.
pub fn apply_fill_result(dst: &mut BpfRegState, result: StackReadResult, size: usize) {
    match result {
        StackReadResult::SpilledReg(spilled) => {
            *dst = spilled;
        }
        StackReadResult::Zero => {
            dst.mark_known_zero();
            if size < BPF_REG_SIZE {
                // Partial read of zero - still zero but limited range
                dst.umax_value = (1u64 << (size * 8)) - 1;
            }
        }
        StackReadResult::Initialized => {
            dst.mark_unknown(false);
            if size < BPF_REG_SIZE {
                // Limit range based on size
                dst.umax_value = (1u64 << (size * 8)) - 1;
                dst.smax_value = dst.umax_value as i64;
            }
        }
        StackReadResult::Uninitialized => {
            // Should have been caught earlier as an error
            dst.mark_unknown(false);
        }
        StackReadResult::Dynptr(spilled) => {
            *dst = spilled;
        }
        StackReadResult::Iterator(spilled) => {
            *dst = spilled;
        }
    }
}
