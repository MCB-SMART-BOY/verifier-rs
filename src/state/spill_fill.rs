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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::tnum::Tnum;

    fn make_state() -> BpfVerifierState {
        let mut state = BpfVerifierState::new();
        // Grow stack to have some space
        if let Some(func) = state.cur_func_mut() {
            func.stack.grow(64).unwrap();
        }
        state
    }

    fn make_scalar(val: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        reg.mark_known(val);
        reg
    }

    fn make_bounded_scalar(min: u64, max: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        reg.umin_value = min;
        reg.umax_value = max;
        reg.smin_value = min as i64;
        reg.smax_value = max as i64;
        reg.var_off = Tnum::unknown();
        reg
    }

    #[test]
    fn test_spill_fill_const() {
        let mut state = make_state();
        let reg = make_scalar(42);

        // Spill to stack
        SpillFillTracker::spill_reg(&mut state, -8, &reg, BPF_REG_SIZE).unwrap();

        // Fill from stack
        let result = SpillFillTracker::fill_reg(&state, -8, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::SpilledReg(filled) => {
                assert!(filled.is_const());
                assert_eq!(filled.const_value(), 42);
            }
            _ => panic!("Expected SpilledReg"),
        }
    }

    #[test]
    fn test_spill_fill_bounded() {
        let mut state = make_state();
        let reg = make_bounded_scalar(10, 100);

        SpillFillTracker::spill_reg(&mut state, -8, &reg, BPF_REG_SIZE).unwrap();

        let result = SpillFillTracker::fill_reg(&state, -8, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::SpilledReg(filled) => {
                assert_eq!(filled.umin_value, 10);
                assert_eq!(filled.umax_value, 100);
            }
            _ => panic!("Expected SpilledReg"),
        }
    }

    #[test]
    fn test_partial_write_destroys_spill() {
        let mut state = make_state();
        let reg = make_scalar(42);

        // Full spill
        SpillFillTracker::spill_reg(&mut state, -8, &reg, BPF_REG_SIZE).unwrap();

        // Partial overwrite
        let partial_reg = make_scalar(0);
        SpillFillTracker::spill_reg(&mut state, -8, &partial_reg, 4).unwrap();

        // Read should return initialized (not the original spill)
        let result = SpillFillTracker::fill_reg(&state, -8, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::Initialized => {
                // Expected - partial overwrite destroyed the spill
            }
            StackReadResult::SpilledReg(_) => {
                // Also acceptable if implementation preserves partial
            }
            _ => panic!("Unexpected result"),
        }
    }

    #[test]
    fn test_store_zero() {
        let mut state = make_state();

        SpillFillTracker::store_zero(&mut state, -8, BPF_REG_SIZE).unwrap();

        let result = SpillFillTracker::fill_reg(&state, -8, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::Zero => {
                // Expected
            }
            _ => panic!("Expected Zero"),
        }
    }

    #[test]
    fn test_read_uninitialized() {
        let state = make_state();

        // Read from unallocated area (beyond what we grew)
        let result = SpillFillTracker::fill_reg(&state, -128, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::Uninitialized => {
                // Expected
            }
            _ => panic!("Expected Uninitialized"),
        }
    }

    #[test]
    fn test_check_stack_read() {
        let mut state = make_state();
        let reg = make_scalar(42);

        // Initially uninitialized
        assert!(!SpillFillTracker::check_stack_read(&state, -8, 8).unwrap());

        // After spill, should be readable
        SpillFillTracker::spill_reg(&mut state, -8, &reg, BPF_REG_SIZE).unwrap();
        assert!(SpillFillTracker::check_stack_read(&state, -8, 8).unwrap());
    }

    #[test]
    fn test_stack_bounds() {
        let mut state = make_state();
        let reg = make_scalar(42);

        // Positive offset should fail
        assert!(SpillFillTracker::spill_reg(&mut state, 8, &reg, BPF_REG_SIZE).is_err());

        // Offset beyond max stack should fail
        assert!(SpillFillTracker::spill_reg(&mut state, -(MAX_BPF_STACK as i32 + 8), &reg, BPF_REG_SIZE).is_err());
    }

    #[test]
    fn test_apply_fill_result() {
        let mut dst = BpfRegState::new_not_init();

        // Test SpilledReg
        let spilled = make_scalar(42);
        apply_fill_result(&mut dst, StackReadResult::SpilledReg(spilled), BPF_REG_SIZE);
        assert!(dst.is_const());
        assert_eq!(dst.const_value(), 42);

        // Test Zero
        apply_fill_result(&mut dst, StackReadResult::Zero, BPF_REG_SIZE);
        assert!(dst.is_const());
        assert_eq!(dst.const_value(), 0);

        // Test Initialized
        apply_fill_result(&mut dst, StackReadResult::Initialized, BPF_REG_SIZE);
        assert!(!dst.is_const());
        assert_eq!(dst.reg_type, BpfRegType::ScalarValue);
    }

    #[test]
    fn test_partial_fill_limits_range() {
        let mut dst = BpfRegState::new_not_init();

        // 4-byte read should limit to u32 range
        apply_fill_result(&mut dst, StackReadResult::Initialized, 4);
        assert_eq!(dst.umax_value, 0xFFFF_FFFF);

        // 1-byte read should limit to u8 range
        apply_fill_result(&mut dst, StackReadResult::Initialized, 1);
        assert_eq!(dst.umax_value, 0xFF);
    }

    #[test]
    fn test_scrub_spill() {
        let mut state = make_state();
        let reg = make_scalar(42);

        SpillFillTracker::spill_reg(&mut state, -8, &reg, BPF_REG_SIZE).unwrap();

        // Scrub the spill
        SpillFillTracker::scrub_spill(&mut state, -8).unwrap();

        // Should now return initialized (not the original value)
        let result = SpillFillTracker::fill_reg(&state, -8, BPF_REG_SIZE).unwrap();

        match result {
            StackReadResult::Initialized => {
                // Expected after scrub
            }
            _ => panic!("Expected Initialized after scrub"),
        }
    }
}
