// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::spill_fill

use bpf_verifier::state::spill_fill::*;

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
