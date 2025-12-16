// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::stack_state

use bpf_verifier::state::stack_state::*;

use super::*;

    #[test]
    fn test_offset_to_slot() {
        let stack = StackState::new();
        assert_eq!(stack.offset_to_slot(-8), Some(0));
        assert_eq!(stack.offset_to_slot(-16), Some(1));
        assert_eq!(stack.offset_to_slot(-24), Some(2));
        assert_eq!(stack.offset_to_slot(0), None);
        assert_eq!(stack.offset_to_slot(8), None);
    }

    #[test]
    fn test_spill_fill() {
        let mut stack = StackState::new();
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 0;
        reg.umax_value = 100;

        stack.spill_reg(-8, &reg).unwrap();
        assert!(stack.stack[0].is_spill());

        let filled = stack.fill_reg(-8).unwrap();
        assert_eq!(filled.reg_type, BpfRegType::ScalarValue);
        assert_eq!(filled.umax_value, 100);
    }

    #[test]
    fn test_write_misc() {
        let mut stack = StackState::new();
        stack.write_misc(-8, 4).unwrap();
        
        assert!(stack.stack[0].is_valid());
        assert!(!stack.stack[0].is_spill());
    }

    #[test]
    fn test_uninitialized_read() {
        let stack = StackState::new();
        let result = stack.fill_reg(-8);
        assert!(result.is_err());
    }

    #[test]
    fn test_allocated_stack() {
        let mut stack = StackState::new();
        assert_eq!(stack.allocated_bytes(), 0);

        stack.write_misc(-8, 8).unwrap();
        assert_eq!(stack.allocated_bytes(), 8);

        stack.write_misc(-24, 8).unwrap();
        assert_eq!(stack.allocated_bytes(), 24);
    }
