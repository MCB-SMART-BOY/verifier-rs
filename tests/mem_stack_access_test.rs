// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::stack_access

use bpf_verifier::mem::stack_access::*;

use super::*;

    #[test]
    fn test_get_spi() {
        // Offset -8 = first slot (spi=0)
        assert_eq!(get_spi(-8), Some((0, 7)));
        
        // Offset -1 = first byte of first slot
        assert_eq!(get_spi(-1), Some((0, 0)));
        
        // Offset -16 = second slot
        assert_eq!(get_spi(-16), Some((1, 7)));
        
        // Positive offset is invalid
        assert_eq!(get_spi(0), None);
        assert_eq!(get_spi(1), None);
    }

    #[test]
    fn test_spi_to_off() {
        assert_eq!(spi_to_off(0), -8);
        assert_eq!(spi_to_off(1), -16);
        assert_eq!(spi_to_off(63), -512);
    }

    #[test]
    fn test_is_spillable_regtype() {
        assert!(is_spillable_regtype(BpfRegType::ScalarValue));
        assert!(is_spillable_regtype(BpfRegType::PtrToStack));
        assert!(is_spillable_regtype(BpfRegType::PtrToMapValue));
        assert!(!is_spillable_regtype(BpfRegType::NotInit));
    }

    #[test]
    fn test_stack_write_read_roundtrip() {
        let mut state = BpfVerifierState::new();
        
        // Create a source register with known value
        let mut src_reg = BpfRegState::default();
        src_reg.reg_type = BpfRegType::ScalarValue;
        src_reg.mark_known(42);
        
        // Create destination register pointing to stack
        let mut dst_reg = BpfRegState::default();
        dst_reg.reg_type = BpfRegType::PtrToStack;
        dst_reg.off = 0;
        
        // Write to stack
        let result = check_stack_write_fixed_off(
            &mut state, &dst_reg, -8, 8, &src_reg, 0
        );
        assert!(result.is_ok());
        
        // Read back
        let read_result = check_stack_read_fixed_off(
            &state, &dst_reg, -8, 8, 0
        );
        assert!(read_result.is_ok());
        
        let read_reg = read_result.unwrap();
        assert_eq!(read_reg.reg_type, BpfRegType::ScalarValue);
        assert!(read_reg.is_const());
        assert_eq!(read_reg.const_value(), 42);
    }

    #[test]
    fn test_stack_uninitialized_read() {
        let state = BpfVerifierState::new();
        
        let mut src_reg = BpfRegState::default();
        src_reg.reg_type = BpfRegType::PtrToStack;
        src_reg.off = 0;
        
        // Try to read from uninitialized stack
        let result = check_stack_read_fixed_off(&state, &src_reg, -8, 8, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_stack_access_type() {
        assert_eq!(StackAccessType::Read, StackAccessType::Read);
        assert_ne!(StackAccessType::Read, StackAccessType::Write);
    }

    #[test]
    fn test_var_off_stack_write_basic() {
        let mut state = BpfVerifierState::new();
        
        // Initialize some stack slots first (privileged mode requires this for unprivileged)
        {
            let mut init_reg = BpfRegState::default();
            init_reg.reg_type = BpfRegType::ScalarValue;
            init_reg.mark_known(0);
            
            let mut ptr_reg = BpfRegState::default();
            ptr_reg.reg_type = BpfRegType::PtrToStack;
            ptr_reg.off = 0;
            
            // Initialize slots -8 to -24
            for off in [-8, -16, -24].iter() {
                let _ = check_stack_write_fixed_off(&mut state, &ptr_reg, *off, 8, &init_reg, 0);
            }
        }
        
        // Create a register with variable offset (range -16 to -8)
        let mut var_reg = BpfRegState::default();
        var_reg.reg_type = BpfRegType::PtrToStack;
        var_reg.smin_value = -16;
        var_reg.smax_value = -8;
        var_reg.off = 0;
        
        let mut src_reg = BpfRegState::default();
        src_reg.reg_type = BpfRegType::ScalarValue;
        src_reg.mark_known(123);
        
        // Variable offset write should succeed for initialized range
        let result = check_stack_write_var_off(
            &mut state, &var_reg, 0, 4, Some(&src_reg), 0, true, 0
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_var_off_stack_read_requires_dst_regno() {
        let mut state = BpfVerifierState::new();
        
        // Initialize stack
        {
            let mut init_reg = BpfRegState::default();
            init_reg.reg_type = BpfRegType::ScalarValue;
            init_reg.mark_known(0);
            
            let mut ptr_reg = BpfRegState::default();
            ptr_reg.reg_type = BpfRegType::PtrToStack;
            ptr_reg.off = 0;
            
            let _ = check_stack_write_fixed_off(&mut state, &ptr_reg, -8, 8, &init_reg, 0);
        }
        
        // Create variable offset register
        let mut var_reg = BpfRegState::default();
        var_reg.reg_type = BpfRegType::PtrToStack;
        var_reg.smin_value = -8;
        var_reg.smax_value = -4;
        var_reg.off = 0;
        
        // Variable offset read with dst_regno < 0 should fail
        // (can't pass variable offset stack pointer to helper)
        let result = check_stack_read_var_off(&state, &var_reg, 0, 4, -1);
        assert!(result.is_err());
        
        // With valid dst_regno should succeed
        let result = check_stack_read_var_off(&state, &var_reg, 0, 4, 0);
        assert!(result.is_ok());
        
        let reg = result.unwrap();
        assert_eq!(reg.reg_type, BpfRegType::ScalarValue);
    }

    #[test]
    fn test_var_off_write_zero_preserves_zero_slots() {
        let mut state = BpfVerifierState::new();
        
        // Initialize a slot with zero using a small write (not a full spill)
        // Full 8-byte writes of scalars create SPILL slots, not ZERO slots
        // So we need to use mark_stack_slots_zero directly or write smaller
        {
            let func = state.cur_func_mut().unwrap();
            func.stack.grow(8).unwrap();
            func.stack.stack[0].slot_type = [BpfStackSlotType::Zero; BPF_REG_SIZE];
        }
        
        // Check slot is zero
        {
            let func = state.cur_func().unwrap();
            assert_eq!(func.stack.stack[0].slot_type[7], BpfStackSlotType::Zero);
        }
        
        // Write zero with variable offset
        let mut var_reg = BpfRegState::default();
        var_reg.reg_type = BpfRegType::PtrToStack;
        var_reg.smin_value = -8;
        var_reg.smax_value = -4;
        var_reg.off = 0;
        
        let mut zero_reg = BpfRegState::default();
        zero_reg.reg_type = BpfRegType::ScalarValue;
        zero_reg.mark_known(0);
        
        let result = check_stack_write_var_off(
            &mut state, &var_reg, 0, 4, Some(&zero_reg), 0, true, 0
        );
        assert!(result.is_ok());
        
        // Zero slots should remain zero when writing zero
        {
            let func = state.cur_func().unwrap();
            // The slot should still be zero since we wrote zero to a zero slot
            assert_eq!(func.stack.stack[0].slot_type[7], BpfStackSlotType::Zero);
        }
    }
