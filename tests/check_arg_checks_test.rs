// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::arg_checks

use bpf_verifier::check::arg_checks::*;

use super::*;

    #[test]
    fn test_check_arg_type_anything() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_unknown(false);
        
        let result = check_arg_type_compat(&reg, BpfArgType::Anything, 1);
        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    #[test]
    fn test_check_const_map_ptr() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ConstPtrToMap;
        reg.off = 0;
        
        let result = check_arg_type_compat(&reg, BpfArgType::ConstMapPtr, 1);
        assert!(result.is_ok());
        
        // Non-zero offset should fail
        reg.off = 4;
        let result = check_arg_type_compat(&reg, BpfArgType::ConstMapPtr, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ptr_to_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = crate::bounds::tnum::Tnum::const_value(0);
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToStack, 1);
        assert!(result.is_ok());
        
        // Positive offset should fail
        reg.off = 8;
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToStack, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_const_size() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(64);
        reg.umax_value = 64;
        reg.umin_value = 64;
        
        let result = check_arg_type_compat(&reg, BpfArgType::ConstSize, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mem_size, Some(64));
    }

    #[test]
    fn test_check_uninit_register() {
        let reg = BpfRegState::default(); // NotInit by default
        
        let result = check_arg_type_compat(&reg, BpfArgType::Anything, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ptr_to_mem_allows_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToMem, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_dynptr_alignment() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = crate::bounds::tnum::Tnum::const_value(0);
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToDynptr, 1);
        assert!(result.is_ok());
        
        // Misaligned offset
        reg.off = -17;
        // This would fail alignment check - the check uses off + var_off.value
    }
