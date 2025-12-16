// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bounds::insn_bounds

use bpf_verifier::bounds::insn_bounds::*;

use super::*;

    #[test]
    fn test_stack_access_bounds() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = Tnum::const_value(0);
        
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
    }

    #[test]
    fn test_stack_access_out_of_bounds() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = 8; // Positive offset - invalid
        reg.var_off = Tnum::const_value(0);
        
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_value_access_bounds() {
        use crate::state::reg_state::MapInfo;
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.off = 0;
        reg.var_off = Tnum::const_value(0);
        reg.map_ptr = Some(MapInfo {
            map_type: BpfMapType::Hash,
            key_size: 4,
            value_size: 64,
            max_entries: 100,
        });
        
        // Valid access
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
        
        // Out of bounds access
        let result = analyze_mem_access_bounds(&reg, 60, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ctx_variable_offset_rejected() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;
        reg.var_off = Tnum::unknown(); // Variable offset
        
        let result = analyze_mem_access_bounds(&reg, 0, 4, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ptr_arithmetic_stack() {
        let mut ptr_reg = BpfRegState::default();
        ptr_reg.reg_type = BpfRegType::PtrToStack;
        ptr_reg.off = -64;
        
        let mut scalar_reg = BpfRegState::default();
        scalar_reg.reg_type = BpfRegType::ScalarValue;
        scalar_reg.smin_value = 0;
        scalar_reg.smax_value = 8;
        scalar_reg.umin_value = 0;
        scalar_reg.umax_value = 8;
        
        // Subtracting from stack pointer (going more negative) should be ok
        let result = analyze_ptr_arithmetic(&ptr_reg, &scalar_reg, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
    }

    #[test]
    fn test_div_by_zero_check() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(0);
        
        let result = check_div_bounds(&reg);
        assert!(result.is_err());
    }

    #[test]
    fn test_div_safe() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 1;
        reg.umax_value = 10;
        reg.smin_value = 1;
        reg.smax_value = 10;
        
        let result = check_div_bounds(&reg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_refine_bounds_on_branch() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 0;
        reg.umax_value = 100;
        reg.smin_value = 0;
        reg.smax_value = 100;
        reg.var_off = Tnum::unknown();
        
        // After JGT 50 (taken)
        refine_bounds_on_branch(&mut reg, 50, 0x20, true);
        
        assert_eq!(reg.umin_value, 51);
    }
