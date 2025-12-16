// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::memory

use bpf_verifier::mem::memory::*;

use super::*;
    use crate::bounds::tnum::Tnum;

    fn make_stack_ptr(off: i32) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.var_off = Tnum::const_value(0);
        reg.off = off;
        reg
    }

    #[test]
    fn test_stack_bounds() {
        let mut state = BpfVerifierState::new();
        let reg = make_stack_ptr(-8);

        // Valid stack write access (initializes the stack)
        let result = check_stack_access(&mut state, &reg, 0, 8, true);
        assert!(result.is_ok());
        
        // Now read should succeed since stack was initialized
        let result2 = check_stack_access(&mut state, &reg, 0, 8, false);
        assert!(result2.is_ok());
    }
    
    #[test]
    fn test_stack_uninitialized_read() {
        let mut state = BpfVerifierState::new();
        let reg = make_stack_ptr(-8);

        // Reading uninitialized stack should fail
        let result = check_stack_access(&mut state, &reg, 0, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_stack_positive_offset() {
        let mut state = BpfVerifierState::new();
        let reg = make_stack_ptr(8); // Positive offset is invalid

        let result = check_stack_access(&mut state, &reg, 0, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_bounds() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.var_off = Tnum::const_value(0);
        reg.off = 0;

        // Valid packet access
        let result = check_packet_access(&reg, 0, 4, false, true);
        assert!(result.is_ok());

        // Negative offset
        let result2 = check_packet_access(&reg, -1, 4, false, true);
        assert!(result2.is_err());
    }

    #[test]
    fn test_alignment() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.off = 1; // Misaligned

        let result = check_ptr_alignment(&reg, 8, true);
        assert!(result.is_err());

        reg.off = 8; // Aligned
        let result2 = check_ptr_alignment(&reg, 8, true);
        assert!(result2.is_ok());
    }
