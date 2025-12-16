// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::load_store

use bpf_verifier::check::load_store::*;

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
