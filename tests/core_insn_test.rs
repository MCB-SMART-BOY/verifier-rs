// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::core::insn

use bpf_verifier::core::insn::*;

use super::*;

    #[test]
    fn test_is_reg64() {
        // ALU64 ADD
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1);
        assert!(is_reg64(&insn, 0, false));

        // ALU ADD (32-bit)
        let insn32 = BpfInsn::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, 0, 1);
        assert!(!is_reg64(&insn32, 0, false));
    }

    #[test]
    fn test_insn_def_regno() {
        // ALU writes to dst_reg
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, 1);
        assert_eq!(insn_def_regno(&insn), Some(3));

        // LDX writes to dst_reg
        let ldx = BpfInsn::new(BPF_LDX | BPF_MEM | 0x18, 5, 1, 0, 0);
        assert_eq!(insn_def_regno(&ldx), Some(5));

        // CALL writes to R0
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        assert_eq!(insn_def_regno(&call), Some(BPF_REG_0));
    }

    #[test]
    fn test_alu_immediate() {
        let mut state = BpfVerifierState::new();

        // Set R1 to 10
        state.reg_mut(1).unwrap().mark_known(10);
        state.reg_mut(1).unwrap().reg_type = BpfRegType::ScalarValue;

        // ADD R1, 5
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5);
        assert!(check_alu_op(&mut state, &insn, true).is_ok());

        assert_eq!(state.reg(1).unwrap().const_value(), 15);
    }
