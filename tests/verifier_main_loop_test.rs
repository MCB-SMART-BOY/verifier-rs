// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::main_loop

use bpf_verifier::verifier::main_loop::*;

use super::*;

    fn make_env(insns: Vec<BpfInsn>) -> VerifierEnv {
        VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap()
    }

    #[test]
    fn test_simple_program() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        assert!(verifier.verify().is_ok());
    }

    #[test]
    fn test_alu_program() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        assert!(verifier.verify().is_ok());
    }

    #[test]
    fn test_branch_program() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        assert!(verifier.verify().is_ok());
    }

    #[test]
    fn test_jump_out_of_range() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 100, 0), // Jump way out of range
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        assert!(verifier.verify().is_err());
    }

    #[test]
    fn test_uninit_register() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 5, 0, 0), // r0 = r5 (uninit)
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        // This should fail because R5 is not initialized
        let result = verifier.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_prune_points() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // 0
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0),   // 1: jump to 4
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), // 2
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0),            // 3: jump to 4
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // 4
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        
        // First instruction should be prune point
        assert!(env.insn_aux[0].prune_point);
        
        // Jump target at index 4 should be prune point
        assert!(env.insn_aux[4].prune_point);
    }

    #[test]
    fn test_state_cache_integration() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = make_env(insns);
        mark_prune_points(&mut env);
        let mut verifier = MainVerifier::new(&mut env);
        
        // Verify should work and potentially use state cache
        assert!(verifier.verify().is_ok());
    }

    #[test]
    fn test_verify_program_api() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        // Use the high-level API
        assert!(verify_program(insns, BpfProgType::SocketFilter, true).is_ok());
    }
