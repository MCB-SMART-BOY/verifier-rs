// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::dead_code

use bpf_verifier::opt::dead_code::*;

use super::*;

    #[test]
    fn test_all_reachable() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert!(unreachable.is_empty());
    }

    #[test]
    fn test_unreachable_after_exit() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Unreachable
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert_eq!(unreachable, vec![2]);
    }

    #[test]
    fn test_unreachable_after_unconditional_jump() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), // Jump to insn 2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Unreachable
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert_eq!(unreachable, vec![1]);
    }

    #[test]
    fn test_conditional_both_paths_reachable() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0), // Jump to 3 if r0 == 0
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), // Fall through path
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert!(unreachable.is_empty());
    }

    #[test]
    fn test_dead_store() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Dead: r1 never used
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let dead = find_dead_stores(&insns).unwrap();
        assert_eq!(dead, vec![0]);
    }

    #[test]
    fn test_live_store() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Live: r1 used below
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),  // r0 = r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let dead = find_dead_stores(&insns).unwrap();
        assert!(dead.is_empty());
    }

    #[test]
    fn test_dead_code_eliminator() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100), // Dead: r2 overwritten
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 200), // Dead: r2 never used
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut eliminator = DeadCodeEliminator::new(insns);
        let dead = eliminator.eliminate().unwrap();
        assert!(dead.contains(&0));
        assert!(dead.contains(&1));
    }

    #[test]
    fn test_is_nop() {
        // ja +0 is a NOP
        let nop = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0);
        assert!(is_nop(&nop));

        // ja +1 is not a NOP
        let not_nop = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0);
        assert!(!is_nop(&not_nop));

        // Other instructions are not NOPs
        let mov = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0);
        assert!(!is_nop(&mov));
    }

    #[test]
    fn test_opt_remove_nops_single() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(result.total_removed, 1);
        assert_eq!(insns.len(), 2);
    }

    #[test]
    fn test_opt_remove_nops_multiple() {
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 3);
        assert_eq!(insns.len(), 2);
    }

    #[test]
    fn test_opt_remove_nops_preserves_real_jumps() {
        // Original program:
        // 0: ja +2    -> jumps to insn 3 (exit)
        // 1: ja +0    <- NOP
        // 2: mov r0, 42  (unreachable from ja +2, but doesn't matter for this test)
        // 3: exit
        //
        // After NOP removal:
        // 0: ja +1    -> jumps to insn 2 (exit) - offset decremented by 1
        // 1: mov r0, 42
        // 2: exit
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 2, 0), // Jump to exit (offset 2)
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(insns.len(), 3);
        
        // First instruction: original target was index 3 (idx 0 + off 2 + 1 = 3)
        // After removing index 1, target index 3 becomes 2
        // New offset: 2 - 0 - 1 = 1
        assert_eq!(insns[0].off, 1); // ja +2 becomes ja +1
    }

    #[test]
    fn test_opt_remove_nops_adjusts_forward_jumps() {
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0), // Jump to exit if r0 == 0
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(insns.len(), 3);
        
        // Conditional jump should now point to exit (offset 1 instead of 2)
        assert_eq!(insns[0].off, 1);
    }

    #[test]
    fn test_opt_remove_nops_no_nops() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let original_len = insns.len();
        let result = opt_remove_nops(&mut insns).unwrap();
        
        assert_eq!(result.total_removed, 0);
        assert_eq!(insns.len(), original_len);
    }

    #[test]
    fn test_optimize_dead_code_combined() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100), // Dead store
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = optimize_dead_code(&mut insns).unwrap();
        
        // Should remove dead store and NOP
        assert!(result.dead_code_removed >= 1);
        assert!(result.total_removed >= 1);
    }
