// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::scc

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::scc::*;


    fn make_insns(codes: &[(u8, i16)]) -> Vec<BpfInsn> {
        codes.iter().map(|&(code, off)| {
            BpfInsn::new(code, 0, 0, off, 0)
        }).collect()
    }

    #[test]
    fn test_no_loops() {
        // Linear program: 3 instructions, no jumps
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_ALU64 | BPF_ADD | BPF_K, 0),
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);

        assert!(analysis.loop_sccs.is_empty());
        assert_eq!(analysis.sccs.len(), 3); // Each instruction is its own SCC
    }

    #[test]
    fn test_simple_loop() {
        // Simple loop: 0: mov, 1: add, 2: jne -2 (back to 1), 3: exit
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_ALU64 | BPF_ADD | BPF_K, 0),
            (BPF_JMP | BPF_JNE | BPF_K, -2), // Jump back to instruction 1
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);

        assert!(!analysis.loop_sccs.is_empty());
        
        // Find the loop SCC
        let loop_scc = analysis.sccs.iter().find(|s| s.is_loop).unwrap();
        assert!(loop_scc.members.contains(&1) || loop_scc.members.contains(&2));
    }

    #[test]
    fn test_nested_loops() {
        // Outer loop with inner loop
        // 0: mov r1, 10
        // 1: mov r2, 5    <- outer loop header
        // 2: add r0, 1    <- inner loop header
        // 3: sub r2, 1
        // 4: jne r2, 0, -3  <- inner loop back edge to 2
        // 5: sub r1, 1
        // 6: jne r1, 0, -6  <- outer loop back edge to 1
        // 7: exit
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_ALU64 | BPF_ADD | BPF_K, 0),
            (BPF_ALU64 | BPF_SUB | BPF_K, 0),
            (BPF_JMP | BPF_JNE | BPF_K, -3),
            (BPF_ALU64 | BPF_SUB | BPF_K, 0),
            (BPF_JMP | BPF_JNE | BPF_K, -6),
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);

        // Should find at least one loop
        assert!(!analysis.loop_sccs.is_empty());
    }

    #[test]
    fn test_back_edge_detection() {
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_JMP | BPF_JA, -1), // Infinite loop back to 0
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);

        let all_back_edges = analysis.all_back_edges();
        assert!(!all_back_edges.is_empty());
    }

    #[test]
    fn test_scc_entries_exits() {
        // Diamond pattern: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3, 3 -> exit
        let insns = make_insns(&[
            (BPF_JMP | BPF_JEQ | BPF_K, 1), // 0: if eq goto 2, else 1
            (BPF_ALU64 | BPF_MOV | BPF_K, 0), // 1: mov
            (BPF_ALU64 | BPF_ADD | BPF_K, 0), // 2: add (join point)
            (BPF_JMP | BPF_EXIT, 0), // 3: exit
        ]);

        let analysis = compute_scc(&insns);

        // Each instruction should be in its own SCC (no loops)
        assert!(analysis.loop_sccs.is_empty());
    }

    #[test]
    fn test_back_edge_propagator() {
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),  // 0: loop header
            (BPF_JMP | BPF_JA, -1),             // 1: jump back to 0
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);
        
        // Check that we found back edges
        let back_edges = analysis.all_back_edges();
        assert!(!back_edges.is_empty(), "Should find back edges");
        
        // Find the back edge target
        let target = back_edges[0].1;
        
        let mut propagator = BackEdgePropagator::from_scc_analysis(&analysis, 5);

        // Should not error on first visits up to limit
        for i in 0..5 {
            assert!(propagator.record_visit(target).is_ok(), "Failed on visit {}", i);
        }

        // Exceeding limit should error
        assert!(propagator.record_visit(target).is_err());
    }

    #[test]
    fn test_scc_visit_state() {
        let mut state = SccVisitState::new();

        assert!(!state.in_scc());

        state.enter_scc(0, 5);
        assert!(state.in_scc());
        assert_eq!(state.current_scc, Some(0));
        assert_eq!(state.entry_insn, Some(5));

        state.enter_scc(1, 10); // Nested SCC
        assert_eq!(state.current_scc, Some(1));
        assert_eq!(state.scc_stack.len(), 1);

        state.exit_scc();
        assert_eq!(state.current_scc, Some(0));

        state.exit_scc();
        assert!(!state.in_scc());
    }

    #[test]
    fn test_topo_order() {
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0),
            (BPF_ALU64 | BPF_ADD | BPF_K, 0),
            (BPF_JMP | BPF_EXIT, 0),
        ]);

        let analysis = compute_scc(&insns);

        // Topo order should include all SCCs
        assert_eq!(analysis.topo_order.len(), analysis.sccs.len());
    }
