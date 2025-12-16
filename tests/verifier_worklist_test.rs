// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::worklist

use bpf_verifier::verifier::worklist::*;

use super::*;

    fn make_state() -> BpfVerifierState {
        BpfVerifierState::new()
    }

    #[test]
    fn test_worklist_push_pop() {
        let mut wl = Worklist::new();

        assert!(wl.is_empty());
        wl.push(0, make_state());
        wl.push(5, make_state());
        wl.push(10, make_state());

        assert_eq!(wl.len(), 3);

        // Depth-first: last in, first out
        let item = wl.pop().unwrap();
        assert_eq!(item.insn_idx, 10);
    }

    #[test]
    fn test_worklist_breadth_first() {
        let mut wl = Worklist::with_strategy(ExplorationStrategy::BreadthFirst);

        wl.push(0, make_state());
        wl.push(5, make_state());
        wl.push(10, make_state());

        // Breadth-first: first in, first out
        let item = wl.pop().unwrap();
        assert_eq!(item.insn_idx, 0);
    }

    #[test]
    fn test_worklist_visited() {
        let mut wl = Worklist::new();

        assert!(!wl.is_visited(5));
        wl.mark_visited(5);
        assert!(wl.is_visited(5));
        assert!(!wl.is_visited(10));
    }

    #[test]
    fn test_worklist_stats() {
        let mut wl = Worklist::new();

        wl.push(0, make_state());
        wl.push(5, make_state());
        wl.record_processed();
        wl.record_processed();
        wl.record_join_point();

        let stats = wl.stats();
        assert_eq!(stats.items_processed, 2);
        assert_eq!(stats.join_points, 1);
        assert!(stats.max_queue_size >= 2);
    }

    #[test]
    fn test_worklist_depth_tracking() {
        let mut wl = Worklist::new();

        wl.push(0, make_state());
        wl.push_with_parent(5, make_state(), 0, 1);
        wl.push_with_parent(10, make_state(), 5, 2);
        wl.push_with_parent(15, make_state(), 10, 3);

        assert_eq!(wl.stats().max_depth, 3);

        let item = wl.pop().unwrap();
        assert_eq!(item.depth, 3);
        assert_eq!(item.parent_idx, Some(10));
    }

    #[test]
    fn test_join_point_detector() {
        let mut detector = JoinPointDetector::new();

        // Create a diamond pattern: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        detector.record_edge(0, 1);
        detector.record_edge(0, 2);
        detector.record_edge(1, 3);
        detector.record_edge(2, 3);

        assert!(!detector.is_join_point(0));
        assert!(!detector.is_join_point(1));
        assert!(!detector.is_join_point(2));
        assert!(detector.is_join_point(3)); // Multiple predecessors

        assert_eq!(detector.predecessor_count(3), 2);
        assert_eq!(detector.predecessor_count(1), 1);
    }

    #[test]
    fn test_join_point_analysis() {
        // Simple branch and merge:
        // 0: if r1 > 0 goto 2
        // 1: r0 = 0
        // 2: exit (join point)
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 1, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let detector = JoinPointDetector::analyze_program(&insns);

        assert!(!detector.is_join_point(0));
        assert!(!detector.is_join_point(1));
        assert!(detector.is_join_point(2)); // Both paths merge here
    }

    #[test]
    fn test_worklist_clear() {
        let mut wl = Worklist::new();

        wl.push(0, make_state());
        wl.push(5, make_state());
        wl.mark_visited(0);
        wl.record_processed();

        wl.clear();

        assert!(wl.is_empty());
        assert!(!wl.is_visited(0));
        assert_eq!(wl.stats().items_processed, 0);
    }

    #[test]
    fn test_save_and_prune() {
        let mut wl = Worklist::new();
        let state = make_state();

        // First time - not pruned
        assert!(!wl.try_prune(5, &state));

        // Save the state
        wl.save_explored(5, state.clone());

        // Same state - should be pruned
        assert!(wl.try_prune(5, &state));

        // Different instruction - not pruned
        assert!(!wl.try_prune(10, &state));
    }

    #[test]
    fn test_work_item_ordering() {
        let item1 = WorkItem::new(0, make_state(), 100);
        let item2 = WorkItem::new(5, make_state(), 200);
        let item3 = WorkItem::new(10, make_state(), 50);

        // Higher priority should come first
        assert!(item2 > item1);
        assert!(item1 > item3);
    }

    #[test]
    fn test_exploration_strategies() {
        // Test that different strategies produce different orderings
        let mut dfs = Worklist::with_strategy(ExplorationStrategy::DepthFirst);
        let mut bfs = Worklist::with_strategy(ExplorationStrategy::BreadthFirst);

        for i in 0..5 {
            dfs.push(i, make_state());
            bfs.push(i, make_state());
        }

        // DFS should pop in reverse order (LIFO)
        assert_eq!(dfs.pop().unwrap().insn_idx, 4);

        // BFS should pop in order (FIFO)
        assert_eq!(bfs.pop().unwrap().insn_idx, 0);
    }
