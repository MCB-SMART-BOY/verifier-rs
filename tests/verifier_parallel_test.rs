// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::parallel

use bpf_verifier::verifier::parallel::*;

use super::*;

    #[test]
    fn test_work_item_creation() {
        let state = BpfVerifierState::new();
        let item = ParallelWorkItem::new(state, 0, 0, 1);
        
        assert_eq!(item.insn_idx, 0);
        assert_eq!(item.id, 1);
        assert_eq!(item.depth, 0);
        assert!(item.parent_id.is_none());
    }

    #[test]
    fn test_work_item_child() {
        let state = BpfVerifierState::new();
        let parent = ParallelWorkItem::new(state.clone(), 0, 0, 1);
        let child = parent.child(state, 5, 2);
        
        assert_eq!(child.insn_idx, 5);
        assert_eq!(child.prev_insn_idx, 0);
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id, Some(1));
    }

    #[test]
    fn test_work_queue_priority() {
        let mut queue = WorkQueue::new(100);
        let state = BpfVerifierState::new();
        
        // Add items with different priorities
        let id1 = queue.alloc_id();
        let id2 = queue.alloc_id();
        let id3 = queue.alloc_id();
        
        queue.push(ParallelWorkItem::new(state.clone(), 0, 0, id1).with_priority(1));
        queue.push(ParallelWorkItem::new(state.clone(), 1, 0, id2).with_priority(3));
        queue.push(ParallelWorkItem::new(state.clone(), 2, 0, id3).with_priority(2));
        
        // Should pop in priority order (highest first)
        assert_eq!(queue.pop().unwrap().priority, 3);
        assert_eq!(queue.pop().unwrap().priority, 2);
        assert_eq!(queue.pop().unwrap().priority, 1);
    }

    #[test]
    fn test_work_queue_steal() {
        let mut queue = WorkQueue::new(100);
        let state = BpfVerifierState::new();
        
        for i in 0..10 {
            let id = queue.alloc_id();
            queue.push(ParallelWorkItem::new(state.clone(), i, 0, id));
        }
        
        let stolen = queue.steal(3);
        assert_eq!(stolen.len(), 3);
        assert_eq!(queue.len(), 7);
    }

    #[test]
    fn test_parallel_config() {
        let config = ParallelConfig::new()
            .with_threads(8)
            .with_strategy(ParallelStrategy::BreadthFirst);
        
        assert_eq!(config.max_threads, 8);
        assert_eq!(config.strategy, ParallelStrategy::BreadthFirst);
    }

    #[test]
    fn test_parallel_explorer() {
        let config = ParallelConfig::single_threaded();
        let mut explorer = ParallelExplorer::new(config);
        
        let state = BpfVerifierState::new();
        explorer.add_initial(state, 0);
        
        assert!(!explorer.is_complete());
        assert_eq!(explorer.queue_size(), 1);
        
        let item = explorer.next_work().unwrap();
        explorer.submit_result(&item, ExploreResult::Complete);
        
        assert!(explorer.is_complete());
        assert_eq!(explorer.stats.items_completed, 1);
    }

    #[test]
    fn test_parallel_explorer_branching() {
        let mut explorer = ParallelExplorer::with_defaults();
        
        let state = BpfVerifierState::new();
        explorer.add_initial(state.clone(), 0);
        
        let item = explorer.next_work().unwrap();
        
        // Simulate branching
        let child1 = item.child(state.clone(), 5, explorer.queue.alloc_id());
        let child2 = item.child(state.clone(), 10, explorer.queue.alloc_id());
        
        explorer.submit_result(&item, ExploreResult::Branched(vec![child1, child2]));
        
        assert_eq!(explorer.queue_size(), 2);
        assert_eq!(explorer.stats.items_branched, 1);
        assert_eq!(explorer.stats.total_branches, 2);
    }

    #[test]
    fn test_parallel_stats() {
        let mut stats = ParallelStats::new();
        
        stats.record_processed();
        stats.record_processed();
        stats.record_completed();
        stats.record_pruned();
        stats.record_branched(3);
        
        assert_eq!(stats.items_processed, 2);
        assert_eq!(stats.items_completed, 1);
        assert_eq!(stats.items_pruned, 1);
        assert_eq!(stats.branching_factor(), 3.0);
        assert_eq!(stats.prune_rate(), 0.5);
    }

    #[test]
    fn test_merge_parallel_results() {
        let results = vec![
            ExploreResult::Complete,
            ExploreResult::Pruned,
            ExploreResult::Complete,
        ];
        
        let merged = merge_parallel_results(results);
        
        assert_eq!(merged.paths_merged, 3);
        assert_eq!(merged.conflicts, 0);
        assert!(merged.all_succeeded);
        assert!(merged.error.is_none());
    }

    #[test]
    fn test_merge_parallel_results_with_error() {
        let results = vec![
            ExploreResult::Complete,
            ExploreResult::Error(VerifierError::InfiniteLoop(0)),
            ExploreResult::Pruned,
        ];
        
        let merged = merge_parallel_results(results);
        
        assert!(!merged.all_succeeded);
        assert!(merged.error.is_some());
    }

    #[test]
    fn test_parallel_strategy_priority() {
        let state = BpfVerifierState::new();
        let mut item = ParallelWorkItem::new(state, 0, 0, 1);
        item.depth = 5;
        item.priority = 10;
        
        let bf_priority = ParallelStrategy::BreadthFirst.compute_priority(&item, 100);
        let df_priority = ParallelStrategy::DepthFirst.compute_priority(&item, 100);
        
        assert_eq!(bf_priority, 95); // 100 - 5
        assert_eq!(df_priority, 5);  // depth
    }
