// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::prune

use bpf_verifier::analysis::prune::*;

use super::*;
    use crate::bounds::tnum::Tnum;

    /// Check if cur's scalar range is subsumed by old's (test helper)
    fn scalar_ranges_subsumed(cur: &BpfRegState, old: &BpfRegState) -> bool {
        // cur's bounds must be within old's bounds
        if cur.umin_value < old.umin_value { return false; }
        if cur.umax_value > old.umax_value { return false; }
        if cur.smin_value < old.smin_value { return false; }
        if cur.smax_value > old.smax_value { return false; }
        if old.precise && !cur.precise { return false; }
        true
    }

    /// Check if two registers are equivalent for pruning (test helper)
    fn regs_equal(cur: &BpfRegState, old: &BpfRegState, _regno: usize) -> bool {
        if old.reg_type == BpfRegType::NotInit { return true; }
        if cur.reg_type == BpfRegType::NotInit { return false; }
        if cur.reg_type != old.reg_type { return false; }
        match cur.reg_type {
            BpfRegType::ScalarValue => scalar_ranges_subsumed(cur, old),
            _ => cur.off == old.off,
        }
    }

    #[test]
    fn test_state_cache() {
        let mut cache = StateCache::new();
        let state = BpfVerifierState::new();
        
        cache.push_state(0, state);
        assert_eq!(cache.total_states, 1);
        assert!(cache.get(0).is_some());
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_scalar_subsumption() {
        let mut cur = BpfRegState::default();
        cur.reg_type = BpfRegType::ScalarValue;
        cur.umin_value = 10;
        cur.umax_value = 20;
        cur.smin_value = 10;
        cur.smax_value = 20;

        let mut old = BpfRegState::default();
        old.reg_type = BpfRegType::ScalarValue;
        old.umin_value = 5;
        old.umax_value = 25;
        old.smin_value = 5;
        old.smax_value = 25;

        // cur is within old's range, should be subsumed
        assert!(scalar_ranges_subsumed(&cur, &old));

        // Flip - old is tighter, cur is NOT subsumed
        assert!(!scalar_ranges_subsumed(&old, &cur));
    }

    #[test]
    fn test_regs_equal_not_init() {
        let cur = BpfRegState::default(); // NotInit
        let old = BpfRegState::default(); // NotInit
        
        // Both uninitialized - equal
        assert!(regs_equal(&cur, &old, 0));
    }

    #[test]
    fn test_regs_equal_scalar() {
        let mut cur = BpfRegState::default();
        cur.reg_type = BpfRegType::ScalarValue;
        cur.mark_known(100);

        let mut old = BpfRegState::default();
        old.reg_type = BpfRegType::ScalarValue;
        old.umin_value = 0;
        old.umax_value = 200;
        old.smin_value = 0;
        old.smax_value = 200;
        old.var_off = Tnum::unknown();

        // cur (exactly 100) is within old's range
        assert!(regs_equal(&cur, &old, 0));
    }

    #[test]
    fn test_states_equal_simple() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();

        // Two fresh states should be equal
        assert!(states_equal_for_pruning(&state1, &state2));
    }

    #[test]
    fn test_clean_old_states() {
        let mut cache = StateCache::new();
        
        for i in 0..100 {
            cache.push_state(i, BpfVerifierState::new());
        }
        
        assert_eq!(cache.total_states, 100);
        
        clean_old_states(&mut cache, 80, 20);
        
        // States before index 60 should be removed
        assert!(cache.get(50).is_none());
        assert!(cache.get(70).is_some());
    }

    #[test]
    fn test_prune_check() {
        let mut cache = StateCache::new();
        
        let state1 = BpfVerifierState::new();
        cache.push_state(0, state1.clone());
        
        // Not verified yet, shouldn't prune
        assert!(!cache.check_prune(0, &state1));
        
        // Mark as verified
        cache.mark_verified(0);
        
        // Now should prune
        assert!(cache.check_prune(0, &state1));
        assert_eq!(cache.prune_hits, 1);
    }

    #[test]
    fn test_is_state_visited_new_state() {
        let mut cache = StateCache::new();
        let state = BpfVerifierState::new();
        let mut ctx = StateVisitContext::new();
        ctx.force_new_state = true;

        let result = is_state_visited(&mut cache, 0, &state, &mut ctx).unwrap();
        
        assert!(matches!(result, StateVisitResult::Explore(_)));
        assert_eq!(cache.total_states, 1);
    }

    #[test]
    fn test_is_state_visited_prune() {
        let mut cache = StateCache::new();
        let state = BpfVerifierState::new();
        
        // Add a state and mark it as verified (all branches completed)
        let _state_id = cache.push_state(0, state.clone());
        // Mark verified and complete all branches
        if let Some(head) = cache.get_mut(0) {
            for cached in &mut head.states {
                cached.verified = true;
                cached.branches = 0; // No pending branches
            }
        }

        // Now visit with same state - should prune because we found
        // an equivalent verified state
        let mut ctx = StateVisitContext::new();
        let result = is_state_visited(&mut cache, 0, &state, &mut ctx).unwrap();
        
        assert!(matches!(result, StateVisitResult::Prune(_)));
    }

    #[test]
    fn test_states_maybe_looping() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();

        // Two identical fresh states should look like they might be looping
        assert!(states_maybe_looping(&state1, &state2));
    }

    #[test]
    fn test_jmp_history() {
        let mut history = JmpHistory::new(50);
        
        assert!(history.is_empty());
        
        assert!(history.push(0, 0, 0, 0));
        assert!(history.push(5, 0, 1, 0));
        
        assert_eq!(history.len(), 2);
        assert!(!history.is_empty());
        
        history.clear();
        assert!(history.is_empty());
    }

    #[test]
    fn test_cached_state_branches() {
        let state = BpfVerifierState::new();
        let mut cached = CachedState::new(0, state, 0); // id=0, state, insn_idx=0
        
        assert_eq!(cached.branches, 1);
        assert!(!cached.verified);
        
        cached.add_branch();
        assert_eq!(cached.branches, 2);
        
        cached.complete_branch();
        assert_eq!(cached.branches, 1);
        assert!(!cached.verified);
        
        cached.complete_branch();
        assert_eq!(cached.branches, 0);
        assert!(cached.verified);
    }

    #[test]
    fn test_state_visit_context_heuristics() {
        let mut ctx = StateVisitContext::new();
        
        // Initially no add
        ctx.update_heuristics();
        assert!(!ctx.add_new_state);
        
        // After enough jumps and instructions
        ctx.jmps_since_prune = 3;
        ctx.insns_since_prune = 10;
        ctx.update_heuristics();
        assert!(ctx.add_new_state);
        
        // Force on long history
        ctx.jmp_history_cnt = 50;
        ctx.update_heuristics();
        assert!(ctx.force_new_state);
    }

    #[test]
    fn test_widen_scalar_bounds() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 10;
        reg.umax_value = 100;
        reg.smin_value = 10;
        reg.smax_value = 100;
        reg.u32_min_value = 10;
        reg.u32_max_value = 100;
        reg.s32_min_value = 10;
        reg.s32_max_value = 100;
        reg.var_off = Tnum::range(10, 100);

        widen_scalar_bounds(&mut reg);

        // After widening, bounds should be fully unknown
        assert_eq!(reg.umin_value, 0);
        assert_eq!(reg.umax_value, u64::MAX);
        assert_eq!(reg.smin_value, i64::MIN);
        assert_eq!(reg.smax_value, i64::MAX);
        assert_eq!(reg.u32_min_value, 0);
        assert_eq!(reg.u32_max_value, u32::MAX);
        assert_eq!(reg.s32_min_value, i32::MIN);
        assert_eq!(reg.s32_max_value, i32::MAX);
        assert!(reg.var_off.is_unknown());
    }

    #[test]
    fn test_widen_scalar_bounds_non_scalar() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = 100;

        widen_scalar_bounds(&mut reg);

        // Non-scalar should not be modified
        assert_eq!(reg.reg_type, BpfRegType::PtrToStack);
        assert_eq!(reg.off, 100);
    }

    #[test]
    fn test_regs_exact_scalars() {
        use crate::analysis::states_equal::IdMap;
        
        let mut idmap = IdMap::new();
        
        let mut reg1 = BpfRegState::default();
        reg1.reg_type = BpfRegType::ScalarValue;
        reg1.mark_known(42);

        let mut reg2 = BpfRegState::default();
        reg2.reg_type = BpfRegType::ScalarValue;
        reg2.mark_known(42);

        // Identical scalars should be exact
        assert!(regs_exact(&reg1, &reg2, &mut idmap));

        // Different values should not be exact
        reg2.mark_known(43);
        assert!(!regs_exact(&reg1, &reg2, &mut idmap));
    }

    #[test]
    fn test_maybe_widen_reg_precise() {
        use crate::analysis::states_equal::IdMap;
        
        let mut idmap = IdMap::new();
        
        let mut old_reg = BpfRegState::default();
        old_reg.reg_type = BpfRegType::ScalarValue;
        old_reg.mark_known(10);
        old_reg.precise = true; // Mark as precise

        let mut cur_reg = BpfRegState::default();
        cur_reg.reg_type = BpfRegType::ScalarValue;
        cur_reg.mark_known(20);

        // Should NOT widen because old is precise
        assert!(!maybe_widen_reg(&old_reg, &mut cur_reg, &mut idmap));
        assert_eq!(cur_reg.umin_value, 20); // Unchanged
    }

    #[test]
    fn test_maybe_widen_reg_imprecise() {
        use crate::analysis::states_equal::IdMap;
        
        let mut idmap = IdMap::new();
        
        let mut old_reg = BpfRegState::default();
        old_reg.reg_type = BpfRegType::ScalarValue;
        old_reg.mark_known(10);
        old_reg.precise = false;

        let mut cur_reg = BpfRegState::default();
        cur_reg.reg_type = BpfRegType::ScalarValue;
        cur_reg.mark_known(20);
        cur_reg.precise = false;

        // Should widen because both are imprecise and values differ
        assert!(maybe_widen_reg(&old_reg, &mut cur_reg, &mut idmap));
        
        // After widening, cur_reg should be unknown
        assert_eq!(cur_reg.umin_value, 0);
        assert_eq!(cur_reg.umax_value, u64::MAX);
    }

    #[test]
    fn test_maybe_widen_reg_exact_match() {
        use crate::analysis::states_equal::IdMap;
        
        let mut idmap = IdMap::new();
        
        let mut old_reg = BpfRegState::default();
        old_reg.reg_type = BpfRegType::ScalarValue;
        old_reg.mark_known(42);
        old_reg.precise = false;

        let mut cur_reg = BpfRegState::default();
        cur_reg.reg_type = BpfRegType::ScalarValue;
        cur_reg.mark_known(42);
        cur_reg.precise = false;

        // Should NOT widen because values are identical
        assert!(!maybe_widen_reg(&old_reg, &mut cur_reg, &mut idmap));
        assert_eq!(cur_reg.umin_value, 42);
    }

    #[test]
    fn test_widen_imprecise_scalars_for_prune() {
        let mut old_state = BpfVerifierState::new();
        let mut cur_state = BpfVerifierState::new();

        // Set up old state with a known scalar in R0
        if let Some(func) = old_state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].mark_known(10);
            func.regs[0].precise = false;
        }

        // Set up cur state with a different scalar in R0
        if let Some(func) = cur_state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].mark_known(20);
            func.regs[0].precise = false;
        }

        let widened = widen_imprecise_scalars_for_prune(&old_state, &mut cur_state);

        // R0 should have been widened
        assert_eq!(widened, 1);
        
        // Check that R0 is now unknown
        if let Some(func) = cur_state.cur_func() {
            assert_eq!(func.regs[0].umin_value, 0);
            assert_eq!(func.regs[0].umax_value, u64::MAX);
        }
    }

    #[test]
    fn test_widen_imprecise_scalars_for_prune_preserves_precise() {
        let mut old_state = BpfVerifierState::new();
        let mut cur_state = BpfVerifierState::new();

        // Set up old state with a precise scalar
        if let Some(func) = old_state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].mark_known(10);
            func.regs[0].precise = true; // Marked precise
        }

        // Set up cur state with a different scalar
        if let Some(func) = cur_state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].mark_known(20);
            func.regs[0].precise = false;
        }

        let widened = widen_imprecise_scalars_for_prune(&old_state, &mut cur_state);

        // Should NOT be widened because old is precise
        assert_eq!(widened, 0);
        
        // R0 should still have its original value
        if let Some(func) = cur_state.cur_func() {
            assert_eq!(func.regs[0].umin_value, 20);
        }
    }

    #[test]
    fn test_detect_infinite_loop_identical_states() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();

        // Two identical fresh states should be detected as potentially looping
        assert!(detect_infinite_loop(&state1, &state2));
    }

    #[test]
    fn test_detect_infinite_loop_different_may_goto_depth() {
        let mut state1 = BpfVerifierState::new();
        let mut state2 = BpfVerifierState::new();
        
        state1.may_goto_depth = 1;
        state2.may_goto_depth = 2;

        // Different may_goto depths means we're making progress
        assert!(!detect_infinite_loop(&state1, &state2));
    }

    #[test]
    fn test_detect_infinite_loop_different_callback_depth() {
        let mut state1 = BpfVerifierState::new();
        let mut state2 = BpfVerifierState::new();
        
        state1.callback_unroll_depth = 0;
        state2.callback_unroll_depth = 1;

        // Different callback depths means we're making progress
        assert!(!detect_infinite_loop(&state1, &state2));
    }

    #[test]
    fn test_memory_pressure_manager() {
        let mut manager = MemoryPressureManager::new(100);
        
        assert_eq!(manager.pressure_level(), PressureLevel::Normal);
        
        // Simulate increasing states - 70% threshold for elevated
        manager.update_state_count(75);
        assert_eq!(manager.pressure_level(), PressureLevel::Elevated);
        
        // 85% threshold for high
        manager.update_state_count(87);
        assert_eq!(manager.pressure_level(), PressureLevel::High);
        
        // 95% threshold for critical
        manager.update_state_count(96);
        assert_eq!(manager.pressure_level(), PressureLevel::Critical);
    }

    #[test]
    fn test_eviction_policy_lru() {
        let mut cache = StateCache::new();
        let state = BpfVerifierState::new();
        
        // Add states
        let id1 = cache.push_state(0, state.clone());
        let id2 = cache.push_state(0, state.clone());
        let _id3 = cache.push_state(0, state.clone());
        
        // Mark all as verified (required for eviction selection)
        cache.mark_verified(0);
        
        // Access id2 to make it recently used (higher hit count)
        cache.increment_hit(id2);
        cache.increment_hit(id2);
        
        let policy = EvictionPolicy::LRU;
        let to_evict = policy.select_for_eviction(&cache, 0, 1);
        
        // Should evict id1 (lowest hit count, not id2 which was accessed)
        assert_eq!(to_evict.len(), 1);
        assert_eq!(to_evict[0], id1);
    }

    #[test]
    fn test_adaptive_pruning() {
        let mut pruning = AdaptivePruning::new();
        
        // Initially should be in Normal mode
        assert!(matches!(pruning.current_mode, PruningMode::Normal));
        
        // Simulate high pressure
        for _ in 0..10 {
            pruning.record_state_added();
        }
        pruning.adjust_mode(PressureLevel::High);
        
        assert!(matches!(pruning.current_mode, PruningMode::Aggressive));
    }
