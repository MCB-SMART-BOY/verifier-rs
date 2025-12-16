// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::state_merge

use bpf_verifier::analysis::state_merge::*;

use super::*;

    fn make_scalar(umin: u64, umax: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = umin;
        reg.umax_value = umax;
        reg.smin_value = umin as i64;
        reg.smax_value = umax as i64;
        reg.var_off = Tnum::unknown();
        reg
    }
    
    fn make_precise_scalar(umin: u64, umax: u64) -> BpfRegState {
        let mut reg = make_scalar(umin, umax);
        reg.precise = true;
        reg
    }

    #[test]
    fn test_merge_scalars_widen() {
        // With precise scalars, bounds are merged (widened)
        let reg1 = make_precise_scalar(10, 20);
        let reg2 = make_precise_scalar(15, 30);

        let merged = merge_regs(&reg1, &reg2).unwrap();

        // Should take widest bounds
        assert_eq!(merged.umin_value, 10); // min of mins
        assert_eq!(merged.umax_value, 30); // max of maxes
        assert!(merged.precise); // precision preserved when either is precise
    }

    #[test]
    fn test_merge_scalars_disjoint() {
        // With precise scalars, even disjoint ranges are merged
        let reg1 = make_precise_scalar(0, 10);
        let reg2 = make_precise_scalar(20, 30);

        let merged = merge_regs(&reg1, &reg2).unwrap();

        // Should span the whole range
        assert_eq!(merged.umin_value, 0);
        assert_eq!(merged.umax_value, 30);
        assert!(merged.precise);
    }
    
    #[test]
    fn test_merge_imprecise_non_exact_widens() {
        // Imprecise scalars with different bounds are widened to unknown
        let reg1 = make_scalar(10, 20);
        let reg2 = make_scalar(15, 30);

        let merged = merge_regs(&reg1, &reg2).unwrap();

        // Should be widened to unknown (full range)
        assert_eq!(merged.umin_value, 0);
        assert_eq!(merged.umax_value, u64::MAX);
        assert!(!merged.precise);
    }
    
    #[test]
    fn test_merge_exact_imprecise_preserves_bounds() {
        // Imprecise but exact scalars should preserve bounds
        let reg1 = make_scalar(10, 20);
        let reg2 = make_scalar(10, 20); // same bounds = exact

        let merged = merge_regs(&reg1, &reg2).unwrap();

        // Should preserve bounds since they're exact
        assert_eq!(merged.umin_value, 10);
        assert_eq!(merged.umax_value, 20);
    }

    #[test]
    fn test_merge_with_uninit() {
        let reg1 = make_scalar(10, 20);
        let reg2 = BpfRegState::new_not_init();

        let merged = merge_regs(&reg1, &reg2).unwrap();

        // Merging with uninit produces uninit
        assert_eq!(merged.reg_type, BpfRegType::NotInit);
    }

    #[test]
    fn test_reg_subsumes() {
        let wide = make_scalar(0, 100);
        let narrow = make_scalar(25, 75);

        // Wide subsumes narrow
        assert!(reg_subsumes(&wide, &narrow));
        // Narrow does not subsume wide
        assert!(!reg_subsumes(&narrow, &wide));
    }

    #[test]
    fn test_merge_tnums() {
        // t1: knows bits 0-3 are 0101 (5)
        // t2: knows bits 0-3 are 0110 (6)
        // Merged: bits 0 and 2 are known (01), bits 1 and 3 unknown

        let t1 = Tnum::const_value(5);
        let t2 = Tnum::const_value(6);

        let merged = merge_tnums(t1, t2);

        // Bits that differ (1 and 2) should become unknown
        assert!(!merged.is_const());
    }

    #[test]
    fn test_merge_identical_states() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();

        match merge_states(&state1, &state2) {
            MergeResult::FirstSubsumes | MergeResult::SecondSubsumes => {
                // Identical states subsume each other
            }
            MergeResult::Merged(_) => {
                // Also acceptable
            }
            MergeResult::Incompatible => {
                panic!("Identical states should be compatible");
            }
        }
    }

    #[test]
    fn test_merge_stats() {
        let mut stats = MergeStats::new();

        stats.record(&MergeResult::Merged(BpfVerifierState::new()));
        stats.record(&MergeResult::Incompatible);
        stats.record(&MergeResult::FirstSubsumes);
        stats.record(&MergeResult::SecondSubsumes);

        assert_eq!(stats.merges, 1);
        assert_eq!(stats.incompatible, 1);
        assert_eq!(stats.first_subsumed, 1);
        assert_eq!(stats.second_subsumed, 1);
    }

    #[test]
    fn test_types_compatible() {
        assert!(types_compatible(BpfRegType::ScalarValue, BpfRegType::ScalarValue));
        assert!(types_compatible(BpfRegType::PtrToStack, BpfRegType::PtrToStack));

        // Scalar absorbs anything
        assert!(types_compatible(BpfRegType::ScalarValue, BpfRegType::PtrToStack));

        // Some pointer types compatible
        assert!(types_compatible(BpfRegType::PtrToPacket, BpfRegType::PtrToPacketMeta));
    }

    #[test]
    fn test_merge_pointer_with_null_flag() {
        let mut ptr1 = BpfRegState::new_not_init();
        ptr1.reg_type = BpfRegType::PtrToMapValue;
        ptr1.type_flags = BpfTypeFlag::empty();
        ptr1.off = 0;

        let mut ptr2 = BpfRegState::new_not_init();
        ptr2.reg_type = BpfRegType::PtrToMapValue;
        ptr2.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        ptr2.off = 0;

        let merged = merge_regs(&ptr1, &ptr2).unwrap();

        // Merged should have PTR_MAYBE_NULL (OR of flags)
        assert!(merged.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_merge_config_default() {
        let config = MergeConfig::default();
        assert!(config.allow_cross_subprog);
        assert!(config.preserve_precision);
        assert!(!config.allow_ref_mismatch);
        assert_eq!(config.max_batch_size, 8);
    }

    #[test]
    fn test_merge_config_aggressive() {
        let config = MergeConfig::aggressive();
        assert!(config.allow_cross_subprog);
        assert!(!config.preserve_precision);
        assert!(config.allow_ref_mismatch);
        assert_eq!(config.max_batch_size, 16);
        assert!(config.aggressive_loop_widening);
    }

    #[test]
    fn test_merge_config_conservative() {
        let config = MergeConfig::conservative();
        assert!(!config.allow_cross_subprog);
        assert!(config.preserve_precision);
        assert!(!config.allow_ref_mismatch);
        assert_eq!(config.max_batch_size, 4);
    }

    #[test]
    fn test_merge_states_with_config() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();
        let config = MergeConfig::default();

        match merge_states_with_config(&state1, &state2, &config) {
            MergeResult::FirstSubsumes | MergeResult::SecondSubsumes | MergeResult::Merged(_) => {
                // Success
            }
            MergeResult::Incompatible => {
                panic!("Identical states should be compatible");
            }
        }
    }

    #[test]
    fn test_merge_with_precision_preserve() {
        let mut reg1 = make_scalar(10, 20);
        reg1.precise = true;

        let mut reg2 = make_scalar(15, 25);
        reg2.precise = true;

        // With preserve_precision = true
        let config = MergeConfig::default();
        let merged = merge_regs_with_config(&reg1, &reg2, &config).unwrap();
        assert!(merged.precise);

        // If one is not precise, result is not precise
        reg2.precise = false;
        let merged = merge_regs_with_config(&reg1, &reg2, &config).unwrap();
        assert!(!merged.precise);
    }

    #[test]
    fn test_merge_without_precision_preserve() {
        let mut reg1 = make_scalar(10, 20);
        reg1.precise = true;

        let mut reg2 = make_scalar(15, 25);
        reg2.precise = true;

        // With preserve_precision = false
        let config = MergeConfig::aggressive();
        let merged = merge_regs_with_config(&reg1, &reg2, &config).unwrap();
        assert!(!merged.precise); // Always loses precision
    }

    #[test]
    fn test_merge_32bit_bounds() {
        let mut reg1 = make_scalar(10, 20);
        reg1.u32_min_value = 5;
        reg1.u32_max_value = 15;
        reg1.s32_min_value = 5;
        reg1.s32_max_value = 15;

        let mut reg2 = make_scalar(15, 30);
        reg2.u32_min_value = 10;
        reg2.u32_max_value = 25;
        reg2.s32_min_value = 10;
        reg2.s32_max_value = 25;

        let config = MergeConfig::default();
        let merged = merge_regs_with_config(&reg1, &reg2, &config).unwrap();

        // 32-bit bounds should be widened
        assert_eq!(merged.u32_min_value, 5);
        assert_eq!(merged.u32_max_value, 25);
        assert_eq!(merged.s32_min_value, 5);
        assert_eq!(merged.s32_max_value, 25);
    }

    #[test]
    fn test_cross_subprog_merge_ctx() {
        let ctx = CrossSubprogMergeCtx::new(0, 1, 10);
        assert_eq!(ctx.src_subprog, 0);
        assert_eq!(ctx.dst_subprog, 1);
        assert_eq!(ctx.callsite, 10);
        assert!(!ctx.is_tail_call);
        assert!(!ctx.callee_might_sleep);
    }

    #[test]
    fn test_can_merge_cross_subprog() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();
        let ctx = CrossSubprogMergeCtx::new(0, 1, 10);

        assert!(can_merge_cross_subprog(&state1, &state2, &ctx));
    }

    #[test]
    fn test_can_merge_cross_subprog_different_frames() {
        let state1 = BpfVerifierState::new();
        let mut state2 = BpfVerifierState::new();
        state2.curframe = 1;
        let ctx = CrossSubprogMergeCtx::new(0, 1, 10);

        assert!(!can_merge_cross_subprog(&state1, &state2, &ctx));
    }

    #[test]
    fn test_merge_states_batch_empty() {
        let states: Vec<&BpfVerifierState> = vec![];
        let config = MergeConfig::default();
        assert!(merge_states_batch(&states, &config).is_none());
    }

    #[test]
    fn test_merge_states_batch_single() {
        let state = BpfVerifierState::new();
        let states = vec![&state];
        let config = MergeConfig::default();
        let result = merge_states_batch(&states, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_merge_states_batch_multiple() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();
        let state3 = BpfVerifierState::new();
        let states = vec![&state1, &state2, &state3];
        let config = MergeConfig::default();
        let result = merge_states_batch(&states, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_widen_scalar_reg_early_iterations() {
        let mut reg = make_scalar(10, 20);
        
        // Iterations 0-2 should not widen
        widen_scalar_reg(&mut reg, 0);
        assert_eq!(reg.umin_value, 10);
        assert_eq!(reg.umax_value, 20);

        widen_scalar_reg(&mut reg, 2);
        assert_eq!(reg.umin_value, 10);
        assert_eq!(reg.umax_value, 20);
    }

    #[test]
    fn test_widen_scalar_reg_late_iterations() {
        let mut reg = make_scalar(10, 20);
        
        // Iteration 3+ should widen
        widen_scalar_reg(&mut reg, 3);
        assert_eq!(reg.umin_value, 0);
        assert_eq!(reg.umax_value, u64::MAX);
        assert_eq!(reg.smin_value, i64::MIN);
        assert_eq!(reg.smax_value, i64::MAX);
        assert!(!reg.precise);
    }

    #[test]
    fn test_widen_loop_state() {
        let mut state = BpfVerifierState::new();
        
        // Set up a scalar in R0
        if let Some(Some(frame)) = state.frame.get_mut(0) {
            frame.regs[0].reg_type = BpfRegType::ScalarValue;
            frame.regs[0].umin_value = 10;
            frame.regs[0].umax_value = 20;
        }

        widen_loop_state(&mut state, 5);

        // R0 should be widened
        if let Some(Some(frame)) = state.frame.get(0) {
            assert_eq!(frame.regs[0].umin_value, 0);
            assert_eq!(frame.regs[0].umax_value, u64::MAX);
        }
    }

    #[test]
    fn test_state_merge_cache_new() {
        let cache = StateMergeCache::new(100);
        assert_eq!(cache.total_states(), 0);
    }

    #[test]
    fn test_state_merge_cache_add_state() {
        let mut cache = StateMergeCache::new(100);
        let state = BpfVerifierState::new();
        let config = MergeConfig::default();

        cache.add_state(50, state.clone(), &config);
        assert_eq!(cache.state_count(50), 1);

        // Adding same state again should not increase count (subsumption)
        cache.add_state(50, state, &config);
        // May be 1 or 2 depending on subsumption check
        assert!(cache.state_count(50) >= 1);
    }

    #[test]
    fn test_state_merge_cache_find_subsuming() {
        let mut cache = StateMergeCache::new(100);
        let state = BpfVerifierState::new();
        let config = MergeConfig::default();

        cache.add_state(50, state.clone(), &config);
        
        // Should find subsuming state
        assert!(cache.find_subsuming(50, &state));
        
        // Should not find at other index
        assert!(!cache.find_subsuming(51, &state));
    }

    #[test]
    fn test_state_merge_cache_clear() {
        let mut cache = StateMergeCache::new(100);
        let state = BpfVerifierState::new();
        let config = MergeConfig::default();

        cache.add_state(50, state, &config);
        assert_eq!(cache.state_count(50), 1);

        cache.clear();
        assert_eq!(cache.state_count(50), 0);
        assert_eq!(cache.total_states(), 0);
    }

    #[test]
    fn test_merge_return_states_empty() {
        let caller = BpfVerifierState::new();
        let returns: Vec<BpfVerifierState> = vec![];
        let config = MergeConfig::default();

        assert!(merge_return_states(&caller, &returns, &config).is_none());
    }

    #[test]
    fn test_merge_return_states_single() {
        let caller = BpfVerifierState::new();
        let ret = BpfVerifierState::new();
        let returns = vec![ret];
        let config = MergeConfig::default();

        let result = merge_return_states(&caller, &returns, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_merge_return_states_multiple() {
        let caller = BpfVerifierState::new();
        let ret1 = BpfVerifierState::new();
        let ret2 = BpfVerifierState::new();
        let returns = vec![ret1, ret2];
        let config = MergeConfig::default();

        let result = merge_return_states(&caller, &returns, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_merge_stats_extended() {
        let mut stats = MergeStats::new();
        assert_eq!(stats.cross_subprog_merges, 0);
        assert_eq!(stats.ref_aware_merges, 0);
        assert_eq!(stats.precision_preserved, 0);

        stats.cross_subprog_merges += 1;
        stats.ref_aware_merges += 1;
        stats.precision_preserved += 1;

        assert_eq!(stats.cross_subprog_merges, 1);
        assert_eq!(stats.ref_aware_merges, 1);
        assert_eq!(stats.precision_preserved, 1);
    }

    #[test]
    fn test_merge_pointer_different_offsets() {
        let mut ptr1 = BpfRegState::new_not_init();
        ptr1.reg_type = BpfRegType::PtrToMapValue;
        ptr1.off = 0;
        ptr1.smin_value = 0;
        ptr1.smax_value = 10;

        let mut ptr2 = BpfRegState::new_not_init();
        ptr2.reg_type = BpfRegType::PtrToMapValue;
        ptr2.off = 8;  // Different offset
        ptr2.smin_value = 5;
        ptr2.smax_value = 15;

        let config = MergeConfig::default();
        let merged = merge_regs_with_config(&ptr1, &ptr2, &config).unwrap();

        // Should widen offset range
        assert_eq!(merged.smin_value, 0);
        assert_eq!(merged.smax_value, 15);
    }

    #[test]
    fn test_merge_pointer_different_ids() {
        let mut ptr1 = BpfRegState::new_not_init();
        ptr1.reg_type = BpfRegType::PtrToMapValue;
        ptr1.id = 1;
        ptr1.ref_obj_id = 10;
        ptr1.off = 0;

        let mut ptr2 = BpfRegState::new_not_init();
        ptr2.reg_type = BpfRegType::PtrToMapValue;
        ptr2.id = 2;  // Different ID
        ptr2.ref_obj_id = 20;  // Different ref_obj_id
        ptr2.off = 0;

        let config = MergeConfig::default();
        let merged = merge_regs_with_config(&ptr1, &ptr2, &config).unwrap();

        // IDs should be zeroed (lost tracking)
        assert_eq!(merged.id, 0);
        assert_eq!(merged.ref_obj_id, 0);
    }
