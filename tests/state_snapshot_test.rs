// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::snapshot

use bpf_verifier::prelude::*;
use bpf_verifier::state::snapshot::*;


    fn make_scalar_snapshot(value: u64, mask: u64) -> RegSnapshot {
        RegSnapshot {
            reg_type: BpfRegType::ScalarValue,
            tnum_value: value,
            tnum_mask: mask,
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            off: 0,
            var_off_min: 0,
            var_off_max: 0,
            ref_obj_id: 0,
            map_uid: 0,
        }
    }

    fn make_const_snapshot(value: u64) -> RegSnapshot {
        RegSnapshot {
            reg_type: BpfRegType::ScalarValue,
            tnum_value: value,
            tnum_mask: 0,
            smin: value as i64,
            smax: value as i64,
            umin: value,
            umax: value,
            off: 0,
            var_off_min: value as i64,
            var_off_max: value as i64,
            ref_obj_id: 0,
            map_uid: 0,
        }
    }

    fn make_uninit_snapshot() -> RegSnapshot {
        RegSnapshot {
            reg_type: BpfRegType::NotInit,
            tnum_value: 0,
            tnum_mask: u64::MAX,
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            off: 0,
            var_off_min: i64::MIN,
            var_off_max: i64::MAX,
            ref_obj_id: 0,
            map_uid: 0,
        }
    }

    #[test]
    fn test_const_snapshot() {
        let snap = make_const_snapshot(42);
        assert!(snap.is_const());
        assert_eq!(snap.const_value(), Some(42));

        let snap2 = make_scalar_snapshot(42, 0xFF);
        assert!(!snap2.is_const());
        assert_eq!(snap2.const_value(), None);
    }

    #[test]
    fn test_scalar_substate() {
        // More precise (narrower range) is substate of less precise
        let narrow = RegSnapshot {
            reg_type: BpfRegType::ScalarValue,
            tnum_value: 0,
            tnum_mask: 0xFF, // Only low 8 bits unknown
            smin: 0,
            smax: 100,
            umin: 0,
            umax: 100,
            off: 0,
            var_off_min: 0,
            var_off_max: 100,
            ref_obj_id: 0,
            map_uid: 0,
        };

        let wide = RegSnapshot {
            reg_type: BpfRegType::ScalarValue,
            tnum_value: 0,
            tnum_mask: 0xFFFF, // Low 16 bits unknown
            smin: -1000,
            smax: 1000,
            umin: 0,
            umax: 1000,
            off: 0,
            var_off_min: -1000,
            var_off_max: 1000,
            ref_obj_id: 0,
            map_uid: 0,
        };

        assert!(narrow.is_substate_of(&wide));
        assert!(!wide.is_substate_of(&narrow));
    }

    #[test]
    fn test_type_mismatch() {
        let scalar = make_const_snapshot(42);
        let ptr = RegSnapshot {
            reg_type: BpfRegType::PtrToStack,
            tnum_value: 0,
            tnum_mask: 0,
            smin: 0,
            smax: 0,
            umin: 0,
            umax: 0,
            off: -8,
            var_off_min: 0,
            var_off_max: 0,
            ref_obj_id: 0,
            map_uid: 0,
        };

        assert!(!scalar.is_substate_of(&ptr));
        assert!(!ptr.is_substate_of(&scalar));
    }

    #[test]
    fn test_uninit_compatibility() {
        let scalar = make_const_snapshot(42);
        let uninit = make_uninit_snapshot();

        // Any state is substate of uninit
        assert!(scalar.is_substate_of(&uninit));
        // Uninit is NOT substate of initialized
        assert!(!uninit.is_substate_of(&scalar));
    }

    #[test]
    fn test_regs_snapshot_substate() {
        let mut regs1: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let mut regs2: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());

        // Set r0 to constant in both
        regs1[0] = make_const_snapshot(42);
        regs2[0] = make_const_snapshot(42);

        let snap1 = RegsSnapshot { regs: regs1 };
        let snap2 = RegsSnapshot { regs: regs2 };

        assert!(snap1.is_substate_of(&snap2));
        assert!(snap2.is_substate_of(&snap1));
    }

    #[test]
    fn test_stack_snapshot() {
        let mut stack1 = StackSnapshot::new();
        stack1.add_slot(-8, StackSlotType::Spill, Some(make_const_snapshot(100)));

        let mut stack2 = StackSnapshot::new();
        stack2.add_slot(-8, StackSlotType::Spill, Some(make_const_snapshot(100)));

        assert!(stack1.is_substate_of(&stack2));
    }

    #[test]
    fn test_stack_snapshot_different_types() {
        let mut stack1 = StackSnapshot::new();
        stack1.add_slot(-8, StackSlotType::Spill, None);

        let mut stack2 = StackSnapshot::new();
        stack2.add_slot(-8, StackSlotType::Misc, None);

        assert!(!stack1.is_substate_of(&stack2));
    }

    #[test]
    fn test_state_cache_basic() {
        let mut cache = StateCache::new();

        let regs: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let regs_snap = RegsSnapshot { regs };
        let stack = StackSnapshot::new();
        let state = StateSnapshot::new(regs_snap, stack, 0);

        // First check should miss
        assert!(!cache.check_prune(0, &state));
        assert_eq!(cache.misses, 1);

        // Add state
        cache.add_state(0, state.clone());
        assert_eq!(cache.stored, 1);

        // Second check should hit
        assert!(cache.check_prune(0, &state));
        assert_eq!(cache.hits, 1);
    }

    #[test]
    fn test_state_cache_stats() {
        let mut cache = StateCache::new();

        let regs: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let regs_snap = RegsSnapshot { regs };
        let stack = StackSnapshot::new();
        let state = StateSnapshot::new(regs_snap, stack, 0);

        // Miss
        cache.check_prune(0, &state);
        cache.add_state(0, state.clone());
        
        // Hit
        cache.check_prune(0, &state);

        assert_eq!(cache.hit_rate(), 50.0);
        assert_eq!(cache.total_states(), 1);
        assert_eq!(cache.states_at(0), 1);
        assert_eq!(cache.states_at(1), 0);
    }

    #[test]
    fn test_state_snapshot_refs_and_locks() {
        let regs: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let regs_snap = RegsSnapshot { regs };
        let stack = StackSnapshot::new();
        
        let mut state1 = StateSnapshot::new(regs_snap.clone(), stack.clone(), 0);
        state1.add_ref(1);
        state1.add_lock(10);

        let mut state2 = StateSnapshot::new(regs_snap, stack, 0);
        state2.add_ref(1);
        state2.add_ref(2);
        state2.add_lock(10);

        // state1 has subset of refs, same locks - is substate
        assert!(state1.is_substate_of(&state2));
        
        // state2 has more refs - not substate
        assert!(!state2.is_substate_of(&state1));
    }

    #[test]
    fn test_state_snapshot_call_depth() {
        let regs: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let regs_snap = RegsSnapshot { regs };
        let stack = StackSnapshot::new();

        let state1 = StateSnapshot::new(regs_snap.clone(), stack.clone(), 0);
        let state2 = StateSnapshot::new(regs_snap, stack, 1);

        // Different call depths are not substates
        assert!(!state1.is_substate_of(&state2));
        assert!(!state2.is_substate_of(&state1));
    }

    #[test]
    fn test_quick_hash() {
        let regs1: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        let mut regs2: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| make_uninit_snapshot());
        regs2[0] = make_const_snapshot(42);

        let snap1 = RegsSnapshot { regs: regs1 };
        let snap2 = RegsSnapshot { regs: regs2 };

        // Different states should (usually) have different hashes
        assert_ne!(snap1.quick_hash(), snap2.quick_hash());
    }
