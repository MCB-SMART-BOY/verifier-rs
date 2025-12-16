// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::sleepable

use bpf_verifier::prelude::*;
use bpf_verifier::check::sleepable::*;

    use bpf_verifier::state::reference::ReferenceManager;
    use bpf_verifier::core::types::BpfRegType;

    #[test]
    fn test_sleepable_context() {
        let mut ctx = SleepableContext::new(true);
        assert!(!ctx.in_atomic_context());

        ctx.enter_spin_lock();
        assert!(ctx.in_atomic_context());

        ctx.leave_spin_lock();
        assert!(!ctx.in_atomic_context());
    }

    #[test]
    fn test_atomic_depth() {
        let mut ctx = SleepableContext::new(true);
        ctx.enter_atomic();
        ctx.enter_atomic();
        assert!(ctx.in_atomic_context());

        ctx.leave_atomic().unwrap();
        assert!(ctx.in_atomic_context());

        ctx.leave_atomic().unwrap();
        assert!(!ctx.in_atomic_context());
    }

    #[test]
    fn test_check_sleepable_call_with_lock() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Should succeed without locks
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_ok());

        // Should fail with lock held
        refs.acquire_lock(0, 0x1000);
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_check_sleepable_call_with_rcu() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();

        // Should succeed without RCU
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_ok());

        // Should fail with RCU held
        refs.rcu_lock();
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_check_sleepable_call_non_sleepable_prog() {
        let state = BpfVerifierState::new(); // in_sleepable = false by default
        let refs = ReferenceManager::new();

        // Should fail because program is not sleepable
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_is_sleepable_helper() {
        assert!(is_sleepable_helper(113)); // bpf_copy_from_user
        assert!(is_sleepable_helper(174)); // bpf_find_vma
        assert!(!is_sleepable_helper(1));  // bpf_map_lookup_elem
    }

    #[test]
    fn test_is_forbidden_in_sleepable() {
        assert!(is_forbidden_in_sleepable(12)); // bpf_tail_call
        assert!(is_forbidden_in_sleepable(35)); // bpf_spin_lock
        assert!(!is_forbidden_in_sleepable(1)); // bpf_map_lookup_elem
    }

    #[test]
    fn test_in_sleepable_context() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Sleepable program with no locks - should be in sleepable context
        assert!(in_sleepable_context(&state, &refs));
        
        // With RCU lock - not in sleepable context
        refs.rcu_lock();
        assert!(!in_sleepable_context(&state, &refs));
        refs.rcu_unlock().unwrap();
        
        // With preempt disabled - not in sleepable context
        refs.preempt_disable();
        assert!(!in_sleepable_context(&state, &refs));
        refs.preempt_enable().unwrap();
        
        // Non-sleepable program - not in sleepable context
        state.in_sleepable = false;
        assert!(!in_sleepable_context(&state, &refs));
    }

    #[test]
    fn test_in_rcu_cs() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Sleepable program with no locks - not in RCU CS
        assert!(!in_rcu_cs(&state, &refs));
        
        // With RCU lock - in RCU CS
        refs.rcu_lock();
        assert!(in_rcu_cs(&state, &refs));
        refs.rcu_unlock().unwrap();
        
        // With spin lock - in RCU CS
        refs.acquire_lock(0, 0x1000);
        assert!(in_rcu_cs(&state, &refs));
        
        // Non-sleepable program - always in RCU CS
        state.in_sleepable = false;
        let refs2 = ReferenceManager::new();
        assert!(in_rcu_cs(&state, &refs2));
    }

    #[test]
    fn test_clear_rcu_flag() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToBtfId;
        reg.type_flags.insert(BpfTypeFlag::MEM_RCU);
        reg.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
        
        assert!(reg.type_flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
        
        clear_rcu_flag(&mut reg);
        
        assert!(!reg.type_flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(!reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_get_kfunc_sync_action() {
        assert_eq!(get_kfunc_sync_action("bpf_rcu_read_lock"), KfuncSyncAction::RcuLock);
        assert_eq!(get_kfunc_sync_action("bpf_rcu_read_unlock"), KfuncSyncAction::RcuUnlock);
        assert_eq!(get_kfunc_sync_action("bpf_preempt_disable"), KfuncSyncAction::PreemptDisable);
        assert_eq!(get_kfunc_sync_action("bpf_preempt_enable"), KfuncSyncAction::PreemptEnable);
        assert_eq!(get_kfunc_sync_action("other_kfunc"), KfuncSyncAction::None);
    }

    #[test]
    fn test_check_kfunc_sync_context_rcu() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // RCU unlock without lock should fail
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_rcu_read_unlock", false).is_err());
        
        // RCU lock should succeed
        refs.rcu_lock();
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_rcu_read_unlock", false).is_ok());
        
        // Sleepable kfunc in RCU region should fail
        assert!(check_kfunc_sync_context(&state, &refs, "sleepable_kfunc", true).is_err());
    }

    #[test]
    fn test_check_kfunc_sync_context_preempt() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Preempt enable without disable should fail
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_preempt_enable", false).is_err());
        
        // Preempt disable should succeed
        refs.preempt_disable();
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_preempt_enable", false).is_ok());
        
        // Sleepable kfunc in preempt-disabled region should fail
        assert!(check_kfunc_sync_context(&state, &refs, "sleepable_kfunc", true).is_err());
    }

    #[test]
    fn test_apply_kfunc_sync_action() {
        let mut refs = ReferenceManager::new();
        
        // RCU lock
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_lock").unwrap());
        assert_eq!(refs.active_rcu_locks, 1);
        
        // Nested RCU lock
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_lock").unwrap());
        assert_eq!(refs.active_rcu_locks, 2);
        
        // RCU unlock (not last)
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_unlock").unwrap());
        assert_eq!(refs.active_rcu_locks, 1);
        
        // RCU unlock (last) - should return true for MEM_RCU clearing
        assert!(apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_unlock").unwrap());
        assert_eq!(refs.active_rcu_locks, 0);
    }

    #[test]
    fn test_check_global_func_sleepable() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Non-sleepable function should always pass
        assert!(check_global_func_sleepable(&state, &refs, "func", false).is_ok());
        
        // Sleepable function in sleepable context should pass
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_ok());
        
        // Sleepable function in RCU region should fail
        refs.rcu_lock();
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
        refs.rcu_unlock().unwrap();
        
        // Sleepable function in preempt-disabled region should fail
        refs.preempt_disable();
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
        refs.preempt_enable().unwrap();
        
        // Sleepable function in non-sleepable program should fail
        state.in_sleepable = false;
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
    }

    #[test]
    fn test_propagate_might_sleep() {
        let mut caller = false;
        
        // Propagate from non-sleeping callee
        propagate_might_sleep(&mut caller, false);
        assert!(!caller);
        
        // Propagate from sleeping callee
        propagate_might_sleep(&mut caller, true);
        assert!(caller);
        
        // Already sleeping caller stays sleeping
        propagate_might_sleep(&mut caller, false);
        assert!(caller);
    }

    #[test]
    fn test_check_iter_rcu_protected() {
        let mut refs = ReferenceManager::new();
        
        // Non-RCU-protected iterator should pass
        assert!(check_iter_rcu_protected(&refs, "iter", false).is_ok());
        
        // RCU-protected iterator without RCU lock should fail
        assert!(check_iter_rcu_protected(&refs, "iter", true).is_err());
        
        // RCU-protected iterator with RCU lock should pass
        refs.rcu_lock();
        assert!(check_iter_rcu_protected(&refs, "iter", true).is_ok());
    }
