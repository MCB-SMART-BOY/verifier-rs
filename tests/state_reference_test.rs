// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::reference

use bpf_verifier::state::reference::*;


    #[test]
    fn test_acquire_release_ptr() {
        let mut mgr = ReferenceManager::new();
        let id = mgr.acquire_ptr(0);
        assert!(mgr.has_ref(id));
        assert!(mgr.release_ptr(id).is_ok());
        assert!(!mgr.has_ref(id));
    }

    #[test]
    fn test_acquire_release_lock() {
        let mut mgr = ReferenceManager::new();
        let id = mgr.acquire_lock(0, 0x1000);
        assert_eq!(mgr.active_locks, 1);
        assert_eq!(mgr.active_lock_id, id);
        assert!(mgr.release_lock(id, 0x1000).is_ok());
        assert_eq!(mgr.active_locks, 0);
    }

    #[test]
    fn test_irq_ordering() {
        let mut mgr = ReferenceManager::new();
        let id1 = mgr.acquire_irq(0);
        let id2 = mgr.acquire_irq(1);

        // Must release in order (id2 first, then id1)
        assert!(mgr.release_irq(id1).is_err()); // Wrong order
        assert!(mgr.release_irq(id2).is_ok());
        assert!(mgr.release_irq(id1).is_ok());
    }

    #[test]
    fn test_rcu_lock() {
        let mut mgr = ReferenceManager::new();
        assert!(!mgr.in_rcu());
        mgr.rcu_lock();
        assert!(mgr.in_rcu());
        assert!(mgr.rcu_unlock().is_ok());
        assert!(!mgr.in_rcu());
    }

    #[test]
    fn test_check_unreleased() {
        let mut mgr = ReferenceManager::new();
        mgr.acquire_ptr(0);
        assert!(mgr.check_all_released().is_err());
    }
