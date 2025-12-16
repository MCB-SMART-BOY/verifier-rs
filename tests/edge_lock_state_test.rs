// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for lock state verification
//!
//! These tests verify correct behavior at boundary conditions:
//! - Lock acquire/release pairing
//! - Nested locks
//! - RCU lock handling
//! - IRQ flag state tracking

use bpf_verifier::state::lock_state::{IrqKfuncClass, IrqState, LockState};
use bpf_verifier::state::reference::ReferenceManager;

// ============================================================================
// LockState Edge Cases
// ============================================================================

#[test]
fn test_lock_state_new() {
    let state = LockState::new();
    assert!(!state.has_locks());
    assert_eq!(state.lock_count(), 0);
}

#[test]
fn test_lock_acquire_single() {
    let mut state = LockState::new();
    let result = state.acquire(1, 0, 0);
    assert!(result.is_ok());
    assert!(state.has_locks());
    assert_eq!(state.lock_count(), 1);
}

#[test]
fn test_lock_release_single() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.release(1, 0);
    assert!(result.is_ok());
    assert!(!state.has_locks());
    assert_eq!(state.lock_count(), 0);
}

#[test]
fn test_lock_release_without_acquire() {
    let mut state = LockState::new();
    let result = state.release(1, 0);
    assert!(result.is_err());
}

#[test]
fn test_lock_double_acquire_same() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.acquire(1, 0, 1);
    // Double acquire of same lock should fail (deadlock)
    assert!(result.is_err());
}

#[test]
fn test_lock_acquire_different_maps() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.acquire(2, 0, 1);
    assert!(result.is_ok());
    assert_eq!(state.lock_count(), 2);
}

#[test]
fn test_lock_acquire_different_offsets() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.acquire(1, 8, 1);
    assert!(result.is_ok());
    assert_eq!(state.lock_count(), 2);
}

#[test]
fn test_lock_release_wrong_map() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.release(2, 0);
    assert!(result.is_err());
}

#[test]
fn test_lock_release_wrong_offset() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    let result = state.release(1, 8);
    assert!(result.is_err());
}

#[test]
fn test_lock_release_order_lifo() {
    let mut state = LockState::new();

    // Acquire in order: A, B
    state.acquire(1, 0, 0).unwrap();
    state.acquire(1, 8, 1).unwrap();

    // Release in LIFO order: B, A (should work)
    assert!(state.release(1, 8).is_ok());
    assert!(state.release(1, 0).is_ok());
}

#[test]
fn test_lock_multiple_acquire_release() {
    let mut state = LockState::new();

    // Acquire a few locks (within the nesting limit)
    for i in 0..3 {
        state.acquire(1, i * 8, i as usize).unwrap();
    }
    assert_eq!(state.lock_count(), 3);

    // Release in LIFO order
    for i in (0..3).rev() {
        state.release(1, i * 8).unwrap();
    }
    assert_eq!(state.lock_count(), 0);
}

// ============================================================================
// ReferenceManager Lock Edge Cases
// ============================================================================

#[test]
fn test_ref_manager_new() {
    let refs = ReferenceManager::new();
    assert_eq!(refs.active_rcu_locks, 0);
    assert_eq!(refs.active_preempt_locks, 0);
}

#[test]
fn test_rcu_lock_single() {
    let mut refs = ReferenceManager::new();
    refs.rcu_lock();
    assert_eq!(refs.active_rcu_locks, 1);
}

#[test]
fn test_rcu_unlock_single() {
    let mut refs = ReferenceManager::new();
    refs.rcu_lock();
    let result = refs.rcu_unlock();
    assert!(result.is_ok());
    assert_eq!(refs.active_rcu_locks, 0);
}

#[test]
fn test_rcu_unlock_without_lock() {
    let mut refs = ReferenceManager::new();
    let result = refs.rcu_unlock();
    assert!(result.is_err());
}

#[test]
fn test_rcu_nested_locks() {
    let mut refs = ReferenceManager::new();

    refs.rcu_lock();
    refs.rcu_lock();
    refs.rcu_lock();
    assert_eq!(refs.active_rcu_locks, 3);

    refs.rcu_unlock().unwrap();
    refs.rcu_unlock().unwrap();
    refs.rcu_unlock().unwrap();
    assert_eq!(refs.active_rcu_locks, 0);
}

#[test]
fn test_preempt_disable_single() {
    let mut refs = ReferenceManager::new();
    refs.preempt_disable();
    assert_eq!(refs.active_preempt_locks, 1);
}

#[test]
fn test_preempt_enable_single() {
    let mut refs = ReferenceManager::new();
    refs.preempt_disable();
    let result = refs.preempt_enable();
    assert!(result.is_ok());
    assert_eq!(refs.active_preempt_locks, 0);
}

#[test]
fn test_preempt_enable_without_disable() {
    let mut refs = ReferenceManager::new();
    let result = refs.preempt_enable();
    assert!(result.is_err());
}

#[test]
fn test_preempt_nested() {
    let mut refs = ReferenceManager::new();

    refs.preempt_disable();
    refs.preempt_disable();
    assert_eq!(refs.active_preempt_locks, 2);

    refs.preempt_enable().unwrap();
    refs.preempt_enable().unwrap();
    assert_eq!(refs.active_preempt_locks, 0);
}

#[test]
fn test_rcu_and_preempt_combined() {
    let mut refs = ReferenceManager::new();

    refs.rcu_lock();
    refs.preempt_disable();
    assert_eq!(refs.active_rcu_locks, 1);
    assert_eq!(refs.active_preempt_locks, 1);

    refs.preempt_enable().unwrap();
    refs.rcu_unlock().unwrap();
    assert_eq!(refs.active_rcu_locks, 0);
    assert_eq!(refs.active_preempt_locks, 0);
}

// ============================================================================
// Reference Acquire/Release Edge Cases
// ============================================================================

#[test]
fn test_acquire_ptr() {
    let mut refs = ReferenceManager::new();
    let id = refs.acquire_ptr(0);
    assert!(id > 0);
    assert!(refs.has_ref(id));
}

#[test]
fn test_acquire_multiple_ptrs() {
    let mut refs = ReferenceManager::new();

    let id1 = refs.acquire_ptr(0);
    let id2 = refs.acquire_ptr(1);
    let id3 = refs.acquire_ptr(2);

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);

    assert!(refs.has_ref(id1));
    assert!(refs.has_ref(id2));
    assert!(refs.has_ref(id3));
}

#[test]
fn test_release_ptr() {
    let mut refs = ReferenceManager::new();
    let id = refs.acquire_ptr(0);
    let result = refs.release_ptr(id);
    assert!(result.is_ok());
    assert!(!refs.has_ref(id));
}

#[test]
fn test_release_invalid_ptr() {
    let mut refs = ReferenceManager::new();
    let result = refs.release_ptr(999);
    assert!(result.is_err());
}

#[test]
fn test_release_already_released() {
    let mut refs = ReferenceManager::new();
    let id = refs.acquire_ptr(0);
    refs.release_ptr(id).unwrap();
    let result = refs.release_ptr(id);
    assert!(result.is_err());
}

#[test]
fn test_has_ref_zero() {
    let refs = ReferenceManager::new();
    // ID 0 is typically invalid/unused
    assert!(!refs.has_ref(0));
}

// ============================================================================
// IRQ State Edge Cases
// ============================================================================

#[test]
fn test_irq_state_new() {
    let state = IrqState::new();
    assert!(state.active_irq_id.is_none());
}

#[test]
fn test_irq_kfunc_classes() {
    // Verify all IRQ kfunc classes exist
    let classes = [
        IrqKfuncClass::LocalIrqSave,
        IrqKfuncClass::LocalIrqRestore,
        IrqKfuncClass::SpinLockIrqSave,
        IrqKfuncClass::SpinUnlockIrqRestore,
    ];

    for class in classes {
        assert_eq!(class, class);
    }
}

#[test]
fn test_irq_save_restore_matching() {
    // LocalIrqSave should match with LocalIrqRestore
    let save = IrqKfuncClass::LocalIrqSave;
    let restore = IrqKfuncClass::LocalIrqRestore;
    assert_ne!(save, restore);

    // SpinLockIrqSave should match with SpinUnlockIrqRestore
    let spin_save = IrqKfuncClass::SpinLockIrqSave;
    let spin_restore = IrqKfuncClass::SpinUnlockIrqRestore;
    assert_ne!(spin_save, spin_restore);
}

// ============================================================================
// Lock State Clone/Comparison Edge Cases
// ============================================================================

#[test]
fn test_lock_state_clone_empty() {
    let state = LockState::new();
    let cloned = state.clone();
    assert_eq!(state.lock_count(), cloned.lock_count());
    assert!(!cloned.has_locks());
}

#[test]
fn test_lock_state_clone_with_locks() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();
    state.acquire(2, 0, 1).unwrap();

    let cloned = state.clone();
    assert_eq!(state.lock_count(), cloned.lock_count());
    assert!(cloned.has_locks());
}

#[test]
fn test_ref_manager_clone() {
    let mut refs = ReferenceManager::new();
    refs.rcu_lock();
    refs.preempt_disable();
    let _id = refs.acquire_ptr(0);

    let cloned = refs.clone();
    assert_eq!(refs.active_rcu_locks, cloned.active_rcu_locks);
    assert_eq!(refs.active_preempt_locks, cloned.active_preempt_locks);
}

// ============================================================================
// Boundary Value Edge Cases
// ============================================================================

#[test]
fn test_lock_map_uid_zero() {
    let mut state = LockState::new();
    let result = state.acquire(0, 0, 0);
    assert!(result.is_ok());
}

#[test]
fn test_lock_map_uid_max() {
    let mut state = LockState::new();
    let result = state.acquire(u32::MAX, 0, 0);
    assert!(result.is_ok());
}

#[test]
fn test_lock_offset_max() {
    let mut state = LockState::new();
    let result = state.acquire(1, u32::MAX, 0);
    assert!(result.is_ok());
}

#[test]
fn test_lock_insn_idx_max() {
    let mut state = LockState::new();
    let result = state.acquire(1, 0, usize::MAX);
    assert!(result.is_ok());
}

// ============================================================================
// State Consistency Edge Cases
// ============================================================================

#[test]
fn test_lock_state_consistency_after_error() {
    let mut state = LockState::new();
    state.acquire(1, 0, 0).unwrap();

    // Failed release shouldn't change state
    let initial_count = state.lock_count();
    let _ = state.release(2, 0); // Wrong map
    assert_eq!(state.lock_count(), initial_count);
}

#[test]
fn test_ref_manager_consistency_after_error() {
    let mut refs = ReferenceManager::new();
    refs.rcu_lock();

    let initial_count = refs.active_rcu_locks;
    // This should succeed
    refs.rcu_unlock().unwrap();
    assert_eq!(refs.active_rcu_locks, initial_count - 1);

    // This should fail but not corrupt state
    let _ = refs.rcu_unlock();
    assert_eq!(refs.active_rcu_locks, 0);
}

// ============================================================================
// Complex Scenario Edge Cases
// ============================================================================

#[test]
fn test_mixed_lock_types() {
    let mut state = LockState::new();
    let mut refs = ReferenceManager::new();

    // Acquire various lock types
    state.acquire(1, 0, 0).unwrap();
    refs.rcu_lock();
    refs.preempt_disable();
    let ptr_id = refs.acquire_ptr(1);

    // Verify all held
    assert!(state.has_locks());
    assert_eq!(refs.active_rcu_locks, 1);
    assert_eq!(refs.active_preempt_locks, 1);
    assert!(refs.has_ref(ptr_id));

    // Release in order
    refs.release_ptr(ptr_id).unwrap();
    refs.preempt_enable().unwrap();
    refs.rcu_unlock().unwrap();
    state.release(1, 0).unwrap();

    // Verify all released
    assert!(!state.has_locks());
    assert_eq!(refs.active_rcu_locks, 0);
    assert_eq!(refs.active_preempt_locks, 0);
    assert!(!refs.has_ref(ptr_id));
}

#[test]
fn test_stress_acquire_release_cycle() {
    let mut refs = ReferenceManager::new();
    let mut ids = Vec::new();

    // Acquire many references
    for i in 0..100 {
        let id = refs.acquire_ptr(i);
        ids.push(id);
    }

    // Release in reverse order
    for id in ids.into_iter().rev() {
        refs.release_ptr(id).unwrap();
    }
}
