// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::lock_state

use bpf_verifier::state::lock_state::*;

use super::*;

    #[test]
    fn test_acquire_release() {
        let mut state = LockState::new();
        
        // Acquire lock
        let id = state.acquire(1, 0, 10).unwrap();
        assert!(state.has_locks());
        assert_eq!(state.lock_count(), 1);
        assert!(state.is_locked(1, 0));
        
        // Release lock
        let released_id = state.release(1, 0).unwrap();
        assert_eq!(id, released_id);
        assert!(!state.has_locks());
    }

    #[test]
    fn test_double_acquire_rejected() {
        let mut state = LockState::new();
        
        state.acquire(1, 0, 10).unwrap();
        
        // Try to acquire same lock again
        let result = state.acquire(1, 0, 20);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_not_held_rejected() {
        let mut state = LockState::new();
        
        // Release without acquire
        let result = state.release(1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_nested_locks() {
        let mut state = LockState::new();
        
        // Acquire two different locks
        state.acquire(1, 0, 10).unwrap();
        state.acquire(2, 0, 20).unwrap();
        
        assert_eq!(state.lock_count(), 2);
        
        // Must release in reverse order
        state.release(2, 0).unwrap();
        state.release(1, 0).unwrap();
        
        assert!(!state.has_locks());
    }

    #[test]
    fn test_wrong_release_order_rejected() {
        let mut state = LockState::new();
        
        state.acquire(1, 0, 10).unwrap();
        state.acquire(2, 0, 20).unwrap();
        
        // Try to release first lock (wrong order)
        let result = state.release(1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_nesting() {
        let mut state = LockState::new();
        
        // Acquire up to limit
        for i in 0..MAX_LOCK_DEPTH {
            state.acquire(i as u32, 0, i * 10).unwrap();
        }
        
        // One more should fail
        let result = state.acquire(100, 0, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_all_released() {
        let mut state = LockState::new();
        
        // No locks - should pass
        assert!(state.check_all_released().is_ok());
        
        // With lock held - should fail
        state.acquire(1, 0, 10).unwrap();
        assert!(state.check_all_released().is_err());
        
        // After release - should pass
        state.release(1, 0).unwrap();
        assert!(state.check_all_released().is_ok());
    }

    #[test]
    fn test_equivalent() {
        let mut state1 = LockState::new();
        let mut state2 = LockState::new();
        
        // Empty states are equivalent
        assert!(state1.equivalent(&state2));
        
        // Same locks (maybe different IDs)
        state1.acquire(1, 0, 10).unwrap();
        state2.acquire(1, 0, 20).unwrap();
        assert!(state1.equivalent(&state2));
        
        // Different locks
        state1.acquire(2, 0, 30).unwrap();
        assert!(!state1.equivalent(&state2));
    }

    #[test]
    fn test_lock_restrictions() {
        let mut state = LockState::new();
        
        // No locks - no restrictions
        assert!(check_lock_restrictions(&state, true, true).is_ok());
        
        // With lock - sleeping helpers forbidden
        state.acquire(1, 0, 10).unwrap();
        assert!(check_lock_restrictions(&state, true, true).is_err());
        assert!(check_lock_restrictions(&state, true, false).is_ok());
        assert!(check_lock_restrictions(&state, false, true).is_ok());
    }

    // ========================================================================
    // IRQ State Tests
    // ========================================================================

    #[test]
    fn test_irq_acquire_release() {
        let mut irq = IrqState::new();
        
        // Initially no IRQs disabled
        assert!(!irq.irqs_disabled());
        assert_eq!(irq.irq_depth(), 0);
        
        // Acquire IRQ (save)
        let id = irq.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        assert!(irq.irqs_disabled());
        assert_eq!(irq.irq_depth(), 1);
        assert_eq!(irq.active_irq_id, Some(id));
        
        // Release IRQ (restore)
        irq.release_irq(id).unwrap();
        assert!(!irq.irqs_disabled());
        assert_eq!(irq.irq_depth(), 0);
        assert_eq!(irq.active_irq_id, None);
    }

    #[test]
    fn test_irq_nested() {
        let mut irq = IrqState::new();
        
        // Acquire two IRQ saves (nested)
        let id1 = irq.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        let id2 = irq.acquire_irq(20, 1, IrqKfuncClass::LocalIrqSave).unwrap();
        
        assert_eq!(irq.irq_depth(), 2);
        assert_eq!(irq.active_irq_id, Some(id2));
        
        // Must release in LIFO order
        irq.release_irq(id2).unwrap();
        assert_eq!(irq.irq_depth(), 1);
        assert_eq!(irq.active_irq_id, Some(id1));
        
        irq.release_irq(id1).unwrap();
        assert_eq!(irq.irq_depth(), 0);
    }

    #[test]
    fn test_irq_wrong_release_order() {
        let mut irq = IrqState::new();
        
        let id1 = irq.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        let _id2 = irq.acquire_irq(20, 1, IrqKfuncClass::LocalIrqSave).unwrap();
        
        // Try to release first IRQ (wrong order) - should fail
        let result = irq.release_irq(id1);
        assert!(result.is_err());
    }

    #[test]
    fn test_irq_release_without_acquire() {
        let mut irq = IrqState::new();
        
        // Try to release without acquire - should fail
        let result = irq.release_irq(42);
        assert!(result.is_err());
    }

    #[test]
    fn test_irq_check_all_restored() {
        let mut irq = IrqState::new();
        
        // Empty - should pass
        assert!(irq.check_all_restored().is_ok());
        
        // With unreleased IRQ - should fail
        let id = irq.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        assert!(irq.check_all_restored().is_err());
        
        // After release - should pass
        irq.release_irq(id).unwrap();
        assert!(irq.check_all_restored().is_ok());
    }

    #[test]
    fn test_irq_get_flag() {
        let mut irq = IrqState::new();
        
        let id = irq.acquire_irq(10, 5, IrqKfuncClass::SpinLockIrqSave).unwrap();
        
        // Should find the flag
        let flag = irq.get_irq_flag(id);
        assert!(flag.is_some());
        let flag = flag.unwrap();
        assert_eq!(flag.ref_obj_id, id);
        assert_eq!(flag.spi, 5);
        assert_eq!(flag.kfunc_class, IrqKfuncClass::SpinLockIrqSave);
        
        // Non-existent ID should return None
        assert!(irq.get_irq_flag(999).is_none());
    }

    #[test]
    fn test_irq_equivalent() {
        let mut irq1 = IrqState::new();
        let mut irq2 = IrqState::new();
        
        // Empty states are equivalent
        assert!(irq1.equivalent(&irq2));
        
        // Same depth = equivalent
        irq1.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        irq2.acquire_irq(20, 1, IrqKfuncClass::SpinLockIrqSave).unwrap();
        assert!(irq1.equivalent(&irq2));
        
        // Different depth = not equivalent
        irq1.acquire_irq(30, 2, IrqKfuncClass::LocalIrqSave).unwrap();
        assert!(!irq1.equivalent(&irq2));
    }

    #[test]
    fn test_full_sync_state() {
        let mut full = FullSyncState::new();
        
        // Initially no sync active
        assert!(!full.has_active_sync());
        assert!(full.check_all_released().is_ok());
        
        // With IRQ disabled
        full.irq.acquire_irq(10, 0, IrqKfuncClass::LocalIrqSave).unwrap();
        assert!(full.has_active_sync());
        assert!(full.check_all_released().is_err());
    }

    #[test]
    fn test_mark_unmark_irq_flag() {
        let mut irq = IrqState::new();
        
        // Mark stack slot as IRQ flag
        let id = mark_stack_slot_irq_flag(&mut irq, 10, 5, IrqKfuncClass::LocalIrqSave).unwrap();
        assert!(irq.irqs_disabled());
        
        // Unmark it
        unmark_stack_slot_irq_flag(&mut irq, id).unwrap();
        assert!(!irq.irqs_disabled());
    }

    #[test]
    fn test_unmark_irq_flag_with_class_matching() {
        let mut irq = IrqState::new();
        
        // Save with native kfunc
        let id = mark_stack_slot_irq_flag(&mut irq, 10, 5, IrqKfuncClass::LocalIrqSave).unwrap();
        
        // Restore with matching native kfunc - should succeed
        let result = unmark_stack_slot_irq_flag_with_class(
            &mut irq, id, IrqKfuncClass::LocalIrqRestore
        );
        assert!(result.is_ok());
        assert!(!irq.irqs_disabled());
    }

    #[test]
    fn test_unmark_irq_flag_with_class_mismatch() {
        let mut irq = IrqState::new();
        
        // Save with native kfunc (local_irq_save)
        let id = mark_stack_slot_irq_flag(&mut irq, 10, 5, IrqKfuncClass::LocalIrqSave).unwrap();
        
        // Try to restore with lock kfunc - should fail
        let result = unmark_stack_slot_irq_flag_with_class(
            &mut irq, id, IrqKfuncClass::SpinUnlockIrqRestore
        );
        assert!(result.is_err());
        
        // IRQ should still be disabled since restore failed
        assert!(irq.irqs_disabled());
    }

    #[test]
    fn test_unmark_irq_flag_with_class_lock_matching() {
        let mut irq = IrqState::new();
        
        // Save with lock kfunc (spin_lock_irqsave)
        let id = mark_stack_slot_irq_flag(&mut irq, 10, 5, IrqKfuncClass::SpinLockIrqSave).unwrap();
        
        // Restore with matching lock kfunc - should succeed
        let result = unmark_stack_slot_irq_flag_with_class(
            &mut irq, id, IrqKfuncClass::SpinUnlockIrqRestore
        );
        assert!(result.is_ok());
        assert!(!irq.irqs_disabled());
    }

    #[test]
    fn test_unmark_irq_flag_with_class_lock_mismatch() {
        let mut irq = IrqState::new();
        
        // Save with lock kfunc (spin_lock_irqsave)
        let id = mark_stack_slot_irq_flag(&mut irq, 10, 5, IrqKfuncClass::SpinLockIrqSave).unwrap();
        
        // Try to restore with native kfunc - should fail
        let result = unmark_stack_slot_irq_flag_with_class(
            &mut irq, id, IrqKfuncClass::LocalIrqRestore
        );
        assert!(result.is_err());
        assert!(irq.irqs_disabled());
    }

    #[test]
    fn test_unmark_irq_flag_not_found() {
        let mut irq = IrqState::new();
        
        // Try to unmark non-existent IRQ flag
        let result = unmark_stack_slot_irq_flag_with_class(
            &mut irq, 999, IrqKfuncClass::LocalIrqRestore
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_irq_kfunc_helpers() {
        // Test get_irq_kfunc_class
        assert_eq!(get_irq_kfunc_class(irq_kfuncs::LOCAL_IRQ_SAVE), Some(IrqKfuncClass::LocalIrqSave));
        assert_eq!(get_irq_kfunc_class(irq_kfuncs::LOCAL_IRQ_RESTORE), Some(IrqKfuncClass::LocalIrqRestore));
        assert_eq!(get_irq_kfunc_class(irq_kfuncs::SPIN_LOCK_IRQSAVE), Some(IrqKfuncClass::SpinLockIrqSave));
        assert_eq!(get_irq_kfunc_class(irq_kfuncs::SPIN_UNLOCK_IRQRESTORE), Some(IrqKfuncClass::SpinUnlockIrqRestore));
        assert_eq!(get_irq_kfunc_class(0), None);
        
        // Test is_irq_save_kfunc
        assert!(is_irq_save_kfunc(irq_kfuncs::LOCAL_IRQ_SAVE));
        assert!(is_irq_save_kfunc(irq_kfuncs::SPIN_LOCK_IRQSAVE));
        assert!(!is_irq_save_kfunc(irq_kfuncs::LOCAL_IRQ_RESTORE));
        assert!(!is_irq_save_kfunc(irq_kfuncs::SPIN_UNLOCK_IRQRESTORE));
        
        // Test is_irq_restore_kfunc
        assert!(is_irq_restore_kfunc(irq_kfuncs::LOCAL_IRQ_RESTORE));
        assert!(is_irq_restore_kfunc(irq_kfuncs::SPIN_UNLOCK_IRQRESTORE));
        assert!(!is_irq_restore_kfunc(irq_kfuncs::LOCAL_IRQ_SAVE));
        assert!(!is_irq_restore_kfunc(irq_kfuncs::SPIN_LOCK_IRQSAVE));
    }
