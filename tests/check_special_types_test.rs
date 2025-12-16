// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::special_types

use bpf_verifier::check::special_types::*;

use super::*;

    #[test]
    fn test_special_types_context() {
        let ctx = SpecialTypesContext::new();
        assert!(!ctx.has_held_resources());
        assert!(ctx.validate_exit().is_ok());
    }

    #[test]
    fn test_lock_handling() {
        let mut ctx = SpecialTypesContext::new();
        
        // Acquire spin lock
        handle_lock_acquire(&mut ctx, LockType::SpinLock).unwrap();
        assert_eq!(ctx.spin_lock_depth, 1);
        assert!(ctx.has_held_resources());
        
        // Release spin lock
        handle_lock_release(&mut ctx, LockType::SpinLock).unwrap();
        assert_eq!(ctx.spin_lock_depth, 0);
        assert!(!ctx.has_held_resources());
    }

    #[test]
    fn test_lock_mismatch() {
        let mut ctx = SpecialTypesContext::new();
        
        // Try to release without acquire
        let result = handle_lock_release(&mut ctx, LockType::SpinLock);
        assert!(result.is_err());
    }

    #[test]
    fn test_sleepable_spinlock() {
        let mut ctx = SpecialTypesContext::new();
        ctx.sleepable = true;
        
        // Spin lock not allowed in sleepable
        let result = handle_lock_acquire(&mut ctx, LockType::SpinLock);
        assert!(result.is_err());
    }
