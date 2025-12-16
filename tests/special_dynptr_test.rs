// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::dynptr

use bpf_verifier::special::dynptr::*;

use super::*;

    #[test]
    fn test_dynptr_type_refcounted() {
        assert!(BpfDynptrType::Ringbuf.is_refcounted());
        assert!(BpfDynptrType::File.is_refcounted());
        assert!(!BpfDynptrType::Local.is_refcounted());
        assert!(!BpfDynptrType::Skb.is_refcounted());
    }

    #[test]
    fn test_is_dynptr_valid_uninit() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.var_off = crate::bounds::tnum::Tnum::const_value(0);
        reg.off = -16;

        let stack = StackManager::new();
        assert!(is_dynptr_reg_valid_uninit(&reg, &stack));
    }

    // ========================================================================
    // Nested State Machine Tests
    // ========================================================================

    #[test]
    fn test_nested_context_transitions() {
        let mut ctx = NestedDynptrContext::new();
        
        // Must init first
        assert!(ctx.transition(DynptrTransition::Slice).is_err());
        
        // Init then slice
        assert!(ctx.transition(DynptrTransition::Init).is_ok());
        assert_eq!(ctx.state, DynptrState::Valid);
        
        assert!(ctx.transition(DynptrTransition::Slice).is_ok());
        assert_eq!(ctx.state, DynptrState::Sliced);
        
        // Can release from sliced
        assert!(ctx.transition(DynptrTransition::Release).is_ok());
        assert_eq!(ctx.state, DynptrState::Released);
        
        // Cannot use after release
        assert!(ctx.transition(DynptrTransition::Check).is_err());
    }

    #[test]
    fn test_nested_depth_limit() {
        let mut ctx = NestedDynptrContext::new();
        ctx.state = DynptrState::Valid;
        
        // First slice changes state to Sliced
        assert!(ctx.transition(DynptrTransition::Slice).is_ok());
        assert_eq!(ctx.state, DynptrState::Sliced);
        
        // Subsequent slices increase depth (depth starts at 0, increments on each slice)
        // After first slice: state=Sliced, depth=0
        // After second slice: state=Sliced, depth=1
        // ...
        // After (MAX+1) slices: depth=MAX, should fail on next
        for _ in 1..MAX_NESTED_DYNPTR_DEPTH {
            assert!(ctx.transition(DynptrTransition::Slice).is_ok());
        }
        
        // At this point depth == MAX_NESTED_DYNPTR_DEPTH - 1
        // One more slice will increment to MAX and succeed
        assert!(ctx.transition(DynptrTransition::Slice).is_ok());
        
        // Now depth == MAX_NESTED_DYNPTR_DEPTH, next should fail
        assert!(ctx.transition(DynptrTransition::Slice).is_err());
    }

    #[test]
    fn test_adjustment_tracking() {
        let mut ctx = NestedDynptrContext::new();
        ctx.state = DynptrState::Valid;
        
        assert!(ctx.transition(DynptrTransition::Adjust).is_ok());
        assert_eq!(ctx.state, DynptrState::Adjusted);
        
        ctx.record_adjustment(10, 100);
        assert!(ctx.adjustment.is_some());
        
        let adj = ctx.adjustment.as_ref().unwrap();
        assert_eq!(adj.current_start, 10);
        assert_eq!(adj.current_end, 100);
    }

    // ========================================================================
    // Exception Context Tests
    // ========================================================================

    #[test]
    fn test_exception_state_enter_exit() {
        let mut state = DynptrExceptionState::new();
        
        assert!(!state.in_try_block);
        
        state.enter_try();
        assert!(state.in_try_block);
        assert_eq!(state.exception_depth, 1);
        
        state.enter_try(); // Nested
        assert_eq!(state.exception_depth, 2);
        
        state.exit_try();
        assert_eq!(state.exception_depth, 1);
        assert!(state.in_try_block);
        
        state.exit_try();
        assert_eq!(state.exception_depth, 0);
        assert!(!state.in_try_block);
    }

    #[test]
    fn test_exception_cleanup_marking() {
        let mut state = DynptrExceptionState::new();
        
        state.enter_try();
        state.mark_for_cleanup(1);
        state.mark_for_cleanup(2);
        state.mark_for_cleanup(1); // Duplicate
        
        assert_eq!(state.get_cleanup_list().len(), 2);
        
        state.clear_cleanup();
        assert!(state.get_cleanup_list().is_empty());
    }

    // ========================================================================
    // Iterator Context Tests
    // ========================================================================

    #[test]
    fn test_iterator_context_basics() {
        let mut iter_ctx = DynptrIteratorContext::new(100);
        
        iter_ctx.register_dynptr(1);
        iter_ctx.register_dynptr(2);
        iter_ctx.register_dynptr(1); // Duplicate
        
        assert_eq!(iter_ctx.iteration_dynptrs.len(), 2);
        
        // Iterate
        for _ in 0..50 {
            assert!(iter_ctx.next_iteration().is_ok());
        }
        assert_eq!(iter_ctx.current_iteration, 50);
    }

    #[test]
    fn test_iterator_max_iterations() {
        let mut iter_ctx = DynptrIteratorContext::new(10);
        
        for _ in 0..10 {
            assert!(iter_ctx.next_iteration().is_ok());
        }
        
        // Exceeds limit
        assert!(iter_ctx.next_iteration().is_err());
    }

    #[test]
    fn test_iterator_safety_checks() {
        let iter_ctx = DynptrIteratorContext::new(100);
        
        // Released dynptr not safe
        let mut ctx = NestedDynptrContext::new();
        ctx.state = DynptrState::Released;
        assert!(!iter_ctx.is_safe_for_iteration(1, &ctx));
        
        // Deep nesting not safe
        let mut ctx2 = NestedDynptrContext::new();
        ctx2.state = DynptrState::Valid;
        ctx2.depth = 5;
        assert!(!iter_ctx.is_safe_for_iteration(2, &ctx2));
        
        // Valid dynptr is safe
        let mut ctx3 = NestedDynptrContext::new();
        ctx3.state = DynptrState::Valid;
        ctx3.depth = 1;
        assert!(iter_ctx.is_safe_for_iteration(3, &ctx3));
    }

    // ========================================================================
    // DynptrTracker Tests
    // ========================================================================

    #[test]
    fn test_tracker_register_and_release() {
        let mut tracker = DynptrTracker::new();
        
        let info = DynptrInfo {
            dynptr_type: BpfDynptrType::Local,
            spi: 0,
            ref_obj_id: 0,
            created_at: 0,
            is_clone: false,
            parent_id: None,
        };
        
        tracker.register(1, info);
        assert!(tracker.exists(1));
        assert!(tracker.is_usable(1));
        assert_eq!(tracker.active_count(), 1);
        
        assert!(tracker.release(1).is_ok());
        assert!(!tracker.is_usable(1));
    }

    #[test]
    fn test_tracker_derived_dynptrs() {
        let mut tracker = DynptrTracker::new();
        
        let parent_info = DynptrInfo {
            dynptr_type: BpfDynptrType::Ringbuf,
            spi: 0,
            ref_obj_id: 1,
            created_at: 0,
            is_clone: false,
            parent_id: None,
        };
        tracker.register(1, parent_info);
        
        let child_info = DynptrInfo {
            dynptr_type: BpfDynptrType::Ringbuf,
            spi: 1,
            ref_obj_id: 1,
            created_at: 1,
            is_clone: true,
            parent_id: Some(1),
        };
        tracker.register_derived(2, 1, child_info);
        
        // Child has parent
        let chain = tracker.get_parent_chain(2);
        assert_eq!(chain, vec![1]);
        
        // Child depth is greater
        assert_eq!(tracker.get_depth(2), 1);
    }

    #[test]
    fn test_tracker_exception_integration() {
        let mut tracker = DynptrTracker::new();
        
        let info = DynptrInfo {
            dynptr_type: BpfDynptrType::Ringbuf,
            spi: 0,
            ref_obj_id: 1,
            created_at: 0,
            is_clone: false,
            parent_id: None,
        };
        tracker.register(1, info);
        
        // Enter try block
        tracker.enter_try_block();
        assert!(tracker.in_exception_context());
        
        // Mark for cleanup
        tracker.mark_exception_cleanup(1);
        
        // Exit normally
        tracker.exit_try_block_normal();
        assert!(!tracker.in_exception_context());
    }

    #[test]
    fn test_tracker_iterator_integration() {
        let mut tracker = DynptrTracker::new();
        
        let info = DynptrInfo {
            dynptr_type: BpfDynptrType::Local,
            spi: 0,
            ref_obj_id: 0,
            created_at: 0,
            is_clone: false,
            parent_id: None,
        };
        tracker.register(1, info);
        
        // Enter iterator
        tracker.enter_iterator(100);
        assert!(tracker.in_iterator());
        
        // Use dynptr in iteration
        assert!(tracker.use_in_iteration(1).is_ok());
        
        // Advance
        assert!(tracker.next_iteration().is_ok());
        
        // Exit iterator
        tracker.exit_iterator();
        assert!(!tracker.in_iterator());
    }

    #[test]
    fn test_tracker_full_validation() {
        let mut tracker = DynptrTracker::new();
        
        // Empty tracker should validate OK
        assert!(tracker.validate_all().is_ok());
        
        // Add non-refcounted dynptr and don't release
        let info = DynptrInfo {
            dynptr_type: BpfDynptrType::Local,
            spi: 0,
            ref_obj_id: 0,
            created_at: 0,
            is_clone: false,
            parent_id: None,
        };
        tracker.register(1, info);
        
        // Non-refcounted is OK to leave
        assert!(tracker.validate_cleanup().is_ok());
        
        // Add refcounted dynptr
        let info2 = DynptrInfo {
            dynptr_type: BpfDynptrType::Ringbuf,
            spi: 1,
            ref_obj_id: 1,
            created_at: 1,
            is_clone: false,
            parent_id: None,
        };
        tracker.register(2, info2);
        
        // Refcounted must be released
        assert!(tracker.validate_cleanup().is_err());
        
        // Release it
        assert!(tracker.release(2).is_ok());
        assert!(tracker.validate_cleanup().is_ok());
    }

    #[test]
    fn test_dynptr_slice_creation() {
        let slice = DynptrSlice::new(1, 0, 100, false, BpfDynptrType::Ringbuf);
        
        assert!(slice.is_valid_access(0, 50));
        assert!(slice.is_valid_access(50, 50));
        assert!(!slice.is_valid_access(50, 100)); // Exceeds
        assert!(!slice.is_valid_access(0, 101)); // Exceeds
    }
