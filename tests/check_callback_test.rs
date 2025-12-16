// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::callback

use bpf_verifier::prelude::*;
use bpf_verifier::check::callback::*;


    #[test]
    fn test_callback_type_args() {
        assert_eq!(CallbackType::ForEachMapElem.num_args(), 4);
        assert_eq!(CallbackType::Loop.num_args(), 2);
        assert_eq!(CallbackType::Timer.num_args(), 3);
    }

    #[test]
    fn test_callback_type_return_range() {
        let range = CallbackType::Loop.return_range();
        assert_eq!(range.minval, 0);
        assert_eq!(range.maxval, 1);

        let timer_range = CallbackType::Timer.return_range();
        assert_eq!(timer_range.minval, 0);
        assert_eq!(timer_range.maxval, 0);
    }

    #[test]
    fn test_callback_state_creation() {
        let state = CallbackState::bpf_loop(10, 1000);
        assert_eq!(state.callback_type, CallbackType::Loop);
        assert_eq!(state.entry_idx, 10);
        assert_eq!(state.max_iterations, 1000);
        assert_eq!(state.arg_types.len(), 2);
    }

    #[test]
    fn test_for_each_map_elem_state() {
        let state = CallbackState::for_each_map_elem(0, 8, 64);
        assert_eq!(state.callback_type, CallbackType::ForEachMapElem);
        assert_eq!(state.arg_types.len(), 3);
        
        // Check key arg
        assert_eq!(state.arg_types[0].regno, 1);
        assert_eq!(state.arg_types[0].mem_size, Some(8));
        
        // Check value arg
        assert_eq!(state.arg_types[1].regno, 2);
        assert_eq!(state.arg_types[1].mem_size, Some(64));
    }

    #[test]
    fn test_callback_nesting() {
        let parent = CallbackState::bpf_loop(0, 100);
        let child = CallbackState::bpf_loop(10, 50).with_parent(parent);
        
        assert_eq!(child.depth, 1);
        assert!(child.parent.is_some());
    }

    #[test]
    fn test_callback_depth_limit() {
        let mut state = CallbackState::bpf_loop(0, 100);
        state.depth = 10; // Exceeds limit
        
        assert!(check_callback_depth(&state).is_err());
    }

    #[test]
    fn test_callback_tracker() {
        let mut tracker = CallbackTracker::new(100);
        
        assert!(!tracker.in_callback());
        
        let cb = CallbackState::bpf_loop(0, 100);
        assert!(tracker.enter(cb).is_ok());
        
        assert!(tracker.in_callback());
        assert_eq!(tracker.depth(), 1);
        
        tracker.exit();
        assert!(!tracker.in_callback());
    }

    #[test]
    fn test_callback_tracker_limit() {
        let mut tracker = CallbackTracker::new(2);
        
        let cb1 = CallbackState::bpf_loop(0, 100);
        let cb2 = CallbackState::bpf_loop(10, 100);
        let cb3 = CallbackState::bpf_loop(20, 100);
        
        assert!(tracker.enter(cb1).is_ok());
        tracker.exit();
        
        assert!(tracker.enter(cb2).is_ok());
        tracker.exit();
        
        // Third invocation exceeds limit
        assert!(tracker.enter(cb3).is_err());
    }

    #[test]
    fn test_forbidden_helpers() {
        // tail_call is forbidden in loops
        assert!(is_forbidden_in_loop(12));
        
        // tail_call is forbidden in timers
        assert!(is_forbidden_in_timer(12));
        
        // Regular helper is allowed
        assert!(!is_forbidden_in_loop(1)); // map_lookup_elem
    }

    #[test]
    fn test_is_callback_helper() {
        assert!(is_callback_helper(164)); // bpf_for_each_map_elem
        assert!(is_callback_helper(181)); // bpf_loop
        assert!(!is_callback_helper(1));  // map_lookup_elem
    }

    #[test]
    fn test_expected_arg() {
        let arg = ExpectedArg::new(1, BpfRegType::PtrToMapValue)
            .with_btf_id(100)
            .with_mem_size(64)
            .nullable();
        
        assert_eq!(arg.regno, 1);
        assert_eq!(arg.btf_id, Some(100));
        assert_eq!(arg.mem_size, Some(64));
        assert!(arg.nullable);
    }
