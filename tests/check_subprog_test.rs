// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::subprog

use bpf_verifier::check::subprog::*;

use super::*;

    #[test]
    fn test_subprog_manager() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.find_containing(50), Some(0));
    }

    #[test]
    fn test_add_subprog() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        let idx = mgr.add_subprog(50).unwrap();
        assert_eq!(idx, 1);
        
        mgr.finalize_boundaries(100);
        
        assert_eq!(mgr.get(0).unwrap().end, 50);
        assert_eq!(mgr.get(1).unwrap().start, 50);
        assert_eq!(mgr.get(1).unwrap().end, 100);
    }

    #[test]
    fn test_call_state() {
        let mut state = CallState::new();
        assert_eq!(state.current_subprog(), 0);
        
        state.push_call(1, 10).unwrap();
        assert_eq!(state.current_subprog(), 1);
        assert_eq!(state.depth(), 2);
        
        state.pop_call().unwrap();
        assert_eq!(state.current_subprog(), 0);
    }

    #[test]
    fn test_call_stack_limit() {
        let mut state = CallState::new();
        
        for i in 1..MAX_CALL_FRAMES {
            state.push_call(i, i * 10).unwrap();
        }
        
        // Should fail on the next push
        assert!(state.push_call(100, 1000).is_err());
    }

    #[test]
    fn test_is_call_insn() {
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        assert!(is_call_insn(&call));
        assert!(is_helper_call(&call));
        
        let subprog_call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 10);
        assert!(is_call_insn(&subprog_call));
        assert!(is_subprog_call(&subprog_call));
        assert!(!is_helper_call(&subprog_call));
    }

    #[test]
    fn test_get_call_target() {
        let insn = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 5);
        // At instruction 10, call +5 means target is 10 + 1 + 5 = 16
        assert_eq!(get_call_target(&insn, 10), 16);
    }

    #[test]
    fn test_tail_call_context_no_tail_calls() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        let call_state = CallState::new();
        let ctx = TailCallContext::build(&mgr, &call_state.call_sites);
        
        assert!(!ctx.has_tail_calls);
        assert!(!ctx.reachable[0]);
    }

    #[test]
    fn test_tail_call_context_with_tail_call() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        // Mark main as having tail call
        if let Some(info) = mgr.get_mut(0) {
            info.has_tail_call = true;
        }
        
        let call_state = CallState::new();
        let ctx = TailCallContext::build(&mgr, &call_state.call_sites);
        
        assert!(ctx.has_tail_calls);
        assert!(ctx.reachable[0]);
    }

    #[test]
    fn test_tail_call_reachability_propagation() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        mgr.add_subprog(50).unwrap();
        mgr.add_subprog(75).unwrap();
        mgr.finalize_boundaries(100);
        
        // Mark main as having tail call
        if let Some(info) = mgr.get_mut(0) {
            info.has_tail_call = true;
        }
        
        // Build call graph: main -> subprog1 -> subprog2
        let mut call_state = CallState::new();
        call_state.call_sites.push(CallSite {
            insn_idx: 10,
            caller: 0,
            callee: 1,
            is_callback: false,
        });
        call_state.call_sites.push(CallSite {
            insn_idx: 60,
            caller: 1,
            callee: 2,
            is_callback: false,
        });
        
        let ctx = TailCallContext::build(&mgr, &call_state.call_sites);
        
        // All should be reachable since main has tail calls
        assert!(ctx.reachable[0]);
        assert!(ctx.reachable[1]);
        assert!(ctx.reachable[2]);
    }

    #[test]
    fn test_tail_call_stack_limit() {
        let ctx = TailCallContext {
            has_tail_calls: true,
            reachable: vec![true],
            call_graph: vec![vec![]],
        };
        
        // Within limit should succeed
        assert!(ctx.check_tail_call_stack(200, 0).is_ok());
        
        // Exceeding limit should fail
        assert!(ctx.check_tail_call_stack(300, 0).is_err());
    }

    #[test]
    fn test_validate_tail_calls_async_conflict() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        mgr.add_subprog(50).unwrap();
        mgr.finalize_boundaries(100);
        
        // Mark subprog as async callback with tail call
        if let Some(info) = mgr.get_mut(1) {
            info.is_async_cb = true;
            info.has_tail_call = true;
        }
        
        let call_state = CallState::new();
        let result = validate_tail_calls(&mut mgr, &call_state);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tail_calls_refcounted_conflict() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        // Mark main as having refcounted args and tail call
        if let Some(info) = mgr.get_mut(0) {
            info.has_refcounted_args = true;
            info.has_tail_call = true;
        }
        
        let call_state = CallState::new();
        let result = validate_tail_calls(&mut mgr, &call_state);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tail_calls_success() {
        let mut mgr = SubprogManager::new();
        mgr.add_main(100);
        
        // Main with tail call, no conflicts
        if let Some(info) = mgr.get_mut(0) {
            info.has_tail_call = true;
            info.returns_scalar = true;
        }
        
        let call_state = CallState::new();
        let result = validate_tail_calls(&mut mgr, &call_state);
        
        assert!(result.is_ok());
        
        // Check that tail_call_reachable was propagated
        assert!(mgr.get(0).unwrap().tail_call_reachable);
    }
