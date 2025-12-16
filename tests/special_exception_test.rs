// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::exception

use bpf_verifier::special::exception::*;

use super::*;

    #[test]
    fn test_exception_state() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: true,
            nargs: 1,
        };

        state.register_callback(1, callback.clone());
        assert!(state.has_callback(1));
        assert!(!state.has_callback(2));
    }

    #[test]
    fn test_exception_nesting() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: false,
            nargs: 1,
        };

        // Can enter exception
        assert!(state.enter_exception(callback.clone()).is_ok());
        assert!(state.in_exception_cb);
        assert_eq!(state.exception_depth, 1);

        // Can exit
        assert!(state.exit_exception().is_ok());
        assert!(!state.in_exception_cb);
    }

    #[test]
    fn test_exception_max_depth() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: false,
            nargs: 0,
        };

        // Enter up to max depth
        for _ in 0..MAX_EXCEPTION_DEPTH {
            assert!(state.enter_exception(callback.clone()).is_ok());
        }

        // Next should fail
        assert!(state.enter_exception(callback.clone()).is_err());
    }

    #[test]
    fn test_async_callback_state() {
        let mut state = AsyncCallbackState::default();
        
        assert!(!state.in_async_cb);
        
        state.enter(AsyncCallbackType::Timer, 42);
        assert!(state.in_async_cb);
        assert_eq!(state.async_id, 42);
        assert_eq!(state.callback_type, AsyncCallbackType::Timer);

        state.exit();
        assert!(!state.in_async_cb);
    }

    #[test]
    fn test_check_exception_callback_exit() {
        let mut state = BpfVerifierState::new();
        
        // Set valid return value
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(0);
        }

        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 0,
            is_global: true,
            nargs: 1,
        };

        assert!(check_exception_callback_exit(&state, &callback).is_ok());
    }

    #[test]
    fn test_check_exception_callback_exit_invalid() {
        let mut state = BpfVerifierState::new();
        
        // Set invalid return value (> 1)
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(5);
        }

        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 0,
            is_global: true,
            nargs: 1,
        };

        assert!(check_exception_callback_exit(&state, &callback).is_err());
    }
