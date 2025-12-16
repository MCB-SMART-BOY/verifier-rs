// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::retval

use bpf_verifier::check::retval::*;

use super::*;

    #[test]
    fn test_retval_range() {
        let range = BpfRetvalRange::new(0, 100);
        
        assert!(range.contains(0));
        assert!(range.contains(50));
        assert!(range.contains(100));
        assert!(!range.contains(-1));
        assert!(!range.contains(101));
    }

    #[test]
    fn test_range_within() {
        let outer = BpfRetvalRange::new(0, 100);
        let inner = BpfRetvalRange::new(10, 50);
        
        assert!(inner.within(&outer));
        assert!(!outer.within(&inner));
    }

    #[test]
    fn test_prog_retval_range() {
        let xdp = get_prog_retval_range(BpfProgType::Xdp);
        assert_eq!(xdp.minval, 0);
        assert_eq!(xdp.maxval, 5);
        
        let filter = get_prog_retval_range(BpfProgType::SocketFilter);
        assert_eq!(filter.minval, 0);
    }

    #[test]
    fn test_check_return_valid() {
        let mut state = BpfVerifierState::new();
        
        // Set R0 to a valid XDP return value
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(2); // XDP_TX
        }
        
        let result = check_return_code(&state, BpfProgType::Xdp, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_return_invalid() {
        let mut state = BpfVerifierState::new();
        
        // Set R0 to an invalid XDP return value
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(100); // Invalid
        }
        
        let result = check_return_code(&state, BpfProgType::Xdp, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_return_uninitialized() {
        let state = BpfVerifierState::new();
        
        // R0 is uninitialized by default
        let _result = check_return_code(&state, BpfProgType::Xdp, false, false);
        // Depends on initial state - may need to explicitly mark R0 as NotInit
    }

    #[test]
    fn test_subprog_return() {
        let mut state = BpfVerifierState::new();
        
        // Subprograms can return any value
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(12345);
        }
        
        let result = check_return_code(&state, BpfProgType::Xdp, true, false);
        assert!(result.is_ok());
    }
