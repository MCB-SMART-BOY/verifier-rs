// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::reg_state

use bpf_verifier::prelude::*;


    #[test]
    fn test_new_not_init() {
        let reg = BpfRegState::new_not_init();
        assert_eq!(reg.reg_type, BpfRegType::NotInit);
    }

    #[test]
    fn test_mark_known() {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        reg.mark_known(42);
        assert!(reg.is_const());
        assert_eq!(reg.const_value(), 42);
    }

    #[test]
    fn test_mark_const_zero() {
        let mut reg = BpfRegState::default();
        reg.mark_const_zero(false);
        assert_eq!(reg.reg_type, BpfRegType::ScalarValue);
        assert!(reg.is_null());
    }

    #[test]
    fn test_bounds_sanity() {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        reg.mark_known(100);
        assert!(reg.bounds_sanity_check().is_ok());
    }
