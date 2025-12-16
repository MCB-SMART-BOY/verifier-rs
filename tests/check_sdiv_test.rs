// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::sdiv

use bpf_verifier::check::sdiv::*;

use super::*;

    #[test]
    fn test_divisor_not_zero() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(5);

        assert!(!divisor_might_be_zero(&reg));
    }

    #[test]
    fn test_divisor_is_zero() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(0);

        assert!(divisor_might_be_zero(&reg));
    }

    #[test]
    fn test_divisor_range_excludes_zero() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 1;
        reg.umax_value = 100;
        reg.smin_value = 1;
        reg.smax_value = 100;

        assert!(!divisor_might_be_zero(&reg));
    }

    #[test]
    fn test_overflow_both_known() {
        let mut dividend = BpfRegState::new_not_init();
        dividend.reg_type = BpfRegType::ScalarValue;
        dividend.smin_value = i64::MIN;
        dividend.smax_value = i64::MIN;

        let mut divisor = BpfRegState::new_not_init();
        divisor.reg_type = BpfRegType::ScalarValue;
        divisor.smin_value = -1;
        divisor.smax_value = -1;

        assert!(might_overflow_sdiv64(&dividend, &divisor));
    }

    #[test]
    fn test_no_overflow_positive_divisor() {
        let mut dividend = BpfRegState::new_not_init();
        dividend.reg_type = BpfRegType::ScalarValue;
        dividend.smin_value = i64::MIN;
        dividend.smax_value = i64::MAX;

        let mut divisor = BpfRegState::new_not_init();
        divisor.reg_type = BpfRegType::ScalarValue;
        divisor.smin_value = 1;
        divisor.smax_value = 100;

        assert!(!might_overflow_sdiv64(&dividend, &divisor));
    }

    #[test]
    fn test_sdiv_safety_safe() {
        let mut dividend = BpfRegState::new_not_init();
        dividend.reg_type = BpfRegType::ScalarValue;
        dividend.mark_known(100);

        let mut divisor = BpfRegState::new_not_init();
        divisor.reg_type = BpfRegType::ScalarValue;
        divisor.mark_known(5);

        assert_eq!(check_sdiv64_safety(&dividend, &divisor), SdivSafety::Safe);
    }

    #[test]
    fn test_sdiv_safety_div_zero() {
        let mut dividend = BpfRegState::new_not_init();
        dividend.reg_type = BpfRegType::ScalarValue;
        dividend.mark_known(100);

        let mut divisor = BpfRegState::new_not_init();
        divisor.reg_type = BpfRegType::ScalarValue;
        divisor.mark_known(0);

        assert_eq!(check_sdiv64_safety(&dividend, &divisor), SdivSafety::MightDivByZero);
    }

    #[test]
    fn test_compute_sdiv_bounds() {
        let dividend = ScalarBounds::known(100);
        let divisor = ScalarBounds::known(5);

        let result = compute_sdiv_bounds(&dividend, &divisor, true).unwrap();
        assert!(result.is_const());
        assert_eq!(result.const_value(), Some(20));
    }

    #[test]
    fn test_compute_sdiv_bounds_div_zero() {
        let dividend = ScalarBounds::known(100);
        let divisor = ScalarBounds::known(0);

        let result = compute_sdiv_bounds(&dividend, &divisor, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_divisions() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 100),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 5),
            BpfInsn::new(BPF_ALU64 | BPF_DIV | BPF_X, 0, 1, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let patches = analyze_divisions(&insns);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].insn_idx, 2);
        assert!(patches[0].needs_zero_check);
    }
