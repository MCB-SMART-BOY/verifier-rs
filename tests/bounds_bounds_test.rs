// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bounds::bounds

use bpf_verifier::prelude::*;


    #[test]
    fn test_known_value() {
        let bounds = ScalarBounds::known(42);
        assert!(bounds.is_const());
        assert_eq!(bounds.const_value(), Some(42));
    }

    #[test]
    fn test_unknown_value() {
        let bounds = ScalarBounds::unknown();
        assert!(!bounds.is_const());
        assert_eq!(bounds.umin_value, 0);
        assert_eq!(bounds.umax_value, u64::MAX);
    }

    #[test]
    fn test_add_known() {
        let a = ScalarBounds::known(10);
        let b = ScalarBounds::known(20);
        let result = a.add(&b, true).unwrap();
        assert!(result.is_const());
        assert_eq!(result.const_value(), Some(30));
    }

    #[test]
    fn test_sub_bounds() {
        let mut a = ScalarBounds::unknown();
        a.umin_value = 100;
        a.umax_value = 200;
        
        let b = ScalarBounds::known(50);
        let result = a.sub(&b, true).unwrap();
        
        assert_eq!(result.umin_value, 50);
        assert_eq!(result.umax_value, 150);
    }

    #[test]
    fn test_div_by_zero() {
        let a = ScalarBounds::known(100);
        let b = ScalarBounds::known(0);
        assert!(a.div(&b, true).is_err());
    }

    #[test]
    fn test_and_bounds() {
        let a = ScalarBounds::known(0xFF);
        let b = ScalarBounds::known(0x0F);
        let result = a.and(&b);
        assert_eq!(result.umax_value, 0x0F);
    }

    #[test]
    fn test_lsh_known() {
        let a = ScalarBounds::known(1);
        let b = ScalarBounds::known(4);
        let result = a.lsh(&b, true).unwrap();
        assert!(result.is_const());
        assert_eq!(result.const_value(), Some(16));
    }

    #[test]
    fn test_cross_inference() {
        let mut bounds = ScalarBounds::unknown();
        bounds.smin_value = 0;
        bounds.smax_value = 100;
        bounds.deduce_bounds();
        
        // Since signed is non-negative, unsigned should match
        assert_eq!(bounds.umin_value, 0);
        assert!(bounds.umax_value <= 100 || bounds.umax_value == u64::MAX);
    }

    #[test]
    fn test_adjust_jgt() {
        let mut bounds = ScalarBounds::unknown();
        bounds.umin_value = 0;
        bounds.umax_value = 100;
        
        // After JGT 50 (taken), value > 50
        bounds.adjust_for_cmp(50, 0x20, true);
        assert_eq!(bounds.umin_value, 51);
    }

    #[test]
    fn test_adjust_jle() {
        let mut bounds = ScalarBounds::unknown();
        bounds.umin_value = 0;
        bounds.umax_value = 100;
        
        // After JLE 30 (taken), value <= 30
        bounds.adjust_for_cmp(30, 0xb0, true);
        assert_eq!(bounds.umax_value, 30);
    }

    #[test]
    fn test_truncate_32() {
        let mut bounds = ScalarBounds::known(0x1_0000_0005);
        bounds.truncate_to_32();
        assert_eq!(bounds.u32_min_value, 5);
        assert_eq!(bounds.u32_max_value, 5);
    }

    #[test]
    fn test_sext_negative() {
        let mut bounds = ScalarBounds::unknown();
        bounds.s32_min_value = -10;
        bounds.s32_max_value = -1;
        bounds.sext_32_to_64();
        
        assert_eq!(bounds.smin_value, -10);
        assert_eq!(bounds.smax_value, -1);
    }

    #[test]
    fn test_could_be_negative() {
        let mut bounds = ScalarBounds::unknown();
        bounds.smin_value = -5;
        bounds.smax_value = 10;
        assert!(bounds.could_be_negative());

        bounds.smin_value = 0;
        assert!(!bounds.could_be_negative());
    }
