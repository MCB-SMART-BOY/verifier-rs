// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bounds::range_refine

use bpf_verifier::bounds::range_refine::*;

use super::*;

    fn make_scalar(umin: u64, umax: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = umin;
        reg.umax_value = umax;
        reg.smin_value = umin as i64;
        reg.smax_value = umax as i64;
        reg.var_off = Tnum::unknown();
        reg
    }

    fn make_scalar_signed(smin: i64, smax: i64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.smin_value = smin;
        reg.smax_value = smax;
        reg.umin_value = 0;
        reg.umax_value = u64::MAX;
        reg.var_off = Tnum::unknown();
        reg
    }

    #[test]
    fn test_branch_cond_from_opcode() {
        assert_eq!(BranchCond::from_opcode(BPF_JEQ), Some(BranchCond::Eq));
        assert_eq!(BranchCond::from_opcode(BPF_JGT), Some(BranchCond::Gt));
        assert_eq!(BranchCond::from_opcode(BPF_JSLT), Some(BranchCond::Slt));
        assert_eq!(BranchCond::from_opcode(0xFF), None);
    }

    #[test]
    fn test_branch_cond_negate() {
        assert_eq!(BranchCond::Eq.negate(), BranchCond::Ne);
        assert_eq!(BranchCond::Gt.negate(), BranchCond::Le);
        assert_eq!(BranchCond::Slt.negate(), BranchCond::Sge);
    }

    #[test]
    fn test_refine_reg_eq_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 42, BranchCond::Eq, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 42);
        assert_eq!(result.umax, 42);
    }

    #[test]
    fn test_refine_reg_gt_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Gt, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 51);
        assert_eq!(result.umax, 100);
    }

    #[test]
    fn test_refine_reg_lt_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Lt, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 0);
        assert_eq!(result.umax, 49);
    }

    #[test]
    fn test_refine_reg_ne_at_boundary() {
        let reg = make_scalar(10, 20);
        
        // NE with min value
        let result = refine_reg_const(&reg, 10, BranchCond::Ne, true);
        assert!(result.refined);
        assert_eq!(result.umin, 11);
        
        // NE with max value
        let result = refine_reg_const(&reg, 20, BranchCond::Ne, true);
        assert!(result.refined);
        assert_eq!(result.umax, 19);
    }

    #[test]
    fn test_refine_reg_signed() {
        let reg = make_scalar_signed(-100, 100);
        
        // JSGT 0 (r > 0)
        let result = refine_reg_const(&reg, 0, BranchCond::Sgt, true);
        assert!(result.refined);
        assert_eq!(result.smin, 1);
        
        // JSLT 0 (r < 0)
        let result = refine_reg_const(&reg, 0, BranchCond::Slt, true);
        assert!(result.refined);
        assert_eq!(result.smax, -1);
    }

    #[test]
    fn test_refine_reg_reg_eq() {
        let dst = make_scalar(0, 100);
        let src = make_scalar(50, 150);
        
        let (dst_result, src_result) = refine_reg_reg(&dst, &src, BranchCond::Eq, true);
        
        // Intersection should be [50, 100]
        assert!(dst_result.refined);
        assert!(src_result.refined);
        assert_eq!(dst_result.umin, 50);
        assert_eq!(dst_result.umax, 100);
        assert_eq!(src_result.umin, 50);
        assert_eq!(src_result.umax, 100);
    }

    #[test]
    fn test_refine_reg_reg_gt() {
        let dst = make_scalar(0, 100);
        let src = make_scalar(0, 100);
        
        // dst > src
        let (dst_result, src_result) = refine_reg_reg(&dst, &src, BranchCond::Gt, true);
        
        assert!(dst_result.refined);
        assert!(src_result.refined);
        // dst > src means dst >= 1 and src <= 99
        assert_eq!(dst_result.umin, 1);
        assert_eq!(src_result.umax, 99);
    }

    #[test]
    fn test_branch_outcome_always_taken() {
        let reg = make_scalar(100, 200);
        
        // 100..200 > 50 is always true
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Gt),
            BranchOutcome::AlwaysTaken
        );
        
        // 100..200 >= 100 is always true
        assert_eq!(
            determine_branch_outcome(&reg, 100, BranchCond::Ge),
            BranchOutcome::AlwaysTaken
        );
    }

    #[test]
    fn test_branch_outcome_never_taken() {
        let reg = make_scalar(100, 200);
        
        // 100..200 < 50 is always false
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Lt),
            BranchOutcome::NeverTaken
        );
        
        // 100..200 == 50 is always false
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Eq),
            BranchOutcome::NeverTaken
        );
    }

    #[test]
    fn test_branch_outcome_unknown() {
        let reg = make_scalar(0, 100);
        
        // 0..100 > 50 could be either
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Gt),
            BranchOutcome::Unknown
        );
    }

    #[test]
    fn test_refinement_result_is_empty() {
        let mut result = RefinementResult {
            refined: true,
            umin: 100,
            umax: 50, // Invalid: min > max
            smin: 0,
            smax: 0,
            var_off: Tnum::unknown(),
        };
        assert!(result.is_empty());
        
        result.umin = 0;
        result.umax = 100;
        result.smin = 50;
        result.smax = 10; // Invalid: smin > smax
        assert!(result.is_empty());
    }

    #[test]
    fn test_branch_false_path() {
        let reg = make_scalar(0, 100);
        
        // if (r > 50) {} else { /* r <= 50 here */ }
        let result = refine_reg_const(&reg, 50, BranchCond::Gt, false);
        
        assert!(result.refined);
        assert_eq!(result.umax, 50); // Not taken means r <= 50
    }

    #[test]
    fn test_refine_applies_to_reg() {
        let mut reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Lt, true);
        
        result.apply_to(&mut reg);
        
        assert_eq!(reg.umax_value, 49);
    }
