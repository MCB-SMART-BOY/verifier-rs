// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::kfunc_args

use bpf_verifier::prelude::*;
use bpf_verifier::check::kfunc_args::*;


    fn make_scalar_reg(val: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = val;
        reg.umax_value = val;
        reg.smin_value = val as i64;
        reg.smax_value = val as i64;
        reg
    }

    fn make_ptr_reg(reg_type: BpfRegType) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = reg_type;
        reg
    }

    #[test]
    fn test_arg_constraint_scalar() {
        let constraint = ArgConstraint::scalar();
        assert_eq!(constraint.kind, ArgKind::Scalar);
        assert!(!constraint.nullable);
    }

    #[test]
    fn test_arg_constraint_builder() {
        let constraint = ArgConstraint::ptr_to_mem(64)
            .nullable()
            .with_alignment(8)
            .readonly();

        assert_eq!(constraint.kind, ArgKind::PtrToMem);
        assert!(constraint.nullable);
        assert_eq!(constraint.min_size, 64);
        assert_eq!(constraint.alignment, 8);
        assert!(constraint.readonly);
    }

    #[test]
    fn test_kfunc_signature_builder() {
        let sig = KfuncSignature::new("test_kfunc")
            .arg(ArgConstraint::ptr_to_ctx())
            .arg(ArgConstraint::scalar())
            .returns(ArgConstraint::scalar())
            .sleepable();

        assert_eq!(sig.name, "test_kfunc");
        assert_eq!(sig.arg_count(), 2);
        assert!(sig.sleepable);
        assert!(sig.ret.is_some());
    }

    #[test]
    fn test_validate_scalar_arg() {
        let reg = make_scalar_reg(42);
        let constraint = ArgConstraint::scalar();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_scalar_wrong_type() {
        let reg = make_ptr_reg(BpfRegType::PtrToStack);
        let constraint = ArgConstraint::scalar();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("scalar"));
    }

    #[test]
    fn test_validate_ptr_arg() {
        let reg = make_ptr_reg(BpfRegType::PtrToMem);
        let constraint = ArgConstraint::ptr_to_mem(0);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_ptr_wrong_type() {
        let reg = make_scalar_reg(0);
        let constraint = ArgConstraint::ptr_to_mem(0);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("pointer"));
    }

    #[test]
    fn test_validate_ctx_ptr() {
        let reg = make_ptr_reg(BpfRegType::PtrToCtx);
        let constraint = ArgConstraint::ptr_to_ctx();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);

        let wrong_reg = make_ptr_reg(BpfRegType::PtrToStack);
        let result = validate_arg(&wrong_reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_const_size() {
        let reg = make_scalar_reg(64);
        let constraint = ArgConstraint::const_size(64);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
        assert_eq!(result.inferred_size, Some(64));
    }

    #[test]
    fn test_validate_const_size_mismatch() {
        let reg = make_scalar_reg(32);
        let constraint = ArgConstraint::const_size(64);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_kfunc_call() {
        let sig = KfuncSignature::new("test")
            .arg(ArgConstraint::ptr_to_ctx())
            .arg(ArgConstraint::scalar());

        let r1 = make_ptr_reg(BpfRegType::PtrToCtx);
        let r2 = make_scalar_reg(100);

        let result = validate_kfunc_call(&sig, &[&r1, &r2]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_kfunc_call_wrong_count() {
        let sig = KfuncSignature::new("test")
            .arg(ArgConstraint::scalar())
            .arg(ArgConstraint::scalar());

        let r1 = make_scalar_reg(1);

        let result = validate_kfunc_call(&sig, &[&r1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_common_signatures() {
        let sig = signatures::bpf_task_acquire();
        assert_eq!(sig.name, "bpf_task_acquire");
        assert_eq!(sig.arg_count(), 1);
        assert!(sig.ret.is_some());

        let sig = signatures::bpf_obj_drop(100);
        assert!(sig.destructive);
    }

    #[test]
    fn test_dynptr_validation() {
        let reg = make_ptr_reg(BpfRegType::PtrToStack);
        let constraint = ArgConstraint {
            kind: ArgKind::Dynptr,
            ..Default::default()
        };

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);

        let wrong_reg = make_ptr_reg(BpfRegType::PtrToMem);
        let result = validate_arg(&wrong_reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_arg_validation_result() {
        let result = ArgValidationResult::success(0)
            .with_warning("test warning".to_string())
            .with_size(64);

        assert!(result.valid);
        assert!(!result.warnings.is_empty());
        assert_eq!(result.inferred_size, Some(64));
    }
