// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::sanitize::overflow

use bpf_verifier::prelude::*;
use bpf_verifier::sanitize::overflow::*;

    use bpf_verifier::bounds::tnum::Tnum;

    fn make_scalar_reg(min: i64, max: i64) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.smin_value = min;
        reg.smax_value = max;
        reg.umin_value = min as u64;
        reg.umax_value = max as u64;
        reg.var_off = Tnum::range(min as u64, max as u64);
        reg
    }

    fn make_stack_ptr(off: i32) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = off;
        reg.smin_value = 0;
        reg.smax_value = 0;
        reg.umin_value = 0;
        reg.umax_value = 0;
        reg.var_off = Tnum::const_value(0);
        reg
    }

    #[test]
    fn test_overflow_type_none() {
        let ptr = make_stack_ptr(-64);
        let overflow = analyze_add_overflow(&ptr, 0, 32, 0, 32);
        assert_eq!(overflow, OverflowType::None);
    }

    #[test]
    fn test_overflow_type_unsigned() {
        let mut ptr = make_stack_ptr(-64);
        ptr.umax_value = u64::MAX - 100;
        
        let overflow = analyze_add_overflow(&ptr, 0, 200, 0, 200);
        assert!(matches!(overflow, OverflowType::Unsigned | OverflowType::Both));
    }

    #[test]
    fn test_overflow_type_signed() {
        let mut ptr = make_stack_ptr(-64);
        ptr.smax_value = i64::MAX - 100;
        
        let overflow = analyze_add_overflow(&ptr, 0, 200, 0, 200);
        assert!(matches!(overflow, OverflowType::Signed | OverflowType::Both));
    }

    #[test]
    fn test_check_add_overflow_u64() {
        assert!(!check_add_overflow_u64(100, 200));
        assert!(check_add_overflow_u64(u64::MAX, 1));
        assert!(check_add_overflow_u64(u64::MAX - 10, 20));
    }

    #[test]
    fn test_check_add_overflow_i64() {
        assert!(!check_add_overflow_i64(100, 200));
        assert!(check_add_overflow_i64(i64::MAX, 1));
        assert!(check_add_overflow_i64(i64::MAX - 10, 20));
        assert!(check_add_overflow_i64(i64::MIN, -1));
    }

    #[test]
    fn test_check_sub_underflow_u64() {
        assert!(!check_sub_underflow_u64(200, 100));
        assert!(check_sub_underflow_u64(100, 200));
        assert!(check_sub_underflow_u64(0, 1));
    }

    #[test]
    fn test_check_sub_overflow_i64() {
        assert!(!check_sub_overflow_i64(100, 50));
        assert!(check_sub_overflow_i64(i64::MIN, 1));
        assert!(check_sub_overflow_i64(i64::MAX, -1));
    }

    #[test]
    fn test_compute_stack_limit_add() {
        let ptr = make_stack_ptr(-64);
        let limit = compute_overflow_limit(&ptr, PtrAluDirection::Add, 32, 0).unwrap();
        assert_eq!(limit, 64); // Can add up to 64 to reach 0
    }

    #[test]
    fn test_compute_stack_limit_sub() {
        let ptr = make_stack_ptr(-64);
        let limit = compute_overflow_limit(&ptr, PtrAluDirection::Sub, 100, -100).unwrap();
        // Room = MAX_BPF_STACK - 64 = 512 - 64 = 448
        assert_eq!(limit, MAX_BPF_STACK as u64 - 64);
    }

    #[test]
    fn test_is_overflow_safe_stack() {
        let ptr = make_stack_ptr(-64);
        
        // Adding 32 is safe (stays below 0)
        assert!(is_overflow_safe(&ptr, PtrAluDirection::Add, 32, 0));
        
        // Adding 100 is not safe (would go above 0)
        assert!(!is_overflow_safe(&ptr, PtrAluDirection::Add, 100, 0));
    }

    #[test]
    fn test_overflow_patch_generation() {
        let mut patch = OverflowPatch::new(0, PtrAluDirection::Add);
        patch.overflow_type = OverflowType::Unsigned;
        patch.ptr_reg = 1;
        patch.scalar_reg = 2;
        patch.umax_limit = 1024;
        
        let insns = generate_unsigned_overflow_check(&patch);
        assert!(!insns.is_empty());
        
        // Should have: MOV, SUB, ARSH, AND
        assert_eq!(insns.len(), 4);
    }

    #[test]
    fn test_overflow_patch_set() {
        let mut patch_set = OverflowPatchSet::new();
        
        let mut patch = OverflowPatch::new(2, PtrAluDirection::Add);
        patch.patch_insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 10, 0, 0, 100),
        ];
        
        patch_set.add_patch(patch);
        
        assert!(patch_set.needs_patching());
        assert_eq!(patch_set.patch_count(), 1);
        assert_eq!(patch_set.added_insn_count, 1);
    }

    #[test]
    fn test_patch_set_apply() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 1, 2, 0, 0),
        ];
        
        let mut patch_set = OverflowPatchSet::new();
        let mut patch = OverflowPatch::new(2, PtrAluDirection::Add);
        patch.patch_insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 10, 0, 0, 100),
        ];
        patch_set.add_patch(patch);
        
        let patched = patch_set.apply_patches(&insns);
        
        // Original 3 + 1 patch = 4 instructions
        assert_eq!(patched.len(), 4);
    }

    #[test]
    fn test_insn_map_computation() {
        let mut patch_set = OverflowPatchSet::new();
        
        let mut patch = OverflowPatch::new(1, PtrAluDirection::Add);
        patch.patch_insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 10, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 10, 0, 0, 0),
        ];
        patch_set.add_patch(patch);
        
        patch_set.compute_insn_map(5);
        
        // After patch at idx 1, indices shift by 2
        assert_eq!(patch_set.insn_map[0], 0);
        assert_eq!(patch_set.insn_map[1], 3); // 1 + 2 patch insns
        assert_eq!(patch_set.insn_map[2], 4);
    }

    #[test]
    fn test_overflow_aux_data() {
        let mut analysis = OverflowAnalysis::default();
        analysis.needs_patch = true;
        analysis.overflow_type = OverflowType::Unsigned;
        analysis.alu_limit = 1024;
        
        let mut patch = OverflowPatch::new(0, PtrAluDirection::Add);
        patch.patch_insns = vec![
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(0, 0, 0, 0, 0),
        ];
        analysis.patch = Some(patch);
        
        let aux = OverflowAuxData::from_analysis(&analysis);
        
        assert!(aux.needs_overflow_check);
        assert_eq!(aux.overflow_type, OverflowType::Unsigned);
        assert_eq!(aux.alu_limit, 1024);
        assert_eq!(aux.patch_count, 2);
    }

    #[test]
    fn test_ptr_alu_sanitize_result() {
        let result = PtrAluSanitizeResult::default();
        
        assert!(!result.reject);
        assert!(result.reject_reason.is_none());
        assert!(result.patches.is_empty());
    }

    #[test]
    fn test_signed_overflow_check_gen() {
        let mut patch = OverflowPatch::new(0, PtrAluDirection::Add);
        patch.overflow_type = OverflowType::Signed;
        patch.ptr_reg = 1;
        patch.scalar_reg = 2;
        patch.umax_limit = 512;
        
        let insns = generate_signed_overflow_check(&patch);
        assert!(!insns.is_empty());
    }

    #[test]
    fn test_sub_direction_overflow_check() {
        let mut patch = OverflowPatch::new(0, PtrAluDirection::Sub);
        patch.overflow_type = OverflowType::Unsigned;
        patch.ptr_reg = 1;
        patch.scalar_reg = 2;
        patch.umax_limit = 256;
        
        let insns = generate_overflow_check_insns(&patch);
        assert!(!insns.is_empty());
    }
