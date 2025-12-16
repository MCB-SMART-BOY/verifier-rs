// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::jump

use bpf_verifier::prelude::*;
use bpf_verifier::check::jump::*;


    #[test]
    fn test_analyze_unconditional() {
        let insn = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
        let info = analyze_jump(&insn, 10, 100).unwrap();

        assert_eq!(info.jump_type, JumpType::Unconditional);
        assert_eq!(info.target_idx, Some(16)); // 10 + 5 + 1
        assert_eq!(info.fallthrough_idx, None);
    }

    #[test]
    fn test_analyze_conditional() {
        let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5, 100);
        let info = analyze_jump(&insn, 10, 100).unwrap();

        assert_eq!(info.jump_type, JumpType::Conditional);
        assert_eq!(info.target_idx, Some(16));
        assert_eq!(info.fallthrough_idx, Some(11));
    }

    #[test]
    fn test_analyze_exit() {
        let insn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        let info = analyze_jump(&insn, 10, 100).unwrap();

        assert_eq!(info.jump_type, JumpType::Exit);
        assert_eq!(info.target_idx, None);
        assert_eq!(info.fallthrough_idx, None);
    }

    #[test]
    fn test_evaluate_eq_true() {
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.mark_known(100);

        let src = BpfRegState::new_not_init();

        let result = evaluate_condition(BPF_JEQ | BPF_K, &dst, &src, 100, false);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_evaluate_eq_false() {
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.mark_known(100);

        let src = BpfRegState::new_not_init();

        let result = evaluate_condition(BPF_JEQ | BPF_K, &dst, &src, 50, false);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_prove_gt_from_bounds() {
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 100;
        dst.umax_value = 200;

        let mut src = BpfRegState::new_not_init();
        src.reg_type = BpfRegType::ScalarValue;
        src.umin_value = 50;
        src.umax_value = 80;

        // dst is always > src
        let result = prove_condition_from_bounds(BPF_JGT | BPF_X, &dst, &src, 0, false);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_refine_on_gt() {
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 0;
        dst.umax_value = 200;

        // After `if (dst > 100) goto taken`
        // On taken branch: dst > 100, so dst >= 101
        refine_bounds_on_branch(&mut dst, BPF_JGT | BPF_K, 100, true, false);
        assert_eq!(dst.umin_value, 101);

        // On not-taken branch: dst <= 100
        let mut dst2 = BpfRegState::new_not_init();
        dst2.reg_type = BpfRegType::ScalarValue;
        dst2.umin_value = 0;
        dst2.umax_value = 200;

        refine_bounds_on_branch(&mut dst2, BPF_JGT | BPF_K, 100, false, false);
        assert_eq!(dst2.umax_value, 100);
    }

    #[test]
    fn test_collect_jump_targets() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0), // jump to 4
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // jump to 4
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let targets = collect_jump_targets(&insns);
        assert!(targets.contains(&0)); // Entry
        assert!(targets.contains(&2)); // Fall-through from jmp
        assert!(targets.contains(&4)); // Jump target
    }

    #[test]
    fn test_refine_on_jset_taken() {
        // JSET: if (dst & 0x80) goto taken
        // On taken branch: bit 7 must be set
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 0;
        dst.umax_value = 255;
        dst.var_off = Tnum::unknown();

        refine_bounds_on_branch(&mut dst, BPF_JSET | BPF_K, 0x80, true, false);
        
        // Bit 7 is now known to be set
        assert_eq!(dst.var_off.value & 0x80, 0x80);
        assert_eq!(dst.var_off.mask & 0x80, 0);
        // umin_value should be at least 1 (non-zero)
        assert!(dst.umin_value >= 1);
    }

    #[test]
    fn test_refine_on_jset_not_taken() {
        // JSET: if (dst & 0x0F) goto taken
        // On not-taken branch: all low 4 bits must be 0
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 0;
        dst.umax_value = 255;
        dst.var_off = Tnum::unknown();

        refine_bounds_on_branch(&mut dst, BPF_JSET | BPF_K, 0x0F, false, false);
        
        // Low 4 bits are known to be 0
        assert_eq!(dst.var_off.value & 0x0F, 0);
        assert_eq!(dst.var_off.mask & 0x0F, 0);
    }

    #[test]
    fn test_refine_on_jne_taken() {
        // JNE: if (dst != 5) goto taken
        // On taken branch with boundary value
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 5;
        dst.umax_value = 10;

        refine_bounds_on_branch(&mut dst, BPF_JNE | BPF_K, 5, true, false);
        
        // dst != 5, and umin was 5, so now umin is 6
        assert_eq!(dst.umin_value, 6);
    }

    #[test]
    fn test_refine_on_jne_not_taken() {
        // JNE: if (dst != 5) goto taken
        // On not-taken branch: dst == 5
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 0;
        dst.umax_value = 10;

        refine_bounds_on_branch(&mut dst, BPF_JNE | BPF_K, 5, false, false);
        
        // dst == 5
        assert_eq!(dst.umin_value, 5);
        assert_eq!(dst.umax_value, 5);
    }

    #[test]
    fn test_refine_on_jeq_taken() {
        // JEQ: if (dst == 42) goto taken
        let mut dst = BpfRegState::new_not_init();
        dst.reg_type = BpfRegType::ScalarValue;
        dst.umin_value = 0;
        dst.umax_value = 100;
        dst.var_off = Tnum::unknown();

        refine_bounds_on_branch(&mut dst, BPF_JEQ | BPF_K, 42, true, false);
        
        // dst == 42
        assert_eq!(dst.umin_value, 42);
        assert_eq!(dst.umax_value, 42);
        assert_eq!(dst.var_off.value, 42);
        assert_eq!(dst.var_off.mask, 0); // Fully known
    }

    // ========================================================================
    // Indirect Jump (gotol / BPF_JA|BPF_X) Tests
    // ========================================================================

    #[test]
    fn test_is_indirect_jump() {
        // Indirect jump: BPF_JMP | BPF_JA with BPF_X mode
        let indirect = BpfInsn::new(BPF_JMP | BPF_JA | BPF_X, 0, 0, 0, 0);
        assert!(is_indirect_jump(&indirect));

        // Regular unconditional jump (not indirect)
        let regular = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
        assert!(!is_indirect_jump(&regular));

        // Conditional jump (not indirect)
        let cond = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5, 100);
        assert!(!is_indirect_jump(&cond));
    }

    #[test]
    fn test_check_indirect_jump_fields_valid() {
        // Valid indirect jump: src_reg=0, imm=0, off=0
        let insn = BpfInsn::new(BPF_JMP | BPF_JA | BPF_X, 0, BPF_REG_0 as u8, 0, 0);
        assert!(check_indirect_jump_fields(&insn, 0).is_ok());
    }

    #[test]
    fn test_check_indirect_jump_fields_invalid_src_reg() {
        // Invalid: src_reg != 0
        let mut insn = BpfInsn::new(BPF_JMP | BPF_JA | BPF_X, 0, 1, 0, 0);
        insn.src_reg = 1; // Not BPF_REG_0
        assert!(check_indirect_jump_fields(&insn, 5).is_err());
    }

    #[test]
    fn test_check_indirect_jump_fields_invalid_imm() {
        // Invalid: imm != 0
        let insn = BpfInsn::new(BPF_JMP | BPF_JA | BPF_X, 0, BPF_REG_0 as u8, 0, 42);
        assert!(check_indirect_jump_fields(&insn, 10).is_err());
    }

    #[test]
    fn test_check_indirect_jump_fields_invalid_off() {
        // Invalid: off != 0
        let insn = BpfInsn::new(BPF_JMP | BPF_JA | BPF_X, 0, BPF_REG_0 as u8, 5, 0);
        assert!(check_indirect_jump_fields(&insn, 3).is_err());
    }

    #[test]
    fn test_check_indirect_jump_known_r0() {
        // R0 is a known scalar value
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.mark_known(5); // R0 = 5
        r0.umin_value = 5;
        r0.umax_value = 5;

        let result = check_indirect_jump(&r0, 10, 100).unwrap();
        
        // Target should be insn_idx + 1 + R0 = 10 + 1 + 5 = 16
        assert_eq!(result.min_target, 16);
        assert_eq!(result.max_target, 16);
        assert!(result.all_targets_valid);
        assert_eq!(result.targets.len(), 1);
        assert_eq!(result.targets[0], 16);
    }

    #[test]
    fn test_check_indirect_jump_bounded_r0() {
        // R0 has a bounded range [2, 5]
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.umin_value = 2;
        r0.umax_value = 5;
        r0.var_off = Tnum::unknown();

        let result = check_indirect_jump(&r0, 10, 100).unwrap();
        
        // Targets: 10 + 1 + [2..5] = [13, 14, 15, 16]
        assert_eq!(result.min_target, 13);
        assert_eq!(result.max_target, 16);
        assert!(result.all_targets_valid);
        assert_eq!(result.targets.len(), 4);
        assert!(result.targets.contains(&13));
        assert!(result.targets.contains(&14));
        assert!(result.targets.contains(&15));
        assert!(result.targets.contains(&16));
    }

    #[test]
    fn test_check_indirect_jump_uninitialized_r0() {
        // R0 is not initialized - should error
        let r0 = BpfRegState::new_not_init();
        
        let result = check_indirect_jump(&r0, 10, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_indirect_jump_non_scalar_r0() {
        // R0 is a pointer, not a scalar - should error
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::PtrToMapValue;
        r0.umin_value = 0;
        r0.umax_value = 10;

        let result = check_indirect_jump(&r0, 10, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_indirect_jump_range_too_large() {
        // R0 range is too large (> 256)
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.umin_value = 0;
        r0.umax_value = 1000; // Range > MAX_INDIRECT_JUMP_RANGE

        let result = check_indirect_jump(&r0, 10, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_indirect_jump_target_out_of_bounds() {
        // Some targets exceed instruction count
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.umin_value = 0;
        r0.umax_value = 10;

        // insn_count = 15, insn_idx = 10
        // Targets: 10 + 1 + [0..10] = [11..21]
        // Valid targets: 11, 12, 13, 14 (< 15)
        // Invalid targets: 15, 16, ... 21 (>= 15)
        let result = check_indirect_jump(&r0, 10, 15).unwrap();
        
        // Not all targets are valid (some >= insn_count)
        assert!(!result.all_targets_valid);
        // But we should have some valid targets
        assert!(!result.targets.is_empty());
        assert!(result.targets.contains(&11));
        assert!(result.targets.contains(&14));
        // 15 and above should not be in targets
        assert!(!result.targets.contains(&15));
    }

    #[test]
    fn test_check_indirect_jump_all_targets_invalid() {
        // All targets exceed instruction count
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.umin_value = 100;
        r0.umax_value = 110;

        // insn_count = 20, insn_idx = 10
        // All targets would be >= 20
        let result = check_indirect_jump(&r0, 10, 20);
        assert!(result.is_err()); // No valid targets
    }

    #[test]
    fn test_validate_indirect_jump_targets_valid() {
        // All targets are valid (not landing in LD_IMM64 continuation)
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 1),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 2),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let targets = vec![0, 1, 2, 3];
        assert!(validate_indirect_jump_targets(&targets, &insns).is_ok());
    }

    #[test]
    fn test_validate_indirect_jump_targets_lands_in_ldimm64() {
        // Target lands in the second half of LD_IMM64 (invalid)
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, 0), // LD_IMM64 first half
            BpfInsn::new(0, 0, 0, 0, 0), // LD_IMM64 second half (continuation)
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        // Target 2 lands in LD_IMM64 continuation (prev insn is LD_IMM64)
        let targets = vec![2];
        assert!(validate_indirect_jump_targets(&targets, &insns).is_err());
    }

    #[test]
    fn test_validate_indirect_jump_targets_first_insn() {
        // Target is first instruction (target=0) - should be valid
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let targets = vec![0];
        assert!(validate_indirect_jump_targets(&targets, &insns).is_ok());
    }

    #[test]
    fn test_validate_indirect_jump_targets_after_ldimm64() {
        // Target lands right after LD_IMM64 (at the second half) is invalid
        // But target at the instruction after LD_IMM64 pair should be valid
        let insns = vec![
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0), // LD_IMM64 at 0
            BpfInsn::new(0, 0, 0, 0, 0), // LD_IMM64 continuation at 1
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0), // Valid target at 2
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        // Target 1 is invalid (lands in LD_IMM64 continuation)
        let targets_invalid = vec![1];
        assert!(validate_indirect_jump_targets(&targets_invalid, &insns).is_err());

        // Target 2 is valid (after LD_IMM64 pair)
        let targets_valid = vec![2, 3];
        assert!(validate_indirect_jump_targets(&targets_valid, &insns).is_ok());
    }

    #[test]
    fn test_indirect_jump_info_creation() {
        // Test JumpInfo::indirect() factory method
        let info = JumpInfo::indirect(10);
        
        assert_eq!(info.jump_type, JumpType::Gotol);
        assert_eq!(info.src_idx, 10);
        assert!(info.target_idx.is_none()); // Dynamic target
        assert!(info.fallthrough_idx.is_none());
        assert_eq!(info.always_taken, Some(true));
    }

    #[test]
    fn test_check_indirect_jump_zero_offset() {
        // R0 = 0, means target is insn_idx + 1
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.mark_known(0);
        r0.umin_value = 0;
        r0.umax_value = 0;

        let result = check_indirect_jump(&r0, 5, 10).unwrap();
        
        // Target: 5 + 1 + 0 = 6
        assert_eq!(result.min_target, 6);
        assert_eq!(result.max_target, 6);
        assert_eq!(result.targets, vec![6]);
    }

    #[test]
    fn test_check_indirect_jump_dedup_targets() {
        // Verify targets are deduplicated (relevant for tnum cases)
        let mut r0 = BpfRegState::new_not_init();
        r0.reg_type = BpfRegType::ScalarValue;
        r0.umin_value = 0;
        r0.umax_value = 3;

        let result = check_indirect_jump(&r0, 10, 100).unwrap();
        
        // Targets should be unique and sorted
        let mut sorted = result.targets.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(result.targets, sorted);
    }
