// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::branch_state

use bpf_verifier::prelude::*;
use bpf_verifier::verifier::branch_state::*;

    use bpf_verifier::bounds::tnum::Tnum;

    fn make_scalar_reg(umin: u64, umax: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = umin;
        reg.umax_value = umax;
        reg.smin_value = umin as i64;
        reg.smax_value = umax as i64;
        reg.var_off = Tnum::unknown();
        reg
    }

    fn make_state_with_reg(regno: usize, reg: BpfRegState) -> BpfVerifierState {
        let mut state = BpfVerifierState::new();
        if let Some(r) = state.reg_mut(regno) {
            *r = reg;
        }
        state
    }

    #[test]
    fn test_process_branch_gt_const() {
        let reg = make_scalar_reg(0, 100);
        let state = make_state_with_reg(1, reg);

        // if (r1 > 50)
        let insn = BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 10, 50);
        let result = process_conditional_branch(&state, &insn);

        assert!(result.taken_reachable);
        assert!(result.fallthrough_reachable);

        // Taken: r1 > 50, so r1 in [51, 100]
        let taken = result.taken_state.unwrap();
        assert_eq!(taken.reg(1).unwrap().umin_value, 51);
        assert_eq!(taken.reg(1).unwrap().umax_value, 100);

        // Fallthrough: r1 <= 50, so r1 in [0, 50]
        let fallthrough = result.fallthrough_state.unwrap();
        assert_eq!(fallthrough.reg(1).unwrap().umin_value, 0);
        assert_eq!(fallthrough.reg(1).unwrap().umax_value, 50);
    }

    #[test]
    fn test_process_branch_always_taken() {
        let reg = make_scalar_reg(100, 200);
        let state = make_state_with_reg(1, reg);

        // if (r1 > 50) - always true when r1 in [100, 200]
        let insn = BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 10, 50);
        let result = process_conditional_branch(&state, &insn);

        assert!(result.taken_reachable);
        assert!(!result.fallthrough_reachable);
        assert!(result.taken_state.is_some());
        assert!(result.fallthrough_state.is_none());
    }

    #[test]
    fn test_process_branch_never_taken() {
        let reg = make_scalar_reg(0, 30);
        let state = make_state_with_reg(1, reg);

        // if (r1 > 50) - always false when r1 in [0, 30]
        let insn = BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 10, 50);
        let result = process_conditional_branch(&state, &insn);

        assert!(!result.taken_reachable);
        assert!(result.fallthrough_reachable);
        assert!(result.taken_state.is_none());
        assert!(result.fallthrough_state.is_some());
    }

    #[test]
    fn test_null_check_handling() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        reg.umin_value = 0;
        reg.umax_value = u64::MAX;

        let mut state = make_state_with_reg(1, reg);

        // if (r1 != 0) - branch taken means non-NULL
        let insn = BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 1, 0, 10, 0);
        let handled = handle_null_check(&mut state, &insn, true);

        assert!(handled);
        assert!(!state.reg(1).unwrap().type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_branch_exploration_state() {
        let mut exploration = BranchExplorationState::new(100);
        let state = BpfVerifierState::new();

        assert!(!exploration.has_pending());
        assert!(exploration.push(5, state.clone()));
        assert!(exploration.has_pending());
        assert_eq!(exploration.pending_count(), 1);

        exploration.mark_explored(5);
        assert!(exploration.is_explored(5));
        assert!(!exploration.is_explored(10));

        let (idx, _) = exploration.pop().unwrap();
        assert_eq!(idx, 5);
        assert!(!exploration.has_pending());
    }

    #[test]
    fn test_reg_reg_comparison() {
        let reg1 = make_scalar_reg(0, 100);
        let reg2 = make_scalar_reg(50, 150);

        let mut state = BpfVerifierState::new();
        if let Some(r) = state.reg_mut(1) {
            *r = reg1;
        }
        if let Some(r) = state.reg_mut(2) {
            *r = reg2;
        }

        // if (r1 == r2)
        let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_X, 1, 2, 10, 0);
        let result = process_conditional_branch(&state, &insn);

        assert!(result.taken_reachable);
        assert!(result.fallthrough_reachable);

        // Taken: r1 == r2, intersection is [50, 100]
        let taken = result.taken_state.unwrap();
        assert_eq!(taken.reg(1).unwrap().umin_value, 50);
        assert_eq!(taken.reg(1).unwrap().umax_value, 100);
        assert_eq!(taken.reg(2).unwrap().umin_value, 50);
        assert_eq!(taken.reg(2).unwrap().umax_value, 100);
    }

    #[test]
    fn test_null_check_jeq_taken() {
        // if (ptr == 0) - branch taken means ptr IS NULL
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;

        let mut state = make_state_with_reg(1, reg);
        let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 10, 0);
        let handled = handle_null_check(&mut state, &insn, true);

        assert!(handled);
        // On taken branch, ptr == NULL, so it becomes a scalar 0
        assert_eq!(state.reg(1).unwrap().reg_type, BpfRegType::ScalarValue);
        assert!(state.reg(1).unwrap().is_const());
        assert_eq!(state.reg(1).unwrap().const_value(), 0);
    }

    #[test]
    fn test_null_check_jeq_not_taken() {
        // if (ptr == 0) - branch NOT taken means ptr is NOT NULL
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;

        let mut state = make_state_with_reg(1, reg);
        let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 10, 0);
        let handled = handle_null_check(&mut state, &insn, false);

        assert!(handled);
        // On fallthrough, ptr != NULL, so PTR_MAYBE_NULL is removed
        assert_eq!(state.reg(1).unwrap().reg_type, BpfRegType::PtrToMapValue);
        assert!(!state.reg(1).unwrap().type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_null_check_jgt_zero() {
        // if (ptr > 0) - branch taken means ptr is non-NULL
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;

        let mut state = make_state_with_reg(1, reg);
        let insn = BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 10, 0);
        let handled = handle_null_check(&mut state, &insn, true);

        assert!(handled);
        assert!(!state.reg(1).unwrap().type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_null_check_reg_comparison() {
        // if (ptr != r2) where r2 == 0 - branch taken means ptr is non-NULL
        let mut ptr_reg = BpfRegState::new_not_init();
        ptr_reg.reg_type = BpfRegType::PtrToMapValue;
        ptr_reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;

        let mut null_reg = BpfRegState::new_not_init();
        null_reg.reg_type = BpfRegType::ScalarValue;
        null_reg.mark_known(0);

        let mut state = BpfVerifierState::new();
        if let Some(r) = state.reg_mut(1) {
            *r = ptr_reg;
        }
        if let Some(r) = state.reg_mut(2) {
            *r = null_reg;
        }

        let insn = BpfInsn::new(BPF_JMP | BPF_JNE | BPF_X, 1, 2, 10, 0);
        let handled = handle_null_check(&mut state, &insn, true);

        assert!(handled);
        assert!(!state.reg(1).unwrap().type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }
