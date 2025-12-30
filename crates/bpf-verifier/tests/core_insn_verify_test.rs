// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bpf_core::insn_verify

use bpf_verifier::prelude::*;
use bpf_verifier::bpf_core::insn_verify::*;


#[test]
fn test_insn_access_size() {
    // 32-bit (BPF_W)
    let insn_w = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, 0, 1, 0, 0);
    assert_eq!(insn_access_size(&insn_w), 4);

    // 64-bit (BPF_DW)
    let insn_dw = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 1, 0, 0);
    assert_eq!(insn_access_size(&insn_dw), 8);

    // 16-bit (BPF_H)
    let insn_h = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_H, 0, 1, 0, 0);
    assert_eq!(insn_access_size(&insn_h), 2);

    // 8-bit (BPF_B)
    let insn_b = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_B, 0, 1, 0, 0);
    assert_eq!(insn_access_size(&insn_b), 1);
}

#[test]
fn test_insn_verify_result_sequential() {
    let result = InsnVerifyResult::sequential(5);
    assert_eq!(result.next_insn, Some(6));
    assert_eq!(result.branch_target, None);
    assert!(!result.terminates);
    assert!(!result.skip_next);
}

#[test]
fn test_insn_verify_result_jump() {
    let result = InsnVerifyResult::jump(10);
    assert_eq!(result.next_insn, None);
    assert_eq!(result.branch_target, Some(10));
    assert!(!result.terminates);
}

#[test]
fn test_insn_verify_result_conditional() {
    let result = InsnVerifyResult::conditional(6, 10);
    assert_eq!(result.next_insn, Some(6));
    assert_eq!(result.branch_target, Some(10));
}

#[test]
fn test_insn_verify_result_terminate() {
    let result = InsnVerifyResult::terminate();
    assert_eq!(result.next_insn, None);
    assert_eq!(result.branch_target, None);
    assert!(result.terminates);
}

#[test]
fn test_insn_verify_result_skip_one() {
    let result = InsnVerifyResult::skip_one(5);
    assert_eq!(result.next_insn, Some(7));
    assert!(result.skip_next);
}

#[test]
fn test_verify_alu_mov_imm() {
    let mut state = BpfVerifierState::new();
    let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

    // mov r1, 42
    let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42);
    let result = verifier.verify_insn(&insn, None, 0).unwrap();

    assert_eq!(result.next_insn, Some(1));
    assert_eq!(verifier.state.reg(1).unwrap().const_value(), 42);
}

#[test]
fn test_verify_alu_add() {
    let mut state = BpfVerifierState::new();
    state.reg_mut(1).unwrap().mark_known(10);
    state.reg_mut(1).unwrap().reg_type = BpfRegType::ScalarValue;

    let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

    // add r1, 5
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5);
    verifier.verify_insn(&insn, None, 0).unwrap();

    assert_eq!(verifier.state.reg(1).unwrap().const_value(), 15);
}

#[test]
fn test_verify_exit() {
    let mut state = BpfVerifierState::new();
    // R0 must be initialized for exit
    state.reg_mut(0).unwrap().reg_type = BpfRegType::ScalarValue;
    state.reg_mut(0).unwrap().mark_known(0);

    let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

    let insn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    let result = verifier.verify_insn(&insn, None, 0).unwrap();

    assert!(result.terminates);
}

#[test]
fn test_verify_unconditional_jump() {
    let mut state = BpfVerifierState::new();
    let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

    // ja +5 (jump ahead 5 instructions)
    let insn = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
    let result = verifier.verify_insn(&insn, None, 0).unwrap();

    assert_eq!(result.branch_target, Some(6)); // 0 + 5 + 1
    assert_eq!(result.next_insn, None);
}

#[test]
fn test_verify_ld_imm64() {
    let mut state = BpfVerifierState::new();
    let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

    // lddw r1, 0x123456789ABCDEF0
    let insn1 = BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, 1, 0, 0, 0x9ABCDEF0u32 as i32);
    let insn2 = BpfInsn::new(0, 0, 0, 0, 0x12345678u32 as i32);

    let result = verifier.verify_insn(&insn1, Some(&insn2), 0).unwrap();

    assert!(result.skip_next);
    assert_eq!(result.next_insn, Some(2));
    assert_eq!(
        verifier.state.reg(1).unwrap().const_value(),
        0x123456789ABCDEF0u64
    );
}
