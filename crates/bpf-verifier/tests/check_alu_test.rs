// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::alu

use bpf_verifier::prelude::*;
use bpf_verifier::check::alu::*;


fn make_state_with_reg(regno: usize, val: u64) -> BpfVerifierState {
    let mut state = BpfVerifierState::new();
    if let Some(reg) = state.reg_mut(regno) {
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(val);
    }
    state
}

#[test]
fn test_mov_imm64() {
    let mut state = BpfVerifierState::new();
    // mov64 r1, 42
    let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 42);
}

#[test]
fn test_mov_imm32() {
    let mut state = BpfVerifierState::new();
    // mov32 r1, -1 (should be 0xFFFFFFFF)
    let insn = BpfInsn::new(BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, -1);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 0xFFFFFFFF);
}

#[test]
fn test_add_const() {
    let mut state = make_state_with_reg(1, 10);
    // add64 r1, 5
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 15);
}

#[test]
fn test_sub_const() {
    let mut state = make_state_with_reg(1, 10);
    // sub64 r1, 3
    let insn = BpfInsn::new(BPF_ALU64 | BPF_SUB | BPF_K, 1, 0, 0, 3);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 7);
}

#[test]
fn test_mul_const() {
    let mut state = make_state_with_reg(1, 6);
    // mul64 r1, 7
    let insn = BpfInsn::new(BPF_ALU64 | BPF_MUL | BPF_K, 1, 0, 0, 7);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 42);
}

#[test]
fn test_div_const() {
    let mut state = make_state_with_reg(1, 42);
    // div64 r1, 6
    let insn = BpfInsn::new(BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, 6);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 7);
}

#[test]
fn test_div_by_zero() {
    let mut state = make_state_with_reg(1, 42);
    // div64 r1, 0
    let insn = BpfInsn::new(BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, 0);
    let result = check_alu_op(&mut state, &insn, 0, true);
    assert!(matches!(result, Err(VerifierError::DivisionByZero)));
}

#[test]
fn test_and_const() {
    let mut state = make_state_with_reg(1, 0xFF);
    // and64 r1, 0x0F
    let insn = BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, 1, 0, 0, 0x0F);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 0x0F);
}

#[test]
fn test_or_const() {
    let mut state = make_state_with_reg(1, 0xF0);
    // or64 r1, 0x0F
    let insn = BpfInsn::new(BPF_ALU64 | BPF_OR | BPF_K, 1, 0, 0, 0x0F);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 0xFF);
}

#[test]
fn test_xor_const() {
    let mut state = make_state_with_reg(1, 0xFF);
    // xor64 r1, 0x0F
    let insn = BpfInsn::new(BPF_ALU64 | BPF_XOR | BPF_K, 1, 0, 0, 0x0F);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 0xF0);
}

#[test]
fn test_lsh_const() {
    let mut state = make_state_with_reg(1, 1);
    // lsh64 r1, 4
    let insn = BpfInsn::new(BPF_ALU64 | BPF_LSH | BPF_K, 1, 0, 0, 4);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 16);
}

#[test]
fn test_rsh_const() {
    let mut state = make_state_with_reg(1, 32);
    // rsh64 r1, 3
    let insn = BpfInsn::new(BPF_ALU64 | BPF_RSH | BPF_K, 1, 0, 0, 3);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 4);
}

#[test]
fn test_neg() {
    let mut state = make_state_with_reg(1, 5);
    // neg64 r1
    let insn = BpfInsn::new(BPF_ALU64 | BPF_NEG | BPF_K, 1, 0, 0, 0);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value() as i64, -5);
}

#[test]
fn test_mov_reg() {
    let mut state = make_state_with_reg(2, 100);
    // mov64 r1, r2
    let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 1, 2, 0, 0);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 100);
}

#[test]
fn test_add_reg() {
    let mut state = make_state_with_reg(1, 10);
    if let Some(r2) = state.reg_mut(2) {
        r2.reg_type = BpfRegType::ScalarValue;
        r2.mark_known(5);
    }
    // add64 r1, r2
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 1, 2, 0, 0);
    check_alu_op(&mut state, &insn, 0, true).unwrap();
    assert_eq!(state.reg(1).unwrap().const_value(), 15);
}
