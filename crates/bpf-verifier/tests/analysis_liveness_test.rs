// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::liveness

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::liveness::*;


#[test]
fn test_liveness_state() {
    let mut state = LivenessState::new();
    
    assert!(!state.is_reg_live(0));
    
    state.mark_reg_read(0);
    assert!(state.is_reg_live(0));
    
    state.mark_reg_written(1);
    assert!(!state.is_reg_live(1));
}

#[test]
fn test_stack_liveness() {
    let mut state = LivenessState::new();
    
    state.mark_stack_written(5);
    assert!(!state.is_stack_live(5));
    
    state.mark_stack_read(5);
    assert!(state.is_stack_live(5));
}

#[test]
fn test_merge_liveness() {
    let mut state1 = LivenessState::new();
    let mut state2 = LivenessState::new();
    
    state1.mark_reg_read(0);
    state2.mark_reg_written(0);
    
    state1.merge(&state2);
    // Read takes precedence
    assert!(state1.is_reg_live(0));
}

#[test]
fn test_insn_liveness_alu() {
    let liveness = InsnLiveness::alu(0, Some(1));
    
    assert!(liveness.reads_reg(0));
    assert!(liveness.reads_reg(1));
    assert!(liveness.writes_reg(0));
    assert!(!liveness.writes_reg(1));
}

#[test]
fn test_insn_liveness_mov() {
    let liveness = InsnLiveness::mov(0, Some(1));
    
    assert!(!liveness.reads_reg(0)); // MOV doesn't read dst
    assert!(liveness.reads_reg(1));
    assert!(liveness.writes_reg(0));
}

#[test]
fn test_insn_liveness_call() {
    let liveness = InsnLiveness::call(3);
    
    assert!(liveness.reads_reg(1));
    assert!(liveness.reads_reg(2));
    assert!(liveness.reads_reg(3));
    assert!(!liveness.reads_reg(4));
    assert!(liveness.writes_reg(0));
}

#[test]
fn test_live_state_merge() {
    assert_eq!(merge_live_state(LiveState::None, LiveState::None), LiveState::None);
    assert_eq!(merge_live_state(LiveState::Read, LiveState::None), LiveState::Read);
    assert_eq!(merge_live_state(LiveState::Written, LiveState::Read), LiveState::Read);
    assert_eq!(merge_live_state(LiveState::Done, LiveState::None), LiveState::Done);
}

#[test]
fn test_get_insn_liveness() {
    // ALU64 ADD r0, r1
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0);
    let liveness = get_insn_liveness(&insn);
    
    assert!(liveness.reads_reg(0));
    assert!(liveness.reads_reg(1));
    assert!(liveness.writes_reg(0));
}
