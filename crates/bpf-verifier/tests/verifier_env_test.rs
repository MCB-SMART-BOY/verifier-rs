// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::env

use bpf_verifier::prelude::*;
use bpf_verifier::verifier::env::*;


#[test]
fn test_env_creation() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true);
    assert!(env.is_ok());
    let env = env.unwrap();
    assert_eq!(env.prog_len(), 2);
    assert_eq!(env.subprogs.len(), 1);
}

#[test]
fn test_empty_program() {
    let env = VerifierEnv::new(vec![], BpfProgType::SocketFilter, true);
    assert!(matches!(env, Err(VerifierError::EmptyProgram)));
}

#[test]
fn test_id_generation() {
    let insns = vec![
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
    assert_eq!(env.new_id(), 1);
    assert_eq!(env.new_id(), 2);
    assert_eq!(env.new_id(), 3);
}

#[test]
fn test_state_stack() {
    let insns = vec![
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
    
    let state1 = Box::new(BpfVerifierState::new());
    let state2 = Box::new(BpfVerifierState::new());
    
    env.push_state(state1, 0);
    env.push_state(state2, 5);
    
    assert!(env.has_states());
    assert_eq!(env.peak_states, 2);
    
    let (_, idx) = env.pop_state().unwrap();
    assert_eq!(idx, 5);
    
    let (_, idx) = env.pop_state().unwrap();
    assert_eq!(idx, 0);
    
    assert!(!env.has_states());
}

#[test]
fn test_caps() {
    let caps = VerifierCaps::modern();
    assert!(caps.bounded_loops);
    assert!(caps.kfuncs);
    assert!(caps.arena);
    
    let caps = VerifierCaps::minimal();
    assert!(!caps.bounded_loops);
}

#[test]
fn test_insn_seen() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
    
    assert!(!env.insn_seen(0));
    env.mark_insn_seen(0);
    assert!(env.insn_seen(0));
    assert!(!env.insn_seen(1));
}
