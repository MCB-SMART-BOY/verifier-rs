// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::loop_check

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::loop_check::*;


fn make_insns(codes: &[(u8, u8, u8, i16, i32)]) -> Vec<BpfInsn> {
    codes
        .iter()
        .map(|&(code, dst, src, off, imm)| BpfInsn::new(code, dst, src, off, imm))
        .collect()
}

#[test]
fn test_no_loops() {
    // Linear program: r0 = 0; exit
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let mut detector = LoopDetector::new();
    assert!(detector.detect(&insns).is_ok());
    assert!(detector.back_edges.is_empty());
}

#[test]
fn test_simple_loop() {
    // Simple loop: r0 = 0; loop: r0++; if r0 < 10 goto loop; exit
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),      // 0: r0 = 0
        (BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),      // 1: r0++
        (BPF_JMP | BPF_JLT | BPF_K, 0, 0, -2, 10),      // 2: if r0 < 10 goto 1
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),               // 3: exit
    ]);

    let mut detector = LoopDetector::new();
    assert!(detector.detect(&insns).is_ok());
    assert_eq!(detector.back_edges.len(), 1);
    assert_eq!(detector.back_edges[0], (2, 1));
}

#[test]
fn test_loop_info() {
    let mut loop_info = LoopInfo::new(1, 2);
    loop_info.body.insert(1);
    loop_info.body.insert(2);

    assert!(loop_info.contains(1));
    assert!(loop_info.contains(2));
    assert!(!loop_info.contains(0));
}

#[test]
fn test_bounded_loop() {
    // Bounded loop with explicit bound
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
        (BPF_JMP | BPF_JLT | BPF_K, 0, 0, -2, 100),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    assert!(verify_loops_bounded(&insns).is_ok());
}

#[test]
fn test_get_successors() {
    let detector = LoopDetector::new();
    
    // Unconditional jump
    let insns = make_insns(&[
        (BPF_JMP | BPF_JA, 0, 0, 2, 0),
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let succs = detector.get_successors(&insns, 0);
    assert_eq!(succs, vec![3]);
}

#[test]
fn test_conditional_successors() {
    let detector = LoopDetector::new();
    
    // Conditional jump
    let insns = make_insns(&[
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0),
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let succs = detector.get_successors(&insns, 0);
    assert_eq!(succs.len(), 2);
    assert!(succs.contains(&1));
    assert!(succs.contains(&2));
}
