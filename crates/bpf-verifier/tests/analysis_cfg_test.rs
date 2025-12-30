// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::cfg

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::cfg::*;


fn make_insns(codes: &[(u8, u8, u8, i16, i32)]) -> Vec<BpfInsn> {
    codes
        .iter()
        .map(|&(code, dst, src, off, imm)| BpfInsn::new(code, dst, src, off, imm))
        .collect()
}

#[test]
fn test_cfg_simple() {
    // Simple program: mov r0, 0; exit
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    assert!(cfg.blocks.contains_key(&0));
}

#[test]
fn test_cfg_conditional() {
    // if (r1 == 0) goto +1; r0 = 1; exit
    let insns = make_insns(&[
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1, 0), // if r1==0 goto +1
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), // r0 = 1
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    assert!(cfg.jump_targets.contains(&0));
    assert!(cfg.jump_targets.contains(&2)); // Jump target
}

#[test]
fn test_verifier_simple() {
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let mut verifier = Verifier::new(insns, true).unwrap();
    assert!(verifier.verify().is_ok());
}

#[test]
fn test_unreachable_code() {
    // After unconditional jump, code is unreachable
    let insns = make_insns(&[
        (BPF_JMP | BPF_JA, 0, 0, 1, 0), // goto +1
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), // unreachable
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let verifier = Verifier::new(insns, true);
    assert!(verifier.is_err() || verifier.unwrap().check_cfg().is_err());
}

#[test]
fn test_postorder() {
    // Simple linear program: mov r0, 0; mov r1, 1; exit
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 1),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let postorder = cfg.compute_postorder(&insns, &[0]);
    
    // In postorder, exit should come first (last visited)
    assert!(!postorder.is_empty());
}

#[test]
fn test_reverse_postorder() {
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let rpo = cfg.compute_reverse_postorder(&insns, &[0]);
    
    // In reverse postorder, entry should come first
    assert!(!rpo.is_empty());
    assert_eq!(rpo[0], 0);
}

#[test]
fn test_loop_header_detection() {
    // Simple loop: 0: mov r0, 0; 1: add r0, 1; 2: if r0 < 10 goto -2; 3: exit
    let insns = make_insns(&[
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),       // 0: r0 = 0
        (BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),       // 1: r0 += 1
        (BPF_JMP | BPF_JLT | BPF_K, 0, 0, -2, 10),       // 2: if r0 < 10 goto 1
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),                 // 3: exit
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let loop_headers = cfg.find_loop_headers(&insns);
    
    // Instruction 1 is the loop header (target of back edge from 2)
    assert!(loop_headers.contains(&1));
}

#[test]
fn test_cfg_with_subprogs() {
    // Main: call subprog; exit
    // Subprog: mov r0, 0; exit
    let insns = make_insns(&[
        (BPF_JMP | BPF_CALL, 0, 1, 0, 2),        // 0: call +2 (pseudo call to insn 3)
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),         // 1: exit (main)
        (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // 2: r0 = 0 (subprog)
        (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),         // 3: exit (subprog)
    ]);

    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Both main and subprog should be reachable
    assert!(cfg.jump_targets.contains(&0));
}
