// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::worklist_verifier

use bpf_verifier::prelude::*;
use bpf_verifier::verifier::worklist_verifier::*;


fn make_env(insns: Vec<BpfInsn>) -> VerifierEnv {
    VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap()
}

#[test]
fn test_simple_program() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    assert!(verifier.verify().is_ok());
}

#[test]
fn test_branch_with_refinement() {
    // if (r1 > 10) { r0 = 1 } else { r0 = 0 }; exit
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 50), // r1 = 50
        BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 2, 10),   // if r1 > 10 goto +2
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),  // r0 = 0
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0),             // goto +1
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),  // r0 = 1
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    assert!(verifier.verify().is_ok());

    let stats = verifier.stats();
    assert!(stats.items_processed > 0);
}

#[test]
fn test_join_point_detection() {
    // Diamond pattern: if (r1) { path1 } else { path2 }; exit
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 1),  // r1 = 1
        BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 2, 0),   // if r1 == 0 goto +2
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),  // r0 = 1
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0),             // goto +1
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),  // r0 = 0
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),           // exit (join point)
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    assert!(verifier.verify().is_ok());

    let stats = verifier.stats();
    assert!(stats.join_points > 0);
}

#[test]
fn test_loop_with_limit() {
    // Simple bounded loop pattern
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),   // r0 = 0
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10),  // r1 = 10 (loop counter)
        // loop:
        BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 3, 0),     // if r1 == 0 goto exit
        BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),   // r0 += 1
        BpfInsn::new(BPF_ALU64 | BPF_SUB | BPF_K, 1, 0, 0, 1),   // r1 -= 1
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, -4, 0),             // goto loop
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);

    // This will either succeed with pruning or hit complexity limit
    let result = verifier.verify();
    // Either outcome is acceptable for this test
    assert!(result.is_ok() || matches!(result, Err(VerifierError::ComplexityLimitExceeded(_))));
}

#[test]
fn test_complexity_limit() {
    // Create a program with many branches that generates exponential states
    // Each branch doubles the number of paths
    let mut insns = vec![];
    for i in 0..20 {
        // if (r1 & (1 << i)) goto +1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 1 << i));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_X, 2, 1, 0, 0));
        insns.push(BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 2, 0, 1, 0));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1));
    }
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));

    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    verifier.set_max_insns(50); // Very low limit

    let result = verifier.verify();
    // Should hit complexity limit due to exponential path explosion
    assert!(matches!(result, Err(VerifierError::ComplexityLimitExceeded(_))));
}

#[test]
fn test_uninit_register_error() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 5, 0, 0), // r0 = r5 (uninit)
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    assert!(verifier.verify().is_err());
}

#[test]
fn test_stats_tracking() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut env = make_env(insns);
    let mut verifier = WorklistVerifier::new(&mut env);
    verifier.verify().unwrap();

    let stats = verifier.stats();
    assert!(stats.items_processed >= 2);
    assert!(stats.max_queue_size >= 1);
}
