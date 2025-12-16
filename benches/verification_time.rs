// SPDX-License-Identifier: GPL-2.0
//! Benchmarks for BPF verification time

#![feature(test)]

extern crate test;

use bpf_verifier::core::insn::*;
use bpf_verifier::core::types::BpfProgType;
use bpf_verifier::verifier::{MainVerifier, VerifierEnv};
use test::Bencher;

/// Create a simple BPF program that just returns 0
fn simple_program() -> Vec<bpf_verifier::core::types::BpfInsn> {
    use bpf_verifier::core::types::BpfInsn;
    vec![
        // mov r0, 0
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        // exit
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]
}

/// Create a medium complexity program with branches
fn medium_program() -> Vec<bpf_verifier::core::types::BpfInsn> {
    use bpf_verifier::core::types::BpfInsn;
    let mut insns = Vec::new();
    
    // r0 = 0
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    // r1 = 10
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10));
    
    // Loop: 10 iterations
    for _ in 0..10 {
        // r0 += 1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1));
        // r1 -= 1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_SUB | BPF_K, 1, 0, 0, 1));
        // if r1 > 0 goto loop
        insns.push(BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 1, 0, -3i16 as i16, 0));
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

/// Create a complex program with many instructions
fn complex_program() -> Vec<bpf_verifier::core::types::BpfInsn> {
    use bpf_verifier::core::types::BpfInsn;
    let mut insns = Vec::new();
    
    // Initialize registers
    for i in 0..10u8 {
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, i, 0, 0, i as i32));
    }
    
    // Many ALU operations
    for _ in 0..100 {
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_SUB | BPF_X, 2, 3, 0, 0));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MUL | BPF_K, 4, 0, 0, 2));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, 5, 0, 0, 0xff));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_OR | BPF_X, 6, 7, 0, 0));
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_XOR | BPF_K, 8, 0, 0, 0x55));
    }
    
    // Return r0
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

#[bench]
fn bench_simple_verification(b: &mut Bencher) {
    let insns = simple_program();
    
    b.iter(|| {
        let mut env = VerifierEnv::new(insns.clone(), BpfProgType::SocketFilter, false)
            .expect("Failed to create env");
        let mut verifier = MainVerifier::new(&mut env);
        verifier.verify()
    });
}

#[bench]
fn bench_medium_verification(b: &mut Bencher) {
    let insns = medium_program();
    
    b.iter(|| {
        let mut env = VerifierEnv::new(insns.clone(), BpfProgType::SocketFilter, false)
            .expect("Failed to create env");
        let mut verifier = MainVerifier::new(&mut env);
        verifier.verify()
    });
}

#[bench]
fn bench_complex_verification(b: &mut Bencher) {
    let insns = complex_program();
    
    b.iter(|| {
        let mut env = VerifierEnv::new(insns.clone(), BpfProgType::SocketFilter, false)
            .expect("Failed to create env");
        let mut verifier = MainVerifier::new(&mut env);
        verifier.verify()
    });
}

#[bench]
fn bench_state_creation(b: &mut Bencher) {
    use bpf_verifier::state::verifier_state::BpfFuncState;
    
    b.iter(|| {
        BpfFuncState::new(0, 0, 0)
    });
}

#[bench]
fn bench_bounds_operations(b: &mut Bencher) {
    use bpf_verifier::bounds::scalar::ScalarBounds;
    
    let a = ScalarBounds::known(1000);
    let b_bounds = ScalarBounds::known(42);
    
    b.iter(|| {
        let result = a.add(&b_bounds);
        let result = result.sub(&b_bounds);
        let result = result.mul(&b_bounds);
        result.div(&b_bounds, true)
    });
}
