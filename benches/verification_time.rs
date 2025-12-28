// SPDX-License-Identifier: GPL-2.0
//! Benchmarks for BPF verification time

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use bpf_verifier::core::types::{BpfInsn, BpfProgType};
use bpf_verifier::prelude::*;
use bpf_verifier::verifier::{MainVerifier, VerifierEnv};

/// Create a simple BPF program that just returns 0
fn simple_program() -> Vec<BpfInsn> {
    vec![
        // mov r0, 0
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        // exit
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]
}

/// Create a medium complexity program with branches
fn medium_program() -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // r0 = 0
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    // r1 = 10
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10));
    
    // Unrolled loop iterations
    for _ in 0..10 {
        // r0 += 1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1));
        // r1 -= 1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_SUB | BPF_K, 1, 0, 0, 1));
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

/// Create a complex program with many instructions
fn complex_program() -> Vec<BpfInsn> {
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

fn bench_simple_verification(c: &mut Criterion) {
    let insns = simple_program();
    
    c.bench_function("simple_verification", |b| {
        b.iter(|| {
            let mut env = VerifierEnv::new(black_box(insns.clone()), BpfProgType::SocketFilter, false)
                .expect("Failed to create env");
            let mut verifier = MainVerifier::new(&mut env);
            verifier.verify()
        })
    });
}

fn bench_medium_verification(c: &mut Criterion) {
    let insns = medium_program();
    
    c.bench_function("medium_verification", |b| {
        b.iter(|| {
            let mut env = VerifierEnv::new(black_box(insns.clone()), BpfProgType::SocketFilter, false)
                .expect("Failed to create env");
            let mut verifier = MainVerifier::new(&mut env);
            verifier.verify()
        })
    });
}

fn bench_complex_verification(c: &mut Criterion) {
    let insns = complex_program();
    
    c.bench_function("complex_verification", |b| {
        b.iter(|| {
            let mut env = VerifierEnv::new(black_box(insns.clone()), BpfProgType::SocketFilter, false)
                .expect("Failed to create env");
            let mut verifier = MainVerifier::new(&mut env);
            verifier.verify()
        })
    });
}

fn bench_state_creation(c: &mut Criterion) {
    use bpf_verifier::state::verifier_state::BpfFuncState;
    
    c.bench_function("state_creation", |b| {
        b.iter(|| {
            black_box(BpfFuncState::new(0, 0, 0))
        })
    });
}

fn bench_bounds_operations(c: &mut Criterion) {
    use bpf_verifier::bounds::scalar::ScalarBounds;
    
    let a = ScalarBounds::known(1000);
    let b_bounds = ScalarBounds::known(42);
    
    c.bench_function("bounds_operations", |b| {
        b.iter(|| {
            let result = a.add(black_box(&b_bounds), true).unwrap();
            let result = result.sub(&b_bounds, true).unwrap();
            let result = result.mul(&b_bounds, true).unwrap();
            result.div(&b_bounds, true)
        })
    });
}

criterion_group!(
    benches,
    bench_simple_verification,
    bench_medium_verification,
    bench_complex_verification,
    bench_state_creation,
    bench_bounds_operations,
);

criterion_main!(benches);
