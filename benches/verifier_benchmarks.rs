//! Performance benchmarks for the BPF verifier
//!
//! Run with: cargo bench
//! Results are saved to target/criterion/

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use bpf_verifier::core::types::*;
use bpf_verifier::state::reg_state::BpfRegState;
use bpf_verifier::state::verifier_state::BpfVerifierState;
use bpf_verifier::bounds::tnum::Tnum;
use bpf_verifier::verifier::env::VerifierEnv;
use bpf_verifier::analysis::cfg::ControlFlowGraph;
use bpf_verifier::analysis::state_merge::{merge_states, MergeConfig, merge_states_with_config};

// ============================================================================
// Test Program Generators
// ============================================================================

/// Generate a simple linear program (no branches)
fn generate_linear_program(size: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::with_capacity(size);
    
    // r0 = 0
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    
    // Add arithmetic operations
    for i in 1..size.saturating_sub(1) {
        let op = match i % 4 {
            0 => BPF_ADD,
            1 => BPF_SUB,
            2 => BPF_AND,
            _ => BPF_OR,
        };
        insns.push(BpfInsn::new(BPF_ALU64 | op | BPF_K, 0, 0, 0, (i % 256) as i32));
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

/// Generate a program with branches (diamond pattern)
fn generate_branching_program(depth: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // r0 = r1 (copy arg)
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0));
    
    // Create diamond branches
    for i in 0..depth {
        let skip = 2i16; // Skip next instruction
        
        // if r0 > i { skip }
        insns.push(BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, 0, 0, skip, i as i32));
        // r0 += 1
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1));
        // r0 += 2 (merge point)
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 2));
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

/// Generate a program with a loop
fn generate_loop_program(iterations: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // r0 = 0 (counter)
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    // r1 = iterations
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, iterations as i32));
    
    // loop_start:
    // r0 += 1
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1));
    // if r0 < r1: goto loop_start
    insns.push(BpfInsn::new(BPF_JMP | BPF_JLT | BPF_X, 0, 1, -2, 0));
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

/// Generate a program with subprogram calls
fn generate_call_program(call_depth: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // Main program
    // r0 = 0
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    
    // Call subprograms
    for i in 0..call_depth {
        // call subprog_i (relative offset)
        let offset = ((call_depth - i) * 3 + 1) as i32;
        insns.push(BpfInsn::new(BPF_JMP | BPF_CALL, 0, 1, 0, offset));
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    // Subprograms
    for i in 0..call_depth {
        // subprog_i:
        // r0 += i
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, i as i32 + 1));
        // r0 *= 2
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MUL | BPF_K, 0, 0, 0, 2));
        // exit (return)
        insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    }
    
    insns
}

/// Generate a program with memory accesses
fn generate_memory_program(accesses: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // r0 = 0
    insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
    
    // Stack accesses
    for i in 0..accesses {
        let offset = -((i % 64) as i16 + 1) * 8;
        
        if i % 2 == 0 {
            // Store r0 to stack
            insns.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 10, 0, offset, 0));
        } else {
            // Load from stack to r0
            insns.push(BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 10, offset, 0));
        }
    }
    
    // exit
    insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
    
    insns
}

// ============================================================================
// Benchmarks
// ============================================================================

/// Benchmark CFG construction
fn bench_cfg_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg_construction");
    
    for size in [100, 500, 1000, 5000].iter() {
        let insns = generate_linear_program(*size);
        
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &insns, |b, insns| {
            b.iter(|| {
                ControlFlowGraph::build(black_box(insns))
            });
        });
    }
    
    group.finish();
}

/// Benchmark CFG with branches
fn bench_cfg_branching(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg_branching");
    
    for depth in [10, 50, 100, 200].iter() {
        let insns = generate_branching_program(*depth);
        
        group.throughput(Throughput::Elements(insns.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(depth), &insns, |b, insns| {
            b.iter(|| {
                ControlFlowGraph::build(black_box(insns))
            });
        });
    }
    
    group.finish();
}

/// Benchmark verifier environment creation
fn bench_env_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("env_creation");
    
    for size in [100, 500, 1000, 5000].iter() {
        let insns = generate_linear_program(*size);
        
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &insns, |b, insns| {
            b.iter(|| {
                VerifierEnv::new(
                    black_box(insns.clone()),
                    BpfProgType::SocketFilter,
                    false,
                )
            });
        });
    }
    
    group.finish();
}

/// Benchmark state creation and cloning
fn bench_state_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_operations");
    
    // State creation
    group.bench_function("state_new", |b| {
        b.iter(|| {
            black_box(BpfVerifierState::new())
        });
    });
    
    // State cloning
    let state = BpfVerifierState::new();
    group.bench_function("state_clone", |b| {
        b.iter(|| {
            black_box(state.clone())
        });
    });
    
    // Register state creation
    group.bench_function("reg_state_new", |b| {
        b.iter(|| {
            black_box(BpfRegState::new_not_init())
        });
    });
    
    // Scalar register creation
    group.bench_function("reg_scalar_unknown", |b| {
        b.iter(|| {
            black_box(BpfRegState::new_scalar_unknown(false))
        });
    });
    
    group.finish();
}

/// Benchmark state merging
fn bench_state_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_merge");
    
    let state1 = BpfVerifierState::new();
    let state2 = BpfVerifierState::new();
    
    // Basic merge
    group.bench_function("merge_identical", |b| {
        b.iter(|| {
            merge_states(black_box(&state1), black_box(&state2))
        });
    });
    
    // Merge with config
    let config = MergeConfig::default();
    group.bench_function("merge_with_config", |b| {
        b.iter(|| {
            merge_states_with_config(black_box(&state1), black_box(&state2), black_box(&config))
        });
    });
    
    // Aggressive merge config
    let aggressive_config = MergeConfig::aggressive();
    group.bench_function("merge_aggressive", |b| {
        b.iter(|| {
            merge_states_with_config(black_box(&state1), black_box(&state2), black_box(&aggressive_config))
        });
    });
    
    group.finish();
}

/// Benchmark Tnum operations
fn bench_tnum_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tnum_operations");
    
    let t1 = Tnum::const_value(0x12345678);
    let t2 = Tnum::const_value(0x87654321);
    let unknown = Tnum::unknown();
    
    // Creation
    group.bench_function("tnum_const", |b| {
        b.iter(|| {
            black_box(Tnum::const_value(black_box(0x12345678)))
        });
    });
    
    group.bench_function("tnum_unknown", |b| {
        b.iter(|| {
            black_box(Tnum::unknown())
        });
    });
    
    group.bench_function("tnum_range", |b| {
        b.iter(|| {
            black_box(Tnum::range(black_box(100), black_box(200)))
        });
    });
    
    // Arithmetic
    group.bench_function("tnum_add", |b| {
        b.iter(|| {
            black_box(t1.add(black_box(t2)))
        });
    });
    
    group.bench_function("tnum_and", |b| {
        b.iter(|| {
            black_box(t1.and(black_box(t2)))
        });
    });
    
    group.bench_function("tnum_or", |b| {
        b.iter(|| {
            black_box(t1.or(black_box(t2)))
        });
    });
    
    group.bench_function("tnum_lsh", |b| {
        b.iter(|| {
            black_box(t1.lsh(black_box(4)))
        });
    });
    
    // Intersection
    group.bench_function("tnum_intersect", |b| {
        b.iter(|| {
            black_box(t1.intersect(black_box(unknown)))
        });
    });
    
    group.finish();
}

/// Benchmark bounds tracking
fn bench_bounds_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("bounds_tracking");
    
    // Create a scalar register and adjust bounds
    group.bench_function("bounds_adjust_32", |b| {
        b.iter(|| {
            let mut reg = BpfRegState::new_scalar_unknown(false);
            reg.umin_value = 0;
            reg.umax_value = 1000;
            reg.smin_value = 0;
            reg.smax_value = 1000;
            reg.u32_min_value = 0;
            reg.u32_max_value = 1000;
            reg.s32_min_value = 0;
            reg.s32_max_value = 1000;
            black_box(reg)
        });
    });
    
    // Mark as unknown
    group.bench_function("mark_unknown", |b| {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        reg.umin_value = 100;
        reg.umax_value = 200;
        b.iter(|| {
            let mut r = reg.clone();
            r.mark_unknown(false);
            black_box(r)
        });
    });
    
    group.finish();
}

/// Benchmark memory access patterns
fn bench_memory_access_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_programs");
    
    for accesses in [10, 50, 100, 500].iter() {
        let insns = generate_memory_program(*accesses);
        
        group.throughput(Throughput::Elements(*accesses as u64));
        group.bench_with_input(BenchmarkId::from_parameter(accesses), &insns, |b, insns| {
            b.iter(|| {
                VerifierEnv::new(
                    black_box(insns.clone()),
                    BpfProgType::SocketFilter,
                    false,
                )
            });
        });
    }
    
    group.finish();
}

/// Benchmark loop programs
fn bench_loop_programs(c: &mut Criterion) {
    let mut group = c.benchmark_group("loop_programs");
    
    for iterations in [10, 50, 100].iter() {
        let insns = generate_loop_program(*iterations);
        
        group.bench_with_input(BenchmarkId::from_parameter(iterations), &insns, |b, insns| {
            b.iter(|| {
                let env = VerifierEnv::new(
                    black_box(insns.clone()),
                    BpfProgType::SocketFilter,
                    false,
                );
                black_box(env)
            });
        });
    }
    
    group.finish();
}

/// Benchmark subprogram call handling
fn bench_call_programs(c: &mut Criterion) {
    let mut group = c.benchmark_group("call_programs");
    
    for depth in [1, 3, 5, 8].iter() {
        let insns = generate_call_program(*depth);
        
        group.bench_with_input(BenchmarkId::from_parameter(depth), &insns, |b, insns| {
            b.iter(|| {
                let env = VerifierEnv::new(
                    black_box(insns.clone()),
                    BpfProgType::SocketFilter,
                    false,
                );
                black_box(env)
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    cfg_benches,
    bench_cfg_construction,
    bench_cfg_branching,
);

criterion_group!(
    state_benches,
    bench_state_operations,
    bench_state_merge,
);

criterion_group!(
    tnum_benches,
    bench_tnum_operations,
    bench_bounds_tracking,
);

criterion_group!(
    env_benches,
    bench_env_creation,
    bench_memory_access_patterns,
    bench_loop_programs,
    bench_call_programs,
);

criterion_main!(cfg_benches, state_benches, tnum_benches, env_benches);
