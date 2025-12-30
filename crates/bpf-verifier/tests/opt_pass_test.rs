// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::pass

use bpf_verifier::prelude::*;
use bpf_verifier::opt::pass::*;


#[test]
fn test_pass_stats_default() {
    let stats = PassStats::new();
    assert_eq!(stats.insns_before, 0);
    assert_eq!(stats.insns_after, 0);
    assert!(!stats.changed);
}

#[test]
fn test_pass_stats_counters() {
    let mut stats = PassStats::new();
    stats.add_counter("test", 10);
    assert_eq!(stats.get_counter("test"), 10);

    stats.increment("test");
    assert_eq!(stats.get_counter("test"), 11); // increment updates existing counter

    stats.increment("new_counter");
    assert_eq!(stats.get_counter("new_counter"), 1);
}

#[test]
fn test_pass_context_default() {
    let ctx = PassContext::default();
    assert!(ctx.insns.is_empty());
    assert_eq!(ctx.prog_type, BpfProgType::Unspec);
    assert!(!ctx.has_subprogs);
}

#[test]
fn test_pass_context_builder() {
    let insns = vec![BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)];
    let ctx = PassContext::new(insns)
        .with_prog_type(BpfProgType::SocketFilter)
        .with_jit(true)
        .with_optimize(true);

    assert_eq!(ctx.insn_count(), 1);
    assert_eq!(ctx.prog_type, BpfProgType::SocketFilter);
    assert!(ctx.jit_enabled);
    assert!(ctx.optimize);
}

#[test]
fn test_pass_manager_empty() {
    let pm = PassManager::new();
    assert_eq!(pm.pass_count(), 0);
}

#[test]
fn test_pass_manager_add_pass() {
    let mut pm = PassManager::new();
    pm.add_pass(DeadCodeElimPass);
    assert_eq!(pm.pass_count(), 1);
}

#[test]
fn test_pass_manager_run_empty_program() {
    let mut pm = PassManager::new();
    pm.add_pass(DeadCodeElimPass);

    let mut ctx = PassContext::new(Vec::new());
    let results = pm.run(&mut ctx).unwrap();

    // DeadCodeElimPass should succeed even on empty program
    assert_eq!(results.len(), 1);
    assert!(results[0].success);
}

#[test]
fn test_pass_manager_run_simple_program() {
    let mut pm = PassManager::new();
    pm.add_pass(DeadCodeElimPass);

    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut ctx = PassContext::new(insns);

    let results = pm.run(&mut ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success);
}

#[test]
fn test_pass_result_success() {
    let stats = PassStats::new();
    let result = PassResult::success(PassId::DeadCodeElim, stats);

    assert!(result.success);
    assert!(result.error.is_none());
    assert_eq!(result.pass_id, PassId::DeadCodeElim);
}

#[test]
fn test_pass_result_failure() {
    let error = VerifierError::TooComplex("test".into());
    let result = PassResult::failure(PassId::DeadCodeElim, error);

    assert!(!result.success);
    assert!(result.error.is_some());
}

#[test]
fn test_dead_code_elim_pass_id() {
    let pass = DeadCodeElimPass;
    assert_eq!(pass.id(), PassId::DeadCodeElim);
    assert_eq!(pass.name(), "dead-code-elim");
}

#[test]
fn test_spectre_mitigation_pass_config() {
    let pass = SpectreMitigationPass::new().with_force_barriers(true);
    assert!(pass.force_barriers);
}

#[test]
fn test_zero_extend_pass_is_enabled() {
    let pass = ZeroExtendPass;

    let ctx_with_jit = PassContext::default().with_jit(true);
    assert!(pass.is_enabled(&ctx_with_jit));

    let ctx_without_jit = PassContext::default().with_jit(false);
    assert!(!pass.is_enabled(&ctx_without_jit));
}

#[test]
fn test_create_standard_pipeline() {
    let pm = create_standard_pipeline();
    assert!(pm.pass_count() >= 4);
}

#[test]
fn test_create_minimal_pipeline() {
    let pm = create_minimal_pipeline();
    assert!(pm.pass_count() >= 1);
}

#[test]
fn test_pass_manager_total_stats() {
    let mut pm = PassManager::new();
    pm.add_pass(DeadCodeElimPass);

    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut ctx = PassContext::new(insns);

    let _ = pm.run(&mut ctx).unwrap();
    let total = pm.total_stats();

    // Stats should be aggregated
    assert!(!total.changed || total.insns_removed > 0 || total.insns_modified > 0);
}

#[test]
fn test_pass_dependencies_empty() {
    let pass = DeadCodeElimPass;
    assert!(pass.dependencies().is_empty());
}

#[test]
fn test_subprog_info_default() {
    let info = PassSubprogInfo::default();
    assert_eq!(info.start, 0);
    assert_eq!(info.end, 0);
    assert_eq!(info.stack_depth, 0);
    assert!(!info.has_tail_call);
}

#[test]
fn test_pass_context_with_subprogs() {
    let subprogs = vec![
        PassSubprogInfo { start: 0, end: 10, stack_depth: 32, has_tail_call: false },
        PassSubprogInfo { start: 10, end: 20, stack_depth: 64, has_tail_call: true },
    ];

    let ctx = PassContext::new(Vec::new()).with_subprogs(subprogs);

    assert!(ctx.has_subprogs);
    assert_eq!(ctx.subprogs.len(), 2);
}

#[test]
fn test_pass_manager_iterative() {
    let mut pm = PassManager::with_config(PassManagerConfig {
        max_iterations: 5,
        ..Default::default()
    });
    pm.add_pass(DeadCodeElimPass);

    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let mut ctx = PassContext::new(insns);

    let iterations = pm.run_iterative(&mut ctx).unwrap();

    // Should converge within max_iterations
    assert!(iterations <= 5);
}

#[test]
fn test_insn_size_adjust_pass() {
    let pass = InsnSizeAdjustPass;
    assert_eq!(pass.id(), PassId::InsnSizeAdjust);
    assert_eq!(pass.name(), "insn-size-adjust");
}

#[test]
fn test_pass_id_equality() {
    assert_eq!(PassId::DeadCodeElim, PassId::DeadCodeElim);
    assert_ne!(PassId::DeadCodeElim, PassId::ZeroExtend);
    assert_eq!(PassId::Custom(1), PassId::Custom(1));
    assert_ne!(PassId::Custom(1), PassId::Custom(2));
}
