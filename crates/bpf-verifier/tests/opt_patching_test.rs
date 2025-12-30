// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::patching

use bpf_verifier::prelude::*;
use bpf_verifier::opt::patching::*;


#[test]
fn test_nop() {
    let nop = BpfInsn::nop();
    assert_eq!(nop.class(), BPF_ALU64);
    assert_eq!(nop.code & 0xf0, BPF_MOV);
}

#[test]
fn test_replace_patch() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut patcher = InsnPatcher::new(insns);
    patcher.add_patch(Patch::replace(
        0,
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 100),
    ));

    let result = patcher.apply().unwrap();
    assert_eq!(result[0].imm, 100);
}

#[test]
fn test_insert_patch() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut patcher = InsnPatcher::new(insns);
    patcher.add_patch(Patch::insert_before(
        1,
        vec![BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1)],
    ));

    let result = patcher.apply().unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[1].code & 0xf0, BPF_ADD);
}

#[test]
fn test_remove_patch() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // To be removed
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut patcher = InsnPatcher::new(insns);
    patcher.add_patch(Patch::remove(0));

    let result = patcher.apply().unwrap();
    // Should be replaced with nop
    assert_eq!(result[0].code, BPF_ALU64 | BPF_MOV | BPF_X);
    assert_eq!(result[0].dst_reg, 0);
    assert_eq!(result[0].src_reg, 0);
}

#[test]
fn test_map_fd_patch() {
    let insns = vec![
        BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD as u8, 0, 5),
        BpfInsn::new(0, 0, 0, 0, 0), // Second part of LD_IMM64
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut patched = insns.clone();
    let map_fds = vec![(5, 0x0000_1234_5678_9ABCu64)];
    patch_map_pointers(&mut patched, &map_fds).unwrap();

    assert_eq!(patched[0].imm, 0x5678_9ABC_u32 as i32);
    assert_eq!(patched[1].imm, 0x0000_1234_u32 as i32);
}

#[test]
fn test_jump_target_update() {
    let insns = vec![
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), // Jump to insn 2
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut patcher = InsnPatcher::new(insns);
    // Insert instruction between insn 1 and 2
    patcher.add_patch(Patch::insert_after(
        1,
        vec![BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 1)],
    ));

    let result = patcher.apply().unwrap();
    
    // The jump at insn 0 should now have offset 2 (to reach the original insn 2)
    assert_eq!(result[0].off, 2);
}

#[test]
fn test_patch_manager_basic() {
    let mut manager = PatchManager::new();
    assert_eq!(manager.patch_count(), 0);

    manager.add_map_patch(0, 0x1234);
    manager.add_subprog_patch(1, 10);
    manager.add_nospec(2);
    manager.add_zext(3, 1);
    manager.mark_dead(4);

    assert_eq!(manager.patch_count(), 5);

    manager.clear();
    assert_eq!(manager.patch_count(), 0);
}

#[test]
fn test_patch_manager_apply_maps() {
    let mut insns = vec![
        BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD as u8, 0, 5),
        BpfInsn::new(0, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut manager = PatchManager::new();
    manager.add_map_patch(0, 0x0000_ABCD_1234_5678u64);

    let result = manager.apply(&mut insns).unwrap();
    assert_eq!(result.maps_patched, 1);
    assert_eq!(insns[0].imm, 0x1234_5678_u32 as i32);
    assert_eq!(insns[1].imm, 0x0000_ABCD_u32 as i32);
}

#[test]
fn test_patch_manager_branch_opt_always() {
    let mut insns = vec![
        BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 2),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut manager = PatchManager::new();
    manager.add_branch_opt(0, BranchOpt::AlwaysTaken);

    let result = manager.apply(&mut insns).unwrap();
    assert_eq!(result.branches_optimized, 1);
    // Should be converted to unconditional jump
    assert_eq!(insns[0].code, BPF_JMP | BPF_JA);
    assert_eq!(insns[0].off, 2);
}

#[test]
fn test_patch_manager_branch_opt_never() {
    let mut insns = vec![
        BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut manager = PatchManager::new();
    manager.add_branch_opt(0, BranchOpt::NeverTaken);

    let result = manager.apply(&mut insns).unwrap();
    assert_eq!(result.branches_optimized, 1);
    // Should be converted to nop
    assert_eq!(insns[0].code, BPF_ALU64 | BPF_MOV | BPF_X);
}

#[test]
fn test_patch_manager_dead_code() {
    let mut insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100), // Dead
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut manager = PatchManager::new();
    manager.mark_dead(1);

    let result = manager.apply(&mut insns).unwrap();
    assert_eq!(result.dead_code_removed, 1);
    // Dead insn should be nop
    assert_eq!(insns[1].code, BPF_ALU64 | BPF_MOV | BPF_X);
}

#[test]
fn test_patch_result_display() {
    let mut result = PatchResult::new(100);
    result.maps_patched = 3;
    result.calls_patched = 2;
    result.zext_inserted = 5;
    result.final_size = 105;

    let display = format!("{}", result);
    assert!(display.contains("3 maps"));
    assert!(display.contains("2 calls"));
    assert!(display.contains("5 zext"));
    assert!(display.contains("+5"));
}

#[test]
fn test_patch_result_no_patches() {
    let result = PatchResult::new(100);
    assert!(!result.has_patches());
    
    let display = format!("{}", result);
    assert!(display.contains("none"));
}

#[test]
fn test_collect_required_patches() {
    let insns = vec![
        BpfInsn::new(BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, 42),
        BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let needs_zext = vec![true, false, false];
    let needs_nospec = vec![false, true, false];
    let dead_insns = vec![false, false, false];

    let manager = collect_required_patches(&insns, &needs_zext, &needs_nospec, &dead_insns);
    
    // Should have 1 zext and 1 nospec
    assert_eq!(manager.zext_patches.len(), 1);
    assert_eq!(manager.nospec_patches.len(), 1);
}

#[test]
fn test_patch_manager_subprog_calls() {
    let mut insns = vec![
        BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL as u8, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];

    let mut manager = PatchManager::new();
    manager.add_subprog_patch(0, 42);

    let result = manager.apply(&mut insns).unwrap();
    assert_eq!(result.calls_patched, 1);
    assert_eq!(insns[0].imm, 42);
}

#[test]
fn test_patch_result_size_delta() {
    let mut result = PatchResult::new(100);
    result.final_size = 110;
    assert_eq!(result.size_delta(), 10);

    result.final_size = 90;
    assert_eq!(result.size_delta(), -10);

    result.final_size = 100;
    assert_eq!(result.size_delta(), 0);
}
