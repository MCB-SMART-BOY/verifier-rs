// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::jit_subprogs

use bpf_verifier::prelude::*;
use bpf_verifier::opt::jit_subprogs::*;


fn make_call_insn(offset: i32) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, offset)
}

fn make_exit_insn() -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

fn make_mov_insn() -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0)
}

#[test]
fn test_subprog_info() {
    let sp = SubprogInfo::new(0, 10);
    assert_eq!(sp.len(), 10);
    assert!(!sp.is_empty());
    assert!(sp.is_main);
}

#[test]
fn test_jit_context_find_subprog() {
    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, 5));
    ctx.subprogs.push(SubprogInfo::new(5, 10));
    
    assert_eq!(ctx.find_subprog(0), Some(0));
    assert_eq!(ctx.find_subprog(3), Some(0));
    assert_eq!(ctx.find_subprog(5), Some(1));
    assert_eq!(ctx.find_subprog(9), Some(1));
    assert_eq!(ctx.find_subprog(10), None);
}

#[test]
fn test_check_tail_calls() {
    let insns = vec![
        make_mov_insn(),
        BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_TAIL_CALL as i32),
        make_exit_insn(),
    ];
    assert!(check_tail_calls(&insns));

    let insns_no_tail = vec![
        make_mov_insn(),
        make_exit_insn(),
    ];
    assert!(!check_tail_calls(&insns_no_tail));
}

#[test]
fn test_calculate_stack_depth() {
    let insns = vec![
        // Store to stack at FP-8
        BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 0, -8, 0),
        // Store to stack at FP-16
        BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 0, -16, 0),
        make_exit_insn(),
    ];

    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, insns.len()));
    
    calculate_stack_depths(&mut ctx, &insns).unwrap();
    
    // Stack depth should be at least 16 + 8 = 24, rounded to 24
    assert!(ctx.subprogs[0].stack_depth >= 16);
}

#[test]
fn test_extract_subprog() {
    let insns = vec![
        make_mov_insn(),
        make_call_insn(1),
        make_exit_insn(),
        // Subprog starts here
        make_mov_insn(),
        make_exit_insn(),
    ];

    let sp = SubprogInfo::new(3, 5);
    let extracted = extract_subprog(&insns, &sp);
    
    assert_eq!(extracted.len(), 2);
}

#[test]
fn test_verify_subprog_calls() {
    let insns = vec![
        make_mov_insn(),
        make_call_insn(1), // Call to insn 3
        make_exit_insn(),
        // Subprog starts at insn 3
        make_mov_insn(),
        make_exit_insn(),
    ];

    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, 3));
    ctx.subprogs.push(SubprogInfo::new(3, 5));

    assert!(verify_subprog_calls(&insns, &ctx).is_ok());
}

#[test]
fn test_max_call_depth() {
    // Main -> Sub1 -> Sub2
    let insns = vec![
        make_call_insn(2), // 0: call to 3
        make_exit_insn(), // 1
        make_exit_insn(), // 2 (padding)
        // Sub1 at 3
        make_call_insn(2), // 3: call to 6
        make_exit_insn(), // 4
        make_exit_insn(), // 5 (padding)
        // Sub2 at 6
        make_mov_insn(), // 6
        make_exit_insn(), // 7
    ];

    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, 3));
    ctx.subprogs.push(SubprogInfo::new(3, 6));
    ctx.subprogs.push(SubprogInfo::new(6, 8));

    let depth = max_call_depth(&insns, &ctx).unwrap();
    assert_eq!(depth, 3); // Main + Sub1 + Sub2
}

#[test]
fn test_propagate_properties() {
    // Main -> Sub1 (might_sleep)
    let insns = vec![
        make_call_insn(1), // 0: call to 2
        make_exit_insn(), // 1
        // Sub1 at 2
        make_mov_insn(), // 2
        make_exit_insn(), // 3
    ];

    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, 2));
    let mut sub1 = SubprogInfo::new(2, 4);
    sub1.might_sleep = true;
    sub1.changes_pkt_data = true;
    ctx.subprogs.push(sub1);

    propagate_subprog_properties(&mut ctx, &insns).unwrap();

    // Properties should propagate to caller
    assert!(ctx.subprogs[0].might_sleep);
    assert!(ctx.subprogs[0].changes_pkt_data);
}

#[test]
fn test_propagate_tail_call_reachable() {
    // Main (has tail call) -> Sub1
    let insns = vec![
        make_call_insn(2), // 0: call to 3
        BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_TAIL_CALL as i32), // 1
        make_exit_insn(), // 2
        // Sub1 at 3
        make_mov_insn(), // 3
        make_exit_insn(), // 4
    ];

    let mut ctx = JitSubprogContext::new();
    let mut main = SubprogInfo::new(0, 3);
    main.tail_call_reachable = true;
    ctx.subprogs.push(main);
    ctx.subprogs.push(SubprogInfo::new(3, 5));

    propagate_subprog_properties(&mut ctx, &insns).unwrap();

    // tail_call_reachable should propagate to callee
    assert!(ctx.subprogs[1].tail_call_reachable);
}

#[test]
fn test_validate_combined_stack_depth() {
    let insns = vec![
        make_call_insn(1), // 0: call to 2
        make_exit_insn(), // 1
        // Sub1 at 2
        make_call_insn(1), // 2: call to 4
        make_exit_insn(), // 3
        // Sub2 at 4
        make_mov_insn(), // 4
        make_exit_insn(), // 5
    ];

    let mut ctx = JitSubprogContext::new();
    let mut sp0 = SubprogInfo::new(0, 2);
    sp0.stack_depth = 100;
    let mut sp1 = SubprogInfo::new(2, 4);
    sp1.stack_depth = 100;
    let mut sp2 = SubprogInfo::new(4, 6);
    sp2.stack_depth = 100;
    
    ctx.subprogs.push(sp0);
    ctx.subprogs.push(sp1);
    ctx.subprogs.push(sp2);

    let combined = validate_combined_stack_depth(&ctx, &insns).unwrap();
    assert!(combined <= MAX_COMBINED_STACK_DEPTH);
}

#[test]
fn test_determine_priv_stack() {
    let insns = vec![
        make_call_insn(1), // 0: call to 2
        make_exit_insn(), // 1
        // Sub1 at 2 (sleepable with stack)
        make_mov_insn(), // 2
        make_exit_insn(), // 3
    ];

    let mut ctx = JitSubprogContext::new();
    ctx.subprogs.push(SubprogInfo::new(0, 2));
    let mut sp1 = SubprogInfo::new(2, 4);
    sp1.might_sleep = true;
    sp1.stack_depth = 200; // > 128
    ctx.subprogs.push(sp1);

    determine_priv_stack_usage(&mut ctx, &insns).unwrap();

    // Sleepable subprog with > 128 stack should use priv stack
    assert!(ctx.subprogs[1].use_priv_stack);
}

#[test]
fn test_subprog_can_use_tail_call() {
    let sp = SubprogInfo::new(0, 10);
    assert!(sp.can_use_tail_call());

    let mut async_sp = SubprogInfo::new(0, 10);
    async_sp.is_async = true;
    assert!(!async_sp.can_use_tail_call());

    let mut sleep_sp = SubprogInfo::new(0, 10);
    sleep_sp.might_sleep = true;
    assert!(!sleep_sp.can_use_tail_call());
}

#[test]
fn test_count_exentries() {
    // Create instructions that need exception entries
    let insns = vec![
        // PROBE_MEM load (mode 5 << 5 = 0xa0)
        BpfInsn::new(BPF_LDX | 0xa0 | BPF_DW, 0, 1, 0, 0),
        make_mov_insn(),
        make_exit_insn(),
    ];

    let sp = SubprogInfo::new(0, 3);
    let count = count_exentries(&insns, &sp);
    assert!(count >= 1);
}
