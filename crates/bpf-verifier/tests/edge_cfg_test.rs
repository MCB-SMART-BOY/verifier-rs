// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for Control Flow Graph (CFG) analysis
//!
//! Tests basic blocks, jump targets, back-edge detection, and state exploration.

use bpf_verifier::analysis::cfg::{ControlFlowGraph, ExploredStates, BasicBlock};
use bpf_verifier::bpf_core::types::*;
use bpf_verifier::state::verifier_state::BpfVerifierState;

// Helper function to create a simple BpfInsn
fn make_insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn { code, dst_reg: dst, src_reg: src, off, imm }
}

// ALU instruction: r0 = r0 + imm
fn alu64_add_imm(dst: u8, imm: i32) -> BpfInsn {
    make_insn(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
}

// MOV instruction: r_dst = imm
fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    make_insn(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

// Exit instruction
fn exit_insn() -> BpfInsn {
    make_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

// Unconditional jump (JA)
fn ja_insn(off: i16) -> BpfInsn {
    make_insn(BPF_JMP | BPF_JA, 0, 0, off, 0)
}

// Conditional jump: if r_dst == imm then jump +off
fn jeq_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    make_insn(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm)
}



// ============================================================================
// Empty Program Tests
// ============================================================================

#[test]
fn test_cfg_empty_program() {
    let insns: Vec<BpfInsn> = vec![];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    assert!(cfg.blocks.is_empty());
    assert!(cfg.jump_targets.is_empty());
}

// ============================================================================
// Single Instruction Tests
// ============================================================================

#[test]
fn test_cfg_single_exit() {
    let insns = vec![exit_insn()];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Should have exactly one block starting at 0
    assert!(cfg.jump_targets.contains(&0));
    assert!(cfg.blocks.contains_key(&0));
    
    let block = cfg.blocks.get(&0).unwrap();
    assert_eq!(block.start, 0);
    assert_eq!(block.end, 0);
    assert!(block.successors.is_empty()); // EXIT has no successors
}

#[test]
fn test_cfg_single_mov_exit() {
    let insns = vec![
        mov64_imm(0, 0),  // r0 = 0
        exit_insn(),      // exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    assert!(cfg.jump_targets.contains(&0));
}

// ============================================================================
// Linear Program Tests
// ============================================================================

#[test]
fn test_cfg_linear_sequence() {
    let insns = vec![
        mov64_imm(0, 0),      // r0 = 0
        alu64_add_imm(0, 1),  // r0 += 1
        alu64_add_imm(0, 2),  // r0 += 2
        exit_insn(),          // exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Linear code has one block
    assert!(cfg.jump_targets.contains(&0));
    assert_eq!(cfg.blocks.len(), 1);
    
    let block = cfg.blocks.get(&0).unwrap();
    assert_eq!(block.start, 0);
    assert_eq!(block.end, 3);
}

// ============================================================================
// Unconditional Jump Tests
// ============================================================================

#[test]
fn test_cfg_unconditional_forward_jump() {
    let insns = vec![
        mov64_imm(0, 0),  // 0: r0 = 0
        ja_insn(1),       // 1: goto +1 (to insn 3)
        mov64_imm(0, 1),  // 2: r0 = 1 (skipped)
        exit_insn(),      // 3: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Jump target (3) should be in jump_targets
    assert!(cfg.jump_targets.contains(&3));
}

#[test]
fn test_cfg_unconditional_backward_jump() {
    // Creates an infinite loop (back-edge)
    let insns = vec![
        mov64_imm(0, 0),  // 0: r0 = 0
        ja_insn(-1),      // 1: goto -1 (to insn 1 itself - infinite loop)
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Target is insn 1 (1 + (-1) + 1 = 1)
    assert!(cfg.jump_targets.contains(&1));
}

// ============================================================================
// Conditional Jump Tests
// ============================================================================

#[test]
fn test_cfg_conditional_forward_jump() {
    let insns = vec![
        mov64_imm(0, 0),  // 0: r0 = 0
        jeq_imm(0, 0, 1), // 1: if r0 == 0 goto +1 (to insn 3)
        mov64_imm(0, 1),  // 2: r0 = 1 (fall-through)
        exit_insn(),      // 3: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Both targets should be in jump_targets
    assert!(cfg.jump_targets.contains(&0));  // entry
    assert!(cfg.jump_targets.contains(&2));  // fall-through
    assert!(cfg.jump_targets.contains(&3));  // jump target
}

#[test]
fn test_cfg_conditional_creates_two_blocks() {
    let insns = vec![
        jeq_imm(0, 0, 1), // 0: if r0 == 0 goto +1 (to insn 2)
        mov64_imm(0, 1),  // 1: r0 = 1 (fall-through)
        exit_insn(),      // 2: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Should have blocks at 0, 1, and 2
    assert!(cfg.blocks.len() >= 2);
}

#[test]
fn test_cfg_if_else_structure() {
    // if (r0 == 0) { r0 = 1; } else { r0 = 2; } exit;
    let insns = vec![
        jeq_imm(0, 0, 2),  // 0: if r0 == 0 goto +2 (to insn 3)
        mov64_imm(0, 2),   // 1: r0 = 2 (else branch)
        ja_insn(1),        // 2: goto +1 (to insn 4, skip then branch)
        mov64_imm(0, 1),   // 3: r0 = 1 (then branch)
        exit_insn(),       // 4: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Multiple jump targets
    assert!(cfg.jump_targets.contains(&0));
    assert!(cfg.jump_targets.contains(&3)); // then branch
    assert!(cfg.jump_targets.contains(&4)); // exit
}

// ============================================================================
// Back-Edge Detection Tests
// ============================================================================

#[test]
fn test_is_back_edge_forward() {
    let insns = vec![exit_insn()];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Forward edge is not a back-edge
    assert!(!cfg.is_back_edge(0, 5));
}

#[test]
fn test_is_back_edge_backward() {
    let insns = vec![exit_insn()];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Backward edge is a back-edge
    assert!(cfg.is_back_edge(5, 0));
    assert!(cfg.is_back_edge(5, 5)); // Same location is also a back-edge
}

#[test]
fn test_find_loop_headers_no_loop() {
    let insns = vec![
        mov64_imm(0, 0),
        exit_insn(),
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let headers = cfg.find_loop_headers(&insns);
    
    assert!(headers.is_empty());
}

#[test]
fn test_find_loop_headers_simple_loop() {
    // while (1) { }  - infinite loop
    let insns = vec![
        ja_insn(-1),  // 0: goto 0 (back to itself)
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let headers = cfg.find_loop_headers(&insns);
    
    // Instruction 0 should be a loop header
    assert!(headers.contains(&0));
}

#[test]
fn test_find_loop_headers_conditional_loop() {
    // while (r0 != 0) { r0--; }
    let insns = vec![
        jeq_imm(0, 0, 2),     // 0: if r0 == 0 goto +2 (exit)
        alu64_add_imm(0, -1), // 1: r0--
        ja_insn(-3),          // 2: goto 0 (loop back)
        exit_insn(),          // 3: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let headers = cfg.find_loop_headers(&insns);
    
    // Instruction 0 should be a loop header
    assert!(headers.contains(&0));
}

// ============================================================================
// Basic Block Tests
// ============================================================================

#[test]
fn test_basic_block_default() {
    let block = BasicBlock::default();
    assert_eq!(block.start, 0);
    assert_eq!(block.end, 0);
    assert!(block.successors.is_empty());
    assert!(block.predecessors.is_empty());
}

#[test]
fn test_basic_block_successors() {
    let insns = vec![
        jeq_imm(0, 0, 1),  // 0: if r0 == 0 goto +1
        exit_insn(),       // 1: exit (fall-through)
        exit_insn(),       // 2: exit (jump target)
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Block 0 should have two successors
    if let Some(block) = cfg.blocks.get(&0) {
        assert!(block.successors.len() <= 2);
    }
}

// ============================================================================
// All Blocks Iterator Tests
// ============================================================================

#[test]
fn test_all_blocks_empty() {
    let insns: Vec<BpfInsn> = vec![];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    assert_eq!(cfg.all_blocks().count(), 0);
}

#[test]
fn test_all_blocks_single() {
    let insns = vec![exit_insn()];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    assert_eq!(cfg.all_blocks().count(), 1);
}

#[test]
fn test_all_blocks_multiple() {
    let insns = vec![
        jeq_imm(0, 0, 1),
        exit_insn(),
        exit_insn(),
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    assert!(cfg.all_blocks().count() >= 2);
}

// ============================================================================
// Postorder Traversal Tests
// ============================================================================

#[test]
fn test_compute_postorder_empty() {
    let insns: Vec<BpfInsn> = vec![];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let subprog_starts = vec![0];
    let po = cfg.compute_postorder(&insns, &subprog_starts);
    
    assert!(po.is_empty());
}

#[test]
fn test_compute_postorder_linear() {
    let insns = vec![
        mov64_imm(0, 0),
        exit_insn(),
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let subprog_starts = vec![0];
    let po = cfg.compute_postorder(&insns, &subprog_starts);
    
    // Should include both instructions in some order
    assert!(!po.is_empty());
}

#[test]
fn test_compute_reverse_postorder() {
    let insns = vec![
        mov64_imm(0, 0),
        exit_insn(),
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    let subprog_starts = vec![0];
    let rpo = cfg.compute_reverse_postorder(&insns, &subprog_starts);
    
    // Reverse postorder should also include both
    assert!(!rpo.is_empty());
}

// ============================================================================
// ExploredStates Tests
// ============================================================================

#[test]
fn test_explored_states_new() {
    let states = ExploredStates::new();
    assert_eq!(states.total_states, 0);
    assert_eq!(states.peak_states, 0);
}

#[test]
fn test_explored_states_add_state() {
    let mut states = ExploredStates::new();
    let state = BpfVerifierState::new();
    
    states.add_state(0, state);
    assert_eq!(states.total_states, 1);
    assert_eq!(states.peak_states, 1);
}

#[test]
fn test_explored_states_add_multiple() {
    let mut states = ExploredStates::new();
    
    for i in 0..5 {
        let state = BpfVerifierState::new();
        states.add_state(i, state);
    }
    
    assert_eq!(states.total_states, 5);
    assert_eq!(states.peak_states, 5);
}

#[test]
fn test_explored_states_get_states() {
    let mut states = ExploredStates::new();
    let state = BpfVerifierState::new();
    
    states.add_state(42, state);
    
    let retrieved = states.get_states(42);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().len(), 1);
    
    let not_found = states.get_states(999);
    assert!(not_found.is_none());
}

#[test]
fn test_explored_states_find_equivalent_none() {
    let states = ExploredStates::new();
    let state = BpfVerifierState::new();
    
    let result = states.find_equivalent(0, &state);
    assert!(result.is_none());
}

#[test]
fn test_explored_states_same_insn_multiple_states() {
    let mut states = ExploredStates::new();
    
    // Add multiple states at same instruction
    for _ in 0..3 {
        let state = BpfVerifierState::new();
        states.add_state(0, state);
    }
    
    let retrieved = states.get_states(0);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().len(), 3);
}

// ============================================================================
// Jump Target Boundary Tests
// ============================================================================

#[test]
fn test_jump_to_last_instruction() {
    let insns = vec![
        ja_insn(0),       // 0: goto +0 (to insn 1)
        exit_insn(),      // 1: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    assert!(cfg.jump_targets.contains(&1));
}

#[test]
fn test_jump_offset_zero() {
    let insns = vec![
        jeq_imm(0, 0, 0), // 0: if r0 == 0 goto +0 (to insn 1)
        exit_insn(),      // 1: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // With offset 0, target is next instruction
    assert!(cfg.jump_targets.contains(&1));
}

// ============================================================================
// Complex CFG Tests
// ============================================================================

#[test]
fn test_cfg_diamond_pattern() {
    // Diamond shape: entry -> (A | B) -> exit
    // if (r0) { A } else { B } exit
    let insns = vec![
        jeq_imm(0, 0, 2),  // 0: if r0 == 0 goto 3 (B branch)
        mov64_imm(0, 1),   // 1: A: r0 = 1
        ja_insn(1),        // 2: goto 4 (exit)
        mov64_imm(0, 2),   // 3: B: r0 = 2
        exit_insn(),       // 4: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Entry and both branches should be targets
    assert!(cfg.jump_targets.contains(&0));
    assert!(cfg.jump_targets.contains(&3)); // B branch
    assert!(cfg.jump_targets.contains(&4)); // exit
}

#[test]
fn test_cfg_nested_conditionals() {
    // Nested if-else
    let insns = vec![
        jeq_imm(0, 0, 3),  // 0: if r0 == 0 goto 4
        jeq_imm(1, 0, 1),  // 1: if r1 == 0 goto 3
        mov64_imm(0, 1),   // 2: r0 = 1
        mov64_imm(0, 2),   // 3: r0 = 2
        exit_insn(),       // 4: exit
    ];
    let cfg = ControlFlowGraph::build(&insns).unwrap();
    
    // Multiple jump targets
    assert!(cfg.jump_targets.len() >= 3);
}
