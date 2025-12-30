// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bpf_core::disasm

use bpf_verifier::prelude::*;
use bpf_verifier::bpf_core::disasm::*;


#[test]
fn test_disasm_alu() {
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 42);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("add r0, 42"));
}

#[test]
fn test_disasm_alu_reg() {
    let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("add r0, r1"));
}

#[test]
fn test_disasm_mov32() {
    let insn = BpfInsn::new(BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, 100);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("mov32 r1, 100"));
}

#[test]
fn test_disasm_ldx() {
    let insn = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 10, -8, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("ldxdw r0, [r10-8]"));
}

#[test]
fn test_disasm_stx() {
    let insn = BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, 10, 1, -4, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("stxw [r10-4], r1"));
}

#[test]
fn test_disasm_jmp() {
    let insn = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("ja +5"));
    assert!(s.contains("<6>")); // target annotation
}

#[test]
fn test_disasm_jeq() {
    let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 3, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("jeq r1, 0, +3"));
}

#[test]
fn test_disasm_call_helper() {
    let insn = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert!(s.contains("map_lookup_elem"));
}

#[test]
fn test_disasm_exit() {
    let insn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    let opts = DisasmOptions::new().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    assert_eq!(s.trim(), "exit");
}

#[test]
fn test_disasm_program() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let opts = DisasmOptions::new();
    let s = disasm_program(&insns, &opts);
    assert!(s.contains("mov r0, 0"));
    assert!(s.contains("exit"));
}

#[test]
fn test_program_dumper() {
    let insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    
    let dumper = ProgramDumper::new(&insns);
    let stats = dumper.stats();
    
    assert_eq!(stats.total_insns, 3);
    assert_eq!(stats.alu64_insns, 2);
    assert_eq!(stats.exit_insns, 1);
}

#[test]
fn test_helper_names() {
    assert_eq!(get_helper_name(1), Some("map_lookup_elem"));
    assert_eq!(get_helper_name(12), Some("tail_call"));
    assert_eq!(get_helper_name(9999), None);
}

#[test]
fn test_disasm_with_bytecode() {
    let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42);
    let opts = DisasmOptions::new().with_bytecode().without_offsets();
    let s = disasm_insn(&insn, 0, &opts);
    // Should contain bytecode
    assert!(s.contains("b7")); // BPF_ALU64 | BPF_MOV | BPF_K = 0xb7
}

#[test]
fn test_disasm_annotated() {
    let insns = vec![
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), // jump to 2
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    
    let s = disasm_annotated(&insns);
    assert!(s.contains("L2:")); // Label at jump target
}
