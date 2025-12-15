//! BPF Verifier - Basic Demo
//!
//! This example demonstrates basic usage of the BPF verifier library.

use bpf_verifier::analysis::cfg::Verifier;
use bpf_verifier::core::types::*;

fn main() {
    println!("BPF Verifier - Rust Implementation");
    println!("===================================\n");

    // Example 1: Simple valid program (mov r0, 0; exit)
    println!("Example 1: Simple valid program");
    let simple_prog = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // r0 = 0
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),           // exit
    ];

    match Verifier::new(simple_prog, true) {
        Ok(mut verifier) => {
            match verifier.verify() {
                Ok(()) => println!("  Result: PASSED\n"),
                Err(e) => println!("  Result: FAILED - {}\n", e),
            }
        }
        Err(e) => println!("  Result: FAILED - {}\n", e),
    }

    // Example 2: Program with ALU operations
    println!("Example 2: ALU operations");
    let alu_prog = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10),  // r1 = 10
        BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5),   // r1 += 5
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),   // r0 = r1
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // exit
    ];

    match Verifier::new(alu_prog, true) {
        Ok(mut verifier) => {
            match verifier.verify() {
                Ok(()) => println!("  Result: PASSED\n"),
                Err(e) => println!("  Result: FAILED - {}\n", e),
            }
        }
        Err(e) => println!("  Result: FAILED - {}\n", e),
    }

    // Example 3: Program with conditional jump
    println!("Example 3: Conditional branch");
    let branch_prog = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),   // r0 = 0
        BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1, 0),     // if r1 == 0 goto +1
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),   // r0 = 1
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // exit
    ];

    match Verifier::new(branch_prog, true) {
        Ok(mut verifier) => {
            match verifier.verify() {
                Ok(()) => println!("  Result: PASSED\n"),
                Err(e) => println!("  Result: FAILED - {}\n", e),
            }
        }
        Err(e) => println!("  Result: FAILED - {}\n", e),
    }

    // Example 4: Invalid - uninitialized register use
    println!("Example 4: Uninitialized register (should fail)");
    let uninit_prog = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0),   // r0 = r2 (r2 uninit)
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // exit
    ];

    match Verifier::new(uninit_prog, true) {
        Ok(mut verifier) => {
            match verifier.verify() {
                Ok(()) => println!("  Result: PASSED (unexpected)\n"),
                Err(e) => println!("  Result: FAILED (expected) - {}\n", e),
            }
        }
        Err(e) => println!("  Result: FAILED - {}\n", e),
    }

    println!("===================================");
    println!("Verification complete.");
}
