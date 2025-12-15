//! BPF Verifier - Program Verification Example
//!
//! This example shows how to use the verifier with different program types
//! and demonstrates the main verification API.

use bpf_verifier::{
    verifier::{VerifierEnv, MainVerifier},
    core::types::*,
};

fn main() {
    println!("BPF Program Verification Example");
    println!("=================================\n");

    // Create a simple socket filter program
    let program = vec![
        // r1 contains ctx pointer
        // Load packet length into r2: r2 = *(u32 *)(r1 + 0)
        // For simplicity, just return 0 (drop all packets)
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // r0 = 0
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // exit
    ];

    println!("Program: Socket filter (return 0)");
    println!("Instructions: {}", program.len());
    
    // Create verifier environment
    match VerifierEnv::new(program, BpfProgType::SocketFilter, true) {
        Ok(mut env) => {
            println!("Verifier environment created");
            
            // Run verification
            let mut verifier = MainVerifier::new(&mut env);
            match verifier.verify() {
                Ok(()) => {
                    println!("Verification: PASSED");
                    println!("Instructions processed: {}", env.insn_processed);
                    println!("Peak states: {}", env.peak_states);
                }
                Err(e) => {
                    println!("Verification: FAILED");
                    println!("Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to create verifier: {}", e);
        }
    }

    println!("\n---------------------------------\n");

    // Create a more complex program with branches
    let complex_program = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),   // r0 = 0
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10),  // r1 = 10
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 5),   // r2 = 5
        BpfInsn::new(BPF_JMP | BPF_JGT | BPF_X, 1, 2, 2, 0),     // if r1 > r2 goto +2
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),   // r0 = 1
        BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0),              // goto +1
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 2),   // r0 = 2
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // exit
    ];

    println!("Program: Complex branching");
    println!("Instructions: {}", complex_program.len());

    match VerifierEnv::new(complex_program, BpfProgType::SocketFilter, true) {
        Ok(mut env) => {
            println!("Verifier environment created");
            
            let mut verifier = MainVerifier::new(&mut env);
            match verifier.verify() {
                Ok(()) => {
                    println!("Verification: PASSED");
                    println!("Instructions processed: {}", env.insn_processed);
                    println!("Peak states: {}", env.peak_states);
                    println!("Total states explored: {}", env.total_states);
                }
                Err(e) => {
                    println!("Verification: FAILED");
                    println!("Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to create verifier: {}", e);
        }
    }

    println!("\n=================================");
    println!("Done.");
}
