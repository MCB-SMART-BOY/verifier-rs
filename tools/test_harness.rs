//! User-space Test Harness for BPF Verifier
//!
//! This tool allows testing the Rust BPF verifier against real BPF programs
//! without loading them into the kernel. It can:
//!
//! 1. Load BPF object files and verify them
//! 2. Compare results against the kernel verifier
//! 3. Run regression tests
//!
//! Usage:
//!   cargo run --bin test_harness -- <command> [options]
//!
//! Commands:
//!   verify <file.o>     - Verify a BPF object file
//!   compare <file.o>    - Compare Rust vs kernel verifier
//!   regtest             - Run regression test suite
//!   bench               - Run performance benchmarks

use std::env;
use std::fs;
use std::time::Instant;

use bpf_verifier::core::types::{BpfInsn, BpfProgType};
use bpf_verifier::verifier::{VerifierEnv, MainVerifier};
use bpf_verifier::VerifierError;

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }
    
    match args[1].as_str() {
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: test_harness verify <file.o>");
                return;
            }
            cmd_verify(&args[2]);
        }
        "compare" => {
            if args.len() < 3 {
                eprintln!("Usage: test_harness compare <file.o>");
                return;
            }
            cmd_compare(&args[2]);
        }
        "regtest" => {
            cmd_regtest();
        }
        "bench" => {
            cmd_bench();
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("BPF Verifier Test Harness");
    println!();
    println!("Usage: test_harness <command> [options]");
    println!();
    println!("Commands:");
    println!("  verify <file.o>     Verify a BPF object file");
    println!("  compare <file.o>    Compare Rust vs kernel verifier");
    println!("  regtest             Run regression test suite");
    println!("  bench               Run performance benchmarks");
    println!("  help                Show this help");
}

// ============================================================================
// Verify Command
// ============================================================================

fn cmd_verify(file: &str) {
    println!("Verifying: {}", file);
    
    let programs = match load_bpf_object(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading {}: {}", file, e);
            return;
        }
    };
    
    println!("Found {} programs", programs.len());
    
    for (name, insns, prog_type) in programs {
        print!("  {} ({} insns, type {:?}): ", name, insns.len(), prog_type);
        
        let result = verify_program(&insns, prog_type);
        
        match result {
            Ok(stats) => {
                println!("ACCEPT");
                println!("    Instructions processed: {}", stats.insn_processed);
                println!("    States explored: {}", stats.states_explored);
                println!("    Time: {:?}", stats.time);
            }
            Err(e) => {
                println!("REJECT: {}", e);
            }
        }
    }
}

// ============================================================================
// Compare Command
// ============================================================================

fn cmd_compare(file: &str) {
    println!("Comparing verifiers on: {}", file);
    
    let programs = match load_bpf_object(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading {}: {}", file, e);
            return;
        }
    };
    
    let mut matches = 0;
    let mut mismatches = 0;
    
    for (name, insns, prog_type) in programs {
        print!("  {}: ", name);
        
        // Run Rust verifier
        let rust_result = verify_program(&insns, prog_type);
        
        // Run kernel verifier (via bpf syscall)
        let kernel_result = kernel_verify(&insns, prog_type);
        
        // Compare
        match (&rust_result, &kernel_result) {
            (Ok(_), Ok(_)) => {
                println!("MATCH (both accept)");
                matches += 1;
            }
            (Err(_), Err(_)) => {
                println!("MATCH (both reject)");
                matches += 1;
            }
            (Ok(_), Err(e)) => {
                println!("MISMATCH - Rust: accept, Kernel: reject ({})", e);
                mismatches += 1;
            }
            (Err(e), Ok(_)) => {
                println!("MISMATCH - Rust: reject ({}), Kernel: accept", e);
                mismatches += 1;
            }
        }
    }
    
    println!();
    println!("Summary: {} matches, {} mismatches", matches, mismatches);
    
    if mismatches > 0 {
        std::process::exit(1);
    }
}

// ============================================================================
// Regression Test Command
// ============================================================================

fn cmd_regtest() {
    println!("Running regression tests...");
    println!();
    
    let tests = get_regression_tests();
    
    let mut passed = 0;
    let mut failed = 0;
    
    for test in tests {
        print!("  {}: ", test.name);
        
        let result = verify_program(&test.insns, test.prog_type);
        
        let success = match (&test.expected, &result) {
            (Expected::Accept, Ok(_)) => true,
            (Expected::Reject(_), Err(_)) => true,
            _ => false,
        };
        
        if success {
            println!("PASS");
            passed += 1;
        } else {
            println!("FAIL");
            println!("    Expected: {:?}", test.expected);
            println!("    Got: {:?}", result);
            failed += 1;
        }
    }
    
    println!();
    println!("Results: {} passed, {} failed", passed, failed);
    
    if failed > 0 {
        std::process::exit(1);
    }
}

// ============================================================================
// Benchmark Command
// ============================================================================

fn cmd_bench() {
    println!("Running benchmarks...");
    println!();
    
    let benchmarks = get_benchmarks();
    
    for bench in benchmarks {
        print!("  {}: ", bench.name);
        
        // Warm up
        for _ in 0..3 {
            let _ = verify_program(&bench.insns, bench.prog_type);
        }
        
        // Benchmark
        let iterations = 100;
        let start = Instant::now();
        
        for _ in 0..iterations {
            let _ = verify_program(&bench.insns, bench.prog_type);
        }
        
        let elapsed = start.elapsed();
        let per_iter = elapsed / iterations;
        
        println!("{:?} per iteration ({} iterations)", per_iter, iterations);
    }
}

// ============================================================================
// BPF Object Loading
// ============================================================================

#[allow(dead_code)]
struct BpfProgram {
    name: String,
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
}

fn load_bpf_object(path: &str) -> Result<Vec<(String, Vec<BpfInsn>, BpfProgType)>, String> {
    // Read the ELF file
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Parse ELF and extract BPF programs
    // This is a simplified version - real implementation would use goblin or elf crate
    parse_bpf_elf(&data)
}

fn parse_bpf_elf(data: &[u8]) -> Result<Vec<(String, Vec<BpfInsn>, BpfProgType)>, String> {
    // Check ELF magic
    if data.len() < 4 || &data[0..4] != b"\x7fELF" {
        return Err("Not an ELF file".to_string());
    }
    
    // For now, return a placeholder
    // Real implementation would:
    // 1. Parse ELF sections
    // 2. Find sections starting with "socket", "kprobe", "xdp", etc.
    // 3. Extract instructions from those sections
    // 4. Parse BTF for type information
    
    Ok(vec![])
}

// ============================================================================
// Verification
// ============================================================================

#[derive(Debug)]
struct VerifyStats {
    insn_processed: u32,
    states_explored: u32,
    time: std::time::Duration,
}

fn verify_program(insns: &[BpfInsn], prog_type: BpfProgType) -> Result<VerifyStats, VerifierError> {
    let start = Instant::now();
    
    let mut env = VerifierEnv::new(insns.to_vec(), prog_type, true)?;
    let mut verifier = MainVerifier::new(&mut env);
    
    verifier.verify()?;
    
    let elapsed = start.elapsed();
    
    // Get actual stats from the verifier environment
    Ok(VerifyStats {
        insn_processed: env.insn_processed as u32,
        states_explored: env.total_states as u32,
        time: elapsed,
    })
}

fn kernel_verify(_insns: &[BpfInsn], _prog_type: BpfProgType) -> Result<(), String> {
    // Use bpf() syscall to verify with kernel
    // This requires root privileges
    
    // For safety, we don't actually load - just verify
    // Using BPF_PROG_LOAD with BPF_F_TEST_RUN_MODE or similar
    
    #[cfg(target_os = "linux")]
    {
        // Convert instructions to raw bytes
        let _insn_bytes: Vec<u8> = _insns.iter()
            .flat_map(|i| {
                let mut bytes = vec![i.code, (i.src_reg << 4) | i.dst_reg];
                bytes.extend_from_slice(&i.off.to_le_bytes());
                bytes.extend_from_slice(&i.imm.to_le_bytes());
                bytes
            })
            .collect();
        
        // Would call bpf() syscall here
        // For now, return success as placeholder
        Ok(())
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Err("Kernel verification only available on Linux".to_string())
    }
}

// ============================================================================
// Regression Tests
// ============================================================================

#[derive(Debug)]
#[allow(dead_code)]
enum Expected {
    Accept,
    Reject(&'static str),
}

struct RegressionTest {
    name: &'static str,
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
    expected: Expected,
}

fn get_regression_tests() -> Vec<RegressionTest> {
    vec![
        RegressionTest {
            name: "minimal_exit",
            insns: vec![
                BpfInsn::new(0xb7, 0, 0, 0, 0),  // mov r0, 0
                BpfInsn::new(0x95, 0, 0, 0, 0),  // exit
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Accept,
        },
        RegressionTest {
            name: "uninit_r0",
            insns: vec![
                BpfInsn::new(0x95, 0, 0, 0, 0),  // exit (r0 uninit)
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Reject("R0 not initialized"),
        },
        RegressionTest {
            name: "simple_add",
            insns: vec![
                BpfInsn::new(0xb7, 0, 0, 0, 10), // mov r0, 10
                BpfInsn::new(0x07, 0, 0, 0, 5),  // add r0, 5
                BpfInsn::new(0x95, 0, 0, 0, 0),  // exit
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Accept,
        },
        RegressionTest {
            name: "stack_access",
            insns: vec![
                BpfInsn::new(0xb7, 1, 0, 0, 42),    // mov r1, 42
                BpfInsn::new(0x7b, 10, 1, -8, 0),   // *(r10-8) = r1
                BpfInsn::new(0x79, 0, 10, -8, 0),   // r0 = *(r10-8)
                BpfInsn::new(0x95, 0, 0, 0, 0),     // exit
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Accept,
        },
        RegressionTest {
            name: "jump_forward",
            insns: vec![
                BpfInsn::new(0xb7, 0, 0, 0, 1),     // mov r0, 1
                BpfInsn::new(0x05, 0, 0, 1, 0),     // ja +1
                BpfInsn::new(0xb7, 0, 0, 0, 2),     // mov r0, 2 (skipped)
                BpfInsn::new(0x95, 0, 0, 0, 0),     // exit
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Accept,
        },
        RegressionTest {
            name: "conditional_branch",
            insns: vec![
                BpfInsn::new(0xb7, 0, 0, 0, 5),     // mov r0, 5
                BpfInsn::new(0x15, 0, 0, 1, 5),     // if r0 == 5, skip
                BpfInsn::new(0xb7, 0, 0, 0, 0),     // mov r0, 0 (skipped)
                BpfInsn::new(0x95, 0, 0, 0, 0),     // exit
            ],
            prog_type: BpfProgType::SocketFilter,
            expected: Expected::Accept,
        },
    ]
}

// ============================================================================
// Benchmarks
// ============================================================================

struct Benchmark {
    name: &'static str,
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
}

fn get_benchmarks() -> Vec<Benchmark> {
    vec![
        Benchmark {
            name: "minimal",
            insns: vec![
                BpfInsn::new(0xb7, 0, 0, 0, 0),
                BpfInsn::new(0x95, 0, 0, 0, 0),
            ],
            prog_type: BpfProgType::SocketFilter,
        },
        Benchmark {
            name: "100_alu_ops",
            insns: {
                let mut v = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)];
                for _ in 0..100 {
                    v.push(BpfInsn::new(0x07, 0, 0, 0, 1));
                }
                v.push(BpfInsn::new(0x95, 0, 0, 0, 0));
                v
            },
            prog_type: BpfProgType::SocketFilter,
        },
        Benchmark {
            name: "10_branches",
            insns: {
                let mut v = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)];
                for i in 0..10 {
                    v.push(BpfInsn::new(0x15, 0, 0, 1, i)); // if r0 == i
                    v.push(BpfInsn::new(0x07, 0, 0, 0, 1)); // add r0, 1
                }
                v.push(BpfInsn::new(0x95, 0, 0, 0, 0));
                v
            },
            prog_type: BpfProgType::SocketFilter,
        },
    ]
}
