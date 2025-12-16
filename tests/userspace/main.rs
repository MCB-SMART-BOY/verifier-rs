//! User-space verification test harness
//!
//! This program tests the Rust BPF verifier by running various BPF programs
//! through it and comparing the results with expected outcomes.

use bpf_verifier::{
    core::types::{BpfInsn, BpfProgType, BPF_ALU64, BPF_MOV, BPF_K, BPF_JMP, BPF_EXIT,
                  BPF_LD, BPF_DW, BPF_IMM, BPF_ADD, BPF_X, BPF_MEM, BPF_STX, BPF_LDX,
                  BPF_JEQ, BPF_JA},
    verifier::{MainVerifier, VerifierEnv},
};

// Register constants
const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R5: u8 = 5;
const R10: u8 = 10;

/// Test result
struct TestResult {
    name: &'static str,
    passed: bool,
    expected_ok: bool,
    actual_ok: bool,
    error_msg: Option<String>,
}

impl TestResult {
    fn success(name: &'static str, expected_ok: bool) -> Self {
        Self {
            name,
            passed: true,
            expected_ok,
            actual_ok: expected_ok,
            error_msg: None,
        }
    }

    fn failure(name: &'static str, expected_ok: bool, actual_ok: bool, msg: String) -> Self {
        Self {
            name,
            passed: false,
            expected_ok,
            actual_ok,
            error_msg: Some(msg),
        }
    }
}

/// Run a single verification test
fn run_test(
    name: &'static str,
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
    expected_ok: bool,
) -> TestResult {
    let mut env = match VerifierEnv::new(insns, prog_type, true) {
        Ok(env) => env,
        Err(e) => {
            if expected_ok {
                return TestResult::failure(name, expected_ok, false, format!("Failed to create env: {}", e));
            } else {
                return TestResult::success(name, expected_ok);
            }
        }
    };

    let mut verifier = MainVerifier::new(&mut env);
    let result = verifier.verify();

    match (result.is_ok(), expected_ok) {
        (true, true) => TestResult::success(name, expected_ok),
        (false, false) => TestResult::success(name, expected_ok),
        (true, false) => TestResult::failure(
            name,
            expected_ok,
            true,
            "Expected rejection but program was accepted".to_string(),
        ),
        (false, true) => TestResult::failure(
            name,
            expected_ok,
            false,
            format!("Expected acceptance but got: {:?}", result.unwrap_err()),
        ),
    }
}

fn main() {
    println!("===========================================");
    println!("  BPF Verifier Rust - User-Space Tests");
    println!("===========================================\n");

    let mut results = Vec::new();

    // Test 1: Simple program that returns 0
    println!("Running test: simple_return_0");
    results.push(run_test(
        "simple_return_0",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0), // r0 = 0
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),           // exit
        ],
        BpfProgType::SocketFilter,
        true, // should pass
    ));

    // Test 2: Return a constant value
    println!("Running test: return_constant");
    results.push(run_test(
        "return_constant",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 42), // r0 = 42
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // exit
        ],
        BpfProgType::SocketFilter,
        true,
    ));

    // Test 3: Register arithmetic
    println!("Running test: register_arithmetic");
    results.push(run_test(
        "register_arithmetic",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 10),    // r1 = 10
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R2, 0, 0, 20),    // r2 = 20
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, R1, R2, 0, 0),    // r1 += r2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, R0, R1, 0, 0),    // r0 = r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),               // exit
        ],
        BpfProgType::SocketFilter,
        true,
    ));

    // Test 4: Stack access
    println!("Running test: stack_access");
    results.push(run_test(
        "stack_access",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 0x12345678u32 as i32), // r1 = value
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, R10, R1, -8, 0),   // *(r10-8) = r1
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, R0, R10, -8, 0),   // r0 = *(r10-8)
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),               // exit
        ],
        BpfProgType::SocketFilter,
        true,
    ));

    // Test 5: Conditional branch
    println!("Running test: conditional_branch");
    results.push(run_test(
        "conditional_branch",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 5),     // r1 = 5
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, R1, 0, 2, 5),       // if r1 == 5 goto +2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0),     // r0 = 0
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0),                 // goto +1
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 1),     // r0 = 1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),               // exit
        ],
        BpfProgType::SocketFilter,
        true,
    ));

    // Test 6: Empty program (should fail - no exit)
    println!("Running test: empty_program");
    results.push(run_test(
        "empty_program",
        vec![],
        BpfProgType::SocketFilter,
        false, // should fail
    ));

    // Test 7: Missing exit instruction
    println!("Running test: missing_exit");
    results.push(run_test(
        "missing_exit",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0), // r0 = 0
            // no exit!
        ],
        BpfProgType::SocketFilter,
        false, // should fail
    ));

    // Test 8: Stack overflow (accessing beyond stack limit)
    println!("Running test: stack_overflow");
    results.push(run_test(
        "stack_overflow",
        vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 0x12345678u32 as i32),
            // Try to access way beyond the 512-byte stack limit
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, R10, R1, -600, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ],
        BpfProgType::SocketFilter,
        false, // should fail - stack overflow
    ));

    // Test 9: Use of uninitialized register
    println!("Running test: uninitialized_register");
    results.push(run_test(
        "uninitialized_register",
        vec![
            // r5 is never initialized, using it should fail
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, R0, R5, 0, 0), // r0 = r5
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ],
        BpfProgType::SocketFilter,
        false, // should fail
    ));

    // Test 10: 64-bit immediate load
    println!("Running test: ld_imm64");
    results.push(run_test(
        "ld_imm64",
        vec![
            // LD_IMM64 is a 2-instruction sequence
            BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, R0, 0, 0, 0x12345678u32 as i32),
            BpfInsn::new(0, 0, 0, 0, 0x9ABCDEFu32 as i32), // upper 32 bits
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ],
        BpfProgType::SocketFilter,
        true,
    ));

    // Print results
    println!("\n===========================================");
    println!("                 RESULTS");
    println!("===========================================\n");

    let mut passed = 0;
    let mut failed = 0;

    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        let expected = if result.expected_ok { "accept" } else { "reject" };
        let actual = if result.actual_ok { "accepted" } else { "rejected" };

        if result.passed {
            println!("[{}] {} (expected: {}, got: {})", status, result.name, expected, actual);
            passed += 1;
        } else {
            println!("[{}] {} (expected: {}, got: {})", status, result.name, expected, actual);
            if let Some(ref msg) = result.error_msg {
                println!("      Error: {}", msg);
            }
            failed += 1;
        }
    }

    println!("\n-------------------------------------------");
    println!("Total: {} tests, {} passed, {} failed", passed + failed, passed, failed);
    println!("-------------------------------------------");

    if failed > 0 {
        std::process::exit(1);
    }
}
