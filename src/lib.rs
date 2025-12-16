// SPDX-License-Identifier: GPL-2.0

//! # BPF Verifier for Rust for Linux
//!
//! A Rust implementation of the Linux kernel BPF verifier (`kernel/bpf/verifier.c`).
//!
//! This crate provides static code analysis for eBPF programs to ensure safety
//! before they are loaded into the kernel.
//!
//! ## Features
//!
//! - **Register State Tracking**: Tracks the type and bounds of all registers
//! - **Memory Safety**: Validates all memory accesses (stack, maps, packets, context)
//! - **Control Flow Analysis**: Explores all possible execution paths
//! - **Reference Tracking**: Ensures acquired resources are properly released
//! - **Bounds Analysis**: Tracks numeric bounds to prevent buffer overflows
//!
//! ## Module Structure
//!
//! - [`core`]: Core types, error definitions, logging, and instruction representations
//! - [`state`]: Register states, stack states, verifier states, and reference tracking
//! - [`bounds`]: Numeric bounds tracking (Tnum and scalar bounds)
//! - [`analysis`]: Program analysis (CFG, precision, liveness, loops, pruning)
//! - [`check`]: Instruction verification (helpers, kfuncs, atomics, jumps)
//! - [`mem`]: Memory access verification (stack, packet, context, arena)
//! - [`special`]: Special object handling (dynptr, iterators, exceptions, maps)
//! - [`btf`]: BTF (BPF Type Format) support
//! - [`sanitize`]: Pointer arithmetic sanitization for Spectre mitigation
//! - [`opt`]: Optimization passes (dead code elimination, instruction patching)
//! - [`verifier`]: Main verification loop and environment

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Unsafe code is required for FFI with kernel and low-level memory operations
#![expect(unsafe_code, reason = "Required for kernel FFI and MaybeUninit usage")]

extern crate alloc;

// Re-export alloc types for internal use
#[expect(unused_imports, reason = "Not all imports used in all configurations")]
pub(crate) mod stdlib {
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::vec;
    pub use alloc::format;
    pub use alloc::collections::{BTreeMap, BTreeSet, VecDeque, BinaryHeap};
}

/// Core types, error definitions, and basic utilities
pub mod core;

/// State tracking (registers, stack, verifier state)
pub mod state;

/// Numeric bounds tracking
pub mod bounds;

/// Program analysis passes
pub mod analysis;

/// Instruction checking
pub mod check;

/// Memory access verification
pub mod mem;

/// Special object handling
pub mod special;

/// BTF type support
pub mod btf;

/// Sanitization passes
pub mod sanitize;

/// Optimization passes
pub mod opt;

/// Main verifier
pub mod verifier;

/// Kernel integration layer
#[cfg(feature = "kernel")]
pub mod kernel;

// ============================================================================
// Prelude - commonly used re-exports
// ============================================================================

/// Commonly used types and traits
pub mod prelude {
    // Core types and errors
    pub use crate::core::error::{Result, VerifierError};
    pub use crate::core::types::{
        BpfArgType, BpfFuncId, BpfInsn, BpfMapType, BpfProgType, BpfRegType,
        BpfRetType, BpfRetvalRange, BpfTypeFlag,
    };
    pub use crate::core::types::{
        BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_ATOMIC, BPF_B,
        BPF_CALL, BPF_DIV, BPF_DW, BPF_END, BPF_EXIT, BPF_H, BPF_IMM, BPF_JA,
        BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP, BPF_JMP32,
        BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_K,
        BPF_LD, BPF_LDX, BPF_LSH, BPF_MEM, BPF_MOD, BPF_MOV, BPF_MUL, BPF_NEG,
        BPF_OR, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL, BPF_PSEUDO_MAP_FD,
        BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5,
        BPF_REG_6, BPF_REG_7, BPF_REG_8, BPF_REG_9, BPF_REG_FP, BPF_REG_SIZE,
        BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_W, BPF_X, BPF_XOR,
        MAX_BPF_REG, MAX_BPF_STACK,
    };

    // State types
    pub use crate::state::reg_state::BpfRegState;
    pub use crate::state::stack_state::BpfStackState;
    pub use crate::state::verifier_state::BpfVerifierState;
    pub use crate::state::reference::{BpfReferenceState, ReferenceManager};
    pub use crate::core::types::RefStateType;
    pub use crate::core::types::BpfStackSlotType;

    // Bounds types
    pub use crate::bounds::tnum::Tnum;
    pub use crate::bounds::scalar::ScalarBounds;

    // BTF types
    pub use crate::btf::{Btf, BpfCoreReloKind};

    // Special types
    pub use crate::core::types::BpfDynptrType;

    // Atomic constants
    pub use crate::core::types::BPF_FETCH;

    // Verifier
    pub use crate::verifier::{MainVerifier, VerifierEnv};
}

// Re-export error types at crate root for convenience
pub use core::error::{Result, VerifierError};
