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
#![allow(unsafe_code)]

extern crate alloc;

// Re-export alloc types for internal use
#[allow(unused_imports)]
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

// ============================================================================
// Prelude - commonly used re-exports
// ============================================================================

/// Commonly used types and traits
pub mod prelude {
    pub use crate::core::error::{Result, VerifierError};
    pub use crate::core::types::{BpfInsn, BpfProgType, BpfRegType};
    pub use crate::state::reg_state::BpfRegState;
    pub use crate::state::verifier_state::BpfVerifierState;
    pub use crate::verifier::{MainVerifier, VerifierEnv};
}

// Re-export error types at crate root for convenience
pub use core::error::{Result, VerifierError};
