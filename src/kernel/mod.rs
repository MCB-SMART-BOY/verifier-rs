// SPDX-License-Identifier: GPL-2.0

//! Kernel integration layer for the BPF verifier.
//!
//! This module provides the interface between the Rust BPF verifier
//! and the Linux kernel. It handles:
//!
//! - FFI bindings to kernel data structures
//! - Memory allocation using kernel allocators
//! - Error code translation
//! - Logging through kernel facilities
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Kernel (C code)                       │
//! │  bpf_check() -> rust_bpf_verify() -> bpf_verifier_ops   │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                 kernel::bindings (FFI)                   │
//! │  - struct bpf_verifier_env                              │
//! │  - struct bpf_prog                                      │
//! │  - struct bpf_map                                       │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                 kernel::bridge                           │
//! │  - KernelVerifierEnv (safe wrapper)                     │
//! │  - Convert C types to Rust types                        │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Rust Verifier (pure Rust)                   │
//! │  - MainVerifier                                         │
//! │  - State tracking, bounds analysis, etc.                │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod bindings;
pub mod bridge;
pub mod error;
pub mod alloc;
pub mod log;

// Re-exports for convenience
pub use bindings::*;
pub use bridge::KernelVerifierEnv;
pub use error::KernelError;
