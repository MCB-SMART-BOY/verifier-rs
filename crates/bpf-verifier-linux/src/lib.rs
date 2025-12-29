// SPDX-License-Identifier: GPL-2.0

//! # BPF Verifier Linux Platform
//!
//! Linux platform implementation for the BPF verifier.
//!
//! This crate provides:
//! - Linux BPF helper function definitions
//! - Linux program type definitions
//! - Linux kfunc definitions
//! - Linux map type definitions
//! - Linux context structure definitions
//! - Kernel integration layer (optional, with `kernel` feature)
//!
//! ## Usage
//!
//! ```ignore
//! use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
//! use bpf_verifier_linux::LinuxSpec;
//!
//! let platform = LinuxSpec::new();
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! let result = MainVerifier::new(&mut env).verify();
//! ```

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Re-export core crate for convenience
pub use bpf_verifier_core as core;

mod spec;

pub use spec::LinuxSpec;

// Platform provider implementations
mod helper_db;
mod prog_types;
mod kfuncs;
mod map_types;
mod context;

pub use helper_db::LinuxHelperProvider;
pub use prog_types::LinuxProgTypeProvider;
pub use kfuncs::LinuxKfuncProvider;
pub use map_types::LinuxMapProvider;
pub use context::LinuxContextProvider;

/// Kernel integration layer (requires `kernel` feature)
#[cfg(feature = "kernel")]
pub mod kernel;
