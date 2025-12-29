// SPDX-License-Identifier: GPL-2.0

//! # BPF Verifier
//!
//! Convenience crate that re-exports the BPF verifier core and Linux platform.
//!
//! This crate provides a single dependency for using the BPF verifier with
//! Linux support. For custom platforms, depend on `bpf-verifier-core` directly.
//!
//! ## Usage
//!
//! ```ignore
//! use bpf_verifier::{LinuxSpec, VerifierEnv, MainVerifier};
//! use bpf_verifier::core::types::BpfProgType;
//!
//! let platform = LinuxSpec::new();
//! let insns = vec![/* BPF instructions */];
//! let mut env = VerifierEnv::new(platform, BpfProgType::Xdp as u32, insns);
//! let mut verifier = MainVerifier::new(&mut env);
//! 
//! match verifier.verify() {
//!     Ok(()) => println!("Program verified successfully"),
//!     Err(e) => println!("Verification failed: {:?}", e),
//! }
//! ```

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Re-export core crate
pub use bpf_verifier_core as core;

// Re-export Linux platform
#[cfg(feature = "linux")]
pub use bpf_verifier_linux as linux;

// Convenient re-exports
pub use bpf_verifier_core::prelude::*;

#[cfg(feature = "linux")]
pub use bpf_verifier_linux::LinuxSpec;
