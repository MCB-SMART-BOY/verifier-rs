// SPDX-License-Identifier: GPL-2.0

//! Platform abstraction layer for BPF verifier.
//!
//! This module defines platform-agnostic traits that allow the verifier
//! to support different BPF implementations (Linux, custom OS, etc.).
//!
//! # Design Philosophy
//!
//! Following the Nix crate's design pattern, we separate:
//! - **Core logic**: Platform-independent verification algorithms
//! - **Platform specification**: OS-specific definitions (helpers, prog types, etc.)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │              bpf-verifier-core (this crate)             │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │              PlatformSpec trait                  │   │
//! │  │  ├─ HelperProvider                              │   │
//! │  │  ├─ ProgTypeProvider                            │   │
//! │  │  ├─ KfuncProvider                               │   │
//! │  │  ├─ MapProvider                                 │   │
//! │  │  └─ ContextProvider                             │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//!                            ▲
//!                            │ implements
//!          ┌─────────────────┼─────────────────┐
//!          │                 │                 │
//! ┌────────┴───────┐ ┌───────┴────────┐ ┌──────┴───────┐
//! │  LinuxSpec     │ │   MyOsSpec     │ │  MockSpec    │
//! │  (Linux impl)  │ │  (Custom OS)   │ │  (Testing)   │
//! └────────────────┘ └────────────────┘ └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use bpf_verifier_core::platform::PlatformSpec;
//! use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
//!
//! // For Linux
//! let platform = LinuxSpec::new();
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! let result = MainVerifier::new(&mut env).verify();
//!
//! // For custom OS
//! let platform = MyOsSpec::new();
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! let result = MainVerifier::new(&mut env).verify();
//! ```

/// Platform specification trait
pub mod spec;
mod helper;
mod prog_type;
mod kfunc;
mod map;
/// Context provider definitions
pub mod context;
/// Platform-agnostic types
pub mod types;

// Re-export all traits and types
pub use spec::{PlatformSpec, NullPlatform};
pub use helper::{HelperProvider, HelperDef, HelperFlags};
pub use prog_type::{ProgTypeProvider, ProgTypeInfo, ProgCapabilities};
pub use kfunc::{KfuncProvider, KfuncDef, KfuncFlags};
pub use map::{MapProvider, MapTypeInfo, MapCapabilities, MapOp};
pub use context::{ContextProvider, ContextFieldDef, FieldAccessMode, FieldResultType, ContextDef};
pub use types::*;
