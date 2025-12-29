// SPDX-License-Identifier: GPL-2.0

//! Main verifier orchestration.
//!
//! This module contains the main verification loop, environment setup,
//! verification statistics tracking, result reporting, resource limits,
//! parallel exploration infrastructure, and program loading entry points.
//!
//! ## Platform-Generic Components
//!
//! For platform-independent verification, use:
//! - [`GenericVerifierEnv`] - Platform-parameterized verifier environment
//! - [`GenericMainVerifier`] - Platform-parameterized main verifier

pub mod branch_state;
pub mod env;
pub mod generic_env;
pub mod generic_verifier;
pub mod limits;
pub mod loader;
pub mod main_loop;
pub mod parallel;
pub mod result;
pub mod stats;
pub mod worklist;
pub mod worklist_verifier;

pub use branch_state::*;
pub use env::*;
pub use generic_env::GenericVerifierEnv;
pub use generic_verifier::{GenericMainVerifier, VerificationStats};
pub use limits::*;
pub use loader::*;
pub use main_loop::*;
pub use parallel::*;
pub use result::*;
pub use stats::*;
pub use worklist::*;
pub use worklist_verifier::*;
