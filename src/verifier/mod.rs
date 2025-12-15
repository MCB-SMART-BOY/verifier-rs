//! Main verifier orchestration.
//!
//! This module contains the main verification loop, environment setup,
//! verification statistics tracking, result reporting, resource limits,
//! parallel exploration infrastructure, and program loading entry points.

pub mod branch_state;
pub mod env;
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
pub use limits::*;
pub use loader::*;
pub use main_loop::*;
pub use parallel::*;
pub use result::*;
pub use stats::*;
pub use worklist::*;
pub use worklist_verifier::*;
