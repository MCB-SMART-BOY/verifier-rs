//! Optimization passes for the BPF verifier.
//!
//! This module contains optimization and transformation passes:
//! - Dead code elimination
//! - Instruction patching
//! - Miscellaneous fixups (do_misc_fixups equivalent)
//! - Context access conversion (convert_ctx_accesses equivalent)
//! - Cache optimization (bloom filters, compression, pooling)
//! - Unified pass framework with pass manager

pub mod dead_code;
pub mod patching;
pub mod misc_fixups;
pub mod ctx_access;
pub mod jit_subprogs;
pub mod cache;
pub mod pass;

pub use dead_code::*;
pub use patching::*;
pub use misc_fixups::*;
pub use ctx_access::*;
pub use jit_subprogs::*;
pub use cache::*;
pub use pass::*;
