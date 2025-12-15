//! Sanitization for the BPF verifier.
//!
//! This module contains pointer arithmetic sanitization and
//! Spectre mitigation support.
//!
//! Key components:
//! - `sanitize`: Core Spectre mitigation and pointer sanitization
//! - `overflow`: Pointer overflow check patches for JIT

pub mod overflow;
pub mod sanitize;

pub use overflow::*;
pub use sanitize::*;
