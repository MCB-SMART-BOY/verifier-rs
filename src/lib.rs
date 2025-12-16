//! # BPF Verifier
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
//! ## Quick Start
//!
//! ```rust
//! use bpf_verifier::{
//!     verifier::{VerifierEnv, MainVerifier},
//!     core::types::*,
//! };
//!
//! // Create a simple BPF program
//! let program = vec![
//!     BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // r0 = 0
//!     BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // exit
//! ];
//!
//! // Create verifier environment
//! let mut env = VerifierEnv::new(program, BpfProgType::SocketFilter, true).unwrap();
//!
//! // Run verification
//! let mut verifier = MainVerifier::new(&mut env);
//! match verifier.verify() {
//!     Ok(()) => println!("Program is safe!"),
//!     Err(e) => println!("Verification failed: {}", e),
//! }
//! ```
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
//!
//! ## no_std Support
//!
//! This crate supports `no_std` for use in kernel modules. Disable default features
//! and enable the `kernel` feature:
//!
//! ```toml
//! [dependencies]
//! bpf-verifier = { version = "0.1", default-features = false, features = ["kernel"] }
//! ```

// Conditional no_std support
#![cfg_attr(not(feature = "std"), no_std)]

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Allow unsafe in kernel mode for panic handler and FFI
#![cfg_attr(feature = "std", deny(unsafe_code))]
#![cfg_attr(not(feature = "std"), allow(unsafe_code))]

// When no_std, use alloc crate for collections
#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-export alloc types for internal use
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
pub(crate) mod stdlib {
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::vec;
    pub use alloc::format;
    pub use alloc::collections::{BTreeMap, BTreeSet, VecDeque, BinaryHeap};
}

#[cfg(feature = "std")]
#[allow(unused_imports)]
pub(crate) mod stdlib {
    pub use std::boxed::Box;
    pub use std::string::{String, ToString};
    pub use std::vec::Vec;
    pub use std::vec;
    pub use std::format;
    pub use std::collections::{BTreeMap, BTreeSet, VecDeque, BinaryHeap};
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

/// C FFI bindings for kernel integration
#[cfg(feature = "ffi")]
pub mod ffi;

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

// ============================================================================
// Kernel mode support (no_std)
// ============================================================================

/// Panic handler for kernel mode (no_std)
/// 
/// When building for kernel integration, this provides the required panic
/// handler. In a real kernel module, this would be replaced by linking
/// with the kernel's panic infrastructure.
#[cfg(all(not(feature = "std"), not(test), feature = "kernel"))]
mod panic_impl {
    use core::panic::PanicInfo;

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        // In kernel mode, we should never panic
        // If we do, halt the CPU or trigger a kernel panic
        loop {
            // Spin forever - the kernel will handle this
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Kernel mode stubs for Rust runtime requirements
// ============================================================================

/// EH personality stub - required even with panic=abort in some cases
#[cfg(all(not(feature = "std"), not(test), feature = "kernel"))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Unwind resume stub - required even with panic=abort
#[cfg(all(not(feature = "std"), not(test), feature = "kernel"))]
#[no_mangle]
pub extern "C" fn _Unwind_Resume(_: usize) -> ! {
    loop {}
}

// Note: Global allocator is defined in ffi.rs when ffi feature is enabled
