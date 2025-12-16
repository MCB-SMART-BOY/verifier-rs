// SPDX-License-Identifier: GPL-2.0

//! Rust BPF Verifier kernel module.
//!
//! This module provides a Rust implementation of the BPF verifier
//! that can be used as an alternative to the C implementation.
//!
//! # Usage
//!
//! Enable `CONFIG_BPF_VERIFIER_RUST=y` in kernel config, then
//! control via sysctl:
//!
//! ```sh
//! # Enable Rust verifier
//! echo 1 > /proc/sys/kernel/bpf_rust_verifier
//! ```

use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ForeignOwnable;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    authors: ["BPF Verifier Contributors"],
    description: "Rust implementation of BPF verifier",
    license: "GPL",
}

/// Main module structure for Rust BPF verifier.
struct RustBpfVerifier {
    /// Whether the Rust verifier is enabled
    enabled: Arc<AtomicBool>,
}

use core::sync::atomic::{AtomicBool, Ordering};

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        pr_info!("Built for kernel {}\n", kernel::build_info::VERSION);

        let enabled = Arc::new(AtomicBool::new(false), GFP_KERNEL)?;

        // Register with BPF subsystem
        // Note: This requires kernel-side hooks in kernel/bpf/verifier.c
        // to call into our verification function

        Ok(RustBpfVerifier { enabled })
    }
}

impl Drop for RustBpfVerifier {
    fn drop(&mut self) {
        pr_info!("Rust BPF verifier unloaded\n");
    }
}

/// BPF verifier environment wrapper for kernel integration.
///
/// This provides the bridge between kernel's `bpf_verifier_env`
/// and our Rust verifier implementation.
pub struct KernelVerifierEnv {
    // Pointer to kernel's bpf_verifier_env
    // In production, this would hold the actual kernel pointer
    _marker: core::marker::PhantomData<()>,
}

impl KernelVerifierEnv {
    /// Create a new verifier environment from kernel pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure `env_ptr` is a valid pointer to `bpf_verifier_env`
    /// that remains valid for the lifetime of this struct.
    pub unsafe fn from_raw(_env_ptr: *mut core::ffi::c_void) -> Result<Self> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }
}

/// Entry point called from kernel BPF subsystem.
///
/// This function is registered as a callback in the kernel's BPF
/// verification path when `CONFIG_BPF_VERIFIER_RUST` is enabled.
///
/// # Safety
///
/// Called from C code with valid `bpf_verifier_env` pointer.
///
/// # Returns
///
/// - `0` on successful verification
/// - Negative errno on verification failure
#[no_mangle]
pub unsafe extern "C" fn rust_bpf_check(env: *mut core::ffi::c_void) -> core::ffi::c_int {
    match do_verify(env) {
        Ok(()) => 0,
        Err(e) => e.to_errno(),
    }
}

/// Internal verification function.
unsafe fn do_verify(env_ptr: *mut core::ffi::c_void) -> Result<()> {
    if env_ptr.is_null() {
        return Err(EINVAL);
    }

    // Create safe wrapper around kernel environment
    let _kenv = KernelVerifierEnv::from_raw(env_ptr)?;

    // TODO: Extract program from kernel environment
    // TODO: Run Rust verifier
    // TODO: Report results back to kernel

    // For now, fall through to C verifier
    Err(ENOSYS)
}
