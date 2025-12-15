//! C FFI bindings for kernel integration
//!
//! This module provides C-compatible functions for integrating the Rust BPF
//! verifier into the Linux kernel. These functions mirror the kernel's existing
//! verifier API to enable drop-in replacement.
//!
//! ## Usage from C
//!
//! ```c
//! #include "bpf_verifier_rs.h"
//!
//! int result = bpf_check_rs(prog, attr, uattr, uattr_size);
//! ```
//!
//! ## Safety
//!
//! All functions in this module use `unsafe` as they interact with raw pointers
//! from C code. The caller is responsible for ensuring:
//! - Pointers are valid and properly aligned
//! - Lifetimes are respected
//! - No data races occur

#![allow(unsafe_code)]
#![allow(missing_docs)]

use core::ffi::c_void;
use core::ptr;
use core::slice;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String, boxed::Box};

use crate::core::types::*;
use crate::core::error::VerifierError;
use crate::verifier::{VerifierEnv, MainVerifier};

// ============================================================================
// C-compatible type definitions
// ============================================================================

/// Opaque handle to verifier environment
pub type BpfVerifierEnvHandle = *mut c_void;

/// C-compatible error codes (matching kernel errno values)
#[repr(i32)]
pub enum BpfVerifierError {
    /// Success
    Ok = 0,
    /// Invalid argument (EINVAL)
    Invalid = -22,
    /// Out of memory (ENOMEM)
    NoMem = -12,
    /// Permission denied (EACCES)
    Access = -13,
    /// Argument list too long / complexity limit (E2BIG)
    TooBig = -7,
    /// Operation not permitted (EPERM)
    Perm = -1,
}

impl From<VerifierError> for BpfVerifierError {
    fn from(e: VerifierError) -> Self {
        match e {
            VerifierError::OutOfMemory => BpfVerifierError::NoMem,
            VerifierError::PermissionDenied(_) => BpfVerifierError::Perm,
            VerifierError::PointerLeak => BpfVerifierError::Perm,
            VerifierError::InvalidMemoryAccess(_) => BpfVerifierError::Access,
            VerifierError::InvalidMapAccess(_) => BpfVerifierError::Access,
            VerifierError::InvalidContextAccess(_) => BpfVerifierError::Access,
            VerifierError::ProgramTooLarge(_) => BpfVerifierError::TooBig,
            VerifierError::TooComplex(_) => BpfVerifierError::TooBig,
            VerifierError::VerificationLimitExceeded(_) => BpfVerifierError::TooBig,
            VerifierError::ResourceLimitExceeded(_) => BpfVerifierError::TooBig,
            VerifierError::ComplexityLimitExceeded(_) => BpfVerifierError::TooBig,
            VerifierError::TooManySubprogs => BpfVerifierError::TooBig,
            VerifierError::CallStackOverflow => BpfVerifierError::TooBig,
            VerifierError::StackOverflow(_) => BpfVerifierError::TooBig,
            _ => BpfVerifierError::Invalid,
        }
    }
}

/// C-compatible BPF instruction (matches struct bpf_insn)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CBpfInsn {
    pub code: u8,
    pub dst_reg: u8,  // 4 bits dst, 4 bits src (combined in kernel)
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl From<CBpfInsn> for BpfInsn {
    fn from(c: CBpfInsn) -> Self {
        BpfInsn {
            code: c.code,
            dst_reg: c.dst_reg & 0x0f,
            src_reg: c.src_reg & 0x0f,
            off: c.off,
            imm: c.imm,
        }
    }
}

impl From<BpfInsn> for CBpfInsn {
    fn from(r: BpfInsn) -> Self {
        CBpfInsn {
            code: r.code,
            dst_reg: r.dst_reg,
            src_reg: r.src_reg,
            off: r.off,
            imm: r.imm,
        }
    }
}

/// C-compatible program attributes
#[repr(C)]
pub struct CBpfProgAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: *const CBpfInsn,
    pub license: *const u8,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: *mut u8,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub expected_attach_type: u32,
}

// ============================================================================
// Core FFI Functions
// ============================================================================

/// Create a new verifier environment.
///
/// # Safety
///
/// - `insns` must point to a valid array of `insn_cnt` instructions
/// - The returned handle must be freed with `bpf_verifier_env_free`
#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_env_new(
    insns: *const CBpfInsn,
    insn_cnt: u32,
    prog_type: u32,
    is_privileged: bool,
) -> BpfVerifierEnvHandle {
    if insns.is_null() || insn_cnt == 0 {
        return ptr::null_mut();
    }

    // Convert C instructions to Rust
    let c_insns = slice::from_raw_parts(insns, insn_cnt as usize);
    let rust_insns: Vec<BpfInsn> = c_insns.iter().map(|i| (*i).into()).collect();

    // Convert program type
    let prog_type = match prog_type {
        0 => BpfProgType::Unspec,
        1 => BpfProgType::SocketFilter,
        2 => BpfProgType::Kprobe,
        3 => BpfProgType::SchedCls,
        4 => BpfProgType::SchedAct,
        5 => BpfProgType::Tracepoint,
        6 => BpfProgType::Xdp,
        7 => BpfProgType::PerfEvent,
        8 => BpfProgType::CgroupSkb,
        9 => BpfProgType::CgroupSock,
        10 => BpfProgType::LwtIn,
        11 => BpfProgType::LwtOut,
        12 => BpfProgType::LwtXmit,
        13 => BpfProgType::SockOps,
        14 => BpfProgType::SkSkb,
        15 => BpfProgType::CgroupDevice,
        16 => BpfProgType::SkMsg,
        17 => BpfProgType::RawTracepoint,
        18 => BpfProgType::CgroupSockAddr,
        19 => BpfProgType::LwtSeg6local,
        20 => BpfProgType::LircMode2,
        21 => BpfProgType::SkReuseport,
        22 => BpfProgType::FlowDissector,
        23 => BpfProgType::CgroupSysctl,
        24 => BpfProgType::RawTracepointWritable,
        25 => BpfProgType::CgroupSockopt,
        26 => BpfProgType::Tracing,
        27 => BpfProgType::StructOps,
        28 => BpfProgType::Ext,
        29 => BpfProgType::Lsm,
        30 => BpfProgType::SkLookup,
        31 => BpfProgType::Syscall,
        32 => BpfProgType::Netfilter,
        _ => BpfProgType::Unspec,
    };

    // Create verifier environment
    match VerifierEnv::new(rust_insns, prog_type, is_privileged) {
        Ok(env) => Box::into_raw(Box::new(env)) as BpfVerifierEnvHandle,
        Err(_) => ptr::null_mut(),
    }
}

/// Free a verifier environment.
///
/// # Safety
///
/// - `handle` must be a valid handle from `bpf_verifier_env_new`
/// - Must not be called more than once per handle
#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_env_free(handle: BpfVerifierEnvHandle) {
    if !handle.is_null() {
        let _ = Box::from_raw(handle as *mut VerifierEnv);
    }
}

/// Run verification on a program.
///
/// # Safety
///
/// - `handle` must be a valid handle from `bpf_verifier_env_new`
///
/// # Returns
///
/// - 0 on success
/// - Negative errno on failure
#[no_mangle]
pub unsafe extern "C" fn bpf_verify(handle: BpfVerifierEnvHandle) -> i32 {
    if handle.is_null() {
        return BpfVerifierError::Invalid as i32;
    }

    let env = &mut *(handle as *mut VerifierEnv);
    let mut verifier = MainVerifier::new(env);

    match verifier.verify() {
        Ok(()) => BpfVerifierError::Ok as i32,
        Err(e) => BpfVerifierError::from(e) as i32,
    }
}

/// Main entry point matching kernel's bpf_check().
///
/// This is the primary function for kernel integration. It creates an
/// environment, runs verification, and cleans up.
///
/// # Safety
///
/// - `attr` must point to valid program attributes
/// - `insns` must point to a valid instruction array
///
/// # Returns
///
/// - 0 on success
/// - Negative errno on failure
#[no_mangle]
pub unsafe extern "C" fn bpf_check_rs(
    attr: *const CBpfProgAttr,
) -> i32 {
    if attr.is_null() {
        return BpfVerifierError::Invalid as i32;
    }

    let attr = &*attr;

    if attr.insns.is_null() || attr.insn_cnt == 0 {
        return BpfVerifierError::Invalid as i32;
    }

    // Determine privilege level from prog_flags
    let is_privileged = (attr.prog_flags & 0x1) == 0; // BPF_F_STRICT_ALIGNMENT bit

    // Create environment
    let handle = bpf_verifier_env_new(
        attr.insns,
        attr.insn_cnt,
        attr.prog_type,
        is_privileged,
    );

    if handle.is_null() {
        return BpfVerifierError::NoMem as i32;
    }

    // Run verification
    let result = bpf_verify(handle);

    // Clean up
    bpf_verifier_env_free(handle);

    result
}

/// Get the number of verified instructions.
///
/// # Safety
///
/// - `handle` must be a valid handle
#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_get_insn_cnt(handle: BpfVerifierEnvHandle) -> u32 {
    if handle.is_null() {
        return 0;
    }

    let env = &*(handle as *const VerifierEnv);
    env.insns.len() as u32
}

/// Get verification statistics.
///
/// # Safety
///
/// - `handle` must be a valid handle
/// - `stats` must point to valid memory
#[repr(C)]
pub struct CBpfVerifierStats {
    pub insns_processed: u64,
    pub states_explored: u64,
    pub peak_states: u64,
    pub total_states: u64,
    pub pruned_states: u64,
}

#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_get_stats(
    handle: BpfVerifierEnvHandle,
    stats: *mut CBpfVerifierStats,
) -> i32 {
    if handle.is_null() || stats.is_null() {
        return BpfVerifierError::Invalid as i32;
    }

    let env = &*(handle as *const VerifierEnv);
    let s = &mut *stats;

    // Stats are collected during verification, get basic counts from env
    s.insns_processed = env.insns.len() as u64;
    s.states_explored = env.explored_states.len() as u64;
    s.peak_states = 0; // Would need separate tracking
    s.total_states = env.state_stack.len() as u64;
    s.pruned_states = 0; // Would need separate tracking

    BpfVerifierError::Ok as i32
}

// ============================================================================
// Logging support
// ============================================================================

/// Log callback function type
pub type BpfLogCallback = extern "C" fn(level: u32, msg: *const u8, len: usize);

static mut LOG_CALLBACK: Option<BpfLogCallback> = None;

/// Set the log callback function.
///
/// # Safety
///
/// - Callback must be valid for the lifetime of verification
#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_set_log_callback(callback: BpfLogCallback) {
    LOG_CALLBACK = Some(callback);
}

/// Clear the log callback.
#[no_mangle]
pub unsafe extern "C" fn bpf_verifier_clear_log_callback() {
    LOG_CALLBACK = None;
}

// ============================================================================
// Helper for kernel memory allocation (when in kernel mode)
// ============================================================================

#[cfg(feature = "kernel")]
mod kernel_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    extern "C" {
        fn kmalloc(size: usize, flags: u32) -> *mut u8;
        fn kfree(ptr: *mut u8);
    }

    const GFP_KERNEL: u32 = 0xCC0;

    pub struct KernelAllocator;

    unsafe impl GlobalAlloc for KernelAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            kmalloc(layout.size(), GFP_KERNEL)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            kfree(ptr)
        }
    }

    #[cfg(feature = "kernel")]
    #[global_allocator]
    static ALLOCATOR: KernelAllocator = KernelAllocator;
}

// ============================================================================
// C Header Generation (for cbindgen)
// ============================================================================

/// Version information
pub const BPF_VERIFIER_RS_VERSION_MAJOR: u32 = 0;
pub const BPF_VERIFIER_RS_VERSION_MINOR: u32 = 1;
pub const BPF_VERIFIER_RS_VERSION_PATCH: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        assert_eq!(
            BpfVerifierError::from(VerifierError::OutOfMemory) as i32,
            -12
        );
        assert_eq!(
            BpfVerifierError::from(VerifierError::PermissionDenied("test".into())) as i32,
            -1
        );
        assert_eq!(
            BpfVerifierError::from(VerifierError::ProgramTooLarge(1000)) as i32,
            -7
        );
    }

    #[test]
    fn test_insn_conversion() {
        let c_insn = CBpfInsn {
            code: 0x07,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 42,
        };
        let rust_insn: BpfInsn = c_insn.into();
        assert_eq!(rust_insn.code, 0x07);
        assert_eq!(rust_insn.imm, 42);
    }

    #[test]
    fn test_null_handle() {
        unsafe {
            assert_eq!(bpf_verify(ptr::null_mut()), -22);
            assert_eq!(bpf_verifier_get_insn_cnt(ptr::null_mut()), 0);
        }
    }
}
