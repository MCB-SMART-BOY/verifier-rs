// SPDX-License-Identifier: GPL-2.0

//! Bridge between kernel C structures and Rust verifier.
//!
//! This module provides safe Rust wrappers around the kernel's BPF
//! data structures, allowing the Rust verifier to interact with
//! kernel code safely.

use crate::core::types::{BpfInsn, BpfProgType};
use crate::check::prog_type::BpfAttachType;
use crate::kernel::bindings::{
    self, bpf_insn, bpf_prog, bpf_prog_type, bpf_attach_type,
    bpf_verifier_env, bpf_map,
};
use crate::kernel::error::{KernelError, KernelResult};
use crate::stdlib::{Vec, Box};
use crate::verifier::VerifierEnv;

// ============================================================================
// Program Wrapper
// ============================================================================

/// Safe wrapper around kernel bpf_prog structure.
pub struct KernelProgram<'a> {
    /// Reference to the kernel program structure
    prog: &'a bpf_prog,
    /// Cached instructions (converted to Rust format)
    insns_cache: Option<Vec<BpfInsn>>,
}

impl<'a> KernelProgram<'a> {
    /// Create a new wrapper from a kernel program pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the pointer is valid for the lifetime 'a.
    pub unsafe fn from_ptr(ptr: *const bpf_prog) -> KernelResult<Self> {
        if ptr.is_null() {
            return Err(KernelError::EINVAL);
        }
        // SAFETY: Caller guarantees ptr is valid for lifetime 'a. We verified
        // the pointer is non-null above. The reference is tied to the lifetime
        // parameter, ensuring it does not outlive the underlying data.
        Ok(Self {
            prog: &*ptr,
            insns_cache: None,
        })
    }

    /// Get the program type.
    pub fn prog_type(&self) -> BpfProgType {
        convert_prog_type(self.prog.prog_type)
    }

    /// Get the expected attach type.
    pub fn attach_type(&self) -> BpfAttachType {
        convert_attach_type(self.prog.expected_attach_type)
    }

    /// Get the number of instructions.
    pub fn len(&self) -> usize {
        self.prog.len as usize
    }

    /// Check if the program is empty.
    pub fn is_empty(&self) -> bool {
        self.prog.len == 0
    }

    /// Get instructions as Rust BpfInsn slice.
    pub fn instructions(&mut self) -> KernelResult<&[BpfInsn]> {
        if self.insns_cache.is_none() {
            let insns = self.convert_instructions()?;
            self.insns_cache = Some(insns);
        }
        // SAFETY: We just set insns_cache to Some above if it was None,
        // so it is guaranteed to be Some at this point.
        debug_assert!(self.insns_cache.is_some(), "insns_cache should be initialized");
        match self.insns_cache.as_ref() {
            Some(cache) => Ok(cache),
            // This branch is unreachable due to the logic above,
            // but we handle it gracefully instead of panicking.
            None => Err(KernelError::EINVAL),
        }
    }

    /// Convert kernel instructions to Rust format.
    fn convert_instructions(&self) -> KernelResult<Vec<BpfInsn>> {
        if self.prog.insns.is_null() {
            return Err(KernelError::EINVAL);
        }

        let len = self.prog.len as usize;
        let mut result = Vec::with_capacity(len);

        // SAFETY: The pointer was validated non-null above, and `len` is obtained
        // from the kernel's bpf_prog structure which guarantees it matches the
        // actual instruction count. The resulting slice lifetime is bounded by
        // the borrow of `self.prog`.
        unsafe {
            let insns = core::slice::from_raw_parts(self.prog.insns, len);
            for insn in insns {
                result.push(convert_insn(insn));
            }
        }

        Ok(result)
    }
}

// ============================================================================
// Verifier Environment Wrapper
// ============================================================================

/// Safe wrapper around kernel bpf_verifier_env structure.
pub struct KernelVerifierEnv<'a> {
    /// Reference to the kernel environment
    env: &'a mut bpf_verifier_env,
    /// Cached program wrapper
    prog: Option<KernelProgram<'a>>,
}

impl<'a> KernelVerifierEnv<'a> {
    /// Create a new wrapper from a kernel environment pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the pointer is valid for the lifetime 'a
    /// and that the environment is properly initialized.
    pub unsafe fn from_ptr(ptr: *mut bpf_verifier_env) -> KernelResult<Self> {
        if ptr.is_null() {
            return Err(KernelError::EINVAL);
        }

        // SAFETY: Caller guarantees ptr is valid and properly initialized for
        // lifetime 'a. We verified non-null above. The mutable reference is
        // exclusive for the lifetime parameter.
        let env = &mut *ptr;

        // Validate the program pointer
        if env.prog.is_null() {
            return Err(KernelError::EINVAL);
        }

        Ok(Self { env, prog: None })
    }

    /// Get the program being verified.
    pub fn program(&mut self) -> KernelResult<&mut KernelProgram<'a>> {
        if self.prog.is_none() {
            // SAFETY: The `self.env.prog` pointer was validated non-null in `from_ptr`.
            // The lifetime of the created `KernelProgram` is bounded by `self`.
            let prog = unsafe { KernelProgram::from_ptr(self.env.prog)? };
            // Note: This transmute is needed due to lifetime complexity
            // In real kernel code, this would be handled differently
            self.prog = Some(prog);
        }
        // SAFETY: We just set prog to Some above if it was None,
        // so it is guaranteed to be Some at this point.
        debug_assert!(self.prog.is_some(), "prog should be initialized");
        match self.prog.as_mut() {
            Some(prog) => Ok(prog),
            // This branch is unreachable due to the logic above,
            // but we handle it gracefully instead of panicking.
            None => Err(KernelError::EINVAL),
        }
    }

    /// Check if the program is privileged.
    pub fn is_privileged(&self) -> bool {
        self.env.allow_ptr_leaks || self.env.bpf_capable
    }

    /// Check if speculative execution mitigations can be bypassed.
    pub fn can_bypass_spec_v1(&self) -> bool {
        self.env.bypass_spec_v1
    }

    /// Check if speculative store bypass mitigations can be bypassed.
    pub fn can_bypass_spec_v4(&self) -> bool {
        self.env.bypass_spec_v4
    }

    /// Get the number of subprograms.
    pub fn subprog_count(&self) -> usize {
        self.env.subprog_cnt as usize
    }

    /// Log a message through the kernel's verifier log.
    pub fn log(&mut self, msg: &str) {
        // In real kernel, this would call bpf_verifier_log_write
        // For now, we just track that logging was requested
        let _ = msg;
    }

    /// Mark that instructions have been processed.
    pub fn add_insns_processed(&mut self, count: u32) {
        self.env.insn_processed = self.env.insn_processed.saturating_add(count);
    }

    /// Get total instructions processed.
    pub fn insns_processed(&self) -> u32 {
        self.env.insn_processed
    }

    /// Create a Rust VerifierEnv from this kernel environment.
    pub fn to_rust_env(&mut self) -> KernelResult<Box<VerifierEnv>> {
        // Get is_privileged first before mutable borrow of program
        let is_privileged = self.is_privileged();
        
        let prog = self.program()?;
        let insns_owned = prog.convert_instructions()?;
        let prog_type = prog.prog_type();
        
        let env = VerifierEnv::new(
            insns_owned,
            prog_type,
            is_privileged,
        ).map_err(|_| KernelError::EINVAL)?;

        Ok(Box::new(env))
    }
}

// ============================================================================
// Map Wrapper
// ============================================================================

/// Safe wrapper around kernel bpf_map structure.
pub struct KernelMap<'a> {
    map: &'a bpf_map,
}

impl<'a> KernelMap<'a> {
    /// Create from a kernel map pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the pointer is valid.
    pub unsafe fn from_ptr(ptr: *const bpf_map) -> KernelResult<Self> {
        if ptr.is_null() {
            return Err(KernelError::EINVAL);
        }
        // SAFETY: Caller guarantees ptr is valid. We verified non-null above.
        // The reference lifetime is tied to the struct lifetime parameter.
        Ok(Self { map: &*ptr })
    }

    /// Get the map type.
    pub fn map_type(&self) -> bindings::bpf_map_type {
        self.map.map_type
    }

    /// Get the key size.
    pub fn key_size(&self) -> u32 {
        self.map.key_size
    }

    /// Get the value size.
    pub fn value_size(&self) -> u32 {
        self.map.value_size
    }

    /// Get the maximum entries.
    pub fn max_entries(&self) -> u32 {
        self.map.max_entries
    }

    /// Get map flags.
    pub fn flags(&self) -> u32 {
        self.map.map_flags
    }

    /// Get spin lock offset (-1 if none).
    pub fn spin_lock_off(&self) -> i32 {
        self.map.spin_lock_off
    }

    /// Get timer offset (-1 if none).
    pub fn timer_off(&self) -> i32 {
        self.map.timer_off
    }
}

// ============================================================================
// Type Conversions
// ============================================================================

/// Convert kernel bpf_insn to Rust BpfInsn.
fn convert_insn(insn: &bpf_insn) -> BpfInsn {
    BpfInsn {
        code: insn.code,
        dst_reg: insn.dst_reg(),
        src_reg: insn.src_reg(),
        off: insn.off,
        imm: insn.imm,
    }
}

/// Convert kernel bpf_prog_type to Rust BpfProgType.
fn convert_prog_type(pt: bpf_prog_type) -> BpfProgType {
    match pt {
        bpf_prog_type::BPF_PROG_TYPE_UNSPEC => BpfProgType::Unspec,
        bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER => BpfProgType::SocketFilter,
        bpf_prog_type::BPF_PROG_TYPE_KPROBE => BpfProgType::Kprobe,
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS => BpfProgType::SchedCls,
        bpf_prog_type::BPF_PROG_TYPE_SCHED_ACT => BpfProgType::SchedAct,
        bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT => BpfProgType::Tracepoint,
        bpf_prog_type::BPF_PROG_TYPE_XDP => BpfProgType::Xdp,
        bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT => BpfProgType::PerfEvent,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB => BpfProgType::CgroupSkb,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK => BpfProgType::CgroupSock,
        bpf_prog_type::BPF_PROG_TYPE_LWT_IN => BpfProgType::LwtIn,
        bpf_prog_type::BPF_PROG_TYPE_LWT_OUT => BpfProgType::LwtOut,
        bpf_prog_type::BPF_PROG_TYPE_LWT_XMIT => BpfProgType::LwtXmit,
        bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS => BpfProgType::SockOps,
        bpf_prog_type::BPF_PROG_TYPE_SK_SKB => BpfProgType::SkSkb,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE => BpfProgType::CgroupDevice,
        bpf_prog_type::BPF_PROG_TYPE_SK_MSG => BpfProgType::SkMsg,
        bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT => BpfProgType::RawTracepoint,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR => BpfProgType::CgroupSockAddr,
        bpf_prog_type::BPF_PROG_TYPE_LWT_SEG6LOCAL => BpfProgType::LwtSeg6local,
        bpf_prog_type::BPF_PROG_TYPE_LIRC_MODE2 => BpfProgType::LircMode2,
        bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT => BpfProgType::SkReuseport,
        bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR => BpfProgType::FlowDissector,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL => BpfProgType::CgroupSysctl,
        bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE => BpfProgType::RawTracepointWritable,
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT => BpfProgType::CgroupSockopt,
        bpf_prog_type::BPF_PROG_TYPE_TRACING => BpfProgType::Tracing,
        bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS => BpfProgType::StructOps,
        bpf_prog_type::BPF_PROG_TYPE_EXT => BpfProgType::Ext,
        bpf_prog_type::BPF_PROG_TYPE_LSM => BpfProgType::Lsm,
        bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP => BpfProgType::SkLookup,
        bpf_prog_type::BPF_PROG_TYPE_SYSCALL => BpfProgType::Syscall,
        bpf_prog_type::BPF_PROG_TYPE_NETFILTER => BpfProgType::Netfilter,
    }
}

/// Convert kernel bpf_attach_type to Rust BpfAttachType.
fn convert_attach_type(at: bpf_attach_type) -> BpfAttachType {
    // For now, map to None for unhandled types
    // A complete implementation would map all attach types
    match at {
        bpf_attach_type::BPF_CGROUP_INET_INGRESS => BpfAttachType::CgroupInetIngress,
        bpf_attach_type::BPF_CGROUP_INET_EGRESS => BpfAttachType::CgroupInetEgress,
        bpf_attach_type::BPF_XDP => BpfAttachType::Xdp,
        // Default to CgroupInetIngress for unhandled types
        // A complete implementation would map all attach types
        _ => BpfAttachType::CgroupInetIngress,
    }
}

// ============================================================================
// Entry Point for Kernel
// ============================================================================

/// Main entry point called from kernel C code.
///
/// This function is the interface between the kernel's bpf_check()
/// and the Rust verifier.
///
/// # Safety
///
/// This function is called from C code with a valid bpf_verifier_env pointer.
/// The pointer must remain valid for the duration of verification.
///
/// # Returns
///
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub unsafe extern "C" fn rust_bpf_verify(env: *mut bpf_verifier_env) -> i32 {
    match verify_program(env) {
        Ok(()) => 0,
        Err(e) => e.raw(),
    }
}

/// Internal verification function.
///
/// # Safety
///
/// Caller must provide a valid, properly initialized `bpf_verifier_env` pointer.
/// The pointer must remain valid for the duration of this function call.
unsafe fn verify_program(env_ptr: *mut bpf_verifier_env) -> KernelResult<()> {
    // SAFETY: Caller (rust_bpf_verify) guarantees env_ptr is valid.
    // KernelVerifierEnv::from_ptr performs additional validation.
    let mut kenv = KernelVerifierEnv::from_ptr(env_ptr)?;

    // Get is_privileged before mutable borrow of program
    let is_privileged = kenv.is_privileged();

    // Get the program
    let prog = kenv.program()?;
    let prog_type = prog.prog_type();
    
    // Get instructions
    let insns = prog.convert_instructions()?;

    // Create the Rust verifier environment
    let mut rust_env = VerifierEnv::new(insns, prog_type, is_privileged)
        .map_err(|_| KernelError::EINVAL)?;
    
    // Run the verifier
    let mut verifier = crate::verifier::MainVerifier::new(&mut rust_env);
    verifier.verify().map_err(KernelError::from)?;

    // Update kernel stats
    kenv.add_insns_processed(rust_env.insn_processed as u32);

    Ok(())
}
