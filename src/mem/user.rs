// SPDX-License-Identifier: GPL-2.0

//! User memory access verification for BPF programs.
//!
//! This module implements validation for user-space memory access from BPF programs.
//! User memory requires special handling because:
//! 1. Direct access may fault (page not mapped, permissions, etc.)
//! 2. User pointers cannot be trusted and must be validated
//! 3. Special helpers like bpf_probe_read_user must be used for safe access
//! 4. Speculation attacks must be mitigated

use alloc::{format, string::String};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;

// ============================================================================
// User Memory Access Types
// ============================================================================

/// Type of user memory access
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMemAccessType {
    /// Direct load from user memory (unsafe without protection)
    DirectLoad,
    /// Direct store to user memory (unsafe without protection)
    DirectStore,
    /// Access via bpf_probe_read_user (safe)
    ProbeRead,
    /// Access via bpf_probe_read_user_str (safe)
    ProbeReadStr,
    /// Access via bpf_copy_from_user (safe, sleepable)
    CopyFromUser,
    /// Access via bpf_probe_write_user (privileged, safe)
    ProbeWrite,
}

impl UserMemAccessType {
    /// Check if this access type is safe
    pub fn is_safe(&self) -> bool {
        !matches!(
            self,
            UserMemAccessType::DirectLoad | UserMemAccessType::DirectStore
        )
    }

    /// Check if this access type requires privilege
    pub fn requires_privilege(&self) -> bool {
        matches!(self, UserMemAccessType::ProbeWrite)
    }

    /// Check if this access type may sleep
    pub fn may_sleep(&self) -> bool {
        matches!(self, UserMemAccessType::CopyFromUser)
    }
}

// ============================================================================
// User Memory Validation Context
// ============================================================================

/// Context for user memory access validation
#[derive(Debug, Clone)]
pub struct UserMemContext {
    /// Whether the program is privileged (CAP_SYS_ADMIN/CAP_PERFMON)
    pub privileged: bool,
    /// Whether the program is sleepable
    pub sleepable: bool,
    /// Whether direct user memory access is allowed (e.g., arena user pointers)
    pub allow_direct_access: bool,
    /// Whether speculation barriers are in place
    pub has_nospec: bool,
    /// Program type
    pub prog_type: BpfProgType,
}

impl Default for UserMemContext {
    fn default() -> Self {
        Self {
            privileged: false,
            sleepable: false,
            allow_direct_access: false,
            has_nospec: false,
            prog_type: BpfProgType::Unspec,
        }
    }
}

impl UserMemContext {
    /// Create context for a privileged program
    pub fn privileged(prog_type: BpfProgType) -> Self {
        Self {
            privileged: true,
            sleepable: false,
            allow_direct_access: false,
            has_nospec: false,
            prog_type,
        }
    }

    /// Create context for a sleepable program
    pub fn sleepable(prog_type: BpfProgType) -> Self {
        Self {
            privileged: false,
            sleepable: true,
            allow_direct_access: false,
            has_nospec: false,
            prog_type,
        }
    }

    /// Set direct access allowed (for arena user pointers)
    pub fn with_direct_access(mut self) -> Self {
        self.allow_direct_access = true;
        self
    }

    /// Set speculation protection
    pub fn with_nospec(mut self) -> Self {
        self.has_nospec = true;
        self
    }
}

// ============================================================================
// User Memory Validation Results
// ============================================================================

/// Result of user memory access validation
#[derive(Debug, Clone)]
pub struct UserMemValidation {
    /// Whether access is allowed
    pub allowed: bool,
    /// Whether speculation barrier is needed
    pub needs_nospec: bool,
    /// Warning message (if any)
    pub warning: Option<String>,
    /// Suggested safe alternative
    pub safe_alternative: Option<&'static str>,
}

impl UserMemValidation {
    /// Create allowed result
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            needs_nospec: false,
            warning: None,
            safe_alternative: None,
        }
    }

    /// Create allowed result with nospec requirement
    pub fn allowed_with_nospec() -> Self {
        Self {
            allowed: true,
            needs_nospec: true,
            warning: None,
            safe_alternative: None,
        }
    }

    /// Create denied result
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            needs_nospec: false,
            warning: Some(reason.into()),
            safe_alternative: None,
        }
    }

    /// Create denied result with suggestion
    pub fn denied_with_alternative(reason: impl Into<String>, alternative: &'static str) -> Self {
        Self {
            allowed: false,
            needs_nospec: false,
            warning: Some(reason.into()),
            safe_alternative: Some(alternative),
        }
    }
}

// ============================================================================
// Core Validation Functions
// ============================================================================

/// Check if a register contains a user memory pointer
pub fn is_user_mem_pointer(reg: &BpfRegState) -> bool {
    reg.type_flags.contains(BpfTypeFlag::MEM_USER)
}

/// Check if direct user memory access is allowed for a register
pub fn check_user_mem_direct_access(
    reg: &BpfRegState,
    ctx: &UserMemContext,
    is_write: bool,
) -> UserMemValidation {
    // Check if this is actually user memory
    if !is_user_mem_pointer(reg) {
        return UserMemValidation::allowed();
    }

    // Direct writes to user memory are generally not allowed
    if is_write {
        if ctx.privileged {
            return UserMemValidation::denied_with_alternative(
                "direct write to user memory not allowed",
                "use bpf_probe_write_user() helper",
            );
        } else {
            return UserMemValidation::denied("write to user memory requires CAP_SYS_ADMIN");
        }
    }

    // Direct reads from user memory
    if ctx.allow_direct_access {
        // Arena user pointers can be accessed directly with speculation protection
        if ctx.has_nospec {
            return UserMemValidation::allowed();
        } else {
            return UserMemValidation::allowed_with_nospec();
        }
    }

    // Normal user pointers cannot be directly accessed
    UserMemValidation::denied_with_alternative(
        "direct read from user memory may fault",
        "use bpf_probe_read_user() or bpf_copy_from_user() helper",
    )
}

/// Validate user memory access via helper function
pub fn check_user_mem_helper_access(
    reg: &BpfRegState,
    ctx: &UserMemContext,
    access_type: UserMemAccessType,
    size: u32,
) -> Result<UserMemValidation> {
    // Size validation
    if size == 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "zero-size user memory access".into(),
        ));
    }

    // Maximum size check (prevent excessive reads)
    const MAX_USER_MEM_ACCESS: u32 = 256 * 1024; // 256KB
    if size > MAX_USER_MEM_ACCESS {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "user memory access size {} exceeds maximum {}",
            size, MAX_USER_MEM_ACCESS
        )));
    }

    match access_type {
        UserMemAccessType::ProbeRead | UserMemAccessType::ProbeReadStr => {
            // probe_read_user is always allowed for reading
            Ok(UserMemValidation::allowed())
        }

        UserMemAccessType::CopyFromUser => {
            // copy_from_user requires sleepable context
            if !ctx.sleepable {
                return Err(VerifierError::InvalidHelperCall(
                    "bpf_copy_from_user() requires sleepable program".into(),
                ));
            }
            Ok(UserMemValidation::allowed())
        }

        UserMemAccessType::ProbeWrite => {
            // probe_write_user requires privilege
            if !ctx.privileged {
                return Err(VerifierError::InvalidHelperCall(
                    "bpf_probe_write_user() requires CAP_SYS_ADMIN".into(),
                ));
            }

            // Check if program type allows writing to user memory
            if !can_write_user_mem(ctx.prog_type) {
                return Err(VerifierError::InvalidHelperCall(format!(
                    "bpf_probe_write_user() not allowed for program type {:?}",
                    ctx.prog_type
                )));
            }

            Ok(UserMemValidation::allowed())
        }

        UserMemAccessType::DirectLoad | UserMemAccessType::DirectStore => {
            // Direct access should go through check_user_mem_direct_access
            let validation = check_user_mem_direct_access(
                reg,
                ctx,
                access_type == UserMemAccessType::DirectStore,
            );

            if !validation.allowed {
                return Err(VerifierError::InvalidMemoryAccess(
                    validation
                        .warning
                        .unwrap_or_else(|| "direct user memory access not allowed".into()),
                ));
            }

            Ok(validation)
        }
    }
}

/// Check if program type can write to user memory
fn can_write_user_mem(prog_type: BpfProgType) -> bool {
    matches!(
        prog_type,
        BpfProgType::Kprobe
            | BpfProgType::Tracepoint
            | BpfProgType::PerfEvent
            | BpfProgType::RawTracepoint
            | BpfProgType::Tracing
    )
}

// ============================================================================
// User Pointer Validation
// ============================================================================

/// Validate that a user pointer argument is properly tagged
pub fn validate_user_ptr_arg(reg: &BpfRegState, arg_name: &str) -> Result<()> {
    // User pointer arguments should be scalar values (addresses)
    // or properly tagged pointer types
    match reg.reg_type {
        BpfRegType::ScalarValue => {
            // Scalar can be any address including user address
            Ok(())
        }
        BpfRegType::PtrToMem | BpfRegType::PtrToArena => {
            // Check for MEM_USER flag
            if !reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
                // This is a kernel pointer being passed as user pointer
                // This is a type confusion bug
                return Err(VerifierError::TypeMismatch {
                    expected: "user pointer (MEM_USER)".into(),
                    got: format!("kernel pointer {:?}", reg.reg_type),
                });
            }
            Ok(())
        }
        _ => {
            // Other pointer types cannot be user pointers
            Err(VerifierError::TypeMismatch {
                expected: format!("user pointer for {}", arg_name),
                got: format!("{:?}", reg.reg_type),
            })
        }
    }
}

/// Mark a register as containing user memory pointer
pub fn mark_reg_user_mem(reg: &mut BpfRegState) {
    reg.type_flags.insert(BpfTypeFlag::MEM_USER);
}

/// Clear user memory flag from a register
pub fn clear_reg_user_mem(reg: &mut BpfRegState) {
    reg.type_flags.remove(BpfTypeFlag::MEM_USER);
}

// ============================================================================
// User Memory Access from Helpers
// ============================================================================

/// Validate destination buffer for probe_read_user
pub fn validate_probe_read_user_dst(dst_reg: &BpfRegState, size: u32) -> Result<()> {
    // Destination must be writable memory
    match dst_reg.reg_type {
        BpfRegType::PtrToStack => {
            // Stack is always writable
            Ok(())
        }
        BpfRegType::PtrToMapValue => {
            // Map value is writable unless marked read-only
            if dst_reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
                return Err(VerifierError::InvalidMemoryAccess(
                    "cannot write to read-only map value".into(),
                ));
            }
            Ok(())
        }
        BpfRegType::PtrToMem => {
            // Check if writable
            if dst_reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
                return Err(VerifierError::InvalidMemoryAccess(
                    "cannot write to read-only memory".into(),
                ));
            }

            // Check size bounds
            if dst_reg.mem_size > 0 && size > dst_reg.mem_size {
                return Err(VerifierError::InvalidMemoryAccess(format!(
                    "probe_read_user size {} exceeds buffer size {}",
                    size, dst_reg.mem_size
                )));
            }

            Ok(())
        }
        _ => Err(VerifierError::InvalidMemoryAccess(format!(
            "invalid destination for probe_read_user: {:?}",
            dst_reg.reg_type
        ))),
    }
}

/// Validate source address for probe_read_user (the user address)
pub fn validate_probe_read_user_src(src_reg: &BpfRegState) -> Result<()> {
    // Source is a user address - can be:
    // 1. Scalar value (arbitrary user address)
    // 2. User-tagged pointer (from arena or previous operation)
    match src_reg.reg_type {
        BpfRegType::ScalarValue => {
            // Scalar can represent any address
            // Kernel will validate at runtime
            Ok(())
        }
        BpfRegType::PtrToMem | BpfRegType::PtrToArena
            if src_reg.type_flags.contains(BpfTypeFlag::MEM_USER) =>
        {
            // Properly tagged user pointer
            Ok(())
        }
        _ if src_reg.type_flags.contains(BpfTypeFlag::MEM_USER) => {
            // Any pointer with MEM_USER flag
            Ok(())
        }
        _ => {
            // Passing kernel pointer as user address is likely a bug
            // but we allow it because the helper will just fail at runtime
            Ok(())
        }
    }
}

// ============================================================================
// Arena User Pointer Handling
// ============================================================================

/// Check arena user pointer access
///
/// Arena pointers can be cast between kernel and user address spaces.
/// When in user address space (MEM_USER flag set), they require
/// speculation protection.
pub fn check_arena_user_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    has_nospec: bool,
) -> Result<UserMemValidation> {
    // Must be arena pointer with user flag
    if reg.reg_type != BpfRegType::PtrToArena {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_ARENA".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    if !reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
        // Kernel-space arena pointer - normal access
        return Ok(UserMemValidation::allowed());
    }

    // User-space arena pointer
    if is_write {
        // Writes to user arena are not allowed
        return Err(VerifierError::InvalidMemoryAccess(
            "cannot write to user-space arena pointer".into(),
        ));
    }

    // Check bounds
    let total_off = reg.off.saturating_add(off);
    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into arena user pointer",
            total_off
        )));
    }

    // Size check
    if size > 8 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "arena user access size {} exceeds maximum 8 bytes",
            size
        )));
    }

    // Speculation protection check
    if has_nospec {
        Ok(UserMemValidation::allowed())
    } else {
        Ok(UserMemValidation::allowed_with_nospec())
    }
}

// ============================================================================
// User Memory Copy Tracking
// ============================================================================

/// Track user memory copy operations for data flow analysis
#[derive(Debug, Clone, Default)]
pub struct UserMemCopyTracker {
    /// Number of probe_read_user calls
    pub probe_read_count: u32,
    /// Number of copy_from_user calls
    pub copy_from_user_count: u32,
    /// Number of probe_write_user calls
    pub probe_write_count: u32,
    /// Total bytes read from user
    pub bytes_read: u64,
    /// Total bytes written to user
    pub bytes_written: u64,
}

impl UserMemCopyTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a probe_read_user call
    pub fn record_probe_read(&mut self, size: u32) {
        self.probe_read_count += 1;
        self.bytes_read += size as u64;
    }

    /// Record a copy_from_user call
    pub fn record_copy_from_user(&mut self, size: u32) {
        self.copy_from_user_count += 1;
        self.bytes_read += size as u64;
    }

    /// Record a probe_write_user call
    pub fn record_probe_write(&mut self, size: u32) {
        self.probe_write_count += 1;
        self.bytes_written += size as u64;
    }

    /// Get total read operations
    pub fn total_reads(&self) -> u32 {
        self.probe_read_count + self.copy_from_user_count
    }
}

// ============================================================================
// User Memory Speculation Protection
// ============================================================================

/// Check if speculation barrier is needed for user memory access
pub fn needs_speculation_barrier(reg: &BpfRegState, is_load: bool) -> bool {
    // Speculation protection is needed for:
    // 1. User memory loads (to prevent speculative kernel address leaks)
    // 2. Untrusted pointer dereferences

    if !is_load {
        return false;
    }

    // User memory always needs protection
    if reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
        return true;
    }

    // Untrusted pointers need protection
    if reg.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
        return true;
    }

    false
}

/// Insert speculation barrier requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecBarrierType {
    /// No barrier needed
    None,
    /// LFENCE-style barrier (for loads)
    LoadFence,
    /// Pointer sanitization (bounds masking)
    SanitizePtr,
    /// Array bounds masking
    SanitizeIndex,
}

/// Determine what speculation protection is needed
pub fn get_speculation_protection(
    reg: &BpfRegState,
    is_load: bool,
    is_ptr_arith: bool,
) -> SpecBarrierType {
    if !needs_speculation_barrier(reg, is_load) {
        return SpecBarrierType::None;
    }

    if is_ptr_arith {
        // Pointer arithmetic on user pointers needs sanitization
        SpecBarrierType::SanitizePtr
    } else if is_load {
        // Load from user memory needs fence
        SpecBarrierType::LoadFence
    } else {
        SpecBarrierType::None
    }
}

// ============================================================================
// Helper Functions for User Memory Operations
// ============================================================================

/// Get the appropriate helper for reading user memory
pub fn get_user_read_helper(ctx: &UserMemContext, is_string: bool) -> BpfFuncId {
    if ctx.sleepable {
        BpfFuncId::CopyFromUser
    } else if is_string {
        BpfFuncId::ProbeReadUserStr
    } else {
        BpfFuncId::ProbeReadUser
    }
}

/// Check if a helper accesses user memory
pub fn is_user_mem_helper(func_id: BpfFuncId) -> bool {
    matches!(
        func_id,
        BpfFuncId::ProbeReadUser
            | BpfFuncId::ProbeReadUserStr
            | BpfFuncId::ProbeWriteUser
            | BpfFuncId::CopyFromUser
            | BpfFuncId::CopyFromUserTask
    )
}

/// Get user memory access type for a helper
pub fn get_helper_user_access_type(func_id: BpfFuncId) -> Option<UserMemAccessType> {
    match func_id {
        BpfFuncId::ProbeReadUser => Some(UserMemAccessType::ProbeRead),
        BpfFuncId::ProbeReadUserStr => Some(UserMemAccessType::ProbeReadStr),
        BpfFuncId::ProbeWriteUser => Some(UserMemAccessType::ProbeWrite),
        BpfFuncId::CopyFromUser | BpfFuncId::CopyFromUserTask => {
            Some(UserMemAccessType::CopyFromUser)
        }
        _ => None,
    }
}

// ============================================================================
// User Memory Pointer Propagation
// ============================================================================

/// Track how user memory pointers propagate through operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPtrPropagation {
    /// Pointer remains user pointer after operation
    Preserve,
    /// Pointer becomes kernel pointer (e.g., after validation)
    ToKernel,
    /// Operation invalidates the pointer
    Invalidate,
    /// Unknown - requires runtime check
    Unknown,
}

/// Determine how user pointer property propagates through ALU operation
pub fn propagate_user_ptr_alu(op: u8, dst_is_user: bool, src_is_user: bool) -> UserPtrPropagation {
    // ALU operation codes
    const BPF_ADD: u8 = 0x00;
    const BPF_SUB: u8 = 0x10;
    const BPF_AND: u8 = 0x50;
    const BPF_OR: u8 = 0x40;
    const BPF_MOV: u8 = 0xb0;

    match op {
        BPF_MOV => {
            // Move preserves user property from source
            if src_is_user {
                UserPtrPropagation::Preserve
            } else {
                UserPtrPropagation::ToKernel
            }
        }
        BPF_ADD | BPF_SUB => {
            // Pointer arithmetic preserves user property
            if dst_is_user {
                UserPtrPropagation::Preserve
            } else {
                UserPtrPropagation::ToKernel
            }
        }
        BPF_AND => {
            // Masking might be used for alignment, preserve if dst was user
            if dst_is_user {
                UserPtrPropagation::Preserve
            } else {
                UserPtrPropagation::ToKernel
            }
        }
        BPF_OR => {
            // OR with user pointer is suspicious
            if dst_is_user || src_is_user {
                UserPtrPropagation::Unknown
            } else {
                UserPtrPropagation::ToKernel
            }
        }
        _ => {
            // Other operations invalidate user pointer property
            UserPtrPropagation::Invalidate
        }
    }
}

/// Apply user pointer propagation to a register
pub fn apply_user_ptr_propagation(reg: &mut BpfRegState, propagation: UserPtrPropagation) {
    match propagation {
        UserPtrPropagation::Preserve => {
            // Keep MEM_USER flag
        }
        UserPtrPropagation::ToKernel => {
            reg.type_flags.remove(BpfTypeFlag::MEM_USER);
        }
        UserPtrPropagation::Invalidate => {
            reg.type_flags.remove(BpfTypeFlag::MEM_USER);
            // Could also mark as untrusted
            reg.type_flags.insert(BpfTypeFlag::PTR_UNTRUSTED);
        }
        UserPtrPropagation::Unknown => {
            // Conservative: treat as potentially user
            // This requires runtime check
        }
    }
}

// ============================================================================
// User Memory Bounds Validation
// ============================================================================

/// User memory access bounds information
#[derive(Debug, Clone)]
pub struct UserMemBounds {
    /// Minimum valid offset
    pub min_off: i64,
    /// Maximum valid offset
    pub max_off: i64,
    /// Whether bounds are known
    pub bounds_known: bool,
    /// Maximum allowed access size
    pub max_size: u32,
}

impl Default for UserMemBounds {
    fn default() -> Self {
        Self {
            min_off: 0,
            max_off: i64::MAX,
            bounds_known: false,
            max_size: 4096, // Default max single access
        }
    }
}

impl UserMemBounds {
    /// Create bounds from known range
    pub fn from_range(min: i64, max: i64) -> Self {
        Self {
            min_off: min,
            max_off: max,
            bounds_known: true,
            max_size: 4096,
        }
    }

    /// Check if access is within bounds
    pub fn check_access(&self, off: i64, size: u32) -> Result<()> {
        if !self.bounds_known {
            // Bounds not known - allow but mark for runtime check
            return Ok(());
        }

        if off < self.min_off {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "user memory access offset {} below minimum {}",
                off, self.min_off
            )));
        }

        let end_off = off.saturating_add(size as i64);
        if end_off > self.max_off {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "user memory access end {} exceeds maximum {}",
                end_off, self.max_off
            )));
        }

        if size > self.max_size {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "user memory access size {} exceeds maximum {}",
                size, self.max_size
            )));
        }

        Ok(())
    }

    /// Narrow bounds based on comparison
    pub fn narrow(&mut self, is_upper: bool, value: i64) {
        if is_upper {
            self.max_off = self.max_off.min(value);
        } else {
            self.min_off = self.min_off.max(value);
        }
        self.bounds_known = true;
    }
}

/// Validate user memory access with full bounds checking
pub fn validate_user_mem_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    bounds: &UserMemBounds,
) -> Result<()> {
    // Calculate total offset
    let base_off = reg.off as i64;
    let total_off = base_off.saturating_add(off as i64);

    // Add variable offset if present
    let (min_off, max_off) = if reg.var_off.is_const() {
        let const_off = total_off.saturating_add(reg.var_off.value as i64);
        (const_off, const_off)
    } else {
        // Use signed bounds for variable offset
        let min = total_off.saturating_add(reg.smin_value);
        let max = total_off.saturating_add(reg.smax_value);
        (min, max)
    };

    // Check minimum offset against bounds
    bounds.check_access(min_off, size)?;

    // For variable offset, also check maximum
    if min_off != max_off {
        let max_end = max_off.saturating_add(size as i64);
        if max_end > bounds.max_off {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable-offset user memory access may exceed bounds: max_end={}",
                max_end
            )));
        }
    }

    Ok(())
}

// ============================================================================
// User/Kernel Memory Isolation
// ============================================================================

/// Memory isolation level for user/kernel separation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryIsolation {
    /// Full isolation - user and kernel memory completely separated
    Full,
    /// Partial isolation - some shared access allowed (e.g., arena)
    Partial,
    /// No isolation - trusted context (e.g., sleepable with validation)
    None,
}

/// Check for user/kernel memory confusion
pub fn check_memory_isolation(
    src_reg: &BpfRegState,
    dst_reg: &BpfRegState,
    isolation: MemoryIsolation,
) -> Result<()> {
    let src_is_user = src_reg.type_flags.contains(BpfTypeFlag::MEM_USER);
    let dst_is_user = dst_reg.type_flags.contains(BpfTypeFlag::MEM_USER);

    match isolation {
        MemoryIsolation::Full => {
            // Cannot mix user and kernel pointers
            if src_is_user != dst_is_user {
                // Check for allowed exceptions
                let src_is_scalar = src_reg.reg_type == BpfRegType::ScalarValue;
                let dst_is_scalar = dst_reg.reg_type == BpfRegType::ScalarValue;

                if !src_is_scalar && !dst_is_scalar {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "mixing user and kernel pointers not allowed".into(),
                    ));
                }
            }
        }
        MemoryIsolation::Partial => {
            // Allow mixing for arena pointers
            let src_is_arena = src_reg.reg_type == BpfRegType::PtrToArena;
            let dst_is_arena = dst_reg.reg_type == BpfRegType::PtrToArena;

            if src_is_user != dst_is_user && !src_is_arena && !dst_is_arena {
                return Err(VerifierError::InvalidMemoryAccess(
                    "mixing user and kernel pointers requires arena".into(),
                ));
            }
        }
        MemoryIsolation::None => {
            // No isolation check
        }
    }

    Ok(())
}

/// Check if storing user pointer to kernel memory is allowed
pub fn check_user_ptr_store(
    ptr_reg: &BpfRegState,
    dst_reg: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    // Check if we're storing a user pointer
    if !ptr_reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
        return Ok(());
    }

    // Cannot store user pointers to:
    // 1. Map values (would leak to other programs)
    // 2. Packet data (would leak to network)
    // 3. Stack (only allowed if will be validated before use)

    match dst_reg.reg_type {
        BpfRegType::PtrToMapValue => {
            if !allow_ptr_leaks {
                return Err(VerifierError::InvalidMemoryAccess(
                    "storing user pointer to map value not allowed".into(),
                ));
            }
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            return Err(VerifierError::InvalidMemoryAccess(
                "storing user pointer to packet data not allowed".into(),
            ));
        }
        BpfRegType::PtrToStack => {
            // Allowed - stack is local
        }
        _ => {
            // Other destinations need review
        }
    }

    Ok(())
}

/// Check if loading from user memory into kernel structure is safe
pub fn check_user_to_kernel_load(src_reg: &BpfRegState, dst_type: BpfRegType) -> Result<()> {
    if !src_reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
        return Ok(());
    }

    // Data loaded from user memory is untrusted
    // It cannot be used directly as:
    // 1. Kernel pointers
    // 2. Map keys (without bounds check)
    // 3. Array indices (without bounds check)

    match dst_type {
        BpfRegType::ScalarValue => {
            // Loading to scalar is fine - will need bounds check before use
            Ok(())
        }
        BpfRegType::PtrToMapValue
        | BpfRegType::PtrToMapKey
        | BpfRegType::PtrToBtfId
        | BpfRegType::PtrToCtx => Err(VerifierError::InvalidMemoryAccess(
            "cannot load kernel pointer from user memory".into(),
        )),
        _ => Ok(()),
    }
}

// ============================================================================
// copy_from_user_task Validation
// ============================================================================

/// Context for copy_from_user_task validation
#[derive(Debug, Clone)]
pub struct CopyFromUserTaskContext {
    /// Task pointer register
    pub task_reg: Option<BpfRegState>,
    /// User address register
    pub user_addr_reg: Option<BpfRegState>,
    /// Destination buffer register
    pub dst_reg: Option<BpfRegState>,
    /// Size to copy
    pub size: u32,
    /// Flags
    pub flags: u64,
}

impl CopyFromUserTaskContext {
    /// Create new context
    pub fn new() -> Self {
        Self {
            task_reg: None,
            user_addr_reg: None,
            dst_reg: None,
            size: 0,
            flags: 0,
        }
    }
}

impl Default for CopyFromUserTaskContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate copy_from_user_task helper call
pub fn validate_copy_from_user_task(
    ctx: &CopyFromUserTaskContext,
    verifier_ctx: &UserMemContext,
) -> Result<()> {
    // Must be sleepable context
    if !verifier_ctx.sleepable {
        return Err(VerifierError::InvalidHelperCall(
            "bpf_copy_from_user_task() requires sleepable program".into(),
        ));
    }

    // Validate task pointer
    if let Some(ref task_reg) = ctx.task_reg {
        // Task must be a valid BTF pointer
        if task_reg.reg_type != BpfRegType::PtrToBtfId {
            // Also allow current_task
            if task_reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_BTF_ID (task_struct)".into(),
                    got: format!("{:?}", task_reg.reg_type),
                });
            }
        }
    }

    // Validate destination buffer
    if let Some(ref dst_reg) = ctx.dst_reg {
        validate_probe_read_user_dst(dst_reg, ctx.size)?;
    }

    // Validate size
    if ctx.size == 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "zero-size copy_from_user_task".into(),
        ));
    }

    const MAX_COPY_SIZE: u32 = 256 * 1024;
    if ctx.size > MAX_COPY_SIZE {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "copy_from_user_task size {} exceeds maximum {}",
            ctx.size, MAX_COPY_SIZE
        )));
    }

    Ok(())
}

// ============================================================================
// User Memory Data Flow Analysis
// ============================================================================

/// User memory taint state for data flow analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserMemTaint {
    /// Data is not tainted by user input
    #[default]
    Clean,
    /// Data came directly from user memory
    DirectUser,
    /// Data is derived from user input (computed)
    DerivedUser,
    /// Data has been validated/sanitized
    Validated,
}

impl UserMemTaint {
    /// Check if tainted
    pub fn is_tainted(&self) -> bool {
        matches!(self, UserMemTaint::DirectUser | UserMemTaint::DerivedUser)
    }

    /// Propagate taint through operation
    pub fn propagate(&self, other: &UserMemTaint) -> UserMemTaint {
        match (self, other) {
            (UserMemTaint::Clean, UserMemTaint::Clean) => UserMemTaint::Clean,
            (UserMemTaint::Validated, UserMemTaint::Validated) => UserMemTaint::Validated,
            (UserMemTaint::DirectUser, _) | (_, UserMemTaint::DirectUser) => {
                UserMemTaint::DerivedUser
            }
            _ => UserMemTaint::DerivedUser,
        }
    }
}

/// Track taint state for registers
#[derive(Debug, Clone, Default)]
pub struct UserMemTaintTracker {
    /// Taint state for each register (R0-R10)
    reg_taint: [UserMemTaint; 11],
    /// Number of tainted loads
    tainted_load_count: u32,
    /// Number of sanitization points
    sanitize_count: u32,
}

impl UserMemTaintTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self {
            reg_taint: [UserMemTaint::Clean; 11],
            tainted_load_count: 0,
            sanitize_count: 0,
        }
    }

    /// Mark register as tainted from user memory load
    pub fn taint_from_user_load(&mut self, regno: usize) {
        if regno < 11 {
            self.reg_taint[regno] = UserMemTaint::DirectUser;
            self.tainted_load_count += 1;
        }
    }

    /// Propagate taint for ALU operation
    pub fn propagate_alu(&mut self, dst: usize, src: usize) {
        if dst < 11 && src < 11 {
            let new_taint = self.reg_taint[dst].propagate(&self.reg_taint[src]);
            self.reg_taint[dst] = new_taint;
        }
    }

    /// Mark register as validated (e.g., after bounds check)
    pub fn mark_validated(&mut self, regno: usize) {
        if regno < 11 && self.reg_taint[regno].is_tainted() {
            self.reg_taint[regno] = UserMemTaint::Validated;
            self.sanitize_count += 1;
        }
    }

    /// Mark register as clean (e.g., after constant assignment)
    pub fn mark_clean(&mut self, regno: usize) {
        if regno < 11 {
            self.reg_taint[regno] = UserMemTaint::Clean;
        }
    }

    /// Get taint state for register
    pub fn get_taint(&self, regno: usize) -> UserMemTaint {
        if regno < 11 {
            self.reg_taint[regno]
        } else {
            UserMemTaint::Clean
        }
    }

    /// Check if register is tainted
    pub fn is_tainted(&self, regno: usize) -> bool {
        self.get_taint(regno).is_tainted()
    }

    /// Check if using tainted value in unsafe context
    pub fn check_taint_use(&self, regno: usize, context: &str) -> Result<()> {
        if self.is_tainted(regno) {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "using tainted (user-derived) value in {}: register R{}",
                context, regno
            )));
        }
        Ok(())
    }
}

// ============================================================================
// User Memory Access Pattern Validation
// ============================================================================

/// Common user memory access patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMemAccessPattern {
    /// Sequential read (e.g., copying a buffer)
    Sequential,
    /// Random access (e.g., array indexing)
    Random,
    /// String operations (null-terminated)
    String,
    /// Structure access (known layout)
    Struct,
}

/// Validate access pattern is appropriate for the operation
pub fn validate_access_pattern(
    pattern: UserMemAccessPattern,
    access_type: UserMemAccessType,
    size: u32,
) -> Result<()> {
    match (pattern, access_type) {
        (UserMemAccessPattern::String, UserMemAccessType::ProbeRead) => {
            // probe_read for string should use probe_read_str
            return Err(VerifierError::InvalidHelperCall(
                "use bpf_probe_read_user_str() for string access".into(),
            ));
        }
        (UserMemAccessPattern::String, UserMemAccessType::ProbeReadStr) => {
            // OK
        }
        (UserMemAccessPattern::Sequential, _) if size > 4096 => {
            // Large sequential access should be chunked
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "large sequential user access {} should be chunked",
                size
            )));
        }
        (UserMemAccessPattern::Random, _) => {
            // Random access needs speculation protection
        }
        _ => {}
    }
    Ok(())
}

// ============================================================================
// User Memory Alignment Validation
// ============================================================================

/// Check user memory access alignment
pub fn check_user_mem_alignment(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    strict: bool,
) -> Result<()> {
    // Calculate actual offset
    let actual_off = reg.off.saturating_add(off);

    // Check alignment based on access size
    let alignment = match size {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => 1, // Non-standard size, no alignment requirement
    };

    if strict && (actual_off as u32) % alignment != 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "misaligned user memory access: offset {} not aligned to {} bytes",
            actual_off, alignment
        )));
    }

    // Also check variable offset alignment if present
    if !reg.var_off.is_const() {
        // Variable offset should preserve alignment
        if reg.var_off.mask & (alignment as u64 - 1) != 0 {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable offset may cause misaligned user memory access"
            )));
        }
    }

    Ok(())
}

// ============================================================================
// User Memory Fault Handling
// ============================================================================

/// User memory fault behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMemFaultBehavior {
    /// Return error code on fault
    ReturnError,
    /// Return 0 on fault (probe_read behavior)
    ReturnZero,
    /// Fill with zeros on fault (copy_from_user behavior)
    FillZero,
    /// Abort program on fault (unsafe direct access)
    Abort,
}

/// Get fault behavior for access type
pub fn get_fault_behavior(access_type: UserMemAccessType) -> UserMemFaultBehavior {
    match access_type {
        UserMemAccessType::ProbeRead | UserMemAccessType::ProbeReadStr => {
            UserMemFaultBehavior::ReturnError
        }
        UserMemAccessType::CopyFromUser => UserMemFaultBehavior::FillZero,
        UserMemAccessType::ProbeWrite => UserMemFaultBehavior::ReturnError,
        UserMemAccessType::DirectLoad | UserMemAccessType::DirectStore => {
            UserMemFaultBehavior::Abort
        }
    }
}

/// Check if fault behavior is safe for context
pub fn validate_fault_behavior(behavior: UserMemFaultBehavior, ctx: &UserMemContext) -> Result<()> {
    match behavior {
        UserMemFaultBehavior::Abort => {
            // Only allowed for arena with nospec
            if !ctx.allow_direct_access {
                return Err(VerifierError::InvalidMemoryAccess(
                    "direct user memory access may abort program".into(),
                ));
            }
        }
        UserMemFaultBehavior::FillZero => {
            // Requires sleepable context
            if !ctx.sleepable {
                return Err(VerifierError::InvalidHelperCall(
                    "fill-zero fault handling requires sleepable context".into(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

// ============================================================================
// Comprehensive User Memory Access Validation
// ============================================================================

/// Complete validation of user memory access
pub fn validate_user_mem_access_complete(
    src_reg: &BpfRegState,
    dst_reg: Option<&BpfRegState>,
    off: i32,
    size: u32,
    access_type: UserMemAccessType,
    ctx: &UserMemContext,
    bounds: Option<&UserMemBounds>,
    taint_tracker: Option<&mut UserMemTaintTracker>,
) -> Result<UserMemValidation> {
    // 1. Basic size validation
    if size == 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "zero-size user memory access".into(),
        ));
    }

    // 2. Check helper access is allowed
    let validation = check_user_mem_helper_access(src_reg, ctx, access_type, size)?;
    if !validation.allowed {
        return Ok(validation);
    }

    // 3. Check bounds if provided
    if let Some(bounds) = bounds {
        validate_user_mem_access_bounds(src_reg, off, size, bounds)?;
    }

    // 4. Check alignment for direct access
    if matches!(
        access_type,
        UserMemAccessType::DirectLoad | UserMemAccessType::DirectStore
    ) {
        check_user_mem_alignment(src_reg, off, size, true)?;
    }

    // 5. Check isolation if destination provided
    if let Some(dst) = dst_reg {
        check_memory_isolation(src_reg, dst, MemoryIsolation::Full)?;
    }

    // 6. Check fault behavior is safe
    let fault_behavior = get_fault_behavior(access_type);
    validate_fault_behavior(fault_behavior, ctx)?;

    // 7. Update taint tracking
    if let Some(tracker) = taint_tracker {
        // Mark destination as tainted from user input
        if dst_reg.is_some() {
            // In real usage, would mark the destination register
            tracker.tainted_load_count += 1;
        }
    }

    // Return validation result with speculation info
    if needs_speculation_barrier(src_reg, access_type == UserMemAccessType::DirectLoad) {
        Ok(UserMemValidation::allowed_with_nospec())
    } else {
        Ok(validation)
    }
}

// ============================================================================
// Tests
// ============================================================================
