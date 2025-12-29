// SPDX-License-Identifier: GPL-2.0

//! Pointer overflow check patches
//!
//! This module implements overflow detection and patching for pointer arithmetic
//! operations. It corresponds to the kernel's pointer overflow checking in
//! `adjust_ptr_min_max_vals()` that generates patches for JIT to insert
//! overflow checks.
//!
//! The kernel uses these patches to ensure pointer arithmetic doesn't overflow
//! even under speculative execution, preventing Spectre-style attacks.

#![allow(missing_docs)]

use alloc::{string::String, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

// ============================================================================
// Overflow Check Types
// ============================================================================

/// Type of overflow that can occur in pointer arithmetic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowType {
    /// No overflow possible
    #[default]
    None,
    /// Unsigned overflow (wrap around)
    Unsigned,
    /// Signed overflow (wrap around)
    Signed,
    /// Both signed and unsigned overflow possible
    Both,
}

/// Direction of pointer arithmetic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrAluDirection {
    /// Pointer addition (ptr + scalar)
    Add,
    /// Pointer subtraction (ptr - scalar)
    Sub,
}

/// Overflow check patch to be applied by JIT
#[derive(Debug, Clone)]
pub struct OverflowPatch {
    /// Instruction index where the patch applies
    pub insn_idx: usize,
    /// Type of overflow being checked
    pub overflow_type: OverflowType,
    /// Direction of the arithmetic operation
    pub direction: PtrAluDirection,
    /// Register containing the pointer
    pub ptr_reg: u8,
    /// Register containing the scalar (or 0 for immediate)
    pub scalar_reg: u8,
    /// Immediate value if scalar_reg is 0
    pub imm: i64,
    /// Upper bound for the offset
    pub umax_limit: u64,
    /// Lower bound for the offset (for subtraction)
    pub smin_limit: i64,
    /// Pointer type for context
    pub ptr_type: BpfRegType,
    /// Whether this is a speculative check only
    pub speculative_only: bool,
    /// Patch instructions to insert
    pub patch_insns: Vec<BpfInsn>,
}

impl OverflowPatch {
    /// Create a new overflow patch
    pub fn new(insn_idx: usize, direction: PtrAluDirection) -> Self {
        Self {
            insn_idx,
            overflow_type: OverflowType::None,
            direction,
            ptr_reg: 0,
            scalar_reg: 0,
            imm: 0,
            umax_limit: u64::MAX,
            smin_limit: i64::MIN,
            ptr_type: BpfRegType::NotInit,
            speculative_only: false,
            patch_insns: Vec::new(),
        }
    }
}

/// Result of overflow analysis for an instruction
#[derive(Debug, Clone)]
pub struct OverflowAnalysis {
    /// Whether overflow is possible
    pub can_overflow: bool,
    /// Type of potential overflow
    pub overflow_type: OverflowType,
    /// Whether a patch is needed
    pub needs_patch: bool,
    /// The patch to apply (if needed)
    pub patch: Option<OverflowPatch>,
    /// Computed ALU limit for the operation
    pub alu_limit: u64,
    /// Whether the operation is within provably safe bounds
    pub is_safe: bool,
    /// Error message if overflow is certain
    pub error: Option<String>,
}

impl Default for OverflowAnalysis {
    fn default() -> Self {
        Self {
            can_overflow: false,
            overflow_type: OverflowType::None,
            needs_patch: false,
            patch: None,
            alu_limit: 0,
            is_safe: true,
            error: None,
        }
    }
}

// ============================================================================
// Overflow Detection
// ============================================================================

/// Check for unsigned overflow in addition
#[inline]
pub fn check_add_overflow_u64(a: u64, b: u64) -> bool {
    a.checked_add(b).is_none()
}

/// Check for signed overflow in addition
#[inline]
pub fn check_add_overflow_i64(a: i64, b: i64) -> bool {
    a.checked_add(b).is_none()
}

/// Check for unsigned underflow in subtraction
#[inline]
pub fn check_sub_underflow_u64(a: u64, b: u64) -> bool {
    a < b
}

/// Check for signed overflow in subtraction
#[inline]
pub fn check_sub_overflow_i64(a: i64, b: i64) -> bool {
    a.checked_sub(b).is_none()
}

/// Analyze pointer arithmetic for potential overflow
///
/// This is the main entry point for overflow analysis. It examines a pointer
/// arithmetic operation and determines if overflow is possible and what
/// patches are needed.
pub fn analyze_ptr_overflow(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<OverflowAnalysis> {
    let mut analysis = OverflowAnalysis::default();

    let dst_reg = insn.dst_reg as usize;
    let src_type = insn.code & 0x08;
    let opcode = insn.code & 0xf0;

    // Only analyze ADD and SUB
    if opcode != BPF_ADD && opcode != BPF_SUB {
        return Ok(analysis);
    }

    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

    // Only analyze pointer arithmetic
    if !dst.is_pointer() {
        return Ok(analysis);
    }

    let direction = if opcode == BPF_ADD {
        PtrAluDirection::Add
    } else {
        PtrAluDirection::Sub
    };

    // Get scalar operand bounds
    let (smin, smax, umin, umax) = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        let src = state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

        if src.is_pointer() {
            // ptr - ptr case handled elsewhere
            return Ok(analysis);
        }

        (
            src.smin_value,
            src.smax_value,
            src.umin_value,
            src.umax_value,
        )
    } else {
        let imm = insn.imm as i64;
        (imm, imm, imm as u64, imm as u64)
    };

    // Check for overflow based on operation type
    let overflow_type = match direction {
        PtrAluDirection::Add => analyze_add_overflow(dst, smin, smax, umin, umax),
        PtrAluDirection::Sub => analyze_sub_overflow(dst, smin, smax, umin, umax),
    };

    analysis.overflow_type = overflow_type;
    analysis.can_overflow = overflow_type != OverflowType::None;

    // If overflow is possible, we need a patch
    if analysis.can_overflow {
        analysis.needs_patch = !allow_ptr_leaks;

        // Compute the limit for bounds checking
        let limit = compute_overflow_limit(dst, direction, umax, smin)?;
        analysis.alu_limit = limit;

        // Generate the patch
        if analysis.needs_patch {
            let mut patch = OverflowPatch::new(insn_idx, direction);
            patch.overflow_type = overflow_type;
            patch.ptr_reg = insn.dst_reg;
            patch.ptr_type = dst.reg_type;
            patch.umax_limit = limit;
            patch.smin_limit = smin;

            if src_type == BPF_X {
                patch.scalar_reg = insn.src_reg;
            } else {
                patch.imm = insn.imm as i64;
            }

            // Generate patch instructions
            patch.patch_insns = generate_overflow_check_insns(&patch);

            analysis.patch = Some(patch);
        }
    }

    // Check if the bounds are provably safe
    analysis.is_safe = !analysis.can_overflow || is_overflow_safe(dst, direction, umax, smin);

    Ok(analysis)
}

/// Analyze overflow for pointer addition
fn analyze_add_overflow(
    ptr: &BpfRegState,
    smin: i64,
    smax: i64,
    _umin: u64,
    umax: u64,
) -> OverflowType {
    let mut has_unsigned = false;
    let mut has_signed = false;

    // Check unsigned overflow: ptr + offset might wrap
    if check_add_overflow_u64(ptr.umax_value, umax) {
        has_unsigned = true;
    }

    // Check signed overflow
    if check_add_overflow_i64(ptr.smax_value, smax) {
        has_signed = true;
    }
    if check_add_overflow_i64(ptr.smin_value, smin) {
        has_signed = true;
    }

    match (has_unsigned, has_signed) {
        (false, false) => OverflowType::None,
        (true, false) => OverflowType::Unsigned,
        (false, true) => OverflowType::Signed,
        (true, true) => OverflowType::Both,
    }
}

/// Analyze overflow for pointer subtraction
fn analyze_sub_overflow(
    ptr: &BpfRegState,
    smin: i64,
    smax: i64,
    _umin: u64,
    umax: u64,
) -> OverflowType {
    let mut has_unsigned = false;
    let mut has_signed = false;

    // Check unsigned underflow: ptr - offset might go negative
    if check_sub_underflow_u64(ptr.umin_value, umax) {
        has_unsigned = true;
    }

    // Check signed overflow
    if check_sub_overflow_i64(ptr.smin_value, smax) {
        has_signed = true;
    }
    if check_sub_overflow_i64(ptr.smax_value, smin) {
        has_signed = true;
    }

    match (has_unsigned, has_signed) {
        (false, false) => OverflowType::None,
        (true, false) => OverflowType::Unsigned,
        (false, true) => OverflowType::Signed,
        (true, true) => OverflowType::Both,
    }
}

/// Compute the limit value for overflow checking
fn compute_overflow_limit(
    ptr: &BpfRegState,
    direction: PtrAluDirection,
    umax_offset: u64,
    smin_offset: i64,
) -> Result<u64> {
    match ptr.reg_type {
        BpfRegType::PtrToStack => {
            // Stack: limit is distance from current offset to stack bottom
            let cur_off = ptr.off as i64;
            let max_stack = MAX_BPF_STACK as i64;

            match direction {
                PtrAluDirection::Add => {
                    // Adding to stack pointer: can't go above frame (0)
                    if cur_off >= 0 {
                        Ok(0)
                    } else {
                        Ok((-cur_off) as u64)
                    }
                }
                PtrAluDirection::Sub => {
                    // Subtracting from stack pointer: can't go below -MAX_BPF_STACK
                    let room = max_stack + cur_off;
                    if room < 0 {
                        Ok(0)
                    } else {
                        Ok(room as u64)
                    }
                }
            }
        }
        BpfRegType::PtrToMapValue => {
            // Map value: limit is value_size - current_offset
            if let Some(ref map) = ptr.map_ptr {
                let cur_off = ptr.off as u64;
                let value_size = map.value_size as u64;

                match direction {
                    PtrAluDirection::Add => {
                        if cur_off >= value_size {
                            Ok(0)
                        } else {
                            Ok(value_size - cur_off)
                        }
                    }
                    PtrAluDirection::Sub => {
                        // Can subtract at most cur_off
                        Ok(cur_off)
                    }
                }
            } else {
                Ok(u64::MAX)
            }
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            // Packet: limit is based on packet_end - current position
            // This is more complex in real implementation, using a conservative limit
            match direction {
                PtrAluDirection::Add => Ok(umax_offset),
                PtrAluDirection::Sub => Ok((-smin_offset) as u64),
            }
        }
        _ => {
            // For other pointer types, use a conservative limit
            Ok(u64::MAX)
        }
    }
}

/// Check if overflow is safe (within known bounds)
fn is_overflow_safe(
    ptr: &BpfRegState,
    direction: PtrAluDirection,
    umax_offset: u64,
    smin_offset: i64,
) -> bool {
    match ptr.reg_type {
        BpfRegType::PtrToStack => {
            let cur_off = ptr.off as i64;
            let max_stack = MAX_BPF_STACK as i64;

            match direction {
                PtrAluDirection::Add => {
                    // Safe if adding umax stays below 0
                    cur_off + (umax_offset as i64) <= 0
                }
                PtrAluDirection::Sub => {
                    // Safe if subtracting stays above -MAX_BPF_STACK
                    let min_off = if smin_offset < 0 {
                        cur_off - (-smin_offset)
                    } else {
                        cur_off - smin_offset
                    };
                    min_off >= -max_stack
                }
            }
        }
        BpfRegType::PtrToMapValue => {
            if let Some(ref map) = ptr.map_ptr {
                let cur_off = ptr.off as i64;
                let value_size = map.value_size as i64;

                match direction {
                    PtrAluDirection::Add => cur_off + (umax_offset as i64) <= value_size,
                    PtrAluDirection::Sub => cur_off - (-smin_offset) >= 0,
                }
            } else {
                false
            }
        }
        _ => false, // Conservative for other types
    }
}

// ============================================================================
// Patch Generation
// ============================================================================

/// Generate overflow check instructions
///
/// These instructions are inserted by JIT to check for overflow at runtime.
/// The strategy is:
/// 1. Compare offset against limit
/// 2. If overflow would occur, mask the result to prevent OOB access
fn generate_overflow_check_insns(patch: &OverflowPatch) -> Vec<BpfInsn> {
    let mut insns = Vec::new();

    match patch.overflow_type {
        OverflowType::None => return insns,
        OverflowType::Unsigned | OverflowType::Both => {
            // Generate unsigned overflow check
            insns.extend(generate_unsigned_overflow_check(patch));
        }
        OverflowType::Signed => {
            // Generate signed overflow check
            insns.extend(generate_signed_overflow_check(patch));
        }
    }

    insns
}

/// Generate unsigned overflow check instructions
fn generate_unsigned_overflow_check(patch: &OverflowPatch) -> Vec<BpfInsn> {
    let mut insns = Vec::new();

    // Strategy: Use conditional to zero out pointer if overflow detected
    // This prevents speculative execution from accessing invalid memory

    // For ptr + offset:
    // 1. tmp = limit - offset
    // 2. tmp >>= 63 (sign bit: 0 if no overflow, -1 if overflow)
    // 3. ptr &= tmp (zeros ptr if overflow)

    let scratch_reg: u8 = BPF_REG_AX; // Use AX as scratch

    if patch.scalar_reg != 0 {
        // Register operand
        // r_ax = limit
        insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            scratch_reg,
            0,
            0,
            patch.umax_limit as i32,
        ));

        // r_ax -= scalar_reg
        insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_SUB | BPF_X,
            scratch_reg,
            patch.scalar_reg,
            0,
            0,
        ));
    } else {
        // Immediate operand
        let diff = patch.umax_limit as i64 - patch.imm;

        insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            scratch_reg,
            0,
            0,
            diff as i32,
        ));
    }

    // r_ax >>= 63 (arithmetic right shift to get sign)
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ARSH | BPF_K,
        scratch_reg,
        0,
        0,
        63,
    ));

    // ptr &= r_ax (mask pointer if overflow)
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_AND | BPF_X,
        patch.ptr_reg,
        scratch_reg,
        0,
        0,
    ));

    insns
}

/// Generate signed overflow check instructions
fn generate_signed_overflow_check(patch: &OverflowPatch) -> Vec<BpfInsn> {
    let mut insns = Vec::new();

    // For signed overflow, we need to check both directions
    let scratch_reg: u8 = BPF_REG_AX;

    match patch.direction {
        PtrAluDirection::Add => {
            // Check if ptr + offset overflows positively
            // if (offset > 0 && ptr > MAX - offset) overflow

            if patch.scalar_reg != 0 {
                // Compare scalar_reg against limit
                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_MOV | BPF_K,
                    scratch_reg,
                    0,
                    0,
                    patch.umax_limit as i32,
                ));

                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_SUB | BPF_X,
                    scratch_reg,
                    patch.scalar_reg,
                    0,
                    0,
                ));

                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_ARSH | BPF_K,
                    scratch_reg,
                    0,
                    0,
                    63,
                ));

                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_AND | BPF_X,
                    patch.ptr_reg,
                    scratch_reg,
                    0,
                    0,
                ));
            }
        }
        PtrAluDirection::Sub => {
            // Check if ptr - offset underflows
            // if (offset > ptr) underflow

            if patch.scalar_reg != 0 {
                // r_ax = ptr
                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_MOV | BPF_X,
                    scratch_reg,
                    patch.ptr_reg,
                    0,
                    0,
                ));

                // r_ax -= scalar_reg
                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_SUB | BPF_X,
                    scratch_reg,
                    patch.scalar_reg,
                    0,
                    0,
                ));

                // r_ax >>= 63
                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_ARSH | BPF_K,
                    scratch_reg,
                    0,
                    0,
                    63,
                ));

                // ptr &= r_ax
                insns.push(BpfInsn::new(
                    BPF_ALU64 | BPF_AND | BPF_X,
                    patch.ptr_reg,
                    scratch_reg,
                    0,
                    0,
                ));
            }
        }
    }

    insns
}

// ============================================================================
// Batch Processing
// ============================================================================

/// Collection of overflow patches for a program
#[derive(Debug, Clone, Default)]
pub struct OverflowPatchSet {
    /// All patches to apply
    pub patches: Vec<OverflowPatch>,
    /// Total instruction count added by patches
    pub added_insn_count: usize,
    /// Map from original insn_idx to patched insn_idx
    pub insn_map: Vec<usize>,
}

impl OverflowPatchSet {
    /// Create new empty patch set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch to the set
    pub fn add_patch(&mut self, patch: OverflowPatch) {
        self.added_insn_count += patch.patch_insns.len();
        self.patches.push(patch);
    }

    /// Check if any patches are needed
    pub fn needs_patching(&self) -> bool {
        !self.patches.is_empty()
    }

    /// Get total patches count
    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }

    /// Compute the instruction index mapping after patching
    pub fn compute_insn_map(&mut self, original_len: usize) {
        self.insn_map = Vec::with_capacity(original_len);

        let mut offset = 0usize;
        let mut patch_iter = self.patches.iter().peekable();

        for i in 0..original_len {
            // Add any patches before this instruction
            while let Some(patch) = patch_iter.peek() {
                if patch.insn_idx <= i {
                    offset += patch.patch_insns.len();
                    patch_iter.next();
                } else {
                    break;
                }
            }
            self.insn_map.push(i + offset);
        }
    }

    /// Apply patches to instruction array
    pub fn apply_patches(&self, insns: &[BpfInsn]) -> Vec<BpfInsn> {
        let mut result = Vec::with_capacity(insns.len() + self.added_insn_count);

        let mut patches_by_idx: Vec<_> = self.patches.iter().collect();
        patches_by_idx.sort_by_key(|p| p.insn_idx);

        let mut patch_iter = patches_by_idx.into_iter().peekable();

        for (i, insn) in insns.iter().enumerate() {
            // Insert any patches before this instruction
            while let Some(patch) = patch_iter.peek() {
                if patch.insn_idx == i {
                    result.extend(patch.patch_insns.iter().cloned());
                    patch_iter.next();
                } else {
                    break;
                }
            }
            result.push(*insn);
        }

        result
    }
}

/// Analyze entire program for overflow patches
pub fn analyze_program_overflow(
    state: &BpfVerifierState,
    insns: &[BpfInsn],
    allow_ptr_leaks: bool,
) -> Result<OverflowPatchSet> {
    let mut patch_set = OverflowPatchSet::new();

    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();

        if class == BPF_ALU || class == BPF_ALU64 {
            let opcode = insn.code & 0xf0;

            if opcode == BPF_ADD || opcode == BPF_SUB {
                let analysis = analyze_ptr_overflow(state, insn, idx, allow_ptr_leaks)?;

                if analysis.needs_patch {
                    if let Some(patch) = analysis.patch {
                        patch_set.add_patch(patch);
                    }
                }
            }
        }
    }

    if patch_set.needs_patching() {
        patch_set.compute_insn_map(insns.len());
    }

    Ok(patch_set)
}

// ============================================================================
// Integration with Existing Sanitization
// ============================================================================

/// Combined overflow and sanitization result
#[derive(Debug, Clone, Default)]
pub struct PtrAluSanitizeResult {
    /// Overflow analysis
    pub overflow: OverflowAnalysis,
    /// Whether operation should be rejected
    pub reject: bool,
    /// Error message if rejected
    pub reject_reason: Option<String>,
    /// Combined patches (overflow + spectre)
    pub patches: Vec<BpfInsn>,
}

/// Full pointer ALU sanitization check
///
/// Combines overflow checking with Spectre mitigation for complete safety.
pub fn sanitize_ptr_alu_full(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<PtrAluSanitizeResult> {
    let mut result = PtrAluSanitizeResult::default();

    // First, analyze for overflow
    let overflow = analyze_ptr_overflow(state, insn, insn_idx, allow_ptr_leaks)?;

    // If overflow is certain and bounds prove it's invalid, reject
    if overflow.can_overflow && !overflow.is_safe && overflow.error.is_some() {
        result.reject = true;
        result.reject_reason = overflow.error.clone();
    }

    // Collect patches from overflow analysis
    if let Some(ref patch) = overflow.patch {
        result.patches.extend(patch.patch_insns.iter().cloned());
    }

    result.overflow = overflow;

    Ok(result)
}

// ============================================================================
// Auxiliary Data Integration
// ============================================================================

/// Extended auxiliary data for overflow tracking
#[derive(Debug, Clone, Default)]
pub struct OverflowAuxData {
    /// Whether overflow check is needed
    pub needs_overflow_check: bool,
    /// Overflow type detected
    pub overflow_type: OverflowType,
    /// Computed ALU limit
    pub alu_limit: u64,
    /// Number of patch instructions to insert
    pub patch_count: usize,
    /// Whether this is a speculative-only check
    pub speculative_only: bool,
}

impl OverflowAuxData {
    /// Create from overflow analysis
    pub fn from_analysis(analysis: &OverflowAnalysis) -> Self {
        Self {
            needs_overflow_check: analysis.needs_patch,
            overflow_type: analysis.overflow_type,
            alu_limit: analysis.alu_limit,
            patch_count: analysis
                .patch
                .as_ref()
                .map(|p| p.patch_insns.len())
                .unwrap_or(0),
            speculative_only: false,
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// BPF register used as scratch for overflow checks
const BPF_REG_AX: u8 = 10; // Auxiliary register

// ============================================================================
// Tests
// ============================================================================
