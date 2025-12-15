//! Spectre mitigation sanitization
//!
//! This module implements sanitization checks to prevent speculative
//! execution attacks (like Spectre). It ensures that pointer arithmetic
//! and memory accesses are safe even under speculative execution.

#![allow(missing_docs)] // Sanitization internals

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::error::{Result, VerifierError};

/// Sanitization state for an instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SanitizeState {
    /// No sanitization needed
    #[default]
    None,
    /// Needs speculation barrier
    NeedsBarrier,
    /// Already sanitized
    Sanitized,
}

/// Pointer limit for sanitization
#[derive(Debug, Clone, Copy)]
pub struct PtrLimit {
    /// Maximum positive offset
    pub umax: u64,
    /// Type of pointer
    pub ptr_type: BpfRegType,
    /// Whether limit is exact
    pub is_exact: bool,
}

impl Default for PtrLimit {
    fn default() -> Self {
        Self {
            umax: 0,
            ptr_type: BpfRegType::NotInit,
            is_exact: false,
        }
    }
}

/// Check if sanitization is needed for this operation
pub fn sanitize_needed(allow_ptr_leaks: bool) -> bool {
    // Unprivileged mode requires sanitization
    !allow_ptr_leaks
}

/// Check if the error is recoverable with a speculation barrier
pub fn error_recoverable_with_nospec(err: &VerifierError) -> bool {
    matches!(
        err,
        VerifierError::PermissionDenied(_)
            | VerifierError::InvalidMemoryAccess(_)
            | VerifierError::StackOutOfBounds(_)
    )
}

/// Retrieve pointer limit for sanitization
pub fn retrieve_ptr_limit(
    reg: &BpfRegState,
    off: i32,
    _is_write: bool,
) -> Result<PtrLimit> {
    let ptr_type = reg.reg_type;
    
    match ptr_type {
        BpfRegType::PtrToStack => {
            // Stack has fixed limit
            let max_off = MAX_BPF_STACK as i64;
            let cur_off = reg.off as i64 + off as i64;
            
            if cur_off >= 0 || cur_off < -max_off {
                return Err(VerifierError::StackOutOfBounds(cur_off as i32));
            }
            
            Ok(PtrLimit {
                umax: (-cur_off) as u64,
                ptr_type,
                is_exact: true,
            })
        }
        BpfRegType::PtrToMapValue => {
            // Map value has its size as limit
            let map_value_size = reg.map_ptr
                .as_ref()
                .map(|m| m.value_size as u64)
                .unwrap_or(0);
            let cur_off = (reg.off as i64 + off as i64) as u64;
            
            if cur_off >= map_value_size {
                return Err(VerifierError::InvalidMemoryAccess(
                    format!("map value offset {} >= size {}", cur_off, map_value_size)
                ));
            }
            
            Ok(PtrLimit {
                umax: map_value_size - cur_off,
                ptr_type,
                is_exact: true,
            })
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            // Packet access - limit based on packet_end
            // This is more complex in the real verifier
            Ok(PtrLimit {
                umax: u64::MAX,
                ptr_type,
                is_exact: false,
            })
        }
        BpfRegType::PtrToCtx => {
            // Context access has its own limits
            Ok(PtrLimit {
                umax: 0, // Conservative
                ptr_type,
                is_exact: false,
            })
        }
        _ => {
            Ok(PtrLimit::default())
        }
    }
}

/// Check if pointer ALU can skip sanitization
pub fn can_skip_alu_sanitation(
    dst_reg: &BpfRegState,
    src_reg: Option<&BpfRegState>,
) -> bool {
    // If destination is not a pointer, no sanitization needed
    if !dst_reg.is_pointer() {
        return true;
    }
    
    // If source is a known constant, we can skip
    if let Some(src) = src_reg {
        if src.is_const() {
            return true;
        }
    }
    
    false
}

/// Update sanitization state for ALU operation
pub fn update_alu_sanitation_state(
    state: &mut SanitizeState,
    dst_reg: &BpfRegState,
    _src_reg: Option<&BpfRegState>,
) {
    if dst_reg.is_pointer() && *state == SanitizeState::None {
        *state = SanitizeState::NeedsBarrier;
    }
}

/// Sanitize a pointer ALU operation
pub fn sanitize_ptr_alu(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    dst_reg: usize,
    src_reg: usize,
    is_add: bool,
    allow_ptr_leaks: bool,
) -> Result<SanitizeState> {
    if !sanitize_needed(allow_ptr_leaks) {
        return Ok(SanitizeState::None);
    }

    let dst = state.reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;
    
    // If not a pointer, no sanitization needed
    if !dst.is_pointer() {
        return Ok(SanitizeState::None);
    }

    let src = state.reg(src_reg);
    
    if can_skip_alu_sanitation(dst, src) {
        return Ok(SanitizeState::None);
    }

    // Get pointer limit
    let limit = retrieve_ptr_limit(dst, insn.off as i32, false)?;
    
    // Check if the operation is within bounds
    if let Some(src_reg) = src {
        if src_reg.reg_type == BpfRegType::ScalarValue {
            let max_val = if is_add {
                src_reg.umax_value
            } else {
                // For subtraction, use the negative
                if src_reg.smin_value < 0 {
                    (-src_reg.smin_value) as u64
                } else {
                    0
                }
            };
            
            if max_val > limit.umax && limit.is_exact {
                return Err(VerifierError::InvalidPointerArithmetic(
                    format!("offset {} exceeds limit {}", max_val, limit.umax)
                ));
            }
        }
    }

    Ok(SanitizeState::NeedsBarrier)
}

/// Sanitize a value used in ALU (for scalar operations)
pub fn sanitize_val_alu(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    allow_ptr_leaks: bool,
) -> Result<()> {
    if !sanitize_needed(allow_ptr_leaks) {
        return Ok(());
    }

    let dst_reg = insn.dst_reg as usize;
    let dst = state.reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

    // Check for pointer leaks in unprivileged mode
    if dst.is_pointer() {
        return Err(VerifierError::PointerLeak);
    }

    Ok(())
}

/// Check bounds for potential speculative access
pub fn sanitize_check_bounds(
    _state: &BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
) -> Result<()> {
    if !reg.is_pointer() {
        return Ok(());
    }

    let limit = retrieve_ptr_limit(reg, off, false)?;
    
    // Check if access is within bounds
    if limit.is_exact && (size as u64) > limit.umax {
        return Err(VerifierError::BoundsCheckFailed(
            format!("access size {} exceeds limit {}", size, limit.umax)
        ));
    }

    Ok(())
}

/// Mark an instruction as needing sanitization
pub fn sanitize_mark_insn_seen(
    aux_data: &mut InsnAuxData,
    needs_barrier: bool,
) {
    if needs_barrier {
        aux_data.needs_nospec_barrier = true;
    }
    aux_data.seen = true;
}

/// Auxiliary data for each instruction
#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub struct InsnAuxData {
    /// Whether instruction has been seen
    pub seen: bool,
    /// Whether instruction needs speculation barrier
    pub needs_nospec_barrier: bool,
    /// Whether instruction is a jump target
    pub is_jmp_target: bool,
    /// Sanitization state
    pub sanitize_state: SanitizeState,
    /// ALU operation limit
    pub alu_limit: u32,
    /// Whether this is a prune point
    pub prune_point: bool,
    /// Whether this forces a checkpoint
    pub force_checkpoint: bool,
}

impl InsnAuxData {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Speculative path sanitization
pub fn sanitize_speculative_path(
    _state: &mut BpfVerifierState,
    insn_idx: usize,
    aux: &mut [InsnAuxData],
) -> Result<()> {
    // Mark current instruction as needing barrier
    if insn_idx < aux.len() {
        aux[insn_idx].needs_nospec_barrier = true;
    }
    Ok(())
}

/// Check stack access for pointer arithmetic safety
pub fn check_stack_access_for_ptr_arithmetic(
    state: &BpfVerifierState,
    regno: usize,
    off: i32,
    size: u32,
    allow_ptr_leaks: bool,
) -> Result<()> {
    if !sanitize_needed(allow_ptr_leaks) {
        return Ok(());
    }

    let reg = state.reg(regno)
        .ok_or(VerifierError::InvalidRegister(regno as u8))?;

    if reg.reg_type != BpfRegType::PtrToStack {
        return Ok(());
    }

    // Check that the stack access is within bounds
    let stack_off = reg.off + off;
    if stack_off >= 0 {
        return Err(VerifierError::StackOutOfBounds(stack_off));
    }
    if stack_off < -(MAX_BPF_STACK as i32) {
        return Err(VerifierError::StackOutOfBounds(stack_off));
    }

    // Check alignment
    if ((-stack_off) as u32) < size {
        return Err(VerifierError::StackOutOfBounds(stack_off));
    }

    Ok(())
}

/// Sanitize error - generate appropriate error for sanitization failure
pub fn sanitize_err(
    _state: &BpfVerifierState,
    _insn: &BpfInsn,
    _reason: &str,
) -> VerifierError {
    VerifierError::SpeculativeViolation
}

/// Spectre variant classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreVariant {
    /// Spectre v1: Bounds Check Bypass
    V1BoundsCheckBypass,
    /// Spectre v2: Branch Target Injection
    V2BranchTargetInjection,
    /// Spectre v4: Speculative Store Bypass
    V4SpeculativeStoreBypass,
}

/// Mitigation strategy for speculative execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MitigationStrategy {
    /// No mitigation needed
    #[default]
    None,
    /// Insert LFENCE/speculation barrier
    SpeculationBarrier,
    /// Use index masking (for array bounds)
    IndexMasking,
    /// Pointer sanitization
    PointerSanitization,
    /// Use conditional select (CSEL) instead of branch
    ConditionalSelect,
}

/// Analysis result for speculative vulnerability
#[derive(Debug, Clone)]
pub struct SpectreAnalysis {
    /// Variant detected
    pub variant: SpectreVariant,
    /// Instruction index
    pub insn_idx: usize,
    /// Recommended mitigation
    pub mitigation: MitigationStrategy,
    /// Description of the vulnerability
    pub description: String,
}

/// Analyze instruction for Spectre v1 (bounds check bypass)
pub fn analyze_spectre_v1(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Option<SpectreAnalysis> {
    // Spectre v1 occurs when:
    // 1. There's a conditional branch based on an attacker-controlled value
    // 2. Followed by an array access using that value as index
    
    // Check if this is a conditional jump
    let opcode = insn.code & 0xf0;
    if opcode < 0x50 || opcode > 0xd0 {
        return None; // Not a conditional jump
    }

    let dst_reg = insn.dst_reg as usize;
    let reg = state.reg(dst_reg)?;
    
    // Check if the comparison involves a scalar with wide bounds
    if reg.reg_type == BpfRegType::ScalarValue {
        let range = reg.umax_value.saturating_sub(reg.umin_value);
        if range > 256 {
            // Wide range suggests potential for bounds speculation
            return Some(SpectreAnalysis {
                variant: SpectreVariant::V1BoundsCheckBypass,
                insn_idx,
                mitigation: MitigationStrategy::IndexMasking,
                description: format!(
                    "conditional branch on scalar with wide range [{}, {}]",
                    reg.umin_value, reg.umax_value
                ),
            });
        }
    }
    
    None
}

/// Analyze memory access for Spectre v1 vulnerability
pub fn analyze_memory_access_v1(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Option<SpectreAnalysis> {
    // Check if this is a load/store
    let class = insn.code & 0x07;
    if class != BPF_LDX && class != BPF_STX && class != BPF_ST {
        return None;
    }

    let src_reg = insn.src_reg as usize;
    let reg = state.reg(src_reg)?;

    // Check if accessing through a pointer with variable offset
    if reg.is_pointer() {
        // Check if the variable offset could be attacker-controlled
        if !reg.var_off.is_const() {
            return Some(SpectreAnalysis {
                variant: SpectreVariant::V1BoundsCheckBypass,
                insn_idx,
                mitigation: MitigationStrategy::PointerSanitization,
                description: format!(
                    "memory access through {:?} with variable offset",
                    reg.reg_type
                ),
            });
        }
    }
    
    None
}

// BPF instruction class constants
const BPF_LDX: u8 = 0x01;
const BPF_STX: u8 = 0x03;
const BPF_ST: u8 = 0x02;

/// Analyze for Spectre v4 (speculative store bypass)
pub fn analyze_spectre_v4(
    state: &BpfVerifierState,
    store_insn: &BpfInsn,
    load_insn: &BpfInsn,
    store_idx: usize,
    load_idx: usize,
) -> Option<SpectreAnalysis> {
    // Spectre v4 occurs when a load speculatively reads stale data
    // because a preceding store hasn't committed yet
    
    // Check if both access the same address
    let store_base = store_insn.dst_reg as usize;
    let load_base = load_insn.src_reg as usize;
    
    let store_reg = state.reg(store_base)?;
    let load_reg = state.reg(load_base)?;
    
    // Same register and offset suggests potential alias
    if store_base == load_base && store_insn.off == load_insn.off {
        return Some(SpectreAnalysis {
            variant: SpectreVariant::V4SpeculativeStoreBypass,
            insn_idx: load_idx,
            mitigation: MitigationStrategy::SpeculationBarrier,
            description: format!(
                "potential store-load alias at offset {}",
                store_insn.off
            ),
        });
    }
    
    // Check for potential overlap through pointers to same region
    if store_reg.reg_type == load_reg.reg_type {
        // Could potentially alias
        let _ = store_idx; // Suppress warning
        return Some(SpectreAnalysis {
            variant: SpectreVariant::V4SpeculativeStoreBypass,
            insn_idx: load_idx,
            mitigation: MitigationStrategy::SpeculationBarrier,
            description: "potential store-load alias through same pointer type".into(),
        });
    }
    
    None
}

/// Insert speculation barrier instruction
pub fn insert_speculation_barrier(patches: &mut Vec<SpectreBarrierPatch>, insn_idx: usize) {
    patches.push(SpectreBarrierPatch {
        insn_idx,
        barrier_type: BarrierType::Lfence,
    });
}

/// Speculation barrier patch to be applied
#[derive(Debug, Clone)]
pub struct SpectreBarrierPatch {
    /// Instruction index after which to insert barrier
    pub insn_idx: usize,
    /// Type of barrier
    pub barrier_type: BarrierType,
}

/// Types of speculation barriers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierType {
    /// LFENCE instruction (x86)
    Lfence,
    /// ISB instruction (ARM)
    Isb,
    /// CSDB instruction (ARM speculation barrier)
    Csdb,
    /// Generic nospec barrier (BPF instruction)
    BpfNospec,
}

/// Generate index mask for bounds check
/// 
/// Creates a mask that zeros out the index if it exceeds bounds
pub fn generate_index_mask(index_max: u64) -> u64 {
    if index_max == 0 {
        return 0;
    }
    // Round up to power of 2 minus 1
    let mut mask = index_max;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    mask |= mask >> 32;
    mask
}

/// Check if a JIT bypass is possible for this access
pub fn check_jit_spectre_bypass(
    reg: &BpfRegState,
    off: i32,
    size: u32,
) -> bool {
    // JIT can bypass speculation barriers in some cases
    // when it can prove the access is always safe
    
    if !reg.is_pointer() {
        return true; // Not a pointer, no speculation issue
    }
    
    // Constant offsets with known bounds can be bypassed
    if reg.var_off.is_const() {
        let total_off = reg.off + off;
        
        match reg.reg_type {
            BpfRegType::PtrToStack => {
                // Stack access with constant offset
                return total_off < 0 && total_off >= -(MAX_BPF_STACK as i32);
            }
            BpfRegType::PtrToMapValue => {
                // Map value with constant offset
                if let Some(map) = &reg.map_ptr {
                    return (total_off as u32) + size <= map.value_size;
                }
            }
            _ => {}
        }
    }
    
    false
}

/// Spectre mitigation configuration
#[derive(Debug, Clone)]
pub struct SpectreConfig {
    /// Enable Spectre v1 mitigations
    pub mitigate_v1: bool,
    /// Enable Spectre v2 mitigations  
    pub mitigate_v2: bool,
    /// Enable Spectre v4 mitigations
    pub mitigate_v4: bool,
    /// Use aggressive mitigations (more barriers, less performance)
    pub aggressive: bool,
    /// Allow JIT to bypass barriers when provably safe
    pub allow_jit_bypass: bool,
}

impl Default for SpectreConfig {
    fn default() -> Self {
        Self {
            mitigate_v1: true,
            mitigate_v2: true,
            mitigate_v4: true,
            aggressive: false,
            allow_jit_bypass: true,
        }
    }
}

/// Full Spectre analysis for a program
pub fn analyze_program_spectre(
    _state: &BpfVerifierState,
    insns: &[BpfInsn],
    config: &SpectreConfig,
) -> Vec<SpectreAnalysis> {
    let mut results = Vec::new();
    
    for (idx, insn) in insns.iter().enumerate() {
        // Analyze for Spectre v1 in conditional jumps
        if config.mitigate_v1 {
            let opcode = insn.code & 0xf0;
            if opcode >= 0x50 && opcode <= 0xd0 {
                // This is a conditional jump - mark as potential Spectre v1 source
                results.push(SpectreAnalysis {
                    variant: SpectreVariant::V1BoundsCheckBypass,
                    insn_idx: idx,
                    mitigation: if config.aggressive {
                        MitigationStrategy::SpeculationBarrier
                    } else {
                        MitigationStrategy::IndexMasking
                    },
                    description: "conditional branch - potential Spectre v1 gadget".into(),
                });
            }
        }
    }
    
    results
}

/// Apply Spectre mitigations by patching the program
pub fn apply_spectre_mitigations(
    analyses: &[SpectreAnalysis],
) -> Vec<SpectreBarrierPatch> {
    let mut patches = Vec::new();
    
    for analysis in analyses {
        match analysis.mitigation {
            MitigationStrategy::SpeculationBarrier => {
                insert_speculation_barrier(&mut patches, analysis.insn_idx);
            }
            MitigationStrategy::IndexMasking => {
                // Index masking is handled by the JIT
                // We just record that it's needed
            }
            MitigationStrategy::PointerSanitization => {
                // Pointer sanitization is also JIT-handled
            }
            MitigationStrategy::ConditionalSelect => {
                // Convert branch to CSEL - JIT handles this
            }
            MitigationStrategy::None => {}
        }
    }
    
    patches
}

// ============================================================================
// ALU Sanitization for JIT
// ============================================================================

/// ALU sanitization action to be applied by JIT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluSanitizeAction {
    /// No sanitization needed
    None,
    /// Apply index masking (AND with mask)
    IndexMask { mask: u64 },
    /// Apply pointer masking
    PointerMask,
    /// Insert bounds check
    BoundsCheck { limit: u64 },
    /// Insert speculation barrier before
    BarrierBefore,
    /// Insert speculation barrier after
    BarrierAfter,
}

/// Result of ALU sanitization analysis
#[derive(Debug, Clone)]
pub struct AluSanitizeResult {
    /// Primary action
    pub action: AluSanitizeAction,
    /// Whether to patch the instruction
    pub needs_patch: bool,
    /// Computed limit for bounds checking
    pub alu_limit: u32,
    /// Whether operation is within known safe bounds
    pub is_safe: bool,
}

impl Default for AluSanitizeResult {
    fn default() -> Self {
        Self {
            action: AluSanitizeAction::None,
            needs_patch: false,
            alu_limit: 0,
            is_safe: true,
        }
    }
}

/// Sanitize ALU operation for Spectre mitigation
/// 
/// This function determines what sanitization is needed for an ALU operation
/// to prevent speculative execution attacks.
pub fn sanitize_alu_op(
    state: &BpfVerifierState,
    insn: &BpfInsn,
    dst_reg: usize,
    src_reg: usize,
    allow_ptr_leaks: bool,
) -> Result<AluSanitizeResult> {
    let mut result = AluSanitizeResult::default();
    
    if !sanitize_needed(allow_ptr_leaks) {
        return Ok(result);
    }

    let dst = state.reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;
    
    // Only pointer arithmetic needs sanitization
    if !dst.is_pointer() {
        return Ok(result);
    }

    let opcode = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    
    // Only ADD and SUB are relevant for pointer arithmetic
    if opcode != BPF_ADD && opcode != BPF_SUB {
        return Ok(result);
    }

    // Get the scalar operand's bounds
    let (smin, _smax, _umin, umax) = if src_type == BPF_X {
        let src = state.reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
        (src.smin_value, src.smax_value, src.umin_value, src.umax_value)
    } else {
        let imm = insn.imm as i64;
        (imm, imm, imm as u64, imm as u64)
    };

    // Compute pointer limit
    let ptr_limit = retrieve_ptr_limit(dst, insn.off as i32, false)?;
    
    // Check if operation is within safe bounds
    let is_add = opcode == BPF_ADD;
    let max_offset = if is_add { umax } else { (-smin) as u64 };
    
    if ptr_limit.is_exact && max_offset <= ptr_limit.umax {
        result.is_safe = true;
        return Ok(result);
    }

    // Need sanitization
    result.is_safe = false;
    result.needs_patch = true;
    
    // Determine sanitization strategy
    if ptr_limit.is_exact {
        // Can use bounds check
        result.action = AluSanitizeAction::BoundsCheck { limit: ptr_limit.umax };
        result.alu_limit = ptr_limit.umax as u32;
    } else {
        // Use pointer masking
        result.action = AluSanitizeAction::PointerMask;
    }

    Ok(result)
}

/// Compute ALU limit for sanitization patching
/// 
/// Returns the limit value to use for masking/bounds checking
pub fn compute_alu_limit(
    state: &BpfVerifierState,
    dst_reg: usize,
    off: i32,
) -> Result<u32> {
    let dst = state.reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

    let ptr_limit = retrieve_ptr_limit(dst, off, false)?;
    
    if ptr_limit.is_exact {
        Ok(ptr_limit.umax as u32)
    } else {
        // Can't compute exact limit
        Ok(u32::MAX)
    }
}

/// Generate ALU sanitization patch
/// 
/// Creates the instruction(s) needed to sanitize an ALU operation
pub fn generate_alu_sanitize_patch(
    insn: &BpfInsn,
    result: &AluSanitizeResult,
) -> Vec<BpfInsn> {
    let mut patches = Vec::new();
    
    match result.action {
        AluSanitizeAction::None => {}
        AluSanitizeAction::IndexMask { mask } => {
            // AND src_reg, mask (before the ALU op)
            if insn.code & 0x08 == BPF_X {
                patches.push(BpfInsn::new(
                    BPF_ALU64 | BPF_AND | BPF_K,
                    insn.src_reg,
                    0,
                    0,
                    mask as i32,
                ));
            }
        }
        AluSanitizeAction::PointerMask => {
            // Generate pointer masking sequence
            // This is architecture-specific, here's a generic version
            // JIT will replace with appropriate instructions
            patches.push(BpfInsn::new(
                BPF_ALU64 | BPF_AND | BPF_K,
                insn.dst_reg,
                0,
                0,
                -1, // Placeholder - JIT replaces
            ));
        }
        AluSanitizeAction::BoundsCheck { limit } => {
            // Insert bounds check before operation
            // if (offset > limit) goto error;
            // This needs JIT support for the actual implementation
            let _ = limit;
        }
        AluSanitizeAction::BarrierBefore => {
            // Insert LFENCE/speculation barrier before
            patches.push(make_nospec_insn());
        }
        AluSanitizeAction::BarrierAfter => {
            // Barrier goes after - handled separately
        }
    }
    
    patches
}

/// Create a nospec barrier instruction
fn make_nospec_insn() -> BpfInsn {
    // JA +0 is used as a placeholder that JIT converts to appropriate barrier
    BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0)
}

/// Sanitize memory access for speculative safety
pub fn sanitize_mem_access(
    state: &BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    allow_ptr_leaks: bool,
) -> Result<AluSanitizeResult> {
    let mut result = AluSanitizeResult::default();
    
    if !sanitize_needed(allow_ptr_leaks) {
        return Ok(result);
    }

    if !reg.is_pointer() {
        return Ok(result);
    }

    // Check if access is within validated bounds
    let ptr_limit = retrieve_ptr_limit(reg, off, is_write)?;
    
    if ptr_limit.is_exact && (size as u64) <= ptr_limit.umax {
        // Access is within bounds
        result.is_safe = true;
        return Ok(result);
    }

    // Need speculation barrier
    result.is_safe = false;
    result.needs_patch = true;
    result.action = AluSanitizeAction::BarrierBefore;
    
    let _ = state; // Used for additional context if needed
    Ok(result)
}

// ============================================================================
// Pointer Masking for Spectre Mitigation
// ============================================================================

/// Pointer masking configuration
#[derive(Debug, Clone)]
pub struct PointerMaskConfig {
    /// Whether to use software masking
    pub use_software_mask: bool,
    /// Whether hardware has built-in mitigation
    pub has_hardware_mitigation: bool,
    /// Mask value for array bounds (power of 2 - 1)
    pub array_mask: u64,
    /// Whether to mask after every pointer arithmetic
    pub aggressive_masking: bool,
}

impl Default for PointerMaskConfig {
    fn default() -> Self {
        Self {
            use_software_mask: true,
            has_hardware_mitigation: false,
            array_mask: u64::MAX,
            aggressive_masking: false,
        }
    }
}

/// Compute pointer mask for array access
/// 
/// The mask ensures that even under speculation, the index cannot
/// exceed the array bounds.
pub fn compute_array_mask(array_size: u64) -> u64 {
    if array_size == 0 {
        return 0;
    }
    // Round up to power of 2, then subtract 1 for mask
    let mut mask = array_size - 1;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    mask |= mask >> 32;
    mask
}

/// Generate pointer masking instructions
/// 
/// Inserts instructions to mask a pointer after arithmetic to prevent
/// speculative out-of-bounds access.
pub fn generate_ptr_mask_insns(
    ptr_reg: u8,
    scratch_reg: u8,
    limit: u64,
) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    
    // Strategy: Use arithmetic right shift to create a mask
    // if ptr > limit, mask becomes 0, otherwise ~0
    
    // r_scratch = ptr - limit
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        scratch_reg,
        ptr_reg,
        0,
        0,
    ));
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_SUB | BPF_K,
        scratch_reg,
        0,
        0,
        limit as i32,
    ));
    
    // r_scratch >>= 63 (arithmetic: fills with sign bit)
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ARSH | BPF_K,
        scratch_reg,
        0,
        0,
        63,
    ));
    
    // ptr &= r_scratch
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_AND | BPF_X,
        ptr_reg,
        scratch_reg,
        0,
        0,
    ));
    
    insns
}

/// Check if JIT can bypass sanitization for this access
/// 
/// Some accesses are provably safe even under speculation
pub fn can_jit_bypass_sanitize(
    reg: &BpfRegState,
    off: i32,
    size: u32,
) -> bool {
    // Same logic as check_jit_spectre_bypass but exported
    check_jit_spectre_bypass(reg, off, size)
}

// ============================================================================
// Comprehensive Sanitization Pass
// ============================================================================

/// Run full sanitization analysis on a program
pub fn analyze_program_sanitization(
    state: &BpfVerifierState,
    insns: &[BpfInsn],
    config: &SpectreConfig,
) -> SanitizationReport {
    let mut report = SanitizationReport::default();
    
    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();
        
        match class {
            BPF_ALU | BPF_ALU64 => {
                let opcode = insn.code & 0xf0;
                if opcode == BPF_ADD || opcode == BPF_SUB {
                    // Check if this is pointer arithmetic
                    let dst_reg = insn.dst_reg as usize;
                    if let Some(dst) = state.reg(dst_reg) {
                        if dst.is_pointer() {
                            report.ptr_alu_count += 1;
                            
                            // Analyze for sanitization needs
                            if let Ok(result) = sanitize_alu_op(
                                state, insn, dst_reg, insn.src_reg as usize, false
                            ) {
                                if result.needs_patch {
                                    report.sanitize_needed.push(idx);
                                    report.actions.push((idx, result.action));
                                }
                            }
                        }
                    }
                }
            }
            BPF_LDX | BPF_STX | BPF_ST => {
                // Memory access
                report.mem_access_count += 1;
                
                let base_reg = if class == BPF_LDX {
                    insn.src_reg as usize
                } else {
                    insn.dst_reg as usize
                };
                
                if let Some(reg) = state.reg(base_reg) {
                    if reg.is_pointer() && !reg.var_off.is_const() {
                        // Variable offset memory access
                        report.var_offset_access.push(idx);
                    }
                }
            }
            BPF_JMP | BPF_JMP32 => {
                let opcode = insn.code & 0xf0;
                if opcode != BPF_JA && opcode != BPF_EXIT && opcode != BPF_CALL {
                    // Conditional branch
                    report.cond_branch_count += 1;
                    
                    if config.mitigate_v1 {
                        report.spectre_v1_sources.push(idx);
                    }
                }
            }
            _ => {}
        }
    }
    
    report
}

/// Sanitization analysis report
#[derive(Debug, Clone, Default)]
pub struct SanitizationReport {
    /// Number of pointer ALU operations
    pub ptr_alu_count: usize,
    /// Number of memory accesses
    pub mem_access_count: usize,
    /// Number of conditional branches
    pub cond_branch_count: usize,
    /// Instruction indices needing sanitization
    pub sanitize_needed: Vec<usize>,
    /// Actions for each instruction
    pub actions: Vec<(usize, AluSanitizeAction)>,
    /// Variable offset memory accesses
    pub var_offset_access: Vec<usize>,
    /// Potential Spectre v1 sources
    pub spectre_v1_sources: Vec<usize>,
}

impl SanitizationReport {
    /// Check if any sanitization is needed
    pub fn needs_sanitization(&self) -> bool {
        !self.sanitize_needed.is_empty()
    }
    
    /// Get total number of mitigations needed
    pub fn mitigation_count(&self) -> usize {
        self.sanitize_needed.len()
    }
}

// ============================================================================
// Enhanced Spectre v1 Analysis
// ============================================================================

/// Spectre v1 gadget types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreV1GadgetType {
    /// Bounds check bypass - array[untrusted_idx]
    BoundsCheckBypass,
    /// Type confusion - accessing wrong variant
    TypeConfusion,
    /// Pointer leak - reading kernel pointer
    PointerLeak,
    /// Data leak - reading sensitive kernel data
    DataLeak,
    /// Control flow hijack - indirect call with tainted target
    ControlFlowHijack,
}

/// Detailed Spectre v1 gadget information
#[derive(Debug, Clone)]
pub struct SpectreV1Gadget {
    /// Type of gadget
    pub gadget_type: SpectreV1GadgetType,
    /// Instruction index of the conditional branch
    pub branch_idx: usize,
    /// Instruction index of the vulnerable access
    pub access_idx: usize,
    /// Register involved in the gadget
    pub reg: u8,
    /// Description of the vulnerability
    pub description: String,
    /// Recommended mitigation
    pub mitigation: MitigationStrategy,
    /// Whether this is on the speculative path
    pub is_speculative: bool,
}

/// Track speculative execution paths after conditional branches
#[derive(Debug, Clone, Default)]
pub struct SpeculativePathTracker {
    /// Stack of branch points (insn_idx, is_taken_path)
    branch_stack: Vec<(usize, bool)>,
    /// Instructions on current speculative path
    speculative_insns: Vec<usize>,
    /// Depth of speculative execution (number of unresolved branches)
    speculation_depth: usize,
    /// Maximum speculation window (instructions)
    max_window: usize,
}

impl SpeculativePathTracker {
    /// Create new tracker with default speculation window
    pub fn new() -> Self {
        Self {
            branch_stack: Vec::new(),
            speculative_insns: Vec::new(),
            speculation_depth: 0,
            max_window: 128, // Conservative speculation window
        }
    }

    /// Create tracker with custom speculation window
    pub fn with_window(max_window: usize) -> Self {
        Self {
            max_window,
            ..Self::new()
        }
    }

    /// Enter a conditional branch point
    pub fn enter_branch(&mut self, insn_idx: usize, is_taken: bool) {
        self.branch_stack.push((insn_idx, is_taken));
        self.speculation_depth += 1;
    }

    /// Exit a branch (branch resolved)
    pub fn exit_branch(&mut self) {
        if let Some(_) = self.branch_stack.pop() {
            self.speculation_depth = self.speculation_depth.saturating_sub(1);
        }
    }

    /// Check if currently on a speculative path
    pub fn is_speculative(&self) -> bool {
        self.speculation_depth > 0
    }

    /// Record an instruction on the speculative path
    pub fn record_insn(&mut self, insn_idx: usize) {
        if self.is_speculative() {
            self.speculative_insns.push(insn_idx);
            
            // Limit speculative window
            if self.speculative_insns.len() > self.max_window {
                self.speculative_insns.remove(0);
            }
        }
    }

    /// Check if an instruction is within the speculation window
    pub fn in_speculation_window(&self, insn_idx: usize) -> bool {
        self.speculative_insns.contains(&insn_idx)
    }

    /// Get the most recent branch point
    pub fn current_branch(&self) -> Option<(usize, bool)> {
        self.branch_stack.last().copied()
    }

    /// Get speculation depth
    pub fn depth(&self) -> usize {
        self.speculation_depth
    }

    /// Clear all state
    pub fn clear(&mut self) {
        self.branch_stack.clear();
        self.speculative_insns.clear();
        self.speculation_depth = 0;
    }
}

/// Taint tracking for Spectre v1 analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpectreV1Taint {
    /// Register is not tainted
    #[default]
    Clean,
    /// Register contains attacker-controlled value
    Tainted,
    /// Register is derived from tainted value
    Derived,
    /// Register was bounds-checked but may be bypassed speculatively
    SpeculativeTainted,
}

impl SpectreV1Taint {
    /// Check if tainted in any form
    pub fn is_tainted(&self) -> bool {
        !matches!(self, SpectreV1Taint::Clean)
    }

    /// Propagate taint through operation
    pub fn propagate(&self, other: &SpectreV1Taint) -> SpectreV1Taint {
        match (self, other) {
            (SpectreV1Taint::Clean, SpectreV1Taint::Clean) => SpectreV1Taint::Clean,
            (SpectreV1Taint::Tainted, _) | (_, SpectreV1Taint::Tainted) => {
                SpectreV1Taint::Tainted
            }
            _ => SpectreV1Taint::Derived,
        }
    }
}

/// Track taint state for Spectre v1 analysis
#[derive(Debug, Clone)]
pub struct SpectreV1TaintTracker {
    /// Taint state for each register
    reg_taint: [SpectreV1Taint; 11],
    /// Instructions that introduced taint
    taint_sources: Vec<usize>,
    /// Bounds checks that may be bypassed
    bypassed_checks: Vec<usize>,
}

impl Default for SpectreV1TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SpectreV1TaintTracker {
    /// Create new taint tracker
    pub fn new() -> Self {
        Self {
            reg_taint: [SpectreV1Taint::Clean; 11],
            taint_sources: Vec::new(),
            bypassed_checks: Vec::new(),
        }
    }

    /// Mark register as tainted from external input
    pub fn taint_from_input(&mut self, reg: usize, insn_idx: usize) {
        if reg < 11 {
            self.reg_taint[reg] = SpectreV1Taint::Tainted;
            self.taint_sources.push(insn_idx);
        }
    }

    /// Mark register as speculatively tainted (after bounds check)
    pub fn mark_speculative_taint(&mut self, reg: usize, check_idx: usize) {
        if reg < 11 && self.reg_taint[reg].is_tainted() {
            self.reg_taint[reg] = SpectreV1Taint::SpeculativeTainted;
            self.bypassed_checks.push(check_idx);
        }
    }

    /// Propagate taint for ALU operation
    pub fn propagate_alu(&mut self, dst: usize, src: usize) {
        if dst < 11 && src < 11 {
            let new_taint = self.reg_taint[dst].propagate(&self.reg_taint[src]);
            self.reg_taint[dst] = new_taint;
        }
    }

    /// Clear taint (after sanitization)
    pub fn clear_taint(&mut self, reg: usize) {
        if reg < 11 {
            self.reg_taint[reg] = SpectreV1Taint::Clean;
        }
    }

    /// Get taint state
    pub fn get_taint(&self, reg: usize) -> SpectreV1Taint {
        if reg < 11 {
            self.reg_taint[reg]
        } else {
            SpectreV1Taint::Clean
        }
    }

    /// Check if register is tainted
    pub fn is_tainted(&self, reg: usize) -> bool {
        self.get_taint(reg).is_tainted()
    }
}

/// Enhanced Spectre v1 analyzer
#[derive(Debug)]
pub struct SpectreV1Analyzer {
    /// Taint tracking
    taint: SpectreV1TaintTracker,
    /// Path tracking
    path: SpeculativePathTracker,
    /// Detected gadgets
    gadgets: Vec<SpectreV1Gadget>,
    /// Configuration
    config: SpectreConfig,
}

impl SpectreV1Analyzer {
    /// Create new analyzer
    pub fn new(config: SpectreConfig) -> Self {
        Self {
            taint: SpectreV1TaintTracker::new(),
            path: SpeculativePathTracker::new(),
            gadgets: Vec::new(),
            config,
        }
    }

    /// Analyze a conditional branch instruction
    pub fn analyze_branch(
        &mut self,
        state: &BpfVerifierState,
        insn: &BpfInsn,
        insn_idx: usize,
        is_taken: bool,
    ) {
        let dst_reg = insn.dst_reg as usize;
        
        // Enter speculative path
        self.path.enter_branch(insn_idx, is_taken);
        
        // If the branch condition involves tainted data, mark as potential gadget source
        if self.taint.is_tainted(dst_reg) {
            // After the branch, the value is "bounds checked" but speculatively tainted
            self.taint.mark_speculative_taint(dst_reg, insn_idx);
        }
        
        // Also check source register for comparisons
        let src_reg = insn.src_reg as usize;
        if self.taint.is_tainted(src_reg) {
            self.taint.mark_speculative_taint(src_reg, insn_idx);
        }
        
        // Check for wide bounds that suggest array indexing
        if let Some(reg) = state.reg(dst_reg) {
            if reg.reg_type == BpfRegType::ScalarValue {
                let range = reg.umax_value.saturating_sub(reg.umin_value);
                if range > 256 && self.taint.is_tainted(dst_reg) {
                    // This is a potential Spectre v1 gadget source
                    self.gadgets.push(SpectreV1Gadget {
                        gadget_type: SpectreV1GadgetType::BoundsCheckBypass,
                        branch_idx: insn_idx,
                        access_idx: insn_idx, // Will be updated when access is found
                        reg: dst_reg as u8,
                        description: format!(
                            "bounds check on tainted R{} with range {}",
                            dst_reg, range
                        ),
                        mitigation: MitigationStrategy::IndexMasking,
                        is_speculative: true,
                    });
                }
            }
        }
    }

    /// Analyze a memory access instruction
    pub fn analyze_memory_access(
        &mut self,
        state: &BpfVerifierState,
        insn: &BpfInsn,
        insn_idx: usize,
    ) {
        // Record this instruction on speculative path
        self.path.record_insn(insn_idx);
        
        let class = insn.code & 0x07;
        let is_load = class == 0x01 || class == 0x61; // LDX or LD
        
        // Get the base register
        let base_reg = if is_load {
            insn.src_reg as usize
        } else {
            insn.dst_reg as usize
        };
        
        // Check if on speculative path with tainted offset
        if self.path.is_speculative() {
            if let Some(reg) = state.reg(base_reg) {
                // Variable offset memory access on speculative path
                if reg.is_pointer() && !reg.var_off.is_const() {
                    // Check if offset might be tainted
                    if self.taint.get_taint(base_reg) == SpectreV1Taint::SpeculativeTainted {
                        if let Some((branch_idx, _)) = self.path.current_branch() {
                            self.gadgets.push(SpectreV1Gadget {
                                gadget_type: SpectreV1GadgetType::BoundsCheckBypass,
                                branch_idx,
                                access_idx: insn_idx,
                                reg: base_reg as u8,
                                description: format!(
                                    "speculative memory access through R{} with variable offset",
                                    base_reg
                                ),
                                mitigation: MitigationStrategy::PointerSanitization,
                                is_speculative: true,
                            });
                        }
                    }
                }
            }
        }
        
        // For loads, propagate taint to destination
        if is_load {
            let dst_reg = insn.dst_reg as usize;
            // If loading from tainted address, result is tainted
            if self.taint.is_tainted(base_reg) {
                self.taint.taint_from_input(dst_reg, insn_idx);
            }
        }
    }

    /// Analyze a helper call for potential Spectre gadgets
    pub fn analyze_helper_call(
        &mut self,
        _state: &BpfVerifierState,
        _insn: &BpfInsn,
        insn_idx: usize,
        func_id: u32,
    ) {
        // Record on speculative path
        self.path.record_insn(insn_idx);
        
        // Certain helpers can be gadget targets
        // map_lookup returns pointer that could leak data
        const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;
        
        if func_id == BPF_FUNC_MAP_LOOKUP_ELEM {
            // R1 contains map, R2 contains key - if key is tainted, potential gadget
            if self.taint.is_tainted(2) && self.path.is_speculative() {
                if let Some((branch_idx, _)) = self.path.current_branch() {
                    self.gadgets.push(SpectreV1Gadget {
                        gadget_type: SpectreV1GadgetType::DataLeak,
                        branch_idx,
                        access_idx: insn_idx,
                        reg: 2,
                        description: "map lookup with speculatively tainted key".into(),
                        mitigation: MitigationStrategy::SpeculationBarrier,
                        is_speculative: true,
                    });
                }
            }
            
            // Return value (R0) could point to sensitive data
            // Mark as potentially tainted if on speculative path
            if self.path.is_speculative() {
                self.taint.taint_from_input(0, insn_idx);
            }
        }
    }

    /// Analyze an ALU operation
    pub fn analyze_alu(&mut self, insn: &BpfInsn, insn_idx: usize) {
        self.path.record_insn(insn_idx);
        
        let dst_reg = insn.dst_reg as usize;
        let src_type = insn.code & 0x08;
        
        if src_type == 0x08 { // BPF_X - register source
            let src_reg = insn.src_reg as usize;
            self.taint.propagate_alu(dst_reg, src_reg);
        }
        // Immediate operations don't introduce taint
    }

    /// Mark a register as receiving external (potentially attacker-controlled) input
    pub fn mark_external_input(&mut self, reg: usize, insn_idx: usize) {
        self.taint.taint_from_input(reg, insn_idx);
    }

    /// Apply sanitization to a register
    pub fn apply_sanitization(&mut self, reg: usize) {
        self.taint.clear_taint(reg);
    }

    /// Get detected gadgets
    pub fn get_gadgets(&self) -> &[SpectreV1Gadget] {
        &self.gadgets
    }

    /// Generate mitigation patches
    pub fn generate_patches(&self) -> Vec<SpectreBarrierPatch> {
        let mut patches = Vec::new();
        
        for gadget in &self.gadgets {
            match gadget.mitigation {
                MitigationStrategy::SpeculationBarrier => {
                    // Insert barrier after the branch
                    patches.push(SpectreBarrierPatch {
                        insn_idx: gadget.branch_idx + 1,
                        barrier_type: BarrierType::BpfNospec,
                    });
                }
                MitigationStrategy::IndexMasking => {
                    // Masking is done at access site
                    patches.push(SpectreBarrierPatch {
                        insn_idx: gadget.access_idx,
                        barrier_type: BarrierType::BpfNospec,
                    });
                }
                MitigationStrategy::PointerSanitization => {
                    // Barrier before memory access
                    patches.push(SpectreBarrierPatch {
                        insn_idx: gadget.access_idx,
                        barrier_type: BarrierType::BpfNospec,
                    });
                }
                _ => {}
            }
        }
        
        // Deduplicate patches
        patches.sort_by_key(|p| p.insn_idx);
        patches.dedup_by_key(|p| p.insn_idx);
        
        patches
    }

    /// Check if speculation barrier is needed at instruction
    pub fn needs_barrier(&self, insn_idx: usize) -> bool {
        self.gadgets.iter().any(|g| {
            g.branch_idx == insn_idx || g.access_idx == insn_idx
        })
    }

    /// Get summary statistics
    pub fn summary(&self) -> SpectreV1Summary {
        SpectreV1Summary {
            total_gadgets: self.gadgets.len(),
            bounds_bypass: self.gadgets.iter()
                .filter(|g| g.gadget_type == SpectreV1GadgetType::BoundsCheckBypass)
                .count(),
            data_leaks: self.gadgets.iter()
                .filter(|g| g.gadget_type == SpectreV1GadgetType::DataLeak)
                .count(),
            pointer_leaks: self.gadgets.iter()
                .filter(|g| g.gadget_type == SpectreV1GadgetType::PointerLeak)
                .count(),
            speculation_depth: self.path.depth(),
        }
    }
}

/// Summary of Spectre v1 analysis
#[derive(Debug, Clone, Default)]
pub struct SpectreV1Summary {
    /// Total gadgets found
    pub total_gadgets: usize,
    /// Bounds check bypass gadgets
    pub bounds_bypass: usize,
    /// Data leak gadgets
    pub data_leaks: usize,
    /// Pointer leak gadgets
    pub pointer_leaks: usize,
    /// Current speculation depth
    pub speculation_depth: usize,
}

/// Full program Spectre v1 analysis
pub fn analyze_program_spectre_v1(
    state: &BpfVerifierState,
    insns: &[BpfInsn],
    config: &SpectreConfig,
) -> (Vec<SpectreV1Gadget>, Vec<SpectreBarrierPatch>) {
    if !config.mitigate_v1 {
        return (Vec::new(), Vec::new());
    }
    
    let mut analyzer = SpectreV1Analyzer::new(config.clone());
    
    // Mark initial inputs as potentially tainted
    // R1 = context pointer (trusted)
    // Other args may be attacker-controlled depending on program type
    
    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.code & 0x07;
        let opcode = insn.code & 0xf0;
        
        match class {
            0x05 | 0x06 => { // JMP, JMP32
                if opcode >= 0x10 && opcode <= 0xd0 && opcode != 0x00 {
                    // Conditional jump
                    analyzer.analyze_branch(state, insn, idx, true);
                }
            }
            0x00 | 0x07 => { // ALU64, ALU
                analyzer.analyze_alu(insn, idx);
            }
            0x01 | 0x02 | 0x03 => { // LDX, ST, STX
                analyzer.analyze_memory_access(state, insn, idx);
            }
            _ => {}
        }
        
        // Check for helper calls
        if class == 0x05 && opcode == 0x80 { // CALL
            analyzer.analyze_helper_call(state, insn, idx, insn.imm as u32);
        }
    }
    
    let gadgets = analyzer.get_gadgets().to_vec();
    let patches = analyzer.generate_patches();
    
    (gadgets, patches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_needed() {
        assert!(sanitize_needed(false)); // Unprivileged
        assert!(!sanitize_needed(true)); // Privileged
    }

    #[test]
    fn test_error_recoverable() {
        assert!(error_recoverable_with_nospec(
            &VerifierError::PermissionDenied("test".into())
        ));
        assert!(error_recoverable_with_nospec(
            &VerifierError::InvalidMemoryAccess("test".into())
        ));
        assert!(!error_recoverable_with_nospec(
            &VerifierError::InvalidInstruction(0)
        ));
    }

    #[test]
    fn test_can_skip_sanitation() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        
        // Scalar destination - can skip
        assert!(can_skip_alu_sanitation(&reg, None));
        
        // Pointer destination - cannot skip with unknown source
        reg.reg_type = BpfRegType::PtrToStack;
        assert!(!can_skip_alu_sanitation(&reg, None));
        
        // Pointer with const source - can skip
        let mut src = BpfRegState::default();
        src.reg_type = BpfRegType::ScalarValue;
        src.mark_known(100);
        assert!(can_skip_alu_sanitation(&reg, Some(&src)));
    }

    #[test]
    fn test_ptr_limit_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        
        let limit = retrieve_ptr_limit(&reg, 0, false).unwrap();
        assert_eq!(limit.umax, 16);
        assert!(limit.is_exact);
    }

    #[test]
    fn test_insn_aux_data() {
        let mut aux = InsnAuxData::new();
        assert!(!aux.seen);
        assert!(!aux.needs_nospec_barrier);
        
        sanitize_mark_insn_seen(&mut aux, true);
        assert!(aux.seen);
        assert!(aux.needs_nospec_barrier);
    }

    #[test]
    fn test_sanitize_state() {
        let mut state = SanitizeState::None;
        assert_eq!(state, SanitizeState::None);
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMapValue;
        
        update_alu_sanitation_state(&mut state, &reg, None);
        assert_eq!(state, SanitizeState::NeedsBarrier);
    }

    // ========================================================================
    // Enhanced Spectre v1 Tests
    // ========================================================================

    #[test]
    fn test_speculative_path_tracker() {
        let mut tracker = SpeculativePathTracker::new();
        
        assert!(!tracker.is_speculative());
        assert_eq!(tracker.depth(), 0);
        
        // Enter a branch
        tracker.enter_branch(10, true);
        assert!(tracker.is_speculative());
        assert_eq!(tracker.depth(), 1);
        assert_eq!(tracker.current_branch(), Some((10, true)));
        
        // Record instructions
        tracker.record_insn(11);
        tracker.record_insn(12);
        assert!(tracker.in_speculation_window(11));
        assert!(tracker.in_speculation_window(12));
        
        // Enter nested branch
        tracker.enter_branch(13, false);
        assert_eq!(tracker.depth(), 2);
        
        // Exit one branch
        tracker.exit_branch();
        assert_eq!(tracker.depth(), 1);
        
        // Exit all
        tracker.exit_branch();
        assert!(!tracker.is_speculative());
    }

    #[test]
    fn test_spectre_v1_taint() {
        assert!(!SpectreV1Taint::Clean.is_tainted());
        assert!(SpectreV1Taint::Tainted.is_tainted());
        assert!(SpectreV1Taint::Derived.is_tainted());
        assert!(SpectreV1Taint::SpeculativeTainted.is_tainted());
    }

    #[test]
    fn test_spectre_v1_taint_propagation() {
        let clean = SpectreV1Taint::Clean;
        let tainted = SpectreV1Taint::Tainted;
        let derived = SpectreV1Taint::Derived;
        
        // Clean + Clean = Clean
        assert_eq!(clean.propagate(&clean), SpectreV1Taint::Clean);
        
        // Tainted + anything = Tainted
        assert_eq!(tainted.propagate(&clean), SpectreV1Taint::Tainted);
        assert_eq!(clean.propagate(&tainted), SpectreV1Taint::Tainted);
        
        // Derived + Derived = Derived
        assert_eq!(derived.propagate(&derived), SpectreV1Taint::Derived);
    }

    #[test]
    fn test_spectre_v1_taint_tracker() {
        let mut tracker = SpectreV1TaintTracker::new();
        
        // Initially clean
        assert!(!tracker.is_tainted(0));
        
        // Taint from input
        tracker.taint_from_input(1, 5);
        assert!(tracker.is_tainted(1));
        assert_eq!(tracker.get_taint(1), SpectreV1Taint::Tainted);
        
        // Propagate taint
        tracker.propagate_alu(2, 1);
        assert!(tracker.is_tainted(2));
        
        // Clear taint
        tracker.clear_taint(1);
        assert!(!tracker.is_tainted(1));
        
        // Mark speculative
        tracker.taint_from_input(3, 10);
        tracker.mark_speculative_taint(3, 15);
        assert_eq!(tracker.get_taint(3), SpectreV1Taint::SpeculativeTainted);
    }

    #[test]
    fn test_spectre_v1_analyzer_creation() {
        let config = SpectreConfig::default();
        let analyzer = SpectreV1Analyzer::new(config);
        
        assert!(analyzer.get_gadgets().is_empty());
    }

    #[test]
    fn test_spectre_v1_gadget_types() {
        // Test all gadget types exist
        let _bounds = SpectreV1GadgetType::BoundsCheckBypass;
        let _confusion = SpectreV1GadgetType::TypeConfusion;
        let _ptr_leak = SpectreV1GadgetType::PointerLeak;
        let _data_leak = SpectreV1GadgetType::DataLeak;
        let _hijack = SpectreV1GadgetType::ControlFlowHijack;
    }

    #[test]
    fn test_spectre_v1_summary() {
        let summary = SpectreV1Summary::default();
        
        assert_eq!(summary.total_gadgets, 0);
        assert_eq!(summary.bounds_bypass, 0);
        assert_eq!(summary.data_leaks, 0);
        assert_eq!(summary.pointer_leaks, 0);
    }

    #[test]
    fn test_spectre_v1_analyzer_external_input() {
        let config = SpectreConfig::default();
        let mut analyzer = SpectreV1Analyzer::new(config);
        
        // Mark external input
        analyzer.mark_external_input(2, 0);
        
        // Check it's tracked
        assert!(analyzer.taint.is_tainted(2));
    }

    #[test]
    fn test_spectre_v1_analyzer_sanitization() {
        let config = SpectreConfig::default();
        let mut analyzer = SpectreV1Analyzer::new(config);
        
        // Taint then sanitize
        analyzer.mark_external_input(3, 0);
        assert!(analyzer.taint.is_tainted(3));
        
        analyzer.apply_sanitization(3);
        assert!(!analyzer.taint.is_tainted(3));
    }

    #[test]
    fn test_speculative_path_window_limit() {
        let mut tracker = SpeculativePathTracker::with_window(3);
        
        tracker.enter_branch(0, true);
        
        // Add more than window size
        tracker.record_insn(1);
        tracker.record_insn(2);
        tracker.record_insn(3);
        tracker.record_insn(4); // Should push out insn 1
        
        assert!(!tracker.in_speculation_window(1));
        assert!(tracker.in_speculation_window(2));
        assert!(tracker.in_speculation_window(3));
        assert!(tracker.in_speculation_window(4));
    }

    #[test]
    fn test_spectre_config_default() {
        let config = SpectreConfig::default();
        
        assert!(config.mitigate_v1);
        assert!(config.mitigate_v2);
        assert!(config.mitigate_v4);
        assert!(!config.aggressive);
        assert!(config.allow_jit_bypass);
    }
}
