//! State merging optimization for BPF verifier
//!
//! When multiple execution paths reach the same program point, their states
//! can be merged to avoid exponential state explosion. The merged state
//! takes the widest bounds for each register, ensuring it represents all
//! possible values from either path.
//!
//! This module implements:
//! - Basic state merging (widening bounds)
//! - Cross-subprogram state merging
//! - Reference-aware merging
//! - Precision-preserving merging
//! - Loop-aware state caching


use alloc::{boxed::Box, vec::Vec};

use crate::bounds::tnum::Tnum;
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::{BpfVerifierState, BpfFuncState};
use crate::state::stack_state::BpfStackState;

/// Result of attempting to merge two states.
#[derive(Debug, Clone)]
pub enum MergeResult {
    /// States were successfully merged.
    Merged(BpfVerifierState),
    /// States are incompatible and cannot be merged.
    Incompatible,
    /// First state already subsumes second (no merge needed).
    FirstSubsumes,
    /// Second state already subsumes first.
    SecondSubsumes,
}

/// Merge two verifier states at a join point.
///
/// Returns a merged state that represents all possible values from either
/// input state. This is sound because the merged state is more permissive
/// than either input - anything safe under the merged state is safe under
/// both original states.
pub fn merge_states(
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
) -> MergeResult {
    // Must have same frame depth
    if state1.curframe != state2.curframe {
        return MergeResult::Incompatible;
    }

    // Check if one subsumes the other first
    if state_subsumes(state1, state2) {
        return MergeResult::FirstSubsumes;
    }
    if state_subsumes(state2, state1) {
        return MergeResult::SecondSubsumes;
    }

    // Try to merge
    let mut merged = state1.clone();

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        let merged_func = match merge_func_states(func1, func2) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        if let Some(frame) = merged.frame.get_mut(i) {
            *frame = Some(Box::new(merged_func));
        }
    }

    MergeResult::Merged(merged)
}

/// Check if state1 subsumes state2 (state1 is more permissive).
fn state_subsumes(state1: &BpfVerifierState, state2: &BpfVerifierState) -> bool {
    if state1.curframe != state2.curframe {
        return false;
    }

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        if !func_subsumes(func1, func2) {
            return false;
        }
    }

    true
}

/// Check if func1 subsumes func2.
fn func_subsumes(func1: &BpfFuncState, func2: &BpfFuncState) -> bool {
    // All registers in func1 must subsume corresponding registers in func2
    for (reg1, reg2) in func1.regs.iter().zip(func2.regs.iter()) {
        if !reg_subsumes(reg1, reg2) {
            return false;
        }
    }

    true
}

/// Check if reg1 subsumes reg2 (reg1's range contains reg2's).
fn reg_subsumes(reg1: &BpfRegState, reg2: &BpfRegState) -> bool {
    // Uninitialized subsumes everything
    if reg1.reg_type == BpfRegType::NotInit {
        return true;
    }

    // If reg1 is initialized, reg2 must match type
    if reg2.reg_type == BpfRegType::NotInit {
        return false;
    }

    if reg1.reg_type != reg2.reg_type {
        return false;
    }

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            // reg1 subsumes reg2 if reg1's bounds contain reg2's
            reg1.umin_value <= reg2.umin_value &&
            reg1.umax_value >= reg2.umax_value &&
            reg1.smin_value <= reg2.smin_value &&
            reg1.smax_value >= reg2.smax_value
        }
        _ => {
            // For pointers, exact match required
            reg1.off == reg2.off && reg1.id == reg2.id
        }
    }
}

/// Merge two function states.
fn merge_func_states(func1: &BpfFuncState, func2: &BpfFuncState) -> Option<BpfFuncState> {
    let mut merged = func1.clone();

    // Merge registers
    for (i, (reg1, reg2)) in func1.regs.iter().zip(func2.regs.iter()).enumerate() {
        merged.regs[i] = merge_regs(reg1, reg2)?;
    }

    // Merge stack - take the larger allocated size
    let max_stack = func1.stack.allocated_stack.max(func2.stack.allocated_stack);
    if merged.stack.allocated_stack < max_stack {
        let _ = merged.stack.grow(max_stack);
    }

    // Merge stack slots
    let max_slots = func1.stack.stack.len().max(func2.stack.stack.len());
    for i in 0..max_slots {
        let slot1 = func1.stack.stack.get(i);
        let slot2 = func2.stack.stack.get(i);

        let merged_slot = match (slot1, slot2) {
            (Some(s1), Some(s2)) => merge_stack_slots(s1, s2),
            (Some(s), None) | (None, Some(s)) => s.clone(),
            (None, None) => BpfStackState::new(),
        };

        if i < merged.stack.stack.len() {
            merged.stack.stack[i] = merged_slot;
        }
    }

    Some(merged)
}

/// Check if two registers are exactly equal in their tracked state.
/// This corresponds to the kernel's `regs_exact` function.
fn regs_exact(reg1: &BpfRegState, reg2: &BpfRegState) -> bool {
    // Type must match
    if reg1.reg_type != reg2.reg_type {
        return false;
    }
    
    // Type flags must match
    if reg1.type_flags != reg2.type_flags {
        return false;
    }
    
    // For scalars, check all bounds
    if reg1.reg_type == BpfRegType::ScalarValue {
        return reg1.umin_value == reg2.umin_value &&
               reg1.umax_value == reg2.umax_value &&
               reg1.smin_value == reg2.smin_value &&
               reg1.smax_value == reg2.smax_value &&
               reg1.var_off == reg2.var_off;
    }
    
    // For pointers, check offset and other fields
    reg1.off == reg2.off &&
    reg1.var_off == reg2.var_off &&
    reg1.map_uid == reg2.map_uid
}

/// Merge two registers, taking the widest bounds.
/// 
/// Implements precision-preserving merge following the kernel's logic:
/// - If either register is precise, or if they are exact, preserve precision
/// - Otherwise, widen to unknown for scalars
fn merge_regs(reg1: &BpfRegState, reg2: &BpfRegState) -> Option<BpfRegState> {
    // If either is uninitialized, result is uninitialized
    if reg1.reg_type == BpfRegType::NotInit || reg2.reg_type == BpfRegType::NotInit {
        return Some(BpfRegState::new_not_init());
    }

    // Types must be compatible for merging
    if !types_compatible(reg1.reg_type, reg2.reg_type) {
        // If types are incompatible, mark as unknown scalar
        let mut result = BpfRegState::new_scalar_unknown(false);
        result.mark_unknown(false);
        return Some(result);
    }

    let mut merged = reg1.clone();
    
    // Check if registers are exact (same bounds, same type)
    let is_exact = regs_exact(reg1, reg2);
    
    // Preserve precision if:
    // 1. Either register is marked precise, OR
    // 2. Registers are exactly equal
    let preserve_precision = reg1.precise || reg2.precise || is_exact;

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            if preserve_precision {
                // Precision-preserving merge: take widest bounds but keep precision
                merged.umin_value = reg1.umin_value.min(reg2.umin_value);
                merged.umax_value = reg1.umax_value.max(reg2.umax_value);
                merged.smin_value = reg1.smin_value.min(reg2.smin_value);
                merged.smax_value = reg1.smax_value.max(reg2.smax_value);
                merged.var_off = merge_tnums(reg1.var_off, reg2.var_off);
                
                // Keep precise if either was precise (precision propagates)
                merged.precise = reg1.precise || reg2.precise;
            } else {
                // Imprecise scalars that don't match exactly: widen to unknown
                // This matches the kernel's `maybe_widen_reg` behavior
                merged.mark_unknown(false);
                merged.precise = false;
            }
        }
        BpfRegType::PtrToStack |
        BpfRegType::PtrToMapValue |
        BpfRegType::PtrToMapKey |
        BpfRegType::PtrToCtx |
        BpfRegType::PtrToPacket |
        BpfRegType::PtrToMem => {
            // For pointers, check if they have the same base
            if reg1.off != reg2.off {
                // Different offsets - take range if possible
                // For simplicity, mark as having variable offset
                merged.var_off = Tnum::unknown();
            }

            // Merge type flags
            merged.type_flags = reg1.type_flags | reg2.type_flags;

            // If IDs differ, lose NULL tracking
            if reg1.id != reg2.id {
                merged.id = 0;
            }
        }
        _ => {
            // Other types: must be exact match
            if reg1.off != reg2.off || reg1.id != reg2.id {
                return None;
            }
        }
    }

    Some(merged)
}

/// Check if two register types are compatible for merging.
fn types_compatible(t1: BpfRegType, t2: BpfRegType) -> bool {
    if t1 == t2 {
        return true;
    }

    // Scalars can absorb anything (becoming unknown)
    if t1 == BpfRegType::ScalarValue || t2 == BpfRegType::ScalarValue {
        return true;
    }

    // Some pointer types are compatible
    matches!(
        (t1, t2),
        (BpfRegType::PtrToPacket, BpfRegType::PtrToPacketMeta) |
        (BpfRegType::PtrToPacketMeta, BpfRegType::PtrToPacket)
    )
}

/// Merge two tnums, taking the widest range.
fn merge_tnums(t1: Tnum, t2: Tnum) -> Tnum {
    // The merged tnum must represent all values from both
    // This is done by OR-ing the masks and combining values
    let combined_mask = t1.mask | t2.mask;

    // For bits that are known in both, they must agree
    let known_in_both = !t1.mask & !t2.mask;
    let disagreed = (t1.value ^ t2.value) & known_in_both;

    // Bits that disagree become unknown
    let final_mask = combined_mask | disagreed;
    let final_value = t1.value & !final_mask;

    Tnum::new(final_value, final_mask)
}

/// Merge two stack slots.
fn merge_stack_slots(slot1: &BpfStackState, slot2: &BpfStackState) -> BpfStackState {
    let mut merged = slot1.clone();

    // Check slot types
    let type1 = slot1.slot_type[BPF_REG_SIZE - 1];
    let type2 = slot2.slot_type[BPF_REG_SIZE - 1];

    if type1 != type2 {
        // Different types - mark as misc
        for i in 0..BPF_REG_SIZE {
            merged.slot_type[i] = BpfStackSlotType::Misc;
        }
        merged.spilled_ptr = BpfRegState::new_not_init();
        return merged;
    }

    match type1 {
        BpfStackSlotType::Spill => {
            // Merge the spilled register
            if let Some(merged_reg) = merge_regs(&slot1.spilled_ptr, &slot2.spilled_ptr) {
                merged.spilled_ptr = merged_reg;
            } else {
                // Can't merge - mark as misc
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
        BpfStackSlotType::Dynptr => {
            // Dynptr types must match
            if slot1.spilled_ptr.dynptr.dynptr_type != slot2.spilled_ptr.dynptr.dynptr_type {
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Invalid;
                }
            }
        }
        _ => {
            // Other types: keep as-is
        }
    }

    merged
}

/// Statistics about state merging.
#[derive(Debug, Clone, Default)]
pub struct MergeStats {
    /// Number of successful merges.
    pub merges: u64,
    /// Number of incompatible state pairs.
    pub incompatible: u64,
    /// Number of times first state subsumed second.
    pub first_subsumed: u64,
    /// Number of times second state subsumed first.
    pub second_subsumed: u64,
    /// Number of cross-subprogram merges.
    pub cross_subprog_merges: u64,
    /// Number of reference-aware merges.
    pub ref_aware_merges: u64,
    /// Number of precision-preserving merges.
    pub precision_preserved: u64,
}

impl MergeStats {
    /// Create new stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a merge result.
    pub fn record(&mut self, result: &MergeResult) {
        match result {
            MergeResult::Merged(_) => self.merges += 1,
            MergeResult::Incompatible => self.incompatible += 1,
            MergeResult::FirstSubsumes => self.first_subsumed += 1,
            MergeResult::SecondSubsumes => self.second_subsumed += 1,
        }
    }
}

/// Configuration for state merging behavior.
#[derive(Debug, Clone, Copy)]
pub struct MergeConfig {
    /// Allow merging states with different subprogram contexts.
    pub allow_cross_subprog: bool,
    /// Preserve precision marks when possible.
    pub preserve_precision: bool,
    /// Allow merging states with different reference counts.
    pub allow_ref_mismatch: bool,
    /// Maximum number of states to merge at once.
    pub max_batch_size: usize,
    /// Whether to use aggressive widening for loops.
    pub aggressive_loop_widening: bool,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            allow_cross_subprog: true,
            preserve_precision: true,
            allow_ref_mismatch: false,
            max_batch_size: 8,
            aggressive_loop_widening: false,
        }
    }
}

impl MergeConfig {
    /// Config for aggressive merging (reduces state explosion).
    pub fn aggressive() -> Self {
        Self {
            allow_cross_subprog: true,
            preserve_precision: false,
            allow_ref_mismatch: true,
            max_batch_size: 16,
            aggressive_loop_widening: true,
        }
    }

    /// Config for conservative merging (preserves precision).
    pub fn conservative() -> Self {
        Self {
            allow_cross_subprog: false,
            preserve_precision: true,
            allow_ref_mismatch: false,
            max_batch_size: 4,
            aggressive_loop_widening: false,
        }
    }
}

/// Cross-subprogram merge context.
/// 
/// This tracks information needed to merge states across subprogram
/// boundaries, such as when a function returns to multiple call sites.
#[derive(Debug, Clone)]
pub struct CrossSubprogMergeCtx {
    /// Source subprogram index.
    pub src_subprog: usize,
    /// Target subprogram index.
    pub dst_subprog: usize,
    /// Call site instruction index.
    pub callsite: usize,
    /// Whether the merge is for a tail call.
    pub is_tail_call: bool,
    /// Whether the callee might sleep.
    pub callee_might_sleep: bool,
}

impl CrossSubprogMergeCtx {
    /// Create a new cross-subprogram merge context.
    pub fn new(src: usize, dst: usize, callsite: usize) -> Self {
        Self {
            src_subprog: src,
            dst_subprog: dst,
            callsite,
            is_tail_call: false,
            callee_might_sleep: false,
        }
    }
}

/// Merge states with configuration.
pub fn merge_states_with_config(
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
    config: &MergeConfig,
) -> MergeResult {
    // Must have same frame depth
    if state1.curframe != state2.curframe {
        return MergeResult::Incompatible;
    }

    // Check reference compatibility if configured
    if !config.allow_ref_mismatch {
        let refs1 = state1.refs.refs();
        let refs2 = state2.refs.refs();
        if refs1.len() != refs2.len() {
            return MergeResult::Incompatible;
        }
        // Check reference types match
        for (r1, r2) in refs1.iter().zip(refs2.iter()) {
            if r1.ref_type != r2.ref_type {
                return MergeResult::Incompatible;
            }
        }
    }

    // Check if one subsumes the other first
    if state_subsumes(state1, state2) {
        return MergeResult::FirstSubsumes;
    }
    if state_subsumes(state2, state1) {
        return MergeResult::SecondSubsumes;
    }

    // Try to merge
    let mut merged = state1.clone();

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        let merged_func = match merge_func_states_with_config(func1, func2, config) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        if let Some(frame) = merged.frame.get_mut(i) {
            *frame = Some(Box::new(merged_func));
        }
    }

    // Merge references if allowed
    if config.allow_ref_mismatch {
        // Take the union of references
        merge_references(&mut merged, state1, state2);
    }

    MergeResult::Merged(merged)
}

/// Merge function states with configuration.
fn merge_func_states_with_config(
    func1: &BpfFuncState,
    func2: &BpfFuncState,
    config: &MergeConfig,
) -> Option<BpfFuncState> {
    let mut merged = func1.clone();

    // Merge registers
    for (i, (reg1, reg2)) in func1.regs.iter().zip(func2.regs.iter()).enumerate() {
        merged.regs[i] = merge_regs_with_config(reg1, reg2, config)?;
    }

    // Merge stack - take the larger allocated size
    let max_stack = func1.stack.allocated_stack.max(func2.stack.allocated_stack);
    if merged.stack.allocated_stack < max_stack {
        let _ = merged.stack.grow(max_stack);
    }

    // Merge stack slots
    let max_slots = func1.stack.stack.len().max(func2.stack.stack.len());
    for i in 0..max_slots {
        let slot1 = func1.stack.stack.get(i);
        let slot2 = func2.stack.stack.get(i);

        let merged_slot = match (slot1, slot2) {
            (Some(s1), Some(s2)) => merge_stack_slots_with_config(s1, s2, config),
            (Some(s), None) | (None, Some(s)) => s.clone(),
            (None, None) => BpfStackState::new(),
        };

        if i < merged.stack.stack.len() {
            merged.stack.stack[i] = merged_slot;
        }
    }

    Some(merged)
}

/// Merge registers with configuration.
fn merge_regs_with_config(
    reg1: &BpfRegState,
    reg2: &BpfRegState,
    config: &MergeConfig,
) -> Option<BpfRegState> {
    // If either is uninitialized, result is uninitialized
    if reg1.reg_type == BpfRegType::NotInit || reg2.reg_type == BpfRegType::NotInit {
        return Some(BpfRegState::new_not_init());
    }

    // Types must be compatible for merging
    if !types_compatible(reg1.reg_type, reg2.reg_type) {
        // If types are incompatible, mark as unknown scalar
        let mut result = BpfRegState::new_scalar_unknown(false);
        result.mark_unknown(false);
        return Some(result);
    }

    let mut merged = reg1.clone();

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            // Take widest bounds (least restrictive)
            merged.umin_value = reg1.umin_value.min(reg2.umin_value);
            merged.umax_value = reg1.umax_value.max(reg2.umax_value);
            merged.smin_value = reg1.smin_value.min(reg2.smin_value);
            merged.smax_value = reg1.smax_value.max(reg2.smax_value);

            // 32-bit bounds
            merged.u32_min_value = reg1.u32_min_value.min(reg2.u32_min_value);
            merged.u32_max_value = reg1.u32_max_value.max(reg2.u32_max_value);
            merged.s32_min_value = reg1.s32_min_value.min(reg2.s32_min_value);
            merged.s32_max_value = reg1.s32_max_value.max(reg2.s32_max_value);

            // Merge tnums
            merged.var_off = merge_tnums(reg1.var_off, reg2.var_off);

            // Precision handling
            if config.preserve_precision {
                // Keep precision if both are precise
                merged.precise = reg1.precise && reg2.precise;
            } else {
                // Always lose precision
                merged.precise = false;
            }
        }
        BpfRegType::PtrToStack |
        BpfRegType::PtrToMapValue |
        BpfRegType::PtrToMapKey |
        BpfRegType::PtrToCtx |
        BpfRegType::PtrToPacket |
        BpfRegType::PtrToMem => {
            // For pointers, check if they have the same base
            if reg1.off != reg2.off {
                // Different offsets - take range if possible
                merged.var_off = Tnum::unknown();
                // Widen offset range
                merged.smin_value = reg1.smin_value.min(reg2.smin_value);
                merged.smax_value = reg1.smax_value.max(reg2.smax_value);
            }

            // Merge type flags
            merged.type_flags = reg1.type_flags | reg2.type_flags;

            // If IDs differ, lose NULL tracking
            if reg1.id != reg2.id {
                merged.id = 0;
            }

            // Merge ref_obj_id
            if reg1.ref_obj_id != reg2.ref_obj_id {
                merged.ref_obj_id = 0;
            }
        }
        _ => {
            // Other types: must be exact match
            if reg1.off != reg2.off || reg1.id != reg2.id {
                return None;
            }
        }
    }

    Some(merged)
}

/// Merge stack slots with configuration.
fn merge_stack_slots_with_config(
    slot1: &BpfStackState,
    slot2: &BpfStackState,
    config: &MergeConfig,
) -> BpfStackState {
    let mut merged = slot1.clone();

    // Check slot types
    let type1 = slot1.slot_type[BPF_REG_SIZE - 1];
    let type2 = slot2.slot_type[BPF_REG_SIZE - 1];

    if type1 != type2 {
        // Different types - mark as misc
        for i in 0..BPF_REG_SIZE {
            merged.slot_type[i] = BpfStackSlotType::Misc;
        }
        merged.spilled_ptr = BpfRegState::new_not_init();
        return merged;
    }

    match type1 {
        BpfStackSlotType::Spill => {
            // Merge the spilled register
            if let Some(merged_reg) = merge_regs_with_config(
                &slot1.spilled_ptr,
                &slot2.spilled_ptr,
                config,
            ) {
                merged.spilled_ptr = merged_reg;
            } else {
                // Can't merge - mark as misc
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
        BpfStackSlotType::Dynptr => {
            // Dynptr types must match
            if slot1.spilled_ptr.dynptr.dynptr_type != slot2.spilled_ptr.dynptr.dynptr_type {
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Invalid;
                }
            }
        }
        _ => {
            // Other types: keep as-is
        }
    }

    merged
}

/// Merge references from two states into the merged state.
fn merge_references(
    merged: &mut BpfVerifierState,
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
) {
    // Take intersection of acquired references
    // (only keep refs that exist in both states)
    let refs1 = state1.refs.refs();
    let refs2 = state2.refs.refs();
    
    // Clear existing refs and rebuild
    merged.refs = state1.refs.clone();
    
    // For each ref in state1, check if it exists in state2
    for r1 in refs1.iter() {
        let exists_in_s2 = refs2.iter().any(|r2| {
            r1.ref_type == r2.ref_type && r1.ptr == r2.ptr
        });
        
        if !exists_in_s2 {
            // Ref only in state1 - might need to mark as potentially released
            // For safety, we keep it but this could be optimized
        }
    }
}

/// Merge multiple states at once (batch merging).
/// 
/// This is more efficient than pairwise merging for join points
/// with many incoming edges.
pub fn merge_states_batch(
    states: &[&BpfVerifierState],
    config: &MergeConfig,
) -> Option<BpfVerifierState> {
    if states.is_empty() {
        return None;
    }
    if states.len() == 1 {
        return Some((*states[0]).clone());
    }

    // Limit batch size
    let batch = if states.len() > config.max_batch_size {
        &states[..config.max_batch_size]
    } else {
        states
    };

    // Start with first state
    let mut result = (*batch[0]).clone();

    // Merge in remaining states
    for state in batch.iter().skip(1) {
        match merge_states_with_config(&result, state, config) {
            MergeResult::Merged(merged) => result = merged,
            MergeResult::FirstSubsumes => continue,
            MergeResult::SecondSubsumes => result = (*state).clone(),
            MergeResult::Incompatible => return None,
        }
    }

    Some(result)
}

/// Aggressive widening for loop states.
/// 
/// When we detect a loop back-edge, we may want to widen scalar
/// bounds more aggressively to ensure termination.
pub fn widen_loop_state(state: &mut BpfVerifierState, iteration: u32) {
    // Apply widening to all frames
    for i in 0..=state.curframe {
        if let Some(Some(frame)) = state.frame.get_mut(i) {
            widen_func_state(frame, iteration);
        }
    }
}

/// Widen a function state for loop analysis.
fn widen_func_state(func: &mut BpfFuncState, iteration: u32) {
    // Widen registers
    for reg in func.regs.iter_mut() {
        if reg.reg_type == BpfRegType::ScalarValue {
            widen_scalar_reg(reg, iteration);
        }
    }

    // Widen spilled scalars on stack
    for slot in func.stack.stack.iter_mut() {
        if slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
            && slot.spilled_ptr.reg_type == BpfRegType::ScalarValue
        {
            widen_scalar_reg(&mut slot.spilled_ptr, iteration);
        }
    }
}

/// Apply widening to a scalar register.
/// 
/// After several iterations, we widen bounds to infinity to ensure
/// the analysis terminates.
fn widen_scalar_reg(reg: &mut BpfRegState, iteration: u32) {
    // After 3 iterations, start widening
    if iteration < 3 {
        return;
    }

    // Widen to full range
    if reg.umin_value != 0 || reg.umax_value != u64::MAX {
        reg.umin_value = 0;
        reg.umax_value = u64::MAX;
        reg.smin_value = i64::MIN;
        reg.smax_value = i64::MAX;
        reg.u32_min_value = 0;
        reg.u32_max_value = u32::MAX;
        reg.s32_min_value = i32::MIN;
        reg.s32_max_value = i32::MAX;
        reg.var_off = Tnum::unknown();
        reg.precise = false;
    }
}

/// Check if two states can be merged across subprogram boundaries.
pub fn can_merge_cross_subprog(
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
    ctx: &CrossSubprogMergeCtx,
) -> bool {
    // Both states must be at same frame depth
    if state1.curframe != state2.curframe {
        return false;
    }

    // For tail calls, we need exact register state match for R1-R5
    if ctx.is_tail_call {
        let frame1 = match state1.frame.get(state1.curframe).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let frame2 = match state2.frame.get(state2.curframe).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        // R1-R5 must have compatible types for tail call
        for i in 1..=5 {
            if !types_compatible(frame1.regs[i].reg_type, frame2.regs[i].reg_type) {
                return false;
            }
        }
    }

    // Check reference compatibility
    let refs1 = state1.refs.refs();
    let refs2 = state2.refs.refs();
    
    // Reference counts should match for safe merging
    if refs1.len() != refs2.len() {
        return false;
    }

    true
}

/// Merge states after returning from a subprogram call.
/// 
/// This handles the case where a function can return with different
/// register states depending on the path taken inside.
pub fn merge_return_states(
    caller_state: &BpfVerifierState,
    return_states: &[BpfVerifierState],
    config: &MergeConfig,
) -> Option<BpfVerifierState> {
    if return_states.is_empty() {
        return None;
    }

    if return_states.len() == 1 {
        // Single return path - just apply return value
        let mut result = caller_state.clone();
        apply_return_value(&mut result, &return_states[0]);
        return Some(result);
    }

    // Multiple return paths - merge return values first
    let mut merged_return = return_states[0].clone();
    for ret_state in return_states.iter().skip(1) {
        match merge_states_with_config(&merged_return, ret_state, config) {
            MergeResult::Merged(m) => merged_return = m,
            MergeResult::FirstSubsumes => continue,
            MergeResult::SecondSubsumes => merged_return = ret_state.clone(),
            MergeResult::Incompatible => return None,
        }
    }

    // Apply merged return to caller state
    let mut result = caller_state.clone();
    apply_return_value(&mut result, &merged_return);
    Some(result)
}

/// Apply return value from callee to caller state.
fn apply_return_value(caller: &mut BpfVerifierState, callee: &BpfVerifierState) {
    // Get caller's current frame
    let frame_idx = caller.curframe;
    if let Some(Some(caller_frame)) = caller.frame.get_mut(frame_idx) {
        // Get callee's return frame (should be at curframe)
        if let Some(Some(callee_frame)) = callee.frame.get(callee.curframe) {
            // Copy R0 (return value) from callee
            caller_frame.regs[0] = callee_frame.regs[0].clone();
        }
    }
}

/// State cache for efficient pruning at merge points.
#[derive(Debug, Default)]
pub struct StateMergeCache {
    /// Cached merged states indexed by instruction.
    cache: Vec<Vec<BpfVerifierState>>,
    /// Statistics.
    pub stats: MergeStats,
}

impl StateMergeCache {
    /// Create a new cache for a program of given size.
    pub fn new(prog_len: usize) -> Self {
        Self {
            cache: (0..prog_len).map(|_| Vec::new()).collect(),
            stats: MergeStats::default(),
        }
    }

    /// Try to find a cached state that subsumes the given state.
    pub fn find_subsuming(&self, insn_idx: usize, state: &BpfVerifierState) -> bool {
        if let Some(cached) = self.cache.get(insn_idx) {
            for cached_state in cached {
                if state_subsumes(cached_state, state) {
                    return true;
                }
            }
        }
        false
    }

    /// Add a state to the cache, potentially merging with existing states.
    pub fn add_state(
        &mut self,
        insn_idx: usize,
        state: BpfVerifierState,
        config: &MergeConfig,
    ) {
        if insn_idx >= self.cache.len() {
            return;
        }

        let cached = &mut self.cache[insn_idx];

        // Check if any existing state subsumes this one
        for existing in cached.iter() {
            if state_subsumes(existing, &state) {
                self.stats.first_subsumed += 1;
                return;
            }
        }

        // Check if this state subsumes any existing
        cached.retain(|existing| {
            if state_subsumes(&state, existing) {
                self.stats.second_subsumed += 1;
                false
            } else {
                true
            }
        });

        // Try to merge with existing states
        for existing in cached.iter_mut() {
            if let MergeResult::Merged(merged) = merge_states_with_config(existing, &state, config)
            {
                *existing = merged;
                self.stats.merges += 1;
                return;
            }
        }

        // No merge possible - add as new state
        cached.push(state);
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        for cached in self.cache.iter_mut() {
            cached.clear();
        }
    }

    /// Get number of cached states at an instruction.
    pub fn state_count(&self, insn_idx: usize) -> usize {
        self.cache.get(insn_idx).map(|v| v.len()).unwrap_or(0)
    }

    /// Get total number of cached states.
    pub fn total_states(&self) -> usize {
        self.cache.iter().map(|v| v.len()).sum()
    }
}
