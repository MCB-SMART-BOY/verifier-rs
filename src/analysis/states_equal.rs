// SPDX-License-Identifier: GPL-2.0

//! Comprehensive state equivalence checking for pruning
//!
//! This module implements the full `states_equal` logic from the kernel verifier.
//! State equivalence is crucial for efficient verification - it allows us to prune
//! exploration when we reach a state that's "at least as restrictive" as one we've
//! already verified.

use alloc::collections::BTreeMap as HashMap;

use crate::core::types::{BpfRegType, BpfStackSlotType, BpfTypeFlag, BPF_REG_SIZE, MAX_BPF_REG};
use crate::state::reference::BpfReferenceState;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::BpfStackState;
use crate::state::verifier_state::{BpfFuncState, BpfVerifierState};

/// ID mapping for comparing states with different ID assignments
#[derive(Debug, Default)]
pub struct IdMap {
    /// Maps old IDs to current IDs
    map: HashMap<u32, u32>,
}

impl IdMap {
    /// Create a new empty ID map
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all ID mappings
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Check if two IDs are equivalent, recording the mapping if new
    pub fn check_ids(&mut self, cur_id: u32, old_id: u32) -> bool {
        // ID 0 means "no ID" - always matches
        if old_id == 0 {
            return true;
        }
        if cur_id == 0 {
            return false;
        }

        // Check if we've seen this old_id before
        if let Some(&mapped_cur) = self.map.get(&old_id) {
            // Must map to the same cur_id
            return mapped_cur == cur_id;
        }

        // New mapping - record it
        self.map.insert(old_id, cur_id);
        true
    }
}

/// Comparison mode for state equivalence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompareMode {
    /// Not exact - allows subsumption (cur more restrictive than old)
    #[default]
    NotExact,
    /// Exact match required (for loop detection)
    Exact,
    /// Range within - cur's ranges must be within old's ranges
    /// Used for iterator convergence detection, may_goto, and callback detection
    RangeWithin,
}

/// Configuration for state comparison
#[derive(Debug, Clone, Copy)]
pub struct CompareConfig {
    /// Comparison mode
    pub mode: CompareMode,
    /// Whether to check precision marks
    pub check_precision: bool,
    /// Whether to compare reference states
    pub check_refs: bool,
    /// Whether to compare lock states
    pub check_locks: bool,
}

impl Default for CompareConfig {
    fn default() -> Self {
        Self {
            mode: CompareMode::NotExact,
            check_precision: true,
            check_refs: true,
            check_locks: true,
        }
    }
}

impl CompareConfig {
    /// Config for pruning - allows subsumption
    pub fn for_pruning() -> Self {
        Self::default()
    }

    /// Config for loop detection - requires exact match
    pub fn for_loop_detection() -> Self {
        Self {
            mode: CompareMode::Exact,
            check_precision: false,
            check_refs: true,
            check_locks: true,
        }
    }

    /// Config for range-within checking (iterators, may_goto, callbacks)
    ///
    /// This mode is used when we want to check if the current state's
    /// scalar ranges are within the old state's ranges, but we don't
    /// require exact matches. This is important for:
    /// - Iterator convergence detection (iter_next)
    /// - may_goto depth checking
    /// - Callback function detection
    pub fn for_range_within() -> Self {
        Self {
            mode: CompareMode::RangeWithin,
            check_precision: false,
            check_refs: true,
            check_locks: true,
        }
    }

    /// Helper: is this exact matching mode?
    pub fn exact(&self) -> bool {
        self.mode == CompareMode::Exact
    }

    /// Helper: is this range-within mode?
    pub fn range_within(&self) -> bool {
        self.mode == CompareMode::RangeWithin
    }
}

/// Check if two verifier states are equivalent using default config
pub fn states_equal(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    states_equal_with_config(cur, old, &CompareConfig::default())
}

/// Check if two verifier states are equivalent with custom config
pub fn states_equal_with_config(
    cur: &BpfVerifierState,
    old: &BpfVerifierState,
    config: &CompareConfig,
) -> bool {
    let mut idmap = IdMap::new();
    states_equal_with_idmap(cur, old, config, &mut idmap)
}

/// Check state equivalence with explicit ID mapping
pub fn states_equal_with_idmap(
    cur: &BpfVerifierState,
    old: &BpfVerifierState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must have same frame depth
    if cur.curframe != old.curframe {
        return false;
    }

    // Check all frames from bottom to top
    for i in 0..=cur.curframe {
        let cur_func = match cur.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let old_func = match old.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        if !func_states_equal(cur_func, old_func, config, idmap) {
            return false;
        }
    }

    // Check references if configured
    if config.check_refs && !refs_equal(&cur.refs, &old.refs, idmap) {
        return false;
    }

    // Check lock state if configured
    if config.check_locks {
        if cur.refs.active_locks != old.refs.active_locks {
            return false;
        }
        if cur.refs.active_rcu_locks != old.refs.active_rcu_locks {
            return false;
        }
    }

    true
}

/// Check if two function states are equivalent
fn func_states_equal(
    cur: &BpfFuncState,
    old: &BpfFuncState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must have same callsite
    if cur.callsite != old.callsite {
        return false;
    }

    // Check all registers
    for i in 0..MAX_BPF_REG {
        let cur_reg = &cur.regs[i];
        let old_reg = &old.regs[i];

        if !regsafe(cur_reg, old_reg, config, idmap) {
            return false;
        }
    }

    // Check stack
    if !stacksafe(cur, old, config, idmap) {
        return false;
    }

    true
}

/// Check if cur register is "safe" relative to old register
///
/// For pruning: cur can be pruned if it's at least as restrictive as old
/// For exact: cur must exactly match old
pub fn regsafe(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // If old is NOT_INIT, cur can be anything
    if old.reg_type == BpfRegType::NotInit {
        return true;
    }

    // If cur is NOT_INIT but old isn't, not safe
    if cur.reg_type == BpfRegType::NotInit {
        return false;
    }

    // Check precision requirement
    if config.check_precision && old.precise && !cur.precise {
        return false;
    }

    // Check type compatibility
    if !type_compatible(cur, old, config) {
        return false;
    }

    // Type-specific checks
    match cur.reg_type {
        BpfRegType::ScalarValue => regsafe_scalar(cur, old, config),
        BpfRegType::PtrToStack => regsafe_ptr_to_stack(cur, old, config, idmap),
        BpfRegType::PtrToMapValue | BpfRegType::PtrToMapKey | BpfRegType::ConstPtrToMap => {
            regsafe_ptr_to_map(cur, old, config, idmap)
        }
        BpfRegType::PtrToCtx => regsafe_ptr_to_ctx(cur, old, config),
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta | BpfRegType::PtrToPacketEnd => {
            regsafe_ptr_to_pkt(cur, old, config, idmap)
        }
        BpfRegType::PtrToBtfId => regsafe_ptr_to_btf_id(cur, old, config, idmap),
        BpfRegType::PtrToMem => regsafe_ptr_to_mem(cur, old, config, idmap),
        _ => {
            // For other pointer types, require exact match
            cur.off == old.off && cur.mem_size == old.mem_size
        }
    }
}

/// Check if types are compatible for comparison
fn type_compatible(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    if cur.reg_type == old.reg_type {
        return true;
    }

    if config.exact() {
        return false;
    }

    // Special case: PTR_MAYBE_NULL compatibility
    // If old might be NULL, cur can be non-NULL (more restrictive)
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL)
        && !cur.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL)
    {
        // Check base types match
        return cur.reg_type == old.reg_type;
    }

    false
}

/// Check scalar value equivalence
fn regsafe_scalar(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    if config.exact() {
        // Exact match required
        return cur.umin_value == old.umin_value
            && cur.umax_value == old.umax_value
            && cur.smin_value == old.smin_value
            && cur.smax_value == old.smax_value
            && cur.var_off == old.var_off;
    }

    if config.range_within() {
        // RANGE_WITHIN mode: cur's range must be within old's range
        // This is used for iterator convergence, may_goto, and callbacks.
        // Unlike NotExact mode, we require that old's bounds contain cur's bounds
        // completely, which is the inverse of subsumption.
        //
        // The semantics here: old represents a "superstate" that should encompass
        // all possible values that cur could take. If cur is within old's range,
        // we can safely prune because we've already explored the superstate.

        // Check 64-bit unsigned bounds: old's range must contain cur's range
        if cur.umin_value < old.umin_value || cur.umax_value > old.umax_value {
            return false;
        }

        // Check 64-bit signed bounds
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }

        // Check 32-bit bounds
        if cur.u32_min_value < old.u32_min_value || cur.u32_max_value > old.u32_max_value {
            return false;
        }
        if cur.s32_min_value < old.s32_min_value || cur.s32_max_value > old.s32_max_value {
            return false;
        }

        // For RANGE_WITHIN, we also require tnum subset relationship
        // This ensures that the known bits of cur are consistent with old
        if !cur.var_off.is_subset_of(&old.var_off) {
            return false;
        }

        return true;
    }

    // NotExact mode: Subsumption - cur must be within old's range
    // This means cur is MORE constrained than old (stricter bounds)
    // This is the standard pruning mode.

    // Check 64-bit unsigned bounds
    if cur.umin_value < old.umin_value || cur.umax_value > old.umax_value {
        return false;
    }

    // Check 64-bit signed bounds
    if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
        return false;
    }

    // Check 32-bit bounds
    if cur.u32_min_value < old.u32_min_value || cur.u32_max_value > old.u32_max_value {
        return false;
    }
    if cur.s32_min_value < old.s32_min_value || cur.s32_max_value > old.s32_max_value {
        return false;
    }

    // Check tnum: cur's known bits must include old's known bits
    // cur.var_off must be a subset of old.var_off
    if !cur.var_off.is_subset_of(&old.var_off) {
        return false;
    }

    true
}

/// Check pointer-to-stack equivalence
fn regsafe_ptr_to_stack(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Offsets must match
    if cur.off != old.off {
        return false;
    }

    // Check frame number (which stack frame this points to)
    if cur.frameno != old.frameno {
        return false;
    }

    // For variable offset pointers, check ranges
    if !config.exact() {
        // cur must be within old's range
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }
    } else if cur.smin_value != old.smin_value || cur.smax_value != old.smax_value {
        return false;
    }

    // Check ID for NULL tracking
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check pointer-to-map equivalence
fn regsafe_ptr_to_map(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must point to same map
    match (&cur.map_ptr, &old.map_ptr) {
        (Some(c), Some(o)) => {
            if c.map_type != o.map_type {
                return false;
            }
            // For map value pointers, check key/value sizes
            if c.key_size != o.key_size || c.value_size != o.value_size {
                return false;
            }
        }
        (None, Some(_)) => return false,
        _ => {}
    }

    // Check offset
    if config.exact() {
        if cur.off != old.off {
            return false;
        }
    } else {
        // cur's offset range must be within old's
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }
    }

    // Check NULL tracking
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check pointer-to-ctx equivalence
fn regsafe_ptr_to_ctx(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    // Context pointer offsets must match exactly
    if cur.off != old.off {
        return false;
    }

    // Check type flags match
    if config.exact() {
        cur.type_flags == old.type_flags
    } else {
        // cur can have fewer flags (more restrictive)
        old.type_flags.contains(cur.type_flags)
    }
}

/// Check packet pointer equivalence
fn regsafe_ptr_to_pkt(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Check ID for packet pointer tracking
    if !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    // Check offset and mem_size (used for packet range)
    if config.exact() {
        cur.off == old.off && cur.mem_size == old.mem_size
    } else {
        // cur must have same or smaller range
        cur.off == old.off && cur.mem_size <= old.mem_size
    }
}

/// Check BTF ID pointer equivalence
fn regsafe_ptr_to_btf_id(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must point to same BTF type
    if cur.btf_id() != old.btf_id() {
        return false;
    }

    // Check offset
    if cur.off != old.off {
        return false;
    }

    // Check reference ID for acquired references
    if old.ref_obj_id != 0 && !idmap.check_ids(cur.ref_obj_id, old.ref_obj_id) {
        return false;
    }

    // Check type flags
    let trust_flags =
        BpfTypeFlag::PTR_TRUSTED | BpfTypeFlag::PTR_UNTRUSTED | BpfTypeFlag::PTR_MAYBE_NULL;

    if config.exact() {
        (cur.type_flags & trust_flags) == (old.type_flags & trust_flags)
    } else {
        // cur can be more trusted than old
        if old.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED)
            && !cur.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED)
        {
            return true;
        }
        (cur.type_flags & trust_flags) == (old.type_flags & trust_flags)
    }
}

/// Check pointer-to-mem equivalence
fn regsafe_ptr_to_mem(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Check memory size
    if config.exact() {
        if cur.mem_size != old.mem_size {
            return false;
        }
    } else {
        // cur can have smaller (more restrictive) size
        if cur.mem_size > old.mem_size {
            return false;
        }
    }

    // Check offset
    if cur.off != old.off {
        return false;
    }

    // Check ID for NULL tracking
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check stack equivalence between two function states
fn stacksafe(
    cur: &BpfFuncState,
    old: &BpfFuncState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // cur must have at least as much stack allocated
    if cur.stack.allocated_stack < old.stack.allocated_stack {
        return false;
    }

    // Check each stack slot that old has initialized
    for (spi, old_slot) in old.stack.stack.iter().enumerate() {
        let cur_slot = match cur.stack.stack.get(spi) {
            Some(s) => s,
            None => return false,
        };

        if !stackslot_safe(cur_slot, old_slot, config, idmap) {
            return false;
        }
    }

    true
}

/// Check if cur stack slot is safe relative to old
pub fn stackslot_safe(
    cur: &BpfStackState,
    old: &BpfStackState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Get the primary slot type (from last byte)
    let cur_type = cur.slot_type[BPF_REG_SIZE - 1];
    let old_type = old.slot_type[BPF_REG_SIZE - 1];

    // If old is uninitialized, cur can be anything
    if old_type == BpfStackSlotType::Invalid {
        return true;
    }

    // MISC slots are compatible with anything initialized
    if old_type == BpfStackSlotType::Misc {
        return cur_type != BpfStackSlotType::Invalid;
    }

    // For exact matching, types must be identical
    if config.exact() && cur_type != old_type {
        return false;
    }

    match old_type {
        BpfStackSlotType::Spill => {
            if cur_type != BpfStackSlotType::Spill {
                // If old has a spill, cur must also have a spill
                // (unless cur has MISC which is compatible)
                if cur_type != BpfStackSlotType::Misc {
                    return false;
                }
                return true;
            }
            // Both are spills - compare the spilled values
            regsafe(&cur.spilled_ptr, &old.spilled_ptr, config, idmap)
        }
        BpfStackSlotType::Zero => {
            // Zero is compatible with zero or misc
            cur_type == BpfStackSlotType::Zero || cur_type == BpfStackSlotType::Misc
        }
        BpfStackSlotType::Dynptr => {
            if cur_type != BpfStackSlotType::Dynptr {
                return false;
            }
            // Dynptr types must match
            cur.spilled_ptr.dynptr.dynptr_type == old.spilled_ptr.dynptr.dynptr_type
        }
        BpfStackSlotType::Iter => {
            if cur_type != BpfStackSlotType::Iter {
                return false;
            }
            // Iterator state must match
            cur.spilled_ptr.iter.state == old.spilled_ptr.iter.state
                && cur.spilled_ptr.iter.depth == old.spilled_ptr.iter.depth
        }
        _ => true,
    }
}

/// Check reference state equivalence
fn refs_equal(
    cur: &crate::state::reference::ReferenceManager,
    old: &crate::state::reference::ReferenceManager,
    idmap: &mut IdMap,
) -> bool {
    let cur_refs = cur.refs();
    let old_refs = old.refs();

    // Must have same number of references
    if cur_refs.len() != old_refs.len() {
        return false;
    }

    // Check each reference (order matters)
    for (cur_ref, old_ref) in cur_refs.iter().zip(old_refs.iter()) {
        if !ref_state_equal(cur_ref, old_ref, idmap) {
            return false;
        }
    }

    true
}

/// Check if two reference states are equivalent
fn ref_state_equal(cur: &BpfReferenceState, old: &BpfReferenceState, idmap: &mut IdMap) -> bool {
    // Types must match
    if cur.ref_type != old.ref_type {
        return false;
    }

    // IDs must be mapped correctly
    if !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    // For locks, pointers must match
    if cur.ptr != old.ptr {
        return false;
    }

    true
}

/// Check if states might be in a loop (for bounded loop detection)
pub fn states_maybe_looping(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    // Quick check: if frames don't match, not looping
    if cur.curframe != old.curframe {
        return false;
    }

    // Check if any iterator has different depth
    // This indicates loop progress
    for i in 0..=cur.curframe {
        let cur_func = match cur.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let old_func = match old.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        // Check for iterator depth changes
        for (cur_slot, old_slot) in cur_func.stack.stack.iter().zip(old_func.stack.stack.iter()) {
            let cur_type = cur_slot.slot_type[BPF_REG_SIZE - 1];
            let old_type = old_slot.slot_type[BPF_REG_SIZE - 1];

            if cur_type == BpfStackSlotType::Iter
                && old_type == BpfStackSlotType::Iter
                && cur_slot.spilled_ptr.iter.depth != old_slot.spilled_ptr.iter.depth
            {
                // Different depths - making progress
                return false;
            }
        }
    }

    // States look similar - might be looping
    true
}
