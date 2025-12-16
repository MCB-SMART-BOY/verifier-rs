// SPDX-License-Identifier: GPL-2.0

//! Register state snapshot and comparison for state pruning.
//!
//! This module provides efficient state comparison to determine if a new
//! verification state is equivalent to or subsumed by a previously seen state,
//! enabling state pruning to avoid redundant verification paths.

use alloc::{boxed::Box, vec::Vec};

use alloc::collections::BTreeMap as HashMap;

use crate::core::types::{BpfRegType, MAX_BPF_REG};
use crate::state::reg_state::BpfRegState;

/// Snapshot of register state for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegSnapshot {
    /// Register type.
    pub reg_type: BpfRegType,
    /// Known bits value (tnum).
    pub tnum_value: u64,
    /// Known bits mask (tnum).
    pub tnum_mask: u64,
    /// Minimum signed value.
    pub smin: i64,
    /// Maximum signed value.
    pub smax: i64,
    /// Minimum unsigned value.
    pub umin: u64,
    /// Maximum unsigned value.
    pub umax: u64,
    /// Offset from base.
    pub off: i32,
    /// Minimum variable offset.
    pub var_off_min: i64,
    /// Maximum variable offset.
    pub var_off_max: i64,
    /// Reference ID if holding a reference.
    pub ref_obj_id: u32,
    /// Map UID if map pointer.
    pub map_uid: u32,
}

impl RegSnapshot {
    /// Create a snapshot from a register state.
    pub fn from_reg(reg: &BpfRegState) -> Self {
        Self {
            reg_type: reg.reg_type,
            tnum_value: reg.var_off.value,
            tnum_mask: reg.var_off.mask,
            smin: reg.smin_value,
            smax: reg.smax_value,
            umin: reg.umin_value,
            umax: reg.umax_value,
            off: reg.off,
            var_off_min: reg.var_off.min() as i64,
            var_off_max: reg.var_off.max() as i64,
            ref_obj_id: reg.ref_obj_id,
            map_uid: reg.map_uid,
        }
    }

    /// Check if this snapshot is "at least as precise" as another.
    /// Returns true if `self` represents a subset of possible values compared to `other`.
    pub fn is_substate_of(&self, other: &RegSnapshot) -> bool {
        // Type must match
        if self.reg_type != other.reg_type {
            // Special case: NOT_INIT is compatible with anything
            if other.reg_type == BpfRegType::NotInit {
                return true;
            }
            return false;
        }

        // For scalars, check value ranges
        if self.reg_type == BpfRegType::ScalarValue {
            // self's range must be within other's range
            if self.smin < other.smin || self.smax > other.smax {
                return false;
            }
            if self.umin < other.umin || self.umax > other.umax {
                return false;
            }
            // Tnum: self must have at least as many known bits
            // (self.mask must be subset of other.mask)
            if (self.tnum_mask & !other.tnum_mask) != 0 {
                return false;
            }
            // Known bits must match where both are known
            let common_known = !self.tnum_mask & !other.tnum_mask;
            if (self.tnum_value & common_known) != (other.tnum_value & common_known) {
                return false;
            }
        }

        // For pointers, offsets must match or be more precise
        if self.reg_type.is_ptr() {
            if self.off != other.off && other.off != 0 {
                return false;
            }
            // Variable offset range must be within
            if self.var_off_min < other.var_off_min || self.var_off_max > other.var_off_max {
                return false;
            }
        }

        // Reference IDs must match if present
        if self.ref_obj_id != 0 && other.ref_obj_id != 0 && self.ref_obj_id != other.ref_obj_id {
            return false;
        }

        // Map UIDs must match for map pointers
        if self.map_uid != 0 && other.map_uid != 0 && self.map_uid != other.map_uid {
            return false;
        }

        true
    }

    /// Check if this snapshot represents a scalar with a known constant value.
    pub fn is_const(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue && self.tnum_mask == 0
    }

    /// Get the constant value if this is a known constant.
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.tnum_value)
        } else {
            None
        }
    }
}

/// Snapshot of all registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegsSnapshot {
    /// Snapshots of all registers.
    pub regs: [RegSnapshot; MAX_BPF_REG],
}

impl RegsSnapshot {
    /// Create a snapshot from register states.
    pub fn from_regs(regs: &[BpfRegState; MAX_BPF_REG]) -> Self {
        let mut snapshots: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| RegSnapshot {
            reg_type: BpfRegType::NotInit,
            tnum_value: 0,
            tnum_mask: u64::MAX,
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            off: 0,
            var_off_min: i64::MIN,
            var_off_max: i64::MAX,
            ref_obj_id: 0,
            map_uid: 0,
        });

        for (i, reg) in regs.iter().enumerate() {
            snapshots[i] = RegSnapshot::from_reg(reg);
        }

        Self { regs: snapshots }
    }

    /// Check if this state is equivalent to or more precise than another.
    pub fn is_substate_of(&self, other: &RegsSnapshot) -> bool {
        for (self_reg, other_reg) in self.regs.iter().zip(other.regs.iter()) {
            if !self_reg.is_substate_of(other_reg) {
                return false;
            }
        }
        true
    }

    /// Compute a hash for quick inequality detection.
    pub fn quick_hash(&self) -> u64 {
        let mut hash: u64 = 0;
        for (i, reg) in self.regs.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(reg.reg_type as u64);
            hash = hash.wrapping_mul(31).wrapping_add(i as u64);
            if reg.reg_type == BpfRegType::ScalarValue {
                hash = hash.wrapping_mul(31).wrapping_add(reg.tnum_value);
            }
        }
        hash
    }
}

/// Stack slot snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StackSlotSnapshot {
    /// Slot type.
    pub slot_type: StackSlotType,
    /// Spilled register snapshot if applicable.
    pub spilled_reg: Option<Box<RegSnapshot>>,
}

/// Stack slot types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackSlotType {
    /// Slot not initialized.
    Invalid,
    /// Slot contains spilled register.
    Spill,
    /// Slot contains miscellaneous data.
    Misc,
    /// Slot contains zero.
    Zero,
}

/// Snapshot of stack state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSnapshot {
    /// Stack slots.
    pub slots: HashMap<i32, StackSlotSnapshot>,
    /// Lowest allocated offset.
    pub allocated_low: i32,
}

impl StackSnapshot {
    /// Create an empty stack snapshot.
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            allocated_low: 0,
        }
    }

    /// Add a slot to the snapshot.
    pub fn add_slot(
        &mut self,
        offset: i32,
        slot_type: StackSlotType,
        spilled: Option<RegSnapshot>,
    ) {
        self.slots.insert(
            offset,
            StackSlotSnapshot {
                slot_type,
                spilled_reg: spilled.map(Box::new),
            },
        );
        if offset < self.allocated_low {
            self.allocated_low = offset;
        }
    }

    /// Check if this stack state is subsumed by another.
    pub fn is_substate_of(&self, other: &StackSnapshot) -> bool {
        // All slots in self must be compatible with other
        for (offset, slot) in &self.slots {
            if let Some(other_slot) = other.slots.get(offset) {
                // Slot types should match
                if slot.slot_type != other_slot.slot_type {
                    // Invalid is compatible with anything
                    if other_slot.slot_type != StackSlotType::Invalid {
                        return false;
                    }
                }
                // Check spilled register if present
                if let (Some(self_spill), Some(other_spill)) =
                    (&slot.spilled_reg, &other_slot.spilled_reg)
                {
                    if !self_spill.is_substate_of(other_spill) {
                        return false;
                    }
                }
            }
            // If other doesn't have this slot, that's okay (other is less precise)
        }
        true
    }
}

impl Default for StackSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete verification state snapshot.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Register snapshot.
    pub regs: RegsSnapshot,
    /// Stack snapshot.
    pub stack: StackSnapshot,
    /// Current call depth.
    pub call_depth: u32,
    /// Active references.
    pub active_refs: Vec<u32>,
    /// Active locks.
    pub active_locks: Vec<u32>,
    /// Quick hash for fast comparison.
    pub hash: u64,
}

impl StateSnapshot {
    /// Create a new state snapshot.
    pub fn new(regs: RegsSnapshot, stack: StackSnapshot, call_depth: u32) -> Self {
        let hash = regs.quick_hash();
        Self {
            regs,
            stack,
            call_depth,
            active_refs: Vec::new(),
            active_locks: Vec::new(),
            hash,
        }
    }

    /// Check if this state is subsumed by another (for pruning).
    /// Returns true if verifying `self` is unnecessary because `other`
    /// already covers all possible behaviors.
    pub fn is_substate_of(&self, other: &StateSnapshot) -> bool {
        // Quick hash check for fast rejection
        // (Note: equal hashes don't guarantee equality)

        // Call depth must match
        if self.call_depth != other.call_depth {
            return false;
        }

        // Check registers
        if !self.regs.is_substate_of(&other.regs) {
            return false;
        }

        // Check stack
        if !self.stack.is_substate_of(&other.stack) {
            return false;
        }

        // Active references must be subset
        for ref_id in &self.active_refs {
            if !other.active_refs.contains(ref_id) {
                return false;
            }
        }

        // Active locks must match exactly
        if self.active_locks != other.active_locks {
            return false;
        }

        true
    }

    /// Add an active reference.
    pub fn add_ref(&mut self, ref_id: u32) {
        if !self.active_refs.contains(&ref_id) {
            self.active_refs.push(ref_id);
        }
    }

    /// Add an active lock.
    pub fn add_lock(&mut self, lock_id: u32) {
        if !self.active_locks.contains(&lock_id) {
            self.active_locks.push(lock_id);
        }
    }
}

/// State cache for pruning.
/// Cache for verification states used in pruning
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct StateCache {
    /// States indexed by instruction index.
    states: HashMap<usize, Vec<StateSnapshot>>,
    /// Statistics.
    pub hits: u64,
    pub misses: u64,
    pub stored: u64,
}

impl StateCache {
    /// Create a new state cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a state at the given instruction can be pruned.
    /// Returns true if verification can be skipped.
    pub fn check_prune(&mut self, insn_idx: usize, state: &StateSnapshot) -> bool {
        if let Some(cached_states) = self.states.get(&insn_idx) {
            for cached in cached_states {
                if state.is_substate_of(cached) {
                    self.hits += 1;
                    return true;
                }
            }
        }
        self.misses += 1;
        false
    }

    /// Add a state to the cache.
    pub fn add_state(&mut self, insn_idx: usize, state: StateSnapshot) {
        self.states.entry(insn_idx).or_default().push(state);
        self.stored += 1;
    }

    /// Get number of states at an instruction.
    pub fn states_at(&self, insn_idx: usize) -> usize {
        self.states.get(&insn_idx).map(|v| v.len()).unwrap_or(0)
    }

    /// Get total number of cached states.
    pub fn total_states(&self) -> usize {
        self.states.values().map(|v| v.len()).sum()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.states.clear();
        self.hits = 0;
        self.misses = 0;
        self.stored = 0;
    }

    /// Get hit rate as a percentage (0-100).
    pub fn hit_rate_percent(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            0
        } else {
            ((self.hits * 100) / total) as u32
        }
    }
}

/// Helper trait to check if a type represents a pointer.
trait IsPtr {
    fn is_ptr(&self) -> bool;
}

impl IsPtr for BpfRegType {
    fn is_ptr(&self) -> bool {
        !matches!(self, BpfRegType::NotInit | BpfRegType::ScalarValue)
    }
}
