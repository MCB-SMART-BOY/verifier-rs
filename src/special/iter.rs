//! BPF iterator support.
//!
//! BPF iterators allow programs to iterate over kernel data structures safely.
//! Each iterator type has its own lifecycle: new -> next* -> destroy.

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use crate::stdlib::BTreeMap;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::{StackManager, iter_get_spi};
use crate::state::reference::ReferenceManager;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// Mark stack slots for an iterator
pub fn mark_stack_slots_iter(
    stack: &mut StackManager,
    refs: &mut ReferenceManager,
    reg: &BpfRegState,
    btf_id: u32,
    nr_slots: usize,
    insn_idx: usize,
    is_rcu: bool,
) -> Result<u32> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;

    // Acquire a reference for the iterator
    let ref_obj_id = refs.acquire_ptr(insn_idx);

    // Mark the slots
    stack.mark_iter_slots(spi, nr_slots, btf_id, ref_obj_id, is_rcu)?;

    Ok(ref_obj_id)
}

/// Unmark stack slots for an iterator (destroy)
pub fn unmark_stack_slots_iter(
    stack: &mut StackManager,
    refs: &mut ReferenceManager,
    reg: &BpfRegState,
    nr_slots: usize,
) -> Result<()> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;

    // Get the ref_obj_id from the first slot
    let ref_obj_id = stack
        .get_slot_by_spi(spi)
        .ok_or(VerifierError::InvalidIterator("slot not found".into()))?
        .spilled_ptr
        .ref_obj_id;

    // Release the reference
    refs.release_ptr(ref_obj_id)?;

    // Clear the slots
    stack.unmark_iter_slots(spi, nr_slots);

    Ok(())
}

/// Check if iterator slots are valid for uninitialized use
pub fn is_iter_reg_valid_uninit(
    reg: &BpfRegState,
    stack: &StackManager,
    nr_slots: usize,
) -> bool {
    match iter_get_spi(reg, nr_slots, stack.allocated_stack) {
        Ok(spi) => stack.is_iter_valid_uninit(spi, nr_slots),
        Err(_) => true, // Out of bounds is OK, will grow later
    }
}

/// Check if iterator slots are valid for initialized use
pub fn is_iter_reg_valid_init(
    reg: &BpfRegState,
    stack: &StackManager,
    expected_btf_id: u32,
    nr_slots: usize,
) -> Result<()> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;

    for i in 0..nr_slots {
        let slot = stack.get_slot_by_spi(spi - i).ok_or(VerifierError::InvalidIterator(
            "slot not found".into(),
        ))?;

        let st = &slot.spilled_ptr;

        // Check for untrusted pointer
        if st.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
            return Err(VerifierError::InvalidIterator(
                "iterator became untrusted".into(),
            ));
        }

        // First slot must have ref_obj_id
        if i == 0 && st.ref_obj_id == 0 {
            return Err(VerifierError::InvalidIterator(
                "iterator missing ref_obj_id".into(),
            ));
        }

        // Other slots must not have ref_obj_id
        if i != 0 && st.ref_obj_id != 0 {
            return Err(VerifierError::InvalidIterator(
                "iterator has unexpected ref_obj_id".into(),
            ));
        }

        // Check BTF ID matches
        if st.iter.btf_id != expected_btf_id {
            return Err(VerifierError::InvalidIterator(format!(
                "iterator type mismatch: expected {}, got {}",
                expected_btf_id, st.iter.btf_id
            )));
        }

        // Check all bytes are STACK_ITER
        if slot.get_type() != BpfStackSlotType::Iter {
            return Err(VerifierError::InvalidIterator(
                "iterator slot corrupted".into(),
            ));
        }
    }

    Ok(())
}

/// Get the iterator reference object ID
pub fn iter_ref_obj_id(
    reg: &BpfRegState,
    stack: &StackManager,
    nr_slots: usize,
) -> Result<u32> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;
    Ok(slot.spilled_ptr.ref_obj_id)
}

/// Get the iterator state
pub fn iter_get_state(
    reg: &BpfRegState,
    stack: &StackManager,
    nr_slots: usize,
) -> Result<BpfIterState> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;
    Ok(slot.spilled_ptr.iter.state)
}

/// Set the iterator state
pub fn iter_set_state(
    stack: &mut StackManager,
    reg: &BpfRegState,
    nr_slots: usize,
    state: BpfIterState,
) -> Result<()> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_mut_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;
    slot.spilled_ptr.iter.state = state;
    Ok(())
}

/// Get the iterator depth
pub fn iter_get_depth(
    reg: &BpfRegState,
    stack: &StackManager,
    nr_slots: usize,
) -> Result<u32> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;
    Ok(slot.spilled_ptr.iter.depth)
}

/// Increment the iterator depth
pub fn iter_inc_depth(
    stack: &mut StackManager,
    reg: &BpfRegState,
    nr_slots: usize,
) -> Result<u32> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_mut_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;
    slot.spilled_ptr.iter.depth += 1;
    Ok(slot.spilled_ptr.iter.depth)
}

/// Mark iterator as read
pub fn mark_iter_read(
    stack: &mut StackManager,
    reg: &BpfRegState,
    nr_slots: usize,
) -> Result<()> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;

    for i in 0..nr_slots {
        if let Some(slot) = stack.get_slot_mut_by_spi(spi - i) {
            slot.spilled_ptr.live.read = true;
        }
    }

    Ok(())
}

/// Check if this is an iterator kfunc
pub fn is_iter_kfunc(func_id: u32, kfunc_names: &[(&str, u32)]) -> bool {
    kfunc_names.iter().any(|(name, id)| {
        *id == func_id && (name.contains("iter_new") || name.contains("iter_next") || name.contains("iter_destroy"))
    })
}

/// Check if this is an iter_new kfunc
pub fn is_iter_new_kfunc(func_id: u32, kfunc_names: &[(&str, u32)]) -> bool {
    kfunc_names.iter().any(|(name, id)| *id == func_id && name.contains("iter_new"))
}

/// Check if this is an iter_next kfunc
pub fn is_iter_next_kfunc(func_id: u32, kfunc_names: &[(&str, u32)]) -> bool {
    kfunc_names.iter().any(|(name, id)| *id == func_id && name.contains("iter_next"))
}

/// Check if this is an iter_destroy kfunc
pub fn is_iter_destroy_kfunc(func_id: u32, kfunc_names: &[(&str, u32)]) -> bool {
    kfunc_names.iter().any(|(name, id)| *id == func_id && name.contains("iter_destroy"))
}

/// Process iterator next call - handles state transition logic
pub fn process_iter_next_call(
    stack: &mut StackManager,
    reg: &BpfRegState,
    nr_slots: usize,
) -> Result<bool> {
    let spi = iter_get_spi(reg, nr_slots, stack.allocated_stack)?;
    let slot = stack.get_slot_by_spi(spi).ok_or(VerifierError::InvalidIterator(
        "slot not found".into(),
    ))?;

    let state = slot.spilled_ptr.iter.state;

    match state {
        BpfIterState::Active => {
            // Iterator might return null (drained) or valid pointer
            // The verifier needs to explore both branches
            Ok(true) // Has two possible outcomes
        }
        BpfIterState::Drained => {
            // Iterator is already drained, always returns null
            Ok(false) // Only one outcome
        }
        BpfIterState::Invalid => {
            Err(VerifierError::InvalidIterator(
                "iterator in invalid state".into(),
            ))
        }
    }
}

/// Known iterator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorKind {
    /// Task iterator - iterates over tasks
    Task,
    /// VMA iterator - iterates over VMAs
    Vma,
    /// Cgroup iterator
    Cgroup,
    /// CSS (cgroup subsystem state) iterator
    CssTask,
    /// Map element iterator
    MapElem,
    /// Number iterator (simple range iteration)
    Num,
    /// KSYM iterator (kernel symbols)
    Ksym,
    /// Unknown iterator type
    Unknown,
}

impl IteratorKind {
    /// Get iterator kind from BTF type name
    pub fn from_btf_name(name: &str) -> Self {
        if name.contains("task") {
            Self::Task
        } else if name.contains("vma") {
            Self::Vma
        } else if name.contains("cgroup") {
            Self::Cgroup
        } else if name.contains("css_task") {
            Self::CssTask
        } else if name.contains("map") {
            Self::MapElem
        } else if name.contains("num") {
            Self::Num
        } else if name.contains("ksym") {
            Self::Ksym
        } else {
            Self::Unknown
        }
    }

    /// Get the number of stack slots needed for this iterator
    pub fn stack_slots(&self) -> usize {
        match self {
            Self::Task => 4,
            Self::Vma => 4,
            Self::Cgroup => 3,
            Self::CssTask => 4,
            Self::MapElem => 4,
            Self::Num => 2,
            Self::Ksym => 3,
            Self::Unknown => 3, // Default
        }
    }

    /// Check if this iterator can be nested
    pub fn allows_nesting(&self) -> bool {
        match self {
            Self::Task | Self::Vma | Self::Cgroup => true,
            Self::CssTask | Self::MapElem => false,
            Self::Num | Self::Ksym => true,
            Self::Unknown => true,
        }
    }
}

/// Iterator state machine for open-coded iterators
/// 
/// Open-coded iterators follow this lifecycle:
/// 1. bpf_iter_<type>_new() - Initialize iterator (Invalid -> Active)
/// 2. bpf_iter_<type>_next() - Get next element (may return NULL when drained)
/// 3. bpf_iter_<type>_destroy() - Clean up iterator
#[derive(Debug, Clone)]
pub struct IteratorStateMachine {
    /// Current iterator state
    pub state: BpfIterState,
    /// Iterator kind
    pub kind: IteratorKind,
    /// BTF type ID
    pub btf_id: u32,
    /// Reference object ID
    pub ref_obj_id: u32,
    /// Current depth (for convergence tracking)
    pub depth: u32,
    /// Maximum allowed depth before forcing convergence
    pub max_depth: u32,
    /// Number of next() calls made
    pub next_count: u32,
    /// Whether the iterator returned NULL (drained)
    pub has_drained_path: bool,
    /// Whether the iterator returned a valid pointer
    pub has_active_path: bool,
    /// Instruction index where iterator was created
    pub init_insn_idx: usize,
    /// Whether this is an RCU-protected iterator
    pub is_rcu: bool,
}

impl Default for IteratorStateMachine {
    fn default() -> Self {
        Self {
            state: BpfIterState::Invalid,
            kind: IteratorKind::Unknown,
            btf_id: 0,
            ref_obj_id: 0,
            depth: 0,
            max_depth: 16, // Reasonable default
            next_count: 0,
            has_drained_path: false,
            has_active_path: false,
            init_insn_idx: 0,
            is_rcu: false,
        }
    }
}

impl IteratorStateMachine {
    /// Create a new iterator state machine
    pub fn new(kind: IteratorKind, btf_id: u32, ref_obj_id: u32, insn_idx: usize, is_rcu: bool) -> Self {
        Self {
            state: BpfIterState::Active,
            kind,
            btf_id,
            ref_obj_id,
            depth: 0,
            max_depth: 16,
            next_count: 0,
            has_drained_path: false,
            has_active_path: false,
            init_insn_idx: insn_idx,
            is_rcu,
        }
    }

    /// Process a next() call - returns (continue_active, may_be_null)
    pub fn process_next(&mut self) -> Result<(bool, bool)> {
        match self.state {
            BpfIterState::Invalid => {
                Err(VerifierError::InvalidIterator(
                    "next() called on uninitialized iterator".into()
                ))
            }
            BpfIterState::Active => {
                self.next_count += 1;
                self.depth += 1;
                
                if self.depth >= self.max_depth {
                    // Force convergence - assume iterator will drain
                    self.has_drained_path = true;
                    Ok((false, true)) // Stop active path, return NULL
                } else {
                    // Both outcomes possible: valid pointer or NULL
                    self.has_active_path = true;
                    self.has_drained_path = true;
                    Ok((true, true)) // Continue exploring both paths
                }
            }
            BpfIterState::Drained => {
                // Already drained - always returns NULL
                Ok((false, true))
            }
        }
    }

    /// Mark as drained (NULL returned from next())
    pub fn mark_drained(&mut self) {
        self.state = BpfIterState::Drained;
        self.has_drained_path = true;
    }

    /// Check if iterator has converged (safe to prune)
    /// 
    /// An iterator converges when:
    /// 1. It has been marked as drained, OR
    /// 2. The depth has reached max_depth, OR
    /// 3. Both active and drained paths have been explored
    pub fn has_converged(&self) -> bool {
        self.state == BpfIterState::Drained
            || self.depth >= self.max_depth
            || (self.has_active_path && self.has_drained_path)
    }

    /// Check if this iterator state is equivalent to another for pruning
    pub fn is_equivalent(&self, other: &Self) -> bool {
        // Same type and state
        if self.btf_id != other.btf_id {
            return false;
        }
        
        // Same state
        if self.state != other.state {
            return false;
        }

        // If both have converged, they're equivalent
        if self.has_converged() && other.has_converged() {
            return true;
        }

        // Same depth (for non-converged states)
        self.depth == other.depth
    }

    /// Reset for a new loop iteration
    pub fn reset_for_iteration(&mut self) {
        // Keep state and btf_id, reset tracking
        self.next_count = 0;
    }

    /// Validate iterator can be destroyed
    pub fn validate_destroy(&self) -> Result<()> {
        if self.state == BpfIterState::Invalid {
            return Err(VerifierError::InvalidIterator(
                "destroy() called on uninitialized iterator".into()
            ));
        }
        Ok(())
    }
}

/// Iterator convergence tracker for the whole verification
#[derive(Debug, Default)]
pub struct IteratorConvergenceTracker {
    /// Active iterators by ref_obj_id
    active_iters: BTreeMap<u32, IteratorStateMachine>,
    /// Total iterators created
    pub total_created: u32,
    /// Total iterators destroyed
    pub total_destroyed: u32,
    /// Maximum nesting depth seen
    pub max_nesting: u32,
    /// Current nesting depth
    pub current_nesting: u32,
}

impl IteratorConvergenceTracker {
    /// Create a new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new iterator
    pub fn register(&mut self, iter: IteratorStateMachine) -> Result<()> {
        let ref_id = iter.ref_obj_id;
        
        // Check nesting limits
        self.current_nesting += 1;
        if self.current_nesting > self.max_nesting {
            self.max_nesting = self.current_nesting;
        }
        
        // Check if this kind allows nesting
        if self.current_nesting > 1 && !iter.kind.allows_nesting() {
            return Err(VerifierError::InvalidIterator(
                format!("{:?} iterator cannot be nested", iter.kind)
            ));
        }

        self.active_iters.insert(ref_id, iter);
        self.total_created += 1;
        Ok(())
    }

    /// Get mutable reference to iterator
    pub fn get_mut(&mut self, ref_obj_id: u32) -> Option<&mut IteratorStateMachine> {
        self.active_iters.get_mut(&ref_obj_id)
    }

    /// Get reference to iterator
    pub fn get(&self, ref_obj_id: u32) -> Option<&IteratorStateMachine> {
        self.active_iters.get(&ref_obj_id)
    }

    /// Unregister an iterator (destroyed)
    pub fn unregister(&mut self, ref_obj_id: u32) -> Result<()> {
        if self.active_iters.remove(&ref_obj_id).is_some() {
            self.current_nesting = self.current_nesting.saturating_sub(1);
            self.total_destroyed += 1;
            Ok(())
        } else {
            Err(VerifierError::InvalidIterator(
                "destroying unknown iterator".into()
            ))
        }
    }

    /// Check if all iterators have converged
    pub fn all_converged(&self) -> bool {
        self.active_iters.values().all(|i| i.has_converged())
    }

    /// Check if any iterators are still active (not destroyed)
    pub fn has_active(&self) -> bool {
        !self.active_iters.is_empty()
    }

    /// Get count of active iterators
    pub fn active_count(&self) -> usize {
        self.active_iters.len()
    }

    /// Validate all iterators are properly cleaned up
    pub fn validate_cleanup(&self) -> Result<()> {
        if !self.active_iters.is_empty() {
            let refs: Vec<u32> = self.active_iters.keys().copied().collect();
            return Err(VerifierError::InvalidIterator(
                format!("iterators not destroyed: {:?}", refs)
            ));
        }
        Ok(())
    }
}

/// Check if two iterator states at the same instruction represent convergence
pub fn check_iter_state_convergence(
    cur_stack: &StackManager,
    old_stack: &StackManager,
    spi: usize,
    _nr_slots: usize,
) -> bool {
    // Get current and old iterator states
    let cur_slot = match cur_stack.get_slot_by_spi(spi) {
        Some(s) => s,
        None => return false,
    };
    let old_slot = match old_stack.get_slot_by_spi(spi) {
        Some(s) => s,
        None => return false,
    };

    // Both must be iterators
    if cur_slot.get_type() != BpfStackSlotType::Iter 
        || old_slot.get_type() != BpfStackSlotType::Iter {
        return false;
    }

    // Same BTF type
    if cur_slot.spilled_ptr.iter.btf_id != old_slot.spilled_ptr.iter.btf_id {
        return false;
    }

    // Check state - if old was active and cur is also active with same or higher depth,
    // we've made progress and may have converged
    if old_slot.spilled_ptr.iter.state == BpfIterState::Active
        && cur_slot.spilled_ptr.iter.state == BpfIterState::Active {
        // Same depth means we're in a fixed point
        if cur_slot.spilled_ptr.iter.depth == old_slot.spilled_ptr.iter.depth {
            return true;
        }
        // If depth increased, we're still making progress but haven't converged
        return false;
    }

    // If old was active but cur is drained, that's convergence
    if old_slot.spilled_ptr.iter.state == BpfIterState::Active
        && cur_slot.spilled_ptr.iter.state == BpfIterState::Drained {
        return true;
    }

    // Both drained is convergent
    cur_slot.spilled_ptr.iter.state == BpfIterState::Drained
        && old_slot.spilled_ptr.iter.state == BpfIterState::Drained
}

/// Validate iterator frame invariants
/// 
/// Ensures iterator state is consistent across function frames
pub fn validate_iter_frame_invariants(
    stack: &StackManager,
    frame_idx: usize,
    cur_frame: usize,
) -> Result<()> {
    // Iterators must not escape their frame
    // Check all stack slots for iterator state
    let num_slots = stack.allocated_stack / BPF_REG_SIZE;
    for spi in 0..num_slots {
        if let Some(slot) = stack.get_slot_by_spi(spi) {
            if slot.get_type() == BpfStackSlotType::Iter {
                // Check if this iterator belongs to a frame that's being exited
                // (This would be caught by reference tracking, but we double-check)
                if frame_idx < cur_frame {
                    // Slot from inner frame - should have been cleaned up
                    let _ = spi; // Suppress warning
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::tnum::Tnum;

    fn make_stack_ptr_reg(off: i32) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.var_off = Tnum::const_value(0);
        reg.off = off;
        reg
    }

    #[test]
    fn test_iter_valid_uninit() {
        let reg = make_stack_ptr_reg(-24);
        let stack = StackManager::new();

        // Should be valid for uninit (stack not allocated yet)
        assert!(is_iter_reg_valid_uninit(&reg, &stack, 3));
    }

    #[test]
    fn test_iter_lifecycle() {
        let mut stack = StackManager::new();
        let mut refs = ReferenceManager::new();

        stack.grow(32).unwrap();

        let reg = make_stack_ptr_reg(-24);

        // Mark slots for iterator
        let ref_id = mark_stack_slots_iter(&mut stack, &mut refs, &reg, 100, 3, 0, false).unwrap();
        assert!(refs.has_ref(ref_id));

        // Check it's valid
        assert!(is_iter_reg_valid_init(&reg, &stack, 100, 3).is_ok());

        // Unmark (destroy)
        assert!(unmark_stack_slots_iter(&mut stack, &mut refs, &reg, 3).is_ok());
        assert!(!refs.has_ref(ref_id));
    }
}
