//! Reference tracking system
//!
//! This module implements reference tracking for the BPF verifier.
//! It handles acquired references (pointers that must be released),
//! locks, RCU read-side critical sections, and IRQ state.


use alloc::{format, vec::Vec};

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// State of an acquired reference
#[derive(Debug, Clone)]
pub struct BpfReferenceState {
    /// Unique ID for this reference
    pub id: u32,
    /// Instruction index where this reference was acquired
    pub insn_idx: usize,
    /// Type of reference
    pub ref_type: RefStateType,
    /// Pointer to lock object (for lock references)
    pub ptr: Option<usize>,
    /// BTF type ID of the referenced object (for type-safe release)
    pub btf_id: u32,
    /// Name of the acquire function (for error messages)
    pub acquire_func: Option<&'static str>,
}

impl BpfReferenceState {
    /// Create a new pointer reference
    pub fn new_ptr(id: u32, insn_idx: usize) -> Self {
        Self {
            id,
            insn_idx,
            ref_type: RefStateType::Ptr,
            ptr: None,
            btf_id: 0,
            acquire_func: None,
        }
    }

    /// Create a new pointer reference with BTF type info
    pub fn new_ptr_typed(id: u32, insn_idx: usize, btf_id: u32, acquire_func: &'static str) -> Self {
        Self {
            id,
            insn_idx,
            ref_type: RefStateType::Ptr,
            ptr: None,
            btf_id,
            acquire_func: Some(acquire_func),
        }
    }

    /// Create a new lock reference
    pub fn new_lock(id: u32, insn_idx: usize, ptr: usize) -> Self {
        Self {
            id,
            insn_idx,
            ref_type: RefStateType::Lock,
            ptr: Some(ptr),
            btf_id: 0,
            acquire_func: None,
        }
    }

    /// Create a new resource lock reference
    pub fn new_res_lock(id: u32, insn_idx: usize, ptr: usize) -> Self {
        Self {
            id,
            insn_idx,
            ref_type: RefStateType::ResLock,
            ptr: Some(ptr),
            btf_id: 0,
            acquire_func: None,
        }
    }

    /// Create a new IRQ state reference
    pub fn new_irq(id: u32, insn_idx: usize) -> Self {
        Self {
            id,
            insn_idx,
            ref_type: RefStateType::Irq,
            ptr: None,
            btf_id: 0,
            acquire_func: None,
        }
    }

    /// Check if this is a lock-type reference
    pub fn is_lock(&self) -> bool {
        matches!(self.ref_type, RefStateType::Lock | RefStateType::ResLock)
    }

    /// Get the BTF type ID of this reference
    pub fn get_btf_id(&self) -> u32 {
        self.btf_id
    }

    /// Check if this reference has type info
    pub fn has_type_info(&self) -> bool {
        self.btf_id != 0
    }
}

/// Manager for tracking references within a verification state
#[derive(Debug, Clone, Default)]
pub struct ReferenceManager {
    /// List of acquired references
    refs: Vec<BpfReferenceState>,
    /// Number of active locks
    pub active_locks: u32,
    /// Number of active preempt locks
    pub active_preempt_locks: u32,
    /// Number of active RCU locks
    pub active_rcu_locks: u32,
    /// Currently active IRQ state ID (0 if none)
    pub active_irq_id: u32,
    /// Currently active lock ID
    pub active_lock_id: u32,
    /// Currently active lock pointer
    pub active_lock_ptr: Option<usize>,
    /// Next ID to assign
    next_id: u32,
}

impl ReferenceManager {
    /// Create a new reference manager
    pub fn new() -> Self {
        Self {
            refs: Vec::new(),
            active_locks: 0,
            active_preempt_locks: 0,
            active_rcu_locks: 0,
            active_irq_id: 0,
            active_lock_id: 0,
            active_lock_ptr: None,
            next_id: 1,
        }
    }

    /// Generate a new unique ID
    pub fn gen_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Get the current ID counter (for copying state)
    pub fn current_id(&self) -> u32 {
        self.next_id
    }

    /// Set the ID counter (for copying state)
    pub fn set_id_counter(&mut self, id: u32) {
        self.next_id = id;
    }

    /// Acquire a new pointer reference
    pub fn acquire_ptr(&mut self, insn_idx: usize) -> u32 {
        let id = self.gen_id();
        self.refs.push(BpfReferenceState::new_ptr(id, insn_idx));
        id
    }

    /// Acquire a new pointer reference with BTF type info
    pub fn acquire_ptr_typed(&mut self, insn_idx: usize, btf_id: u32, acquire_func: &'static str) -> u32 {
        let id = self.gen_id();
        self.refs.push(BpfReferenceState::new_ptr_typed(id, insn_idx, btf_id, acquire_func));
        id
    }

    /// Acquire a new lock reference
    pub fn acquire_lock(&mut self, insn_idx: usize, ptr: usize) -> u32 {
        let id = self.gen_id();
        self.refs.push(BpfReferenceState::new_lock(id, insn_idx, ptr));
        self.active_locks += 1;
        self.active_lock_id = id;
        self.active_lock_ptr = Some(ptr);
        id
    }

    /// Acquire a new resource lock reference
    pub fn acquire_res_lock(&mut self, insn_idx: usize, ptr: usize) -> u32 {
        let id = self.gen_id();
        self.refs.push(BpfReferenceState::new_res_lock(id, insn_idx, ptr));
        self.active_locks += 1;
        self.active_lock_id = id;
        self.active_lock_ptr = Some(ptr);
        id
    }

    /// Acquire a new IRQ state reference
    pub fn acquire_irq(&mut self, insn_idx: usize) -> u32 {
        let id = self.gen_id();
        self.refs.push(BpfReferenceState::new_irq(id, insn_idx));
        self.active_irq_id = id;
        id
    }

    /// Find a reference by ID
    pub fn find_ref(&self, id: u32) -> Option<&BpfReferenceState> {
        self.refs.iter().find(|r| r.id == id)
    }

    /// Check if a reference exists
    pub fn has_ref(&self, id: u32) -> bool {
        self.refs.iter().any(|r| r.id == id)
    }

    /// Release a pointer reference by ID
    pub fn release_ptr(&mut self, id: u32) -> Result<()> {
        let idx = self.refs.iter().position(|r| r.id == id && r.ref_type == RefStateType::Ptr);
        match idx {
            Some(i) => {
                self.refs.remove(i);
                Ok(())
            }
            None => Err(VerifierError::UnreleasedReference(id)),
        }
    }

    /// Release a pointer reference with type checking
    /// 
    /// This ensures that the release function matches the type of the acquired reference.
    /// For example, bpf_task_release should only release task_struct references.
    pub fn release_ptr_typed(&mut self, id: u32, expected_btf_id: u32, release_func: &str) -> Result<()> {
        let idx = self.refs.iter().position(|r| r.id == id && r.ref_type == RefStateType::Ptr);
        match idx {
            Some(i) => {
                let ref_state = &self.refs[i];
                
                // If the reference has type info, verify it matches
                if ref_state.has_type_info() && expected_btf_id != 0 {
                    if ref_state.btf_id != expected_btf_id {
                        let acquire_name = ref_state.acquire_func.unwrap_or("unknown");
                        return Err(VerifierError::TypeMismatch {
                            expected: format!("BTF type {} for {}", expected_btf_id, release_func),
                            got: format!("BTF type {} from {}", ref_state.btf_id, acquire_name),
                        });
                    }
                }
                
                self.refs.remove(i);
                Ok(())
            }
            None => Err(VerifierError::UnreleasedReference(id)),
        }
    }

    /// Get type info for a reference
    pub fn get_ref_type_info(&self, id: u32) -> Option<(u32, Option<&'static str>)> {
        self.refs.iter()
            .find(|r| r.id == id)
            .map(|r| (r.btf_id, r.acquire_func))
    }

    /// Release a lock reference
    pub fn release_lock(&mut self, id: u32, ptr: usize) -> Result<()> {
        // Find the lock with matching ID and pointer
        let idx = self.refs.iter().position(|r| {
            r.id == id && r.is_lock() && r.ptr == Some(ptr)
        });

        match idx {
            Some(i) => {
                self.refs.remove(i);
                self.active_locks -= 1;

                // Find the previous lock (if any) and update active lock state
                let prev_lock = self.refs.iter().rev().find(|r| r.is_lock());
                if let Some(lock) = prev_lock {
                    self.active_lock_id = lock.id;
                    self.active_lock_ptr = lock.ptr;
                } else {
                    self.active_lock_id = 0;
                    self.active_lock_ptr = None;
                }
                Ok(())
            }
            None => Err(VerifierError::InvalidLock(format!(
                "lock with id={} ptr={} not found",
                id, ptr
            ))),
        }
    }

    /// Release an IRQ state reference (must be in order)
    pub fn release_irq(&mut self, id: u32) -> Result<()> {
        // IRQ release must be in order (stack-like)
        if id != self.active_irq_id {
            return Err(VerifierError::InvalidIrq(format!(
                "cannot restore irq state out of order, expected id={}",
                self.active_irq_id
            )));
        }

        let idx = self.refs.iter().position(|r| r.id == id && r.ref_type == RefStateType::Irq);
        match idx {
            Some(i) => {
                self.refs.remove(i);

                // Find the previous IRQ state (if any)
                let prev_irq = self.refs.iter().rev().find(|r| r.ref_type == RefStateType::Irq);
                self.active_irq_id = prev_irq.map(|r| r.id).unwrap_or(0);
                Ok(())
            }
            None => Err(VerifierError::InvalidIrq(format!(
                "irq state with id={} not found",
                id
            ))),
        }
    }

    /// Check for unreleased references
    pub fn check_all_released(&self) -> Result<()> {
        for r in &self.refs {
            match r.ref_type {
                RefStateType::Ptr => {
                    return Err(VerifierError::UnreleasedReference(r.id));
                }
                RefStateType::Lock | RefStateType::ResLock => {
                    return Err(VerifierError::InvalidLock(format!(
                        "lock acquired at insn {} not released",
                        r.insn_idx
                    )));
                }
                RefStateType::Irq => {
                    return Err(VerifierError::InvalidIrq(format!(
                        "irq state acquired at insn {} not restored",
                        r.insn_idx
                    )));
                }
                _ => {}
            }
        }

        if self.active_rcu_locks > 0 {
            return Err(VerifierError::InvalidLock(
                "RCU read lock not released".into(),
            ));
        }

        if self.active_preempt_locks > 0 {
            return Err(VerifierError::InvalidLock(
                "preempt not re-enabled".into(),
            ));
        }

        Ok(())
    }

    /// Enter RCU read-side critical section
    pub fn rcu_lock(&mut self) {
        self.active_rcu_locks += 1;
    }

    /// Exit RCU read-side critical section
    pub fn rcu_unlock(&mut self) -> Result<()> {
        if self.active_rcu_locks == 0 {
            return Err(VerifierError::InvalidLock(
                "RCU unlock without lock".into(),
            ));
        }
        self.active_rcu_locks -= 1;
        Ok(())
    }

    /// Check if in RCU read-side critical section
    pub fn in_rcu(&self) -> bool {
        self.active_rcu_locks > 0
    }

    /// Disable preemption
    pub fn preempt_disable(&mut self) {
        self.active_preempt_locks += 1;
    }

    /// Enable preemption
    pub fn preempt_enable(&mut self) -> Result<()> {
        if self.active_preempt_locks == 0 {
            return Err(VerifierError::InvalidLock(
                "preempt enable without disable".into(),
            ));
        }
        self.active_preempt_locks -= 1;
        Ok(())
    }

    /// Get all references (for state comparison)
    pub fn refs(&self) -> &[BpfReferenceState] {
        &self.refs
    }

    /// Get number of acquired references
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// Check if there are no references
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Copy reference state from another manager
    pub fn copy_from(&mut self, other: &ReferenceManager) {
        self.refs = other.refs.clone();
        self.active_locks = other.active_locks;
        self.active_preempt_locks = other.active_preempt_locks;
        self.active_rcu_locks = other.active_rcu_locks;
        self.active_irq_id = other.active_irq_id;
        self.active_lock_id = other.active_lock_id;
        self.active_lock_ptr = other.active_lock_ptr;
        self.next_id = other.next_id;
    }

    /// Find a lock state by type, id, and pointer
    pub fn find_lock(&self, id: u32, ptr: usize) -> Option<&BpfReferenceState> {
        self.refs.iter().find(|r| {
            r.id == id && r.is_lock() && r.ptr == Some(ptr)
        })
    }

    /// Invalidate non-owning references (after lock release in certain contexts)
    pub fn invalidate_non_owning_refs(&mut self) {
        // In the full implementation, this would mark certain PTR_TO_BTF_ID
        // registers with NON_OWN_REF as invalid
    }
}
