// SPDX-License-Identifier: GPL-2.0

//!

//! This module tracks BPF spin lock state to ensure correct lock/unlock

//! pairing and detect potential deadlocks.

use alloc::{format, vec::Vec};

use crate::core::error::{Result, VerifierError};

/// Maximum number of nested locks
pub const MAX_LOCK_DEPTH: usize = 4;

/// Lock ID type
pub type LockId = u32;

/// Information about a held lock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldLock {
    /// Lock ID (unique identifier)
    pub id: LockId,
    /// Map pointer where lock is located
    pub map_uid: u32,
    /// Offset within map value
    pub map_off: u32,
    /// Instruction index where lock was acquired
    pub acquired_at: usize,
}

/// Lock state for a verification path
#[derive(Debug, Clone, Default)]
pub struct LockState {
    /// Currently held locks (stack for nested locks)
    held_locks: Vec<HeldLock>,
    /// Next lock ID to assign
    next_id: LockId,
    /// Whether spin locks are enabled for this program
    pub enabled: bool,
}

impl LockState {
    /// Create a new lock state
    pub fn new() -> Self {
        Self {
            held_locks: Vec::new(),
            next_id: 1,
            enabled: true,
        }
    }

    /// Acquire a lock
    pub fn acquire(&mut self, map_uid: u32, map_off: u32, insn_idx: usize) -> Result<LockId> {
        // Check nesting limit
        if self.held_locks.len() >= MAX_LOCK_DEPTH {
            return Err(VerifierError::InvalidLock("too many nested locks".into()));
        }

        // Check for already held (same lock)
        for lock in &self.held_locks {
            if lock.map_uid == map_uid && lock.map_off == map_off {
                return Err(VerifierError::InvalidLock(format!(
                    "lock at map_uid={}, offset={} already held (acquired at insn {})",
                    map_uid, map_off, lock.acquired_at
                )));
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        self.held_locks.push(HeldLock {
            id,
            map_uid,
            map_off,
            acquired_at: insn_idx,
        });

        Ok(id)
    }

    /// Release a lock
    pub fn release(&mut self, map_uid: u32, map_off: u32) -> Result<LockId> {
        // Find the lock
        let pos = self
            .held_locks
            .iter()
            .position(|l| l.map_uid == map_uid && l.map_off == map_off);

        match pos {
            Some(idx) => {
                // For proper nesting, should release most recent lock
                if idx != self.held_locks.len() - 1 {
                    return Err(VerifierError::InvalidLock(
                        "locks must be released in reverse order".into(),
                    ));
                }
                match self.held_locks.pop() {
                    Some(lock) => Ok(lock.id),
                    None => Err(VerifierError::InvalidLock(
                        "lock state inconsistency".into(),
                    )),
                }
            }
            None => Err(VerifierError::InvalidLock(format!(
                "releasing lock not held: map_uid={}, offset={}",
                map_uid, map_off
            ))),
        }
    }

    /// Check if any locks are held
    pub fn has_locks(&self) -> bool {
        !self.held_locks.is_empty()
    }

    /// Get number of held locks
    pub fn lock_count(&self) -> usize {
        self.held_locks.len()
    }

    /// Check if a specific lock is held
    pub fn is_locked(&self, map_uid: u32, map_off: u32) -> bool {
        self.held_locks
            .iter()
            .any(|l| l.map_uid == map_uid && l.map_off == map_off)
    }

    /// Get the most recently acquired lock
    pub fn current_lock(&self) -> Option<&HeldLock> {
        self.held_locks.last()
    }

    /// Check that all locks are released at program exit
    pub fn check_all_released(&self) -> Result<()> {
        if let Some(lock) = self.held_locks.first() {
            return Err(VerifierError::InvalidLock(format!(
                "lock not released: map_uid={}, offset={} (acquired at insn {})",
                lock.map_uid, lock.map_off, lock.acquired_at
            )));
        }
        Ok(())
    }

    /// Copy state for branch exploration
    pub fn clone_for_branch(&self) -> Self {
        Self {
            held_locks: self.held_locks.clone(),
            next_id: self.next_id,
            enabled: self.enabled,
        }
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &LockState) -> bool {
        if self.held_locks.len() != other.held_locks.len() {
            return false;
        }

        // Lock IDs may differ but locks should be at same locations
        for (a, b) in self.held_locks.iter().zip(other.held_locks.iter()) {
            if a.map_uid != b.map_uid || a.map_off != b.map_off {
                return false;
            }
        }

        true
    }
}

/// Operations that are allowed while holding a lock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAllowedOp {
    /// Memory access to same map value
    MapValueAccess,
    /// ALU operations
    Alu,
    /// Conditional jumps (within locked region)
    ConditionalJump,
    /// Function calls to lock-safe helpers
    LockSafeHelper,
}

/// Check if an operation is allowed while holding a lock
pub fn is_op_lock_safe(op: LockAllowedOp) -> bool {
    matches!(
        op,
        LockAllowedOp::MapValueAccess
            | LockAllowedOp::Alu
            | LockAllowedOp::ConditionalJump
            | LockAllowedOp::LockSafeHelper
    )
}

/// Operations forbidden while holding a spin lock
pub fn check_lock_restrictions(
    lock_state: &LockState,
    is_helper_call: bool,
    might_sleep: bool,
) -> Result<()> {
    if !lock_state.has_locks() {
        return Ok(());
    }

    // Cannot call helpers that might sleep while holding lock
    if is_helper_call && might_sleep {
        return Err(VerifierError::InvalidLock(
            "cannot call sleeping helper while holding spin lock".into(),
        ));
    }

    Ok(())
}

/// Spin lock helper IDs
pub mod spin_lock_helpers {
    /// bpf_spin_lock helper ID
    pub const BPF_SPIN_LOCK: u32 = 93;
    /// bpf_spin_unlock helper ID  
    pub const BPF_SPIN_UNLOCK: u32 = 94;
}

/// Check if helper is bpf_spin_lock
pub fn is_spin_lock_helper(helper_id: u32) -> bool {
    helper_id == spin_lock_helpers::BPF_SPIN_LOCK
}

/// Check if helper is bpf_spin_unlock
pub fn is_spin_unlock_helper(helper_id: u32) -> bool {
    helper_id == spin_lock_helpers::BPF_SPIN_UNLOCK
}

/// RCU read-side critical section state
#[derive(Debug, Clone, Default)]
pub struct RcuState {
    /// Whether we're in an RCU read-side critical section
    pub in_rcu_section: bool,
    /// Instruction where RCU section started
    pub rcu_lock_insn: Option<usize>,
    /// Nesting depth for RCU locks
    pub rcu_nesting: u32,
    /// RCU pointers acquired in this section
    rcu_pointers: Vec<RcuPointer>,
}

/// Information about an RCU-protected pointer
#[derive(Debug, Clone)]
pub struct RcuPointer {
    /// Register that holds the pointer
    pub reg_id: u32,
    /// BTF type ID
    pub btf_id: u32,
    /// Whether pointer is still valid
    pub valid: bool,
}

impl RcuState {
    /// Create new RCU state
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter RCU read-side critical section
    pub fn rcu_read_lock(&mut self, insn_idx: usize) -> Result<()> {
        if self.rcu_nesting == 0 {
            self.rcu_lock_insn = Some(insn_idx);
        }
        self.rcu_nesting += 1;
        self.in_rcu_section = true;
        Ok(())
    }

    /// Exit RCU read-side critical section
    pub fn rcu_read_unlock(&mut self) -> Result<()> {
        if self.rcu_nesting == 0 {
            return Err(VerifierError::InvalidLock(
                "rcu_read_unlock without matching rcu_read_lock".into(),
            ));
        }
        self.rcu_nesting -= 1;
        if self.rcu_nesting == 0 {
            self.in_rcu_section = false;
            self.rcu_lock_insn = None;
            // Invalidate all RCU pointers
            for ptr in &mut self.rcu_pointers {
                ptr.valid = false;
            }
        }
        Ok(())
    }

    /// Track an RCU-protected pointer
    pub fn track_rcu_pointer(&mut self, reg_id: u32, btf_id: u32) {
        if self.in_rcu_section {
            self.rcu_pointers.push(RcuPointer {
                reg_id,
                btf_id,
                valid: true,
            });
        }
    }

    /// Check if RCU pointer access is valid
    pub fn check_rcu_access(&self, reg_id: u32) -> Result<()> {
        for ptr in &self.rcu_pointers {
            if ptr.reg_id == reg_id {
                if !ptr.valid {
                    return Err(VerifierError::InvalidLock(
                        "accessing RCU pointer after rcu_read_unlock".into(),
                    ));
                }
                return Ok(());
            }
        }
        // Not an RCU pointer we're tracking
        Ok(())
    }

    /// Check all RCU sections are closed at exit
    pub fn check_all_unlocked(&self) -> Result<()> {
        if self.rcu_nesting > 0 {
            return Err(VerifierError::InvalidLock(format!(
                "rcu_read_lock not unlocked (nesting={})",
                self.rcu_nesting
            )));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &RcuState) -> bool {
        self.rcu_nesting == other.rcu_nesting
    }
}

/// Combined lock and RCU state
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// Spin lock state
    pub lock: LockState,
    /// RCU state
    pub rcu: RcuState,
    /// Whether preemption is disabled
    pub preempt_disabled: bool,
    /// Preemption disable depth
    pub preempt_disable_depth: u32,
}

impl SyncState {
    /// Create new synchronization state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check all synchronization primitives are properly released
    pub fn check_all_released(&self) -> Result<()> {
        self.lock.check_all_released()?;
        self.rcu.check_all_unlocked()?;
        if self.preempt_disabled {
            return Err(VerifierError::InvalidLock(
                "preemption not re-enabled at exit".into(),
            ));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &SyncState) -> bool {
        self.lock.equivalent(&other.lock)
            && self.rcu.equivalent(&other.rcu)
            && self.preempt_disable_depth == other.preempt_disable_depth
    }

    /// Disable preemption
    pub fn preempt_disable(&mut self) {
        self.preempt_disable_depth += 1;
        self.preempt_disabled = true;
    }

    /// Enable preemption
    pub fn preempt_enable(&mut self) -> Result<()> {
        if self.preempt_disable_depth == 0 {
            return Err(VerifierError::InvalidLock(
                "preempt_enable without matching preempt_disable".into(),
            ));
        }
        self.preempt_disable_depth -= 1;
        if self.preempt_disable_depth == 0 {
            self.preempt_disabled = false;
        }
        Ok(())
    }
}

/// Helpers that might sleep (cannot be called while holding locks)
pub fn helper_might_sleep(helper_id: u32) -> bool {
    // List of helpers that might sleep
    const SLEEPING_HELPERS: &[u32] = &[
        1, // bpf_map_lookup_elem (some map types)
        2, // bpf_map_update_elem (some map types)
        3, // bpf_map_delete_elem (some map types)
        11, // bpf_get_current_comm
           // ... more helpers
    ];
    SLEEPING_HELPERS.contains(&helper_id)
}

/// Validate synchronization state for a helper call
pub fn validate_sync_for_helper(sync: &SyncState, helper_id: u32) -> Result<()> {
    // Check spin lock restrictions
    if sync.lock.has_locks() {
        if helper_might_sleep(helper_id) {
            return Err(VerifierError::InvalidLock(format!(
                "helper {} might sleep while holding spin lock",
                helper_id
            )));
        }
    }

    // Spin lock/unlock helpers have special handling
    if is_spin_lock_helper(helper_id) || is_spin_unlock_helper(helper_id) {
        // These are the lock operations themselves
        return Ok(());
    }

    Ok(())
}

/// bpf_rcu_read_lock/unlock kfunc IDs  
pub mod rcu_kfuncs {
    /// bpf_rcu_read_lock kfunc
    pub const RCU_READ_LOCK: u32 = 0x1001;
    /// bpf_rcu_read_unlock kfunc
    pub const RCU_READ_UNLOCK: u32 = 0x1002;
}

/// Check if kfunc is bpf_rcu_read_lock
pub fn is_rcu_lock_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == rcu_kfuncs::RCU_READ_LOCK
}

/// Check if kfunc is bpf_rcu_read_unlock
pub fn is_rcu_unlock_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == rcu_kfuncs::RCU_READ_UNLOCK
}

/// Validate pointer access based on synchronization state
pub fn validate_ptr_access_sync(sync: &SyncState, is_rcu_ptr: bool, _ptr_id: u32) -> Result<()> {
    if is_rcu_ptr && !sync.rcu.in_rcu_section {
        return Err(VerifierError::InvalidLock(
            "accessing RCU pointer outside RCU read-side critical section".into(),
        ));
    }
    Ok(())
}

/// Lock ordering validator to detect potential deadlocks
#[derive(Debug, Clone, Default)]
pub struct LockOrderValidator {
    /// Known lock orderings (lock_a must be acquired before lock_b)
    orderings: Vec<(LockId, LockId)>,
}

impl LockOrderValidator {
    /// Create new validator
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a lock ordering
    pub fn record_ordering(&mut self, first: LockId, second: LockId) {
        // Check for existing conflicting ordering
        for (a, b) in &self.orderings {
            if *a == second && *b == first {
                // Conflicting ordering detected - potential deadlock
                // In a real implementation, we'd return an error
            }
        }
        self.orderings.push((first, second));
    }

    /// Check if acquiring `second` after `first` is valid
    pub fn check_ordering(&self, first: LockId, second: LockId) -> Result<()> {
        for (a, b) in &self.orderings {
            if *a == second && *b == first {
                return Err(VerifierError::InvalidLock(format!(
                    "potential deadlock: lock {} must be acquired before lock {}",
                    first, second
                )));
            }
        }
        Ok(())
    }
}

// ============================================================================
// IRQ Flag State Tracking
// ============================================================================

/// IRQ flag kfunc classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqKfuncClass {
    /// bpf_local_irq_save
    LocalIrqSave,
    /// bpf_local_irq_restore
    LocalIrqRestore,
    /// bpf_spin_lock_irqsave
    SpinLockIrqSave,
    /// bpf_spin_unlock_irqrestore
    SpinUnlockIrqRestore,
}

/// IRQ flag information stored on stack
#[derive(Debug, Clone)]
pub struct IrqFlagSlot {
    /// Reference ID for this IRQ state
    pub ref_obj_id: u32,
    /// Kfunc class that created this flag
    pub kfunc_class: IrqKfuncClass,
    /// Instruction where IRQ was disabled
    pub acquired_at: usize,
    /// Stack slot index
    pub spi: usize,
}

/// IRQ state tracking
#[derive(Debug, Clone, Default)]
pub struct IrqState {
    /// Active IRQ disable ID (most recent)
    pub active_irq_id: Option<u32>,
    /// Stack of IRQ flags (for nested IRQ disable)
    irq_flags: Vec<IrqFlagSlot>,
    /// Next IRQ flag ID
    next_id: u32,
}

impl IrqState {
    /// Create new IRQ state
    pub fn new() -> Self {
        Self {
            active_irq_id: None,
            irq_flags: Vec::new(),
            next_id: 1,
        }
    }

    /// Acquire IRQ state (disable interrupts)
    pub fn acquire_irq(
        &mut self,
        insn_idx: usize,
        spi: usize,
        kfunc_class: IrqKfuncClass,
    ) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;

        self.irq_flags.push(IrqFlagSlot {
            ref_obj_id: id,
            kfunc_class,
            acquired_at: insn_idx,
            spi,
        });

        self.active_irq_id = Some(id);
        Ok(id)
    }

    /// Release IRQ state (restore interrupts)
    /// Must be released in LIFO order (stack-like)
    pub fn release_irq(&mut self, ref_obj_id: u32) -> Result<()> {
        // IRQ flags must be restored in reverse order
        if let Some(last) = self.irq_flags.last() {
            if last.ref_obj_id != ref_obj_id {
                return Err(VerifierError::InvalidLock(format!(
                    "IRQ flags must be restored in order: expected {}, got {}",
                    last.ref_obj_id, ref_obj_id
                )));
            }
        } else {
            return Err(VerifierError::InvalidLock(
                "restoring IRQ state without matching save".into(),
            ));
        }

        self.irq_flags.pop();

        // Update active IRQ ID
        self.active_irq_id = self.irq_flags.last().map(|f| f.ref_obj_id);

        Ok(())
    }

    /// Check if IRQs are currently disabled
    pub fn irqs_disabled(&self) -> bool {
        !self.irq_flags.is_empty()
    }

    /// Get current IRQ disable depth
    pub fn irq_depth(&self) -> usize {
        self.irq_flags.len()
    }

    /// Get IRQ flag by reference ID
    pub fn get_irq_flag(&self, ref_obj_id: u32) -> Option<&IrqFlagSlot> {
        self.irq_flags.iter().find(|f| f.ref_obj_id == ref_obj_id)
    }

    /// Check all IRQ flags are restored at exit
    pub fn check_all_restored(&self) -> Result<()> {
        if let Some(flag) = self.irq_flags.first() {
            return Err(VerifierError::InvalidLock(format!(
                "IRQ flag not restored: id={} (saved at insn {})",
                flag.ref_obj_id, flag.acquired_at
            )));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &IrqState) -> bool {
        self.irq_flags.len() == other.irq_flags.len()
    }
}

/// Mark stack slot as IRQ flag
pub fn mark_stack_slot_irq_flag(
    irq_state: &mut IrqState,
    insn_idx: usize,
    spi: usize,
    kfunc_class: IrqKfuncClass,
) -> Result<u32> {
    irq_state.acquire_irq(insn_idx, spi, kfunc_class)
}

/// Unmark stack slot IRQ flag (on restore)
pub fn unmark_stack_slot_irq_flag(irq_state: &mut IrqState, ref_obj_id: u32) -> Result<()> {
    irq_state.release_irq(ref_obj_id)
}

/// Unmark stack slot IRQ flag with kfunc class validation
///
/// This ensures that IRQ flags are restored using the matching kfunc class:
/// - native kfuncs (local_irq_save/restore) must be matched
/// - lock kfuncs (spin_lock_irqsave/unlock_irqrestore) must be matched
pub fn unmark_stack_slot_irq_flag_with_class(
    irq_state: &mut IrqState,
    ref_obj_id: u32,
    restore_kfunc_class: IrqKfuncClass,
) -> Result<()> {
    // Find the IRQ flag to get its kfunc class
    let saved_class = irq_state
        .get_irq_flag(ref_obj_id)
        .map(|f| f.kfunc_class)
        .ok_or_else(|| VerifierError::InvalidLock("IRQ flag not found for restore".into()))?;

    // Validate kfunc class compatibility
    let is_native_save = matches!(saved_class, IrqKfuncClass::LocalIrqSave);
    let is_native_restore = matches!(restore_kfunc_class, IrqKfuncClass::LocalIrqRestore);
    let is_lock_save = matches!(saved_class, IrqKfuncClass::SpinLockIrqSave);
    let is_lock_restore = matches!(restore_kfunc_class, IrqKfuncClass::SpinUnlockIrqRestore);

    if (is_native_save && !is_native_restore) || (is_lock_save && !is_lock_restore) {
        let flag_type = if is_native_save { "native" } else { "lock" };
        let used_type = if is_native_restore { "native" } else { "lock" };
        return Err(VerifierError::InvalidLock(format!(
            "IRQ flag acquired by {} kfuncs cannot be restored with {} kfuncs",
            flag_type, used_type
        )));
    }

    irq_state.release_irq(ref_obj_id)
}

/// Check if IRQ flag register is valid for init
pub fn is_irq_flag_reg_valid_uninit(spi: usize, stack_size: usize) -> bool {
    // Check stack slot is within bounds
    spi < stack_size
}

/// Check if IRQ flag register is valid (already initialized)
pub fn is_irq_flag_reg_valid_init(irq_state: &IrqState, ref_obj_id: u32) -> Result<()> {
    if irq_state.get_irq_flag(ref_obj_id).is_none() {
        return Err(VerifierError::InvalidLock(
            "invalid IRQ flag reference".into(),
        ));
    }
    Ok(())
}

/// IRQ-related kfunc IDs
pub mod irq_kfuncs {
    /// bpf_local_irq_save
    pub const LOCAL_IRQ_SAVE: u32 = 0x2001;
    /// bpf_local_irq_restore
    pub const LOCAL_IRQ_RESTORE: u32 = 0x2002;
    /// bpf_spin_lock_irqsave
    pub const SPIN_LOCK_IRQSAVE: u32 = 0x2003;
    /// bpf_spin_unlock_irqrestore
    pub const SPIN_UNLOCK_IRQRESTORE: u32 = 0x2004;
}

/// Get IRQ kfunc class from kfunc ID
pub fn get_irq_kfunc_class(kfunc_id: u32) -> Option<IrqKfuncClass> {
    match kfunc_id {
        irq_kfuncs::LOCAL_IRQ_SAVE => Some(IrqKfuncClass::LocalIrqSave),
        irq_kfuncs::LOCAL_IRQ_RESTORE => Some(IrqKfuncClass::LocalIrqRestore),
        irq_kfuncs::SPIN_LOCK_IRQSAVE => Some(IrqKfuncClass::SpinLockIrqSave),
        irq_kfuncs::SPIN_UNLOCK_IRQRESTORE => Some(IrqKfuncClass::SpinUnlockIrqRestore),
        _ => None,
    }
}

/// Check if kfunc is an IRQ save operation
pub fn is_irq_save_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        irq_kfuncs::LOCAL_IRQ_SAVE | irq_kfuncs::SPIN_LOCK_IRQSAVE
    )
}

/// Check if kfunc is an IRQ restore operation
pub fn is_irq_restore_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        irq_kfuncs::LOCAL_IRQ_RESTORE | irq_kfuncs::SPIN_UNLOCK_IRQRESTORE
    )
}

// ============================================================================
// Extended SyncState with IRQ
// ============================================================================

/// Full synchronization state including IRQ
#[derive(Debug, Clone, Default)]
pub struct FullSyncState {
    /// Basic sync state (locks, RCU, preemption)
    pub sync: SyncState,
    /// IRQ state
    pub irq: IrqState,
}

impl FullSyncState {
    /// Create new full sync state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check all synchronization primitives are properly released
    pub fn check_all_released(&self) -> Result<()> {
        self.sync.check_all_released()?;
        self.irq.check_all_restored()?;
        Ok(())
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &FullSyncState) -> bool {
        self.sync.equivalent(&other.sync) && self.irq.equivalent(&other.irq)
    }

    /// Check if any synchronization is active
    pub fn has_active_sync(&self) -> bool {
        self.sync.lock.has_locks()
            || self.sync.rcu.in_rcu_section
            || self.sync.preempt_disabled
            || self.irq.irqs_disabled()
    }
}
