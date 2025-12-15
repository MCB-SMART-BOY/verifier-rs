//! Sleepable context validation
//!
//! This module implements validation for sleepable BPF programs.
//! Sleepable programs can call sleeping functions (like bpf_copy_from_user),
//! but have additional restrictions:
//! - Cannot be called while holding spin locks
//! - Cannot be called in atomic context (preempt disabled, RCU read lock)
//! - Cannot be called from certain program types
//!
//! RCU/Preempt interaction rules:
//! - Sleepable helpers cannot be called inside bpf_rcu_read_lock region
//! - Sleepable helpers cannot be called inside bpf_preempt_disable region
//! - Sleepable helpers cannot be called while holding IRQ state
//! - When RCU lock is released, MEM_RCU pointers become invalid
//! - Global functions that might_sleep propagate this property to callers

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::BpfTypeFlag;
use crate::state::verifier_state::BpfVerifierState;
use crate::state::reference::ReferenceManager;
use crate::state::reg_state::BpfRegState;

/// Context state for sleepable validation
#[derive(Debug, Clone, Default)]
pub struct SleepableContext {
    /// Whether program is sleepable
    pub prog_sleepable: bool,
    /// Current atomic context depth
    pub atomic_depth: u32,
    /// Whether in spin lock critical section
    pub in_spin_lock: bool,
    /// Whether in RCU read-side critical section
    pub in_rcu: bool,
    /// Whether preemption is disabled
    pub preempt_disabled: bool,
}

impl SleepableContext {
    /// Create new sleepable context
    pub fn new(prog_sleepable: bool) -> Self {
        Self {
            prog_sleepable,
            atomic_depth: 0,
            in_spin_lock: false,
            in_rcu: false,
            preempt_disabled: false,
        }
    }

    /// Check if currently in atomic context (cannot sleep)
    pub fn in_atomic_context(&self) -> bool {
        self.in_spin_lock || self.in_rcu || self.preempt_disabled || self.atomic_depth > 0
    }

    /// Enter atomic context
    pub fn enter_atomic(&mut self) {
        self.atomic_depth += 1;
    }

    /// Leave atomic context
    pub fn leave_atomic(&mut self) -> Result<()> {
        if self.atomic_depth == 0 {
            return Err(VerifierError::Internal(
                "leaving atomic context without entering".into()
            ));
        }
        self.atomic_depth -= 1;
        Ok(())
    }

    /// Enter spin lock
    pub fn enter_spin_lock(&mut self) {
        self.in_spin_lock = true;
    }

    /// Leave spin lock
    pub fn leave_spin_lock(&mut self) {
        self.in_spin_lock = false;
    }

    /// Enter RCU read-side
    pub fn enter_rcu(&mut self) {
        self.in_rcu = true;
    }

    /// Leave RCU read-side
    pub fn leave_rcu(&mut self) {
        self.in_rcu = false;
    }

    /// Disable preemption
    pub fn disable_preempt(&mut self) {
        self.preempt_disabled = true;
    }

    /// Enable preemption
    pub fn enable_preempt(&mut self) {
        self.preempt_disabled = false;
    }
}

/// Check if a sleepable helper can be called in current context
pub fn check_sleepable_call(
    state: &BpfVerifierState,
    refs: &ReferenceManager,
    helper_name: &str,
) -> Result<()> {
    // Check for spin lock held
    if refs.active_locks > 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "cannot call sleepable helper '{}' while holding spin lock",
            helper_name
        )));
    }

    // Check for RCU read lock held
    if refs.in_rcu() {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "cannot call sleepable helper '{}' while in RCU read-side critical section",
            helper_name
        )));
    }

    // Check for preemption disabled
    if refs.active_preempt_locks > 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "cannot call sleepable helper '{}' while preemption is disabled",
            helper_name
        )));
    }

    // Check for IRQ state held
    if refs.active_irq_id != 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "cannot call sleepable helper '{}' while holding IRQ state",
            helper_name
        )));
    }

    // Verify program is sleepable
    if !state.in_sleepable {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "sleepable helper '{}' requires sleepable program",
            helper_name
        )));
    }

    Ok(())
}

/// Check if entering a non-sleepable context is valid
pub fn check_enter_non_sleepable(
    state: &BpfVerifierState,
    context_name: &str,
) -> Result<()> {
    // This is always allowed - we're just tracking state
    let _ = (state, context_name);
    Ok(())
}

/// Helpers that require sleepable context
pub fn is_sleepable_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        113 | // bpf_copy_from_user
        114 | // bpf_copy_to_user  (hypothetical)
        209 | // bpf_copy_from_user_task
        195 | // bpf_ima_inode_hash
        174 | // bpf_find_vma (can sleep)
        210   // bpf_ima_file_hash
    )
}

/// Helpers that are forbidden in sleepable programs
pub fn is_forbidden_in_sleepable(helper_id: u32) -> bool {
    matches!(
        helper_id,
        12 | // bpf_tail_call - changes control flow
        25 | // bpf_get_prandom_u32 - atomic context may be required
        35   // bpf_spin_lock - should use res_spin_lock in sleepable
    )
}

/// Check helper compatibility with sleepable context
pub fn check_helper_sleepable_compat(
    state: &BpfVerifierState,
    refs: &ReferenceManager,
    helper_id: u32,
    helper_name: &str,
    helper_may_sleep: bool,
) -> Result<()> {
    // If helper may sleep, check sleepable constraints
    if helper_may_sleep || is_sleepable_helper(helper_id) {
        check_sleepable_call(state, refs, helper_name)?;
    }

    // If program is sleepable, check forbidden helpers
    if state.in_sleepable && is_forbidden_in_sleepable(helper_id) {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "helper '{}' is not allowed in sleepable programs",
            helper_name
        )));
    }

    Ok(())
}

/// Check kfunc compatibility with sleepable context
pub fn check_kfunc_sleepable_compat(
    state: &BpfVerifierState,
    refs: &ReferenceManager,
    kfunc_name: &str,
    kfunc_sleepable: bool,
) -> Result<()> {
    if kfunc_sleepable {
        check_sleepable_call(state, refs, kfunc_name)?;
    }
    Ok(())
}

/// Validate that program can be marked sleepable
pub fn validate_sleepable_prog(prog_type: crate::core::types::BpfProgType) -> Result<()> {
    use crate::core::types::BpfProgType;
    
    // Only certain program types can be sleepable
    match prog_type {
        BpfProgType::Tracing |
        BpfProgType::Lsm |
        BpfProgType::StructOps |
        BpfProgType::Syscall => Ok(()),
        _ => Err(VerifierError::InvalidFunctionCall(format!(
            "{:?} programs cannot be sleepable",
            prog_type
        ))),
    }
}

/// Check callback context for sleepable restrictions
pub fn check_callback_sleepable(
    state: &BpfVerifierState,
    callback_sleepable: bool,
) -> Result<()> {
    if callback_sleepable && !state.in_sleepable {
        return Err(VerifierError::InvalidFunctionCall(
            "sleepable callback requires sleepable program".into()
        ));
    }
    Ok(())
}

/// Check if we're in a sleepable context (kernel's in_sleepable_context)
/// 
/// Returns true only if:
/// - No active RCU locks
/// - No active preempt locks  
/// - No active IRQ state
/// - Program is sleepable
pub fn in_sleepable_context(state: &BpfVerifierState, refs: &ReferenceManager) -> bool {
    refs.active_rcu_locks == 0 &&
    refs.active_preempt_locks == 0 &&
    refs.active_irq_id == 0 &&
    state.in_sleepable
}

/// Check if we're in RCU read-side critical section (kernel's in_rcu_cs)
/// 
/// Returns true if:
/// - Active RCU locks, OR
/// - Active spin locks, OR
/// - Not in sleepable program
pub fn in_rcu_cs(state: &BpfVerifierState, refs: &ReferenceManager) -> bool {
    refs.active_rcu_locks > 0 ||
    refs.active_locks > 0 ||
    !state.in_sleepable
}

/// Clear MEM_RCU flag from a register when RCU lock is released
/// 
/// When bpf_rcu_read_unlock is called and the RCU lock count drops to zero,
/// all pointers with MEM_RCU flag must have this flag cleared since they
/// are no longer protected.
pub fn clear_rcu_flag(reg: &mut BpfRegState) {
    if reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
        reg.type_flags.remove(BpfTypeFlag::MEM_RCU);
        // Also remove PTR_MAYBE_NULL if it was only set due to RCU
        // (kernel does: reg->type &= ~(MEM_RCU | PTR_MAYBE_NULL))
        reg.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
    }
}

/// Information about registers that need RCU flag clearing
#[derive(Debug, Clone)]
pub struct RcuClearInfo {
    /// Register index
    pub reg_idx: usize,
    /// Stack slot offset (if spilled)
    pub stack_off: Option<i32>,
    /// Frame number
    pub frame: u32,
}

/// Find all registers and stack slots with MEM_RCU flag
/// 
/// This is used when RCU lock is released to find all pointers that
/// need their MEM_RCU flag cleared.
pub fn find_rcu_protected_regs(state: &BpfVerifierState) -> Vec<RcuClearInfo> {
    let mut result = Vec::new();
    
    // Check all frames
    for (frame_idx, maybe_func_state) in state.frame.iter().enumerate() {
        let func_state = match maybe_func_state {
            Some(fs) => fs,
            None => continue,
        };
        
        // Check registers
        for (reg_idx, reg) in func_state.regs.iter().enumerate() {
            if reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
                result.push(RcuClearInfo {
                    reg_idx,
                    stack_off: None,
                    frame: frame_idx as u32,
                });
            }
        }
        
        // Check spilled registers on stack
        // stack.stack is Vec<BpfStackState>, each slot is 8 bytes
        for (slot_idx, slot) in func_state.stack.stack.iter().enumerate() {
            // Check if spilled_ptr has MEM_RCU flag
            if slot.spilled_ptr.type_flags.contains(BpfTypeFlag::MEM_RCU) {
                // Convert slot index to stack offset (slot 0 = fp-8, slot 1 = fp-16, etc.)
                let off = -(((slot_idx + 1) * 8) as i32);
                result.push(RcuClearInfo {
                    reg_idx: 0, // Not a register
                    stack_off: Some(off),
                    frame: frame_idx as u32,
                });
            }
        }
    }
    
    result
}

/// Check if a global function call is valid in current context
/// 
/// Global functions that might sleep cannot be called from:
/// - RCU read-side critical section
/// - Preempt-disabled region  
/// - IRQ-disabled region
/// - Non-sleepable program
pub fn check_global_func_sleepable(
    state: &BpfVerifierState,
    refs: &ReferenceManager,
    func_name: &str,
    might_sleep: bool,
) -> Result<()> {
    if !might_sleep {
        return Ok(());
    }
    
    if refs.active_rcu_locks > 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "global function '{}' that may sleep cannot be called in RCU read-side critical section",
            func_name
        )));
    }
    
    if refs.active_preempt_locks > 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "global function '{}' that may sleep cannot be called in preempt-disabled region",
            func_name
        )));
    }
    
    if refs.active_irq_id != 0 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "global function '{}' that may sleep cannot be called in IRQ-disabled region",
            func_name
        )));
    }
    
    if !state.in_sleepable {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "global function '{}' that may sleep cannot be called from non-sleepable program",
            func_name
        )));
    }
    
    Ok(())
}

/// Propagate might_sleep property from callee to caller
/// 
/// If a subprogram calls another subprogram that might_sleep,
/// the caller also might_sleep.
pub fn propagate_might_sleep(caller_might_sleep: &mut bool, callee_might_sleep: bool) {
    *caller_might_sleep |= callee_might_sleep;
}

/// Check kfunc RCU/preempt restrictions
/// 
/// Handles special kfuncs:
/// - bpf_rcu_read_lock: increments RCU lock count
/// - bpf_rcu_read_unlock: decrements RCU lock count, clears MEM_RCU
/// - bpf_preempt_disable: increments preempt lock count
/// - bpf_preempt_enable: decrements preempt lock count
/// - Sleepable kfuncs: cannot be called in RCU/preempt region
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncSyncAction {
    /// No synchronization action needed
    None,
    /// Increment RCU lock count
    RcuLock,
    /// Decrement RCU lock count and clear MEM_RCU flags
    RcuUnlock,
    /// Increment preempt lock count
    PreemptDisable,
    /// Decrement preempt lock count
    PreemptEnable,
}

/// Determine what synchronization action a kfunc performs
pub fn get_kfunc_sync_action(kfunc_name: &str) -> KfuncSyncAction {
    match kfunc_name {
        "bpf_rcu_read_lock" => KfuncSyncAction::RcuLock,
        "bpf_rcu_read_unlock" => KfuncSyncAction::RcuUnlock,
        "bpf_preempt_disable" => KfuncSyncAction::PreemptDisable,
        "bpf_preempt_enable" => KfuncSyncAction::PreemptEnable,
        _ => KfuncSyncAction::None,
    }
}

/// Validate kfunc call with respect to RCU/preempt state
pub fn check_kfunc_sync_context(
    _state: &BpfVerifierState,
    refs: &ReferenceManager,
    kfunc_name: &str,
    is_sleepable: bool,
) -> Result<()> {
    let action = get_kfunc_sync_action(kfunc_name);
    
    match action {
        KfuncSyncAction::RcuUnlock => {
            if refs.active_rcu_locks == 0 {
                return Err(VerifierError::InvalidKfunc(format!(
                    "unmatched rcu read unlock (kernel function {})",
                    kfunc_name
                )));
            }
        }
        KfuncSyncAction::PreemptEnable => {
            if refs.active_preempt_locks == 0 {
                return Err(VerifierError::InvalidKfunc(format!(
                    "unmatched attempt to enable preemption (kernel function {})",
                    kfunc_name
                )));
            }
        }
        _ => {}
    }
    
    // Check sleepable kfuncs
    if is_sleepable {
        if refs.active_rcu_locks > 0 {
            return Err(VerifierError::InvalidKfunc(format!(
                "kernel func {} is sleepable within rcu_read_lock region",
                kfunc_name
            )));
        }
        
        if refs.active_preempt_locks > 0 {
            return Err(VerifierError::InvalidKfunc(format!(
                "kernel func {} is sleepable within non-preemptible region",
                kfunc_name
            )));
        }
        
        if refs.active_irq_id != 0 {
            return Err(VerifierError::InvalidKfunc(format!(
                "kernel func {} is sleepable within IRQ-disabled region",
                kfunc_name
            )));
        }
    }
    
    Ok(())
}

/// Apply synchronization state changes after kfunc call
pub fn apply_kfunc_sync_action(
    refs: &mut ReferenceManager,
    kfunc_name: &str,
) -> Result<bool> {
    let action = get_kfunc_sync_action(kfunc_name);
    
    match action {
        KfuncSyncAction::RcuLock => {
            refs.rcu_lock();
            Ok(false) // No MEM_RCU clearing needed
        }
        KfuncSyncAction::RcuUnlock => {
            refs.rcu_unlock()?;
            // Return true if this was the last RCU lock (need to clear MEM_RCU)
            Ok(refs.active_rcu_locks == 0)
        }
        KfuncSyncAction::PreemptDisable => {
            refs.preempt_disable();
            Ok(false)
        }
        KfuncSyncAction::PreemptEnable => {
            refs.preempt_enable()?;
            Ok(false)
        }
        KfuncSyncAction::None => Ok(false),
    }
}

/// Validate iterator access under RCU protection
/// 
/// Iterators that return RCU-protected pointers (KF_RCU_PROTECTED)
/// must be used within an RCU read-side critical section.
pub fn check_iter_rcu_protected(
    refs: &ReferenceManager,
    iter_name: &str,
    is_rcu_protected: bool,
) -> Result<()> {
    if is_rcu_protected && refs.active_rcu_locks == 0 {
        return Err(VerifierError::InvalidIterator(format!(
            "iterator '{}' returns RCU-protected pointer but not in RCU read-side critical section",
            iter_name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::reference::ReferenceManager;
    use crate::core::types::BpfRegType;

    #[test]
    fn test_sleepable_context() {
        let mut ctx = SleepableContext::new(true);
        assert!(!ctx.in_atomic_context());

        ctx.enter_spin_lock();
        assert!(ctx.in_atomic_context());

        ctx.leave_spin_lock();
        assert!(!ctx.in_atomic_context());
    }

    #[test]
    fn test_atomic_depth() {
        let mut ctx = SleepableContext::new(true);
        ctx.enter_atomic();
        ctx.enter_atomic();
        assert!(ctx.in_atomic_context());

        ctx.leave_atomic().unwrap();
        assert!(ctx.in_atomic_context());

        ctx.leave_atomic().unwrap();
        assert!(!ctx.in_atomic_context());
    }

    #[test]
    fn test_check_sleepable_call_with_lock() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Should succeed without locks
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_ok());

        // Should fail with lock held
        refs.acquire_lock(0, 0x1000);
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_check_sleepable_call_with_rcu() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();

        // Should succeed without RCU
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_ok());

        // Should fail with RCU held
        refs.rcu_lock();
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_check_sleepable_call_non_sleepable_prog() {
        let state = BpfVerifierState::new(); // in_sleepable = false by default
        let refs = ReferenceManager::new();

        // Should fail because program is not sleepable
        assert!(check_sleepable_call(&state, &refs, "test_helper").is_err());
    }

    #[test]
    fn test_is_sleepable_helper() {
        assert!(is_sleepable_helper(113)); // bpf_copy_from_user
        assert!(is_sleepable_helper(174)); // bpf_find_vma
        assert!(!is_sleepable_helper(1));  // bpf_map_lookup_elem
    }

    #[test]
    fn test_is_forbidden_in_sleepable() {
        assert!(is_forbidden_in_sleepable(12)); // bpf_tail_call
        assert!(is_forbidden_in_sleepable(35)); // bpf_spin_lock
        assert!(!is_forbidden_in_sleepable(1)); // bpf_map_lookup_elem
    }

    #[test]
    fn test_in_sleepable_context() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Sleepable program with no locks - should be in sleepable context
        assert!(in_sleepable_context(&state, &refs));
        
        // With RCU lock - not in sleepable context
        refs.rcu_lock();
        assert!(!in_sleepable_context(&state, &refs));
        refs.rcu_unlock().unwrap();
        
        // With preempt disabled - not in sleepable context
        refs.preempt_disable();
        assert!(!in_sleepable_context(&state, &refs));
        refs.preempt_enable().unwrap();
        
        // Non-sleepable program - not in sleepable context
        state.in_sleepable = false;
        assert!(!in_sleepable_context(&state, &refs));
    }

    #[test]
    fn test_in_rcu_cs() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Sleepable program with no locks - not in RCU CS
        assert!(!in_rcu_cs(&state, &refs));
        
        // With RCU lock - in RCU CS
        refs.rcu_lock();
        assert!(in_rcu_cs(&state, &refs));
        refs.rcu_unlock().unwrap();
        
        // With spin lock - in RCU CS
        refs.acquire_lock(0, 0x1000);
        assert!(in_rcu_cs(&state, &refs));
        
        // Non-sleepable program - always in RCU CS
        state.in_sleepable = false;
        let refs2 = ReferenceManager::new();
        assert!(in_rcu_cs(&state, &refs2));
    }

    #[test]
    fn test_clear_rcu_flag() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToBtfId;
        reg.type_flags.insert(BpfTypeFlag::MEM_RCU);
        reg.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
        
        assert!(reg.type_flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
        
        clear_rcu_flag(&mut reg);
        
        assert!(!reg.type_flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(!reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    }

    #[test]
    fn test_get_kfunc_sync_action() {
        assert_eq!(get_kfunc_sync_action("bpf_rcu_read_lock"), KfuncSyncAction::RcuLock);
        assert_eq!(get_kfunc_sync_action("bpf_rcu_read_unlock"), KfuncSyncAction::RcuUnlock);
        assert_eq!(get_kfunc_sync_action("bpf_preempt_disable"), KfuncSyncAction::PreemptDisable);
        assert_eq!(get_kfunc_sync_action("bpf_preempt_enable"), KfuncSyncAction::PreemptEnable);
        assert_eq!(get_kfunc_sync_action("other_kfunc"), KfuncSyncAction::None);
    }

    #[test]
    fn test_check_kfunc_sync_context_rcu() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // RCU unlock without lock should fail
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_rcu_read_unlock", false).is_err());
        
        // RCU lock should succeed
        refs.rcu_lock();
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_rcu_read_unlock", false).is_ok());
        
        // Sleepable kfunc in RCU region should fail
        assert!(check_kfunc_sync_context(&state, &refs, "sleepable_kfunc", true).is_err());
    }

    #[test]
    fn test_check_kfunc_sync_context_preempt() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Preempt enable without disable should fail
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_preempt_enable", false).is_err());
        
        // Preempt disable should succeed
        refs.preempt_disable();
        assert!(check_kfunc_sync_context(&state, &refs, "bpf_preempt_enable", false).is_ok());
        
        // Sleepable kfunc in preempt-disabled region should fail
        assert!(check_kfunc_sync_context(&state, &refs, "sleepable_kfunc", true).is_err());
    }

    #[test]
    fn test_apply_kfunc_sync_action() {
        let mut refs = ReferenceManager::new();
        
        // RCU lock
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_lock").unwrap());
        assert_eq!(refs.active_rcu_locks, 1);
        
        // Nested RCU lock
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_lock").unwrap());
        assert_eq!(refs.active_rcu_locks, 2);
        
        // RCU unlock (not last)
        assert!(!apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_unlock").unwrap());
        assert_eq!(refs.active_rcu_locks, 1);
        
        // RCU unlock (last) - should return true for MEM_RCU clearing
        assert!(apply_kfunc_sync_action(&mut refs, "bpf_rcu_read_unlock").unwrap());
        assert_eq!(refs.active_rcu_locks, 0);
    }

    #[test]
    fn test_check_global_func_sleepable() {
        let mut state = BpfVerifierState::new();
        state.in_sleepable = true;
        let mut refs = ReferenceManager::new();
        
        // Non-sleepable function should always pass
        assert!(check_global_func_sleepable(&state, &refs, "func", false).is_ok());
        
        // Sleepable function in sleepable context should pass
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_ok());
        
        // Sleepable function in RCU region should fail
        refs.rcu_lock();
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
        refs.rcu_unlock().unwrap();
        
        // Sleepable function in preempt-disabled region should fail
        refs.preempt_disable();
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
        refs.preempt_enable().unwrap();
        
        // Sleepable function in non-sleepable program should fail
        state.in_sleepable = false;
        assert!(check_global_func_sleepable(&state, &refs, "func", true).is_err());
    }

    #[test]
    fn test_propagate_might_sleep() {
        let mut caller = false;
        
        // Propagate from non-sleeping callee
        propagate_might_sleep(&mut caller, false);
        assert!(!caller);
        
        // Propagate from sleeping callee
        propagate_might_sleep(&mut caller, true);
        assert!(caller);
        
        // Already sleeping caller stays sleeping
        propagate_might_sleep(&mut caller, false);
        assert!(caller);
    }

    #[test]
    fn test_check_iter_rcu_protected() {
        let mut refs = ReferenceManager::new();
        
        // Non-RCU-protected iterator should pass
        assert!(check_iter_rcu_protected(&refs, "iter", false).is_ok());
        
        // RCU-protected iterator without RCU lock should fail
        assert!(check_iter_rcu_protected(&refs, "iter", true).is_err());
        
        // RCU-protected iterator with RCU lock should pass
        refs.rcu_lock();
        assert!(check_iter_rcu_protected(&refs, "iter", true).is_ok());
    }
}
