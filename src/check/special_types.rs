// SPDX-License-Identifier: GPL-2.0

//! Special types verification integration
//!
//! This module integrates dynptr, iterator, and arena verification
//! into the main verification loop.

use alloc::{format, string::String};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reference::ReferenceManager;
use crate::state::reg_state::{BpfRegState, BtfInfo};
use crate::state::verifier_state::BpfVerifierState;

use crate::mem::arena::{check_arena_access, ArenaState};
use crate::special::dynptr::{
    dynptr_id, dynptr_ref_obj_id, is_dynptr_reg_valid_init, mark_stack_slots_dynptr, DynptrInfo,
    DynptrTracker,
};
use crate::special::iter::{
    is_iter_reg_valid_init, is_iter_reg_valid_uninit, iter_get_state, mark_stack_slots_iter,
    unmark_stack_slots_iter, IteratorConvergenceTracker, IteratorKind, IteratorStateMachine,
};

/// Special types context for verification
#[derive(Debug, Default)]
pub struct SpecialTypesContext {
    /// Dynptr tracker
    pub dynptr_tracker: DynptrTracker,
    /// Iterator convergence tracker
    pub iter_tracker: IteratorConvergenceTracker,
    /// Arena state
    pub arena_state: ArenaState,
    /// Current spinlock depth
    pub spin_lock_depth: u32,
    /// Current RCU read lock depth
    pub rcu_lock_depth: u32,
    /// Whether we're in a sleepable context
    pub sleepable: bool,
}

impl SpecialTypesContext {
    /// Create a new special types context
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any special resources are held
    pub fn has_held_resources(&self) -> bool {
        self.dynptr_tracker.active_count() > 0
            || self.iter_tracker.has_active()
            || self.spin_lock_depth > 0
            || self.rcu_lock_depth > 0
    }

    /// Validate cleanup at function exit
    pub fn validate_exit(&self) -> Result<()> {
        // Check dynptrs are released
        self.dynptr_tracker.validate_cleanup()?;

        // Check iterators are destroyed
        self.iter_tracker.validate_cleanup()?;

        // Check locks are released
        if self.spin_lock_depth > 0 {
            return Err(VerifierError::InvalidFunctionCall(
                "spinlock held at exit".into(),
            ));
        }
        if self.rcu_lock_depth > 0 {
            return Err(VerifierError::InvalidFunctionCall(
                "RCU read lock held at exit".into(),
            ));
        }

        Ok(())
    }
}

/// Result of special type argument check
#[derive(Debug, Clone)]
pub struct SpecialArgCheck {
    /// Argument is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Dynptr ID if this is a dynptr arg
    pub dynptr_id: Option<u32>,
    /// Iterator ref ID if this is an iterator arg
    pub iter_ref_id: Option<u32>,
    /// Reference ID if this acquires/releases a reference
    pub ref_id: Option<u32>,
}

impl Default for SpecialArgCheck {
    fn default() -> Self {
        Self {
            valid: true,
            error: None,
            dynptr_id: None,
            iter_ref_id: None,
            ref_id: None,
        }
    }
}

/// Check a helper/kfunc argument for special types
pub fn check_special_type_arg(
    state: &BpfVerifierState,
    reg: &BpfRegState,
    arg_type: BpfArgType,
    ctx: &SpecialTypesContext,
) -> SpecialArgCheck {
    let mut result = SpecialArgCheck::default();

    match arg_type {
        BpfArgType::PtrToDynptr => {
            result = check_dynptr_arg(state, reg, false);
        }
        BpfArgType::PtrToIter => {
            result = check_iter_arg(state, reg);
        }
        BpfArgType::PtrToArena => {
            result = check_arena_arg(state, reg, ctx);
        }
        BpfArgType::PtrToMapValue => {
            // Map value pointers may need special handling
            let _ = (state, reg, ctx);
        }
        _ => {}
    }

    result
}

/// Check dynptr argument
fn check_dynptr_arg(
    state: &BpfVerifierState,
    reg: &BpfRegState,
    nullable: bool,
) -> SpecialArgCheck {
    let mut result = SpecialArgCheck::default();

    let func = match state.cur_func() {
        Some(f) => f,
        None => {
            result.valid = false;
            result.error = Some("no current function".into());
            return result;
        }
    };

    // Check if it's a valid dynptr register
    if !is_dynptr_reg_valid_init(reg, &func.stack) {
        if nullable
            && reg.reg_type == BpfRegType::ScalarValue
            && reg.is_const()
            && reg.const_value() == 0
        {
            // NULL is OK for nullable
            return result;
        }
        result.valid = false;
        result.error = Some("invalid dynptr".into());
        return result;
    }

    // Get dynptr info
    match dynptr_id(reg, &func.stack) {
        Ok(id) => result.dynptr_id = Some(id),
        Err(e) => {
            result.valid = false;
            result.error = Some(format!("failed to get dynptr id: {:?}", e));
            return result;
        }
    }

    // Get ref_obj_id for refcounted dynptrs
    if let Ok(ref_id) = dynptr_ref_obj_id(reg, &func.stack) {
        if ref_id != 0 {
            result.ref_id = Some(ref_id);
        }
    }

    result
}

/// Check iterator argument for open-coded iterator support
fn check_iter_arg(state: &BpfVerifierState, reg: &BpfRegState) -> SpecialArgCheck {
    let mut result = SpecialArgCheck::default();

    let func = match state.cur_func() {
        Some(f) => f,
        None => {
            result.valid = false;
            result.error = Some("no current function".into());
            return result;
        }
    };

    // Determine iterator size (default to 3 slots)
    let nr_slots = 3;

    // Check for uninitialized use (iter_new)
    if is_iter_reg_valid_uninit(reg, &func.stack, nr_slots) {
        // Valid for initialization
        return result;
    }

    // Check for initialized use (iter_next, iter_destroy)
    // Would need BTF ID from kfunc info
    let expected_btf_id = 0; // Placeholder

    match is_iter_reg_valid_init(reg, &func.stack, expected_btf_id, nr_slots) {
        Ok(()) => {
            // Get ref_obj_id
            if let Ok(id) = crate::special::iter::iter_ref_obj_id(reg, &func.stack, nr_slots) {
                result.iter_ref_id = Some(id);
                result.ref_id = Some(id);
            }
        }
        Err(e) => {
            result.valid = false;
            result.error = Some(format!("{:?}", e));
        }
    }

    result
}

/// Check arena argument for BPF arena support
fn check_arena_arg(
    state: &BpfVerifierState,
    reg: &BpfRegState,
    ctx: &SpecialTypesContext,
) -> SpecialArgCheck {
    let mut result = SpecialArgCheck::default();

    if reg.reg_type != BpfRegType::PtrToArena {
        result.valid = false;
        result.error = Some("expected PTR_TO_ARENA".into());
        return result;
    }

    // Validate arena access at offset 0, size 0 (just type check)
    if let Err(e) = check_arena_access(reg, &ctx.arena_state, 0, 0, false) {
        result.valid = false;
        result.error = Some(format!("{:?}", e));
    }

    let _ = state; // Used for additional context
    result
}

/// Process dynptr helper call
pub fn process_dynptr_helper(
    state: &mut BpfVerifierState,
    refs: &mut ReferenceManager,
    ctx: &mut SpecialTypesContext,
    helper_id: u32,
    arg_reg: usize,
    insn_idx: usize,
) -> Result<Option<BpfRegState>> {
    let func = state
        .cur_func_mut()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    let reg = func
        .regs
        .get(arg_reg)
        .ok_or(VerifierError::InvalidRegister(arg_reg as u8))?
        .clone();

    match helper_id {
        // bpf_dynptr_from_mem
        1 => {
            let dynptr_type = BpfDynptrType::Local;
            let id =
                mark_stack_slots_dynptr(&mut func.stack, refs, &reg, dynptr_type, insn_idx, None)?;

            ctx.dynptr_tracker.register(
                id,
                DynptrInfo {
                    dynptr_type,
                    spi: 0, // Would be computed
                    ref_obj_id: 0,
                    created_at: insn_idx,
                    is_clone: false,
                    parent_id: None,
                },
            );

            Ok(None)
        }
        // bpf_ringbuf_reserve_dynptr
        2 => {
            let dynptr_type = BpfDynptrType::Ringbuf;
            let id =
                mark_stack_slots_dynptr(&mut func.stack, refs, &reg, dynptr_type, insn_idx, None)?;

            ctx.dynptr_tracker.register(
                id,
                DynptrInfo {
                    dynptr_type,
                    spi: 0,
                    ref_obj_id: id, // Ringbuf is refcounted
                    created_at: insn_idx,
                    is_clone: false,
                    parent_id: None,
                },
            );

            // Return value is error code
            let mut ret = BpfRegState::new_scalar_unknown(false);
            ret.smin_value = i32::MIN as i64;
            ret.smax_value = 0; // 0 on success, negative on error
            Ok(Some(ret))
        }
        // bpf_dynptr_read/write
        3 | 4 => {
            // Just validate the dynptr
            if !is_dynptr_reg_valid_init(&reg, &func.stack) {
                return Err(VerifierError::InvalidDynptr(
                    "dynptr not initialized".into(),
                ));
            }

            let mut ret = BpfRegState::new_scalar_unknown(false);
            ret.smin_value = i32::MIN as i64;
            ret.smax_value = 0;
            Ok(Some(ret))
        }
        _ => Ok(None),
    }
}

/// Process iterator kfunc call
pub fn process_iter_kfunc(
    state: &mut BpfVerifierState,
    refs: &mut ReferenceManager,
    ctx: &mut SpecialTypesContext,
    kfunc_name: &str,
    arg_reg: usize,
    insn_idx: usize,
    btf_id: u32,
) -> Result<Option<BpfRegState>> {
    let func = state
        .cur_func_mut()
        .ok_or(VerifierError::Internal("no current function".into()))?;

    let reg = func
        .regs
        .get(arg_reg)
        .ok_or(VerifierError::InvalidRegister(arg_reg as u8))?
        .clone();

    if kfunc_name.contains("_new") {
        // Iterator initialization
        let kind = IteratorKind::from_btf_name(kfunc_name);
        let nr_slots = kind.stack_slots();
        let is_rcu = kfunc_name.contains("_rcu");

        let ref_obj_id = mark_stack_slots_iter(
            &mut func.stack,
            refs,
            &reg,
            btf_id,
            nr_slots,
            insn_idx,
            is_rcu,
        )?;

        let iter_sm = IteratorStateMachine::new(kind, btf_id, ref_obj_id, insn_idx, is_rcu);
        ctx.iter_tracker.register(iter_sm)?;

        // Return 0 on success
        let mut ret = BpfRegState::new_scalar_unknown(false);
        ret.mark_known(0);
        Ok(Some(ret))
    } else if kfunc_name.contains("_next") {
        // Iterator next
        let nr_slots = 3; // Default

        // Get iterator state
        let iter_state = iter_get_state(&reg, &func.stack, nr_slots)?;

        if iter_state == BpfIterState::Invalid {
            return Err(VerifierError::InvalidIterator(
                "iterator not initialized".into(),
            ));
        }

        // Update iterator state in tracker
        if let Ok(ref_id) = crate::special::iter::iter_ref_obj_id(&reg, &func.stack, nr_slots) {
            if let Some(iter) = ctx.iter_tracker.get_mut(ref_id) {
                let (_, may_be_null) = iter.process_next()?;

                // Return pointer or NULL
                let mut ret = BpfRegState::new_scalar_unknown(false);
                ret.reg_type = BpfRegType::PtrToBtfId;
                if may_be_null {
                    ret.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
                }
                ret.btf_info = Some(BtfInfo::new(btf_id));
                return Ok(Some(ret));
            }
        }

        // Default: return maybe-null pointer
        let mut ret = BpfRegState::new_scalar_unknown(false);
        ret.reg_type = BpfRegType::PtrToBtfId;
        ret.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
        Ok(Some(ret))
    } else if kfunc_name.contains("_destroy") {
        // Iterator destruction
        let nr_slots = 3;

        // Get ref_obj_id
        let ref_id = crate::special::iter::iter_ref_obj_id(&reg, &func.stack, nr_slots)?;

        // Unmark stack slots and release reference
        unmark_stack_slots_iter(&mut func.stack, refs, &reg, nr_slots)?;

        // Unregister from tracker
        ctx.iter_tracker.unregister(ref_id)?;

        Ok(None)
    } else {
        Ok(None)
    }
}

/// Check if iterator has converged for state pruning
pub fn check_iter_convergence(state: &BpfVerifierState, cached_state: &BpfVerifierState) -> bool {
    let func = match state.cur_func() {
        Some(f) => f,
        None => return false,
    };
    let cached_func = match cached_state.cur_func() {
        Some(f) => f,
        None => return false,
    };

    // Compare iterator states in stack slots
    let num_slots = func.stack.allocated_stack / BPF_REG_SIZE;
    for spi in 0..num_slots {
        let cur_slot = func.stack.get_slot_by_spi(spi);
        let cached_slot = cached_func.stack.get_slot_by_spi(spi);

        match (cur_slot, cached_slot) {
            (Some(cur), Some(cached)) => {
                if cur.get_type() == BpfStackSlotType::Iter
                    && cached.get_type() == BpfStackSlotType::Iter
                {
                    // Check for convergence
                    if !crate::special::iter::check_iter_state_convergence(
                        &func.stack,
                        &cached_func.stack,
                        spi,
                        1,
                    ) {
                        return false;
                    }
                }
            }
            (Some(cur), None) if cur.get_type() == BpfStackSlotType::Iter => {
                return false;
            }
            (None, Some(cached)) if cached.get_type() == BpfStackSlotType::Iter => {
                return false;
            }
            _ => {}
        }
    }

    true
}

/// Validate memory access through special pointer types
pub fn validate_special_mem_access(
    state: &BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    ctx: &SpecialTypesContext,
) -> Result<()> {
    match reg.reg_type {
        BpfRegType::PtrToArena => {
            check_arena_access(reg, &ctx.arena_state, off, size, is_write)?;
        }
        BpfRegType::ConstPtrToDynptr => {
            // Dynptr access - verify through dynptr API
            let func = state
                .cur_func()
                .ok_or(VerifierError::Internal("no current function".into()))?;

            if !is_dynptr_reg_valid_init(reg, &func.stack) {
                return Err(VerifierError::InvalidDynptr(
                    "invalid dynptr for access".into(),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

/// Handle lock acquire for special types
pub fn handle_lock_acquire(ctx: &mut SpecialTypesContext, lock_type: LockType) -> Result<()> {
    match lock_type {
        LockType::SpinLock => {
            if ctx.sleepable {
                return Err(VerifierError::InvalidFunctionCall(
                    "spin_lock in sleepable context".into(),
                ));
            }
            ctx.spin_lock_depth += 1;
        }
        LockType::RcuRead => {
            ctx.rcu_lock_depth += 1;
        }
    }
    Ok(())
}

/// Handle lock release for special types
pub fn handle_lock_release(ctx: &mut SpecialTypesContext, lock_type: LockType) -> Result<()> {
    match lock_type {
        LockType::SpinLock => {
            if ctx.spin_lock_depth == 0 {
                return Err(VerifierError::InvalidFunctionCall(
                    "spin_unlock without lock".into(),
                ));
            }
            ctx.spin_lock_depth -= 1;
        }
        LockType::RcuRead => {
            if ctx.rcu_lock_depth == 0 {
                return Err(VerifierError::InvalidFunctionCall(
                    "rcu_read_unlock without lock".into(),
                ));
            }
            ctx.rcu_lock_depth -= 1;
        }
    }
    Ok(())
}

/// Lock types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// Spinlock
    SpinLock,
    /// RCU read lock
    RcuRead,
}
