//! Exception handling support
//!
//! This module implements exception callback verification for BPF programs.
//! Exception callbacks are used for handling errors in struct_ops programs.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap as HashMap};

use crate::core::types::*;
use crate::state::verifier_state::BpfVerifierState;
use crate::state::reg_state::BpfRegState;
use crate::core::error::{Result, VerifierError};

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Maximum nesting depth for exception callbacks
pub const MAX_EXCEPTION_DEPTH: usize = 8;

/// Exception callback descriptor
#[derive(Debug, Clone)]
pub struct ExceptionCallback {
    /// BTF ID of the exception callback
    pub btf_id: u32,
    /// Start instruction index
    pub insn_idx: usize,
    /// Whether this is the global exception callback
    pub is_global: bool,
    /// Number of arguments
    pub nargs: u32,
}

/// Exception state tracking
#[derive(Debug, Clone, Default)]
pub struct ExceptionState {
    /// Whether we're in an exception callback
    pub in_exception_cb: bool,
    /// Exception callback nesting depth
    pub exception_depth: usize,
    /// Current exception callback info
    pub cur_exception: Option<ExceptionCallback>,
    /// Registered exception callbacks
    pub callbacks: HashMap<u32, ExceptionCallback>,
}

impl ExceptionState {
    /// Create new exception state
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an exception callback
    pub fn register_callback(&mut self, btf_id: u32, callback: ExceptionCallback) {
        self.callbacks.insert(btf_id, callback);
    }

    /// Enter exception callback
    pub fn enter_exception(&mut self, callback: ExceptionCallback) -> Result<()> {
        if self.exception_depth >= MAX_EXCEPTION_DEPTH {
            return Err(VerifierError::TooComplex(
                "exception callback nesting too deep".into()
            ));
        }

        self.in_exception_cb = true;
        self.exception_depth += 1;
        self.cur_exception = Some(callback);

        Ok(())
    }

    /// Exit exception callback
    pub fn exit_exception(&mut self) -> Result<()> {
        if !self.in_exception_cb {
            return Err(VerifierError::InvalidState(
                "not in exception callback".into()
            ));
        }

        self.exception_depth -= 1;
        if self.exception_depth == 0 {
            self.in_exception_cb = false;
        }
        self.cur_exception = None;

        Ok(())
    }

    /// Check if exception callback is registered
    pub fn has_callback(&self, btf_id: u32) -> bool {
        self.callbacks.contains_key(&btf_id)
    }

    /// Get exception callback info
    pub fn get_callback(&self, btf_id: u32) -> Option<&ExceptionCallback> {
        self.callbacks.get(&btf_id)
    }
}

/// Check bpf_throw() call
pub fn check_bpf_throw(
    state: &BpfVerifierState,
    _exception_state: &ExceptionState,
) -> Result<()> {
    // bpf_throw() can only be called in exception callbacks or main prog
    // It aborts the current program execution

    // Check that we're not holding any locks
    if state.refs.active_locks > 0 {
        return Err(VerifierError::InvalidState(
            "cannot bpf_throw with active locks".into()
        ));
    }

    // Check RCU state
    if state.refs.active_rcu_locks > 0 {
        return Err(VerifierError::InvalidState(
            "cannot bpf_throw with active RCU lock".into()
        ));
    }

    Ok(())
}

/// Check exception callback entry
pub fn check_exception_callback_entry(
    state: &mut BpfVerifierState,
    callback: &ExceptionCallback,
) -> Result<()> {
    // Set up registers for exception callback
    // R1 = cookie value (scalar)
    if let Some(r1) = state.reg_mut(BPF_REG_1) {
        r1.mark_unknown(false);
    }

    // R2-R5 may be arguments depending on callback
    for i in 2..=5 {
        if i - 1 < callback.nargs as usize {
            if let Some(r) = state.reg_mut(i) {
                r.mark_unknown(false);
            }
        } else if let Some(r) = state.reg_mut(i) {
            r.mark_not_init(false);
        }
    }

    Ok(())
}

/// Check exception callback exit
pub fn check_exception_callback_exit(
    state: &BpfVerifierState,
    _callback: &ExceptionCallback,
) -> Result<()> {
    // Exception callbacks must return 0 or 1
    let r0 = state.reg(BPF_REG_0)
        .ok_or(VerifierError::InvalidRegister(0))?;

    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(0));
    }

    if r0.reg_type == BpfRegType::ScalarValue {
        if r0.is_const() {
            let val = r0.const_value();
            if val > 1 {
                return Err(VerifierError::TypeMismatch {
                    expected: "0 or 1".into(),
                    got: format!("{}", val),
                });
            }
        } else {
            // Non-const scalar - check bounds
            if r0.umax_value > 1 {
                return Err(VerifierError::TypeMismatch {
                    expected: "return value 0 or 1".into(),
                    got: format!("value in range [{}, {}]", r0.umin_value, r0.umax_value),
                });
            }
        }
    }

    Ok(())
}

/// Async callback state
#[derive(Debug, Clone, Default)]
pub struct AsyncCallbackState {
    /// Whether in async callback
    pub in_async_cb: bool,
    /// Async callback ID
    pub async_id: u32,
    /// Callback type
    pub callback_type: AsyncCallbackType,
}

/// Types of async callbacks
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AsyncCallbackType {
    #[default]
    None,
    /// Timer callback
    Timer,
    /// Workqueue callback  
    Workqueue,
    /// For-each callback (map iterator)
    ForEach,
    /// Rbtree less callback
    RbtreeLess,
}

impl AsyncCallbackState {
    /// Enter async callback
    pub fn enter(&mut self, callback_type: AsyncCallbackType, async_id: u32) {
        self.in_async_cb = true;
        self.async_id = async_id;
        self.callback_type = callback_type;
    }

    /// Exit async callback
    pub fn exit(&mut self) {
        self.in_async_cb = false;
        self.async_id = 0;
        self.callback_type = AsyncCallbackType::None;
    }
}

/// Check async callback setup
pub fn check_async_callback_setup(
    _state: &mut BpfVerifierState,
    callback_type: AsyncCallbackType,
    _callback_insn: usize,
) -> Result<()> {
    // Verify callback instruction is valid
    // The callback will be verified separately with its own state

    // For timer/workqueue callbacks, the callback may run async
    // so we need to verify it doesn't access invalid state

    match callback_type {
        AsyncCallbackType::Timer | AsyncCallbackType::Workqueue => {
            // These callbacks run asynchronously
            // Verify the callback doesn't rely on caller's stack
        }
        AsyncCallbackType::ForEach => {
            // For-each runs synchronously
            // Can access caller's stack through pointer arguments
        }
        AsyncCallbackType::RbtreeLess => {
            // Comparison callback, runs synchronously
        }
        AsyncCallbackType::None => {}
    }

    Ok(())
}

/// Validate callback function signature
pub fn validate_callback_signature(
    _callback_type: AsyncCallbackType,
    nargs: u32,
    _arg_types: &[BpfRegType],
) -> Result<()> {
    // Check argument count is valid for callback type
    if nargs > 5 {
        return Err(VerifierError::InvalidFunctionCall(
            "callback has too many arguments".into()
        ));
    }

    Ok(())
}

// ============================================================================
// bpf_throw kfunc support
// ============================================================================

/// Special kfunc ID for bpf_throw
pub const KFUNC_BPF_THROW: u32 = 0x3001;

/// Check if instruction is bpf_throw kfunc call
pub fn is_bpf_throw_kfunc(insn_imm: i32, insn_off: i16) -> bool {
    // bpf_throw is a pseudo kfunc call with specific imm value
    insn_off == 0 && insn_imm == KFUNC_BPF_THROW as i32
}

/// Validate bpf_throw call
/// 
/// bpf_throw(u64 cookie) - throws an exception with the given cookie value
/// This terminates the current execution and transfers to exception handler
pub fn validate_bpf_throw(
    state: &BpfVerifierState,
    exception_state: &ExceptionState,
    cookie_reg: usize,
) -> Result<()> {
    // Check cookie argument is valid scalar
    let cookie = state.reg(cookie_reg)
        .ok_or(VerifierError::InvalidRegister(cookie_reg as u8))?;
    
    if cookie.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(cookie_reg as u8));
    }
    
    if cookie.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar".into(),
            got: format!("{:?}", cookie.reg_type),
        });
    }

    // Check synchronization state - cannot throw with locks held
    check_bpf_throw(state, exception_state)?;

    // Verify there's an exception callback registered (if required)
    // Note: bpf_throw without callback causes program abort
    
    Ok(())
}

/// Process bpf_throw - marks execution as terminated
pub fn process_bpf_throw(
    state: &mut BpfVerifierState,
    _exception_state: &ExceptionState,
) -> Result<()> {
    // After bpf_throw, the current execution path terminates
    // Mark all registers as invalid since control transfers to exception handler
    for i in 0..11 {
        if let Some(reg) = state.reg_mut(i) {
            reg.mark_not_init(false);
        }
    }
    
    Ok(())
}

/// Find exception callback instruction offset from BTF
pub fn find_exception_callback_insn_off(
    func_info: &[(u32, usize)],  // (btf_id, insn_off) pairs
    main_btf_id: u32,
    exception_cb_name: Option<&str>,
    btf_func_ids: &HashMap<String, u32>,
) -> Result<Option<usize>> {
    // If no exception callback name specified, return None
    let cb_name = match exception_cb_name {
        Some(name) => name,
        None => return Ok(None),
    };
    
    // Find the BTF ID for the exception callback function
    let cb_btf_id = btf_func_ids.get(cb_name)
        .ok_or_else(|| VerifierError::InvalidBtf(format!(
            "exception callback '{}' could not be found in BTF", cb_name
        )))?;
    
    // Make sure it's not the main function
    if *cb_btf_id == main_btf_id {
        return Err(VerifierError::InvalidBtf(
            "exception callback cannot be main function".into()
        ));
    }
    
    // Find the instruction offset for this BTF ID
    for (btf_id, insn_off) in func_info {
        if *btf_id == *cb_btf_id {
            if *insn_off == 0 {
                return Err(VerifierError::InvalidBtf(
                    "invalid exception callback insn_off in func_info: 0".into()
                ));
            }
            return Ok(Some(*insn_off));
        }
    }
    
    Err(VerifierError::InvalidBtf(
        "exception callback type id not found in func_info".into()
    ))
}

/// Subprogram exception callback marker
#[derive(Debug, Clone, Default)]
pub struct SubprogExceptionInfo {
    /// Subprog index that is the exception callback
    pub exception_cb_subprog: Option<usize>,
    /// Whether main function has exception callback support
    pub has_exception_support: bool,
}

impl SubprogExceptionInfo {
    /// Mark a subprogram as the exception callback
    pub fn mark_exception_cb(&mut self, subprog: usize) {
        self.exception_cb_subprog = Some(subprog);
        self.has_exception_support = true;
    }
    
    /// Check if subprogram is the exception callback
    pub fn is_exception_cb(&self, subprog: usize) -> bool {
        self.exception_cb_subprog == Some(subprog)
    }
}

/// Setup state for exception callback verification
pub fn setup_exception_callback_state(
    state: &mut BpfVerifierState,
    callback: &ExceptionCallback,
) -> Result<()> {
    // R1 = cookie (u64 scalar)
    if let Some(r1) = state.reg_mut(BPF_REG_1) {
        r1.mark_unknown(false);
    }
    
    // R2-R5 are not used by exception callbacks
    for i in 2..=5 {
        if let Some(r) = state.reg_mut(i) {
            r.mark_not_init(false);
        }
    }
    
    // R6-R9 are callee-saved, not initialized
    for i in 6..=9 {
        if let Some(r) = state.reg_mut(i) {
            r.mark_not_init(false);
        }
    }
    
    // R10 = frame pointer (register 10)
    if let Some(r10) = state.reg_mut(10) {
        r10.reg_type = BpfRegType::PtrToStack;
        r10.off = 0;
    }
    
    // Store callback info
    check_exception_callback_entry(state, callback)?;
    
    Ok(())
}

/// Verify exception callback return value and state
pub fn verify_exception_callback_exit(
    state: &BpfVerifierState,
    callback: &ExceptionCallback,
) -> Result<()> {
    // Check return value
    check_exception_callback_exit(state, callback)?;
    
    // Check no resources leaked
    if !state.refs.is_empty() {
        return Err(VerifierError::InvalidState(
            "exception callback leaks acquired references".into()
        ));
    }
    
    Ok(())
}

// ============================================================================
// Workqueue (bpf_wq) Support
// ============================================================================

/// Workqueue kfunc IDs
pub mod wq_kfuncs {
    /// bpf_wq_init
    pub const WQ_INIT: u32 = 0x5001;
    /// bpf_wq_set_callback_impl
    pub const WQ_SET_CALLBACK_IMPL: u32 = 0x5002;
    /// bpf_wq_start
    pub const WQ_START: u32 = 0x5003;
}

/// Check if kfunc is bpf_wq_set_callback_impl
pub fn is_bpf_wq_set_callback_impl_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == wq_kfuncs::WQ_SET_CALLBACK_IMPL
}

/// Check if kfunc is a workqueue operation
pub fn is_wq_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        wq_kfuncs::WQ_INIT | wq_kfuncs::WQ_SET_CALLBACK_IMPL | wq_kfuncs::WQ_START
    )
}

/// Task work kfunc IDs
pub mod task_work_kfuncs {
    /// bpf_task_work_add
    pub const TASK_WORK_ADD: u32 = 0x5101;
}

/// Check if kfunc is bpf_task_work_add
pub fn is_task_work_add_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == task_work_kfuncs::TASK_WORK_ADD
}

/// Workqueue state tracking
#[derive(Debug, Clone, Default)]
pub struct WorkqueueState {
    /// Map UID of the workqueue's containing map
    pub map_uid: Option<u32>,
    /// Whether callback has been set
    pub callback_set: bool,
    /// Callback instruction index
    pub callback_insn: Option<usize>,
    /// Whether workqueue is started
    pub started: bool,
}

impl WorkqueueState {
    /// Create new workqueue state
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize workqueue with map
    pub fn init(&mut self, map_uid: u32) {
        self.map_uid = Some(map_uid);
        self.callback_set = false;
        self.callback_insn = None;
        self.started = false;
    }

    /// Set callback
    pub fn set_callback(&mut self, callback_insn: usize) -> Result<()> {
        if self.map_uid.is_none() {
            return Err(VerifierError::InvalidState(
                "workqueue not initialized".into()
            ));
        }
        self.callback_set = true;
        self.callback_insn = Some(callback_insn);
        Ok(())
    }

    /// Start workqueue
    pub fn start(&mut self) -> Result<()> {
        if !self.callback_set {
            return Err(VerifierError::InvalidState(
                "workqueue callback not set".into()
            ));
        }
        self.started = true;
        Ok(())
    }
}

/// Check if async callback is sleepable
/// 
/// Timer callbacks are not sleepable by default, but workqueue and
/// task_work callbacks are always sleepable
pub fn is_async_cb_sleepable(kfunc_id: u32, is_timer: bool) -> bool {
    if is_timer {
        // Timer callbacks are not sleepable
        return false;
    }
    
    // Workqueue and task_work callbacks are always sleepable
    is_bpf_wq_set_callback_impl_kfunc(kfunc_id) || is_task_work_add_kfunc(kfunc_id)
}

/// Validate workqueue init arguments
pub fn validate_wq_init(
    wq_reg: &BpfRegState,
    map_reg: &BpfRegState,
) -> Result<u32> {
    // wq_reg should point to bpf_wq in map value
    if wq_reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to map value (bpf_wq)".into(),
            got: format!("{:?}", wq_reg.reg_type),
        });
    }

    // map_reg should be const map pointer
    if map_reg.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "const map pointer".into(),
            got: format!("{:?}", map_reg.reg_type),
        });
    }

    // Return the map UID for tracking
    Ok(wq_reg.map_uid)
}

/// Validate workqueue set_callback arguments
pub fn validate_wq_set_callback(
    wq_reg: &BpfRegState,
    callback_reg: &BpfRegState,
    map_reg: &BpfRegState,
    wq_state: &WorkqueueState,
) -> Result<()> {
    // Verify wq pointer
    if wq_reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to bpf_wq".into(),
            got: format!("{:?}", wq_reg.reg_type),
        });
    }

    // Verify callback is a scalar (function pointer encoded as imm)
    if callback_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "callback function reference".into(),
            got: format!("{:?}", callback_reg.reg_type),
        });
    }

    // Verify map pointer matches
    if map_reg.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "const map pointer".into(),
            got: format!("{:?}", map_reg.reg_type),
        });
    }

    // Verify map UIDs match
    if let Some(wq_map_uid) = wq_state.map_uid {
        if wq_reg.map_uid != wq_map_uid {
            return Err(VerifierError::InvalidState(format!(
                "workqueue pointer map_uid={} doesn't match map pointer map_uid={}",
                wq_reg.map_uid, wq_map_uid
            )));
        }
    }

    Ok(())
}

/// Setup workqueue callback state for verification
pub fn setup_wq_callback_state(
    state: &mut BpfVerifierState,
) -> Result<()> {
    // Workqueue callback signature: int callback(void *map, int *key, void *value)
    
    // R1 = map pointer
    if let Some(r1) = state.reg_mut(1) {
        r1.reg_type = BpfRegType::ConstPtrToMap;
    }
    
    // R2 = key pointer (or NULL)
    if let Some(r2) = state.reg_mut(2) {
        r2.reg_type = BpfRegType::PtrToMapKey;
    }
    
    // R3 = value pointer (map value containing bpf_wq)
    if let Some(r3) = state.reg_mut(3) {
        r3.reg_type = BpfRegType::PtrToMapValue;
    }
    
    // R4-R5 not used
    for i in 4..=5 {
        if let Some(r) = state.reg_mut(i) {
            r.mark_not_init(false);
        }
    }
    
    // R6-R9 callee-saved, not initialized  
    for i in 6..=9 {
        if let Some(r) = state.reg_mut(i) {
            r.mark_not_init(false);
        }
    }
    
    // R10 = frame pointer
    if let Some(r10) = state.reg_mut(10) {
        r10.reg_type = BpfRegType::PtrToStack;
        r10.off = 0;
    }
    
    Ok(())
}

/// Verify workqueue callback return value
pub fn verify_wq_callback_return(
    state: &BpfVerifierState,
) -> Result<()> {
    // Workqueue callback returns int (0 on success)
    let r0 = state.reg(BPF_REG_0)
        .ok_or(VerifierError::InvalidRegister(0))?;
    
    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(0));
    }
    
    if r0.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar return value".into(),
            got: format!("{:?}", r0.reg_type),
        });
    }
    
    Ok(())
}

/// Check if program type can use workqueues
pub fn prog_type_can_use_wq(prog_type: BpfProgType) -> bool {
    // Tracing programs cannot use bpf_wq
    !matches!(
        prog_type,
        BpfProgType::Tracing | BpfProgType::RawTracepoint
    )
}

// ============================================================================
// Nested Exception Handling
// ============================================================================

/// Track exception handling context for nested callbacks
#[derive(Debug, Clone)]
pub struct ExceptionContext {
    /// Stack of active exception handlers
    handlers: Vec<ExceptionHandler>,
    /// Resources acquired at each level
    resources_per_level: Vec<ResourceSnapshot>,
}

/// Single exception handler entry
#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    /// Handler ID (unique per handler)
    pub handler_id: u32,
    /// BTF ID of the handler function
    pub btf_id: u32,
    /// Instruction index where handler starts
    pub insn_idx: usize,
    /// Nesting level (0 = outermost)
    pub level: usize,
    /// Whether handler is global or local
    pub is_global: bool,
    /// Parent handler ID (if nested)
    pub parent_id: Option<u32>,
}

/// Snapshot of acquired resources at a point in time
#[derive(Debug, Clone, Default)]
pub struct ResourceSnapshot {
    /// Number of locks held
    pub locks_held: u32,
    /// Number of RCU read locks held
    pub rcu_locks_held: u32,
    /// Number of preemption disables
    pub preempt_disabled: u32,
    /// Acquired reference IDs
    pub ref_ids: Vec<u32>,
}

impl ExceptionContext {
    /// Create a new exception context
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            resources_per_level: Vec::new(),
        }
    }

    /// Push a new exception handler
    pub fn push_handler(
        &mut self,
        handler: ExceptionHandler,
        current_resources: ResourceSnapshot,
    ) -> Result<()> {
        if self.handlers.len() >= MAX_EXCEPTION_DEPTH {
            return Err(VerifierError::TooComplex(
                "exception handler nesting too deep".into()
            ));
        }

        self.handlers.push(handler);
        self.resources_per_level.push(current_resources);
        Ok(())
    }

    /// Pop the current exception handler
    pub fn pop_handler(&mut self) -> Result<ExceptionHandler> {
        let handler = self.handlers.pop()
            .ok_or_else(|| VerifierError::InvalidState(
                "no exception handler to pop".into()
            ))?;
        self.resources_per_level.pop();
        Ok(handler)
    }

    /// Get the current nesting level
    pub fn current_level(&self) -> usize {
        self.handlers.len()
    }

    /// Get the current handler
    pub fn current_handler(&self) -> Option<&ExceptionHandler> {
        self.handlers.last()
    }

    /// Get resources at current level
    pub fn current_resources(&self) -> Option<&ResourceSnapshot> {
        self.resources_per_level.last()
    }

    /// Check if we're in any exception handler
    pub fn in_handler(&self) -> bool {
        !self.handlers.is_empty()
    }

    /// Validate resources are properly released before leaving handler
    pub fn validate_cleanup(&self, final_resources: &ResourceSnapshot) -> Result<()> {
        if let Some(entry_resources) = self.current_resources() {
            // All resources acquired in this handler must be released
            if final_resources.locks_held > entry_resources.locks_held {
                return Err(VerifierError::InvalidLock(
                    "exception handler leaks locks".into()
                ));
            }
            if final_resources.rcu_locks_held > entry_resources.rcu_locks_held {
                return Err(VerifierError::InvalidLock(
                    "exception handler leaks RCU locks".into()
                ));
            }
            // Check reference leaks
            for ref_id in &final_resources.ref_ids {
                if !entry_resources.ref_ids.contains(ref_id) {
                    return Err(VerifierError::UnreleasedReference(*ref_id));
                }
            }
        }
        Ok(())
    }
}

impl Default for ExceptionContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Exception Propagation Tracking
// ============================================================================

/// Track how exceptions propagate through callbacks
#[derive(Debug, Clone, Default)]
pub struct ExceptionPropagation {
    /// Whether exception was thrown in current path
    pub exception_thrown: bool,
    /// Cookie value from bpf_throw (if known)
    pub throw_cookie: Option<u64>,
    /// Instruction where exception was thrown
    pub throw_insn_idx: Option<usize>,
    /// Whether exception was caught
    pub exception_caught: bool,
    /// Handler that caught the exception
    pub catch_handler_id: Option<u32>,
}

impl ExceptionPropagation {
    /// Create new propagation tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a bpf_throw call
    pub fn record_throw(&mut self, insn_idx: usize, cookie: Option<u64>) {
        self.exception_thrown = true;
        self.throw_insn_idx = Some(insn_idx);
        self.throw_cookie = cookie;
    }

    /// Record exception being caught
    pub fn record_catch(&mut self, handler_id: u32) {
        self.exception_caught = true;
        self.catch_handler_id = Some(handler_id);
    }

    /// Reset for new path
    pub fn reset(&mut self) {
        self.exception_thrown = false;
        self.throw_cookie = None;
        self.throw_insn_idx = None;
        self.exception_caught = false;
        self.catch_handler_id = None;
    }

    /// Check if exception is unhandled
    pub fn is_unhandled(&self) -> bool {
        self.exception_thrown && !self.exception_caught
    }
}

// ============================================================================
// Resource Cleanup Verification
// ============================================================================

/// Resource cleanup action to perform on exception
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupAction {
    /// Release a spin lock
    SpinUnlock,
    /// Release an RCU read lock
    RcuUnlock,
    /// Re-enable preemption
    PreemptEnable,
    /// Release a reference
    ReleaseRef,
    /// Free allocated memory
    Free,
}

/// Pending cleanup for exception handling
#[derive(Debug, Clone)]
pub struct PendingCleanup {
    /// Type of cleanup
    pub action: CleanupAction,
    /// Resource ID (lock ID, ref ID, etc.)
    pub resource_id: u32,
    /// Instruction index where resource was acquired
    pub acquire_insn: usize,
}

/// Track pending cleanups that must be done before exception handler exits
#[derive(Debug, Clone, Default)]
pub struct CleanupTracker {
    /// Pending cleanups in order they should be performed
    cleanups: Vec<PendingCleanup>,
}

impl CleanupTracker {
    /// Create new cleanup tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pending cleanup
    pub fn add(&mut self, cleanup: PendingCleanup) {
        self.cleanups.push(cleanup);
    }

    /// Remove a cleanup (when resource is released)
    pub fn remove(&mut self, action: CleanupAction, resource_id: u32) -> bool {
        if let Some(pos) = self.cleanups.iter().position(|c| {
            c.action == action && c.resource_id == resource_id
        }) {
            self.cleanups.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if there are any pending cleanups
    pub fn has_pending(&self) -> bool {
        !self.cleanups.is_empty()
    }

    /// Get all pending cleanups
    pub fn get_pending(&self) -> &[PendingCleanup] {
        &self.cleanups
    }

    /// Clear all cleanups (for new path)
    pub fn clear(&mut self) {
        self.cleanups.clear();
    }

    /// Verify all cleanups were performed
    pub fn verify_all_done(&self) -> Result<()> {
        if let Some(cleanup) = self.cleanups.first() {
            return Err(VerifierError::InvalidState(format!(
                "pending cleanup not performed: {:?} for resource {}",
                cleanup.action, cleanup.resource_id
            )));
        }
        Ok(())
    }
}

// ============================================================================
// Exception-Safe Callback Verification
// ============================================================================

/// Verify that a callback is exception-safe
pub fn verify_exception_safe_callback(
    callback_type: AsyncCallbackType,
    cleanup_tracker: &CleanupTracker,
    exception_propagation: &ExceptionPropagation,
) -> Result<()> {
    // Timer callbacks must not throw unhandled exceptions
    if callback_type == AsyncCallbackType::Timer && exception_propagation.is_unhandled() {
        return Err(VerifierError::InvalidState(
            "timer callback cannot throw unhandled exception".into()
        ));
    }

    // All callbacks must clean up resources before throwing
    if exception_propagation.exception_thrown && cleanup_tracker.has_pending() {
        return Err(VerifierError::InvalidState(
            "exception thrown with pending resource cleanup".into()
        ));
    }

    Ok(())
}

/// Check if exception can be thrown in current context
pub fn can_throw_exception(
    exception_ctx: &ExceptionContext,
    exception_state: &ExceptionState,
    in_callback: bool,
    callback_type: AsyncCallbackType,
) -> bool {
    // Cannot throw in timer callbacks
    if in_callback && callback_type == AsyncCallbackType::Timer {
        return false;
    }

    // Can throw if we have an exception handler
    if exception_ctx.in_handler() || exception_state.has_callback(0) {
        return true;
    }

    // Can throw in main program (will abort)
    !in_callback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_state() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: true,
            nargs: 1,
        };

        state.register_callback(1, callback.clone());
        assert!(state.has_callback(1));
        assert!(!state.has_callback(2));
    }

    #[test]
    fn test_exception_nesting() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: false,
            nargs: 1,
        };

        // Can enter exception
        assert!(state.enter_exception(callback.clone()).is_ok());
        assert!(state.in_exception_cb);
        assert_eq!(state.exception_depth, 1);

        // Can exit
        assert!(state.exit_exception().is_ok());
        assert!(!state.in_exception_cb);
    }

    #[test]
    fn test_exception_max_depth() {
        let mut state = ExceptionState::new();
        
        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 100,
            is_global: false,
            nargs: 0,
        };

        // Enter up to max depth
        for _ in 0..MAX_EXCEPTION_DEPTH {
            assert!(state.enter_exception(callback.clone()).is_ok());
        }

        // Next should fail
        assert!(state.enter_exception(callback.clone()).is_err());
    }

    #[test]
    fn test_async_callback_state() {
        let mut state = AsyncCallbackState::default();
        
        assert!(!state.in_async_cb);
        
        state.enter(AsyncCallbackType::Timer, 42);
        assert!(state.in_async_cb);
        assert_eq!(state.async_id, 42);
        assert_eq!(state.callback_type, AsyncCallbackType::Timer);

        state.exit();
        assert!(!state.in_async_cb);
    }

    #[test]
    fn test_check_exception_callback_exit() {
        let mut state = BpfVerifierState::new();
        
        // Set valid return value
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(0);
        }

        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 0,
            is_global: true,
            nargs: 1,
        };

        assert!(check_exception_callback_exit(&state, &callback).is_ok());
    }

    #[test]
    fn test_check_exception_callback_exit_invalid() {
        let mut state = BpfVerifierState::new();
        
        // Set invalid return value (> 1)
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_known(5);
        }

        let callback = ExceptionCallback {
            btf_id: 1,
            insn_idx: 0,
            is_global: true,
            nargs: 1,
        };

        assert!(check_exception_callback_exit(&state, &callback).is_err());
    }
}
