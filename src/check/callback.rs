//!

//! This module implements verification of callback functions used with

//! helpers like bpf_for_each_map_elem, bpf_loop, bpf_timer_set_callback,

//! and similar constructs.

//!

//! Callbacks must satisfy specific requirements:

//! - Correct argument types based on the callback context

//! - Correct return value semantics

//! - No unreleased resources at callback exit

//! - Bounded execution (for loop callbacks)


#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, vec, vec::Vec};

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Types of callbacks supported by BPF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackType {
    /// bpf_for_each_map_elem callback
    ForEachMapElem,
    /// bpf_loop callback  
    Loop,
    /// bpf_timer_set_callback
    Timer,
    /// Iterator next callback
    IterNext,
    /// Socket ops callback
    SockOps,
    /// Struct ops callback
    StructOps,
    /// Sleepable callback
    Sleepable,
}

impl CallbackType {
    /// Get the number of arguments for this callback type
    pub fn num_args(&self) -> usize {
        match self {
            CallbackType::ForEachMapElem => 4, // map, key, value, ctx
            CallbackType::Loop => 2,           // index, ctx
            CallbackType::Timer => 3,          // map, key, value
            CallbackType::IterNext => 2,       // iter_data, ctx
            CallbackType::SockOps => 1,        // skops
            CallbackType::StructOps => 5,      // varies, max 5
            CallbackType::Sleepable => 1,      // ctx
        }
    }

    /// Check if this callback type allows sleeping
    pub fn is_sleepable(&self) -> bool {
        matches!(self, CallbackType::Sleepable | CallbackType::Timer)
    }

    /// Get the expected return value range
    pub fn return_range(&self) -> BpfRetvalRange {
        match self {
            CallbackType::ForEachMapElem => BpfRetvalRange::new(0, 1), // 0 = continue, 1 = stop
            CallbackType::Loop => BpfRetvalRange::new(0, 1),          // 0 = continue, 1 = stop
            CallbackType::Timer => BpfRetvalRange::new(0, 0),         // must return 0
            CallbackType::IterNext => BpfRetvalRange::new(0, 1),      // 0 = continue, 1 = stop
            CallbackType::SockOps => BpfRetvalRange::new(i32::MIN, i32::MAX),
            CallbackType::StructOps => BpfRetvalRange::new(i32::MIN, i32::MAX),
            CallbackType::Sleepable => BpfRetvalRange::new(0, 0),
        }
    }
}

/// State for tracking callback verification
#[derive(Debug, Clone)]
pub struct CallbackState {
    /// Type of callback being verified
    pub callback_type: CallbackType,
    /// Instruction index where callback starts
    pub entry_idx: usize,
    /// Expected argument types
    pub arg_types: Vec<ExpectedArg>,
    /// Expected return value range
    pub ret_range: BpfRetvalRange,
    /// Whether callback has been verified
    pub verified: bool,
    /// Maximum iterations for loop callbacks (0 = unbounded)
    pub max_iterations: u32,
    /// Current iteration depth (for nested loops)
    pub depth: u32,
    /// Parent callback (for nested callbacks)
    pub parent: Option<Box<CallbackState>>,
}

/// Expected argument type for callback
#[derive(Debug, Clone)]
pub struct ExpectedArg {
    /// Register number (R1-R5)
    pub regno: usize,
    /// Expected register type
    pub reg_type: BpfRegType,
    /// BTF ID if applicable
    pub btf_id: Option<u32>,
    /// Whether argument can be NULL
    pub nullable: bool,
    /// Size of pointed-to memory (if applicable)
    pub mem_size: Option<u32>,
}

impl ExpectedArg {
    /// Create a new expected argument
    pub fn new(regno: usize, reg_type: BpfRegType) -> Self {
        Self {
            regno,
            reg_type,
            btf_id: None,
            nullable: false,
            mem_size: None,
        }
    }

    /// Set BTF ID
    pub fn with_btf_id(mut self, btf_id: u32) -> Self {
        self.btf_id = Some(btf_id);
        self
    }

    /// Mark as nullable
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    /// Set memory size
    pub fn with_mem_size(mut self, size: u32) -> Self {
        self.mem_size = Some(size);
        self
    }
}

impl CallbackState {
    /// Create a new callback state
    pub fn new(callback_type: CallbackType, entry_idx: usize) -> Self {
        let ret_range = callback_type.return_range();
        Self {
            callback_type,
            entry_idx,
            arg_types: Vec::new(),
            ret_range,
            verified: false,
            max_iterations: 0,
            depth: 0,
            parent: None,
        }
    }

    /// Create callback state for bpf_for_each_map_elem
    pub fn for_each_map_elem(entry_idx: usize, key_size: u32, value_size: u32) -> Self {
        let mut state = Self::new(CallbackType::ForEachMapElem, entry_idx);
        state.arg_types = vec![
            ExpectedArg::new(1, BpfRegType::PtrToMapKey).with_mem_size(key_size),
            ExpectedArg::new(2, BpfRegType::PtrToMapValue).with_mem_size(value_size),
            ExpectedArg::new(3, BpfRegType::ScalarValue).nullable(), // ctx can be NULL
        ];
        state
    }

    /// Create callback state for bpf_loop
    pub fn bpf_loop(entry_idx: usize, max_iterations: u32) -> Self {
        let mut state = Self::new(CallbackType::Loop, entry_idx);
        state.arg_types = vec![
            ExpectedArg::new(1, BpfRegType::ScalarValue), // index
            ExpectedArg::new(2, BpfRegType::ScalarValue).nullable(), // ctx
        ];
        state.max_iterations = max_iterations;
        state
    }

    /// Create callback state for bpf_timer_set_callback
    pub fn timer_callback(entry_idx: usize) -> Self {
        let mut state = Self::new(CallbackType::Timer, entry_idx);
        state.arg_types = vec![
            ExpectedArg::new(1, BpfRegType::PtrToMapValue), // timer in map value
            ExpectedArg::new(2, BpfRegType::PtrToMapKey),
            ExpectedArg::new(3, BpfRegType::PtrToMapValue),
        ];
        state
    }

    /// Set parent callback (for nesting)
    pub fn with_parent(mut self, parent: CallbackState) -> Self {
        self.depth = parent.depth + 1;
        self.parent = Some(Box::new(parent));
        self
    }
}

/// Verify callback argument types
pub fn verify_callback_args(
    state: &BpfVerifierState,
    callback: &CallbackState,
) -> Result<()> {
    for expected in &callback.arg_types {
        let reg = state.reg(expected.regno).ok_or(
            VerifierError::InvalidRegister(expected.regno as u8)
        )?;

        // Check register type
        if !is_compatible_type(reg, expected) {
            return Err(VerifierError::TypeMismatch {
                expected: format!("{:?}", expected.reg_type),
                got: format!("{:?}", reg.reg_type),
            });
        }

        // Check nullability
        if !expected.nullable && reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            return Err(VerifierError::InvalidPointer(format!(
                "callback arg {} cannot be NULL",
                expected.regno
            )));
        }

        // Check BTF ID if required
        if let Some(expected_btf_id) = expected.btf_id {
            let actual_btf_id = reg.btf_id();
            if actual_btf_id != expected_btf_id {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("btf_id={}", expected_btf_id),
                    got: format!("btf_id={}", actual_btf_id),
                });
            }
        }
    }

    Ok(())
}

/// Check if register type is compatible with expected type
fn is_compatible_type(reg: &BpfRegState, expected: &ExpectedArg) -> bool {
    match expected.reg_type {
        BpfRegType::ScalarValue => {
            reg.reg_type == BpfRegType::ScalarValue ||
            (expected.nullable && reg.reg_type == BpfRegType::NotInit)
        }
        BpfRegType::PtrToMapKey => {
            reg.reg_type == BpfRegType::PtrToMapKey ||
            reg.reg_type == BpfRegType::PtrToMem
        }
        BpfRegType::PtrToMapValue => {
            reg.reg_type == BpfRegType::PtrToMapValue ||
            reg.reg_type == BpfRegType::PtrToMem
        }
        BpfRegType::PtrToCtx => {
            reg.reg_type == BpfRegType::PtrToCtx
        }
        _ => reg.reg_type == expected.reg_type
    }
}

/// Verify callback return value
pub fn verify_callback_return(
    state: &BpfVerifierState,
    callback: &CallbackState,
) -> Result<()> {
    let r0 = state.reg(BPF_REG_0).ok_or(
        VerifierError::InvalidRegister(BPF_REG_0 as u8)
    )?;

    // R0 must be a scalar
    if r0.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar return value".into(),
            got: format!("{:?}", r0.reg_type),
        });
    }

    // Check return value is within expected range
    let ret_min = r0.smin_value;
    let ret_max = r0.smax_value;

    if ret_min < callback.ret_range.minval as i64 ||
       ret_max > callback.ret_range.maxval as i64 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "callback return value [{}, {}] not in expected range [{}, {}]",
            ret_min, ret_max,
            callback.ret_range.minval, callback.ret_range.maxval
        )));
    }

    Ok(())
}

/// Check if callback nesting depth is within limits
pub fn check_callback_depth(callback: &CallbackState) -> Result<()> {
    const MAX_CALLBACK_DEPTH: u32 = 8;
    
    if callback.depth >= MAX_CALLBACK_DEPTH {
        return Err(VerifierError::TooComplex(format!(
            "callback nesting depth {} exceeds maximum {}",
            callback.depth, MAX_CALLBACK_DEPTH
        )));
    }
    Ok(())
}

/// Initialize register state for callback entry
pub fn init_callback_regs(
    state: &mut BpfVerifierState,
    callback: &CallbackState,
) -> Result<()> {
    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // Clear caller-saved registers
    for i in 0..=5 {
        func.regs[i].mark_not_init(false);
    }

    // R10 is always frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    // Initialize argument registers based on callback type
    for arg in &callback.arg_types {
        let reg = &mut func.regs[arg.regno];
        
        match arg.reg_type {
            BpfRegType::ScalarValue => {
                reg.mark_unknown(false);
            }
            BpfRegType::PtrToMapKey => {
                reg.reg_type = BpfRegType::PtrToMapKey;
                reg.off = 0;
                if let Some(size) = arg.mem_size {
                    reg.mem_size = size;
                }
            }
            BpfRegType::PtrToMapValue => {
                reg.reg_type = BpfRegType::PtrToMapValue;
                reg.off = 0;
                if let Some(size) = arg.mem_size {
                    reg.mem_size = size;
                }
            }
            BpfRegType::PtrToCtx => {
                reg.reg_type = BpfRegType::PtrToCtx;
                reg.off = 0;
            }
            _ => {
                reg.reg_type = arg.reg_type;
                reg.off = 0;
            }
        }

        if arg.nullable {
            reg.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
        }

        if let Some(btf_id) = arg.btf_id {
            reg.btf_info = Some(crate::state::reg_state::BtfInfo::new(btf_id));
        }
    }

    // Set callback return range in function state
    func.callback_ret_range = callback.ret_range;

    Ok(())
}

/// Check restrictions during callback execution
pub fn check_callback_restrictions(
    callback: &CallbackState,
    is_helper_call: bool,
    helper_id: Option<u32>,
) -> Result<()> {
    // Check for forbidden operations in callbacks
    if let Some(id) = helper_id {
        match callback.callback_type {
            CallbackType::Timer => {
                // Timer callbacks have restrictions on certain helpers
                if is_forbidden_in_timer(id) {
                    return Err(VerifierError::PermissionDenied(format!(
                        "helper {} not allowed in timer callback",
                        id
                    )));
                }
            }
            CallbackType::ForEachMapElem | CallbackType::Loop => {
                // Loop callbacks cannot use certain helpers
                if is_forbidden_in_loop(id) {
                    return Err(VerifierError::PermissionDenied(format!(
                        "helper {} not allowed in loop callback",
                        id
                    )));
                }
            }
            _ => {}
        }
    }

    // Check for nested callback calls
    if is_helper_call {
        if let Some(id) = helper_id {
            if is_callback_helper(id) && callback.depth > 0 {
                // Nested callback invocations have additional restrictions
                check_callback_depth(callback)?;
            }
        }
    }

    Ok(())
}

/// Check if helper is forbidden in timer callbacks
fn is_forbidden_in_timer(helper_id: u32) -> bool {
    matches!(
        helper_id,
        12 | // tail_call
        64   // bind (socket operations)
    )
}

/// Check if helper is forbidden in loop callbacks
fn is_forbidden_in_loop(helper_id: u32) -> bool {
    matches!(
        helper_id,
        12  // tail_call - can't tail call from callback
    )
}

/// Check if helper invokes a callback
pub fn is_callback_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        164 | // bpf_for_each_map_elem
        181 | // bpf_loop
        170 | // bpf_user_ringbuf_drain
        174 | // bpf_find_vma
        165   // bpf_snprintf
    )
}

/// Check if this is a synchronous callback (executed inline)
pub fn is_sync_callback_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        164 | // bpf_for_each_map_elem
        181 | // bpf_loop
        170 | // bpf_user_ringbuf_drain
        174   // bpf_find_vma
    )
}

/// Check if this is an async callback (scheduled for later)
pub fn is_async_callback_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        167 | // bpf_timer_set_callback
        195   // bpf_wq_set_callback_impl
    )
}

/// Push a callback call onto the verification stack.
///
/// This is called when we encounter a helper that takes a callback function.
/// We need to verify the callback function separately with appropriate
/// argument types.
pub fn push_callback_call(
    state: &mut BpfVerifierState,
    callback_idx: usize,
    callback_type: CallbackType,
    parent_insn_idx: usize,
) -> Result<CallbackState> {
    // Create callback state based on type
    let callback_state = match callback_type {
        CallbackType::Loop => CallbackState::bpf_loop(callback_idx, BPF_MAX_LOOPS),
        CallbackType::ForEachMapElem => {
            // Get map info from state if available
            let (key_size, value_size) = get_map_sizes_from_state(state);
            CallbackState::for_each_map_elem(callback_idx, key_size, value_size)
        }
        CallbackType::Timer => CallbackState::timer_callback(callback_idx),
        _ => CallbackState::new(callback_type, callback_idx),
    };

    // Push a new frame for the callback
    state.push_frame(parent_insn_idx as i32, callback_idx as u32)?;

    // Initialize registers for the callback
    init_callback_regs(state, &callback_state)?;

    Ok(callback_state)
}

/// Get map key and value sizes from verifier state.
fn get_map_sizes_from_state(state: &BpfVerifierState) -> (u32, u32) {
    // Try to get map info from R1 (map pointer)
    if let Some(r1) = state.reg(1) {
        if r1.reg_type == BpfRegType::ConstPtrToMap || r1.reg_type == BpfRegType::PtrToMapValue {
            if let Some(ref map_info) = r1.map_ptr {
                return (map_info.key_size, map_info.value_size);
            }
        }
    }
    // Default sizes if we can't determine
    (8, 8)
}

/// Maximum loop iterations for bpf_loop
pub const BPF_MAX_LOOPS: u32 = 1 << 23; // 8 million

/// Set up callee state for map element callback (bpf_for_each_map_elem).
pub fn set_map_elem_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
    map_ptr_regno: usize,
) -> Result<CallbackState> {
    // Get map information from the map pointer register
    let map_reg = state.reg(map_ptr_regno).ok_or(
        VerifierError::InvalidRegister(map_ptr_regno as u8)
    )?.clone();

    let (key_size, value_size) = if let Some(ref map_info) = map_reg.map_ptr {
        (map_info.key_size, map_info.value_size)
    } else {
        return Err(VerifierError::InvalidMapAccess(
            "cannot determine map key/value size for callback".into()
        ));
    };

    let mut callback = CallbackState::for_each_map_elem(callback_idx, key_size, value_size);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;
    
    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = pointer to map key
    func.regs[1].reg_type = BpfRegType::PtrToMapKey;
    func.regs[1].mem_size = key_size;
    func.regs[1].off = 0;

    // R2 = pointer to map value  
    func.regs[2].reg_type = BpfRegType::PtrToMapValue;
    func.regs[2].mem_size = value_size;
    func.regs[2].off = 0;
    func.regs[2].map_ptr = map_reg.map_ptr.clone();

    // R3 = callback context (can be NULL)
    func.regs[3].mark_unknown(false);
    func.regs[3].type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Set up callee state for bpf_loop callback.
pub fn set_loop_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
    nr_loops_reg: usize,
) -> Result<CallbackState> {
    // Get the number of loops from the register
    let loops_reg = state.reg(nr_loops_reg).ok_or(
        VerifierError::InvalidRegister(nr_loops_reg as u8)
    )?;

    // Determine max iterations
    let max_iterations = if loops_reg.is_const() {
        loops_reg.const_value() as u32
    } else {
        // Variable loop count - use maximum
        loops_reg.umax_value.min(BPF_MAX_LOOPS as u64) as u32
    };

    let mut callback = CallbackState::bpf_loop(callback_idx, max_iterations);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;

    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = loop index (0 to nr_loops-1)
    func.regs[1].mark_unknown(false);
    func.regs[1].umin_value = 0;
    func.regs[1].umax_value = max_iterations.saturating_sub(1) as u64;
    func.regs[1].smin_value = 0;
    func.regs[1].smax_value = max_iterations.saturating_sub(1) as i64;

    // R2 = callback context (passed through from caller)
    func.regs[2].mark_unknown(false);
    func.regs[2].type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Set up callee state for bpf_timer_set_callback.
pub fn set_timer_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
    map_ptr_regno: usize,
) -> Result<CallbackState> {
    let map_reg = state.reg(map_ptr_regno).ok_or(
        VerifierError::InvalidRegister(map_ptr_regno as u8)
    )?.clone();

    let mut callback = CallbackState::timer_callback(callback_idx);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;

    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = pointer to map containing timer
    func.regs[1].reg_type = BpfRegType::PtrToMapValue;
    if let Some(ref map_info) = map_reg.map_ptr {
        func.regs[1].mem_size = map_info.value_size;
    }
    func.regs[1].off = 0;

    // R2 = map key (can be NULL for some map types)
    func.regs[2].reg_type = BpfRegType::PtrToMapKey;
    func.regs[2].type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);

    // R3 = map value
    func.regs[3].reg_type = BpfRegType::PtrToMapValue;
    func.regs[3].map_ptr = map_reg.map_ptr.clone();

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Set up callee state for bpf_find_vma callback.
pub fn set_find_vma_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
) -> Result<CallbackState> {
    let mut callback = CallbackState::new(CallbackType::Sleepable, callback_idx);
    callback.ret_range = BpfRetvalRange::new(0, 1);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;

    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = task_struct pointer
    func.regs[1].reg_type = BpfRegType::PtrToBtfId;
    func.regs[1].type_flags.insert(BpfTypeFlag::PTR_TRUSTED);

    // R2 = vm_area_struct pointer
    func.regs[2].reg_type = BpfRegType::PtrToBtfId;
    func.regs[2].type_flags.insert(BpfTypeFlag::PTR_TRUSTED);

    // R3 = callback context
    func.regs[3].mark_unknown(false);
    func.regs[3].type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Set up callee state for user ring buffer drain callback.
pub fn set_user_ringbuf_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
) -> Result<CallbackState> {
    let mut callback = CallbackState::new(CallbackType::ForEachMapElem, callback_idx);
    callback.ret_range = BpfRetvalRange::new(0, 1);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;

    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = dynptr to sample
    func.regs[1].reg_type = BpfRegType::PtrToStack;
    func.regs[1].type_flags.insert(BpfTypeFlag::DYNPTR_TYPE_LOCAL);

    // R2 = callback context
    func.regs[2].mark_unknown(false);
    func.regs[2].type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Set up callee state for rbtree add callback.
pub fn set_rbtree_add_callback_state(
    state: &mut BpfVerifierState,
    callback_idx: usize,
) -> Result<CallbackState> {
    let mut callback = CallbackState::new(CallbackType::Sleepable, callback_idx);
    callback.ret_range = BpfRetvalRange::new(i32::MIN, i32::MAX);

    // Push frame and init regs
    state.push_frame(0, callback_idx as u32)?;

    let func = state.cur_func_mut().ok_or(
        VerifierError::Internal("no current function".into())
    )?;

    // R1 = first node to compare (non-owning reference)
    func.regs[1].reg_type = BpfRegType::PtrToBtfId;
    func.regs[1].type_flags.insert(BpfTypeFlag::NON_OWN_REF);

    // R2 = second node to compare (non-owning reference)
    func.regs[2].reg_type = BpfRegType::PtrToBtfId;
    func.regs[2].type_flags.insert(BpfTypeFlag::NON_OWN_REF);

    // R10 = frame pointer
    func.regs[BPF_REG_FP] = BpfRegState::new_fp();

    callback.verified = false;
    Ok(callback)
}

/// Prepare callee state for callback execution.
/// Returns the callback state and the instruction index to jump to.
pub fn prepare_callback_callee(
    state: &mut BpfVerifierState,
    helper_id: u32,
    callback_idx: usize,
    insn_idx: usize,
) -> Result<CallbackState> {
    match helper_id {
        164 => {
            // bpf_for_each_map_elem - R1 is map pointer, R4 is callback
            set_map_elem_callback_state(state, callback_idx, 1)
        }
        181 => {
            // bpf_loop - R1 is nr_loops, R2 is callback
            set_loop_callback_state(state, callback_idx, 1)
        }
        167 => {
            // bpf_timer_set_callback - R1 is timer, R2 is callback
            set_timer_callback_state(state, callback_idx, 1)
        }
        174 => {
            // bpf_find_vma - callback for VMA lookup
            set_find_vma_callback_state(state, callback_idx)
        }
        170 => {
            // bpf_user_ringbuf_drain - R1 is map, R2 is callback
            set_user_ringbuf_callback_state(state, callback_idx)
        }
        _ => {
            // Generic callback handling
            push_callback_call(state, callback_idx, CallbackType::Sleepable, insn_idx)
        }
    }
}

/// Track callback invocation for bounded loop analysis
#[derive(Debug, Clone, Default)]
pub struct CallbackTracker {
    /// Active callbacks
    pub active: Vec<CallbackState>,
    /// Total callback invocations (for complexity tracking)
    pub total_invocations: u32,
    /// Maximum allowed invocations
    pub max_invocations: u32,
}

impl CallbackTracker {
    /// Create a new callback tracker
    pub fn new(max_invocations: u32) -> Self {
        Self {
            active: Vec::new(),
            total_invocations: 0,
            max_invocations,
        }
    }

    /// Enter a callback
    pub fn enter(&mut self, callback: CallbackState) -> Result<()> {
        check_callback_depth(&callback)?;
        
        self.total_invocations += 1;
        if self.total_invocations > self.max_invocations {
            return Err(VerifierError::TooComplex(format!(
                "too many callback invocations: {} > {}",
                self.total_invocations, self.max_invocations
            )));
        }

        self.active.push(callback);
        Ok(())
    }

    /// Exit a callback
    pub fn exit(&mut self) -> Option<CallbackState> {
        self.active.pop()
    }

    /// Get the current callback (if any)
    pub fn current(&self) -> Option<&CallbackState> {
        self.active.last()
    }

    /// Check if we're inside a callback
    pub fn in_callback(&self) -> bool {
        !self.active.is_empty()
    }

    /// Get callback nesting depth
    pub fn depth(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_type_args() {
        assert_eq!(CallbackType::ForEachMapElem.num_args(), 4);
        assert_eq!(CallbackType::Loop.num_args(), 2);
        assert_eq!(CallbackType::Timer.num_args(), 3);
    }

    #[test]
    fn test_callback_type_return_range() {
        let range = CallbackType::Loop.return_range();
        assert_eq!(range.minval, 0);
        assert_eq!(range.maxval, 1);

        let timer_range = CallbackType::Timer.return_range();
        assert_eq!(timer_range.minval, 0);
        assert_eq!(timer_range.maxval, 0);
    }

    #[test]
    fn test_callback_state_creation() {
        let state = CallbackState::bpf_loop(10, 1000);
        assert_eq!(state.callback_type, CallbackType::Loop);
        assert_eq!(state.entry_idx, 10);
        assert_eq!(state.max_iterations, 1000);
        assert_eq!(state.arg_types.len(), 2);
    }

    #[test]
    fn test_for_each_map_elem_state() {
        let state = CallbackState::for_each_map_elem(0, 8, 64);
        assert_eq!(state.callback_type, CallbackType::ForEachMapElem);
        assert_eq!(state.arg_types.len(), 3);
        
        // Check key arg
        assert_eq!(state.arg_types[0].regno, 1);
        assert_eq!(state.arg_types[0].mem_size, Some(8));
        
        // Check value arg
        assert_eq!(state.arg_types[1].regno, 2);
        assert_eq!(state.arg_types[1].mem_size, Some(64));
    }

    #[test]
    fn test_callback_nesting() {
        let parent = CallbackState::bpf_loop(0, 100);
        let child = CallbackState::bpf_loop(10, 50).with_parent(parent);
        
        assert_eq!(child.depth, 1);
        assert!(child.parent.is_some());
    }

    #[test]
    fn test_callback_depth_limit() {
        let mut state = CallbackState::bpf_loop(0, 100);
        state.depth = 10; // Exceeds limit
        
        assert!(check_callback_depth(&state).is_err());
    }

    #[test]
    fn test_callback_tracker() {
        let mut tracker = CallbackTracker::new(100);
        
        assert!(!tracker.in_callback());
        
        let cb = CallbackState::bpf_loop(0, 100);
        assert!(tracker.enter(cb).is_ok());
        
        assert!(tracker.in_callback());
        assert_eq!(tracker.depth(), 1);
        
        tracker.exit();
        assert!(!tracker.in_callback());
    }

    #[test]
    fn test_callback_tracker_limit() {
        let mut tracker = CallbackTracker::new(2);
        
        let cb1 = CallbackState::bpf_loop(0, 100);
        let cb2 = CallbackState::bpf_loop(10, 100);
        let cb3 = CallbackState::bpf_loop(20, 100);
        
        assert!(tracker.enter(cb1).is_ok());
        tracker.exit();
        
        assert!(tracker.enter(cb2).is_ok());
        tracker.exit();
        
        // Third invocation exceeds limit
        assert!(tracker.enter(cb3).is_err());
    }

    #[test]
    fn test_forbidden_helpers() {
        // tail_call is forbidden in loops
        assert!(is_forbidden_in_loop(12));
        
        // tail_call is forbidden in timers
        assert!(is_forbidden_in_timer(12));
        
        // Regular helper is allowed
        assert!(!is_forbidden_in_loop(1)); // map_lookup_elem
    }

    #[test]
    fn test_is_callback_helper() {
        assert!(is_callback_helper(164)); // bpf_for_each_map_elem
        assert!(is_callback_helper(181)); // bpf_loop
        assert!(!is_callback_helper(1));  // map_lookup_elem
    }

    #[test]
    fn test_expected_arg() {
        let arg = ExpectedArg::new(1, BpfRegType::PtrToMapValue)
            .with_btf_id(100)
            .with_mem_size(64)
            .nullable();
        
        assert_eq!(arg.regno, 1);
        assert_eq!(arg.btf_id, Some(100));
        assert_eq!(arg.mem_size, Some(64));
        assert!(arg.nullable);
    }
}
