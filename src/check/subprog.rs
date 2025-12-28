// SPDX-License-Identifier: GPL-2.0

//! Subprogram and function call handling
//!
//! This module handles BPF subprograms (functions within a BPF program),
//! including call tracking, stack depth calculation, and callback handling.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use alloc::collections::BTreeMap as HashMap;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::verifier_state::{BpfFuncState, BpfVerifierState};

/// Maximum call stack depth
pub const MAX_CALL_FRAMES: usize = MAX_BPF_STACK_FRAMES;

/// Private stack mode for subprogram (Linux 6.13+)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivStackMode {
    /// No private stack
    #[default]
    NoPrivStack,
    /// Private stack mode unknown (needs determination)
    Unknown,
    /// Adaptive private stack (enabled based on stack depth)
    Adaptive,
}

/// Information about a subprogram
#[derive(Debug, Clone, Default)]
pub struct SubprogInfo {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (exclusive)
    pub end: usize,
    /// Stack depth in bytes
    pub stack_depth: i32,
    /// Whether this is a global function
    pub is_global: bool,
    /// Whether this is an async callback
    pub is_async_cb: bool,
    /// Whether this is an exception callback
    pub is_exception_cb: bool,
    /// Whether this subprogram has tail calls
    pub has_tail_call: bool,
    /// Whether tail calls can reach this subprogram
    ///
    /// This is propagated from callers: if any function that calls this
    /// subprogram has tail_call_reachable set, this is also set.
    pub tail_call_reachable: bool,
    /// Whether this subprogram changes packet data
    pub changes_pkt_data: bool,
    /// Whether this subprogram might sleep
    pub might_sleep: bool,
    /// BTF function ID (if available)
    pub btf_id: u32,
    /// Number of arguments
    pub arg_cnt: u8,
    /// Whether this returns a scalar (required for tail call)
    pub returns_scalar: bool,
    /// Whether this subprogram has refcounted arguments
    pub has_refcounted_args: bool,
    /// Private stack mode (Linux 6.13+)
    pub priv_stack_mode: PrivStackMode,
}

/// Subprogram manager
#[derive(Debug, Default)]
pub struct SubprogManager {
    /// All subprograms, sorted by start index
    subprogs: Vec<SubprogInfo>,
    /// Map from instruction index to subprogram index
    insn_to_subprog: HashMap<usize, usize>,
}

impl SubprogManager {
    /// Create a new subprogram manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the main program (subprog 0)
    pub fn add_main(&mut self, insn_cnt: usize) {
        self.subprogs.push(SubprogInfo {
            start: 0,
            end: insn_cnt,
            ..Default::default()
        });

        // Map all instructions to subprog 0 initially
        for i in 0..insn_cnt {
            self.insn_to_subprog.insert(i, 0);
        }
    }

    /// Add a subprogram at the given instruction index
    pub fn add_subprog(&mut self, start: usize) -> Result<usize> {
        // Check if already exists
        if let Some(idx) = self.find_subprog(start) {
            return Ok(idx);
        }

        // Check limit
        if self.subprogs.len() >= BPF_MAX_SUBPROGS {
            return Err(VerifierError::TooManySubprogs);
        }

        let idx = self.subprogs.len();
        self.subprogs.push(SubprogInfo {
            start,
            end: start, // Will be set later
            ..Default::default()
        });

        Ok(idx)
    }

    /// Find subprogram containing an instruction
    pub fn find_containing(&self, insn_idx: usize) -> Option<usize> {
        self.insn_to_subprog.get(&insn_idx).copied()
    }

    /// Find subprogram starting at an instruction
    pub fn find_subprog(&self, start: usize) -> Option<usize> {
        self.subprogs.iter().position(|s| s.start == start)
    }

    /// Get subprogram info by index
    pub fn get(&self, idx: usize) -> Option<&SubprogInfo> {
        self.subprogs.get(idx)
    }

    /// Get mutable subprogram info
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut SubprogInfo> {
        self.subprogs.get_mut(idx)
    }

    /// Get number of subprograms
    pub fn count(&self) -> usize {
        self.subprogs.len()
    }

    /// Check if a subprogram is global
    pub fn is_global(&self, idx: usize) -> bool {
        self.subprogs.get(idx).map(|s| s.is_global).unwrap_or(false)
    }

    /// Finalize subprogram boundaries after scanning
    pub fn finalize_boundaries(&mut self, insn_cnt: usize) {
        // Sort by start index
        self.subprogs.sort_by_key(|s| s.start);

        // Set end indices
        for i in 0..self.subprogs.len() {
            let end = if i + 1 < self.subprogs.len() {
                self.subprogs[i + 1].start
            } else {
                insn_cnt
            };
            self.subprogs[i].end = end;
        }

        // Update instruction mapping
        self.insn_to_subprog.clear();
        for (idx, subprog) in self.subprogs.iter().enumerate() {
            for i in subprog.start..subprog.end {
                self.insn_to_subprog.insert(i, idx);
            }
        }
    }

    /// Get subprogram name (for debugging)
    pub fn name(&self, idx: usize) -> String {
        if idx == 0 {
            "main".to_string()
        } else {
            format!("func#{}", idx)
        }
    }
}

/// Call site information
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Instruction index of the call
    pub insn_idx: usize,
    /// Caller subprogram
    pub caller: usize,
    /// Callee subprogram
    pub callee: usize,
    /// Whether this is a callback (not a direct call)
    pub is_callback: bool,
}

/// Function call state for verification
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct CallState {
    /// Current call chain
    pub callchain: Vec<usize>,
    /// All call sites discovered
    pub call_sites: Vec<CallSite>,
    /// Maximum stack depth seen
    pub max_stack_depth: i32,
}

impl Default for CallState {
    fn default() -> Self {
        Self::new()
    }
}

impl CallState {
    /// Create a new call state starting in main
    pub fn new() -> Self {
        Self {
            callchain: vec![0], // Start in main
            call_sites: Vec::new(),
            max_stack_depth: 0,
        }
    }

    /// Get current subprogram index
    pub fn current_subprog(&self) -> usize {
        *self.callchain.last().unwrap_or(&0)
    }

    /// Push a function call
    pub fn push_call(&mut self, callee: usize, insn_idx: usize) -> Result<()> {
        if self.callchain.len() >= MAX_CALL_FRAMES {
            return Err(VerifierError::CallStackOverflow);
        }

        let caller = self.current_subprog();
        self.call_sites.push(CallSite {
            insn_idx,
            caller,
            callee,
            is_callback: false,
        });

        self.callchain.push(callee);
        Ok(())
    }

    /// Pop from function call
    pub fn pop_call(&mut self) -> Result<usize> {
        if self.callchain.len() <= 1 {
            return Err(VerifierError::Internal("call stack underflow".into()));
        }
        self.callchain
            .pop()
            .ok_or_else(|| VerifierError::Internal("call stack inconsistency".into()))
    }

    /// Get call depth
    pub fn depth(&self) -> usize {
        self.callchain.len()
    }
}

/// Check maximum stack depth for all subprograms
/// Uses iterative DFS to avoid stack overflow in kernel mode
pub fn check_max_stack_depth(subprogs: &SubprogManager, call_state: &CallState) -> Result<i32> {
    let mut max_depth: i32 = 0;
    let mut visited = vec![false; subprogs.count()];
    let mut stack_depth_arr = vec![0i32; subprogs.count()];

    // Calculate stack depth for each subprogram
    for (i, depth) in stack_depth_arr.iter_mut().enumerate().take(subprogs.count()) {
        if let Some(info) = subprogs.get(i) {
            *depth = info.stack_depth;
        }
    }

    // Build adjacency list for call graph
    let mut callees: Vec<Vec<usize>> = vec![Vec::new(); subprogs.count()];
    for site in &call_state.call_sites {
        if site.caller < subprogs.count() && site.callee < subprogs.count() {
            callees[site.caller].push(site.callee);
        }
    }

    // Iterative DFS through call graph
    // Stack contains: (subprog_idx, callee_idx, current_total_stack, call_depth)
    let mut stack: Vec<(usize, usize, i32, usize)> = Vec::new();

    // Start from main (subprog 0)
    let initial_total = stack_depth_arr[0];
    if initial_total > MAX_BPF_STACK as i32 {
        return Err(VerifierError::StackOverflow(initial_total));
    }
    max_depth = max_depth.max(initial_total);
    stack.push((0, 0, initial_total, 0));

    while let Some((idx, mut callee_idx, current_stack, depth)) = stack.pop() {
        // Process remaining callees for this subprogram
        while callee_idx < callees[idx].len() {
            let callee = callees[idx][callee_idx];
            callee_idx += 1;

            if depth + 1 > MAX_CALL_FRAMES {
                return Err(VerifierError::CallStackOverflow);
            }

            if visited[callee] {
                continue; // Already processed
            }

            let total = current_stack + stack_depth_arr[callee];
            if total > MAX_BPF_STACK as i32 {
                return Err(VerifierError::StackOverflow(total));
            }

            max_depth = max_depth.max(total);

            // Push current state back with updated callee index
            stack.push((idx, callee_idx, current_stack, depth));

            // Push callee to explore
            stack.push((callee, 0, total, depth + 1));
            break;
        }

        // If we've processed all callees for this node, mark as visited
        if callee_idx >= callees[idx].len() {
            visited[idx] = true;
        }
    }

    Ok(max_depth)
}

/// Setup callee state for a function call
pub fn setup_func_entry(
    caller_state: &BpfVerifierState,
    subprogs: &SubprogManager,
    callee_idx: usize,
) -> Result<BpfFuncState> {
    let subprog = subprogs
        .get(callee_idx)
        .ok_or(VerifierError::InvalidSubprog(format!(
            "invalid subprog index {}",
            callee_idx
        )))?;

    let frameno = (caller_state.curframe + 1) as u32;
    let mut callee = BpfFuncState::new(caller_state.insn_idx as i32, frameno, callee_idx as u32);

    // Copy argument registers R1-R5 from caller
    if let Some(caller_func) = caller_state.cur_func() {
        for i in 1..=5 {
            if i <= subprog.arg_cnt as usize {
                callee.regs[i] = caller_func.regs[i].clone();
            } else {
                callee.regs[i].mark_not_init(false);
            }
        }
    }

    // R10 is frame pointer - already set by init_regs in new()

    Ok(callee)
}

/// Prepare return from a function
pub fn prepare_func_exit(state: &mut BpfVerifierState) -> Result<()> {
    if state.curframe == 0 {
        // Exit from main - this is program exit
        return Ok(());
    }

    // Pop the current frame
    let ret_reg = if let Some(func) = state.cur_func() {
        func.regs[BPF_REG_0].clone()
    } else {
        return Err(VerifierError::Internal("no current function".into()));
    };

    state.pop_frame()?;

    // Set R0 in caller to return value
    if let Some(func) = state.cur_func_mut() {
        func.regs[BPF_REG_0] = ret_reg;

        // Clear caller-saved registers R1-R5
        for i in 1..=5 {
            func.regs[i].mark_not_init(false);
        }
    }

    Ok(())
}

/// Check if an instruction is a function call
pub fn is_call_insn(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL)
}

/// Check if this is a subprogram call (not helper)
pub fn is_subprog_call(insn: &BpfInsn) -> bool {
    is_call_insn(insn) && insn.src_reg == BPF_PSEUDO_CALL
}

/// Check if this is a helper call
pub fn is_helper_call(insn: &BpfInsn) -> bool {
    is_call_insn(insn) && insn.src_reg == 0
}

// Note: is_kfunc_call is provided by the kfunc module

/// Get the target of a subprogram call
pub fn get_call_target(insn: &BpfInsn, insn_idx: usize) -> usize {
    // Target is relative to next instruction
    (insn_idx as i64 + 1 + insn.imm as i64) as usize
}

/// BTF-based subprogram call argument checking
///
/// This validates that the caller's register state matches the callee's
/// expected argument types based on BTF function information.
///
/// Returns:
/// - Ok(()) if types match or BTF info is not available
/// - Err if there's a type mismatch
pub fn btf_check_subprog_call(
    state: &BpfVerifierState,
    subprog: &SubprogInfo,
    _subprog_idx: usize,
) -> Result<()> {
    // If no BTF info available, skip the check
    if subprog.btf_id == 0 {
        return Ok(());
    }

    let caller = state.cur_func().ok_or(VerifierError::Internal(
        "no current function for subprog call".into(),
    ))?;

    // Check each argument register
    for i in 1..=subprog.arg_cnt as usize {
        let reg = &caller.regs[i];

        // For global functions, arguments must be properly typed
        if subprog.is_global {
            // Global functions expect specific types from BTF
            // Scalar values and pointers to context are always safe
            match reg.reg_type {
                BpfRegType::ScalarValue => {
                    // Scalars are always acceptable for global func args
                }
                BpfRegType::PtrToCtx => {
                    // Context pointers are acceptable
                }
                BpfRegType::PtrToMem | BpfRegType::PtrToMapValue => {
                    // Memory pointers may be acceptable depending on BTF
                }
                BpfRegType::NotInit => {
                    return Err(VerifierError::UninitializedRegister(i as u8));
                }
                _ => {
                    // Other pointer types need more checking
                    // For now, allow them but could be stricter with full BTF
                }
            }
        }
    }

    // For static (non-global) subprogs, the check is more lenient
    // as the compiler may have optimized away unused arguments
    if !subprog.is_global {
        // Just verify that used registers are initialized
        for i in 1..=subprog.arg_cnt as usize {
            let reg = &caller.regs[i];
            if reg.reg_type == BpfRegType::NotInit {
                // Mark function as having unreliable BTF info
                // In the real implementation, this would set a flag
                return Err(VerifierError::TypeMismatch {
                    expected: format!("initialized arg{}", i),
                    got: "uninitialized register".into(),
                });
            }
        }
    }

    Ok(())
}

/// Check compatibility between caller and callee for a subprogram call
///
/// This performs various compatibility checks including:
/// - Stack depth limits
/// - Argument type matching
/// - Sleepable/non-sleepable compatibility
pub fn check_subprog_call_compat(
    state: &BpfVerifierState,
    subprogs: &SubprogManager,
    caller_idx: usize,
    callee_idx: usize,
    is_sleepable_prog: bool,
) -> Result<()> {
    let caller = subprogs
        .get(caller_idx)
        .ok_or(VerifierError::InvalidSubprog(format!(
            "invalid caller subprog {}",
            caller_idx
        )))?;
    let callee = subprogs
        .get(callee_idx)
        .ok_or(VerifierError::InvalidSubprog(format!(
            "invalid callee subprog {}",
            callee_idx
        )))?;

    // Check stack depth
    let combined_stack = caller.stack_depth + callee.stack_depth;
    if combined_stack > MAX_BPF_STACK as i32 {
        return Err(VerifierError::StackOverflow(combined_stack));
    }

    // Check sleepable compatibility
    if callee.might_sleep && !is_sleepable_prog {
        return Err(VerifierError::PermissionDenied(
            "cannot call sleepable function from non-sleepable context".into(),
        ));
    }

    // Check tail call restrictions
    if callee.has_tail_call && state.curframe > 0 {
        return Err(VerifierError::InvalidFunctionCall(
            "tail_call not allowed in subprograms".into(),
        ));
    }

    // BTF-based argument type checking
    btf_check_subprog_call(state, callee, callee_idx)?;

    Ok(())
}

/// Validate global function signature against BTF
///
/// Global functions have stricter requirements:
/// - All arguments must be BTF-typed
/// - Return type must be scalar or void
/// - Cannot access caller's stack
pub fn check_global_func_signature(subprog: &SubprogInfo) -> Result<()> {
    if !subprog.is_global {
        return Ok(());
    }

    // Global functions must have BTF info
    if subprog.btf_id == 0 {
        return Err(VerifierError::InvalidFunctionCall(
            "global function must have BTF type info".into(),
        ));
    }

    // Check argument count is reasonable
    if subprog.arg_cnt > 5 {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "global function has {} args, max is 5",
            subprog.arg_cnt
        )));
    }

    Ok(())
}

/// Mark subprogram properties based on its instructions
///
/// This scans a subprogram to determine:
/// - Whether it changes packet data
/// - Whether it might sleep
/// - Whether it has tail calls
pub fn mark_subprog_properties(subprog: &mut SubprogInfo, insns: &[BpfInsn]) {
    let start = subprog.start;
    let end = subprog.end.min(insns.len());

    for insn in insns[start..end].iter() {
        // Check for tail_call
        if is_helper_call(insn) && insn.imm == 12 {
            // BPF_FUNC_tail_call = 12
            subprog.has_tail_call = true;
        }

        // Check for packet data changing helpers
        if is_helper_call(insn) {
            let helper_id = insn.imm as u32;
            if changes_pkt_data(helper_id) {
                subprog.changes_pkt_data = true;
            }
            if might_sleep(helper_id) {
                subprog.might_sleep = true;
            }
        }
    }
}

/// Check if a helper might change packet data
fn changes_pkt_data(helper_id: u32) -> bool {
    matches!(
        helper_id,
        44 |  // bpf_skb_store_bytes
        45 |  // bpf_skb_load_bytes
        35 |  // bpf_skb_change_proto
        46 |  // bpf_skb_change_type
        50 |  // bpf_skb_change_tail
        51 |  // bpf_skb_change_head
        98 |  // bpf_xdp_adjust_head
        65 // bpf_xdp_adjust_tail
    )
}

/// Check if a helper might sleep
fn might_sleep(helper_id: u32) -> bool {
    matches!(
        helper_id,
        130 | // bpf_copy_from_user
        148 | // bpf_copy_from_user_task
        171 | // bpf_ima_file_hash
        174 // bpf_find_vma
    )
}

// ============================================================================
// Tail Call Verification and Propagation
// ============================================================================

/// Maximum stack depth when tail calls are present
///
/// When a subprogram has tail calls and the call stack of previous frames
/// is too large, tail calls are not allowed as they would overflow.
pub const MAX_TAIL_CALL_STACK: i32 = 256;

/// Tail call verification context
#[derive(Debug, Clone)]
pub struct TailCallContext {
    /// Whether any subprogram has tail calls
    pub has_tail_calls: bool,
    /// Subprograms that are tail call reachable
    pub reachable: Vec<bool>,
    /// Call graph edges (caller -> callees)
    pub call_graph: Vec<Vec<usize>>,
}

impl TailCallContext {
    /// Create new tail call context
    pub fn new(subprog_cnt: usize) -> Self {
        Self {
            has_tail_calls: false,
            reachable: vec![false; subprog_cnt],
            call_graph: vec![Vec::new(); subprog_cnt],
        }
    }

    /// Build context from subprogram info and call sites
    pub fn build(subprogs: &SubprogManager, call_sites: &[CallSite]) -> Self {
        let cnt = subprogs.count();
        let mut ctx = Self::new(cnt);

        // Build call graph
        for site in call_sites {
            if site.caller < cnt && site.callee < cnt {
                ctx.call_graph[site.caller].push(site.callee);
            }
        }

        // Check for tail calls in each subprogram
        for i in 0..cnt {
            if let Some(info) = subprogs.get(i) {
                if info.has_tail_call {
                    ctx.has_tail_calls = true;
                    ctx.reachable[i] = true;
                }
            }
        }

        // Propagate tail_call_reachable through call graph
        ctx.propagate_reachability();

        ctx
    }

    /// Propagate tail call reachability through the call graph
    ///
    /// If a function A calls function B, and B has tail_call_reachable,
    /// then A also becomes tail_call_reachable (in reverse - if A has
    /// tail calls, all functions it can reach get the flag).
    fn propagate_reachability(&mut self) {
        let cnt = self.reachable.len();
        let mut changed = true;

        // Forward propagation: if a function has tail calls,
        // mark all reachable functions
        while changed {
            changed = false;
            for i in 0..cnt {
                if self.reachable[i] {
                    for &callee in &self.call_graph[i].clone() {
                        if !self.reachable[callee] {
                            self.reachable[callee] = true;
                            changed = true;
                        }
                    }
                }
            }
        }

        // Also mark main (subprog 0) as reachable if any subprog has tail calls
        if self.has_tail_calls && cnt > 0 {
            self.reachable[0] = true;
        }
    }

    /// Check if tail call is allowed given current stack depth
    pub fn check_tail_call_stack(&self, stack_depth: i32, subprog_idx: usize) -> Result<()> {
        if !self.reachable.get(subprog_idx).copied().unwrap_or(false) {
            return Ok(());
        }

        if stack_depth > MAX_TAIL_CALL_STACK {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "tail_call not allowed when call stack of previous frames is {} bytes (max {})",
                stack_depth, MAX_TAIL_CALL_STACK
            )));
        }

        Ok(())
    }
}

/// Validate tail call usage in subprograms
///
/// This checks various restrictions on tail calls:
/// - Tail calls not allowed in async callbacks
/// - Stack depth limit when tail calls present
/// - Return type must be scalar for functions with tail calls
/// - Refcounted args not allowed with tail calls
pub fn validate_tail_calls(
    subprogs: &mut SubprogManager,
    call_state: &CallState,
) -> Result<TailCallContext> {
    let ctx = TailCallContext::build(subprogs, &call_state.call_sites);

    if !ctx.has_tail_calls {
        return Ok(ctx);
    }

    // Apply reachability to subprogs
    for i in 0..subprogs.count() {
        if ctx.reachable[i] {
            if let Some(info) = subprogs.get_mut(i) {
                info.tail_call_reachable = true;
            }
        }
    }

    // Validate each subprogram
    for i in 0..subprogs.count() {
        if let Some(info) = subprogs.get(i) {
            // Async callbacks can't have tail calls
            if info.is_async_cb && info.has_tail_call {
                return Err(VerifierError::InvalidFunctionCall(format!(
                    "subprog {} is async callback, incompatible with tail calls",
                    i
                )));
            }

            // Tail calls require scalar return type for non-main functions
            if i > 0 && info.has_tail_call && !info.returns_scalar {
                return Err(VerifierError::InvalidFunctionCall(
                    "tail_call is only allowed in functions that return 'int'".into(),
                ));
            }

            // Refcounted arguments conflict with tail calls
            if info.has_refcounted_args && info.has_tail_call {
                return Err(VerifierError::InvalidFunctionCall(format!(
                    "subprog {} has refcounted args, incompatible with tail calls",
                    i
                )));
            }
        }
    }

    Ok(ctx)
}

/// Check tail call compatibility for a specific call
///
/// Called when processing a bpf_tail_call helper.
pub fn check_tail_call_compat(state: &BpfVerifierState, subprogs: &SubprogManager) -> Result<()> {
    // Can't tail call from a subprogram (curframe > 0)
    if state.curframe > 0 {
        return Err(VerifierError::InvalidFunctionCall(
            "tail_call not allowed in subprograms".into(),
        ));
    }

    // Check stack depth
    let current_stack = state
        .cur_func()
        .map(|f| f.stack.allocated_stack as i32)
        .unwrap_or(0);

    if current_stack > MAX_TAIL_CALL_STACK {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "tail_call not allowed when stack usage is {} bytes (max {})",
            current_stack, MAX_TAIL_CALL_STACK
        )));
    }

    // Check mixing of tail calls and bpf-to-bpf calls
    if subprogs.count() > 1 {
        // Allow if all other subprogs are global or have compatible stack
        for i in 1..subprogs.count() {
            if let Some(info) = subprogs.get(i) {
                if !info.is_global && info.stack_depth + current_stack > MAX_BPF_STACK as i32 {
                    return Err(VerifierError::InvalidFunctionCall(
                        "mixing of tail_calls and bpf-to-bpf calls may exceed stack limit".into(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Check for resource leaks before tail call
///
/// Tail calls transfer control and don't return, so any acquired
/// resources must be released first.
pub fn check_tail_call_resources(state: &BpfVerifierState) -> Result<()> {
    // Check for unreleased references
    if !state.refs.is_empty() {
        return Err(VerifierError::InvalidState(
            "tail_call with unreleased references".into(),
        ));
    }

    // Check for unreleased locks
    if state.refs.active_locks > 0 {
        return Err(VerifierError::InvalidState(
            "tail_call with held locks".into(),
        ));
    }

    // Check for active RCU read lock
    if state.refs.in_rcu() {
        return Err(VerifierError::InvalidState(
            "tail_call inside rcu_read_lock region".into(),
        ));
    }

    // Check spin lock state
    if state.lock_state.has_locks() {
        return Err(VerifierError::InvalidState(
            "tail_call with held spin lock".into(),
        ));
    }

    Ok(())
}

/// Full tail call verification combining all checks
pub fn verify_tail_call(state: &BpfVerifierState, subprogs: &SubprogManager) -> Result<()> {
    check_tail_call_compat(state, subprogs)?;
    check_tail_call_resources(state)?;
    Ok(())
}

// ============================================================================
// Private Stack Support (Linux 6.13+)
// ============================================================================

/// Check if JIT supports private stack
///
/// This would query the JIT backend, but for now we assume support is available
/// if the feature is enabled.
pub fn jit_supports_private_stack() -> bool {
    // In a real implementation, this would check:
    // - JIT architecture capabilities
    // - Kernel configuration
    // - Platform support
    //
    // For now, return true if BPF_PRIV_STACK_MIN_SIZE is defined
    true
}

/// Determine private stack mode for a subprogram
///
/// This analyzes the subprogram's characteristics and decides whether
/// it should use a private stack.
pub fn determine_priv_stack_mode(
    subprog: &SubprogInfo,
    has_tail_calls: bool,
) -> PrivStackMode {
    // Can't use private stack with tail calls
    if has_tail_calls || subprog.tail_call_reachable {
        return PrivStackMode::NoPrivStack;
    }

    // Main subprog (index 0) can't use private stack
    if subprog.start == 0 {
        return PrivStackMode::NoPrivStack;
    }

    // Check if JIT supports private stack
    if !jit_supports_private_stack() {
        return PrivStackMode::NoPrivStack;
    }

    // Request private stack only if stack depth is significant
    // This is the BPF_PRIV_STACK_MIN_SIZE threshold (64 bytes)
    if subprog.stack_depth >= BPF_PRIV_STACK_MIN_SIZE as i32 {
        PrivStackMode::Adaptive
    } else {
        PrivStackMode::NoPrivStack
    }
}

/// Update private stack modes for all subprograms
///
/// This should be called after stack depth calculation is complete.
pub fn update_priv_stack_modes(subprogs: &mut SubprogManager) -> Result<()> {
    let count = subprogs.count();

    // Check if any subprogram has tail calls
    let has_tail_calls = (0..count)
        .any(|i| subprogs.get(i).map(|s| s.has_tail_call).unwrap_or(false));

    // Update each subprogram's private stack mode
    for i in 0..count {
        if let Some(subprog) = subprogs.get_mut(i) {
            let mode = determine_priv_stack_mode(subprog, has_tail_calls);
            subprog.priv_stack_mode = mode;
        }
    }

    Ok(())
}

/// Get the total stack depth considering private stack
///
/// Returns (shared_stack_depth, private_stack_depth)
pub fn get_stack_depths(subprogs: &SubprogManager, subprog_idx: usize) -> (i32, i32) {
    if let Some(subprog) = subprogs.get(subprog_idx) {
        match subprog.priv_stack_mode {
            PrivStackMode::Adaptive => {
                // With private stack, all stack is private
                (0, subprog.stack_depth)
            }
            _ => {
                // Without private stack, all stack is shared
                (subprog.stack_depth, 0)
            }
        }
    } else {
        (0, 0)
    }
}

/// Round up stack size to required alignment (32 bytes)
pub fn round_stack_size(size: i32) -> i32 {
    // Round up to 32-byte granularity
    ((size.max(1) + 31) / 32) * 32
}
