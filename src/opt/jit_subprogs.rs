//!

//! This module implements the jit_subprogs() functionality from the kernel verifier.

//! It handles:

//! - Subprogram extraction and preparation for JIT compilation

//! - Stack depth calculation for each subprogram

//! - Tail call compatibility checking

//! - Subprogram patching for function calls



use alloc::{format, vec, vec::Vec};

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::verifier::env::VerifierEnv;

/// Maximum number of subprograms allowed
pub const MAX_SUBPROGS: usize = 256;

/// Maximum total stack depth across all frames
pub const MAX_COMBINED_STACK_DEPTH: i32 = 512;

/// JIT compilation context for subprograms
#[derive(Debug, Clone)]
pub struct JitSubprogContext {
    /// Subprogram information
    pub subprogs: Vec<SubprogInfo>,
    /// Whether all subprograms can be JIT compiled
    pub jit_requested: bool,
    /// Total stack depth needed
    pub total_stack_depth: i32,
    /// Whether tail calls are used
    pub has_tail_calls: bool,
}

/// Information about a single subprogram for JIT
#[derive(Debug, Clone)]
pub struct SubprogInfo {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (exclusive)
    pub end: usize,
    /// Stack depth used by this subprogram
    pub stack_depth: i32,
    /// Whether this is the main program
    pub is_main: bool,
    /// Whether this subprogram is async (callback)
    pub is_async: bool,
    /// Whether this subprogram is an exception callback
    pub is_exception_cb: bool,
    /// BTF function ID if available
    pub btf_id: Option<u32>,
    /// Number of arguments
    pub arg_cnt: u8,
    /// Adjusted start after patching
    pub adjusted_start: usize,
    /// Whether this subprog has been JIT compiled
    pub jited: bool,
    /// Whether tail calls can reach this subprogram
    pub tail_call_reachable: bool,
    /// Whether this subprogram changes packet data
    pub changes_pkt_data: bool,
    /// Whether this subprogram might sleep
    pub might_sleep: bool,
    /// Number of exception table entries needed
    pub num_exentries: u32,
    /// Line info index for this subprogram
    pub linfo_idx: u32,
    /// Whether to use private stack (for deep call chains)
    pub use_priv_stack: bool,
    /// Whether this is a global function
    pub is_global: bool,
}

impl SubprogInfo {
    /// Create a new subprogram info
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            stack_depth: 0,
            is_main: start == 0,
            is_async: false,
            is_exception_cb: false,
            btf_id: None,
            arg_cnt: 0,
            adjusted_start: start,
            jited: false,
            tail_call_reachable: false,
            changes_pkt_data: false,
            might_sleep: false,
            num_exentries: 0,
            linfo_idx: 0,
            use_priv_stack: false,
            is_global: false,
        }
    }

    /// Get the length of this subprogram in instructions
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if this subprogram is empty
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
    
    /// Check if this subprogram can use tail calls
    pub fn can_use_tail_call(&self) -> bool {
        !self.is_async && !self.is_exception_cb && !self.might_sleep
    }
}

impl JitSubprogContext {
    /// Create a new JIT context
    pub fn new() -> Self {
        Self {
            subprogs: Vec::new(),
            jit_requested: false,
            total_stack_depth: 0,
            has_tail_calls: false,
        }
    }

    /// Initialize from verifier environment
    pub fn from_env(env: &VerifierEnv) -> Self {
        let mut ctx = Self::new();
        
        for sp in &env.subprogs {
            let mut info = SubprogInfo::new(sp.start, sp.end);
            info.stack_depth = sp.stack_depth;
            info.is_async = sp.is_async_cb;
            info.is_exception_cb = sp.is_exception_cb;
            info.btf_id = sp.btf_id;
            info.arg_cnt = sp.arg_cnt;
            info.tail_call_reachable = sp.tail_call_reachable;
            info.changes_pkt_data = sp.changes_pkt_data;
            info.might_sleep = sp.might_sleep;
            info.is_global = sp.is_global;
            ctx.subprogs.push(info);
        }
        
        ctx
    }

    /// Get the subprogram containing an instruction
    pub fn find_subprog(&self, insn_idx: usize) -> Option<usize> {
        for (i, sp) in self.subprogs.iter().enumerate() {
            if insn_idx >= sp.start && insn_idx < sp.end {
                return Some(i);
            }
        }
        None
    }

    /// Get subprogram by index
    pub fn get(&self, idx: usize) -> Option<&SubprogInfo> {
        self.subprogs.get(idx)
    }

    /// Get mutable subprogram by index
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut SubprogInfo> {
        self.subprogs.get_mut(idx)
    }

    /// Number of subprograms
    pub fn count(&self) -> usize {
        self.subprogs.len()
    }
}

impl Default for JitSubprogContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Prepare subprograms for JIT compilation
///
/// This function:
/// 1. Validates subprogram structure
/// 2. Calculates stack depths
/// 3. Checks for tail call compatibility
/// 4. Prepares call instruction patching
pub fn jit_subprogs(
    env: &mut VerifierEnv,
    insns: &mut [BpfInsn],
) -> Result<JitSubprogContext> {
    let mut ctx = JitSubprogContext::from_env(env);
    
    if ctx.count() <= 1 {
        // Only main program, no subprograms to process
        return Ok(ctx);
    }
    
    // Validate subprogram count
    if ctx.count() > MAX_SUBPROGS {
        return Err(VerifierError::TooComplex(
            format!("too many subprograms: {} > {}", ctx.count(), MAX_SUBPROGS)
        ));
    }
    
    // Calculate stack depths for all subprograms
    calculate_stack_depths(&mut ctx, insns)?;
    
    // Check combined stack depth
    ctx.total_stack_depth = ctx.subprogs.iter()
        .map(|sp| sp.stack_depth)
        .max()
        .unwrap_or(0);
    
    // Check for tail calls
    ctx.has_tail_calls = check_tail_calls(insns);
    
    // Validate tail call compatibility
    if ctx.has_tail_calls && ctx.count() > 1 {
        validate_tail_call_subprogs(&ctx)?;
    }
    
    // Patch subprogram calls
    patch_subprog_calls(&mut ctx, insns)?;
    
    ctx.jit_requested = true;
    
    Ok(ctx)
}

/// Calculate stack depth for each subprogram
fn calculate_stack_depths(
    ctx: &mut JitSubprogContext,
    insns: &[BpfInsn],
) -> Result<()> {
    for sp in &mut ctx.subprogs {
        let mut max_depth: i32 = 0;
        
        // Scan instructions for stack accesses
        for idx in sp.start..sp.end {
            if let Some(insn) = insns.get(idx) {
                let depth = get_stack_depth_for_insn(insn);
                if depth > max_depth {
                    max_depth = depth;
                }
            }
        }
        
        // Round up to 8-byte alignment
        sp.stack_depth = (max_depth + 7) & !7;
        
        // Check max stack depth
        if sp.stack_depth > MAX_BPF_STACK as i32 {
            return Err(VerifierError::StackOutOfBounds(sp.stack_depth));
        }
    }
    
    Ok(())
}

/// Get the stack depth required by an instruction
fn get_stack_depth_for_insn(insn: &BpfInsn) -> i32 {
    let class = insn.class();
    
    // Check for stack accesses via FP
    if insn.src_reg == BPF_REG_FP as u8 || insn.dst_reg == BPF_REG_FP as u8 {
        let off = insn.off as i32;
        if off < 0 {
            return -off;
        }
    }
    
    // STX/LDX with FP base
    match class {
        BPF_STX | BPF_LDX | BPF_ST => {
            if insn.dst_reg == BPF_REG_FP as u8 {
                let off = insn.off as i32;
                if off < 0 {
                    return -off + get_access_size(insn) as i32;
                }
            }
        }
        _ => {}
    }
    
    0
}

/// Get the access size from instruction
fn get_access_size(insn: &BpfInsn) -> u32 {
    match insn.size() {
        0 => 4, // BPF_W
        1 => 2, // BPF_H
        2 => 1, // BPF_B
        3 => 8, // BPF_DW
        _ => 4,
    }
}

/// Check if the program uses tail calls
fn check_tail_calls(insns: &[BpfInsn]) -> bool {
    for insn in insns {
        if insn.code == (BPF_JMP | BPF_CALL) && 
           insn.imm == BPF_FUNC_TAIL_CALL as i32 {
            return true;
        }
    }
    false
}

/// Tail call helper function ID
const BPF_FUNC_TAIL_CALL: u32 = 12;

/// Validate that subprograms are compatible with tail calls
fn validate_tail_call_subprogs(ctx: &JitSubprogContext) -> Result<()> {
    // With tail calls, all subprograms must have compatible stack usage
    // In the kernel, this is more complex, but here we do basic validation
    
    for (i, sp) in ctx.subprogs.iter().enumerate() {
        if sp.is_async {
            return Err(VerifierError::InvalidState(
                format!("subprog {} is async callback, incompatible with tail calls", i)
            ));
        }
    }
    
    Ok(())
}

/// Patch subprogram call instructions
///
/// Converts pseudo-calls (BPF_PSEUDO_CALL with relative offset) to
/// actual call instructions with proper offsets.
fn patch_subprog_calls(
    ctx: &mut JitSubprogContext,
    insns: &mut [BpfInsn],
) -> Result<()> {
    for (i, insn) in insns.iter_mut().enumerate() {
        // Check for pseudo call
        if insn.code == (BPF_JMP | BPF_CALL) && 
           insn.src_reg == BPF_PSEUDO_CALL {
            // Calculate target instruction index
            let target = (i as i32 + insn.imm + 1) as usize;
            
            // Find the target subprogram
            let target_sp = ctx.find_subprog(target).ok_or_else(|| {
                VerifierError::InvalidJumpTarget(target)
            })?;
            
            // Validate target is at subprogram start
            if let Some(sp) = ctx.get(target_sp) {
                if target != sp.start {
                    return Err(VerifierError::InvalidJumpTarget(target));
                }
            }
            
            // The instruction is already correctly set up with relative offset
            // JIT compiler will handle the actual address resolution
        }
    }
    
    Ok(())
}

/// Fixup subprogram calls after instruction patching
///
/// When instructions are inserted or removed, call offsets need adjustment
pub fn fixup_subprog_calls_after_patch(
    insns: &mut [BpfInsn],
    patch_idx: usize,
    delta: i32,
) {
    for (i, insn) in insns.iter_mut().enumerate() {
        if insn.code == (BPF_JMP | BPF_CALL) && 
           insn.src_reg == BPF_PSEUDO_CALL {
            // Calculate original target
            let orig_target = i as i32 + insn.imm + 1;
            
            // If the call is before the patch point and target is after,
            // or if the call is after and target is before, adjust
            let call_before = (i as i32) < patch_idx as i32;
            let target_after = orig_target >= patch_idx as i32;
            
            if call_before && target_after {
                // Target moved forward
                insn.imm += delta;
            } else if !call_before && !target_after {
                // Call moved, target didn't
                insn.imm -= delta;
            }
        }
    }
}

/// Extract a subprogram as a separate program
///
/// Used when subprograms need to be JIT compiled separately
pub fn extract_subprog(
    insns: &[BpfInsn],
    sp: &SubprogInfo,
) -> Vec<BpfInsn> {
    insns[sp.start..sp.end].to_vec()
}

/// Verify that all subprogram calls have valid targets
pub fn verify_subprog_calls(
    insns: &[BpfInsn],
    ctx: &JitSubprogContext,
) -> Result<()> {
    for (i, insn) in insns.iter().enumerate() {
        if insn.code == (BPF_JMP | BPF_CALL) && 
           insn.src_reg == BPF_PSEUDO_CALL {
            let target = (i as i32 + insn.imm + 1) as usize;
            
            if target >= insns.len() {
                return Err(VerifierError::JumpOutOfRange(target, insns.len()));
            }
            
            // Verify target is a subprogram start
            let sp_idx = ctx.find_subprog(target);
            if sp_idx.is_none() {
                return Err(VerifierError::InvalidJumpTarget(target));
            }
            
            if let Some(sp) = sp_idx.and_then(|idx| ctx.get(idx)) {
                if target != sp.start {
                    return Err(VerifierError::InvalidJumpTarget(target));
                }
            }
        }
    }
    
    Ok(())
}

/// Count exception table entries needed for a subprogram
/// 
/// Exception entries are needed for:
/// - PROBE_MEM loads
/// - PROBE_ATOMIC stores
/// - Arena memory accesses
pub fn count_exentries(insns: &[BpfInsn], sp: &SubprogInfo) -> u32 {
    let mut count = 0u32;
    
    for idx in sp.start..sp.end {
        if let Some(insn) = insns.get(idx) {
            let class = insn.code & 0x07;
            let mode = insn.code & 0xe0;
            
            // LDX with PROBE_MEM modes
            if class == BPF_LDX {
                match mode >> 5 {
                    5 | 6 | 7 | 8 => count += 1, // PROBE_MEM variants
                    _ => {}
                }
            }
            
            // STX with PROBE_ATOMIC
            if class == BPF_STX && mode == 0xc0 {
                count += 1;
            }
            
            // Arena access (ADDR_SPACE_CAST followed by memory access)
            if insn.code == (BPF_ALU64 | BPF_MOV | BPF_X) && insn.off == 1 {
                // ADDR_SPACE_CAST
                count += 1;
            }
        }
    }
    
    count
}

/// Propagate properties through call graph
/// 
/// Propagates:
/// - tail_call_reachable: if caller has tail call, callee is reachable
/// - changes_pkt_data: if callee changes packet, caller does too
/// - might_sleep: if callee might sleep, caller might too
pub fn propagate_subprog_properties(
    ctx: &mut JitSubprogContext,
    insns: &[BpfInsn],
) -> Result<()> {
    let n = ctx.count();
    if n == 0 {
        return Ok(());
    }
    
    // Build call graph
    let mut calls: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut callers: Vec<Vec<usize>> = vec![Vec::new(); n];
    
    for (sp_idx, sp) in ctx.subprogs.iter().enumerate() {
        for idx in sp.start..sp.end {
            if let Some(insn) = insns.get(idx) {
                if insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_CALL {
                    let target = (idx as i32 + insn.imm + 1) as usize;
                    if let Some(target_sp) = ctx.find_subprog(target) {
                        calls[sp_idx].push(target_sp);
                        callers[target_sp].push(sp_idx);
                    }
                }
            }
        }
    }
    
    // Propagate tail_call_reachable forward (caller -> callee)
    let mut changed = true;
    while changed {
        changed = false;
        for sp_idx in 0..n {
            if ctx.subprogs[sp_idx].tail_call_reachable {
                for &callee in &calls[sp_idx] {
                    if !ctx.subprogs[callee].tail_call_reachable {
                        ctx.subprogs[callee].tail_call_reachable = true;
                        changed = true;
                    }
                }
            }
        }
    }
    
    // Propagate changes_pkt_data and might_sleep backward (callee -> caller)
    changed = true;
    while changed {
        changed = false;
        for sp_idx in 0..n {
            let pkt = ctx.subprogs[sp_idx].changes_pkt_data;
            let sleep = ctx.subprogs[sp_idx].might_sleep;
            
            for &caller in &callers[sp_idx] {
                if pkt && !ctx.subprogs[caller].changes_pkt_data {
                    ctx.subprogs[caller].changes_pkt_data = true;
                    changed = true;
                }
                if sleep && !ctx.subprogs[caller].might_sleep {
                    ctx.subprogs[caller].might_sleep = true;
                    changed = true;
                }
            }
        }
    }
    
    Ok(())
}

/// Determine which subprograms should use private stack
/// 
/// Private stack is used when:
/// - Call depth is very deep
/// - Stack usage is high
/// - Program is sleepable (needs interruptible stack)
pub fn determine_priv_stack_usage(
    ctx: &mut JitSubprogContext,
    insns: &[BpfInsn],
) -> Result<()> {
    // Calculate call depths for each subprogram
    let depths = calculate_call_depths(ctx, insns)?;
    
    // Calculate cumulative stack depth along call chains
    for (sp_idx, sp) in ctx.subprogs.iter_mut().enumerate() {
        let depth = depths.get(sp_idx).copied().unwrap_or(1);
        let cumulative_stack = sp.stack_depth * depth as i32;
        
        // Use private stack if:
        // - Cumulative stack > 256 bytes (half of max)
        // - Or if sleepable and stack > 128 bytes
        if cumulative_stack > 256 || (sp.might_sleep && sp.stack_depth > 128) {
            sp.use_priv_stack = true;
        }
    }
    
    Ok(())
}

/// Calculate call depth for each subprogram
fn calculate_call_depths(
    ctx: &JitSubprogContext,
    insns: &[BpfInsn],
) -> Result<Vec<u32>> {
    let n = ctx.count();
    let mut depths = vec![0u32; n];
    let mut visited = vec![false; n];
    let mut in_stack = vec![false; n];
    
    fn dfs(
        sp_idx: usize,
        insns: &[BpfInsn],
        ctx: &JitSubprogContext,
        depths: &mut [u32],
        visited: &mut [bool],
        in_stack: &mut [bool],
    ) -> Result<u32> {
        if in_stack[sp_idx] {
            return Err(VerifierError::InvalidState("recursive call detected".into()));
        }
        if visited[sp_idx] {
            return Ok(depths[sp_idx]);
        }
        
        visited[sp_idx] = true;
        in_stack[sp_idx] = true;
        
        let mut max_depth = 1u32;
        
        if let Some(sp) = ctx.get(sp_idx) {
            for idx in sp.start..sp.end {
                if let Some(insn) = insns.get(idx) {
                    if insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_CALL {
                        let target = (idx as i32 + insn.imm + 1) as usize;
                        if let Some(target_sp) = ctx.find_subprog(target) {
                            let sub_depth = dfs(target_sp, insns, ctx, depths, visited, in_stack)?;
                            max_depth = max_depth.max(1 + sub_depth);
                        }
                    }
                }
            }
        }
        
        in_stack[sp_idx] = false;
        depths[sp_idx] = max_depth;
        Ok(max_depth)
    }
    
    // Start from main program
    if n > 0 {
        dfs(0, insns, ctx, &mut depths, &mut visited, &mut in_stack)?;
    }
    
    // Also process any unvisited subprograms (callbacks)
    for i in 0..n {
        if !visited[i] {
            dfs(i, insns, ctx, &mut depths, &mut visited, &mut in_stack)?;
        }
    }
    
    Ok(depths)
}

/// Validate combined stack depth across all call chains
pub fn validate_combined_stack_depth(
    ctx: &JitSubprogContext,
    insns: &[BpfInsn],
) -> Result<i32> {
    let depths = calculate_call_depths(ctx, insns)?;
    let mut max_combined = 0i32;
    
    // For each leaf subprogram, calculate the max stack along the path
    for (sp_idx, sp) in ctx.subprogs.iter().enumerate() {
        let depth = depths.get(sp_idx).copied().unwrap_or(1);
        
        // Simplified: assume worst case is depth * max stack of any subprog in chain
        // In reality, we'd trace actual call paths
        let path_stack = sp.stack_depth * depth as i32;
        max_combined = max_combined.max(path_stack);
    }
    
    if max_combined > MAX_COMBINED_STACK_DEPTH {
        return Err(VerifierError::StackOverflow(max_combined));
    }
    
    Ok(max_combined)
}

/// Calculate the maximum call depth
pub fn max_call_depth(
    insns: &[BpfInsn],
    ctx: &JitSubprogContext,
) -> Result<u32> {
    let mut visited = vec![false; ctx.count()];
    let mut depth = vec![0u32; ctx.count()];
    
    fn dfs(
        sp_idx: usize,
        insns: &[BpfInsn],
        ctx: &JitSubprogContext,
        visited: &mut [bool],
        depth: &mut [u32],
        current_depth: u32,
    ) -> Result<u32> {
        if visited[sp_idx] {
            // Check for recursion
            if depth[sp_idx] == 0 {
                return Err(VerifierError::InvalidState(
                    "recursive call detected".into()
                ));
            }
            return Ok(depth[sp_idx]);
        }
        
        visited[sp_idx] = true;
        let mut max_depth = current_depth;
        
        if let Some(sp) = ctx.get(sp_idx) {
            for idx in sp.start..sp.end {
                if let Some(insn) = insns.get(idx) {
                    if insn.code == (BPF_JMP | BPF_CALL) && 
                       insn.src_reg == BPF_PSEUDO_CALL {
                        let target = (idx as i32 + insn.imm + 1) as usize;
                        if let Some(target_sp) = ctx.find_subprog(target) {
                            let sub_depth = dfs(
                                target_sp, insns, ctx, visited, depth, current_depth + 1
                            )?;
                            max_depth = max_depth.max(sub_depth);
                        }
                    }
                }
            }
        }
        
        depth[sp_idx] = max_depth;
        Ok(max_depth)
    }
    
    // Start from main program (subprog 0)
    if ctx.count() > 0 {
        dfs(0, insns, ctx, &mut visited, &mut depth, 1)
    } else {
        Ok(1)
    }
}
