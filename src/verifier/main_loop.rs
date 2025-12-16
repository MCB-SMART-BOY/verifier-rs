//! Main verification loop for BPF verifier
//!
//! This module implements the core verification loop that walks through
//! all program paths and validates each instruction. This corresponds to
//! the kernel's `do_check()` function.
//!
//! Key features:
//! - Branch exploration using a state stack (DFS)
//! - State pruning to avoid redundant exploration
//! - Branch counting for parent state tracking
//! - Subprogram call/return handling
//! - Precision tracking for conditional jumps


use alloc::{format, vec::Vec, boxed::Box};

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::core::log::{log_insn, log_branch};
use crate::core::insn::{check_alu_op, check_cond_jmp_op, check_ld_imm64};
use crate::check::helper::check_helper_call_with_ctx;
use crate::state::verifier_state::BpfVerifierState;
use crate::state::reg_state::BpfRegState;
use crate::check::load_store::bpf_size_to_bytes;

use crate::analysis::prune::{
    StateCache, StateVisitContext, StateVisitResult,
    is_state_visited, JmpHistory, clean_live_states,
    SccTracker, StateId,
};
use crate::analysis::precision::mark_jmp_precision;
use crate::mem::memory::check_mem_access_with_ctx;
use crate::sanitize::sanitize::{
    sanitize_needed, sanitize_ptr_alu, sanitize_check_bounds,
    sanitize_mark_insn_seen, SanitizeState,
};
use crate::check::kfunc::{check_kfunc_call, KfuncRegistry};
use crate::special::exception::{
    ExceptionState, is_bpf_throw_kfunc, validate_bpf_throw,
    setup_exception_callback_state,
};
use crate::check::callback::CallbackState;
use crate::check::jump::{
    is_may_goto_insn, check_may_goto, MayGotoState,
    is_indirect_jump, check_indirect_jump_fields, check_indirect_jump,
    validate_indirect_jump_targets,
};
use super::env::VerifierEnv;

/// Result of processing a single instruction
#[derive(Debug, Clone)]
pub enum InsnResult {
    /// Continue to next instruction
    Continue,
    /// Jump to specific instruction
    Jump(usize),
    /// Branch: explore both paths (fall-through, target)
    Branch(usize, usize),
    /// Exit from program
    Exit,
    /// Call to subprogram
    Call(usize),
    /// Return from subprogram  
    Return,
}

/// Jump history entry flags
pub mod jmp_flags {
    /// Branch was taken
    pub const BRANCH_TAKEN: u32 = 0x01;
    /// Branch was not taken (fall-through)
    pub const BRANCH_NOT_TAKEN: u32 = 0x02;
    /// This is a call instruction
    pub const CALL: u32 = 0x04;
    /// This is a return instruction
    pub const RET: u32 = 0x08;
}

/// Stack element for branch exploration
/// 
/// This corresponds to the kernel's `bpf_verifier_stack_elem`
#[derive(Debug)]
pub struct StackElem {
    /// Verifier state at this point (boxed for kernel safety)
    pub state: Box<BpfVerifierState>,
    /// Instruction index to explore
    pub insn_idx: usize,
    /// Previous instruction index (for jump history)
    pub prev_insn_idx: usize,
    /// Log position at push time (for rollback)
    pub log_pos: usize,
    /// Parent state ID in state cache (using StateId for proper tracking)
    pub parent_id: Option<crate::analysis::prune::StateId>,
}

impl StackElem {
    /// Create a new exploration stack element
    pub fn new(state: Box<BpfVerifierState>, insn_idx: usize, prev_insn_idx: usize) -> Self {
        Self {
            state,
            insn_idx,
            prev_insn_idx,
            log_pos: 0,
            parent_id: None,
        }
    }
}

/// Main verifier structure
pub struct MainVerifier<'a> {
    /// Verifier environment
    pub env: &'a mut VerifierEnv,
    /// State cache for pruning
    pub state_cache: StateCache,
    /// SCC tracker for loop precision propagation
    pub scc_tracker: SccTracker,
    /// Jump history for precision tracking
    pub jmp_history: JmpHistory,
    /// Number of jumps processed
    pub jmps_processed: u32,
    /// Previous prune point jump count
    pub prev_jmps_processed: u32,
    /// Previous prune point instruction count
    pub prev_insn_processed: usize,
    /// Exploration stack (replaces env.state_stack for better tracking)
    pub stack: Vec<StackElem>,
    /// Current parent state ID in state cache (using StateId for proper tracking)
    pub cur_parent_id: Option<StateId>,
    /// Maximum stack depth seen
    pub max_stack_depth: usize,
    /// Kfunc registry for kfunc validation
    pub kfunc_registry: KfuncRegistry,
    /// Exception state tracking
    pub exception_state: ExceptionState,
    /// Current callback state (if in callback)
    pub callback_state: Option<CallbackState>,
    /// may_goto state tracking for bounded loops
    pub may_goto_state: MayGotoState,
}

/// Complexity limit for jump sequence depth
pub const BPF_COMPLEXITY_LIMIT_JMP_SEQ: usize = 8192;

impl<'a> MainVerifier<'a> {
    /// Create a new main verifier
    pub fn new(env: &'a mut VerifierEnv) -> Self {
        let kfunc_registry = KfuncRegistry::new();
        // Register common kfuncs
        let kfunc_registry = {
            let mut registry = kfunc_registry;
            registry.register_common();
            registry
        };
        
        Self {
            env,
            state_cache: StateCache::new(),
            scc_tracker: SccTracker::new(),
            jmp_history: JmpHistory::new(64), // Max 64 entries like kernel
            jmps_processed: 0,
            prev_jmps_processed: 0,
            prev_insn_processed: 0,
            stack: Vec::new(),
            cur_parent_id: None,
            max_stack_depth: 0,
            kfunc_registry,
            exception_state: ExceptionState::new(),
            callback_state: None,
            may_goto_state: MayGotoState::new(),
        }
    }

    /// Push a state onto the exploration stack
    /// 
    /// This corresponds to the kernel's `push_stack()` function.
    /// Returns the index of the pushed state in the stack.
    fn push_stack(
        &mut self,
        insn_idx: usize,
        prev_insn_idx: usize,
        speculative: bool,
    ) -> Result<usize> {
        let cur_state = self.env.cur_state.as_ref()
            .ok_or(VerifierError::Internal("no current state".into()))?;
        
        let mut elem = StackElem::new(cur_state.clone_boxed(), insn_idx, prev_insn_idx);
        elem.log_pos = self.env.log.len();
        elem.parent_id = self.cur_parent_id;
        
        // Mark state as speculative if needed
        if speculative {
            elem.state.speculative = true;
        }
        
        // Check complexity limit
        if self.stack.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
            return Err(VerifierError::TooComplex(
                format!("jump sequence of {} is too complex", self.stack.len())
            ));
        }
        
        // Increment parent's branch count in the cache
        if let Some(parent_id) = self.cur_parent_id {
            if let Some(cached) = self.state_cache.get_by_id_mut(parent_id) {
                cached.add_branch();
            }
        }
        
        let idx = self.stack.len();
        self.stack.push(elem);
        self.max_stack_depth = self.max_stack_depth.max(self.stack.len());
        
        Ok(idx)
    }

    /// Pop a state from the exploration stack
    /// 
    /// This corresponds to the kernel's `pop_stack()` function.
    fn pop_stack(&mut self, pop_log: bool) -> Option<StackElem> {
        let elem = self.stack.pop()?;
        
        if pop_log {
            self.env.log.truncate(elem.log_pos);
        }
        
        Some(elem)
    }

    /// Update branch counts after completing exploration of a path
    /// 
    /// This corresponds to the kernel's `update_branch_counts()` function.
    /// When a path completes (exit or prune), we decrement the branch counts
    /// up the parent chain. When a state's branch count reaches 0, it's fully
    /// verified and can be used for pruning.
    /// 
    /// Also handles SCC exit when a state's branches reach 0, triggering
    /// backedge precision propagation.
    fn update_branch_counts(&mut self) -> Result<()> {
        if let Some(parent_id) = self.cur_parent_id {
            // Walk parent chain and decrement branch counts
            let mut current_id = Some(parent_id);
            
            while let Some(id) = current_id {
                // Get the cached state
                let (all_branches_done, next_parent, state_clone) = {
                    match self.state_cache.get_by_id_mut(id) {
                        Some(cached) => {
                            if cached.in_free_list {
                                (false, cached.parent_id, None)
                            } else {
                                let done = cached.complete_branch();
                                let parent = cached.parent_id;
                                let state = if done { Some(cached.state.clone()) } else { None };
                                (done, parent, state)
                            }
                        }
                        None => break,
                    }
                };
                
                // If all branches done, check for SCC exit
                if all_branches_done {
                    if let Some(ref state) = state_clone {
                        // Call maybe_exit_scc to propagate backedge precision
                        self.scc_tracker.maybe_exit_scc(
                            state,
                            id,
                            &self.env.insn_aux,
                            &mut self.state_cache,
                        )?;
                    }
                    current_id = next_parent;
                } else {
                    // Still have pending branches, stop propagation
                    break;
                }
            }
        }
        Ok(())
    }

    /// Run the main verification loop
    /// 
    /// This corresponds to the kernel's `do_check()` function.
    pub fn verify(&mut self) -> Result<()> {
        // Initialize SCC analysis for loop detection
        self.env.init_scc_analysis();
        
        // Check subprogram compatibility before starting
        self.check_subprogs()?;
        
        // Initialize state (use boxed allocation for kernel safety)
        let mut state = BpfVerifierState::new_boxed();
        self.init_regs(&mut state)?;
        
        // Set initial state with branch count = 1
        state.branches = 1;
        self.env.cur_state = Some(state);
        self.env.insn_idx = 0;

        // Main verification loop
        loop {
            // Reset current history entry
            self.env.prev_insn_idx = self.env.insn_idx;

            // Bounds check
            if self.env.insn_idx >= self.env.prog_len() {
                return Err(VerifierError::InvalidInsnIdx(self.env.insn_idx));
            }

            // Check complexity limits
            self.env.count_insn()?;

            // Update state tracking
            if let Some(ref mut state) = self.env.cur_state {
                state.last_insn_idx = self.env.prev_insn_idx;
            }

            // Record loop visit for back edge detection
            if self.env.is_in_loop(self.env.insn_idx) {
                self.env.record_loop_visit(self.env.insn_idx)?;
            }

            // Check for pruning opportunity at prune points
            if self.is_prune_point(self.env.insn_idx) {
                match self.check_state_visited()? {
                    Some(StateVisitResult::Prune(_matched_id)) => {
                        // Found equivalent state, can prune
                        // Precision propagation already done in check_state_visited
                        // Update branch counts before moving to next path
                        self.update_branch_counts()?;
                        
                        // Go to exit handling to pop next path
                        if !self.handle_path_completion()? {
                            break; // All paths explored
                        }
                        continue;
                    }
                    Some(StateVisitResult::InfiniteLoop) => {
                        return Err(VerifierError::InfiniteLoop(self.env.insn_idx));
                    }
                    Some(StateVisitResult::Explore(_new_state_id)) => {
                        // New state cached, parent ID updated in check_state_visited
                        // Continue exploration
                    }
                    Some(StateVisitResult::ExploreNoCache) | None => {
                        // Continue exploration without caching
                    }
                }
            }

            // Record jump history at jump points
            if self.is_jmp_point(self.env.insn_idx) {
                self.push_jmp_history(0, 0)?;
            }

            // Handle speculative execution with nospec barrier
            // If we're on a speculative path and hit a nospec instruction, prune
            if let Some(ref state) = self.env.cur_state {
                if state.speculative {
                    if let Some(aux) = self.env.insn_aux.get(self.env.insn_idx) {
                        if aux.nospec {
                            // Stop speculative path at nospec barrier
                            self.update_branch_counts()?;
                            if !self.handle_path_completion()? {
                                break;
                            }
                            continue;
                        }
                    }
                }
            }

            // Reset stack write marks before processing instruction
            self.env.reset_stack_write_marks();

            // Process current instruction
            let result = self.verify_insn();
            
            // Commit stack write marks on success or recoverable error
            // Note: commit() returns whether any new writes were made, not success/failure
            match &result {
                Ok(_) => {
                    self.env.commit_stack_write_marks();
                }
                Err(e) if self.is_recoverable_with_nospec(e) => {
                    self.env.commit_stack_write_marks();
                }
                Err(_) => {
                    // Don't commit on hard error - reset instead
                    self.env.reset_stack_write_marks();
                }
            };
            
            // Handle recoverable errors with nospec on speculative paths
            let result = match result {
                Err(ref e) if self.is_recoverable_with_nospec(e) => {
                    if let Some(ref state) = self.env.cur_state {
                        if state.speculative {
                            // Mark instruction with nospec to prevent future speculation
                            if let Some(aux) = self.env.insn_aux.get_mut(self.env.insn_idx) {
                                aux.nospec = true;
                                aux.alu_state = 0; // Clear ALU sanitization marks
                            }
                            // Prune this speculative path
                            self.update_branch_counts()?;
                            if !self.handle_path_completion()? {
                                break;
                            }
                            continue;
                        }
                    }
                    // Non-speculative path - propagate the error
                    result
                }
                other => other,
            };
            
            let result = result?;

            match result {
                InsnResult::Continue => {
                    self.env.insn_idx += 1;
                    if self.env.insn_idx >= self.env.prog_len() {
                        return Err(VerifierError::FallThroughExit);
                    }
                }
                InsnResult::Jump(target) => {
                    self.jmps_processed += 1;
                    self.env.insn_idx = target;
                }
                InsnResult::Branch(fall_through, target) => {
                    self.jmps_processed += 1;
                    
                    // Get the current instruction for constraint refinement
                    let insn = *self.env.insn(self.env.insn_idx).ok_or(
                        VerifierError::InvalidInsnIdx(self.env.insn_idx)
                    )?;
                    
                    // Split state for both branches and apply constraints
                    self.split_branch_states(&insn, fall_through, target)?;
                    
                    // Record branch in jump history
                    self.push_jmp_history(jmp_flags::BRANCH_TAKEN, 0)?;
                    
                    log_branch(&mut self.env.log, self.env.insn_idx, false, fall_through);
                    self.env.insn_idx = fall_through;
                }
                InsnResult::Exit => {
                    // Update branch counts - this path is complete
                    self.update_branch_counts()?;
                    
                    // Check if there are more paths to explore
                    if !self.handle_path_completion()? {
                        break; // All paths explored
                    }
                }
                InsnResult::Call(target) => {
                    // Handle subprogram call
                    self.handle_call(target)?;
                }
                InsnResult::Return => {
                    // Handle return from subprogram
                    self.handle_return()?;
                }
            }
        }

        Ok(())
    }
    
    /// Check subprogram definitions and compatibility
    /// 
    /// This validates that subprograms are properly defined and
    /// compatible with each other (matching signatures, etc.)
    fn check_subprogs(&self) -> Result<()> {
        // Verify each subprogram has valid boundaries
        for (i, subprog) in self.env.subprogs.iter().enumerate() {
            if subprog.start >= self.env.prog_len() {
                return Err(VerifierError::InvalidSubprog(
                    format!("subprog {} start {} out of range", i, subprog.start)
                ));
            }
            if subprog.end > self.env.prog_len() {
                return Err(VerifierError::InvalidSubprog(
                    format!("subprog {} end {} out of range", i, subprog.end)
                ));
            }
            if subprog.start >= subprog.end {
                return Err(VerifierError::InvalidSubprog(
                    format!("subprog {} has invalid range [{}, {})", 
                        i, subprog.start, subprog.end)
                ));
            }
        }
        
        // Check that subprograms don't overlap (except for main)
        for i in 1..self.env.subprogs.len() {
            for j in (i + 1)..self.env.subprogs.len() {
                let a = &self.env.subprogs[i];
                let b = &self.env.subprogs[j];
                if (a.start < b.end && a.end > b.start) ||
                   (b.start < a.end && b.end > a.start) {
                    return Err(VerifierError::InvalidSubprog(
                        format!("subprogs {} and {} overlap", i, j)
                    ));
                }
            }
        }
        
        Ok(())
    }

    /// Check if instruction is a prune point
    fn is_prune_point(&self, insn_idx: usize) -> bool {
        if let Some(aux) = self.env.insn_aux.get(insn_idx) {
            aux.prune_point || aux.force_prune_point
        } else {
            false
        }
    }

    /// Check if instruction is a jump point (for history recording)
    fn is_jmp_point(&self, insn_idx: usize) -> bool {
        if let Some(aux) = self.env.insn_aux.get(insn_idx) {
            aux.jmp_point
        } else {
            false
        }
    }

    /// Push entry to jump history
    fn push_jmp_history(&mut self, flags: u32, linked_regs: u64) -> Result<()> {
        if !self.jmp_history.push(
            self.env.insn_idx,
            self.env.prev_insn_idx,
            flags,
            linked_regs,
        ) {
            // History full - not an error, just can't track more
        }
        Ok(())
    }

    /// Check if current state was visited before
    /// 
    /// This implements the kernel's `is_state_visited()` integration with SCC tracking.
    /// When a new state is cached, we call `maybe_enter_scc()` to track SCC entry.
    /// When we find a loop (prune with pending branches), we add a backedge for
    /// precision propagation.
    fn check_state_visited(&mut self) -> Result<Option<StateVisitResult>> {
        let cur_state = match self.env.cur_state.as_ref() {
            Some(s) => s,
            None => return Ok(None),
        };

        // Create context for visit check
        let mut ctx = StateVisitContext::new();
        ctx.jmps_since_prune = self.jmps_processed - self.prev_jmps_processed;
        ctx.insns_since_prune = (self.env.insn_processed - self.prev_insn_processed) as u32;
        ctx.jmp_history_cnt = self.jmp_history.len() as u32;
        ctx.parent_state_id = self.cur_parent_id;

        // Check instruction type for special handling
        if let Some(insn) = self.env.insn(self.env.insn_idx) {
            let op = insn.code & 0xf0;
            ctx.is_iter_next = self.is_iter_next_insn(self.env.insn_idx);
            ctx.is_may_goto = op == BPF_JA && insn.src_reg == BPF_PSEUDO_CALL;
            ctx.is_callback_call = self.is_callback_call(self.env.insn_idx);
        }
        
        // Check if this is a force checkpoint (e.g., back edge)
        if let Some(aux) = self.env.insn_aux.get(self.env.insn_idx) {
            ctx.is_force_checkpoint = aux.force_prune_point;
        }

        // Clean stale states
        clean_live_states(&mut self.state_cache, self.env.insn_idx, cur_state);

        // Check for pruning
        let result = is_state_visited(
            &mut self.state_cache,
            self.env.insn_idx,
            cur_state,
            &mut ctx,
        )?;

        // Update prune point tracking and parent state ID based on result
        match &result {
            StateVisitResult::Explore(new_state_id) => {
                self.prev_jmps_processed = self.jmps_processed;
                self.prev_insn_processed = self.env.insn_processed;
                // Update current parent to the newly cached state
                self.cur_parent_id = Some(*new_state_id);
                
                // Enter SCC if this state is in a loop (SCC)
                // This tracks the entry state for later precision propagation
                self.scc_tracker.maybe_enter_scc(
                    cur_state,
                    *new_state_id,
                    &self.env.insn_aux,
                );
            }
            StateVisitResult::ExploreNoCache => {
                self.prev_jmps_processed = self.jmps_processed;
                self.prev_insn_processed = self.env.insn_processed;
            }
            StateVisitResult::Prune(matched_id) => {
                // Check if this is a loop (matched state has pending branches)
                let is_loop = self.state_cache.get_by_id(*matched_id)
                    .map(|cached| cached.branches > 0)
                    .unwrap_or(false);
                
                if is_loop {
                    // This is a backedge - add to SCC tracker for precision propagation
                    // The backedge state will be used later when the SCC is fully explored
                    let _ = self.scc_tracker.add_backedge(
                        cur_state,
                        *matched_id,
                        &self.env.insn_aux,
                    );
                }
                
                // Propagate precision from the matched state to current state
                if let Some(cached) = self.state_cache.get_by_id(*matched_id) {
                    if let Some(ref mut cur) = self.env.cur_state {
                        let _ = crate::analysis::prune::propagate_precision(cur, &cached.state);
                    }
                }
            }
            StateVisitResult::InfiniteLoop => {
                // Will be handled by caller
            }
        }

        Ok(Some(result))
    }

    /// Check if instruction is an iterator next call
    /// 
    /// Iterator next calls are marked in insn_aux during first pass analysis.
    /// These are critical for loop convergence detection.
    fn is_iter_next_insn(&self, insn_idx: usize) -> bool {
        // Check if insn_aux marks this as iter_next
        if let Some(aux) = self.env.insn_aux.get(insn_idx) {
            if aux.is_iter_next {
                return true;
            }
        }
        
        // Also check if this is a kfunc call to an iter_next function
        if let Some(insn) = self.env.insn(insn_idx) {
            // Check for BPF_CALL instruction with kfunc
            if insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_KFUNC_CALL {
                // The imm field contains the kfunc BTF ID
                // In a full implementation, we would look up the kfunc name
                // and check if it matches *_iter_next pattern
                if let Some(aux) = self.env.insn_aux.get(insn_idx) {
                    // Check if kfunc_btf_id indicates an iter_next
                    if aux.kfunc_btf_id > 0 {
                        // Would check kfunc name here - for now use the is_iter_next flag
                        return aux.is_iter_next;
                    }
                }
            }
        }
        
        false
    }

    /// Check if instruction is a callback call
    fn is_callback_call(&self, insn_idx: usize) -> bool {
        if let Some(aux) = self.env.insn_aux.get(insn_idx) {
            // Check if this call invokes a callback
            aux.call_target.is_some()
        } else {
            false
        }
    }

    /// Handle completion of a path (exit or prune)
    /// 
    /// This pops the next state from the exploration stack and sets up
    /// the verifier to continue from that point.
    fn handle_path_completion(&mut self) -> Result<bool> {
        // Pop next state from our stack first, then fall back to env's stack
        if let Some(elem) = self.pop_stack(false) {
            self.env.cur_state = Some(elem.state);
            self.env.insn_idx = elem.insn_idx;
            self.env.prev_insn_idx = elem.prev_insn_idx;
            self.cur_parent_id = elem.parent_id;
            
            log_branch(&mut self.env.log, elem.insn_idx, true, elem.insn_idx);
            
            // Reset jump history for new path
            self.jmp_history.clear();
            
            Ok(true)
        } else if let Some((state, idx)) = self.env.pop_state() {
            // Fall back to env's stack for backwards compatibility
            self.env.cur_state = Some(state);
            self.env.insn_idx = idx;
            self.cur_parent_id = None;
            
            log_branch(&mut self.env.log, idx, true, idx);
            
            // Reset jump history for new path
            self.jmp_history.clear();
            
            Ok(true)
        } else {
            // All paths explored
            Ok(false)
        }
    }

    /// Initialize register states for program entry
    fn init_regs(&self, state: &mut BpfVerifierState) -> Result<()> {
        let func = state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into()
        ))?;

        // R1 = context pointer (depends on program type)
        func.regs[1] = BpfRegState::new_ctx_ptr(self.env.prog_type);

        // R10 = frame pointer (read-only)
        func.regs[BPF_REG_FP] = BpfRegState::new_fp();

        // R0 and R2-R9 are not initialized
        // (R2-R5 might have arguments depending on program type)

        Ok(())
    }

    /// Verify a single instruction
    fn verify_insn(&mut self) -> Result<InsnResult> {
        let idx = self.env.insn_idx;
        let insn = self.env.insn(idx).ok_or(VerifierError::InvalidInsnIdx(idx))?;
        let insn = *insn;

        // Mark instruction as seen
        self.env.mark_insn_seen(idx);
        
        // Mark sanitization state for instruction
        let needs_nospec = self.env.needs_nospec(idx);
        if let Some(aux) = self.env.sanitize_aux.get_mut(idx) {
            sanitize_mark_insn_seen(aux, needs_nospec);
        }

        // Log instruction
        if let Some(ref state) = self.env.cur_state {
            log_insn(&mut self.env.log, &insn, idx, state);
        }

        // Get class and dispatch
        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => {
                self.check_alu(&insn)?;
                Ok(InsnResult::Continue)
            }
            BPF_LDX => {
                self.check_ldx(&insn)?;
                Ok(InsnResult::Continue)
            }
            BPF_STX => {
                self.check_stx(&insn)?;
                Ok(InsnResult::Continue)
            }
            BPF_ST => {
                self.check_st(&insn)?;
                Ok(InsnResult::Continue)
            }
            BPF_LD => {
                self.check_ld(&insn, idx)
            }
            BPF_JMP | BPF_JMP32 => {
                self.check_jmp(&insn, idx)
            }
            _ => {
                Err(VerifierError::InvalidInstruction(class as usize))
            }
        }
    }

    /// Check ALU instruction
    fn check_alu(&mut self, insn: &BpfInsn) -> Result<()> {
        // Check if this is pointer arithmetic that needs sanitization
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let op = insn.code & 0xf0;
        let is_add = op == BPF_ADD;
        let is_sub = op == BPF_SUB;
        let allow_ptr_leaks = self.env.allow_ptr_leaks;
        let insn_idx = self.env.insn_idx;
        
        // For pointer arithmetic, apply sanitization in unprivileged mode
        let mut needs_nospec_mark = false;
        if (is_add || is_sub) && sanitize_needed(allow_ptr_leaks) {
            if let Some(ref mut state) = self.env.cur_state {
                if let Some(dst) = state.reg(dst_reg) {
                    if dst.is_pointer() {
                        let sanitize_result = sanitize_ptr_alu(
                            state,
                            insn,
                            dst_reg,
                            src_reg,
                            is_add,
                            allow_ptr_leaks,
                        )?;
                        
                        // Mark instruction for nospec barrier if needed
                        if sanitize_result == SanitizeState::NeedsBarrier {
                            needs_nospec_mark = true;
                        }
                    }
                }
            }
        }
        
        if needs_nospec_mark {
            self.env.mark_nospec(insn_idx);
        }
        
        // Perform the actual ALU operation check
        if let Some(ref mut state) = self.env.cur_state {
            check_alu_op(state, insn, allow_ptr_leaks)
        } else {
            Err(VerifierError::Internal("no state".into()))
        }
    }

    /// Check LDX (load from memory) instruction
    fn check_ldx(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow of state
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        let src_reg = insn.src_reg as usize;
        let dst_reg = insn.dst_reg as usize;
        let off = insn.off as i32;
        let size = bpf_size_to_bytes(insn.size());
        let is_ldsx = insn.mode() == BPF_MEMSX;

        // Check source register (must be pointer)
        let src = state.reg(src_reg).ok_or(
            VerifierError::InvalidRegister(src_reg as u8)
        )?.clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check memory access with user memory context
        check_mem_access_with_ctx(state, &src, off, size, false, allow_ptr_leaks, &user_ctx)?;

        // Sanitization check for potential speculative access
        if sanitize_needed(self.env.allow_ptr_leaks) {
            sanitize_check_bounds(state, &src, off, size)?;
        }

        // Set destination register based on load
        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
            dst.reg_type = BpfRegType::ScalarValue;
            
            // Set bounds based on load size
            let size_bits = match size {
                1 => 8,
                2 => 16,
                4 => 32,
                8 => 64,
                _ => 64,
            };
            
            if is_ldsx {
                // Sign-extended load - result is signed
                match size_bits {
                    8 => {
                        dst.smin_value = i8::MIN as i64;
                        dst.smax_value = i8::MAX as i64;
                        dst.umin_value = 0;
                        dst.umax_value = u64::MAX; // Sign extension can produce any value
                    }
                    16 => {
                        dst.smin_value = i16::MIN as i64;
                        dst.smax_value = i16::MAX as i64;
                        dst.umin_value = 0;
                        dst.umax_value = u64::MAX;
                    }
                    32 => {
                        dst.smin_value = i32::MIN as i64;
                        dst.smax_value = i32::MAX as i64;
                        dst.umin_value = 0;
                        dst.umax_value = u64::MAX;
                    }
                    _ => {
                        // 64-bit - full range
                    }
                }
            } else {
                // Zero-extended load - result is unsigned within size
                match size_bits {
                    8 => {
                        dst.umin_value = 0;
                        dst.umax_value = u8::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u8::MAX as i64;
                    }
                    16 => {
                        dst.umin_value = 0;
                        dst.umax_value = u16::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u16::MAX as i64;
                    }
                    32 => {
                        dst.umin_value = 0;
                        dst.umax_value = u32::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u32::MAX as i64;
                    }
                    _ => {
                        // 64-bit - full range
                    }
                }
            }
            
            // Sync 32-bit bounds
            dst.u32_min_value = dst.umin_value as u32;
            dst.u32_max_value = dst.umax_value.min(u32::MAX as u64) as u32;
            dst.s32_min_value = dst.smin_value.max(i32::MIN as i64) as i32;
            dst.s32_max_value = dst.smax_value.min(i32::MAX as i64) as i32;
        }

        Ok(())
    }

    /// Check STX (store to memory) instruction
    fn check_stx(&mut self, insn: &BpfInsn) -> Result<()> {
        // Check for atomic operations first (uses separate path)
        if insn.mode() == BPF_ATOMIC {
            return self.check_atomic(insn);
        }

        // Extract user memory context before mutable borrow of state
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let off = insn.off as i32;
        let size = bpf_size_to_bytes(insn.size());

        // Check destination (must be pointer)
        let dst = state.reg(dst_reg).ok_or(
            VerifierError::InvalidRegister(dst_reg as u8)
        )?.clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check source register
        let src = state.reg(src_reg).ok_or(
            VerifierError::InvalidRegister(src_reg as u8)
        )?;

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check memory access with user memory context
        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        Ok(())
    }

    /// Check ST (store immediate) instruction
    fn check_st(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow of state
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        let dst_reg = insn.dst_reg as usize;
        let off = insn.off as i32;
        let size = bpf_size_to_bytes(insn.size());

        // Check destination (must be pointer)
        let dst = state.reg(dst_reg).ok_or(
            VerifierError::InvalidRegister(dst_reg as u8)
        )?.clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check memory access with user memory context
        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        Ok(())
    }

    /// Check LD instruction (including LD_IMM64, LD_ABS, LD_IND)
    fn check_ld(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        let mode = insn.mode();
        
        match mode {
            BPF_IMM => {
                // LD_IMM64 is a two-instruction sequence
                if insn.code != (BPF_LD | BPF_IMM | BPF_DW) {
                    return Err(VerifierError::InvalidInstruction(idx));
                }
                
                let next_idx = idx + 1;
                let next_insn = *self.env.insn(next_idx).ok_or(
                    VerifierError::InvalidInsnIdx(next_idx)
                )?;

                if let Some(ref mut state) = self.env.cur_state {
                    check_ld_imm64(state, insn, &next_insn)?;
                }

                // Skip the next instruction (it's part of LD_IMM64)
                self.env.insn_idx += 1;
                Ok(InsnResult::Continue)
            }
            BPF_ABS | BPF_IND => {
                // Legacy packet access (LD_ABS/LD_IND)
                // These are only allowed in specific program types (socket filters, etc.)
                self.check_ld_abs_ind(insn, mode == BPF_IND)?;
                Ok(InsnResult::Continue)
            }
            _ => {
                Err(VerifierError::InvalidInstruction(idx))
            }
        }
    }

    /// Check LD_ABS/LD_IND instruction (legacy packet access)
    fn check_ld_abs_ind(&mut self, insn: &BpfInsn, is_indirect: bool) -> Result<()> {
        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // Check program type allows legacy packet access
        if !self.env.prog_type.allows_legacy_pkt_access() {
            return Err(VerifierError::InvalidMemoryAccess(
                "LD_ABS/LD_IND not allowed for this program type".into()
            ));
        }

        // For LD_IND, check source register
        if is_indirect {
            let src_reg = insn.src_reg as usize;
            let src = state.reg(src_reg).ok_or(
                VerifierError::InvalidRegister(src_reg as u8)
            )?;
            
            if src.reg_type == BpfRegType::NotInit {
                return Err(VerifierError::UninitializedRegister(src_reg as u8));
            }
            
            // Source must be a scalar for offset calculation
            if src.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::InvalidMemoryAccess(
                    "LD_IND offset must be scalar".into()
                ));
            }
        }

        // Result goes to R0
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_unknown(false);
            r0.reg_type = BpfRegType::ScalarValue;
        }

        // R1-R5 are clobbered by LD_ABS/LD_IND
        for reg_idx in 1..=5 {
            if let Some(reg) = state.reg_mut(reg_idx) {
                reg.mark_not_init(false);
            }
        }

        Ok(())
    }

    /// Check JMP instruction
    fn check_jmp(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        let op = insn.code & 0xf0;

        // Check for may_goto instruction first (has special opcode)
        if is_may_goto_insn(insn) {
            return self.check_may_goto_insn(insn, idx);
        }

        match op {
            BPF_JA => {
                // Check for indirect jump (BPF_JA | BPF_X)
                if is_indirect_jump(insn) {
                    return self.check_indirect_jmp(insn, idx);
                }
                // Unconditional jump
                let target = (idx as i32 + insn.off as i32 + 1) as usize;
                self.check_jump_target(target)?;
                Ok(InsnResult::Jump(target))
            }
            BPF_EXIT => {
                // Process exit - this implements process_bpf_exit_full
                self.process_bpf_exit(false)
            }
            BPF_CALL => {
                self.check_call_insn(insn, idx)
            }
            _ => {
                // Conditional jump
                self.check_cond_jmp(insn, idx)
            }
        }
    }

    /// Check indirect jump instruction (BPF_JA | BPF_X)
    /// 
    /// Indirect jumps use R0 to determine the jump offset dynamically.
    /// The verifier must explore all possible targets within R0's bounds.
    fn check_indirect_jmp(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        // Validate reserved fields
        check_indirect_jump_fields(insn, idx)?;
        
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?;
        
        // Get R0 state for bounds checking
        let r0 = state.reg(BPF_REG_0).ok_or(
            VerifierError::InvalidRegister(BPF_REG_0 as u8)
        )?;
        
        // Check indirect jump and get all possible targets
        let result = check_indirect_jump(r0, idx, self.env.prog_len())?;
        
        // Validate none of the targets land in LD_IMM64 continuation
        validate_indirect_jump_targets(&result.targets, &self.env.insns)?;
        
        // Mark all targets as prune points
        for &target in &result.targets {
            if let Some(aux) = self.env.insn_aux.get_mut(target) {
                aux.prune_point = true;
                aux.jmp_point = true;
            }
        }
        
        // If only one target, treat as unconditional jump
        if result.targets.len() == 1 {
            return Ok(InsnResult::Jump(result.targets[0]));
        }
        
        // Multiple targets - push all but first onto stack
        for &target in result.targets.iter().skip(1) {
            self.push_stack(target, idx, false)?;
            if let Some(ref mut state) = self.env.cur_state {
                state.branches += 1;
            }
        }
        
        self.jmps_processed += 1;
        
        // Continue with first target
        Ok(InsnResult::Jump(result.targets[0]))
    }

    /// Check may_goto instruction
    /// 
    /// may_goto provides bounded loop support. It's like a conditional jump
    /// that can be taken up to MAX_MAY_GOTO_DEPTH times, after which it 
    /// must fall through.
    fn check_may_goto_insn(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        // Check if may_goto is allowed
        if !self.env.caps.may_goto {
            return Err(VerifierError::InvalidInstruction(idx));
        }

        // Check may_goto using the jump module
        let result = check_may_goto(insn, idx, self.env.prog_len(), &self.may_goto_state)?;
        
        // Update verifier state's may_goto_depth
        if let Some(ref mut state) = self.env.cur_state {
            state.may_goto_depth = self.may_goto_state.depth;
        }

        if result.can_take_goto && result.can_fall_through {
            // Both paths possible - this is a branch
            // Push state for the goto branch (with incremented depth)
            let mut goto_state = self.env.cur_state.as_ref().ok_or(
                VerifierError::Internal("no state".into())
            )?.clone();
            
            // Increment may_goto depth for the taken branch
            goto_state.may_goto_depth += 1;
            
            // Push goto branch onto stack
            let mut elem = StackElem::new(goto_state, result.goto_target, idx);
            elem.log_pos = self.env.log.len();
            elem.parent_id = self.cur_parent_id;
            
            if self.stack.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
                return Err(VerifierError::TooComplex(
                    format!("jump sequence of {} is too complex", self.stack.len())
                ));
            }
            
            self.stack.push(elem);
            self.max_stack_depth = self.max_stack_depth.max(self.stack.len());
            
            // Increment branch count
            if let Some(ref mut state) = self.env.cur_state {
                state.branches += 1;
            }
            
            self.jmps_processed += 1;
            
            // Continue with fall-through (loop exit)
            Ok(InsnResult::Jump(result.fall_through))
        } else if result.can_take_goto {
            // Only goto is possible (shouldn't happen normally)
            self.may_goto_state.increment_depth();
            if let Some(ref mut state) = self.env.cur_state {
                state.may_goto_depth = self.may_goto_state.depth;
            }
            self.jmps_processed += 1;
            Ok(InsnResult::Jump(result.goto_target))
        } else {
            // Only fall-through (max depth reached)
            // This ensures loop termination
            Ok(InsnResult::Jump(result.fall_through))
        }
    }

    /// Process BPF exit instruction
    /// 
    /// This implements the kernel's `process_bpf_exit_full()` function.
    /// It handles:
    /// 1. Resource leak checking
    /// 2. Nested function exit (return from subprogram)
    /// 3. Return code validation for main program exit
    fn process_bpf_exit(&mut self, exception_exit: bool) -> Result<InsnResult> {
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state at exit".into())
        )?;

        // Check for resource leaks before exit
        // Must be done before prepare_func_exit for callbacks
        let is_main_exit = state.curframe == 0;
        self.check_resource_leak(exception_exit, is_main_exit)?;

        // For exception exits (bpf_throw), skip return code checks
        if exception_exit {
            return Ok(InsnResult::Exit);
        }

        // Check if we're in a nested function (subprogram)
        if state.curframe > 0 {
            // Validate subprogram return value
            let r0 = state.reg(BPF_REG_0).ok_or(
                VerifierError::Internal("no R0".into())
            )?;
            self.check_subprog_return(r0)?;
            
            // Exit from nested function - prepare return
            return Ok(InsnResult::Return);
        }

        // Main program exit - check return code
        self.check_return_code()?;

        Ok(InsnResult::Exit)
    }

    /// Check for resource leaks at exit
    fn check_resource_leak(&self, exception_exit: bool, is_main_exit: bool) -> Result<()> {
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // Check for unreleased references
        state.check_resource_leak()?;

        // For main program exit, additional checks
        if is_main_exit && !exception_exit {
            // Check for held locks
            if state.refs.active_locks > 0 {
                return Err(VerifierError::InvalidLock(
                    "BPF_EXIT with unreleased lock".into()
                ));
            }

            // Check for active RCU read lock
            if state.refs.active_rcu_locks > 0 {
                return Err(VerifierError::InvalidLock(
                    "BPF_EXIT with active RCU read lock".into()
                ));
            }

            // Check for active preempt disable
            if state.refs.active_preempt_locks > 0 {
                return Err(VerifierError::InvalidLock(
                    "BPF_EXIT with active preempt disable".into()
                ));
            }

            // Check for active IRQ flags
            if state.refs.active_irq_id != 0 {
                return Err(VerifierError::InvalidIrq(
                    "BPF_EXIT with unreleased IRQ flags".into()
                ));
            }
        }

        Ok(())
    }

    /// Check return code at main program exit
    fn check_return_code(&self) -> Result<()> {
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // R0 must be initialized
        let r0 = state.reg(BPF_REG_0).ok_or(
            VerifierError::Internal("no R0".into())
        )?;

        if r0.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(0));
        }

        // R0 must be a scalar (not a pointer)
        if r0.is_pointer() && !self.env.allow_ptr_leaks {
            return Err(VerifierError::InvalidReturnValue(
                "R0 leaks pointer at exit".into()
            ));
        }

        // Program-type specific return code checks
        self.check_return_code_for_prog_type(r0)?;

        Ok(())
    }

    /// Check return code is valid for the program type
    fn check_return_code_for_prog_type(&self, r0: &BpfRegState) -> Result<()> {
        // Get the valid return value range for this program type
        let range = self.get_retval_range();
        
        // If no range restriction, allow any return value
        if range.is_none() {
            return Ok(());
        }
        
        let (min_val, max_val) = match range {
            Some(r) => r,
            None => return Ok(()), // No range restriction
        };
        
        // Check if R0's bounds are within the valid range
        self.check_retval_in_range(r0, min_val, max_val)
    }
    
    /// Get the valid return value range for this program type
    /// 
    /// Returns None if any return value is allowed, Some((min, max)) for a range
    fn get_retval_range(&self) -> Option<(i64, i64)> {
        match self.env.prog_type {
            // XDP programs must return XDP action (0-4)
            // XDP_ABORTED=0, XDP_DROP=1, XDP_PASS=2, XDP_TX=3, XDP_REDIRECT=4
            BpfProgType::Xdp => Some((0, 4)),
            
            // Cgroup socket programs return 0 or 1
            BpfProgType::CgroupSock => Some((0, 1)),
            
            // Cgroup sock addr programs - depends on attach type
            // For bind: 0-3, for others: 0-1 or 1
            BpfProgType::CgroupSockAddr => {
                // Default to 0-1, specific attach types may vary
                Some((0, 1))
            }
            
            // Cgroup SKB - egress can return 0-3
            BpfProgType::CgroupSkb => Some((0, 3)),
            
            // Cgroup device programs return 0 or 1
            BpfProgType::CgroupDevice => Some((0, 1)),
            
            // Cgroup sysctl programs return 0 or 1
            BpfProgType::CgroupSysctl => Some((0, 1)),
            
            // Cgroup sockopt programs return 0 or 1
            BpfProgType::CgroupSockopt => Some((0, 1)),
            
            // Sock ops programs return 0 or 1
            BpfProgType::SockOps => Some((0, 1)),
            
            // SK lookup programs return SK_DROP(0) or SK_PASS(1)
            BpfProgType::SkLookup => Some((0, 1)),
            
            // Tracing programs - depends on attach type
            BpfProgType::Tracing => {
                // FENTRY/FEXIT should return 0
                // MODIFY_RETURN can return any value
                // For now, no restriction
                None
            }
            
            // LSM programs - typically 0 for allow, negative for deny
            // Actual range depends on the hook
            BpfProgType::Lsm => None,
            
            // Struct ops - depends on the operator
            BpfProgType::StructOps => None,
            
            // Raw tracepoint with BTF should return 0
            BpfProgType::RawTracepoint => {
                // If attached to BTF, return 0
                // Otherwise, no restriction
                None
            }
            
            // Kprobe session programs return 0 or 1
            BpfProgType::Kprobe => None,
            
            // Socket filter, TC, etc - no specific range
            _ => None,
        }
    }
    
    /// Check if return value is within the valid range
    fn check_retval_in_range(&self, r0: &BpfRegState, min_val: i64, max_val: i64) -> Result<()> {
        // For constant values, check exactly
        if r0.is_const() {
            let val = r0.const_value() as i64;
            if val < min_val || val > max_val {
                return Err(VerifierError::InvalidReturnValue(
                    format!("return value {} not in range [{}, {}]", val, min_val, max_val)
                ));
            }
            return Ok(());
        }
        
        // For variable values, check if the possible range overlaps
        // with the valid range
        let r0_min = r0.smin_value;
        let r0_max = r0.smax_value;
        
        // If the register's range is entirely outside the valid range, it's an error
        if r0_min > max_val || r0_max < min_val {
            return Err(VerifierError::InvalidReturnValue(
                format!("return value range [{}, {}] outside valid range [{}, {}]",
                    r0_min, r0_max, min_val, max_val)
            ));
        }
        
        // If the register might have values outside the valid range,
        // we should ideally reject in unprivileged mode
        if r0_min < min_val || r0_max > max_val {
            // In privileged mode, we might allow this with a warning
            // In unprivileged mode, we should be strict
            if !self.env.caps.bounded_loops {
                // Unprivileged mode - be strict
                return Err(VerifierError::InvalidReturnValue(
                    format!("return value range [{}, {}] may exceed valid range [{}, {}]",
                        r0_min, r0_max, min_val, max_val)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Check return value for async callback
    /// 
    /// Async callbacks (timer, workqueue, etc.) have specific return value requirements.
    fn check_async_callback_return(&self, r0: &BpfRegState, expected_range: (i64, i64)) -> Result<()> {
        self.check_retval_in_range(r0, expected_range.0, expected_range.1)
    }
    
    /// Check return value for subprogram
    fn check_subprog_return(&self, r0: &BpfRegState) -> Result<()> {
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?;
        
        // Check if current subprogram is an async callback
        if let Some(subprog) = self.env.subprogs.get(state.curframe) {
            if subprog.is_async_cb {
                // Async callbacks typically expect return value 0 (success) or 1 (reschedule)
                return self.check_async_callback_return(r0, (0, 1));
            }
        }
        
        // Regular subprograms should return scalar values
        if r0.reg_type != BpfRegType::ScalarValue && r0.reg_type != BpfRegType::NotInit {
            // Allow PTR types only if they're acquired references that will be returned
            if !r0.is_pointer() || r0.ref_obj_id == 0 {
                return Err(VerifierError::InvalidReturnValue(
                    format!("subprogram must return scalar, got {:?}", r0.reg_type)
                ));
            }
        }
        Ok(())
    }

    /// Check conditional jump
    fn check_cond_jmp(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // Mark precision for registers used in conditional jump
        // This is critical for state pruning correctness
        mark_jmp_precision(state, &self.env.insns, insn)?;

        let (path1, path2) = check_cond_jmp_op(state, insn, idx, self.env.allow_ptr_leaks)?;

        match (path1, path2) {
            (Some(target), None) => {
                // Only one path (branch is always/never taken)
                self.check_jump_target(target)?;
                Ok(InsnResult::Jump(target))
            }
            (Some(fall), Some(target)) => {
                // Both paths possible
                self.check_jump_target(target)?;
                self.check_jump_target(fall)?;
                Ok(InsnResult::Branch(fall, target))
            }
            _ => {
                Err(VerifierError::Internal("invalid branch result".into()))
            }
        }
    }

    /// Split state for conditional branch and apply constraints to both paths.
    ///
    /// This implements the kernel's logic for refining register bounds
    /// on both the true (taken) and false (fall-through) branches.
    ///
    /// For example, for `if r1 > 10 goto target`:
    /// - Fall-through path: r1 <= 10 (branch not taken)
    /// - Target path: r1 > 10 (branch taken)
    fn split_branch_states(
        &mut self,
        insn: &BpfInsn,
        _fall_through: usize,
        target: usize,
    ) -> Result<()> {
        use crate::bounds::range_refine::{BranchCond, refine_reg_const, refine_regs};
        
        let op = insn.code & 0xf0;
        let src_type = insn.code & 0x08;
        let dst_reg = insn.dst_reg as usize;
        let is_32bit = insn.class() == BPF_JMP32;

        // Clone current state for the target (taken) branch
        let mut target_state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?.clone();

        // Get source value for comparison
        let src_val = if src_type == BPF_X {
            // Register source - get from current state
            let cur_state = self.env.cur_state.as_ref().ok_or_else(|| {
                VerifierError::Internal("no current state".into())
            })?;
            cur_state.reg(insn.src_reg as usize).cloned()
        } else {
            // Immediate source
            let mut reg = BpfRegState::new_scalar_unknown(false);
            if is_32bit {
                reg.mark_known(insn.imm as u32 as u64);
            } else {
                reg.mark_known(insn.imm as i64 as u64);
            }
            Some(reg)
        };

        let src_state = match src_val {
            Some(s) => s,
            None => {
                // Can't refine without source
                self.push_stack(target, self.env.insn_idx, false)?;
                if let Some(ref mut state) = self.env.cur_state {
                    state.branches += 1;
                }
                return Ok(());
            }
        };

        // Get branch condition
        let cond = match BranchCond::from_opcode(op) {
            Some(c) => c,
            None => {
                // Unknown condition, can't refine
                self.push_stack(target, self.env.insn_idx, false)?;
                if let Some(ref mut state) = self.env.cur_state {
                    state.branches += 1;
                }
                return Ok(());
            }
        };

        // Apply constraints to both branches
        // Current state becomes fall-through (branch NOT taken)
        // Target state becomes taken (branch IS taken)
        
        if let Some(ref mut cur_state) = self.env.cur_state {
            // Check if both registers are scalars for refinement
            let dst_is_scalar = cur_state.reg(dst_reg)
                .map(|r| r.reg_type == BpfRegType::ScalarValue)
                .unwrap_or(false);
            let src_is_scalar = src_state.reg_type == BpfRegType::ScalarValue;

            if dst_is_scalar && src_is_scalar {
                // Refine fall-through state (branch NOT taken)
                // Use negated condition
                let neg_cond = cond.negate();
                
                if src_type == BPF_K {
                    // Immediate comparison - refine just dst register
                    let src_val = src_state.const_value();
                    if let Some(dst) = cur_state.reg_mut(dst_reg) {
                        let result = refine_reg_const(dst, src_val, neg_cond, true);
                        result.apply_to(dst);
                        if is_32bit {
                            dst.sync_bounds();
                        }
                    }
                    
                    // Refine target state (branch taken)
                    if let Some(dst) = target_state.reg_mut(dst_reg) {
                        let result = refine_reg_const(dst, src_val, cond, true);
                        result.apply_to(dst);
                        if is_32bit {
                            dst.sync_bounds();
                        }
                    }
                } else {
                    // Register comparison - refine both registers on both paths
                    let src_reg = insn.src_reg as usize;
                    
                    // Fall-through: apply negated condition
                    if let (Some(dst), Some(src)) = (
                        cur_state.reg(dst_reg).cloned(),
                        cur_state.reg(src_reg).cloned()
                    ) {
                        let (new_dst, new_src) = refine_regs(&dst, &src, neg_cond, is_32bit);
                        if let Some(d) = cur_state.reg_mut(dst_reg) {
                            new_dst.apply_to(d);
                        }
                        if let Some(s) = cur_state.reg_mut(src_reg) {
                            new_src.apply_to(s);
                        }
                    }
                    
                    // Target: apply original condition  
                    if let (Some(dst), Some(src)) = (
                        target_state.reg(dst_reg).cloned(),
                        target_state.reg(src_reg).cloned()
                    ) {
                        let (new_dst, new_src) = refine_regs(&dst, &src, cond, is_32bit);
                        if let Some(d) = target_state.reg_mut(dst_reg) {
                            new_dst.apply_to(d);
                        }
                        if let Some(s) = target_state.reg_mut(src_reg) {
                            new_src.apply_to(s);
                        }
                    }
                }
            }
            
            // Increment branch count
            cur_state.branches += 1;
        }

        // Handle PTR_MAYBE_NULL refinement for pointer comparisons
        // Done outside the borrow to avoid borrow checker issues
        if let Some(ref mut cur_state) = self.env.cur_state {
            Self::refine_ptr_null_check_static(cur_state, &mut target_state, insn, cond);
        }

        // Push target state with refined constraints
        let mut elem = StackElem::new(target_state, target, self.env.insn_idx);
        elem.log_pos = self.env.log.len();
        elem.parent_id = self.cur_parent_id;
        
        if self.stack.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
            return Err(VerifierError::TooComplex(
                format!("jump sequence of {} is too complex", self.stack.len())
            ));
        }
        
        self.stack.push(elem);
        self.max_stack_depth = self.max_stack_depth.max(self.stack.len());

        Ok(())
    }

    /// Refine PTR_MAYBE_NULL pointers based on NULL check (static version)
    fn refine_ptr_null_check_static(
        false_state: &mut BpfVerifierState,
        true_state: &mut BpfVerifierState,
        insn: &BpfInsn,
        cond: crate::bounds::range_refine::BranchCond,
    ) {
        use crate::bounds::range_refine::BranchCond;
        
        let dst_reg = insn.dst_reg as usize;
        let src_type = insn.code & 0x08;
        
        // Only handle JEQ/JNE with immediate 0 or register comparison
        if cond != BranchCond::Eq && cond != BranchCond::Ne {
            return;
        }
        
        // Check if comparing with NULL (0)
        let comparing_with_null = if src_type == BPF_K {
            insn.imm == 0
        } else {
            let src_reg = insn.src_reg as usize;
            false_state.reg(src_reg)
                .map(|r| r.is_const() && r.const_value() == 0)
                .unwrap_or(false)
        };
        
        if !comparing_with_null {
            return;
        }
        
        // Check if dst is PTR_MAYBE_NULL
        let dst_maybe_null = false_state.reg(dst_reg)
            .map(|r| r.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL))
            .unwrap_or(false);
        
        if !dst_maybe_null {
            return;
        }
        
        // Get the pointer ID for tracking across all registers
        let ptr_id = false_state.reg(dst_reg).map(|r| r.id).unwrap_or(0);
        
        if cond == BranchCond::Eq {
            // if (ptr == NULL) goto target
            // true_state: ptr IS NULL -> mark as scalar 0
            // false_state: ptr is NOT NULL -> clear PTR_MAYBE_NULL
            Self::mark_ptr_or_null_in_state_static(true_state, ptr_id, true);
            Self::mark_ptr_or_null_in_state_static(false_state, ptr_id, false);
        } else {
            // if (ptr != NULL) goto target  
            // true_state: ptr is NOT NULL -> clear PTR_MAYBE_NULL
            // false_state: ptr IS NULL -> mark as scalar 0
            Self::mark_ptr_or_null_in_state_static(true_state, ptr_id, false);
            Self::mark_ptr_or_null_in_state_static(false_state, ptr_id, true);
        }
    }

    /// Mark pointer as NULL or not-NULL in a state (static version)
    fn mark_ptr_or_null_in_state_static(
        state: &mut BpfVerifierState,
        id: u32,
        is_null: bool,
    ) {
        if id == 0 {
            return;
        }
        
        // Iterate through all frames and registers
        for frame_idx in 0..=state.curframe {
            if let Some(Some(func)) = state.frame.get_mut(frame_idx) {
                // Check all registers
                for reg in &mut func.regs {
                    if reg.id == id && reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                        if is_null {
                            // Pointer is NULL - convert to scalar 0
                            reg.reg_type = BpfRegType::ScalarValue;
                            reg.mark_known(0);
                            reg.id = 0;
                            reg.ref_obj_id = 0;
                        } else {
                            // Pointer is NOT NULL - clear the maybe-null flag
                            reg.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
                            // Keep the ID for spin_lock tracking, clear for others
                            if !reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) {
                                reg.id = 0;
                            }
                        }
                    }
                }
                
                // Also check spilled registers on stack
                for slot in &mut func.stack.stack {
                    if slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill {
                        let spilled = &mut slot.spilled_ptr;
                        if spilled.id == id && spilled.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                            if is_null {
                                spilled.reg_type = BpfRegType::ScalarValue;
                                spilled.mark_known(0);
                                spilled.id = 0;
                                spilled.ref_obj_id = 0;
                            } else {
                                spilled.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
                                if !spilled.type_flags.contains(BpfTypeFlag::MEM_ALLOC) {
                                    spilled.id = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check jump target is valid
    fn check_jump_target(&self, target: usize) -> Result<()> {
        if target >= self.env.prog_len() {
            return Err(VerifierError::JumpOutOfRange(target, self.env.prog_len()));
        }

        // Check we're not jumping into a LD_IMM64 continuation
        if target > 0 {
            if let Some(prev) = self.env.insn(target - 1) {
                if prev.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    return Err(VerifierError::InvalidJumpTarget(target));
                }
            }
        }

        Ok(())
    }

    /// Check call instruction
    fn check_call_insn(&mut self, insn: &BpfInsn, idx: usize) -> Result<InsnResult> {
        if insn.is_pseudo_call() {
            // Subprogram call
            let target = (idx as i32 + insn.imm + 1) as usize;
            self.check_jump_target(target)?;
            
            // Record in jump history
            self.push_jmp_history(jmp_flags::CALL, 0)?;
            
            Ok(InsnResult::Call(target))
        } else if insn.is_kfunc_call() {
            // Kfunc call - may return Exit for bpf_throw
            self.check_kfunc_call(insn)
        } else {
            // Helper function call
            self.check_helper_call(insn, idx)?;
            Ok(InsnResult::Continue)
        }
    }

    /// Check helper function call with full validation
    /// 
    /// This validates BPF helper calls including:
    /// - Argument type checking
    /// - User memory access validation
    /// - Reference tracking
    /// - Return value setup
    fn check_helper_call(&mut self, insn: &BpfInsn, idx: usize) -> Result<()> {
        let func_id = BpfFuncId::from_imm(insn.imm);
        
        // Get user memory context for this instruction
        let user_ctx = self.env.user_mem_context_for_insn(idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;
        let id_gen = &mut self.env.id_gen;
        
        // Get mutable access to state (which contains the reference manager)
        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;
        
        // Use the comprehensive helper call checker with user memory validation
        check_helper_call_with_ctx(
            state,
            id_gen,
            func_id,
            idx,
            allow_ptr_leaks,
            &user_ctx,
        )?;
        
        Ok(())
    }

    /// Check kfunc call
    /// 
    /// This implements the kernel's `check_kfunc_call()` with full validation:
    /// - Look up kfunc in registry
    /// - Validate arguments based on kfunc prototype
    /// - Handle acquire/release semantics
    /// - Handle bpf_throw for exception support
    /// - Set return value appropriately
    fn check_kfunc_call(&mut self, insn: &BpfInsn) -> Result<InsnResult> {
        let insn_idx = self.env.insn_idx;
        let btf_id = insn.imm as u32;
        
        // Check for bpf_throw kfunc (exception handling)
        if is_bpf_throw_kfunc(insn.imm, insn.off) {
            return self.handle_bpf_throw(insn);
        }
        
        // Look up kfunc in registry
        let desc = self.kfunc_registry.find_by_id(btf_id);
        
        if let Some(desc) = desc {
            // Check program type compatibility
            if !desc.is_allowed_for_prog_type(self.env.prog_type) {
                return Err(VerifierError::InvalidKfunc(
                    format!("kfunc {} not allowed for program type {:?}", 
                        desc.name, self.env.prog_type)
                ));
            }
            
            // Check sleepable compatibility
            if desc.flags.sleepable && !self.env.prog_sleepable {
                return Err(VerifierError::InvalidKfunc(
                    format!("sleepable kfunc {} called from non-sleepable program", desc.name)
                ));
            }
            
            // Perform full kfunc argument validation
            let state = self.env.cur_state.as_mut().ok_or(
                VerifierError::Internal("no state".into())
            )?;
            
            let meta = check_kfunc_call(
                state,
                &self.kfunc_registry,
                insn,
                insn_idx,
            )?;
            
            // Handle RCU lock acquire/release
            // Note: need to re-borrow state after check_kfunc_call
            let state = self.env.cur_state.as_mut().ok_or(
                VerifierError::Internal("no state".into())
            )?;
            
            if desc.name == "bpf_rcu_read_lock" {
                state.refs.active_rcu_locks += 1;
            } else if desc.name == "bpf_rcu_read_unlock" {
                if state.refs.active_rcu_locks == 0 {
                    return Err(VerifierError::InvalidLock(
                        "bpf_rcu_read_unlock without matching lock".into()
                    ));
                }
                state.refs.active_rcu_locks -= 1;
            }
            
            // Mark kfunc BTF ID in instruction aux for later use
            if let Some(aux) = self.env.insn_aux.get_mut(insn_idx) {
                aux.kfunc_btf_id = btf_id;
                
                // Mark as iter_next if applicable
                if desc.name.ends_with("_iter_next") || desc.name.contains("iter_next") {
                    aux.is_iter_next = true;
                }
            }
            
            // Record reference acquisition if applicable
            if meta.ref_obj_id != 0 {
                // Reference was acquired - tracked in meta
            }
        } else {
            // Unknown kfunc - do basic validation only
            let state = self.env.cur_state.as_mut().ok_or(
                VerifierError::Internal("no state".into())
            )?;
            
            // Check that R1-R5 are initialized (if used)
            for regno in 1..=5 {
                if let Some(reg) = state.reg(regno) {
                    if reg.reg_type == BpfRegType::NotInit {
                        // Uninitialized is OK for unused args
                    }
                }
            }
            
            // Clear caller-saved registers and set unknown return
            state.clear_caller_saved_regs();
            if let Some(r0) = state.reg_mut(BPF_REG_0) {
                r0.mark_unknown(false);
            }
        }
        
        Ok(InsnResult::Continue)
    }
    
    /// Handle bpf_throw kfunc call
    /// 
    /// bpf_throw terminates the current execution path and transfers
    /// control to the exception callback (if registered) or aborts.
    fn handle_bpf_throw(&mut self, _insn: &BpfInsn) -> Result<InsnResult> {
        let state = self.env.cur_state.as_ref().ok_or(
            VerifierError::Internal("no state".into())
        )?;
        
        // bpf_throw(u64 cookie) - R1 contains the cookie value
        // Validate bpf_throw preconditions with cookie in R1
        validate_bpf_throw(state, &self.exception_state, BPF_REG_1)?;
        
        // Check if we have an exception callback registered
        if let Some(callback_subprog) = self.env.exception_callback_subprog {
            // Get callback info
            if let Some(callback) = self.exception_state.callbacks.values().next() {
                // Set up state for exception callback
                if let Some(ref mut state) = self.env.cur_state {
                    setup_exception_callback_state(state, callback)?;
                }
                
                // Jump to exception callback
                let callback_insn = self.env.subprogs.get(callback_subprog)
                    .map(|s| s.start)
                    .unwrap_or(0);
                    
                return Ok(InsnResult::Jump(callback_insn));
            }
        }
        
        // No exception callback - this is an exception exit
        // The program will abort; treat as normal exit for verification
        Ok(InsnResult::Exit)
    }

    /// Check atomic operation
    fn check_atomic(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow of state
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let off = insn.off as i32;
        let size = bpf_size_to_bytes(insn.size());

        // Get destination register state
        let dst = state.reg(dst_reg).ok_or(
            VerifierError::InvalidRegister(dst_reg as u8)
        )?.clone();

        // Check memory access (both read and write for atomic) with user memory context
        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        // Handle fetch operations
        let atomic_op = insn.imm as u32;
        if atomic_op & BPF_FETCH != 0 {
            // Result is stored in src_reg
            if let Some(src) = state.reg_mut(src_reg) {
                src.mark_unknown(false);
            }
        }

        // CMPXCHG stores result in R0
        if atomic_op == BPF_CMPXCHG {
            if let Some(r0) = state.reg_mut(BPF_REG_0) {
                r0.mark_unknown(false);
            }
        }

        Ok(())
    }

    /// Handle subprogram call
    fn handle_call(&mut self, target: usize) -> Result<()> {
        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // Push new frame
        state.push_frame(self.env.insn_idx as i32, 0)?;

        // Jump to target
        self.env.insn_idx = target;

        Ok(())
    }

    /// Handle return from subprogram
    fn handle_return(&mut self) -> Result<()> {
        let state = self.env.cur_state.as_mut().ok_or(
            VerifierError::Internal("no state".into())
        )?;

        // Get callsite before popping
        let callsite = state.cur_func()
            .ok_or(VerifierError::Internal("no current function".into()))?
            .callsite;

        // Pop frame
        state.pop_frame()?;

        // Record in jump history
        self.push_jmp_history(jmp_flags::RET, 0)?;

        // Return to instruction after call
        self.env.insn_idx = (callsite + 1) as usize;

        Ok(())
    }

    /// Check if an error is recoverable with nospec barrier
    /// 
    /// Some errors during speculative execution can be recovered from by
    /// inserting a nospec barrier. This corresponds to the kernel's
    /// `error_recoverable_with_nospec()` function.
    /// 
    /// Recoverable errors include:
    /// - Out of bounds memory access that might be speculative
    /// - Invalid pointer arithmetic that might be speculative
    fn is_recoverable_with_nospec(&self, err: &VerifierError) -> bool {
        // Only recover if we're in unprivileged mode (need sanitization)
        if self.env.allow_ptr_leaks {
            return false;
        }
        
        match err {
            // Out of bounds memory access - could be speculative
            VerifierError::InvalidMemoryAccess(_) => true,
            // Invalid pointer arithmetic - could be speculative
            VerifierError::InvalidPointerArithmetic(_) => true,
            // Other errors are not recoverable
            _ => false,
        }
    }
}

/// Verify a program using the main verification loop
pub fn verify_program(
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let mut env = VerifierEnv::new(insns, prog_type, allow_ptr_leaks)?;
    
    // Mark prune points
    mark_prune_points(&mut env);
    
    let mut verifier = MainVerifier::new(&mut env);
    verifier.verify()
}

/// Mark instructions as prune points
///
/// Prune points are locations where we check for state equivalence.
/// Good prune points are:
/// - Back edges (loop headers)
/// - Join points (targets of multiple branches)
/// - After calls
fn mark_prune_points(env: &mut VerifierEnv) {
    // Mark all jump targets as prune points
    for (idx, insn) in env.insns.iter().enumerate() {
        let class = insn.class();
        
        match class {
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;
                
                // Mark jump targets
                if op == BPF_JA || (op != BPF_EXIT && op != BPF_CALL) {
                    let target = (idx as i32 + insn.off as i32 + 1) as usize;
                    if target < env.insn_aux.len() {
                        env.insn_aux[target].prune_point = true;
                        env.insn_aux[target].jmp_point = true;
                    }
                }
                
                // Also mark instruction after call as prune point
                if op == BPF_CALL && idx + 1 < env.insn_aux.len() {
                    env.insn_aux[idx + 1].prune_point = true;
                }
            }
            _ => {}
        }
    }
    
    // Mark first instruction as prune point
    if !env.insn_aux.is_empty() {
        env.insn_aux[0].prune_point = true;
    }
}
