// SPDX-License-Identifier: GPL-2.0

//! Worklist-based verifier implementation.
//!
//! This module provides an advanced verifier that uses worklist-based
//! exploration with integrated state merging and range refinement.

use crate::core::error::{Result, VerifierError};
use crate::core::insn::{check_alu_op, check_call, check_exit, check_ld_imm64};
use crate::core::log::{log_branch, log_insn};
use crate::core::types::*;
use crate::mem::memory::check_mem_access_with_ctx;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

use super::branch_state::{handle_null_check, process_conditional_branch, BranchStateResult};
use super::env::VerifierEnv;
use super::limits::{LimitChecker, ResourceLimits};
use super::worklist::{ExplorationStrategy, JoinPointDetector, Worklist, WorklistStats};

/// Result of verifying an instruction.
#[derive(Debug, Clone)]
pub enum VerifyResult {
    /// Continue to next instruction.
    Continue,
    /// Jump to a specific instruction.
    Jump(usize),
    /// Conditional branch with refined states.
    Branch(BranchStateResult, usize, usize),
    /// Program exits.
    Exit,
    /// Call to subprogram.
    Call(usize),
    /// Return from subprogram.
    Return,
}

/// Worklist-based verifier.
pub struct WorklistVerifier<'a> {
    /// Verifier environment.
    env: &'a mut VerifierEnv,
    /// Worklist for path exploration.
    worklist: Worklist,
    /// Join point detector.
    join_points: JoinPointDetector,
    /// Current verification state.
    cur_state: Option<BpfVerifierState>,
    /// Current instruction index.
    cur_idx: usize,
    /// Resource limit checker.
    limit_checker: LimitChecker,
}

impl<'a> WorklistVerifier<'a> {
    /// Create a new worklist verifier.
    pub fn new(env: &'a mut VerifierEnv) -> Self {
        Self::with_limits(env, ResourceLimits::default())
    }

    /// Create a new worklist verifier with custom resource limits.
    pub fn with_limits(env: &'a mut VerifierEnv, limits: ResourceLimits) -> Self {
        // Pre-analyze program for join points
        let join_points = JoinPointDetector::analyze_program(&env.insns);

        Self {
            env,
            worklist: Worklist::with_strategy(ExplorationStrategy::DepthFirst),
            join_points,
            cur_state: None,
            cur_idx: 0,
            limit_checker: LimitChecker::new(limits),
        }
    }

    /// Set maximum instructions to process.
    pub fn set_max_insns(&mut self, max: u64) {
        let limits = ResourceLimits::default().with_max_complexity(max);
        self.limit_checker = LimitChecker::new(limits);
    }

    /// Get the limit checker.
    pub fn limit_checker(&self) -> &LimitChecker {
        &self.limit_checker
    }

    /// Run the verification.
    pub fn verify(&mut self) -> Result<()> {
        // Initialize limit checker and validate initial constraints
        self.limit_checker.start();
        self.limit_checker.set_insn_count(self.env.prog_len())?;
        self.limit_checker
            .set_subprog_count(self.env.subprog_count())?;

        // Initialize state
        let mut initial_state = BpfVerifierState::new();
        self.init_regs(&mut initial_state)?;

        // Start at instruction 0
        self.worklist.push(0, initial_state);

        // Main verification loop
        while let Some(item) = self.worklist.pop() {
            self.worklist.record_processed();
            self.cur_idx = item.insn_idx;
            self.cur_state = Some(item.state);

            // Check complexity limit and time
            self.limit_checker.check_insn_processed()?;

            // Try to prune this path
            if let Some(ref state) = self.cur_state {
                if self.worklist.try_prune(self.cur_idx, state) {
                    continue;
                }
            }

            // Check for join point - try to merge
            if self.join_points.is_join_point(self.cur_idx) {
                self.worklist.record_join_point();
                if let Some(ref state) = self.cur_state {
                    if let Some(merged) = self.worklist.try_merge_at_join(self.cur_idx, state) {
                        self.cur_state = Some(merged);
                    }
                }
            }

            // Process instruction
            let result = self.verify_insn()?;

            // Save state for pruning
            if let Some(ref state) = self.cur_state {
                self.worklist.save_explored(self.cur_idx, state.clone());
            }

            // Handle result
            match result {
                VerifyResult::Continue => {
                    let next_idx = self.cur_idx + 1;
                    if next_idx >= self.env.prog_len() {
                        return Err(VerifierError::FallThroughExit);
                    }
                    if let Some(state) = self.cur_state.take() {
                        self.worklist.push_with_parent(
                            next_idx,
                            state,
                            self.cur_idx,
                            item.depth + 1,
                        );
                    }
                }
                VerifyResult::Jump(target) => {
                    if let Some(state) = self.cur_state.take() {
                        self.worklist
                            .push_with_parent(target, state, self.cur_idx, item.depth + 1);
                    }
                }
                VerifyResult::Branch(branch_result, fall_through, target) => {
                    // Push both paths with refined states
                    if let Some(taken_state) = branch_result.taken_state {
                        self.worklist.push_with_parent(
                            target,
                            taken_state,
                            self.cur_idx,
                            item.depth + 1,
                        );
                        log_branch(&mut self.env.log, self.cur_idx, true, target);
                    }
                    if let Some(fallthrough_state) = branch_result.fallthrough_state {
                        self.worklist.push_with_parent(
                            fall_through,
                            fallthrough_state,
                            self.cur_idx,
                            item.depth + 1,
                        );
                        log_branch(&mut self.env.log, self.cur_idx, false, fall_through);
                    }
                }
                VerifyResult::Exit => {
                    // Path complete - continue with other paths
                }
                VerifyResult::Call(target) => {
                    self.handle_call(target)?;
                    if let Some(state) = self.cur_state.take() {
                        self.worklist
                            .push_with_parent(target, state, self.cur_idx, item.depth + 1);
                    }
                }
                VerifyResult::Return => {
                    self.handle_return()?;
                    if let Some(state) = self.cur_state.take() {
                        // Return to instruction after call
                        let return_idx = self.cur_idx + 1;
                        self.worklist.push_with_parent(
                            return_idx,
                            state,
                            self.cur_idx,
                            item.depth + 1,
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Get worklist statistics.
    pub fn stats(&self) -> &WorklistStats {
        self.worklist.stats()
    }

    /// Initialize register states.
    fn init_regs(&self, state: &mut BpfVerifierState) -> Result<()> {
        let func = state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        // R1 = context pointer
        func.regs[1] = BpfRegState::new_ctx_ptr(self.env.prog_type);

        // R10 = frame pointer (read-only)
        func.regs[BPF_REG_FP] = BpfRegState::new_fp();

        Ok(())
    }

    /// Verify a single instruction.
    fn verify_insn(&mut self) -> Result<VerifyResult> {
        let idx = self.cur_idx;
        let insn = self
            .env
            .insn(idx)
            .ok_or(VerifierError::InvalidInsnIdx(idx))?;
        let insn = *insn;

        // Mark instruction as seen
        self.env.mark_insn_seen(idx);

        // Log instruction
        if let Some(ref state) = self.cur_state {
            log_insn(&mut self.env.log, &insn, idx, state);
        }

        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => {
                self.check_alu(&insn)?;
                Ok(VerifyResult::Continue)
            }
            BPF_LDX => {
                self.check_ldx(&insn)?;
                Ok(VerifyResult::Continue)
            }
            BPF_STX => {
                self.check_stx(&insn)?;
                Ok(VerifyResult::Continue)
            }
            BPF_ST => {
                self.check_st(&insn)?;
                Ok(VerifyResult::Continue)
            }
            BPF_LD => self.check_ld(&insn, idx),
            BPF_JMP | BPF_JMP32 => self.check_jmp(&insn, idx),
            _ => Err(VerifierError::InvalidInstruction(class as usize)),
        }
    }

    /// Check ALU instruction.
    fn check_alu(&mut self, insn: &BpfInsn) -> Result<()> {
        if let Some(ref mut state) = self.cur_state {
            check_alu_op(state, insn, self.env.allow_ptr_leaks)
        } else {
            Err(VerifierError::Internal("no state".into()))
        }
    }

    /// Check LDX instruction.
    fn check_ldx(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let src_reg = insn.src_reg as usize;
        let dst_reg = insn.dst_reg as usize;
        let off = insn.off as i32;
        let size = insn.size() as u32;

        let src = state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
            .clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        check_mem_access_with_ctx(state, &src, off, size, false, allow_ptr_leaks, &user_ctx)?;

        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
        }

        Ok(())
    }

    /// Check STX instruction.
    fn check_stx(&mut self, insn: &BpfInsn) -> Result<()> {
        // Check for atomic operations first (uses separate path)
        if insn.mode() == BPF_ATOMIC {
            return self.check_atomic(insn);
        }

        // Extract user memory context before mutable borrow
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let off = insn.off as i32;
        let size = insn.size() as u32;

        let dst = state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        let src = state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        Ok(())
    }

    /// Check ST instruction.
    fn check_st(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let dst_reg = insn.dst_reg as usize;
        let off = insn.off as i32;
        let size = insn.size() as u32;

        let dst = state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        Ok(())
    }

    /// Check LD instruction.
    fn check_ld(&mut self, insn: &BpfInsn, idx: usize) -> Result<VerifyResult> {
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            let next_idx = idx + 1;
            let next_insn = *self
                .env
                .insn(next_idx)
                .ok_or(VerifierError::InvalidInsnIdx(next_idx))?;

            if let Some(ref mut state) = self.cur_state {
                check_ld_imm64(state, insn, &next_insn)?;
            }

            // Skip the continuation instruction - push idx+2 directly
            if let Some(state) = self.cur_state.take() {
                self.worklist.push(idx + 2, state);
            }
            // Return Exit to avoid double-pushing
            Ok(VerifyResult::Exit)
        } else {
            Err(VerifierError::InvalidInstruction(idx))
        }
    }

    /// Check JMP instruction.
    fn check_jmp(&mut self, insn: &BpfInsn, idx: usize) -> Result<VerifyResult> {
        let op = insn.code & 0xf0;

        match op {
            BPF_JA => {
                let target = (idx as i32 + insn.off as i32 + 1) as usize;
                self.check_jump_target(target)?;
                Ok(VerifyResult::Jump(target))
            }
            BPF_EXIT => {
                if let Some(ref state) = self.cur_state {
                    check_exit(state)?;
                }
                Ok(VerifyResult::Exit)
            }
            BPF_CALL => self.check_call_insn(insn, idx),
            _ => self.check_cond_jmp(insn, idx),
        }
    }

    /// Check conditional jump with range refinement.
    fn check_cond_jmp(&mut self, insn: &BpfInsn, idx: usize) -> Result<VerifyResult> {
        let state = self
            .cur_state
            .as_ref()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let fall_through = idx + 1;
        let target = (idx as i32 + insn.off as i32 + 1) as usize;

        self.check_jump_target(target)?;
        self.check_jump_target(fall_through)?;

        // Use range refinement to get precise states for each branch
        let branch_result = process_conditional_branch(state, insn);

        // Handle NULL checks specially
        if let Some(mut taken) = branch_result.taken_state.clone() {
            handle_null_check(&mut taken, insn, true);
        }
        if let Some(mut fallthrough) = branch_result.fallthrough_state.clone() {
            handle_null_check(&mut fallthrough, insn, false);
        }

        Ok(VerifyResult::Branch(branch_result, fall_through, target))
    }

    /// Check jump target validity.
    fn check_jump_target(&self, target: usize) -> Result<()> {
        if target >= self.env.prog_len() {
            return Err(VerifierError::JumpOutOfRange(target, self.env.prog_len()));
        }

        if target > 0 {
            if let Some(prev) = self.env.insn(target - 1) {
                if prev.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    return Err(VerifierError::InvalidJumpTarget(target));
                }
            }
        }

        Ok(())
    }

    /// Check call instruction.
    fn check_call_insn(&mut self, insn: &BpfInsn, idx: usize) -> Result<VerifyResult> {
        if insn.is_pseudo_call() {
            let target = (idx as i32 + insn.imm + 1) as usize;
            self.check_jump_target(target)?;
            Ok(VerifyResult::Call(target))
        } else if insn.is_kfunc_call() {
            self.check_kfunc_call(insn)?;
            Ok(VerifyResult::Continue)
        } else {
            if let Some(ref mut state) = self.cur_state {
                check_call(state, insn, idx)?;
            }
            Ok(VerifyResult::Continue)
        }
    }

    /// Check kfunc call.
    fn check_kfunc_call(&mut self, _insn: &BpfInsn) -> Result<()> {
        if let Some(ref mut state) = self.cur_state {
            state.clear_caller_saved_regs();
            if let Some(r0) = state.reg_mut(BPF_REG_0) {
                r0.mark_unknown(false);
            }
        }
        Ok(())
    }

    /// Check atomic operation.
    fn check_atomic(&mut self, insn: &BpfInsn) -> Result<()> {
        // Extract user memory context before mutable borrow
        let user_ctx = self.env.user_mem_context_for_insn(self.env.insn_idx);
        let allow_ptr_leaks = self.env.allow_ptr_leaks;

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let off = insn.off as i32;
        let size = insn.size() as u32;

        let dst = state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        check_mem_access_with_ctx(state, &dst, off, size, true, allow_ptr_leaks, &user_ctx)?;

        let atomic_op = insn.imm as u32;
        if atomic_op & BPF_FETCH != 0 {
            if let Some(src) = state.reg_mut(src_reg) {
                src.mark_unknown(false);
            }
        }

        if atomic_op == BPF_CMPXCHG {
            if let Some(r0) = state.reg_mut(BPF_REG_0) {
                r0.mark_unknown(false);
            }
        }

        Ok(())
    }

    /// Handle subprogram call.
    fn handle_call(&mut self, _target: usize) -> Result<()> {
        // Check call depth limit
        self.limit_checker.check_call_enter()?;

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        state.push_frame(self.cur_idx as i32, 0)?;
        Ok(())
    }

    /// Handle return from subprogram.
    fn handle_return(&mut self) -> Result<()> {
        // Record call exit for limit tracking
        self.limit_checker.record_call_exit();

        let state = self
            .cur_state
            .as_mut()
            .ok_or(VerifierError::Internal("no state".into()))?;

        let callsite = state
            .cur_func()
            .ok_or(VerifierError::Internal("no current function".into()))?
            .callsite;

        state.pop_frame()?;
        self.cur_idx = callsite as usize;
        Ok(())
    }

    /// Get a summary of resource usage.
    pub fn resource_summary(&self) -> super::limits::ResourceSummary {
        self.limit_checker.summary()
    }
}
