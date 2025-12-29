// SPDX-License-Identifier: GPL-2.0

//! Generic main verifier with platform abstraction.
//!
//! This module provides a platform-generic version of the main verifier
//! that uses the [`PlatformSpec`] trait for platform-specific operations.

use alloc::{boxed::Box, format, string::String, vec::Vec};

use crate::platform::{PlatformSpec, ProgTypeProvider};
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::verifier_state::BpfVerifierState;

use super::generic_env::GenericVerifierEnv;
use super::main_loop::{StackElem, InsnResult, BPF_COMPLEXITY_LIMIT_JMP_SEQ};
use crate::analysis::prune::{JmpHistory, SccTracker, StateCache, StateId};
use crate::check::callback::CallbackState;
use crate::check::jump::MayGotoState;
use crate::check::kfunc::KfuncRegistry;
use crate::special::exception::ExceptionState;

/// Generic main verifier parameterized by platform.
///
/// This is the platform-generic version of [`MainVerifier`] that uses
/// the [`PlatformSpec`] trait for all platform-specific operations.
///
/// # Type Parameters
///
/// * `P` - The platform specification implementing [`PlatformSpec`]
///
/// # Example
///
/// ```ignore
/// use bpf_verifier_core::verifier::{GenericVerifierEnv, GenericMainVerifier};
/// use bpf_verifier_linux::LinuxSpec;
///
/// let platform = LinuxSpec::new();
/// let insns = vec![/* BPF instructions */];
/// let mut env = GenericVerifierEnv::new(platform, insns, 6, false)?;
/// let mut verifier = GenericMainVerifier::new(&mut env);
/// verifier.verify()?;
/// ```
pub struct GenericMainVerifier<'a, P: PlatformSpec> {
    /// Verifier environment
    pub env: &'a mut GenericVerifierEnv<P>,
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
    /// Exploration stack
    pub stack: Vec<StackElem>,
    /// Current parent state ID in state cache
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

impl<'a, P: PlatformSpec> GenericMainVerifier<'a, P> {
    /// Create a new generic main verifier.
    pub fn new(env: &'a mut GenericVerifierEnv<P>) -> Self {
        let mut kfunc_registry = KfuncRegistry::new();
        kfunc_registry.register_common();

        Self {
            env,
            state_cache: StateCache::new(),
            scc_tracker: SccTracker::new(),
            jmp_history: JmpHistory::new(64),
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

    /// Run the main verification loop.
    ///
    /// This is the entry point for program verification.
    pub fn verify(&mut self) -> Result<()> {
        // Validate program type using platform
        self.check_prog_type()?;

        // Initialize verification state
        self.init_verification()?;

        // Run the main verification loop
        self.do_check()?;

        // Post-verification checks
        self.post_verify()?;

        Ok(())
    }

    /// Check that the program type is valid for this platform.
    fn check_prog_type(&self) -> Result<()> {
        let prog_type = self.env.prog_type;
        
        if !self.env.platform().prog_type().is_valid(prog_type) {
            return Err(VerifierError::InvalidProgramType(
                format!("program type {} not supported by platform '{}'", 
                        prog_type, self.env.platform().name())
            ));
        }

        Ok(())
    }

    /// Initialize verification state.
    fn init_verification(&mut self) -> Result<()> {
        // Create initial state
        let init_state = BpfVerifierState::new();
        
        // Note: R1 (context pointer) and R10 (frame pointer) are initialized
        // by default in BpfFuncState::new(). The ctx_size from platform is
        // used during context access validation, not initialization.

        // Set as current state
        self.env.cur_state = Some(Box::new(init_state));

        Ok(())
    }

    /// Main verification loop.
    fn do_check(&mut self) -> Result<()> {
        let prog_len = self.env.prog_len();
        
        while self.env.insn_idx < prog_len {
            // Check complexity limits
            self.env.count_insn()?;

            // Get current instruction
            let insn = self.env.insn(self.env.insn_idx)
                .ok_or_else(|| VerifierError::Internal("invalid insn_idx".into()))?
                .clone();

            // Mark instruction as seen
            self.env.mark_insn_seen(self.env.insn_idx);

            // Process the instruction
            let result = self.do_check_insn(&insn)?;

            // Handle the result
            match result {
                InsnResult::Continue => {
                    self.env.prev_insn_idx = self.env.insn_idx;
                    self.env.insn_idx += 1;
                }
                InsnResult::Jump(target) => {
                    self.env.prev_insn_idx = self.env.insn_idx;
                    self.env.insn_idx = target;
                }
                InsnResult::Branch(fall_through, target) => {
                    // Push the fall-through path for later
                    self.push_stack(fall_through, self.env.insn_idx, false)?;
                    // Continue with the taken branch
                    self.env.prev_insn_idx = self.env.insn_idx;
                    self.env.insn_idx = target;
                }
                InsnResult::Exit => {
                    // Try to pop a state to continue exploring
                    if let Some(elem) = self.pop_stack() {
                        self.restore_state(elem)?;
                    } else {
                        // No more states to explore, we're done
                        break;
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

    /// Process a single instruction.
    fn do_check_insn(&mut self, insn: &BpfInsn) -> Result<InsnResult> {
        let class = insn.code & 0x07;

        match class {
            BPF_ALU | BPF_ALU64 => self.check_alu(insn),
            BPF_LDX => self.check_ldx(insn),
            BPF_STX | BPF_ST => self.check_stx(insn),
            BPF_LD => self.check_ld(insn),
            BPF_JMP | BPF_JMP32 => self.check_jmp(insn),
            _ => Err(VerifierError::InvalidInstruction(self.env.insn_idx)),
        }
    }

    /// Check ALU instruction.
    fn check_alu(&mut self, _insn: &BpfInsn) -> Result<InsnResult> {
        // Delegate to existing ALU check logic
        // This would be updated to use platform traits if needed
        Ok(InsnResult::Continue)
    }

    /// Check LDX instruction.
    fn check_ldx(&mut self, _insn: &BpfInsn) -> Result<InsnResult> {
        Ok(InsnResult::Continue)
    }

    /// Check STX/ST instruction.
    fn check_stx(&mut self, _insn: &BpfInsn) -> Result<InsnResult> {
        Ok(InsnResult::Continue)
    }

    /// Check LD instruction.
    fn check_ld(&mut self, _insn: &BpfInsn) -> Result<InsnResult> {
        Ok(InsnResult::Continue)
    }

    /// Check JMP instruction.
    fn check_jmp(&mut self, insn: &BpfInsn) -> Result<InsnResult> {
        let op = insn.code & 0xf0;

        match op {
            BPF_EXIT => {
                // Validate return value using platform
                self.check_return_value()?;
                Ok(InsnResult::Exit)
            }
            BPF_CALL => {
                self.check_call(insn)
            }
            BPF_JA => {
                let target = (self.env.insn_idx as i32 + 1 + insn.off as i32) as usize;
                Ok(InsnResult::Jump(target))
            }
            _ => {
                // Conditional jump
                let target = (self.env.insn_idx as i32 + 1 + insn.off as i32) as usize;
                let fall_through = self.env.insn_idx + 1;
                Ok(InsnResult::Branch(fall_through, target))
            }
        }
    }

    /// Check CALL instruction using platform helpers.
    fn check_call(&mut self, insn: &BpfInsn) -> Result<InsnResult> {
        let src = insn.src_reg;

        if src == BPF_PSEUDO_CALL as u8 {
            // Subprogram call
            let target = (self.env.insn_idx as i32 + 1 + insn.imm) as usize;
            Ok(InsnResult::Call(target))
        } else if src == BPF_PSEUDO_KFUNC_CALL as u8 {
            // Kfunc call - use platform kfunc provider
            self.check_kfunc_call(insn)?;
            Ok(InsnResult::Continue)
        } else {
            // Helper call - use platform helper provider
            self.check_helper_call(insn)?;
            Ok(InsnResult::Continue)
        }
    }

    /// Check helper call using platform's helper provider.
    fn check_helper_call(&mut self, insn: &BpfInsn) -> Result<()> {
        let func_id = insn.imm as u32;

        // Look up helper using platform
        let _helper = self.env.lookup_helper(func_id)
            .ok_or_else(|| VerifierError::UnknownHelper(func_id))?;

        // Check if helper is allowed for this program type
        if !self.env.is_helper_allowed(func_id) {
            return Err(VerifierError::HelperNotAllowedForProgType {
                helper_id: func_id,
                prog_type: self.env.prog_type,
            });
        }

        // TODO: Validate arguments using helper.arg_types
        // TODO: Apply return type effects

        Ok(())
    }

    /// Check kfunc call using platform's kfunc provider.
    fn check_kfunc_call(&mut self, insn: &BpfInsn) -> Result<()> {
        let btf_id = insn.imm as u32;

        // Look up kfunc using platform
        let _kfunc = self.env.lookup_kfunc(btf_id)
            .ok_or_else(|| VerifierError::UnknownKfunc(btf_id))?;

        // Check if kfunc is allowed for this program type
        if !self.env.is_kfunc_allowed(btf_id) {
            return Err(VerifierError::KfuncNotAllowedForProgType {
                kfunc_id: btf_id,
                prog_type: self.env.prog_type,
            });
        }

        // TODO: Validate arguments and apply effects

        Ok(())
    }

    /// Check return value using platform's program type provider.
    fn check_return_value(&self) -> Result<()> {
        // Get R0 value and validate against platform's return range
        if let Some(ref state) = self.env.cur_state {
            // Access registers through the current frame
            if let Some(ref frame) = state.frame[state.curframe] {
                let _r0 = &frame.regs[BPF_REG_0];
                
                // If R0 is a known scalar, validate the range
                // For now, just check if platform allows this return
                // Full implementation would check the actual scalar bounds
            }
        }
        Ok(())
    }

    /// Push a state onto the exploration stack.
    fn push_stack(
        &mut self,
        insn_idx: usize,
        prev_insn_idx: usize,
        speculative: bool,
    ) -> Result<usize> {
        let cur_state = self.env.cur_state.as_ref()
            .ok_or(VerifierError::Internal("no current state".into()))?;

        let mut elem = StackElem::new(cur_state.clone_boxed(), insn_idx, prev_insn_idx);
        elem.parent_id = self.cur_parent_id;

        if speculative {
            elem.state.speculative = true;
        }

        if self.stack.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
            return Err(VerifierError::TooComplex(
                format!("jump sequence of {} is too complex", self.stack.len())
            ));
        }

        self.stack.push(elem);
        self.max_stack_depth = self.max_stack_depth.max(self.stack.len());
        
        Ok(self.stack.len() - 1)
    }

    /// Pop a state from the exploration stack.
    fn pop_stack(&mut self) -> Option<StackElem> {
        self.stack.pop()
    }

    /// Restore state from a stack element.
    fn restore_state(&mut self, elem: StackElem) -> Result<()> {
        self.env.cur_state = Some(elem.state);
        self.env.insn_idx = elem.insn_idx;
        self.env.prev_insn_idx = elem.prev_insn_idx;
        self.cur_parent_id = elem.parent_id;
        Ok(())
    }

    /// Handle subprogram call.
    fn handle_call(&mut self, target: usize) -> Result<()> {
        // Save return address and jump to target
        self.env.prev_insn_idx = self.env.insn_idx;
        self.env.insn_idx = target;
        Ok(())
    }

    /// Handle return from subprogram.
    fn handle_return(&mut self) -> Result<()> {
        // Pop and restore state
        if let Some(elem) = self.pop_stack() {
            self.restore_state(elem)?;
        }
        Ok(())
    }

    /// Post-verification checks.
    fn post_verify(&mut self) -> Result<()> {
        // Check that all instructions were verified
        // Check reference leaks, etc.
        Ok(())
    }

    /// Get verification statistics.
    pub fn stats(&self) -> VerificationStats {
        VerificationStats {
            insn_processed: self.env.insn_processed,
            peak_states: self.env.peak_states,
            total_states: self.env.total_states,
            max_stack_depth: self.max_stack_depth,
        }
    }
}

/// Verification statistics.
#[derive(Debug, Clone, Default)]
pub struct VerificationStats {
    /// Number of instructions processed
    pub insn_processed: usize,
    /// Peak number of states on the stack
    pub peak_states: usize,
    /// Total states explored
    pub total_states: usize,
    /// Maximum stack depth reached
    pub max_stack_depth: usize,
}

/// Error types for helper verification
#[derive(Debug, Clone)]
pub struct HelperVerificationError {
    /// Helper function ID
    pub helper_id: u32,
    /// Error message
    pub message: String,
}

#[cfg(test)]
mod tests {
    // Tests would go here
}
