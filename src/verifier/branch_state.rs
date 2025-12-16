//!

//! This module integrates range refinement into the verification process,

//! propagating refined register bounds to both taken and not-taken branches.



use alloc::vec::Vec;

use crate::bounds::range_refine::{
    BranchCond, BranchOutcome,
    determine_branch_outcome, refine_reg_const, refine_reg_reg,
};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Result of processing a conditional branch.
#[derive(Debug, Clone)]
pub struct BranchStateResult {
    /// State for the taken branch (if reachable).
    pub taken_state: Option<BpfVerifierState>,
    /// State for the not-taken branch (if reachable).
    pub fallthrough_state: Option<BpfVerifierState>,
    /// Whether the taken branch is statically determined to be reachable.
    pub taken_reachable: bool,
    /// Whether the fallthrough is statically determined to be reachable.
    pub fallthrough_reachable: bool,
}

impl BranchStateResult {
    /// Both branches are reachable.
    pub fn both(taken: BpfVerifierState, fallthrough: BpfVerifierState) -> Self {
        Self {
            taken_state: Some(taken),
            fallthrough_state: Some(fallthrough),
            taken_reachable: true,
            fallthrough_reachable: true,
        }
    }

    /// Only taken branch is reachable.
    pub fn taken_only(taken: BpfVerifierState) -> Self {
        Self {
            taken_state: Some(taken),
            fallthrough_state: None,
            taken_reachable: true,
            fallthrough_reachable: false,
        }
    }

    /// Only fallthrough is reachable.
    pub fn fallthrough_only(fallthrough: BpfVerifierState) -> Self {
        Self {
            taken_state: None,
            fallthrough_state: Some(fallthrough),
            taken_reachable: false,
            fallthrough_reachable: true,
        }
    }
}

/// Process a conditional branch and produce refined states for both paths.
pub fn process_conditional_branch(
    state: &BpfVerifierState,
    insn: &BpfInsn,
) -> BranchStateResult {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let is_32bit = insn.class() == BPF_JMP32;

    // Get the branch condition
    let cond = match BranchCond::from_opcode(op) {
        Some(c) => c,
        None => {
            // Unknown condition - return both branches without refinement
            return BranchStateResult::both(state.clone(), state.clone());
        }
    };

    // Get destination register
    let dst = match state.reg(dst_reg) {
        Some(r) => r.clone(),
        None => return BranchStateResult::both(state.clone(), state.clone()),
    };

    // Get source value or register
    let (src_const, src_reg_state) = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        match state.reg(src_reg) {
            Some(r) => (None, Some(r.clone())),
            None => return BranchStateResult::both(state.clone(), state.clone()),
        }
    } else {
        let val = if is_32bit {
            insn.imm as u32 as u64
        } else {
            insn.imm as i64 as u64
        };
        (Some(val), None)
    };

    // Determine if branch outcome is statically known
    let outcome = if let Some(val) = src_const {
        determine_branch_outcome(&dst, val, cond)
    } else {
        BranchOutcome::Unknown
    };

    match outcome {
        BranchOutcome::AlwaysTaken => {
            let mut taken = state.clone();
            apply_refinements(&mut taken, dst_reg, &dst, src_const, src_reg_state.as_ref(), insn.src_reg as usize, cond, true);
            BranchStateResult::taken_only(taken)
        }
        BranchOutcome::NeverTaken => {
            let mut fallthrough = state.clone();
            apply_refinements(&mut fallthrough, dst_reg, &dst, src_const, src_reg_state.as_ref(), insn.src_reg as usize, cond, false);
            BranchStateResult::fallthrough_only(fallthrough)
        }
        BranchOutcome::Unknown => {
            let mut taken = state.clone();
            let mut fallthrough = state.clone();

            apply_refinements(&mut taken, dst_reg, &dst, src_const, src_reg_state.as_ref(), insn.src_reg as usize, cond, true);
            apply_refinements(&mut fallthrough, dst_reg, &dst, src_const, src_reg_state.as_ref(), insn.src_reg as usize, cond, false);

            BranchStateResult::both(taken, fallthrough)
        }
    }
}

/// Apply range refinements to a state based on branch outcome.
fn apply_refinements(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    dst: &BpfRegState,
    src_const: Option<u64>,
    src_reg: Option<&BpfRegState>,
    src_reg_idx: usize,
    cond: BranchCond,
    branch_taken: bool,
) {
    if let Some(val) = src_const {
        // Register vs constant comparison
        let result = refine_reg_const(dst, val, cond, branch_taken);
        if result.refined {
            if let Some(reg) = state.reg_mut(dst_reg) {
                result.apply_to(reg);
            }
        }
    } else if let Some(src) = src_reg {
        // Register vs register comparison
        let (dst_result, src_result) = refine_reg_reg(dst, src, cond, branch_taken);

        if dst_result.refined {
            if let Some(reg) = state.reg_mut(dst_reg) {
                dst_result.apply_to(reg);
            }
        }
        if src_result.refined {
            if let Some(reg) = state.reg_mut(src_reg_idx) {
                src_result.apply_to(reg);
            }
        }
    }
}

/// Check if a NULL check pattern is detected and handle it.
/// This handles both immediate comparisons (ptr == 0) and register comparisons.
pub fn handle_null_check(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    branch_taken: bool,
) -> bool {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Case 1: Comparison with immediate 0 (most common NULL check)
    if src_type == BPF_K && insn.imm == 0 {
        return handle_null_check_imm(state, dst_reg, op, branch_taken);
    }

    // Case 2: Register comparison where one side is known to be 0 (NULL)
    if src_type == BPF_X {
        return handle_null_check_reg(state, dst_reg, src_reg, op, branch_taken);
    }

    false
}

/// Handle NULL check with immediate 0
fn handle_null_check_imm(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    op: u8,
    branch_taken: bool,
) -> bool {
    let dst = match state.reg(dst_reg) {
        Some(r) => r,
        None => return false,
    };

    // Only handle pointers with PTR_MAYBE_NULL
    if !dst.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
        return false;
    }

    match op {
        BPF_JEQ => {
            // if (ptr == 0) { /* ptr is NULL here */ } else { /* ptr is non-NULL */ }
            if let Some(reg) = state.reg_mut(dst_reg) {
                if branch_taken {
                    // Taken means ptr is NULL
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                } else {
                    // Not taken means ptr is non-NULL
                    reg.mark_ptr_not_null();
                }
            }
            true
        }
        BPF_JNE => {
            // if (ptr != 0) { /* ptr is non-NULL here */ } else { /* ptr is NULL */ }
            if let Some(reg) = state.reg_mut(dst_reg) {
                if branch_taken {
                    // Taken means ptr is non-NULL
                    reg.mark_ptr_not_null();
                } else {
                    // Not taken means ptr is NULL
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                }
            }
            true
        }
        // Also handle JGT/JGE/JLT/JLE with 0 for pointer bounds
        BPF_JGT => {
            // if (ptr > 0) - ptr is non-NULL when taken
            if let Some(reg) = state.reg_mut(dst_reg) {
                if branch_taken {
                    reg.mark_ptr_not_null();
                }
                // Not taken: ptr <= 0, for unsigned means ptr == 0
                else {
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                }
            }
            true
        }
        _ => false,
    }
}

/// Handle NULL check with register comparison
fn handle_null_check_reg(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    src_reg: usize,
    op: u8,
    branch_taken: bool,
) -> bool {
    let dst = state.reg(dst_reg);
    let src = state.reg(src_reg);

    let (dst, src) = match (dst, src) {
        (Some(d), Some(s)) => (d.clone(), s.clone()),
        _ => return false,
    };

    // Check if either register is a known NULL (scalar with value 0)
    let dst_is_null = dst.reg_type == BpfRegType::ScalarValue && dst.is_const() && dst.const_value() == 0;
    let src_is_null = src.reg_type == BpfRegType::ScalarValue && src.is_const() && src.const_value() == 0;

    // Check if either side has PTR_MAYBE_NULL
    let dst_maybe_null = dst.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL);
    let src_maybe_null = src.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL);

    // Case: comparing PTR_MAYBE_NULL with known NULL value
    if dst_maybe_null && src_is_null {
        return apply_null_check_result(state, dst_reg, op, branch_taken);
    }
    if src_maybe_null && dst_is_null {
        // Swap the logic - we're checking if src == dst where dst is NULL
        let swapped_op = match op {
            BPF_JEQ => BPF_JEQ, // symmetric
            BPF_JNE => BPF_JNE, // symmetric
            BPF_JGT => BPF_JLT, // swap: dst > src becomes src < dst
            BPF_JGE => BPF_JLE,
            BPF_JLT => BPF_JGT,
            BPF_JLE => BPF_JGE,
            _ => return false,
        };
        return apply_null_check_result(state, src_reg, swapped_op, branch_taken);
    }

    // Case: comparing two PTR_MAYBE_NULL pointers with same ID
    // if (ptr1 == ptr2) and they have same ID, both are either NULL or non-NULL
    if dst_maybe_null && src_maybe_null && dst.id != 0 && dst.id == src.id {
        match op {
            BPF_JEQ if branch_taken => {
                // Both are equal - if one is NULL, both are NULL; if one is non-NULL, both are
                // We can't determine which, so don't refine
                return false;
            }
            BPF_JNE if !branch_taken => {
                // They're equal (branch not taken)
                return false;
            }
            _ => {}
        }
    }

    false
}

/// Apply NULL check result to a register
fn apply_null_check_result(
    state: &mut BpfVerifierState,
    reg_idx: usize,
    op: u8,
    branch_taken: bool,
) -> bool {
    match op {
        BPF_JEQ => {
            if let Some(reg) = state.reg_mut(reg_idx) {
                if branch_taken {
                    // ptr == NULL is true
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                } else {
                    // ptr == NULL is false, so ptr is non-NULL
                    reg.mark_ptr_not_null();
                }
            }
            true
        }
        BPF_JNE => {
            if let Some(reg) = state.reg_mut(reg_idx) {
                if branch_taken {
                    // ptr != NULL is true, so ptr is non-NULL
                    reg.mark_ptr_not_null();
                } else {
                    // ptr != NULL is false, so ptr is NULL
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                }
            }
            true
        }
        BPF_JGT => {
            // ptr > NULL (0)
            if let Some(reg) = state.reg_mut(reg_idx) {
                if branch_taken {
                    reg.mark_ptr_not_null();
                } else {
                    // ptr <= 0 means ptr == 0 for unsigned
                    reg.mark_known_zero();
                    reg.reg_type = BpfRegType::ScalarValue;
                    reg.type_flags = BpfTypeFlag::empty();
                }
            }
            true
        }
        _ => false,
    }
}

/// State for tracking explored branch paths.
#[derive(Debug, Clone)]
pub struct BranchExplorationState {
    /// Pending states to explore (instruction index, state).
    pending: Vec<(usize, BpfVerifierState)>,
    /// Explored instruction indices.
    explored: Vec<usize>,
    /// Maximum number of states to track.
    max_states: usize,
}

impl BranchExplorationState {
    /// Create a new branch exploration state.
    pub fn new(max_states: usize) -> Self {
        Self {
            pending: Vec::new(),
            explored: Vec::new(),
            max_states,
        }
    }

    /// Push a new state to explore.
    pub fn push(&mut self, insn_idx: usize, state: BpfVerifierState) -> bool {
        if self.pending.len() >= self.max_states {
            return false;
        }
        self.pending.push((insn_idx, state));
        true
    }

    /// Pop the next state to explore.
    pub fn pop(&mut self) -> Option<(usize, BpfVerifierState)> {
        self.pending.pop()
    }

    /// Mark an instruction as explored.
    pub fn mark_explored(&mut self, insn_idx: usize) {
        if !self.explored.contains(&insn_idx) {
            self.explored.push(insn_idx);
        }
    }

    /// Check if an instruction has been explored.
    pub fn is_explored(&self, insn_idx: usize) -> bool {
        self.explored.contains(&insn_idx)
    }

    /// Check if there are pending states.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get number of pending states.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
