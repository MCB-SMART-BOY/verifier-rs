// SPDX-License-Identifier: GPL-2.0

//!

//! This module implements verification of jump instruction sequences,

//! including conditional jumps, unconditional jumps, and call instructions.

use alloc::{format, vec::Vec};

use crate::bounds::tnum::Tnum;
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;

use crate::core::error::{Result, VerifierError};

/// Maximum jump offset
pub const MAX_JMP_OFFSET: i32 = 0x7FFF;

/// Minimum jump offset
pub const MIN_JMP_OFFSET: i32 = -0x8000;

/// Maximum may_goto iterations (for bounding loops)
pub const MAX_MAY_GOTO_ITERATIONS: u32 = 8192;

/// Jump type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpType {
    /// Unconditional jump (JA)
    Unconditional,
    /// Conditional jump based on comparison
    Conditional,
    /// Function call
    Call,
    /// Tail call (program exit and transfer)
    TailCall,
    /// Program exit
    Exit,
    /// BPF-to-BPF call (pseudo call)
    PseudoCall,
    /// gotol (32-bit offset jump)
    Gotol,
    /// may_goto (bounded loop construct)
    MayGoto,
}

/// Jump instruction info
#[derive(Debug, Clone)]
pub struct JumpInfo {
    /// Jump type
    pub jump_type: JumpType,
    /// Source instruction index
    pub src_idx: usize,
    /// Target instruction index (for jumps)
    pub target_idx: Option<usize>,
    /// Fall-through instruction index
    pub fallthrough_idx: Option<usize>,
    /// Whether jump is always taken (for const conditions)
    pub always_taken: Option<bool>,
}

impl JumpInfo {
    /// Create info for unconditional jump
    pub fn unconditional(src_idx: usize, target_idx: usize) -> Self {
        Self {
            jump_type: JumpType::Unconditional,
            src_idx,
            target_idx: Some(target_idx),
            fallthrough_idx: None,
            always_taken: Some(true),
        }
    }

    /// Create info for conditional jump
    pub fn conditional(src_idx: usize, target_idx: usize, fallthrough_idx: usize) -> Self {
        Self {
            jump_type: JumpType::Conditional,
            src_idx,
            target_idx: Some(target_idx),
            fallthrough_idx: Some(fallthrough_idx),
            always_taken: None,
        }
    }

    /// Create info for call
    pub fn call(src_idx: usize, is_pseudo: bool) -> Self {
        Self {
            jump_type: if is_pseudo {
                JumpType::PseudoCall
            } else {
                JumpType::Call
            },
            src_idx,
            target_idx: None,
            fallthrough_idx: Some(src_idx + 1),
            always_taken: None,
        }
    }

    /// Create info for exit
    pub fn exit(src_idx: usize) -> Self {
        Self {
            jump_type: JumpType::Exit,
            src_idx,
            target_idx: None,
            fallthrough_idx: None,
            always_taken: None,
        }
    }
}

/// Analyze jump instruction
pub fn analyze_jump(insn: &BpfInsn, insn_idx: usize, insn_count: usize) -> Result<JumpInfo> {
    let class = insn.class();

    if class != BPF_JMP && class != BPF_JMP32 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    let op = insn.code & 0xf0;

    match op {
        BPF_JA => {
            // Unconditional jump
            let target = compute_jump_target(insn_idx, insn.off as i32, insn_count)?;
            Ok(JumpInfo::unconditional(insn_idx, target))
        }
        BPF_EXIT => Ok(JumpInfo::exit(insn_idx)),
        BPF_CALL => {
            let is_pseudo = insn.src_reg == BPF_PSEUDO_CALL;
            Ok(JumpInfo::call(insn_idx, is_pseudo))
        }
        BPF_JCOND => {
            // may_goto instruction
            if insn.is_may_goto() {
                let target = compute_jump_target(insn_idx, insn.off as i32, insn_count)?;
                let fallthrough = insn_idx + 1;

                if fallthrough >= insn_count {
                    return Err(VerifierError::InvalidInstruction(insn_idx));
                }

                Ok(JumpInfo {
                    jump_type: JumpType::MayGoto,
                    src_idx: insn_idx,
                    target_idx: Some(target),
                    fallthrough_idx: Some(fallthrough),
                    always_taken: None,
                })
            } else {
                Err(VerifierError::InvalidInstruction(insn_idx))
            }
        }
        _ => {
            // Conditional jump
            let target = compute_jump_target(insn_idx, insn.off as i32, insn_count)?;
            let fallthrough = insn_idx + 1;

            if fallthrough >= insn_count {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }

            Ok(JumpInfo::conditional(insn_idx, target, fallthrough))
        }
    }
}

/// Compute jump target from offset
fn compute_jump_target(src: usize, off: i32, insn_count: usize) -> Result<usize> {
    let target = src as i64 + off as i64 + 1;

    if target < 0 || target >= insn_count as i64 {
        return Err(VerifierError::InvalidJumpDestination(target as i32));
    }

    Ok(target as usize)
}

/// Evaluate conditional jump with known values
pub fn evaluate_condition(
    op: u8,
    dst: &BpfRegState,
    src: &BpfRegState,
    imm: i32,
    is_jmp32: bool,
) -> Option<bool> {
    // Both must be scalars for evaluation
    if dst.reg_type != BpfRegType::ScalarValue {
        return None;
    }

    // Get comparison values
    let dst_const = dst.is_const();
    let src_const = if op & BPF_X != 0 {
        src.reg_type == BpfRegType::ScalarValue && src.is_const()
    } else {
        true // Immediate is always const
    };

    if !dst_const || !src_const {
        return None; // Can't evaluate with non-const
    }

    let dst_val = if is_jmp32 {
        dst.const_value() as u32 as u64
    } else {
        dst.const_value()
    };

    let src_val = if op & BPF_X != 0 {
        if is_jmp32 {
            src.const_value() as u32 as u64
        } else {
            src.const_value()
        }
    } else if is_jmp32 {
        imm as u32 as u64
    } else {
        imm as i64 as u64
    };

    let jmp_op = op & 0xf0;

    Some(match jmp_op {
        BPF_JEQ => dst_val == src_val,
        BPF_JNE => dst_val != src_val,
        BPF_JGT => dst_val > src_val,
        BPF_JGE => dst_val >= src_val,
        BPF_JLT => dst_val < src_val,
        BPF_JLE => dst_val <= src_val,
        BPF_JSET => (dst_val & src_val) != 0,
        BPF_JSGT => (dst_val as i64) > (src_val as i64),
        BPF_JSGE => (dst_val as i64) >= (src_val as i64),
        BPF_JSLT => (dst_val as i64) < (src_val as i64),
        BPF_JSLE => (dst_val as i64) <= (src_val as i64),
        _ => return None,
    })
}

/// Check if condition can be proven true/false from bounds
pub fn prove_condition_from_bounds(
    op: u8,
    dst: &BpfRegState,
    src: &BpfRegState,
    imm: i32,
    is_jmp32: bool,
) -> Option<bool> {
    if dst.reg_type != BpfRegType::ScalarValue {
        return None;
    }

    let jmp_op = op & 0xf0;
    let is_reg = (op & BPF_X) != 0;

    // Get bounds
    let (dst_umin, dst_umax, dst_smin, dst_smax) = if is_jmp32 {
        (
            dst.u32_min_value as u64,
            dst.u32_max_value as u64,
            dst.s32_min_value as i64,
            dst.s32_max_value as i64,
        )
    } else {
        (
            dst.umin_value,
            dst.umax_value,
            dst.smin_value,
            dst.smax_value,
        )
    };

    let (src_umin, src_umax, src_smin, src_smax) = if is_reg {
        if src.reg_type != BpfRegType::ScalarValue {
            return None;
        }
        if is_jmp32 {
            (
                src.u32_min_value as u64,
                src.u32_max_value as u64,
                src.s32_min_value as i64,
                src.s32_max_value as i64,
            )
        } else {
            (
                src.umin_value,
                src.umax_value,
                src.smin_value,
                src.smax_value,
            )
        }
    } else {
        let val = if is_jmp32 {
            imm as u32 as u64
        } else {
            imm as i64 as u64
        };
        let sval = i64::from(imm);
        (val, val, sval, sval)
    };

    match jmp_op {
        BPF_JEQ => {
            // Equal: ranges must overlap at single point
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(true);
            }
            // Can prove false if ranges don't overlap
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(false);
            }
        }
        BPF_JNE => {
            // Not equal: can prove if ranges don't overlap
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(true);
            }
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(false);
            }
        }
        BPF_JGT => {
            // Greater than (unsigned)
            if dst_umin > src_umax {
                return Some(true);
            }
            if dst_umax <= src_umin {
                return Some(false);
            }
        }
        BPF_JGE => {
            if dst_umin >= src_umax {
                return Some(true);
            }
            if dst_umax < src_umin {
                return Some(false);
            }
        }
        BPF_JLT => {
            if dst_umax < src_umin {
                return Some(true);
            }
            if dst_umin >= src_umax {
                return Some(false);
            }
        }
        BPF_JLE => {
            if dst_umax <= src_umin {
                return Some(true);
            }
            if dst_umin > src_umax {
                return Some(false);
            }
        }
        BPF_JSGT => {
            if dst_smin > src_smax {
                return Some(true);
            }
            if dst_smax <= src_smin {
                return Some(false);
            }
        }
        BPF_JSGE => {
            if dst_smin >= src_smax {
                return Some(true);
            }
            if dst_smax < src_smin {
                return Some(false);
            }
        }
        BPF_JSLT => {
            if dst_smax < src_smin {
                return Some(true);
            }
            if dst_smin >= src_smax {
                return Some(false);
            }
        }
        BPF_JSLE => {
            if dst_smax <= src_smin {
                return Some(true);
            }
            if dst_smin > src_smax {
                return Some(false);
            }
        }
        _ => {}
    }

    None
}

/// Refine register bounds based on taken branch
pub fn refine_bounds_on_branch(
    dst: &mut BpfRegState,
    op: u8,
    src_val: u64,
    is_taken: bool,
    is_jmp32: bool,
) {
    if dst.reg_type != BpfRegType::ScalarValue {
        return;
    }

    let jmp_op = op & 0xf0;

    // Refine based on comparison outcome
    match jmp_op {
        BPF_JEQ => {
            if is_taken {
                // dst == src_val
                if is_jmp32 {
                    dst.u32_min_value = src_val as u32;
                    dst.u32_max_value = src_val as u32;
                    dst.s32_min_value = src_val as i32;
                    dst.s32_max_value = src_val as i32;
                } else {
                    dst.umin_value = src_val;
                    dst.umax_value = src_val;
                    dst.smin_value = src_val as i64;
                    dst.smax_value = src_val as i64;
                }
                // Also refine tnum to known value
                dst.var_off = Tnum::const_value(src_val);
            }
            // If not taken, dst != src_val - can tighten at boundaries
        }
        BPF_JNE => {
            if !is_taken {
                // dst == src_val (branch not taken means equal)
                if is_jmp32 {
                    dst.u32_min_value = src_val as u32;
                    dst.u32_max_value = src_val as u32;
                    dst.s32_min_value = src_val as i32;
                    dst.s32_max_value = src_val as i32;
                } else {
                    dst.umin_value = src_val;
                    dst.umax_value = src_val;
                    dst.smin_value = src_val as i64;
                    dst.smax_value = src_val as i64;
                }
                dst.var_off = Tnum::const_value(src_val);
            }
            // If taken, dst != src_val - can tighten at boundaries
            // e.g., if src_val == umin_value, we know dst > umin_value
            if is_taken {
                if is_jmp32 {
                    if dst.u32_min_value == src_val as u32 {
                        dst.u32_min_value = (src_val as u32).saturating_add(1);
                    }
                    if dst.u32_max_value == src_val as u32 {
                        dst.u32_max_value = (src_val as u32).saturating_sub(1);
                    }
                } else {
                    if dst.umin_value == src_val {
                        dst.umin_value = src_val.saturating_add(1);
                    }
                    if dst.umax_value == src_val {
                        dst.umax_value = src_val.saturating_sub(1);
                    }
                }
            }
        }
        BPF_JSET => {
            // JSET: if (dst & src_val) != 0
            if is_taken {
                // At least one common bit is set
                // We can refine tnum: mask bits must have at least one 1
                // If src_val is a power of 2, we know that bit must be set in dst
                if src_val.is_power_of_two() {
                    // dst must have this bit set
                    dst.var_off = Tnum {
                        value: dst.var_off.value | src_val,
                        mask: dst.var_off.mask & !src_val,
                    };
                }
                // Also: dst cannot be 0 if src_val != 0
                if src_val != 0 {
                    if is_jmp32 {
                        if dst.u32_min_value == 0 {
                            dst.u32_min_value = 1;
                        }
                    } else if dst.umin_value == 0 {
                        dst.umin_value = 1;
                    }
                }
            } else {
                // (dst & src_val) == 0, so all bits in src_val are 0 in dst
                dst.var_off = Tnum {
                    value: dst.var_off.value & !src_val,
                    mask: dst.var_off.mask & !src_val,
                };
                // Upper bound can be refined: dst <= !src_val (in the mask area)
                if is_jmp32 {
                    dst.u32_max_value = dst.u32_max_value.min(!(src_val as u32));
                } else {
                    dst.umax_value = dst.umax_value.min(!src_val);
                }
            }
        }
        BPF_JGT => {
            if is_taken {
                // dst > src_val
                if is_jmp32 {
                    dst.u32_min_value = dst.u32_min_value.max((src_val as u32).saturating_add(1));
                } else {
                    dst.umin_value = dst.umin_value.max(src_val.saturating_add(1));
                }
            } else {
                // dst <= src_val
                if is_jmp32 {
                    dst.u32_max_value = dst.u32_max_value.min(src_val as u32);
                } else {
                    dst.umax_value = dst.umax_value.min(src_val);
                }
            }
        }
        BPF_JGE => {
            if is_taken {
                // dst >= src_val
                if is_jmp32 {
                    dst.u32_min_value = dst.u32_min_value.max(src_val as u32);
                } else {
                    dst.umin_value = dst.umin_value.max(src_val);
                }
            } else {
                // dst < src_val
                if is_jmp32 {
                    dst.u32_max_value = dst.u32_max_value.min((src_val as u32).saturating_sub(1));
                } else {
                    dst.umax_value = dst.umax_value.min(src_val.saturating_sub(1));
                }
            }
        }
        BPF_JLT => {
            if is_taken {
                // dst < src_val
                if is_jmp32 {
                    dst.u32_max_value = dst.u32_max_value.min((src_val as u32).saturating_sub(1));
                } else {
                    dst.umax_value = dst.umax_value.min(src_val.saturating_sub(1));
                }
            } else {
                // dst >= src_val
                if is_jmp32 {
                    dst.u32_min_value = dst.u32_min_value.max(src_val as u32);
                } else {
                    dst.umin_value = dst.umin_value.max(src_val);
                }
            }
        }
        BPF_JLE => {
            if is_taken {
                // dst <= src_val
                if is_jmp32 {
                    dst.u32_max_value = dst.u32_max_value.min(src_val as u32);
                } else {
                    dst.umax_value = dst.umax_value.min(src_val);
                }
            } else {
                // dst > src_val
                if is_jmp32 {
                    dst.u32_min_value = dst.u32_min_value.max((src_val as u32).saturating_add(1));
                } else {
                    dst.umin_value = dst.umin_value.max(src_val.saturating_add(1));
                }
            }
        }
        // Signed comparisons - update signed bounds
        BPF_JSGT => {
            let sval = src_val as i64;
            if is_taken {
                dst.smin_value = dst.smin_value.max(sval.saturating_add(1));
            } else {
                dst.smax_value = dst.smax_value.min(sval);
            }
        }
        BPF_JSGE => {
            let sval = src_val as i64;
            if is_taken {
                dst.smin_value = dst.smin_value.max(sval);
            } else {
                dst.smax_value = dst.smax_value.min(sval.saturating_sub(1));
            }
        }
        BPF_JSLT => {
            let sval = src_val as i64;
            if is_taken {
                dst.smax_value = dst.smax_value.min(sval.saturating_sub(1));
            } else {
                dst.smin_value = dst.smin_value.max(sval);
            }
        }
        BPF_JSLE => {
            let sval = src_val as i64;
            if is_taken {
                dst.smax_value = dst.smax_value.min(sval);
            } else {
                dst.smin_value = dst.smin_value.max(sval.saturating_add(1));
            }
        }
        _ => {}
    }
}

/// Verify jump target is valid
pub fn verify_jump_target(
    _insn_idx: usize,
    target: usize,
    insn_count: usize,
    _is_call: bool,
) -> Result<()> {
    if target >= insn_count {
        return Err(VerifierError::InvalidJumpDestination(target as i32));
    }

    // Jump into middle of LD_IMM64 is not allowed
    // This would need to check the target instruction

    Ok(())
}

/// Collect all jump targets in program
pub fn collect_jump_targets(insns: &[BpfInsn]) -> Vec<usize> {
    let mut targets = Vec::new();
    targets.push(0); // Entry point

    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();

        if class != BPF_JMP && class != BPF_JMP32 {
            continue;
        }

        let op = insn.code & 0xf0;

        match op {
            BPF_EXIT => {}
            BPF_CALL => {
                if insn.src_reg == BPF_PSEUDO_CALL {
                    let target = (idx as i32 + insn.imm + 1) as usize;
                    if target < insns.len() && !targets.contains(&target) {
                        targets.push(target);
                    }
                }
                // Fall-through
                if idx + 1 < insns.len() && !targets.contains(&(idx + 1)) {
                    targets.push(idx + 1);
                }
            }
            BPF_JA => {
                let target = (idx as i32 + insn.off as i32 + 1) as usize;
                if target < insns.len() && !targets.contains(&target) {
                    targets.push(target);
                }
            }
            _ => {
                // Conditional
                let target = (idx as i32 + insn.off as i32 + 1) as usize;
                if target < insns.len() && !targets.contains(&target) {
                    targets.push(target);
                }
                if idx + 1 < insns.len() && !targets.contains(&(idx + 1)) {
                    targets.push(idx + 1);
                }
            }
        }
    }

    targets.sort();
    targets
}

// ============================================================================
// may_goto instruction support
// ============================================================================

/// BPF_JCOND opcode for may_goto
pub const BPF_JCOND: u8 = 0xe0;

/// BPF_MAY_GOTO src_reg value
pub const BPF_MAY_GOTO: u8 = 0;

/// Maximum may_goto depth (loop iteration limit)
pub const MAX_MAY_GOTO_DEPTH: u32 = 8;

/// Check if instruction is may_goto
pub fn is_may_goto_insn(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_JCOND) && insn.src_reg == BPF_MAY_GOTO
}

/// Check if instruction at index is may_goto
pub fn is_may_goto_insn_at(insns: &[BpfInsn], insn_idx: usize) -> bool {
    insns.get(insn_idx).map(is_may_goto_insn).unwrap_or(false)
}

/// may_goto state tracking for a verification state
#[derive(Debug, Clone, Default)]
pub struct MayGotoState {
    /// Current may_goto depth (number of times may_goto taken path was chosen)
    pub depth: u32,
    /// Maximum allowed depth
    pub max_depth: u32,
}

impl MayGotoState {
    /// Create new may_goto state
    pub fn new() -> Self {
        Self {
            depth: 0,
            max_depth: MAX_MAY_GOTO_DEPTH,
        }
    }

    /// Check if we can take another may_goto jump
    pub fn can_take_goto(&self) -> bool {
        self.depth < self.max_depth
    }

    /// Increment depth when taking may_goto branch
    pub fn increment_depth(&mut self) {
        self.depth += 1;
    }

    /// Check if states are equivalent for pruning
    pub fn equivalent(&self, other: &MayGotoState) -> bool {
        self.depth == other.depth
    }
}

/// Result of checking a may_goto instruction
#[derive(Debug, Clone)]
pub struct MayGotoResult {
    /// Whether the goto branch can be taken
    pub can_take_goto: bool,
    /// Whether the fall-through branch can be taken
    pub can_fall_through: bool,
    /// Target instruction index if goto taken
    pub goto_target: usize,
    /// Fall-through instruction index
    pub fall_through: usize,
}

/// Check may_goto instruction
///
/// may_goto provides bounded loop support. It's like a conditional jump that
/// can be taken up to MAX_MAY_GOTO_DEPTH times, after which it must fall through.
pub fn check_may_goto(
    insn: &BpfInsn,
    insn_idx: usize,
    insn_count: usize,
    may_goto_state: &MayGotoState,
) -> Result<MayGotoResult> {
    if !is_may_goto_insn(insn) {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Validate offset
    if insn.off == 0 {
        return Err(VerifierError::InvalidJumpDestination(0));
    }

    let goto_target = compute_jump_target(insn_idx, insn.off as i32, insn_count)?;
    let fall_through = insn_idx + 1;

    if fall_through >= insn_count {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Determine which branches are possible
    let can_take_goto = may_goto_state.can_take_goto();
    // Fall-through is always possible (represents loop exit)
    let can_fall_through = true;

    Ok(MayGotoResult {
        can_take_goto,
        can_fall_through,
        goto_target,
        fall_through,
    })
}

/// Process may_goto for state exploration
///
/// Returns the states for both branches:
/// - First state: goto taken (with incremented depth)
/// - Second state: fall through (loop exit)
pub fn process_may_goto_branches(
    may_goto_state: &MayGotoState,
    result: &MayGotoResult,
) -> (Option<MayGotoState>, Option<MayGotoState>) {
    // Goto branch (if can take)
    let goto_state = if result.can_take_goto {
        let mut new_state = may_goto_state.clone();
        new_state.increment_depth();
        Some(new_state)
    } else {
        None
    };

    // Fall-through branch (always possible)
    let fall_through_state = if result.can_fall_through {
        Some(may_goto_state.clone())
    } else {
        None
    };

    (goto_state, fall_through_state)
}

/// Widen imprecise scalars when taking may_goto branch
///
/// When the verifier takes a may_goto branch, it may need to widen
/// scalar bounds to ensure loop convergence
pub fn widen_scalars_for_may_goto(regs: &mut [BpfRegState], prev_regs: &[BpfRegState]) {
    for (i, reg) in regs.iter_mut().enumerate() {
        if reg.reg_type != BpfRegType::ScalarValue {
            continue;
        }
        if i >= prev_regs.len() {
            continue;
        }
        let prev = &prev_regs[i];
        if prev.reg_type != BpfRegType::ScalarValue {
            continue;
        }

        // If bounds are changing, widen to accelerate convergence
        if reg.umin_value != prev.umin_value || reg.umax_value != prev.umax_value {
            // Widen to unknown bounds to ensure termination
            if reg.umin_value > prev.umin_value {
                // Value is increasing - set to max
                reg.umax_value = u64::MAX;
            }
            if reg.umin_value < prev.umin_value {
                // Value is decreasing - set to 0
                reg.umin_value = 0;
            }
        }
    }
}

/// Create JumpInfo for may_goto instruction
impl JumpInfo {
    /// Create info for may_goto
    pub fn may_goto(src_idx: usize, target_idx: usize, fallthrough_idx: usize) -> Self {
        Self {
            jump_type: JumpType::MayGoto,
            src_idx,
            target_idx: Some(target_idx),
            fallthrough_idx: Some(fallthrough_idx),
            always_taken: None, // Never always taken - depends on depth
        }
    }

    /// Create info for indirect jump (gotol)
    pub fn indirect(src_idx: usize) -> Self {
        Self {
            jump_type: JumpType::Gotol,
            src_idx,
            target_idx: None, // Dynamic target determined at runtime
            fallthrough_idx: None,
            always_taken: Some(true),
        }
    }
}

// ============================================================================
// Indirect Jump (BPF_JA|BPF_X) Support
// ============================================================================

/// Check if instruction is an indirect jump (gotol/JA|X)
///
/// Indirect jumps use R0 to determine the jump offset dynamically.
/// The format is: JA|X with src_reg=0, imm=0, off=0, and R0 contains
/// an index into a jump table.
pub fn is_indirect_jump(insn: &BpfInsn) -> bool {
    // BPF_JA|BPF_X is the indirect jump opcode
    insn.code == (BPF_JMP | BPF_JA | BPF_X)
}

/// Check reserved fields for indirect jump
///
/// For BPF_JA|BPF_X (indirect jump), the following must hold:
/// - src_reg must be BPF_REG_0
/// - imm must be 0
/// - off must be 0
pub fn check_indirect_jump_fields(insn: &BpfInsn, insn_idx: usize) -> Result<()> {
    if insn.src_reg as usize != BPF_REG_0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }
    if insn.imm != 0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }
    if insn.off != 0 {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }
    Ok(())
}

/// Result of checking an indirect jump instruction
#[derive(Debug, Clone)]
pub struct IndirectJumpResult {
    /// Minimum possible target index (from R0 bounds)
    pub min_target: usize,
    /// Maximum possible target index (from R0 bounds)
    pub max_target: usize,
    /// Whether all possible targets are valid
    pub all_targets_valid: bool,
    /// List of concrete targets if R0 has bounded range
    pub targets: Vec<usize>,
}

/// Check indirect jump instruction
///
/// For indirect jumps, R0 must contain a scalar value with known bounds
/// that maps to valid instruction indices. The verifier must explore
/// all possible targets.
///
/// This implements the kernel's `check_indirect_jump()` function.
pub fn check_indirect_jump(
    r0: &BpfRegState,
    insn_idx: usize,
    insn_count: usize,
) -> Result<IndirectJumpResult> {
    // R0 must be initialized
    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(BPF_REG_0 as u8));
    }

    // R0 must be a scalar
    if r0.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::InvalidInstruction(insn_idx));
    }

    // Get bounds on R0
    let min_off = r0.umin_value;
    let max_off = r0.umax_value;

    // Check if bounds are reasonable for jump table
    // If range is too large, reject as potentially unbounded
    const MAX_INDIRECT_JUMP_RANGE: u64 = 256;
    if max_off - min_off > MAX_INDIRECT_JUMP_RANGE {
        return Err(VerifierError::TooComplex(format!(
            "indirect jump range {} too large",
            max_off - min_off
        )));
    }

    // Compute possible targets: insn_idx + 1 + R0
    let mut targets = Vec::new();
    let mut all_valid = true;

    for off in min_off..=max_off {
        let target = insn_idx as u64 + 1 + off;
        if target >= insn_count as u64 {
            all_valid = false;
            continue;
        }
        targets.push(target as usize);
    }

    if targets.is_empty() {
        return Err(VerifierError::InvalidJumpDestination(
            (insn_idx + 1 + min_off as usize) as i32,
        ));
    }

    // Remove duplicates and sort
    targets.sort();
    targets.dedup();

    let min_target = targets.first().copied().unwrap_or(0);
    let max_target = targets.last().copied().unwrap_or(0);

    Ok(IndirectJumpResult {
        min_target,
        max_target,
        all_targets_valid: all_valid,
        targets,
    })
}

/// Validate all indirect jump targets don't land in LD_IMM64 continuation
pub fn validate_indirect_jump_targets(targets: &[usize], insns: &[BpfInsn]) -> Result<()> {
    for &target in targets {
        // Check target is not in the middle of a LD_IMM64
        if target > 0 {
            if let Some(prev_insn) = insns.get(target - 1) {
                if prev_insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    return Err(VerifierError::InvalidJumpTarget(target));
                }
            }
        }
    }
    Ok(())
}

// ============================================================================
// Speculative execution recovery support
// ============================================================================

/// Check if an error can be recovered with nospec barrier
///
/// Some verification errors in speculative execution paths can be
/// recovered by inserting a speculation barrier. This is used for
/// Spectre mitigation.
pub fn error_recoverable_with_nospec(err: &VerifierError) -> bool {
    match err {
        // Pointer arithmetic errors in speculative path
        VerifierError::InvalidPointerArithmetic(_) => true,
        // Memory access errors in speculative path
        VerifierError::InvalidMemoryAccess(_) => true,
        // Pointer comparison errors
        VerifierError::InvalidPointerComparison(_) => true,
        // Other errors are not recoverable
        _ => false,
    }
}

/// Mark instruction as needing nospec barrier
///
/// This is called when an error in speculative execution is recovered
/// by inserting a speculation barrier.
#[derive(Debug, Clone, Default)]
pub struct NospecMark {
    /// Whether instruction needs nospec barrier
    pub needs_barrier: bool,
    /// Original ALU state before nospec (for restoration)
    pub alu_state: u32,
}

impl NospecMark {
    /// Create a new nospec mark
    pub fn new(needs_barrier: bool) -> Self {
        Self {
            needs_barrier,
            alu_state: 0,
        }
    }
}
