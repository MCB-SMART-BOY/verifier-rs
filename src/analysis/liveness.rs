// SPDX-License-Identifier: GPL-2.0

//! Register liveness tracking
//!
//! This module implements register liveness analysis for the BPF verifier.
//! It tracks which registers are read, written, and whether they need
//! precise tracking for verification correctness.

use alloc::{vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::RegLiveness;

/// Liveness states for registers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveState {
    /// Register has not been accessed
    #[default]
    None,
    /// Register has been written but not read
    Written,
    /// Register has been read
    Read,
    /// Liveness analysis is complete for this register
    Done,
}

impl From<RegLiveness> for LiveState {
    fn from(liveness: RegLiveness) -> Self {
        if liveness.done {
            LiveState::Done
        } else if liveness.read {
            LiveState::Read
        } else if liveness.written {
            LiveState::Written
        } else {
            LiveState::None
        }
    }
}

impl From<LiveState> for RegLiveness {
    fn from(state: LiveState) -> Self {
        match state {
            LiveState::None => RegLiveness {
                read: false,
                written: false,
                done: false,
            },
            LiveState::Written => RegLiveness {
                read: false,
                written: true,
                done: false,
            },
            LiveState::Read => RegLiveness {
                read: true,
                written: false,
                done: false,
            },
            LiveState::Done => RegLiveness {
                read: true,
                written: true,
                done: true,
            },
        }
    }
}

/// Liveness tracking for all registers
#[derive(Debug, Clone, Default)]
pub struct LivenessState {
    /// Liveness state for each register
    pub regs: [LiveState; MAX_BPF_REG],
    /// Stack slot liveness (indexed by slot, not offset)
    pub stack: Vec<LiveState>,
}

impl LivenessState {
    /// Create new liveness state
    pub fn new() -> Self {
        Self {
            regs: [LiveState::None; MAX_BPF_REG],
            stack: Vec::new(),
        }
    }

    /// Mark register as read
    pub fn mark_reg_read(&mut self, regno: usize) {
        if regno < MAX_BPF_REG
            && (self.regs[regno] == LiveState::None || self.regs[regno] == LiveState::Written)
        {
            self.regs[regno] = LiveState::Read;
        }
    }

    /// Mark register as written
    pub fn mark_reg_written(&mut self, regno: usize) {
        if regno < MAX_BPF_REG {
            self.regs[regno] = LiveState::Written;
        }
    }

    /// Mark register liveness as done
    pub fn mark_reg_done(&mut self, regno: usize) {
        if regno < MAX_BPF_REG {
            self.regs[regno] = LiveState::Done;
        }
    }

    /// Check if register is live (read after this point)
    pub fn is_reg_live(&self, regno: usize) -> bool {
        if regno < MAX_BPF_REG {
            matches!(self.regs[regno], LiveState::Read | LiveState::Done)
        } else {
            false
        }
    }

    /// Ensure stack has enough slots
    fn ensure_stack_slot(&mut self, slot: usize) {
        if slot >= self.stack.len() {
            self.stack.resize(slot + 1, LiveState::None);
        }
    }

    /// Mark stack slot as read
    pub fn mark_stack_read(&mut self, slot: usize) {
        self.ensure_stack_slot(slot);
        if self.stack[slot] == LiveState::None || self.stack[slot] == LiveState::Written {
            self.stack[slot] = LiveState::Read;
        }
    }

    /// Mark stack slot as written
    pub fn mark_stack_written(&mut self, slot: usize) {
        self.ensure_stack_slot(slot);
        self.stack[slot] = LiveState::Written;
    }

    /// Check if stack slot is live
    pub fn is_stack_live(&self, slot: usize) -> bool {
        if slot < self.stack.len() {
            matches!(self.stack[slot], LiveState::Read | LiveState::Done)
        } else {
            false
        }
    }

    /// Merge liveness from another state (for control flow joins)
    pub fn merge(&mut self, other: &LivenessState) {
        for i in 0..MAX_BPF_REG {
            self.regs[i] = merge_live_state(self.regs[i], other.regs[i]);
        }

        // Extend stack if needed
        let max_len = self.stack.len().max(other.stack.len());
        self.stack.resize(max_len, LiveState::None);

        for i in 0..other.stack.len() {
            self.stack[i] = merge_live_state(self.stack[i], other.stack[i]);
        }
    }
}

/// Merge two liveness states for control flow join
fn merge_live_state(a: LiveState, b: LiveState) -> LiveState {
    // If either path reads the register, it's live
    match (a, b) {
        (LiveState::Done, _) | (_, LiveState::Done) => LiveState::Done,
        (LiveState::Read, _) | (_, LiveState::Read) => LiveState::Read,
        (LiveState::Written, LiveState::Written) => LiveState::Written,
        (LiveState::Written, LiveState::None) | (LiveState::None, LiveState::Written) => {
            LiveState::Written
        }
        (LiveState::None, LiveState::None) => LiveState::None,
    }
}

/// Instruction liveness effects
#[derive(Debug, Clone, Default)]
pub struct InsnLiveness {
    /// Registers read by this instruction
    pub regs_read: u16,
    /// Register written by this instruction
    pub reg_written: Option<u8>,
    /// Stack slots read
    pub stack_read: Vec<usize>,
    /// Stack slots written
    pub stack_written: Vec<usize>,
}

impl InsnLiveness {
    /// Create liveness info for an ALU instruction
    pub fn alu(dst: u8, src: Option<u8>) -> Self {
        let mut regs_read = 1u16 << dst;
        if let Some(s) = src {
            regs_read |= 1u16 << s;
        }
        Self {
            regs_read,
            reg_written: Some(dst),
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for a MOV instruction
    pub fn mov(dst: u8, src: Option<u8>) -> Self {
        let regs_read = src.map(|s| 1u16 << s).unwrap_or(0);
        Self {
            regs_read,
            reg_written: Some(dst),
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for a load instruction
    pub fn load(dst: u8, src: u8, stack_slot: Option<usize>) -> Self {
        let mut stack_read = Vec::new();
        if let Some(slot) = stack_slot {
            stack_read.push(slot);
        }
        Self {
            regs_read: 1u16 << src,
            reg_written: Some(dst),
            stack_read,
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for a store instruction
    pub fn store(dst: u8, src: u8, stack_slot: Option<usize>) -> Self {
        let mut stack_written = Vec::new();
        if let Some(slot) = stack_slot {
            stack_written.push(slot);
        }
        Self {
            regs_read: (1u16 << dst) | (1u16 << src),
            reg_written: None,
            stack_read: Vec::new(),
            stack_written,
        }
    }

    /// Create liveness info for a call instruction
    pub fn call(nargs: u8) -> Self {
        // Calls read R1-R5 (up to nargs) and write R0
        let mut regs_read = 0u16;
        for i in 1..=nargs.min(5) {
            regs_read |= 1u16 << i;
        }
        Self {
            regs_read,
            reg_written: Some(0),
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for an exit instruction
    pub fn exit() -> Self {
        // Exit reads R0 (return value)
        Self {
            regs_read: 1u16 << 0,
            reg_written: None,
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for a conditional jump
    pub fn cond_jmp(dst: u8, src: Option<u8>) -> Self {
        let mut regs_read = 1u16 << dst;
        if let Some(s) = src {
            regs_read |= 1u16 << s;
        }
        Self {
            regs_read,
            reg_written: None,
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Check if a register is read
    pub fn reads_reg(&self, regno: u8) -> bool {
        (self.regs_read & (1u16 << regno)) != 0
    }

    /// Check if a register is written
    pub fn writes_reg(&self, regno: u8) -> bool {
        self.reg_written == Some(regno)
    }
}

/// Get liveness effects for an instruction
pub fn get_insn_liveness(insn: &BpfInsn) -> InsnLiveness {
    let class = insn.class();
    let dst = insn.dst_reg;
    let src = insn.src_reg;

    match class {
        BPF_ALU | BPF_ALU64 => {
            let op = insn.code & 0xf0;
            if op == BPF_MOV {
                if insn.code & BPF_X != 0 {
                    InsnLiveness::mov(dst, Some(src))
                } else {
                    InsnLiveness::mov(dst, None)
                }
            } else if op == BPF_NEG {
                InsnLiveness::alu(dst, None)
            } else if insn.code & BPF_X != 0 {
                InsnLiveness::alu(dst, Some(src))
            } else {
                InsnLiveness::alu(dst, None)
            }
        }
        BPF_LDX => {
            // Check if loading from stack
            let stack_slot = if src == BPF_REG_FP as u8 {
                let off = insn.off as i32;
                if off < 0 {
                    Some(((-off - 1) / 8) as usize)
                } else {
                    None
                }
            } else {
                None
            };
            InsnLiveness::load(dst, src, stack_slot)
        }
        BPF_STX | BPF_ST => {
            let stack_slot = if dst == BPF_REG_FP as u8 {
                let off = insn.off as i32;
                if off < 0 {
                    Some(((-off - 1) / 8) as usize)
                } else {
                    None
                }
            } else {
                None
            };
            if class == BPF_ST {
                // ST uses immediate, not src register
                InsnLiveness::store(dst, dst, stack_slot)
            } else {
                InsnLiveness::store(dst, src, stack_slot)
            }
        }
        BPF_JMP | BPF_JMP32 => {
            let op = insn.code & 0xf0;
            match op {
                BPF_EXIT => InsnLiveness::exit(),
                BPF_CALL => InsnLiveness::call(5), // Assume max args
                BPF_JA => InsnLiveness::default(),
                _ => {
                    // Conditional jump
                    if insn.code & BPF_X != 0 {
                        InsnLiveness::cond_jmp(dst, Some(src))
                    } else {
                        InsnLiveness::cond_jmp(dst, None)
                    }
                }
            }
        }
        BPF_LD => {
            // LD_IMM64 and others
            InsnLiveness::mov(dst, None)
        }
        _ => InsnLiveness::default(),
    }
}

/// Backward liveness analysis for a basic block
pub fn analyze_block_liveness(
    insns: &[BpfInsn],
    start: usize,
    end: usize,
    exit_liveness: &LivenessState,
) -> Result<Vec<LivenessState>> {
    if start > end || end >= insns.len() {
        return Err(VerifierError::InvalidInstruction(end));
    }

    let block_len = end - start + 1;
    let mut liveness = vec![LivenessState::new(); block_len];

    // Start from exit liveness
    liveness[block_len - 1] = exit_liveness.clone();

    // Process instructions backward
    for i in (0..block_len - 1).rev() {
        let insn_idx = start + i;
        let insn = &insns[insn_idx];
        let effects = get_insn_liveness(insn);

        // Start with successor's liveness
        liveness[i] = liveness[i + 1].clone();

        // Remove writes (they kill liveness)
        if let Some(reg) = effects.reg_written {
            liveness[i].regs[reg as usize] = LiveState::None;
        }
        for &slot in &effects.stack_written {
            if slot < liveness[i].stack.len() {
                liveness[i].stack[slot] = LiveState::None;
            }
        }

        // Add reads (they generate liveness)
        for r in 0..MAX_BPF_REG {
            if effects.reads_reg(r as u8) {
                liveness[i].mark_reg_read(r);
            }
        }
        for &slot in &effects.stack_read {
            liveness[i].mark_stack_read(slot);
        }
    }

    Ok(liveness)
}

/// Check if a register needs precise tracking at an instruction
pub fn needs_precise_tracking(
    liveness: &LivenessState,
    regno: usize,
    is_jmp_condition: bool,
) -> bool {
    // Register needs precise tracking if:
    // 1. It's used in a conditional jump
    // 2. It's live and could affect memory access bounds
    if is_jmp_condition {
        return true;
    }

    liveness.is_reg_live(regno)
}

/// Propagate precision requirements backward through liveness
pub fn propagate_precision_liveness(
    insns: &[BpfInsn],
    precise_regs: &mut [bool; MAX_BPF_REG],
    insn_idx: usize,
) -> Result<()> {
    if insn_idx >= insns.len() {
        return Ok(());
    }

    let insn = &insns[insn_idx];
    let effects = get_insn_liveness(insn);

    // If destination is precise, source(s) must be precise too
    if let Some(dst) = effects.reg_written {
        if precise_regs[dst as usize] {
            for (r, precise) in precise_regs.iter_mut().enumerate().take(MAX_BPF_REG) {
                if effects.reads_reg(r as u8) {
                    *precise = true;
                }
            }
        }
    }

    Ok(())
}
