// SPDX-License-Identifier: GPL-2.0

//! Register liveness tracking
//! 寄存器活性跟踪
//!
//! This module implements register liveness analysis for the BPF verifier.
//! 本模块为 BPF 验证器实现寄存器活性分析。
//! It tracks which registers are read, written, and whether they need
//! 它跟踪哪些寄存器被读取、写入，以及它们是否需要
//! precise tracking for verification correctness.
//! 精确跟踪以确保验证正确性。

use alloc::{vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::RegLiveness;

/// Liveness states for registers
/// 寄存器的活性状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveState {
    /// Register has not been accessed
    /// 寄存器未被访问
    #[default]
    None,
    /// Register has been written but not read
    /// 寄存器已写入但未读取
    Written,
    /// Register has been read
    /// 寄存器已读取
    Read,
    /// Liveness analysis is complete for this register
    /// 此寄存器的活性分析已完成
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
/// 所有寄存器的活性跟踪
#[derive(Debug, Clone, Default)]
pub struct LivenessState {
    /// Liveness state for each register
    /// 每个寄存器的活性状态
    pub regs: [LiveState; MAX_BPF_REG],
    /// Stack slot liveness (indexed by slot, not offset)
    /// 栈槽活性（按槽索引，不是偏移量）
    pub stack: Vec<LiveState>,
}

impl LivenessState {
    /// Create new liveness state
    /// 创建新的活性状态
    pub fn new() -> Self {
        Self {
            regs: [LiveState::None; MAX_BPF_REG],
            stack: Vec::new(),
        }
    }

    /// Mark register as read
    /// 标记寄存器为已读取
    pub fn mark_reg_read(&mut self, regno: usize) {
        if regno < MAX_BPF_REG
            && (self.regs[regno] == LiveState::None || self.regs[regno] == LiveState::Written)
        {
            self.regs[regno] = LiveState::Read;
        }
    }

    /// Mark register as written
    /// 标记寄存器为已写入
    pub fn mark_reg_written(&mut self, regno: usize) {
        if regno < MAX_BPF_REG {
            self.regs[regno] = LiveState::Written;
        }
    }

    /// Mark register liveness as done
    /// 标记寄存器活性分析完成
    pub fn mark_reg_done(&mut self, regno: usize) {
        if regno < MAX_BPF_REG {
            self.regs[regno] = LiveState::Done;
        }
    }

    /// Check if register is live (read after this point)
    /// 检查寄存器是否活跃（在此点之后被读取）
    pub fn is_reg_live(&self, regno: usize) -> bool {
        if regno < MAX_BPF_REG {
            matches!(self.regs[regno], LiveState::Read | LiveState::Done)
        } else {
            false
        }
    }

    /// Ensure stack has enough slots
    /// 确保栈有足够的槽位
    fn ensure_stack_slot(&mut self, slot: usize) {
        if slot >= self.stack.len() {
            self.stack.resize(slot + 1, LiveState::None);
        }
    }

    /// Mark stack slot as read
    /// 标记栈槽为已读取
    pub fn mark_stack_read(&mut self, slot: usize) {
        self.ensure_stack_slot(slot);
        if self.stack[slot] == LiveState::None || self.stack[slot] == LiveState::Written {
            self.stack[slot] = LiveState::Read;
        }
    }

    /// Mark stack slot as written
    /// 标记栈槽为已写入
    pub fn mark_stack_written(&mut self, slot: usize) {
        self.ensure_stack_slot(slot);
        self.stack[slot] = LiveState::Written;
    }

    /// Check if stack slot is live
    /// 检查栈槽是否活跃
    pub fn is_stack_live(&self, slot: usize) -> bool {
        if slot < self.stack.len() {
            matches!(self.stack[slot], LiveState::Read | LiveState::Done)
        } else {
            false
        }
    }

    /// Merge liveness from another state (for control flow joins)
    /// 合并来自另一个状态的活性（用于控制流汇合）
    pub fn merge(&mut self, other: &LivenessState) {
        for i in 0..MAX_BPF_REG {
            self.regs[i] = merge_live_state(self.regs[i], other.regs[i]);
        }

        // Extend stack if needed
        // 如需要则扩展栈
        let max_len = self.stack.len().max(other.stack.len());
        self.stack.resize(max_len, LiveState::None);

        for i in 0..other.stack.len() {
            self.stack[i] = merge_live_state(self.stack[i], other.stack[i]);
        }
    }
}

/// Merge two liveness states for control flow join
/// 合并两个活性状态用于控制流汇合
fn merge_live_state(a: LiveState, b: LiveState) -> LiveState {
    // If either path reads the register, it's live
    // 如果任一路径读取寄存器，则它是活跃的
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
/// 指令活性影响
#[derive(Debug, Clone, Default)]
pub struct InsnLiveness {
    /// Registers read by this instruction
    /// 此指令读取的寄存器
    pub regs_read: u16,
    /// Register written by this instruction
    /// 此指令写入的寄存器
    pub reg_written: Option<u8>,
    /// Stack slots read
    /// 读取的栈槽
    pub stack_read: Vec<usize>,
    /// Stack slots written
    /// 写入的栈槽
    pub stack_written: Vec<usize>,
}

impl InsnLiveness {
    /// Create liveness info for an ALU instruction
    /// 为 ALU 指令创建活性信息
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
    /// 为 MOV 指令创建活性信息
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
    /// 为加载指令创建活性信息
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
    /// 为存储指令创建活性信息
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
    /// 为调用指令创建活性信息
    pub fn call(nargs: u8) -> Self {
        // Calls read R1-R5 (up to nargs) and write R0
        // 调用读取 R1-R5（最多 nargs 个）并写入 R0
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
    /// 为退出指令创建活性信息
    pub fn exit() -> Self {
        // Exit reads R0 (return value)
        // 退出读取 R0（返回值）
        Self {
            regs_read: 1u16 << 0,
            reg_written: None,
            stack_read: Vec::new(),
            stack_written: Vec::new(),
        }
    }

    /// Create liveness info for a conditional jump
    /// 为条件跳转创建活性信息
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
    /// 检查寄存器是否被读取
    pub fn reads_reg(&self, regno: u8) -> bool {
        (self.regs_read & (1u16 << regno)) != 0
    }

    /// Check if a register is written
    /// 检查寄存器是否被写入
    pub fn writes_reg(&self, regno: u8) -> bool {
        self.reg_written == Some(regno)
    }
}

/// Get liveness effects for an instruction
/// 获取指令的活性影响
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
            // 检查是否从栈加载
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
                // ST 使用立即数，不是源寄存器
                InsnLiveness::store(dst, dst, stack_slot)
            } else {
                InsnLiveness::store(dst, src, stack_slot)
            }
        }
        BPF_JMP | BPF_JMP32 => {
            let op = insn.code & 0xf0;
            match op {
                BPF_EXIT => InsnLiveness::exit(),
                BPF_CALL => InsnLiveness::call(5), // Assume max args / 假设最大参数数
                BPF_JA => InsnLiveness::default(),
                _ => {
                    // Conditional jump
                    // 条件跳转
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
            // LD_IMM64 和其他
            InsnLiveness::mov(dst, None)
        }
        _ => InsnLiveness::default(),
    }
}

/// Backward liveness analysis for a basic block
/// 基本块的反向活性分析
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
    // 从出口活性开始
    liveness[block_len - 1] = exit_liveness.clone();

    // Process instructions backward
    // 反向处理指令
    for i in (0..block_len - 1).rev() {
        let insn_idx = start + i;
        let insn = &insns[insn_idx];
        let effects = get_insn_liveness(insn);

        // Start with successor's liveness
        // 从后继的活性开始
        liveness[i] = liveness[i + 1].clone();

        // Remove writes (they kill liveness)
        // 移除写入（它们终止活性）
        if let Some(reg) = effects.reg_written {
            liveness[i].regs[reg as usize] = LiveState::None;
        }
        for &slot in &effects.stack_written {
            if slot < liveness[i].stack.len() {
                liveness[i].stack[slot] = LiveState::None;
            }
        }

        // Add reads (they generate liveness)
        // 添加读取（它们生成活性）
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
/// 检查寄存器在某指令处是否需要精确跟踪
pub fn needs_precise_tracking(
    liveness: &LivenessState,
    regno: usize,
    is_jmp_condition: bool,
) -> bool {
    // Register needs precise tracking if:
    // 寄存器需要精确跟踪如果：
    // 1. It's used in a conditional jump
    // 1. 它用于条件跳转
    // 2. It's live and could affect memory access bounds
    // 2. 它是活跃的并且可能影响内存访问边界
    if is_jmp_condition {
        return true;
    }

    liveness.is_reg_live(regno)
}

/// Propagate precision requirements backward through liveness
/// 通过活性反向传播精度要求
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
    // 如果目标是精确的，源也必须是精确的
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
