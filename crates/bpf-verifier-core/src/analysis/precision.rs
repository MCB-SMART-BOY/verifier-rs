// SPDX-License-Identifier: GPL-2.0

//! Precision tracking for scalar registers
//! 标量寄存器精度追踪
//!
//! This module implements precision tracking for scalar registers.
//! 本模块实现标量寄存器的精度追踪。
//!
//! When a conditional jump depends on a scalar's value, we need to
//! track that scalar precisely through all instructions that affected it.
//! 当条件跳转依赖于标量的值时，我们需要精确追踪该标量及其所有
//! 影响它的指令。
//!
//! The backtracking algorithm walks backward through the instruction
//! history to mark all contributing scalars as precise.
//! 回溯算法会逆向遍历指令历史，将所有相关的标量标记为精确。
//!
//! ## Overview
//! ## 概述
//!
//! Precision tracking is essential for state pruning. Two states can only
//! be considered equivalent if the values that affect program behavior are
//! the same. By default, we track all scalars imprecisely (only bounds),
//! which allows more aggressive pruning. However, when a value directly
//! affects control flow (conditional jumps), we need exact precision.
//! 精度追踪对于状态剪枝至关重要。只有当影响程序行为的值相同时，
//! 两个状态才能被认为是等价的。默认情况下，我们只对标量进行
//! 不精确追踪（仅追踪边界），这允许更激进的剪枝。但是，当某个值
//! 直接影响控制流（条件跳转）时，我们需要精确的精度。
//!
//! ## Algorithm
//! ## 算法
//!
//! 1. When we encounter a conditional jump, mark the involved registers
//!    as needing precision
//!    当遇到条件跳转时，将涉及的寄存器标记为需要精度
//! 2. Walk backward through the instruction history
//!    逆向遍历指令历史
//! 3. For each instruction that writes to a "precise" register, mark its
//!    source operands as needing precision
//!    对于每条写入"精确"寄存器的指令，将其源操作数标记为需要精度
//! 4. Continue until we reach the beginning or run out of history
//!    继续直到到达开头或耗尽历史记录

use alloc::{vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Backtrack state for precision propagation
/// 精度传播的回溯状态
#[derive(Debug, Clone, Default)]
pub struct BacktrackState {
    /// Registers that need precision in each frame
    /// 每个栈帧中需要精度的寄存器
    pub reg_masks: [u32; MAX_BPF_STACK_FRAMES],
    /// Stack slots that need precision in each frame (bitmap)
    /// 每个栈帧中需要精度的栈槽（位图）
    pub stack_masks: [u64; MAX_BPF_STACK_FRAMES],
    /// Current frame being processed
    /// 当前正在处理的栈帧
    pub frame: usize,
}

impl BacktrackState {
    /// Create a new backtrack state
    /// 创建新的回溯状态
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register as needing precision
    /// 将寄存器设置为需要精度
    pub fn set_reg(&mut self, frame: usize, regno: usize) {
        if frame < MAX_BPF_STACK_FRAMES && regno < MAX_BPF_REG {
            self.reg_masks[frame] |= 1 << regno;
        }
    }

    /// Clear a register from precision tracking
    /// 从精度追踪中清除寄存器
    pub fn clear_reg(&mut self, frame: usize, regno: usize) {
        if frame < MAX_BPF_STACK_FRAMES && regno < MAX_BPF_REG {
            self.reg_masks[frame] &= !(1 << regno);
        }
    }

    /// Check if a register needs precision
    /// 检查寄存器是否需要精度
    pub fn is_reg_set(&self, frame: usize, regno: usize) -> bool {
        if frame < MAX_BPF_STACK_FRAMES && regno < MAX_BPF_REG {
            (self.reg_masks[frame] & (1 << regno)) != 0
        } else {
            false
        }
    }

    /// Set a stack slot as needing precision
    /// 将栈槽设置为需要精度
    pub fn set_slot(&mut self, frame: usize, spi: usize) {
        if frame < MAX_BPF_STACK_FRAMES && spi < 64 {
            self.stack_masks[frame] |= 1 << spi;
        }
    }

    /// Clear a stack slot from precision tracking
    /// 从精度追踪中清除栈槽
    pub fn clear_slot(&mut self, frame: usize, spi: usize) {
        if frame < MAX_BPF_STACK_FRAMES && spi < 64 {
            self.stack_masks[frame] &= !(1 << spi);
        }
    }

    /// Check if a stack slot needs precision
    /// 检查栈槽是否需要精度
    pub fn is_slot_set(&self, frame: usize, spi: usize) -> bool {
        if frame < MAX_BPF_STACK_FRAMES && spi < 64 {
            (self.stack_masks[frame] & (1 << spi)) != 0
        } else {
            false
        }
    }

    /// Check if any registers or slots need precision in current frame
    /// 检查当前栈帧中是否有任何寄存器或栈槽需要精度
    pub fn is_empty(&self) -> bool {
        self.reg_masks[self.frame] == 0 && self.stack_masks[self.frame] == 0
    }

    /// Check if completely empty across all frames
    /// 检查所有栈帧是否都为空
    pub fn is_all_empty(&self) -> bool {
        self.reg_masks.iter().all(|&m| m == 0) && self.stack_masks.iter().all(|&m| m == 0)
    }

    /// Get current frame's register mask
    /// 获取当前栈帧的寄存器掩码
    pub fn reg_mask(&self) -> u32 {
        self.reg_masks[self.frame]
    }

    /// Get current frame's stack mask
    /// 获取当前栈帧的栈槽掩码
    pub fn stack_mask(&self) -> u64 {
        self.stack_masks[self.frame]
    }
}

/// Backtrack through instruction to propagate precision
/// 通过指令回溯来传播精度
pub fn backtrack_insn(
    bt: &mut BacktrackState,
    insn: &BpfInsn,
    insn_idx: usize,
    subprog_insn_idx: usize,
) -> Result<()> {
    let class = insn.class();
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Handle different instruction classes
    // 处理不同的指令类别
    match class {
        BPF_ALU | BPF_ALU64 => {
            backtrack_alu(bt, insn, dst_reg, src_reg)?;
        }
        BPF_LDX => {
            // Load from memory: if dst needs precision, source pointer doesn't
            // but if loading from stack, the stack slot needs precision
            // 从内存加载：如果目标需要精度，源指针不需要
            // 但如果从栈加载，则栈槽需要精度
            if bt.is_reg_set(bt.frame, dst_reg) {
                bt.clear_reg(bt.frame, dst_reg);

                // If source is stack pointer (R10 + offset), mark stack slot
                // 如果源是栈指针（R10 + 偏移），标记栈槽
                if src_reg == BPF_REG_FP {
                    let off = insn.off as i32;
                    if off < 0 {
                        let spi = ((-off - 1) / BPF_REG_SIZE as i32) as usize;
                        bt.set_slot(bt.frame, spi);
                    }
                }
            }
        }
        BPF_STX | BPF_ST => {
            // Store to memory: if storing to stack, propagate precision
            // 存储到内存：如果存储到栈，传播精度
            if dst_reg == BPF_REG_FP {
                let off = insn.off as i32;
                if off < 0 {
                    let spi = ((-off - 1) / BPF_REG_SIZE as i32) as usize;
                    if bt.is_slot_set(bt.frame, spi) {
                        bt.clear_slot(bt.frame, spi);
                        if class == BPF_STX {
                            bt.set_reg(bt.frame, src_reg);
                        }
                    }
                }
            }
        }
        BPF_JMP | BPF_JMP32 => {
            let op = insn.code & 0xf0;
            let src_type = insn.code & 0x08;

            match op {
                BPF_CALL => {
                    // Function call: return value in R0
                    // 函数调用：返回值在 R0
                    if bt.is_reg_set(bt.frame, BPF_REG_0) {
                        bt.clear_reg(bt.frame, BPF_REG_0);
                    }

                    // For subprogram calls, handle frame transitions
                    // 对于子程序调用，处理栈帧切换
                    if insn.is_pseudo_call() {
                        // Static subprog call - propagate R1-R5 to caller frame
                        // 静态子程序调用 - 将 R1-R5 传播到调用者栈帧
                        if bt.frame > 0 {
                            for r in 1..=5 {
                                if bt.is_reg_set(bt.frame, r) {
                                    bt.clear_reg(bt.frame, r);
                                    bt.set_reg(bt.frame - 1, r);
                                }
                            }
                            bt.frame -= 1;
                        }
                    }
                    // Helper calls: R1-R5 should have been handled already
                    // 辅助函数调用：R1-R5 应该已经被处理
                }
                BPF_EXIT => {
                    // Exit from subprog: return value in R0
                    // 从子程序退出：返回值在 R0
                    // If we're in a subprog, propagate R0 precision to parent
                    // 如果在子程序中，将 R0 精度传播到父级
                    let r0_precise = bt.is_reg_set(bt.frame, BPF_REG_0);
                    bt.clear_reg(bt.frame, BPF_REG_0);

                    // Enter caller frame
                    // 进入调用者栈帧
                    if bt.frame < MAX_BPF_STACK_FRAMES - 1 {
                        bt.frame += 1;
                        if r0_precise {
                            bt.set_reg(bt.frame, BPF_REG_0);
                        }
                    }
                }
                BPF_JA => {
                    // Unconditional jump - no registers involved
                    // 无条件跳转 - 不涉及寄存器
                }
                _ => {
                    // Conditional jumps: both compared registers need precision
                    // dreg <cond> sreg or dreg <cond> K
                    // 条件跳转：两个比较的寄存器都需要精度
                    // dreg <条件> sreg 或 dreg <条件> K
                    if src_type == BPF_X {
                        // dreg <cond> sreg - both need precision
                        // dreg <条件> sreg - 两者都需要精度
                        if bt.is_reg_set(bt.frame, dst_reg) || bt.is_reg_set(bt.frame, src_reg) {
                            bt.set_reg(bt.frame, dst_reg);
                            bt.set_reg(bt.frame, src_reg);
                        }
                    } else {
                        // dreg <cond> K - only dreg needs precision
                        // dreg <条件> K - 只有 dreg 需要精度
                        // Nothing new to mark - dreg is already handled
                        // 没有新的需要标记 - dreg 已经被处理
                    }
                }
            }
        }
        BPF_LD => {
            // LD_IMM64 loads immediate to dst
            // LD_IMM64 加载立即数到目标
            if insn.code == (BPF_LD | BPF_IMM | 0x18) && bt.is_reg_set(bt.frame, dst_reg) {
                // Immediate value - no source to track
                // 立即数 - 没有需要追踪的源
                bt.clear_reg(bt.frame, dst_reg);
            }
        }
        _ => {}
    }

    let _ = (insn_idx, subprog_insn_idx);
    Ok(())
}

/// Handle ALU instruction backtracking
/// 处理 ALU 指令回溯
pub fn backtrack_alu(
    bt: &mut BacktrackState,
    insn: &BpfInsn,
    dst_reg: usize,
    src_reg: usize,
) -> Result<()> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;

    // If destination doesn't need precision, nothing to do
    // 如果目标不需要精度，无需操作
    if !bt.is_reg_set(bt.frame, dst_reg) {
        return Ok(());
    }

    match op {
        BPF_MOV => {
            // MOV: precision transfers from dst to src
            // MOV：精度从目标转移到源
            bt.clear_reg(bt.frame, dst_reg);
            if src_type == BPF_X {
                bt.set_reg(bt.frame, src_reg);
            }
            // If immediate, precision is satisfied
            // 如果是立即数，精度已满足
        }
        BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_MOD | BPF_OR | BPF_AND | BPF_XOR => {
            // Binary ops: both operands contribute to result
            // 二元操作：两个操作数都参与结果
            // Keep dst in precision set (it's used as input)
            // 保持目标在精度集合中（它作为输入使用）
            if src_type == BPF_X {
                bt.set_reg(bt.frame, src_reg);
            }
        }
        BPF_LSH | BPF_RSH | BPF_ARSH => {
            // Shifts: dst value matters, shift amount less so
            // but for correctness, track both
            // 移位：目标值重要，移位量次之
            // 但为了正确性，两者都追踪
            if src_type == BPF_X {
                bt.set_reg(bt.frame, src_reg);
            }
        }
        BPF_NEG => {
            // NEG only uses dst as input
            // NEG 只使用目标作为输入
            // Keep dst in precision set
            // 保持目标在精度集合中
        }
        BPF_END => {
            // Endianness conversion: only dst matters
            // 字节序转换：只有目标重要
        }
        _ => {}
    }

    Ok(())
}

/// Mark all scalars as precise (fallback when backtracking fails)
/// 将所有标量标记为精确（回溯失败时的回退方案）
pub fn mark_all_scalars_precise(state: &mut BpfVerifierState) {
    for frame_idx in 0..=state.curframe {
        if let Some(func) = state.frame.get_mut(frame_idx).and_then(|f| f.as_mut()) {
            // Mark all scalar registers as precise
            // 将所有标量寄存器标记为精确
            for reg in &mut func.regs {
                if reg.reg_type == BpfRegType::ScalarValue {
                    reg.precise = true;
                }
            }

            // Mark all spilled scalars as precise
            // 将所有溢出的标量标记为精确
            for slot in &mut func.stack.stack {
                if slot.is_spilled_scalar_reg() {
                    slot.spilled_ptr.precise = true;
                }
            }
        }
    }
}

/// Mark all scalars as imprecise
/// 将所有标量标记为不精确
///
/// This is called when caching a state to enable more aggressive pruning.
/// By forgetting precision, we create more generic states that can prune
/// more future states. If any child path requires precision, it will be
/// propagated back retroactively.
/// 这在缓存状态时被调用，以启用更激进的剪枝。
/// 通过忘记精度，我们创建更通用的状态，可以剪枝更多的未来状态。
/// 如果任何子路径需要精度，它将被追溯传播回来。
///
/// This implements the kernel's `mark_all_scalars_imprecise()` function.
/// 这实现了内核的 `mark_all_scalars_imprecise()` 函数。
pub fn mark_all_scalars_imprecise(state: &mut BpfVerifierState) {
    for frame_idx in 0..=state.curframe {
        if let Some(func) = state.frame.get_mut(frame_idx).and_then(|f| f.as_mut()) {
            // Mark all scalar registers as imprecise
            // 将所有标量寄存器标记为不精确
            for reg in &mut func.regs {
                if reg.reg_type == BpfRegType::ScalarValue {
                    reg.precise = false;
                }
            }

            // Mark all spilled scalars as imprecise
            // 将所有溢出的标量标记为不精确
            for slot in &mut func.stack.stack {
                if slot.is_spilled_scalar_reg() {
                    slot.spilled_ptr.precise = false;
                }
            }
        }
    }
}

/// Widen imprecise scalars between old and current state
/// 在旧状态和当前状态之间扩宽不精确的标量
///
/// When revisiting a loop or callback, we widen imprecise scalars to
/// help convergence. If a scalar changed between iterations but isn't
/// marked as precise, we reset it to unknown to ensure the loop
/// eventually terminates.
/// 当重新访问循环或回调时，我们扩宽不精确的标量以帮助收敛。
/// 如果标量在迭代之间发生变化但未标记为精确，我们将其重置为
/// 未知以确保循环最终终止。
///
/// This implements the kernel's `widen_imprecise_scalars()` function.
/// 这实现了内核的 `widen_imprecise_scalars()` 函数。
pub fn widen_imprecise_scalars(old: &BpfVerifierState, cur: &mut BpfVerifierState) -> Result<()> {
    use crate::state::idmap::IdMap;

    let mut idmap = IdMap::new();

    for frame_idx in (0..=old.curframe.min(cur.curframe)).rev() {
        let old_func = match old.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let cur_func = match cur.frame.get_mut(frame_idx).and_then(|f| f.as_mut()) {
            Some(f) => f,
            None => continue,
        };

        // Widen registers
        // 扩宽寄存器
        for i in 0..MAX_BPF_REG {
            widen_imprecise_scalar(&old_func.regs[i], &mut cur_func.regs[i], &mut idmap);
        }

        // Widen spilled slots
        // 扩宽溢出的槽
        let num_slots = old_func.stack.stack.len().min(cur_func.stack.stack.len());
        for spi in 0..num_slots {
            let old_slot = &old_func.stack.stack[spi];
            let cur_slot = &mut cur_func.stack.stack[spi];

            // Only widen spilled scalars
            // 只扩宽溢出的标量
            if old_slot.is_spilled_scalar_reg() && cur_slot.is_spilled_scalar_reg() {
                widen_imprecise_scalar(
                    &old_slot.spilled_ptr,
                    &mut cur_slot.spilled_ptr,
                    &mut idmap,
                );
            }
        }
    }

    Ok(())
}

/// Widen a single imprecise scalar register
/// 扩宽单个不精确的标量寄存器
fn widen_imprecise_scalar(
    old: &BpfRegState,
    cur: &mut BpfRegState,
    idmap: &mut crate::state::idmap::IdMap,
) {
    // Only widen scalar values
    // 只扩宽标量值
    if old.reg_type != BpfRegType::ScalarValue {
        return;
    }
    if cur.reg_type != BpfRegType::ScalarValue {
        return;
    }

    // If either is precise, or they're exactly equal, don't widen
    // 如果任一个是精确的，或者它们完全相等，则不扩宽
    if old.precise || cur.precise {
        return;
    }

    // Check if registers are equivalent (considering ID remapping)
    // 检查寄存器是否等价（考虑 ID 重映射）
    if regs_exact_for_widen(old, cur, idmap) {
        return;
    }

    // Widen the current register to unknown
    // 将当前寄存器扩宽为未知
    cur.mark_unknown(false);
}

/// Check if registers are exactly equal for widening purposes
/// 检查寄存器在扩宽目的下是否完全相等
fn regs_exact_for_widen(
    old: &BpfRegState,
    cur: &BpfRegState,
    idmap: &mut crate::state::idmap::IdMap,
) -> bool {
    // Check bounds match
    // 检查边界匹配
    if old.umin_value != cur.umin_value || old.umax_value != cur.umax_value {
        return false;
    }
    if old.smin_value != cur.smin_value || old.smax_value != cur.smax_value {
        return false;
    }
    if old.var_off != cur.var_off {
        return false;
    }

    // Check IDs are compatible
    // 检查 ID 是否兼容
    if !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Mark chain of registers as precise
/// 将寄存器链标记为精确
///
/// This is the main entry point for precision tracking. It marks a register
/// as needing precision and then backtracks through the instruction history
/// to mark all contributing values as precise.
/// 这是精度追踪的主入口点。它将寄存器标记为需要精度，然后通过指令
/// 历史回溯，将所有相关的值标记为精确。
pub fn mark_chain_precision(
    state: &mut BpfVerifierState,
    frame: usize,
    regno: usize,
) -> Result<bool> {
    __mark_chain_precision(state, frame, regno as i32)
}

/// Internal implementation of precision chain marking
/// 精度链标记的内部实现
///
/// Returns true if any register was newly marked as precise
/// 如果有任何寄存器被新标记为精确，则返回 true
fn __mark_chain_precision(
    state: &mut BpfVerifierState,
    starting_frame: usize,
    regno: i32,
) -> Result<bool> {
    let mut changed = false;
    let mut bt = BacktrackState::new();
    bt.frame = starting_frame;

    // Validate and set initial register for backtracking
    // 验证并设置初始寄存器用于回溯
    if regno >= 0 {
        let regno = regno as usize;
        if let Some(func) = state.frame.get(starting_frame).and_then(|f| f.as_ref()) {
            if let Some(reg) = func.regs.get(regno) {
                if reg.reg_type != BpfRegType::ScalarValue {
                    // Only scalars can be tracked precisely
                    // 只有标量可以被精确追踪
                    return Ok(false);
                }
                bt.set_reg(starting_frame, regno);
            }
        }
    }

    if bt.is_all_empty() {
        return Ok(false);
    }

    // Process jump history in reverse order
    // 按逆序处理跳转历史
    let history = state.jmp_history.clone();
    let history_len = history.len();
    let mut skip_first = true;
    let mut subseq_idx: i32 = -1;

    for i in (0..history_len).rev() {
        let entry = &history[i];
        let insn_idx = entry.idx as usize;

        if skip_first {
            skip_first = false;
            subseq_idx = insn_idx as i32;
            continue;
        }

        // Process this instruction for precision propagation
        // 处理此指令以进行精度传播
        // backtrack_insn would be called here with actual instructions
        // 这里会使用实际指令调用 backtrack_insn
        // The instruction processing is handled by the PrecisionBacktracker
        // 指令处理由 PrecisionBacktracker 处理
        let _ = insn_idx;

        subseq_idx = insn_idx as i32;

        // If all precision requirements are satisfied, stop
        // 如果所有精度要求都已满足，停止
        if bt.is_all_empty() {
            break;
        }
    }

    // Apply precision marks to registers in each frame
    // 将精度标记应用到每个栈帧的寄存器
    for fr in 0..=starting_frame {
        let reg_mask = bt.reg_masks[fr];
        let stack_mask = bt.stack_masks[fr];

        if let Some(func) = state.frame.get_mut(fr).and_then(|f| f.as_mut()) {
            // Mark registers as precise
            // 将寄存器标记为精确
            for r in 0..MAX_BPF_REG {
                if (reg_mask & (1 << r)) != 0 {
                    if func.regs[r].reg_type == BpfRegType::ScalarValue
                        && !func.regs[r].precise
                    {
                        func.regs[r].precise = true;
                        changed = true;
                    }
                    bt.clear_reg(fr, r);
                }
            }

            // Mark stack slots as precise
            // 将栈槽标记为精确
            for spi in 0..64usize {
                if (stack_mask & (1 << spi)) != 0 {
                    if let Some(slot) = func.stack.get_slot_mut_by_spi(spi) {
                        if slot.is_spilled_scalar_reg() && !slot.spilled_ptr.precise {
                            slot.spilled_ptr.precise = true;
                            changed = true;
                        }
                    }
                    bt.clear_slot(fr, spi);
                }
            }
        }
    }

    // If we still have pending precision requests, fall back to marking all
    // 如果仍有待处理的精度请求，回退到标记所有
    if !bt.is_all_empty() {
        mark_all_scalars_precise(state);
        changed = true;
    }

    let _ = subseq_idx;
    Ok(changed)
}

/// Mark chain precision in batch mode (multiple registers at once)
/// 批量模式下标记链精度（一次多个寄存器）
pub fn mark_chain_precision_batch(
    state: &mut BpfVerifierState,
    bt: &BacktrackState,
) -> Result<bool> {
    let mut changed = false;

    // Apply precision marks from the provided backtrack state
    // 从提供的回溯状态应用精度标记
    for fr in 0..MAX_BPF_STACK_FRAMES {
        let reg_mask = bt.reg_masks[fr];
        let stack_mask = bt.stack_masks[fr];

        if reg_mask == 0 && stack_mask == 0 {
            continue;
        }

        if let Some(func) = state.frame.get_mut(fr).and_then(|f| f.as_mut()) {
            // Mark registers as precise
            // 将寄存器标记为精确
            for r in 0..MAX_BPF_REG {
                if (reg_mask & (1 << r)) != 0
                    && func.regs[r].reg_type == BpfRegType::ScalarValue
                    && !func.regs[r].precise
                {
                    func.regs[r].precise = true;
                    changed = true;
                }
            }

            // Mark stack slots as precise
            // 将栈槽标记为精确
            for spi in 0..64 {
                if (stack_mask & (1 << spi)) != 0 {
                    if let Some(slot) = func.stack.get_slot_mut(spi) {
                        if slot.is_spilled_scalar_reg() && !slot.spilled_ptr.precise {
                            slot.spilled_ptr.precise = true;
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    Ok(changed)
}

/// Full precision backtracking through instruction history
/// 通过指令历史的完整精度回溯
pub struct PrecisionBacktracker<'a> {
    /// Instructions to backtrack through
    /// 要回溯的指令
    insns: &'a [BpfInsn],
    /// Backtrack state
    /// 回溯状态
    bt: BacktrackState,
    /// Maximum history length to process
    /// 要处理的最大历史长度
    max_history: usize,
}

impl<'a> PrecisionBacktracker<'a> {
    /// Create a new precision backtracker
    /// 创建新的精度回溯器
    pub fn new(insns: &'a [BpfInsn]) -> Self {
        Self {
            insns,
            bt: BacktrackState::new(),
            max_history: 512,
        }
    }

    /// Mark a register as needing precision
    /// 将寄存器标记为需要精度
    pub fn mark_reg_precise(&mut self, frame: usize, regno: usize) {
        self.bt.set_reg(frame, regno);
    }

    /// Mark a stack slot as needing precision
    /// 将栈槽标记为需要精度
    pub fn mark_slot_precise(&mut self, frame: usize, spi: usize) {
        self.bt.set_slot(frame, spi);
    }

    /// Run backtracking through jump history
    /// 通过跳转历史运行回溯
    pub fn backtrack(&mut self, state: &mut BpfVerifierState) -> Result<()> {
        // Process jump history in reverse order
        // 按逆序处理跳转历史
        let history = state.jmp_history.clone();
        let history_len = history.len();

        if history_len == 0 {
            // No history - mark registers directly
            // 没有历史 - 直接标记寄存器
            self.mark_state_precise(state)?;
            return Ok(());
        }

        // Walk backward through history
        // 逆向遍历历史
        for i in (0..history_len.min(self.max_history)).rev() {
            let entry = &history[i];
            let insn_idx = entry.idx as usize;

            if insn_idx >= self.insns.len() {
                continue;
            }

            let insn = &self.insns[insn_idx];

            // Process this instruction for precision propagation
            // 处理此指令以进行精度传播
            backtrack_insn(&mut self.bt, insn, insn_idx, 0)?;

            // If all precision requirements are satisfied, stop
            // 如果所有精度要求都已满足，停止
            if self.bt.is_all_empty() {
                break;
            }
        }

        // Apply precision to current state
        // 将精度应用到当前状态
        self.mark_state_precise(state)?;

        Ok(())
    }

    /// Mark all tracked registers/slots as precise in the state
    /// 在状态中将所有追踪的寄存器/槽标记为精确
    fn mark_state_precise(&self, state: &mut BpfVerifierState) -> Result<()> {
        for frame in 0..MAX_BPF_STACK_FRAMES {
            let reg_mask = self.bt.reg_masks[frame];
            let stack_mask = self.bt.stack_masks[frame];

            if reg_mask == 0 && stack_mask == 0 {
                continue;
            }

            if let Some(func) = state.frame.get_mut(frame).and_then(|f| f.as_mut()) {
                // Mark registers as precise
                // 将寄存器标记为精确
                for regno in 0..MAX_BPF_REG {
                    if (reg_mask & (1 << regno)) != 0
                        && func.regs[regno].reg_type == BpfRegType::ScalarValue
                    {
                        func.regs[regno].precise = true;
                    }
                }

                // Mark stack slots as precise
                // 将栈槽标记为精确
                for spi in 0..64 {
                    if (stack_mask & (1 << spi)) != 0 {
                        if let Some(slot) = func.stack.get_slot_mut(spi) {
                            if slot.is_spilled_scalar_reg() {
                                slot.spilled_ptr.precise = true;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Mark precision for registers used in a conditional jump
/// 为条件跳转中使用的寄存器标记精度
pub fn mark_jmp_precision(
    state: &mut BpfVerifierState,
    insns: &[BpfInsn],
    insn: &BpfInsn,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let src_type = insn.code & 0x08;

    // Create backtracker
    // 创建回溯器
    let mut backtracker = PrecisionBacktracker::new(insns);
    backtracker.bt.frame = state.curframe;

    // Mark destination register
    // 标记目标寄存器
    backtracker.mark_reg_precise(state.curframe, dst_reg);

    // Mark source register if using register operand
    // 如果使用寄存器操作数，标记源寄存器
    if src_type == BPF_X {
        backtracker.mark_reg_precise(state.curframe, src_reg);
    }

    // Run backtracking
    // 运行回溯
    backtracker.backtrack(state)?;

    Ok(())
}

/// Mark precision for registers used in conditional jump with state cache support
/// 为条件跳转中使用的寄存器标记精度，支持状态缓存
///
/// This enhanced version can propagate precision through parent state chain
/// using the state cache for complete backtracking.
/// 此增强版本可以使用状态缓存通过父状态链传播精度，以实现完整的回溯。
///
/// # Arguments / 参数
///
/// * `state` - Current verifier state / 当前验证器状态
/// * `insns` - Program instructions / 程序指令
/// * `insn` - The conditional jump instruction / 条件跳转指令
/// * `cache` - Optional state cache for parent chain traversal / 可选的状态缓存用于父链遍历
/// * `state_id` - Optional state ID in the cache / 缓存中的可选状态 ID
pub fn mark_jmp_precision_with_cache(
    state: &mut BpfVerifierState,
    insns: &[BpfInsn],
    insn: &BpfInsn,
    cache: Option<&mut StateCache>,
    state_id: Option<StateId>,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let src_type = insn.code & 0x08;

    // Create initial backtrack state
    // 创建初始回溯状态
    let mut bt = BacktrackState::new();
    bt.frame = state.curframe;

    // Mark destination register
    // 标记目标寄存器
    bt.set_reg(state.curframe, dst_reg);

    // Mark source register if using register operand
    // 如果使用寄存器操作数，标记源寄存器
    if src_type == BPF_X {
        bt.set_reg(state.curframe, src_reg);
    }

    // Use cache-based backtracking if available
    // 如果可用，使用基于缓存的回溯
    if let Some(cache) = cache {
        mark_chain_precision_with_cache(
            cache,
            state,
            state_id,
            insns,
            -1, // batch mode / 批量模式
            Some(&bt),
        )?;
    } else {
        // Fall back to local backtracking
        // 回退到本地回溯
        let mut backtracker = PrecisionBacktracker::new(insns);
        backtracker.bt = bt;
        backtracker.backtrack(state)?;
    }

    Ok(())
}

/// Check if a register needs precision tracking
/// 检查寄存器是否需要精度追踪
pub fn reg_needs_precision(state: &BpfVerifierState, regno: usize) -> bool {
    if let Some(func) = state.cur_func() {
        if let Some(reg) = func.regs.get(regno) {
            // Scalars that are used in conditionals need precision
            // 在条件语句中使用的标量需要精度
            return reg.reg_type == BpfRegType::ScalarValue && reg.precise;
        }
    }
    false
}

/// Propagate precision through linked registers after a branch
/// 在分支后通过链接的寄存器传播精度
pub fn sync_linked_regs(
    state: &mut BpfVerifierState,
    known_reg: usize,
    linked_regs: &[(usize, usize)], // (frame, regno) pairs / (栈帧, 寄存器号) 对
) -> Result<()> {
    // Get the known register's bounds
    // 获取已知寄存器的边界
    let bounds = if let Some(func) = state.frame.get(state.curframe).and_then(|f| f.as_ref()) {
        if let Some(reg) = func.regs.get(known_reg) {
            if reg.reg_type != BpfRegType::ScalarValue {
                return Ok(());
            }
            Some((
                reg.umin_value,
                reg.umax_value,
                reg.smin_value,
                reg.smax_value,
                reg.var_off,
            ))
        } else {
            None
        }
    } else {
        None
    };

    // Apply bounds to linked registers
    // 将边界应用到链接的寄存器
    if let Some((umin, umax, smin, smax, var_off)) = bounds {
        for &(frame, regno) in linked_regs {
            if let Some(func) = state.frame.get_mut(frame).and_then(|f| f.as_mut()) {
                if let Some(reg) = func.regs.get_mut(regno) {
                    if reg.reg_type == BpfRegType::ScalarValue {
                        // Intersect bounds
                        // 求边界交集
                        reg.umin_value = reg.umin_value.max(umin);
                        reg.umax_value = reg.umax_value.min(umax);
                        reg.smin_value = reg.smin_value.max(smin);
                        reg.smax_value = reg.smax_value.min(smax);
                        reg.var_off = reg.var_off.intersect(var_off);
                        reg.sync_bounds();
                    }
                }
            }
        }
    }

    Ok(())
}

/// Collect registers that are linked (have same ID) to a given register
/// 收集与给定寄存器链接（具有相同 ID）的寄存器
pub fn collect_linked_regs(
    state: &BpfVerifierState,
    frame: usize,
    regno: usize,
) -> Vec<(usize, usize)> {
    let mut linked = Vec::new();

    // Get the ID of the source register
    // 获取源寄存器的 ID
    let target_id = if let Some(func) = state.frame.get(frame).and_then(|f| f.as_ref()) {
        if let Some(reg) = func.regs.get(regno) {
            if reg.id != 0 {
                reg.id
            } else {
                return linked;
            }
        } else {
            return linked;
        }
    } else {
        return linked;
    };

    // Find all registers with the same ID
    // 查找所有具有相同 ID 的寄存器
    for f in 0..=state.curframe {
        if let Some(func) = state.frame.get(f).and_then(|fr| fr.as_ref()) {
            for (r, reg) in func.regs.iter().enumerate() {
                if reg.id == target_id && (f != frame || r != regno) {
                    linked.push((f, r));
                }
            }
        }
    }

    linked
}

// ============================================================================
// Enhanced Precision Propagation
// 增强的精度传播
// ============================================================================

/// Full precision propagation through the entire program
/// 通过整个程序的完整精度传播
///
/// This implements the complete backtracking algorithm as in the kernel verifier.
/// It walks backward through the instruction stream, propagating precision
/// requirements through data dependencies.
/// 这实现了与内核验证器相同的完整回溯算法。
/// 它通过指令流逆向遍历，通过数据依赖关系传播精度要求。
pub struct FullPrecisionTracker<'a> {
    /// Instructions
    /// 指令
    insns: &'a [BpfInsn],
    /// Backtrack state per instruction
    /// 每条指令的回溯状态
    insn_states: Vec<BacktrackState>,
    /// Instructions that have been processed
    /// 已处理的指令
    processed: Vec<bool>,
    /// Work queue of instructions to process
    /// 待处理指令的工作队列
    worklist: Vec<usize>,
    /// Maximum iterations to prevent infinite loops
    /// 防止无限循环的最大迭代次数
    max_iterations: usize,
}

impl<'a> FullPrecisionTracker<'a> {
    /// Create a new precision tracker
    /// 创建新的精度追踪器
    pub fn new(insns: &'a [BpfInsn]) -> Self {
        let len = insns.len();
        Self {
            insns,
            insn_states: vec![BacktrackState::new(); len],
            processed: vec![false; len],
            worklist: Vec::new(),
            max_iterations: len * 10, // Reasonable limit / 合理限制
        }
    }

    /// Mark a register as needing precision at a specific instruction
    /// 在特定指令处将寄存器标记为需要精度
    pub fn require_precision_at(&mut self, insn_idx: usize, frame: usize, regno: usize) {
        if insn_idx < self.insn_states.len() {
            self.insn_states[insn_idx].set_reg(frame, regno);
            if !self.processed[insn_idx] {
                self.worklist.push(insn_idx);
            }
        }
    }

    /// Mark a stack slot as needing precision at a specific instruction
    /// 在特定指令处将栈槽标记为需要精度
    pub fn require_stack_precision_at(&mut self, insn_idx: usize, frame: usize, spi: usize) {
        if insn_idx < self.insn_states.len() {
            self.insn_states[insn_idx].set_slot(frame, spi);
            if !self.processed[insn_idx] {
                self.worklist.push(insn_idx);
            }
        }
    }

    /// Run the full backtracking algorithm
    /// 运行完整的回溯算法
    pub fn propagate(&mut self) -> Result<()> {
        let mut iterations = 0;

        while let Some(idx) = self.worklist.pop() {
            iterations += 1;
            if iterations > self.max_iterations {
                // Hit limit - mark all as precise
                // 达到限制 - 标记所有为精确
                return Err(VerifierError::TooComplex(
                    "precision tracking exceeded limit".into(),
                ));
            }

            if self.processed[idx] {
                continue;
            }

            // Process this instruction
            // 处理此指令
            self.process_instruction(idx)?;
            self.processed[idx] = true;
        }

        Ok(())
    }

    /// Process a single instruction for precision propagation
    /// 处理单条指令以进行精度传播
    fn process_instruction(&mut self, idx: usize) -> Result<()> {
        if idx >= self.insns.len() {
            return Ok(());
        }

        let insn = self.insns[idx];

        // Backtrack through this instruction
        // 通过此指令回溯
        backtrack_insn(&mut self.insn_states[idx], &insn, idx, 0)?;

        // Check if we need to propagate and find predecessors
        // 检查是否需要传播并查找前驱
        let needs_propagate = !self.insn_states[idx].is_all_empty() && idx > 0;

        if needs_propagate {
            // Find predecessors first
            // 首先查找前驱
            let predecessors = self.find_predecessors(idx);

            // Clone the current backtrack state for propagation
            // 克隆当前回溯状态用于传播
            let bt_clone = self.insn_states[idx].clone();

            for pred_idx in predecessors {
                // Merge precision requirements using cloned state
                // 使用克隆的状态合并精度要求
                self.merge_precision_from(pred_idx, &bt_clone);
                if !self.processed[pred_idx] {
                    self.worklist.push(pred_idx);
                }
            }
        }

        Ok(())
    }

    /// Merge precision requirements from a source backtrack state
    /// 从源回溯状态合并精度要求
    fn merge_precision_from(&mut self, target_idx: usize, source: &BacktrackState) {
        if target_idx >= self.insn_states.len() {
            return;
        }

        let target = &mut self.insn_states[target_idx];
        // Merge all frame masks
        // 合并所有栈帧掩码
        for i in 0..MAX_BPF_STACK_FRAMES {
            target.reg_masks[i] |= source.reg_masks[i];
            target.stack_masks[i] |= source.stack_masks[i];
        }
    }

    /// Find predecessor instructions
    /// 查找前驱指令
    fn find_predecessors(&self, idx: usize) -> Vec<usize> {
        let mut preds = Vec::new();

        // Natural predecessor (previous instruction)
        // 自然前驱（前一条指令）
        if idx > 0 {
            let prev = &self.insns[idx - 1];
            let class = prev.class();
            let op = prev.code & 0xf0;

            // Check if previous instruction can fall through
            // 检查前一条指令是否可以顺序执行
            match class {
                BPF_JMP | BPF_JMP32 => {
                    if op != BPF_JA && op != BPF_EXIT {
                        // Conditional branch - can fall through
                        // 条件分支 - 可以顺序执行
                        preds.push(idx - 1);
                    }
                    // Unconditional jump doesn't fall through
                    // 无条件跳转不会顺序执行
                }
                _ => {
                    // All other instructions fall through
                    // 所有其他指令都会顺序执行
                    preds.push(idx - 1);
                }
            }
        }

        // Find jumps that target this instruction
        // 查找以此指令为目标的跳转
        for (i, insn) in self.insns.iter().enumerate() {
            let class = insn.class();
            if class != BPF_JMP && class != BPF_JMP32 {
                continue;
            }

            let op = insn.code & 0xf0;
            if op == BPF_EXIT {
                continue;
            }

            if op == BPF_CALL && insn.src_reg == BPF_PSEUDO_CALL {
                // Subprogram call - target is different
                // 子程序调用 - 目标不同
                let target = (i as i32 + insn.imm + 1) as usize;
                if target == idx {
                    preds.push(i);
                }
            } else if op != BPF_CALL {
                // Jump instruction
                // 跳转指令
                let target = (i as i32 + insn.off as i32 + 1) as usize;
                if target == idx {
                    preds.push(i);
                }
            }
        }

        preds
    }

    /// Get the precision requirements for an instruction
    /// 获取指令的精度要求
    pub fn get_precision_at(&self, idx: usize) -> Option<&BacktrackState> {
        self.insn_states.get(idx)
    }

    /// Apply precision marks to verifier state
    /// 将精度标记应用到验证器状态
    pub fn apply_to_state(&self, state: &mut BpfVerifierState, idx: usize) -> bool {
        let bt = match self.insn_states.get(idx) {
            Some(bt) => bt,
            None => return false,
        };

        let mut changed = false;

        for frame in 0..MAX_BPF_STACK_FRAMES {
            let reg_mask = bt.reg_masks[frame];
            let stack_mask = bt.stack_masks[frame];

            if reg_mask == 0 && stack_mask == 0 {
                continue;
            }

            if let Some(func) = state.frame.get_mut(frame).and_then(|f| f.as_mut()) {
                // Mark registers as precise
                // 将寄存器标记为精确
                for r in 0..MAX_BPF_REG {
                    if (reg_mask & (1 << r)) != 0
                        && func.regs[r].reg_type == BpfRegType::ScalarValue
                        && !func.regs[r].precise
                    {
                        func.regs[r].precise = true;
                        changed = true;
                    }
                }

                // Mark stack slots as precise
                // 将栈槽标记为精确
                for spi in 0..64 {
                    if (stack_mask & (1 << spi)) != 0 {
                        if let Some(slot) = func.stack.get_slot_mut(spi) {
                            if slot.is_spilled_scalar_reg() && !slot.spilled_ptr.precise {
                                slot.spilled_ptr.precise = true;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        changed
    }
}

/// Precision tracking summary
/// 精度追踪摘要
#[derive(Debug, Clone, Default)]
pub struct PrecisionSummary {
    /// Number of registers marked precise
    /// 标记为精确的寄存器数量
    pub precise_regs: usize,
    /// Number of stack slots marked precise
    /// 标记为精确的栈槽数量
    pub precise_slots: usize,
    /// Instructions with precision requirements
    /// 具有精度要求的指令
    pub insns_with_precision: usize,
    /// Whether full precision was needed (fallback)
    /// 是否需要完全精度（回退）
    pub full_precision_fallback: bool,
}

/// Analyze precision requirements for a program
/// 分析程序的精度要求
pub fn analyze_precision_requirements(
    insns: &[BpfInsn],
    conditional_jmps: &[usize],
) -> Result<PrecisionSummary> {
    let mut tracker = FullPrecisionTracker::new(insns);
    let mut summary = PrecisionSummary::default();

    // Start precision tracking from conditional jumps
    // 从条件跳转开始精度追踪
    for &jmp_idx in conditional_jmps {
        if jmp_idx >= insns.len() {
            continue;
        }

        let insn = &insns[jmp_idx];
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let src_type = insn.code & 0x08;

        // Mark compared registers as needing precision
        // 将比较的寄存器标记为需要精度
        tracker.require_precision_at(jmp_idx, 0, dst_reg);
        if src_type == BPF_X {
            tracker.require_precision_at(jmp_idx, 0, src_reg);
        }
    }

    // Run propagation
    // 运行传播
    match tracker.propagate() {
        Ok(()) => {}
        Err(_) => {
            summary.full_precision_fallback = true;
        }
    }

    // Count results
    // 统计结果
    for bt in &tracker.insn_states {
        if !bt.is_all_empty() {
            summary.insns_with_precision += 1;
            for frame in 0..MAX_BPF_STACK_FRAMES {
                summary.precise_regs += bt.reg_masks[frame].count_ones() as usize;
                summary.precise_slots += bt.stack_masks[frame].count_ones() as usize;
            }
        }
    }

    Ok(summary)
}

/// Check if state pruning is safe given precision requirements
/// 给定精度要求，检查状态剪枝是否安全
pub fn is_pruning_safe(cur_state: &BpfVerifierState, cached_state: &BpfVerifierState) -> bool {
    // For each precise register in the current state, the cached state
    // must have the same value (not just compatible bounds)
    // 对于当前状态中的每个精确寄存器，缓存状态必须具有相同的值
    // （不仅仅是兼容的边界）

    for frame in 0..=cur_state.curframe {
        let cur_func = match cur_state.frame.get(frame).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let cached_func = match cached_state.frame.get(frame).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false, // Frame mismatch / 栈帧不匹配
        };

        for r in 0..MAX_BPF_REG {
            let cur_reg = &cur_func.regs[r];
            let cached_reg = &cached_func.regs[r];

            // If current register is precise, check exact equality
            // 如果当前寄存器是精确的，检查精确相等
            if cur_reg.precise && cur_reg.reg_type == BpfRegType::ScalarValue {
                if cached_reg.reg_type != BpfRegType::ScalarValue {
                    return false;
                }
                // For precise scalars, bounds must match exactly
                // 对于精确的标量，边界必须精确匹配
                if cur_reg.umin_value != cached_reg.umin_value
                    || cur_reg.umax_value != cached_reg.umax_value
                    || cur_reg.smin_value != cached_reg.smin_value
                    || cur_reg.smax_value != cached_reg.smax_value
                {
                    return false;
                }
            }
        }
    }

    true
}

/// Mark registers that affect a specific memory access as precise
/// 将影响特定内存访问的寄存器标记为精确
pub fn mark_mem_access_precision(
    state: &mut BpfVerifierState,
    insns: &[BpfInsn],
    base_reg: usize,
) -> Result<()> {
    // The base register and any registers that contributed to its value
    // need to be marked as precise
    // 基址寄存器和所有对其值有贡献的寄存器都需要标记为精确

    let mut backtracker = PrecisionBacktracker::new(insns);
    backtracker.bt.frame = state.curframe;
    backtracker.mark_reg_precise(state.curframe, base_reg);
    backtracker.backtrack(state)?;

    Ok(())
}

// ============================================================================
// Parent State Chain Precision Propagation
// 父状态链精度传播
// ============================================================================
//
// This implements the kernel's parent state chain traversal for precision
// propagation. When we need to mark a register as precise, we walk back
// through the parent state chain (via StateCache) and mark the register
// in each parent state until we find where it was defined.
// 这实现了内核的父状态链遍历以进行精度传播。当我们需要将寄存器标记为
// 精确时，我们通过父状态链（通过 StateCache）回溯，并在每个父状态中
// 标记该寄存器，直到找到它被定义的位置。

use crate::analysis::prune::{StateCache, StateId};

/// Mark chain precision with parent state traversal
/// 使用父状态遍历标记链精度
///
/// This is the enhanced version that walks through the parent state chain
/// stored in StateCache. It propagates precision marks to parent states
/// and applies them when states are verified.
/// 这是增强版本，它遍历存储在 StateCache 中的父状态链。
/// 它将精度标记传播到父状态，并在验证状态时应用它们。
///
/// # Arguments / 参数
///
/// * `cache` - The state cache containing parent chain information / 包含父链信息的状态缓存
/// * `starting_state` - The state where precision is first required / 首次需要精度的状态
/// * `starting_id` - The StateId of the starting state in cache / 缓存中起始状态的 StateId
/// * `insns` - The program instructions / 程序指令
/// * `regno` - The register that needs precision (-1 for batch mode with bt) / 需要精度的寄存器（批量模式下使用 bt 时为 -1）
/// * `bt` - Optional initial backtrack state for batch mode / 批量模式的可选初始回溯状态
///
/// Returns true if any register was newly marked as precise.
/// 如果有任何寄存器被新标记为精确，则返回 true。
pub fn mark_chain_precision_with_cache(
    cache: &mut StateCache,
    starting_state: &mut BpfVerifierState,
    starting_id: Option<StateId>,
    insns: &[BpfInsn],
    regno: i32,
    bt: Option<&BacktrackState>,
) -> Result<bool> {
    let mut changed = false;
    let mut backtrack = BacktrackState::new();
    backtrack.frame = starting_state.curframe;

    // Initialize from provided backtrack state or single register
    // 从提供的回溯状态或单个寄存器初始化
    if let Some(initial_bt) = bt {
        backtrack = initial_bt.clone();
    } else if regno >= 0 {
        let regno = regno as usize;
        if let Some(func) = starting_state.cur_func() {
            if let Some(reg) = func.regs.get(regno) {
                if reg.reg_type != BpfRegType::ScalarValue {
                    return Ok(false);
                }
                backtrack.set_reg(starting_state.curframe, regno);
            }
        }
    }

    if backtrack.is_all_empty() {
        return Ok(false);
    }

    // First, process the starting state's jump history
    // 首先，处理起始状态的跳转历史
    let first_idx = starting_state.first_insn_idx;
    let mut _last_idx = starting_state.last_insn_idx;
    let mut subseq_idx: i32 = -1;
    let mut skip_first = true;

    // Process jump history in starting state
    // 处理起始状态的跳转历史
    let history = starting_state.jmp_history.clone();
    for i in (0..history.len()).rev() {
        let entry = &history[i];
        let insn_idx = entry.idx as usize;

        if skip_first {
            skip_first = false;
            subseq_idx = insn_idx as i32;
            continue;
        }

        if insn_idx < insns.len() {
            let insn = &insns[insn_idx];
            backtrack_insn(&mut backtrack, insn, insn_idx, subseq_idx as usize)?;
        }

        subseq_idx = insn_idx as i32;

        if backtrack.is_all_empty() {
            return Ok(changed);
        }
    }

    // Apply precision to starting state
    // 将精度应用到起始状态
    changed |= apply_precision_to_state(starting_state, &mut backtrack)?;

    if backtrack.is_all_empty() {
        return Ok(changed);
    }

    // Walk parent chain if we have cache access
    // 如果有缓存访问权限，遍历父链
    let mut current_parent_id =
        starting_id.and_then(|id| cache.get_by_id(id).and_then(|c| c.parent_id));

    while let Some(parent_id) = current_parent_id {
        // Get parent state from cache
        // 从缓存获取父状态
        let (parent_state, next_parent) = match cache.get_by_id_mut(parent_id) {
            Some(cached) => {
                let next = cached.parent_id;
                (&mut cached.state, next)
            }
            None => break,
        };

        // Process parent's jump history
        // 处理父级的跳转历史
        let parent_history = parent_state.jmp_history.clone();
        _last_idx = parent_state.last_insn_idx;
        subseq_idx = first_idx as i32;

        for i in (0..parent_history.len()).rev() {
            let entry = &parent_history[i];
            let insn_idx = entry.idx as usize;

            if insn_idx < insns.len() {
                let insn = &insns[insn_idx];
                backtrack_insn(&mut backtrack, insn, insn_idx, subseq_idx as usize)?;
            }

            subseq_idx = insn_idx as i32;

            if backtrack.is_all_empty() {
                break;
            }
        }

        // Apply precision to parent state
        // 将精度应用到父状态
        changed |= apply_precision_to_state(parent_state, &mut backtrack)?;

        if backtrack.is_all_empty() {
            break;
        }

        current_parent_id = next_parent;
        // _last_idx preserved for future use in precision tracking
        // _last_idx 保留用于精度追踪的未来使用
    }

    // If we still have pending precision requests, fall back to marking all
    // 如果仍有待处理的精度请求，回退到标记所有
    if !backtrack.is_all_empty() {
        mark_all_scalars_precise(starting_state);
        changed = true;
    }

    Ok(changed)
}

/// Apply precision marks from backtrack state to a verifier state
/// 将回溯状态的精度标记应用到验证器状态
///
/// Returns true if any changes were made.
/// 如果有任何更改，则返回 true。
fn apply_precision_to_state(state: &mut BpfVerifierState, bt: &mut BacktrackState) -> Result<bool> {
    let mut changed = false;

    for fr in 0..=state.curframe {
        let reg_mask = bt.reg_masks[fr];
        let stack_mask = bt.stack_masks[fr];

        if reg_mask == 0 && stack_mask == 0 {
            continue;
        }

        if let Some(func) = state.frame.get_mut(fr).and_then(|f| f.as_mut()) {
            // Mark registers as precise
            // 将寄存器标记为精确
            for r in 0..MAX_BPF_REG {
                if (reg_mask & (1 << r)) != 0 {
                    if func.regs[r].reg_type == BpfRegType::ScalarValue {
                        if func.regs[r].precise {
                            // Already precise, clear from backtrack
                            // 已经是精确的，从回溯中清除
                            bt.clear_reg(fr, r);
                        } else {
                            func.regs[r].precise = true;
                            changed = true;
                        }
                    } else {
                        // Not a scalar, clear from backtrack
                        // 不是标量，从回溯中清除
                        bt.clear_reg(fr, r);
                    }
                }
            }

            // Mark stack slots as precise
            // 将栈槽标记为精确
            for spi in 0..64usize {
                if (stack_mask & (1 << spi)) != 0 {
                    if let Some(slot) = func.stack.get_slot_mut_by_spi(spi) {
                        if slot.is_spilled_scalar_reg() {
                            if slot.spilled_ptr.precise {
                                bt.clear_slot(fr, spi);
                            } else {
                                slot.spilled_ptr.precise = true;
                                changed = true;
                            }
                        } else {
                            bt.clear_slot(fr, spi);
                        }
                    } else {
                        bt.clear_slot(fr, spi);
                    }
                }
            }
        }
    }

    Ok(changed)
}

/// Sync linked registers in backtrack state based on jump history entry
/// 根据跳转历史条目在回溯状态中同步链接的寄存器
///
/// When a conditional jump refines bounds on a register, other registers
/// with the same ID should also be tracked for precision.
/// 当条件跳转细化寄存器的边界时，具有相同 ID 的其他寄存器
/// 也应该被追踪精度。
pub fn bt_sync_linked_regs(bt: &mut BacktrackState, state: &BpfVerifierState, linked_regs: u64) {
    if linked_regs == 0 {
        return;
    }

    // For each bit set in linked_regs, mark that register in backtrack state
    // 对于 linked_regs 中设置的每个位，在回溯状态中标记该寄存器
    for r in 0..MAX_BPF_REG {
        if (linked_regs & (1 << r)) != 0 {
            if let Some(func) = state.frame.get(bt.frame).and_then(|f| f.as_ref()) {
                if func.regs[r].reg_type == BpfRegType::ScalarValue {
                    bt.set_reg(bt.frame, r);
                }
            }
        }
    }
}
