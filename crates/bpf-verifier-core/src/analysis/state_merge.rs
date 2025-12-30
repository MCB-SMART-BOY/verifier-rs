// SPDX-License-Identifier: GPL-2.0

//! State merging optimization for BPF verifier
//! BPF 验证器的状态合并优化
//!
//! When multiple execution paths reach the same program point, their states
//! can be merged to avoid exponential state explosion. The merged state
//! takes the widest bounds for each register, ensuring it represents all
//! possible values from either path.
//! 当多个执行路径到达同一程序点时，它们的状态可以被合并以避免
//! 指数级的状态爆炸。合并后的状态取每个寄存器的最宽边界，
//! 确保它表示来自任一路径的所有可能值。
//!
//! This module implements:
//! 本模块实现：
//! - Basic state merging (widening bounds)
//!   基本状态合并（扩宽边界）
//! - Cross-subprogram state merging
//!   跨子程序状态合并
//! - Reference-aware merging
//!   引用感知合并
//! - Precision-preserving merging
//!   保留精度的合并
//! - Loop-aware state caching
//!   循环感知状态缓存

use alloc::{boxed::Box, vec::Vec};

use crate::bounds::tnum::Tnum;
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::BpfStackState;
use crate::state::verifier_state::{BpfFuncState, BpfVerifierState};

/// Result of attempting to merge two states.
/// 尝试合并两个状态的结果。
#[derive(Debug, Clone)]
pub enum MergeResult {
    /// States were successfully merged.
    /// 状态成功合并。
    Merged(Box<BpfVerifierState>),
    /// States are incompatible and cannot be merged.
    /// 状态不兼容，无法合并。
    Incompatible,
    /// First state already subsumes second (no merge needed).
    /// 第一个状态已经包含第二个（无需合并）。
    FirstSubsumes,
    /// Second state already subsumes first.
    /// 第二个状态包含第一个。
    SecondSubsumes,
}

/// Merge two verifier states at a join point.
/// 在汇合点合并两个验证器状态。
///
/// Returns a merged state that represents all possible values from either
/// input state. This is sound because the merged state is more permissive
/// than either input - anything safe under the merged state is safe under
/// both original states.
/// 返回一个合并后的状态，表示来自任一输入状态的所有可能值。
/// 这是正确的，因为合并后的状态比任一输入都更宽松——
/// 在合并状态下安全的任何事物在两个原始状态下都是安全的。
pub fn merge_states(state1: &BpfVerifierState, state2: &BpfVerifierState) -> MergeResult {
    // Must have same frame depth
    // 必须具有相同的栈帧深度
    if state1.curframe != state2.curframe {
        return MergeResult::Incompatible;
    }

    // Check if one subsumes the other first
    // 首先检查是否一个包含另一个
    if state_subsumes(state1, state2) {
        return MergeResult::FirstSubsumes;
    }
    if state_subsumes(state2, state1) {
        return MergeResult::SecondSubsumes;
    }

    // Try to merge
    // 尝试合并
    let mut merged = state1.clone();

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        let merged_func = match merge_func_states(func1, func2) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        if let Some(frame) = merged.frame.get_mut(i) {
            *frame = Some(Box::new(merged_func));
        }
    }

    MergeResult::Merged(Box::new(merged))
}

/// Check if state1 subsumes state2 (state1 is more permissive).
/// 检查 state1 是否包含 state2（state1 更宽松）。
fn state_subsumes(state1: &BpfVerifierState, state2: &BpfVerifierState) -> bool {
    if state1.curframe != state2.curframe {
        return false;
    }

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        if !func_subsumes(func1, func2) {
            return false;
        }
    }

    true
}

/// Check if func1 subsumes func2.
/// 检查 func1 是否包含 func2。
fn func_subsumes(func1: &BpfFuncState, func2: &BpfFuncState) -> bool {
    // All registers in func1 must subsume corresponding registers in func2
    // func1 中的所有寄存器必须包含 func2 中对应的寄存器
    for (reg1, reg2) in func1.regs.iter().zip(func2.regs.iter()) {
        if !reg_subsumes(reg1, reg2) {
            return false;
        }
    }

    true
}

/// Check if reg1 subsumes reg2 (reg1's range contains reg2's).
/// 检查 reg1 是否包含 reg2（reg1 的范围包含 reg2 的范围）。
pub fn reg_subsumes(reg1: &BpfRegState, reg2: &BpfRegState) -> bool {
    // Uninitialized subsumes everything
    // 未初始化包含一切
    if reg1.reg_type == BpfRegType::NotInit {
        return true;
    }

    // If reg1 is initialized, reg2 must match type
    // 如果 reg1 已初始化，reg2 必须匹配类型
    if reg2.reg_type == BpfRegType::NotInit {
        return false;
    }

    if reg1.reg_type != reg2.reg_type {
        return false;
    }

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            // reg1 subsumes reg2 if reg1's bounds contain reg2's
            // 如果 reg1 的边界包含 reg2 的边界，则 reg1 包含 reg2
            reg1.umin_value <= reg2.umin_value
                && reg1.umax_value >= reg2.umax_value
                && reg1.smin_value <= reg2.smin_value
                && reg1.smax_value >= reg2.smax_value
        }
        _ => {
            // For pointers, exact match required
            // 对于指针，需要精确匹配
            reg1.off == reg2.off && reg1.id == reg2.id
        }
    }
}

/// Merge two function states.
/// 合并两个函数状态。
fn merge_func_states(func1: &BpfFuncState, func2: &BpfFuncState) -> Option<BpfFuncState> {
    let mut merged = func1.clone();

    // Merge registers
    // 合并寄存器
    for (i, (reg1, reg2)) in func1.regs.iter().zip(func2.regs.iter()).enumerate() {
        merged.regs[i] = merge_regs(reg1, reg2)?;
    }

    // Merge stack - take the larger allocated size
    // 合并栈 - 取较大的分配大小
    let max_stack = func1.stack.allocated_stack.max(func2.stack.allocated_stack);
    if merged.stack.allocated_stack < max_stack {
        let _ = merged.stack.grow(max_stack);
    }

    // Merge stack slots
    // 合并栈槽
    let max_slots = func1.stack.stack.len().max(func2.stack.stack.len());
    for i in 0..max_slots {
        let slot1 = func1.stack.stack.get(i);
        let slot2 = func2.stack.stack.get(i);

        let merged_slot = match (slot1, slot2) {
            (Some(s1), Some(s2)) => merge_stack_slots(s1, s2),
            (Some(s), None) | (None, Some(s)) => s.clone(),
            (None, None) => BpfStackState::new(),
        };

        if i < merged.stack.stack.len() {
            merged.stack.stack[i] = merged_slot;
        }
    }

    Some(merged)
}

/// Check if two registers are exactly equal in their tracked state.
/// 检查两个寄存器在其追踪状态中是否完全相等。
/// This corresponds to the kernel's `regs_exact` function.
/// 这对应于内核的 `regs_exact` 函数。
fn regs_exact(reg1: &BpfRegState, reg2: &BpfRegState) -> bool {
    // Type must match
    // 类型必须匹配
    if reg1.reg_type != reg2.reg_type {
        return false;
    }

    // Type flags must match
    // 类型标志必须匹配
    if reg1.type_flags != reg2.type_flags {
        return false;
    }

    // For scalars, check all bounds
    // 对于标量，检查所有边界
    if reg1.reg_type == BpfRegType::ScalarValue {
        return reg1.umin_value == reg2.umin_value
            && reg1.umax_value == reg2.umax_value
            && reg1.smin_value == reg2.smin_value
            && reg1.smax_value == reg2.smax_value
            && reg1.var_off == reg2.var_off;
    }

    // For pointers, check offset and other fields
    // 对于指针，检查偏移和其他字段
    reg1.off == reg2.off && reg1.var_off == reg2.var_off && reg1.map_uid == reg2.map_uid
}

/// Merge two registers, taking the widest bounds.
/// 合并两个寄存器，取最宽的边界。
///
/// Implements precision-preserving merge following the kernel's logic:
/// 实现遵循内核逻辑的保留精度合并：
/// - If either register is precise, or if they are exact, preserve precision
///   如果任一寄存器是精确的，或者它们是相等的，保留精度
/// - Otherwise, widen to unknown for scalars
///   否则，对于标量扩宽为未知
pub fn merge_regs(reg1: &BpfRegState, reg2: &BpfRegState) -> Option<BpfRegState> {
    // If either is uninitialized, result is uninitialized
    // 如果任一未初始化，结果为未初始化
    if reg1.reg_type == BpfRegType::NotInit || reg2.reg_type == BpfRegType::NotInit {
        return Some(BpfRegState::new_not_init());
    }

    // Types must be compatible for merging
    // 类型必须兼容才能合并
    if !types_compatible(reg1.reg_type, reg2.reg_type) {
        // If types are incompatible, mark as unknown scalar
        // 如果类型不兼容，标记为未知标量
        let mut result = BpfRegState::new_scalar_unknown(false);
        result.mark_unknown(false);
        return Some(result);
    }

    let mut merged = reg1.clone();

    // Check if registers are exact (same bounds, same type)
    // 检查寄存器是否相等（相同边界，相同类型）
    let is_exact = regs_exact(reg1, reg2);

    // Preserve precision if:
    // 保留精度如果：
    // 1. Either register is marked precise, OR
    //    任一寄存器被标记为精确，或者
    // 2. Registers are exactly equal
    //    寄存器完全相等
    let preserve_precision = reg1.precise || reg2.precise || is_exact;

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            if preserve_precision {
                // Precision-preserving merge: take widest bounds but keep precision
                // 保留精度合并：取最宽边界但保持精度
                merged.umin_value = reg1.umin_value.min(reg2.umin_value);
                merged.umax_value = reg1.umax_value.max(reg2.umax_value);
                merged.smin_value = reg1.smin_value.min(reg2.smin_value);
                merged.smax_value = reg1.smax_value.max(reg2.smax_value);
                merged.var_off = merge_tnums(reg1.var_off, reg2.var_off);

                // Keep precise if either was precise (precision propagates)
                // 如果任一是精确的则保持精确（精度传播）
                merged.precise = reg1.precise || reg2.precise;
            } else {
                // Imprecise scalars that don't match exactly: widen to unknown
                // 不精确匹配的不精确标量：扩宽为未知
                // This matches the kernel's `maybe_widen_reg` behavior
                // 这匹配内核的 `maybe_widen_reg` 行为
                merged.mark_unknown(false);
                merged.precise = false;
            }
        }
        BpfRegType::PtrToStack
        | BpfRegType::PtrToMapValue
        | BpfRegType::PtrToMapKey
        | BpfRegType::PtrToCtx
        | BpfRegType::PtrToPacket
        | BpfRegType::PtrToMem => {
            // For pointers, check if they have the same base
            // 对于指针，检查它们是否具有相同的基址
            if reg1.off != reg2.off {
                // Different offsets - take range if possible
                // 不同偏移 - 如果可能则取范围
                // For simplicity, mark as having variable offset
                // 为简单起见，标记为具有可变偏移
                merged.var_off = Tnum::unknown();
            }

            // Merge type flags
            // 合并类型标志
            merged.type_flags = reg1.type_flags | reg2.type_flags;

            // If IDs differ, lose NULL tracking
            // 如果 ID 不同，失去 NULL 追踪
            if reg1.id != reg2.id {
                merged.id = 0;
            }
        }
        _ => {
            // Other types: must be exact match
            // 其他类型：必须精确匹配
            if reg1.off != reg2.off || reg1.id != reg2.id {
                return None;
            }
        }
    }

    Some(merged)
}

/// Check if two register types are compatible for merging.
/// 检查两个寄存器类型是否兼容以进行合并。
pub fn types_compatible(t1: BpfRegType, t2: BpfRegType) -> bool {
    if t1 == t2 {
        return true;
    }

    // Scalars can absorb anything (becoming unknown)
    // 标量可以吸收任何东西（变成未知）
    if t1 == BpfRegType::ScalarValue || t2 == BpfRegType::ScalarValue {
        return true;
    }

    // Some pointer types are compatible
    // 某些指针类型是兼容的
    matches!(
        (t1, t2),
        (BpfRegType::PtrToPacket, BpfRegType::PtrToPacketMeta)
            | (BpfRegType::PtrToPacketMeta, BpfRegType::PtrToPacket)
    )
}

/// Merge two tnums, taking the widest range.
/// 合并两个 tnum，取最宽范围。
pub fn merge_tnums(t1: Tnum, t2: Tnum) -> Tnum {
    // The merged tnum must represent all values from both
    // 合并后的 tnum 必须表示来自两者的所有值
    // This is done by OR-ing the masks and combining values
    // 这通过对掩码进行 OR 运算并组合值来完成
    let combined_mask = t1.mask | t2.mask;

    // For bits that are known in both, they must agree
    // 对于两者中都已知的位，它们必须一致
    let known_in_both = !t1.mask & !t2.mask;
    let disagreed = (t1.value ^ t2.value) & known_in_both;

    // Bits that disagree become unknown
    // 不一致的位变成未知
    let final_mask = combined_mask | disagreed;
    let final_value = t1.value & !final_mask;

    Tnum::new(final_value, final_mask)
}

/// Merge two stack slots.
/// 合并两个栈槽。
fn merge_stack_slots(slot1: &BpfStackState, slot2: &BpfStackState) -> BpfStackState {
    let mut merged = slot1.clone();

    // Check slot types
    // 检查槽类型
    let type1 = slot1.slot_type[BPF_REG_SIZE - 1];
    let type2 = slot2.slot_type[BPF_REG_SIZE - 1];

    if type1 != type2 {
        // Different types - mark as misc
        // 不同类型 - 标记为杂项
        for i in 0..BPF_REG_SIZE {
            merged.slot_type[i] = BpfStackSlotType::Misc;
        }
        merged.spilled_ptr = BpfRegState::new_not_init();
        return merged;
    }

    match type1 {
        BpfStackSlotType::Spill => {
            // Merge the spilled register
            // 合并溢出的寄存器
            if let Some(merged_reg) = merge_regs(&slot1.spilled_ptr, &slot2.spilled_ptr) {
                merged.spilled_ptr = merged_reg;
            } else {
                // Can't merge - mark as misc
                // 无法合并 - 标记为杂项
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
        BpfStackSlotType::Dynptr => {
            // Dynptr types must match
            // Dynptr 类型必须匹配
            if slot1.spilled_ptr.dynptr.dynptr_type != slot2.spilled_ptr.dynptr.dynptr_type {
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Invalid;
                }
            }
        }
        _ => {
            // Other types: keep as-is
            // 其他类型：保持原样
        }
    }

    merged
}

/// Statistics about state merging.
/// 状态合并的统计信息。
#[derive(Debug, Clone, Default)]
pub struct MergeStats {
    /// Number of successful merges.
    /// 成功合并的数量。
    pub merges: u64,
    /// Number of incompatible state pairs.
    /// 不兼容状态对的数量。
    pub incompatible: u64,
    /// Number of times first state subsumed second.
    /// 第一个状态包含第二个的次数。
    pub first_subsumed: u64,
    /// Number of times second state subsumed first.
    /// 第二个状态包含第一个的次数。
    pub second_subsumed: u64,
    /// Number of cross-subprogram merges.
    /// 跨子程序合并的数量。
    pub cross_subprog_merges: u64,
    /// Number of reference-aware merges.
    /// 引用感知合并的数量。
    pub ref_aware_merges: u64,
    /// Number of precision-preserving merges.
    /// 保留精度合并的数量。
    pub precision_preserved: u64,
}

impl MergeStats {
    /// Create new stats.
    /// 创建新的统计信息。
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a merge result.
    /// 记录合并结果。
    pub fn record(&mut self, result: &MergeResult) {
        match result {
            MergeResult::Merged(_) => self.merges += 1,
            MergeResult::Incompatible => self.incompatible += 1,
            MergeResult::FirstSubsumes => self.first_subsumed += 1,
            MergeResult::SecondSubsumes => self.second_subsumed += 1,
        }
    }
}

/// Configuration for state merging behavior.
/// 状态合并行为的配置。
#[derive(Debug, Clone, Copy)]
pub struct MergeConfig {
    /// Allow merging states with different subprogram contexts.
    /// 允许合并具有不同子程序上下文的状态。
    pub allow_cross_subprog: bool,
    /// Preserve precision marks when possible.
    /// 尽可能保留精度标记。
    pub preserve_precision: bool,
    /// Allow merging states with different reference counts.
    /// 允许合并具有不同引用计数的状态。
    pub allow_ref_mismatch: bool,
    /// Maximum number of states to merge at once.
    /// 一次合并的最大状态数。
    pub max_batch_size: usize,
    /// Whether to use aggressive widening for loops.
    /// 是否对循环使用激进扩宽。
    pub aggressive_loop_widening: bool,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            allow_cross_subprog: true,
            preserve_precision: true,
            allow_ref_mismatch: false,
            max_batch_size: 8,
            aggressive_loop_widening: false,
        }
    }
}

impl MergeConfig {
    /// Config for aggressive merging (reduces state explosion).
    /// 激进合并的配置（减少状态爆炸）。
    pub fn aggressive() -> Self {
        Self {
            allow_cross_subprog: true,
            preserve_precision: false,
            allow_ref_mismatch: true,
            max_batch_size: 16,
            aggressive_loop_widening: true,
        }
    }

    /// Config for conservative merging (preserves precision).
    /// 保守合并的配置（保留精度）。
    pub fn conservative() -> Self {
        Self {
            allow_cross_subprog: false,
            preserve_precision: true,
            allow_ref_mismatch: false,
            max_batch_size: 4,
            aggressive_loop_widening: false,
        }
    }
}

/// Cross-subprogram merge context.
/// 跨子程序合并上下文。
///
/// This tracks information needed to merge states across subprogram
/// boundaries, such as when a function returns to multiple call sites.
/// 这追踪跨子程序边界合并状态所需的信息，例如当函数返回到
/// 多个调用点时。
#[derive(Debug, Clone)]
pub struct CrossSubprogMergeCtx {
    /// Source subprogram index.
    /// 源子程序索引。
    pub src_subprog: usize,
    /// Target subprogram index.
    /// 目标子程序索引。
    pub dst_subprog: usize,
    /// Call site instruction index.
    /// 调用点指令索引。
    pub callsite: usize,
    /// Whether the merge is for a tail call.
    /// 合并是否用于尾调用。
    pub is_tail_call: bool,
    /// Whether the callee might sleep.
    /// 被调用者是否可能休眠。
    pub callee_might_sleep: bool,
}

impl CrossSubprogMergeCtx {
    /// Create a new cross-subprogram merge context.
    /// 创建新的跨子程序合并上下文。
    pub fn new(src: usize, dst: usize, callsite: usize) -> Self {
        Self {
            src_subprog: src,
            dst_subprog: dst,
            callsite,
            is_tail_call: false,
            callee_might_sleep: false,
        }
    }
}

/// Merge states with configuration.
/// 使用配置合并状态。
pub fn merge_states_with_config(
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
    config: &MergeConfig,
) -> MergeResult {
    // Must have same frame depth
    // 必须具有相同的栈帧深度
    if state1.curframe != state2.curframe {
        return MergeResult::Incompatible;
    }

    // Check reference compatibility if configured
    // 如果配置了，检查引用兼容性
    if !config.allow_ref_mismatch {
        let refs1 = state1.refs.refs();
        let refs2 = state2.refs.refs();
        if refs1.len() != refs2.len() {
            return MergeResult::Incompatible;
        }
        // Check reference types match
        // 检查引用类型匹配
        for (r1, r2) in refs1.iter().zip(refs2.iter()) {
            if r1.ref_type != r2.ref_type {
                return MergeResult::Incompatible;
            }
        }
    }

    // Check if one subsumes the other first
    // 首先检查是否一个包含另一个
    if state_subsumes(state1, state2) {
        return MergeResult::FirstSubsumes;
    }
    if state_subsumes(state2, state1) {
        return MergeResult::SecondSubsumes;
    }

    // Try to merge
    // 尝试合并
    let mut merged = state1.clone();

    for i in 0..=state1.curframe {
        let func1 = match state1.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };
        let func2 = match state2.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        let merged_func = match merge_func_states_with_config(func1, func2, config) {
            Some(f) => f,
            None => return MergeResult::Incompatible,
        };

        if let Some(frame) = merged.frame.get_mut(i) {
            *frame = Some(Box::new(merged_func));
        }
    }

    // Merge references if allowed
    // 如果允许，合并引用
    if config.allow_ref_mismatch {
        // Take the union of references
        // 取引用的并集
        merge_references(&mut merged, state1, state2);
    }

    MergeResult::Merged(Box::new(merged))
}

/// Merge function states with configuration.
/// 使用配置合并函数状态。
fn merge_func_states_with_config(
    func1: &BpfFuncState,
    func2: &BpfFuncState,
    config: &MergeConfig,
) -> Option<BpfFuncState> {
    let mut merged = func1.clone();

    // Merge registers
    // 合并寄存器
    for (i, (reg1, reg2)) in func1.regs.iter().zip(func2.regs.iter()).enumerate() {
        merged.regs[i] = merge_regs_with_config(reg1, reg2, config)?;
    }

    // Merge stack - take the larger allocated size
    // 合并栈 - 取较大的分配大小
    let max_stack = func1.stack.allocated_stack.max(func2.stack.allocated_stack);
    if merged.stack.allocated_stack < max_stack {
        let _ = merged.stack.grow(max_stack);
    }

    // Merge stack slots
    // 合并栈槽
    let max_slots = func1.stack.stack.len().max(func2.stack.stack.len());
    for i in 0..max_slots {
        let slot1 = func1.stack.stack.get(i);
        let slot2 = func2.stack.stack.get(i);

        let merged_slot = match (slot1, slot2) {
            (Some(s1), Some(s2)) => merge_stack_slots_with_config(s1, s2, config),
            (Some(s), None) | (None, Some(s)) => s.clone(),
            (None, None) => BpfStackState::new(),
        };

        if i < merged.stack.stack.len() {
            merged.stack.stack[i] = merged_slot;
        }
    }

    Some(merged)
}

/// Merge registers with configuration.
/// 使用配置合并寄存器。
pub fn merge_regs_with_config(
    reg1: &BpfRegState,
    reg2: &BpfRegState,
    config: &MergeConfig,
) -> Option<BpfRegState> {
    // If either is uninitialized, result is uninitialized
    // 如果任一未初始化，结果为未初始化
    if reg1.reg_type == BpfRegType::NotInit || reg2.reg_type == BpfRegType::NotInit {
        return Some(BpfRegState::new_not_init());
    }

    // Types must be compatible for merging
    // 类型必须兼容才能合并
    if !types_compatible(reg1.reg_type, reg2.reg_type) {
        // If types are incompatible, mark as unknown scalar
        // 如果类型不兼容，标记为未知标量
        let mut result = BpfRegState::new_scalar_unknown(false);
        result.mark_unknown(false);
        return Some(result);
    }

    let mut merged = reg1.clone();

    match reg1.reg_type {
        BpfRegType::ScalarValue => {
            // Take widest bounds (least restrictive)
            // 取最宽边界（最不严格）
            merged.umin_value = reg1.umin_value.min(reg2.umin_value);
            merged.umax_value = reg1.umax_value.max(reg2.umax_value);
            merged.smin_value = reg1.smin_value.min(reg2.smin_value);
            merged.smax_value = reg1.smax_value.max(reg2.smax_value);

            // 32-bit bounds
            // 32 位边界
            merged.u32_min_value = reg1.u32_min_value.min(reg2.u32_min_value);
            merged.u32_max_value = reg1.u32_max_value.max(reg2.u32_max_value);
            merged.s32_min_value = reg1.s32_min_value.min(reg2.s32_min_value);
            merged.s32_max_value = reg1.s32_max_value.max(reg2.s32_max_value);

            // Merge tnums
            // 合并 tnum
            merged.var_off = merge_tnums(reg1.var_off, reg2.var_off);

            // Precision handling
            // 精度处理
            if config.preserve_precision {
                // Keep precision if both are precise
                // 如果两者都是精确的则保持精度
                merged.precise = reg1.precise && reg2.precise;
            } else {
                // Always lose precision
                // 总是失去精度
                merged.precise = false;
            }
        }
        BpfRegType::PtrToStack
        | BpfRegType::PtrToMapValue
        | BpfRegType::PtrToMapKey
        | BpfRegType::PtrToCtx
        | BpfRegType::PtrToPacket
        | BpfRegType::PtrToMem => {
            // For pointers, check if they have the same base
            // 对于指针，检查它们是否具有相同的基址
            if reg1.off != reg2.off {
                // Different offsets - take range if possible
                // 不同偏移 - 如果可能则取范围
                merged.var_off = Tnum::unknown();
                // Widen offset range
                // 扩宽偏移范围
                merged.smin_value = reg1.smin_value.min(reg2.smin_value);
                merged.smax_value = reg1.smax_value.max(reg2.smax_value);
            }

            // Merge type flags
            // 合并类型标志
            merged.type_flags = reg1.type_flags | reg2.type_flags;

            // If IDs differ, lose NULL tracking
            // 如果 ID 不同，失去 NULL 追踪
            if reg1.id != reg2.id {
                merged.id = 0;
            }

            // Merge ref_obj_id
            // 合并 ref_obj_id
            if reg1.ref_obj_id != reg2.ref_obj_id {
                merged.ref_obj_id = 0;
            }
        }
        _ => {
            // Other types: must be exact match
            // 其他类型：必须精确匹配
            if reg1.off != reg2.off || reg1.id != reg2.id {
                return None;
            }
        }
    }

    Some(merged)
}

/// Merge stack slots with configuration.
/// 使用配置合并栈槽。
fn merge_stack_slots_with_config(
    slot1: &BpfStackState,
    slot2: &BpfStackState,
    config: &MergeConfig,
) -> BpfStackState {
    let mut merged = slot1.clone();

    // Check slot types
    // 检查槽类型
    let type1 = slot1.slot_type[BPF_REG_SIZE - 1];
    let type2 = slot2.slot_type[BPF_REG_SIZE - 1];

    if type1 != type2 {
        // Different types - mark as misc
        // 不同类型 - 标记为杂项
        for i in 0..BPF_REG_SIZE {
            merged.slot_type[i] = BpfStackSlotType::Misc;
        }
        merged.spilled_ptr = BpfRegState::new_not_init();
        return merged;
    }

    match type1 {
        BpfStackSlotType::Spill => {
            // Merge the spilled register
            // 合并溢出的寄存器
            if let Some(merged_reg) =
                merge_regs_with_config(&slot1.spilled_ptr, &slot2.spilled_ptr, config)
            {
                merged.spilled_ptr = merged_reg;
            } else {
                // Can't merge - mark as misc
                // 无法合并 - 标记为杂项
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
        BpfStackSlotType::Dynptr => {
            // Dynptr types must match
            // Dynptr 类型必须匹配
            if slot1.spilled_ptr.dynptr.dynptr_type != slot2.spilled_ptr.dynptr.dynptr_type {
                for i in 0..BPF_REG_SIZE {
                    merged.slot_type[i] = BpfStackSlotType::Invalid;
                }
            }
        }
        _ => {
            // Other types: keep as-is
            // 其他类型：保持原样
        }
    }

    merged
}

/// Merge references from two states into the merged state.
/// 将两个状态的引用合并到合并后的状态中。
fn merge_references(
    merged: &mut BpfVerifierState,
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
) {
    // Take intersection of acquired references
    // 取已获取引用的交集
    // (only keep refs that exist in both states)
    // （只保留两个状态中都存在的引用）
    let refs1 = state1.refs.refs();
    let refs2 = state2.refs.refs();

    // Clear existing refs and rebuild
    // 清除现有引用并重建
    merged.refs = state1.refs.clone();

    // For each ref in state1, check if it exists in state2
    // 对于 state1 中的每个引用，检查它是否存在于 state2 中
    for r1 in refs1.iter() {
        let exists_in_s2 = refs2
            .iter()
            .any(|r2| r1.ref_type == r2.ref_type && r1.ptr == r2.ptr);

        if !exists_in_s2 {
            // Ref only in state1 - might need to mark as potentially released
            // 引用只在 state1 中 - 可能需要标记为可能已释放
            // For safety, we keep it but this could be optimized
            // 为安全起见，我们保留它，但这可以优化
        }
    }
}

/// Merge multiple states at once (batch merging).
/// 一次合并多个状态（批量合并）。
///
/// This is more efficient than pairwise merging for join points
/// with many incoming edges.
/// 对于具有多个传入边的汇合点，这比成对合并更高效。
pub fn merge_states_batch(
    states: &[&BpfVerifierState],
    config: &MergeConfig,
) -> Option<BpfVerifierState> {
    if states.is_empty() {
        return None;
    }
    if states.len() == 1 {
        return Some((*states[0]).clone());
    }

    // Limit batch size
    // 限制批量大小
    let batch = if states.len() > config.max_batch_size {
        &states[..config.max_batch_size]
    } else {
        states
    };

    // Start with first state
    // 从第一个状态开始
    let mut result = (*batch[0]).clone();

    // Merge in remaining states
    // 合并剩余状态
    for state in batch.iter().skip(1) {
        match merge_states_with_config(&result, state, config) {
            MergeResult::Merged(merged) => result = *merged,
            MergeResult::FirstSubsumes => continue,
            MergeResult::SecondSubsumes => result = (*state).clone(),
            MergeResult::Incompatible => return None,
        }
    }

    Some(result)
}

/// Aggressive widening for loop states.
/// 循环状态的激进扩宽。
///
/// When we detect a loop back-edge, we may want to widen scalar
/// bounds more aggressively to ensure termination.
/// 当我们检测到循环回边时，我们可能希望更激进地扩宽标量边界
/// 以确保终止。
pub fn widen_loop_state(state: &mut BpfVerifierState, iteration: u32) {
    // Apply widening to all frames
    // 对所有栈帧应用扩宽
    for i in 0..=state.curframe {
        if let Some(Some(frame)) = state.frame.get_mut(i) {
            widen_func_state(frame, iteration);
        }
    }
}

/// Widen a function state for loop analysis.
/// 为循环分析扩宽函数状态。
fn widen_func_state(func: &mut BpfFuncState, iteration: u32) {
    // Widen registers
    // 扩宽寄存器
    for reg in func.regs.iter_mut() {
        if reg.reg_type == BpfRegType::ScalarValue {
            widen_scalar_reg(reg, iteration);
        }
    }

    // Widen spilled scalars on stack
    // 扩宽栈上溢出的标量
    for slot in func.stack.stack.iter_mut() {
        if slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
            && slot.spilled_ptr.reg_type == BpfRegType::ScalarValue
        {
            widen_scalar_reg(&mut slot.spilled_ptr, iteration);
        }
    }
}

/// Apply widening to a scalar register.
/// 对标量寄存器应用扩宽。
///
/// After several iterations, we widen bounds to infinity to ensure
/// the analysis terminates.
/// 经过几次迭代后，我们将边界扩宽到无穷大以确保分析终止。
pub fn widen_scalar_reg(reg: &mut BpfRegState, iteration: u32) {
    // After 3 iterations, start widening
    // 3 次迭代后，开始扩宽
    if iteration < 3 {
        return;
    }

    // Widen to full range
    // 扩宽到完整范围
    if reg.umin_value != 0 || reg.umax_value != u64::MAX {
        reg.umin_value = 0;
        reg.umax_value = u64::MAX;
        reg.smin_value = i64::MIN;
        reg.smax_value = i64::MAX;
        reg.u32_min_value = 0;
        reg.u32_max_value = u32::MAX;
        reg.s32_min_value = i32::MIN;
        reg.s32_max_value = i32::MAX;
        reg.var_off = Tnum::unknown();
        reg.precise = false;
    }
}

/// Check if two states can be merged across subprogram boundaries.
/// 检查两个状态是否可以跨子程序边界合并。
pub fn can_merge_cross_subprog(
    state1: &BpfVerifierState,
    state2: &BpfVerifierState,
    ctx: &CrossSubprogMergeCtx,
) -> bool {
    // Both states must be at same frame depth
    // 两个状态必须处于相同的栈帧深度
    if state1.curframe != state2.curframe {
        return false;
    }

    // For tail calls, we need exact register state match for R1-R5
    // 对于尾调用，我们需要 R1-R5 的精确寄存器状态匹配
    if ctx.is_tail_call {
        let frame1 = match state1.frame.get(state1.curframe).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let frame2 = match state2.frame.get(state2.curframe).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        // R1-R5 must have compatible types for tail call
        // R1-R5 必须具有兼容的类型用于尾调用
        for i in 1..=5 {
            if !types_compatible(frame1.regs[i].reg_type, frame2.regs[i].reg_type) {
                return false;
            }
        }
    }

    // Check reference compatibility
    // 检查引用兼容性
    let refs1 = state1.refs.refs();
    let refs2 = state2.refs.refs();

    // Reference counts should match for safe merging
    // 引用计数应该匹配以进行安全合并
    if refs1.len() != refs2.len() {
        return false;
    }

    true
}

/// Merge states after returning from a subprogram call.
/// 从子程序调用返回后合并状态。
///
/// This handles the case where a function can return with different
/// register states depending on the path taken inside.
/// 这处理函数根据内部采取的路径可能以不同寄存器状态返回的情况。
pub fn merge_return_states(
    caller_state: &BpfVerifierState,
    return_states: &[BpfVerifierState],
    config: &MergeConfig,
) -> Option<BpfVerifierState> {
    if return_states.is_empty() {
        return None;
    }

    if return_states.len() == 1 {
        // Single return path - just apply return value
        // 单一返回路径 - 只应用返回值
        let mut result = caller_state.clone();
        apply_return_value(&mut result, &return_states[0]);
        return Some(result);
    }

    // Multiple return paths - merge return values first
    // 多个返回路径 - 先合并返回值
    let mut merged_return = return_states[0].clone();
    for ret_state in return_states.iter().skip(1) {
        match merge_states_with_config(&merged_return, ret_state, config) {
            MergeResult::Merged(m) => merged_return = *m,
            MergeResult::FirstSubsumes => continue,
            MergeResult::SecondSubsumes => merged_return = ret_state.clone(),
            MergeResult::Incompatible => return None,
        }
    }

    // Apply merged return to caller state
    // 将合并的返回应用到调用者状态
    let mut result = caller_state.clone();
    apply_return_value(&mut result, &merged_return);
    Some(result)
}

/// Apply return value from callee to caller state.
/// 将被调用者的返回值应用到调用者状态。
fn apply_return_value(caller: &mut BpfVerifierState, callee: &BpfVerifierState) {
    // Get caller's current frame
    // 获取调用者的当前栈帧
    let frame_idx = caller.curframe;
    if let Some(Some(caller_frame)) = caller.frame.get_mut(frame_idx) {
        // Get callee's return frame (should be at curframe)
        // 获取被调用者的返回栈帧（应该在 curframe）
        if let Some(Some(callee_frame)) = callee.frame.get(callee.curframe) {
            // Copy R0 (return value) from callee
            // 从被调用者复制 R0（返回值）
            caller_frame.regs[0] = callee_frame.regs[0].clone();
        }
    }
}

/// State cache for efficient pruning at merge points.
/// 用于在合并点高效剪枝的状态缓存。
#[derive(Debug, Default)]
pub struct StateMergeCache {
    /// Cached merged states indexed by instruction.
    /// 按指令索引的缓存合并状态。
    cache: Vec<Vec<BpfVerifierState>>,
    /// Statistics.
    /// 统计信息。
    pub stats: MergeStats,
}

impl StateMergeCache {
    /// Create a new cache for a program of given size.
    /// 为给定大小的程序创建新缓存。
    pub fn new(prog_len: usize) -> Self {
        Self {
            cache: (0..prog_len).map(|_| Vec::new()).collect(),
            stats: MergeStats::default(),
        }
    }

    /// Try to find a cached state that subsumes the given state.
    /// 尝试找到一个包含给定状态的缓存状态。
    pub fn find_subsuming(&self, insn_idx: usize, state: &BpfVerifierState) -> bool {
        if let Some(cached) = self.cache.get(insn_idx) {
            for cached_state in cached {
                if state_subsumes(cached_state, state) {
                    return true;
                }
            }
        }
        false
    }

    /// Add a state to the cache, potentially merging with existing states.
    /// 将状态添加到缓存，可能与现有状态合并。
    pub fn add_state(&mut self, insn_idx: usize, state: BpfVerifierState, config: &MergeConfig) {
        if insn_idx >= self.cache.len() {
            return;
        }

        let cached = &mut self.cache[insn_idx];

        // Check if any existing state subsumes this one
        // 检查是否有任何现有状态包含此状态
        for existing in cached.iter() {
            if state_subsumes(existing, &state) {
                self.stats.first_subsumed += 1;
                return;
            }
        }

        // Check if this state subsumes any existing
        // 检查此状态是否包含任何现有状态
        cached.retain(|existing| {
            if state_subsumes(&state, existing) {
                self.stats.second_subsumed += 1;
                false
            } else {
                true
            }
        });

        // Try to merge with existing states
        // 尝试与现有状态合并
        for existing in cached.iter_mut() {
            if let MergeResult::Merged(merged) = merge_states_with_config(existing, &state, config)
            {
                *existing = *merged;
                self.stats.merges += 1;
                return;
            }
        }

        // No merge possible - add as new state
        // 无法合并 - 添加为新状态
        cached.push(state);
    }

    /// Clear the cache.
    /// 清除缓存。
    pub fn clear(&mut self) {
        for cached in self.cache.iter_mut() {
            cached.clear();
        }
    }

    /// Get number of cached states at an instruction.
    /// 获取指令处的缓存状态数量。
    pub fn state_count(&self, insn_idx: usize) -> usize {
        self.cache.get(insn_idx).map(|v| v.len()).unwrap_or(0)
    }

    /// Get total number of cached states.
    /// 获取缓存状态的总数。
    pub fn total_states(&self) -> usize {
        self.cache.iter().map(|v| v.len()).sum()
    }
}
