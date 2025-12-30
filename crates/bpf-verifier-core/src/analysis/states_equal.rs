// SPDX-License-Identifier: GPL-2.0

//! Comprehensive state equivalence checking for pruning
//! 用于剪枝的全面状态等价检查
//!
//! This module implements the full `states_equal` logic from the kernel verifier.
//! State equivalence is crucial for efficient verification - it allows us to prune
//! exploration when we reach a state that's "at least as restrictive" as one we've
//! already verified.
//! 本模块实现了内核验证器中完整的 `states_equal` 逻辑。
//! 状态等价对于高效验证至关重要——它允许我们在到达一个"至少与我们
//! 已验证的状态一样严格"的状态时剪枝探索。

use alloc::collections::BTreeMap as HashMap;

use crate::core::types::{BpfRegType, BpfStackSlotType, BpfTypeFlag, BPF_REG_SIZE, MAX_BPF_REG};
use crate::state::reference::BpfReferenceState;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::BpfStackState;
use crate::state::verifier_state::{BpfFuncState, BpfVerifierState};

/// ID mapping for comparing states with different ID assignments
/// 用于比较具有不同 ID 分配的状态的 ID 映射
#[derive(Debug, Default)]
pub struct IdMap {
    /// Maps old IDs to current IDs
    /// 将旧 ID 映射到当前 ID
    map: HashMap<u32, u32>,
}

impl IdMap {
    /// Create a new empty ID map
    /// 创建新的空 ID 映射
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all ID mappings
    /// 清除所有 ID 映射
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Check if two IDs are equivalent, recording the mapping if new
    /// 检查两个 ID 是否等价，如果是新的则记录映射
    pub fn check_ids(&mut self, cur_id: u32, old_id: u32) -> bool {
        // ID 0 means "no ID" - always matches
        // ID 0 表示"无 ID" - 总是匹配
        if old_id == 0 {
            return true;
        }
        if cur_id == 0 {
            return false;
        }

        // Check if we've seen this old_id before
        // 检查我们之前是否见过这个 old_id
        if let Some(&mapped_cur) = self.map.get(&old_id) {
            // Must map to the same cur_id
            // 必须映射到相同的 cur_id
            return mapped_cur == cur_id;
        }

        // New mapping - record it
        // 新映射 - 记录它
        self.map.insert(old_id, cur_id);
        true
    }
}

/// Comparison mode for state equivalence
/// 状态等价的比较模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompareMode {
    /// Not exact - allows subsumption (cur more restrictive than old)
    /// 不精确 - 允许包含（cur 比 old 更严格）
    #[default]
    NotExact,
    /// Exact match required (for loop detection)
    /// 需要精确匹配（用于循环检测）
    Exact,
    /// Range within - cur's ranges must be within old's ranges
    /// 范围内 - cur 的范围必须在 old 的范围内
    /// Used for iterator convergence detection, may_goto, and callback detection
    /// 用于迭代器收敛检测、may_goto 和回调检测
    RangeWithin,
}

/// Configuration for state comparison
/// 状态比较的配置
#[derive(Debug, Clone, Copy)]
pub struct CompareConfig {
    /// Comparison mode
    /// 比较模式
    pub mode: CompareMode,
    /// Whether to check precision marks
    /// 是否检查精度标记
    pub check_precision: bool,
    /// Whether to compare reference states
    /// 是否比较引用状态
    pub check_refs: bool,
    /// Whether to compare lock states
    /// 是否比较锁状态
    pub check_locks: bool,
}

impl Default for CompareConfig {
    fn default() -> Self {
        Self {
            mode: CompareMode::NotExact,
            check_precision: true,
            check_refs: true,
            check_locks: true,
        }
    }
}

impl CompareConfig {
    /// Config for pruning - allows subsumption
    /// 用于剪枝的配置 - 允许包含
    pub fn for_pruning() -> Self {
        Self::default()
    }

    /// Config for loop detection - requires exact match
    /// 用于循环检测的配置 - 需要精确匹配
    pub fn for_loop_detection() -> Self {
        Self {
            mode: CompareMode::Exact,
            check_precision: false,
            check_refs: true,
            check_locks: true,
        }
    }

    /// Config for range-within checking (iterators, may_goto, callbacks)
    /// 用于范围内检查的配置（迭代器、may_goto、回调）
    ///
    /// This mode is used when we want to check if the current state's
    /// scalar ranges are within the old state's ranges, but we don't
    /// require exact matches. This is important for:
    /// 此模式用于当我们想要检查当前状态的标量范围是否在旧状态
    /// 的范围内，但不需要精确匹配时。这对以下情况很重要：
    /// - Iterator convergence detection (iter_next)
    ///   迭代器收敛检测 (iter_next)
    /// - may_goto depth checking
    ///   may_goto 深度检查
    /// - Callback function detection
    ///   回调函数检测
    pub fn for_range_within() -> Self {
        Self {
            mode: CompareMode::RangeWithin,
            check_precision: false,
            check_refs: true,
            check_locks: true,
        }
    }

    /// Helper: is this exact matching mode?
    /// 辅助函数：这是精确匹配模式吗？
    pub fn exact(&self) -> bool {
        self.mode == CompareMode::Exact
    }

    /// Helper: is this range-within mode?
    /// 辅助函数：这是范围内模式吗？
    pub fn range_within(&self) -> bool {
        self.mode == CompareMode::RangeWithin
    }
}

/// Check if two verifier states are equivalent using default config
/// 使用默认配置检查两个验证器状态是否等价
pub fn states_equal(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    states_equal_with_config(cur, old, &CompareConfig::default())
}

/// Check if two verifier states are equivalent with custom config
/// 使用自定义配置检查两个验证器状态是否等价
pub fn states_equal_with_config(
    cur: &BpfVerifierState,
    old: &BpfVerifierState,
    config: &CompareConfig,
) -> bool {
    let mut idmap = IdMap::new();
    states_equal_with_idmap(cur, old, config, &mut idmap)
}

/// Check state equivalence with explicit ID mapping
/// 使用显式 ID 映射检查状态等价
pub fn states_equal_with_idmap(
    cur: &BpfVerifierState,
    old: &BpfVerifierState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must have same frame depth
    // 必须具有相同的栈帧深度
    if cur.curframe != old.curframe {
        return false;
    }

    // Check all frames from bottom to top
    // 从底部到顶部检查所有栈帧
    for i in 0..=cur.curframe {
        let cur_func = match cur.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let old_func = match old.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        if !func_states_equal(cur_func, old_func, config, idmap) {
            return false;
        }
    }

    // Check references if configured
    // 如果配置了，检查引用
    if config.check_refs && !refs_equal(&cur.refs, &old.refs, idmap) {
        return false;
    }

    // Check lock state if configured
    // 如果配置了，检查锁状态
    if config.check_locks {
        if cur.refs.active_locks != old.refs.active_locks {
            return false;
        }
        if cur.refs.active_rcu_locks != old.refs.active_rcu_locks {
            return false;
        }
    }

    true
}

/// Check if two function states are equivalent
/// 检查两个函数状态是否等价
fn func_states_equal(
    cur: &BpfFuncState,
    old: &BpfFuncState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must have same callsite
    // 必须具有相同的调用点
    if cur.callsite != old.callsite {
        return false;
    }

    // Check all registers
    // 检查所有寄存器
    for i in 0..MAX_BPF_REG {
        let cur_reg = &cur.regs[i];
        let old_reg = &old.regs[i];

        if !regsafe(cur_reg, old_reg, config, idmap) {
            return false;
        }
    }

    // Check stack
    // 检查栈
    if !stacksafe(cur, old, config, idmap) {
        return false;
    }

    true
}

/// Check if cur register is "safe" relative to old register
/// 检查 cur 寄存器相对于 old 寄存器是否"安全"
///
/// For pruning: cur can be pruned if it's at least as restrictive as old
/// 用于剪枝：如果 cur 至少与 old 一样严格，则可以剪枝 cur
/// For exact: cur must exactly match old
/// 用于精确：cur 必须与 old 完全匹配
pub fn regsafe(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // If old is NOT_INIT, cur can be anything
    // 如果 old 是 NOT_INIT，cur 可以是任何东西
    if old.reg_type == BpfRegType::NotInit {
        return true;
    }

    // If cur is NOT_INIT but old isn't, not safe
    // 如果 cur 是 NOT_INIT 但 old 不是，则不安全
    if cur.reg_type == BpfRegType::NotInit {
        return false;
    }

    // Check precision requirement
    // 检查精度要求
    if config.check_precision && old.precise && !cur.precise {
        return false;
    }

    // Check type compatibility
    // 检查类型兼容性
    if !type_compatible(cur, old, config) {
        return false;
    }

    // Type-specific checks
    // 类型特定检查
    match cur.reg_type {
        BpfRegType::ScalarValue => regsafe_scalar(cur, old, config),
        BpfRegType::PtrToStack => regsafe_ptr_to_stack(cur, old, config, idmap),
        BpfRegType::PtrToMapValue | BpfRegType::PtrToMapKey | BpfRegType::ConstPtrToMap => {
            regsafe_ptr_to_map(cur, old, config, idmap)
        }
        BpfRegType::PtrToCtx => regsafe_ptr_to_ctx(cur, old, config),
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta | BpfRegType::PtrToPacketEnd => {
            regsafe_ptr_to_pkt(cur, old, config, idmap)
        }
        BpfRegType::PtrToBtfId => regsafe_ptr_to_btf_id(cur, old, config, idmap),
        BpfRegType::PtrToMem => regsafe_ptr_to_mem(cur, old, config, idmap),
        _ => {
            // For other pointer types, require exact match
            // 对于其他指针类型，要求精确匹配
            cur.off == old.off && cur.mem_size == old.mem_size
        }
    }
}

/// Check if types are compatible for comparison
/// 检查类型是否兼容以进行比较
fn type_compatible(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    if cur.reg_type == old.reg_type {
        return true;
    }

    if config.exact() {
        return false;
    }

    // Special case: PTR_MAYBE_NULL compatibility
    // 特殊情况：PTR_MAYBE_NULL 兼容性
    // If old might be NULL, cur can be non-NULL (more restrictive)
    // 如果 old 可能是 NULL，cur 可以是非 NULL（更严格）
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL)
        && !cur.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL)
    {
        // Check base types match
        // 检查基本类型匹配
        return cur.reg_type == old.reg_type;
    }

    false
}

/// Check scalar value equivalence
/// 检查标量值等价
fn regsafe_scalar(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    if config.exact() {
        // Exact match required
        // 需要精确匹配
        return cur.umin_value == old.umin_value
            && cur.umax_value == old.umax_value
            && cur.smin_value == old.smin_value
            && cur.smax_value == old.smax_value
            && cur.var_off == old.var_off;
    }

    if config.range_within() {
        // RANGE_WITHIN mode: cur's range must be within old's range
        // RANGE_WITHIN 模式：cur 的范围必须在 old 的范围内
        // This is used for iterator convergence, may_goto, and callbacks.
        // 这用于迭代器收敛、may_goto 和回调。
        // Unlike NotExact mode, we require that old's bounds contain cur's bounds
        // completely, which is the inverse of subsumption.
        // 与 NotExact 模式不同，我们要求 old 的边界完全包含 cur 的边界，
        // 这是包含的逆向。
        //
        // The semantics here: old represents a "superstate" that should encompass
        // all possible values that cur could take. If cur is within old's range,
        // we can safely prune because we've already explored the superstate.
        // 这里的语义：old 表示一个"超状态"，应该包含 cur 可能取的所有值。
        // 如果 cur 在 old 的范围内，我们可以安全地剪枝，因为我们已经
        // 探索了超状态。

        // Check 64-bit unsigned bounds: old's range must contain cur's range
        // 检查 64 位无符号边界：old 的范围必须包含 cur 的范围
        if cur.umin_value < old.umin_value || cur.umax_value > old.umax_value {
            return false;
        }

        // Check 64-bit signed bounds
        // 检查 64 位有符号边界
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }

        // Check 32-bit bounds
        // 检查 32 位边界
        if cur.u32_min_value < old.u32_min_value || cur.u32_max_value > old.u32_max_value {
            return false;
        }
        if cur.s32_min_value < old.s32_min_value || cur.s32_max_value > old.s32_max_value {
            return false;
        }

        // For RANGE_WITHIN, we also require tnum subset relationship
        // 对于 RANGE_WITHIN，我们还要求 tnum 子集关系
        // This ensures that the known bits of cur are consistent with old
        // 这确保 cur 的已知位与 old 一致
        if !cur.var_off.is_subset_of(&old.var_off) {
            return false;
        }

        return true;
    }

    // NotExact mode: Subsumption - cur must be within old's range
    // NotExact 模式：包含 - cur 必须在 old 的范围内
    // This means cur is MORE constrained than old (stricter bounds)
    // 这意味着 cur 比 old 更受约束（更严格的边界）
    // This is the standard pruning mode.
    // 这是标准的剪枝模式。

    // Check 64-bit unsigned bounds
    // 检查 64 位无符号边界
    if cur.umin_value < old.umin_value || cur.umax_value > old.umax_value {
        return false;
    }

    // Check 64-bit signed bounds
    // 检查 64 位有符号边界
    if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
        return false;
    }

    // Check 32-bit bounds
    // 检查 32 位边界
    if cur.u32_min_value < old.u32_min_value || cur.u32_max_value > old.u32_max_value {
        return false;
    }
    if cur.s32_min_value < old.s32_min_value || cur.s32_max_value > old.s32_max_value {
        return false;
    }

    // Check tnum: cur's known bits must include old's known bits
    // 检查 tnum：cur 的已知位必须包含 old 的已知位
    // cur.var_off must be a subset of old.var_off
    // cur.var_off 必须是 old.var_off 的子集
    if !cur.var_off.is_subset_of(&old.var_off) {
        return false;
    }

    true
}

/// Check pointer-to-stack equivalence
/// 检查指向栈的指针等价
fn regsafe_ptr_to_stack(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Offsets must match
    // 偏移必须匹配
    if cur.off != old.off {
        return false;
    }

    // Check frame number (which stack frame this points to)
    // 检查栈帧号（这指向哪个栈帧）
    if cur.frameno != old.frameno {
        return false;
    }

    // For variable offset pointers, check ranges
    // 对于可变偏移指针，检查范围
    if !config.exact() {
        // cur must be within old's range
        // cur 必须在 old 的范围内
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }
    } else if cur.smin_value != old.smin_value || cur.smax_value != old.smax_value {
        return false;
    }

    // Check ID for NULL tracking
    // 检查用于 NULL 追踪的 ID
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check pointer-to-map equivalence
/// 检查指向映射的指针等价
fn regsafe_ptr_to_map(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must point to same map
    // 必须指向相同的映射
    match (&cur.map_ptr, &old.map_ptr) {
        (Some(c), Some(o)) => {
            if c.map_type != o.map_type {
                return false;
            }
            // For map value pointers, check key/value sizes
            // 对于映射值指针，检查键/值大小
            if c.key_size != o.key_size || c.value_size != o.value_size {
                return false;
            }
        }
        (None, Some(_)) => return false,
        _ => {}
    }

    // Check offset
    // 检查偏移
    if config.exact() {
        if cur.off != old.off {
            return false;
        }
    } else {
        // cur's offset range must be within old's
        // cur 的偏移范围必须在 old 的范围内
        if cur.smin_value < old.smin_value || cur.smax_value > old.smax_value {
            return false;
        }
    }

    // Check NULL tracking
    // 检查 NULL 追踪
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check pointer-to-ctx equivalence
/// 检查指向上下文的指针等价
fn regsafe_ptr_to_ctx(cur: &BpfRegState, old: &BpfRegState, config: &CompareConfig) -> bool {
    // Context pointer offsets must match exactly
    // 上下文指针偏移必须精确匹配
    if cur.off != old.off {
        return false;
    }

    // Check type flags match
    // 检查类型标志匹配
    if config.exact() {
        cur.type_flags == old.type_flags
    } else {
        // cur can have fewer flags (more restrictive)
        // cur 可以有更少的标志（更严格）
        old.type_flags.contains(cur.type_flags)
    }
}

/// Check packet pointer equivalence
/// 检查数据包指针等价
fn regsafe_ptr_to_pkt(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Check ID for packet pointer tracking
    // 检查用于数据包指针追踪的 ID
    if !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    // Check offset and mem_size (used for packet range)
    // 检查偏移和 mem_size（用于数据包范围）
    if config.exact() {
        cur.off == old.off && cur.mem_size == old.mem_size
    } else {
        // cur must have same or smaller range
        // cur 必须具有相同或更小的范围
        cur.off == old.off && cur.mem_size <= old.mem_size
    }
}

/// Check BTF ID pointer equivalence
/// 检查 BTF ID 指针等价
fn regsafe_ptr_to_btf_id(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Must point to same BTF type
    // 必须指向相同的 BTF 类型
    if cur.btf_id() != old.btf_id() {
        return false;
    }

    // Check offset
    // 检查偏移
    if cur.off != old.off {
        return false;
    }

    // Check reference ID for acquired references
    // 检查已获取引用的引用 ID
    if old.ref_obj_id != 0 && !idmap.check_ids(cur.ref_obj_id, old.ref_obj_id) {
        return false;
    }

    // Check type flags
    // 检查类型标志
    let trust_flags =
        BpfTypeFlag::PTR_TRUSTED | BpfTypeFlag::PTR_UNTRUSTED | BpfTypeFlag::PTR_MAYBE_NULL;

    if config.exact() {
        (cur.type_flags & trust_flags) == (old.type_flags & trust_flags)
    } else {
        // cur can be more trusted than old
        // cur 可以比 old 更受信任
        if old.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED)
            && !cur.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED)
        {
            return true;
        }
        (cur.type_flags & trust_flags) == (old.type_flags & trust_flags)
    }
}

/// Check pointer-to-mem equivalence
/// 检查指向内存的指针等价
fn regsafe_ptr_to_mem(
    cur: &BpfRegState,
    old: &BpfRegState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Check memory size
    // 检查内存大小
    if config.exact() {
        if cur.mem_size != old.mem_size {
            return false;
        }
    } else {
        // cur can have smaller (more restrictive) size
        // cur 可以有更小（更严格）的大小
        if cur.mem_size > old.mem_size {
            return false;
        }
    }

    // Check offset
    // 检查偏移
    if cur.off != old.off {
        return false;
    }

    // Check ID for NULL tracking
    // 检查用于 NULL 追踪的 ID
    if old.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) && !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    true
}

/// Check stack equivalence between two function states
/// 检查两个函数状态之间的栈等价
fn stacksafe(
    cur: &BpfFuncState,
    old: &BpfFuncState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // cur must have at least as much stack allocated
    // cur 必须分配至少同样多的栈
    if cur.stack.allocated_stack < old.stack.allocated_stack {
        return false;
    }

    // Check each stack slot that old has initialized
    // 检查 old 已初始化的每个栈槽
    for (spi, old_slot) in old.stack.stack.iter().enumerate() {
        let cur_slot = match cur.stack.stack.get(spi) {
            Some(s) => s,
            None => return false,
        };

        if !stackslot_safe(cur_slot, old_slot, config, idmap) {
            return false;
        }
    }

    true
}

/// Check if cur stack slot is safe relative to old
/// 检查 cur 栈槽相对于 old 是否安全
pub fn stackslot_safe(
    cur: &BpfStackState,
    old: &BpfStackState,
    config: &CompareConfig,
    idmap: &mut IdMap,
) -> bool {
    // Get the primary slot type (from last byte)
    // 获取主槽类型（从最后一个字节）
    let cur_type = cur.slot_type[BPF_REG_SIZE - 1];
    let old_type = old.slot_type[BPF_REG_SIZE - 1];

    // If old is uninitialized, cur can be anything
    // 如果 old 未初始化，cur 可以是任何东西
    if old_type == BpfStackSlotType::Invalid {
        return true;
    }

    // MISC slots are compatible with anything initialized
    // MISC 槽与任何已初始化的槽兼容
    if old_type == BpfStackSlotType::Misc {
        return cur_type != BpfStackSlotType::Invalid;
    }

    // For exact matching, types must be identical
    // 对于精确匹配，类型必须相同
    if config.exact() && cur_type != old_type {
        return false;
    }

    match old_type {
        BpfStackSlotType::Spill => {
            if cur_type != BpfStackSlotType::Spill {
                // If old has a spill, cur must also have a spill
                // 如果 old 有溢出，cur 也必须有溢出
                // (unless cur has MISC which is compatible)
                // （除非 cur 有 MISC 是兼容的）
                if cur_type != BpfStackSlotType::Misc {
                    return false;
                }
                return true;
            }
            // Both are spills - compare the spilled values
            // 两者都是溢出 - 比较溢出的值
            regsafe(&cur.spilled_ptr, &old.spilled_ptr, config, idmap)
        }
        BpfStackSlotType::Zero => {
            // Zero is compatible with zero or misc
            // Zero 与 zero 或 misc 兼容
            cur_type == BpfStackSlotType::Zero || cur_type == BpfStackSlotType::Misc
        }
        BpfStackSlotType::Dynptr => {
            if cur_type != BpfStackSlotType::Dynptr {
                return false;
            }
            // Dynptr types must match
            // Dynptr 类型必须匹配
            cur.spilled_ptr.dynptr.dynptr_type == old.spilled_ptr.dynptr.dynptr_type
        }
        BpfStackSlotType::Iter => {
            if cur_type != BpfStackSlotType::Iter {
                return false;
            }
            // Iterator state must match
            // 迭代器状态必须匹配
            cur.spilled_ptr.iter.state == old.spilled_ptr.iter.state
                && cur.spilled_ptr.iter.depth == old.spilled_ptr.iter.depth
        }
        _ => true,
    }
}

/// Check reference state equivalence
/// 检查引用状态等价
fn refs_equal(
    cur: &crate::state::reference::ReferenceManager,
    old: &crate::state::reference::ReferenceManager,
    idmap: &mut IdMap,
) -> bool {
    let cur_refs = cur.refs();
    let old_refs = old.refs();

    // Must have same number of references
    // 必须具有相同数量的引用
    if cur_refs.len() != old_refs.len() {
        return false;
    }

    // Check each reference (order matters)
    // 检查每个引用（顺序重要）
    for (cur_ref, old_ref) in cur_refs.iter().zip(old_refs.iter()) {
        if !ref_state_equal(cur_ref, old_ref, idmap) {
            return false;
        }
    }

    true
}

/// Check if two reference states are equivalent
/// 检查两个引用状态是否等价
fn ref_state_equal(cur: &BpfReferenceState, old: &BpfReferenceState, idmap: &mut IdMap) -> bool {
    // Types must match
    // 类型必须匹配
    if cur.ref_type != old.ref_type {
        return false;
    }

    // IDs must be mapped correctly
    // ID 必须正确映射
    if !idmap.check_ids(cur.id, old.id) {
        return false;
    }

    // For locks, pointers must match
    // 对于锁，指针必须匹配
    if cur.ptr != old.ptr {
        return false;
    }

    true
}

/// Check if states might be in a loop (for bounded loop detection)
/// 检查状态是否可能处于循环中（用于有界循环检测）
pub fn states_maybe_looping(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    // Quick check: if frames don't match, not looping
    // 快速检查：如果栈帧不匹配，则不是循环
    if cur.curframe != old.curframe {
        return false;
    }

    // Check if any iterator has different depth
    // 检查是否有任何迭代器具有不同的深度
    // This indicates loop progress
    // 这表示循环进展
    for i in 0..=cur.curframe {
        let cur_func = match cur.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };
        let old_func = match old.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return false,
        };

        // Check for iterator depth changes
        // 检查迭代器深度变化
        for (cur_slot, old_slot) in cur_func.stack.stack.iter().zip(old_func.stack.stack.iter()) {
            let cur_type = cur_slot.slot_type[BPF_REG_SIZE - 1];
            let old_type = old_slot.slot_type[BPF_REG_SIZE - 1];

            if cur_type == BpfStackSlotType::Iter
                && old_type == BpfStackSlotType::Iter
                && cur_slot.spilled_ptr.iter.depth != old_slot.spilled_ptr.iter.depth
            {
                // Different depths - making progress
                // 不同深度 - 正在进展
                return false;
            }
        }
    }

    // States look similar - might be looping
    // 状态看起来相似 - 可能正在循环
    true
}
