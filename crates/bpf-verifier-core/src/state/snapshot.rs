// SPDX-License-Identifier: GPL-2.0

//! Register state snapshot and comparison for state pruning.
//! 寄存器状态快照和比较，用于状态剪枝
//!
//! This module provides efficient state comparison to determine if a new
//! verification state is equivalent to or subsumed by a previously seen state,
//! enabling state pruning to avoid redundant verification paths.
//! 本模块提供高效的状态比较，以确定新的验证状态是否等效于或被之前看到的状态包含，
//! 从而启用状态剪枝以避免冗余的验证路径。

use alloc::{boxed::Box, vec::Vec};

use alloc::collections::BTreeMap as HashMap;

use crate::core::types::{BpfRegType, MAX_BPF_REG};
use crate::state::reg_state::BpfRegState;

/// Snapshot of register state for comparison.
/// 用于比较的寄存器状态快照
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegSnapshot {
    /// Register type.
    /// 寄存器类型
    pub reg_type: BpfRegType,
    /// Known bits value (tnum).
    /// 已知位值（tnum）
    pub tnum_value: u64,
    /// Known bits mask (tnum).
    /// 已知位掩码（tnum）
    pub tnum_mask: u64,
    /// Minimum signed value.
    /// 最小有符号值
    pub smin: i64,
    /// Maximum signed value.
    /// 最大有符号值
    pub smax: i64,
    /// Minimum unsigned value.
    /// 最小无符号值
    pub umin: u64,
    /// Maximum unsigned value.
    /// 最大无符号值
    pub umax: u64,
    /// Offset from base.
    /// 距基址的偏移
    pub off: i32,
    /// Minimum variable offset.
    /// 最小可变偏移
    pub var_off_min: i64,
    /// Maximum variable offset.
    /// 最大可变偏移
    pub var_off_max: i64,
    /// Reference ID if holding a reference.
    /// 如果持有引用则为引用 ID
    pub ref_obj_id: u32,
    /// Map UID if map pointer.
    /// 如果是 map 指针则为 map UID
    pub map_uid: u32,
}

impl RegSnapshot {
    /// Create a snapshot from a register state.
    /// 从寄存器状态创建快照
    pub fn from_reg(reg: &BpfRegState) -> Self {
        Self {
            reg_type: reg.reg_type,
            tnum_value: reg.var_off.value,
            tnum_mask: reg.var_off.mask,
            smin: reg.smin_value,
            smax: reg.smax_value,
            umin: reg.umin_value,
            umax: reg.umax_value,
            off: reg.off,
            var_off_min: reg.var_off.min() as i64,
            var_off_max: reg.var_off.max() as i64,
            ref_obj_id: reg.ref_obj_id,
            map_uid: reg.map_uid,
        }
    }

    /// Check if this snapshot is "at least as precise" as another.
    /// 检查此快照是否"至少与另一个一样精确"
    /// Returns true if `self` represents a subset of possible values compared to `other`.
    /// 如果 `self` 表示与 `other` 相比可能值的子集，则返回 true
    pub fn is_substate_of(&self, other: &RegSnapshot) -> bool {
        // Type must match
        // 类型必须匹配
        if self.reg_type != other.reg_type {
            // Special case: NOT_INIT is compatible with anything
            // 特殊情况：NOT_INIT 与任何类型兼容
            if other.reg_type == BpfRegType::NotInit {
                return true;
            }
            return false;
        }

        // For scalars, check value ranges
        // 对于标量，检查值范围
        if self.reg_type == BpfRegType::ScalarValue {
            // self's range must be within other's range
            // self 的范围必须在 other 的范围内
            if self.smin < other.smin || self.smax > other.smax {
                return false;
            }
            if self.umin < other.umin || self.umax > other.umax {
                return false;
            }
            // Tnum: self must have at least as many known bits
            // Tnum：self 必须至少有同样多的已知位
            // (self.mask must be subset of other.mask)
            // （self.mask 必须是 other.mask 的子集）
            if (self.tnum_mask & !other.tnum_mask) != 0 {
                return false;
            }
            // Known bits must match where both are known
            // 在两者都已知的位上，已知位必须匹配
            let common_known = !self.tnum_mask & !other.tnum_mask;
            if (self.tnum_value & common_known) != (other.tnum_value & common_known) {
                return false;
            }
        }

        // For pointers, offsets must match or be more precise
        // 对于指针，偏移必须匹配或更精确
        if self.reg_type.is_ptr() {
            if self.off != other.off && other.off != 0 {
                return false;
            }
            // Variable offset range must be within
            // 可变偏移范围必须在内
            if self.var_off_min < other.var_off_min || self.var_off_max > other.var_off_max {
                return false;
            }
        }

        // Reference IDs must match if present
        // 如果存在，引用 ID 必须匹配
        if self.ref_obj_id != 0 && other.ref_obj_id != 0 && self.ref_obj_id != other.ref_obj_id {
            return false;
        }

        // Map UIDs must match for map pointers
        // 对于 map 指针，map UID 必须匹配
        if self.map_uid != 0 && other.map_uid != 0 && self.map_uid != other.map_uid {
            return false;
        }

        true
    }

    /// Check if this snapshot represents a scalar with a known constant value.
    /// 检查此快照是否表示具有已知常量值的标量
    pub fn is_const(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue && self.tnum_mask == 0
    }

    /// Get the constant value if this is a known constant.
    /// 如果这是已知常量，获取常量值
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.tnum_value)
        } else {
            None
        }
    }
}

/// Snapshot of all registers.
/// 所有寄存器的快照
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegsSnapshot {
    /// Snapshots of all registers.
    /// 所有寄存器的快照
    pub regs: [RegSnapshot; MAX_BPF_REG],
}

impl RegsSnapshot {
    /// Create a snapshot from register states.
    /// 从寄存器状态创建快照
    pub fn from_regs(regs: &[BpfRegState; MAX_BPF_REG]) -> Self {
        let mut snapshots: [RegSnapshot; MAX_BPF_REG] = core::array::from_fn(|_| RegSnapshot {
            reg_type: BpfRegType::NotInit,
            tnum_value: 0,
            tnum_mask: u64::MAX,
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            off: 0,
            var_off_min: i64::MIN,
            var_off_max: i64::MAX,
            ref_obj_id: 0,
            map_uid: 0,
        });

        for (i, reg) in regs.iter().enumerate() {
            snapshots[i] = RegSnapshot::from_reg(reg);
        }

        Self { regs: snapshots }
    }

    /// Check if this state is equivalent to or more precise than another.
    /// 检查此状态是否等效于或比另一个更精确
    pub fn is_substate_of(&self, other: &RegsSnapshot) -> bool {
        for (self_reg, other_reg) in self.regs.iter().zip(other.regs.iter()) {
            if !self_reg.is_substate_of(other_reg) {
                return false;
            }
        }
        true
    }

    /// Compute a hash for quick inequality detection.
    /// 计算用于快速不等检测的哈希
    pub fn quick_hash(&self) -> u64 {
        let mut hash: u64 = 0;
        for (i, reg) in self.regs.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(reg.reg_type as u64);
            hash = hash.wrapping_mul(31).wrapping_add(i as u64);
            if reg.reg_type == BpfRegType::ScalarValue {
                hash = hash.wrapping_mul(31).wrapping_add(reg.tnum_value);
            }
        }
        hash
    }
}

/// Stack slot snapshot.
/// 栈槽快照
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StackSlotSnapshot {
    /// Slot type.
    /// 槽类型
    pub slot_type: StackSlotType,
    /// Spilled register snapshot if applicable.
    /// 如果适用，溢出的寄存器快照
    pub spilled_reg: Option<Box<RegSnapshot>>,
}

/// Stack slot types.
/// 栈槽类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackSlotType {
    /// Slot not initialized.
    /// 槽未初始化
    Invalid,
    /// Slot contains spilled register.
    /// 槽包含溢出的寄存器
    Spill,
    /// Slot contains miscellaneous data.
    /// 槽包含杂项数据
    Misc,
    /// Slot contains zero.
    /// 槽包含零
    Zero,
}

/// Snapshot of stack state.
/// 栈状态快照
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSnapshot {
    /// Stack slots.
    /// 栈槽
    pub slots: HashMap<i32, StackSlotSnapshot>,
    /// Lowest allocated offset.
    /// 最低已分配偏移
    pub allocated_low: i32,
}

impl StackSnapshot {
    /// Create an empty stack snapshot.
    /// 创建空的栈快照
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            allocated_low: 0,
        }
    }

    /// Add a slot to the snapshot.
    /// 向快照添加槽
    pub fn add_slot(
        &mut self,
        offset: i32,
        slot_type: StackSlotType,
        spilled: Option<RegSnapshot>,
    ) {
        self.slots.insert(
            offset,
            StackSlotSnapshot {
                slot_type,
                spilled_reg: spilled.map(Box::new),
            },
        );
        if offset < self.allocated_low {
            self.allocated_low = offset;
        }
    }

    /// Check if this stack state is subsumed by another.
    /// 检查此栈状态是否被另一个包含
    pub fn is_substate_of(&self, other: &StackSnapshot) -> bool {
        // All slots in self must be compatible with other
        // self 中的所有槽必须与 other 兼容
        for (offset, slot) in &self.slots {
            if let Some(other_slot) = other.slots.get(offset) {
                // Slot types should match
                // 槽类型应该匹配
                if slot.slot_type != other_slot.slot_type {
                    // Invalid is compatible with anything
                    // Invalid 与任何类型兼容
                    if other_slot.slot_type != StackSlotType::Invalid {
                        return false;
                    }
                }
                // Check spilled register if present
                // 如果存在，检查溢出的寄存器
                if let (Some(self_spill), Some(other_spill)) =
                    (&slot.spilled_reg, &other_slot.spilled_reg)
                {
                    if !self_spill.is_substate_of(other_spill) {
                        return false;
                    }
                }
            }
            // If other doesn't have this slot, that's okay (other is less precise)
            // 如果 other 没有这个槽，那没关系（other 不太精确）
        }
        true
    }
}

impl Default for StackSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete verification state snapshot.
/// 完整的验证状态快照
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Register snapshot.
    /// 寄存器快照
    pub regs: RegsSnapshot,
    /// Stack snapshot.
    /// 栈快照
    pub stack: StackSnapshot,
    /// Current call depth.
    /// 当前调用深度
    pub call_depth: u32,
    /// Active references.
    /// 活动引用
    pub active_refs: Vec<u32>,
    /// Active locks.
    /// 活动锁
    pub active_locks: Vec<u32>,
    /// Quick hash for fast comparison.
    /// 用于快速比较的快速哈希
    pub hash: u64,
}

impl StateSnapshot {
    /// Create a new state snapshot.
    /// 创建新的状态快照
    pub fn new(regs: RegsSnapshot, stack: StackSnapshot, call_depth: u32) -> Self {
        let hash = regs.quick_hash();
        Self {
            regs,
            stack,
            call_depth,
            active_refs: Vec::new(),
            active_locks: Vec::new(),
            hash,
        }
    }

    /// Check if this state is subsumed by another (for pruning).
    /// 检查此状态是否被另一个包含（用于剪枝）
    /// Returns true if verifying `self` is unnecessary because `other`
    /// already covers all possible behaviors.
    /// 如果验证 `self` 是不必要的，因为 `other` 已经覆盖了所有可能的行为，则返回 true
    pub fn is_substate_of(&self, other: &StateSnapshot) -> bool {
        // Quick hash check for fast rejection
        // 快速哈希检查以快速拒绝
        // (Note: equal hashes don't guarantee equality)
        // （注意：相等的哈希不保证相等）

        // Call depth must match
        // 调用深度必须匹配
        if self.call_depth != other.call_depth {
            return false;
        }

        // Check registers
        // 检查寄存器
        if !self.regs.is_substate_of(&other.regs) {
            return false;
        }

        // Check stack
        // 检查栈
        if !self.stack.is_substate_of(&other.stack) {
            return false;
        }

        // Active references must be subset
        // 活动引用必须是子集
        for ref_id in &self.active_refs {
            if !other.active_refs.contains(ref_id) {
                return false;
            }
        }

        // Active locks must match exactly
        // 活动锁必须完全匹配
        if self.active_locks != other.active_locks {
            return false;
        }

        true
    }

    /// Add an active reference.
    /// 添加活动引用
    pub fn add_ref(&mut self, ref_id: u32) {
        if !self.active_refs.contains(&ref_id) {
            self.active_refs.push(ref_id);
        }
    }

    /// Add an active lock.
    /// 添加活动锁
    pub fn add_lock(&mut self, lock_id: u32) {
        if !self.active_locks.contains(&lock_id) {
            self.active_locks.push(lock_id);
        }
    }
}

/// State cache for pruning.
/// 用于剪枝的状态缓存
/// Cache for verification states used in pruning
/// 用于剪枝的验证状态缓存
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct StateCache {
    /// States indexed by instruction index.
    /// 按指令索引索引的状态
    states: HashMap<usize, Vec<StateSnapshot>>,
    /// Statistics.
    /// 统计信息
    pub hits: u64,
    pub misses: u64,
    pub stored: u64,
}

impl StateCache {
    /// Create a new state cache.
    /// 创建新的状态缓存
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a state at the given instruction can be pruned.
    /// 检查给定指令处的状态是否可以被剪枝
    /// Returns true if verification can be skipped.
    /// 如果可以跳过验证，则返回 true
    pub fn check_prune(&mut self, insn_idx: usize, state: &StateSnapshot) -> bool {
        if let Some(cached_states) = self.states.get(&insn_idx) {
            for cached in cached_states {
                if state.is_substate_of(cached) {
                    self.hits += 1;
                    return true;
                }
            }
        }
        self.misses += 1;
        false
    }

    /// Add a state to the cache.
    /// 将状态添加到缓存
    pub fn add_state(&mut self, insn_idx: usize, state: StateSnapshot) {
        self.states.entry(insn_idx).or_default().push(state);
        self.stored += 1;
    }

    /// Get number of states at an instruction.
    /// 获取指令处的状态数量
    pub fn states_at(&self, insn_idx: usize) -> usize {
        self.states.get(&insn_idx).map(|v| v.len()).unwrap_or(0)
    }

    /// Get total number of cached states.
    /// 获取缓存状态的总数
    pub fn total_states(&self) -> usize {
        self.states.values().map(|v| v.len()).sum()
    }

    /// Clear the cache.
    /// 清除缓存
    pub fn clear(&mut self) {
        self.states.clear();
        self.hits = 0;
        self.misses = 0;
        self.stored = 0;
    }

    /// Get hit rate as a percentage (0-100).
    /// 获取命中率（百分比，0-100）
    pub fn hit_rate_percent(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            0
        } else {
            ((self.hits * 100) / total) as u32
        }
    }
}

/// Helper trait to check if a type represents a pointer.
/// 用于检查类型是否表示指针的辅助 trait
trait IsPtr {
    /// Check if this is a pointer type.
    /// 检查这是否是指针类型
    fn is_ptr(&self) -> bool;
}

impl IsPtr for BpfRegType {
    fn is_ptr(&self) -> bool {
        !matches!(self, BpfRegType::NotInit | BpfRegType::ScalarValue)
    }
}
