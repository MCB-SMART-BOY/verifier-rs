// SPDX-License-Identifier: GPL-2.0

//! ID mapping for state comparison
//! 用于状态比较的 ID 映射
//!
//! This module handles ID mapping during state comparison. When comparing
//! two verifier states, we need to track which IDs in one state correspond
//! to which IDs in the other state.
//! 本模块处理状态比较期间的 ID 映射。当比较两个验证器状态时，
//! 我们需要跟踪一个状态中的哪些 ID 对应另一个状态中的哪些 ID。

use alloc::vec::Vec;

use alloc::collections::BTreeMap as HashMap;

/// Maximum number of ID mappings to track
/// 要跟踪的最大 ID 映射数量
pub const BPF_ID_MAP_SIZE: usize = 64;

/// ID mapping entry
/// ID 映射条目
#[derive(Debug, Clone, Copy, Default)]
pub struct IdMapEntry {
    /// ID from the old (cached) state
    /// 来自旧（缓存）状态的 ID
    pub old_id: u32,
    /// ID from the current state
    /// 来自当前状态的 ID
    pub cur_id: u32,
}

/// ID map for state comparison
/// 用于状态比较的 ID 映射
///
/// When comparing states for pruning, IDs in different states may have
/// different values but represent the same logical entity. This map
/// tracks the correspondence between old and current IDs.
/// 在比较状态以进行剪枝时，不同状态中的 ID 可能具有不同的值，
/// 但代表相同的逻辑实体。此映射跟踪旧 ID 和当前 ID 之间的对应关系。
#[derive(Debug, Clone)]
pub struct IdMap {
    /// Mapping entries
    /// 映射条目
    entries: Vec<IdMapEntry>,
    /// Fast lookup: old_id -> index
    /// 快速查找：old_id -> 索引
    old_to_idx: HashMap<u32, usize>,
}

impl Default for IdMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdMap {
    /// Create a new empty ID map
    /// 创建新的空 ID 映射
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(BPF_ID_MAP_SIZE),
            old_to_idx: HashMap::new(),
        }
    }

    /// Reset the ID map for a new comparison
    /// 为新的比较重置 ID 映射
    pub fn reset(&mut self) {
        self.entries.clear();
        self.old_to_idx.clear();
    }

    /// Check if two IDs match according to the current mapping
    /// 检查两个 ID 是否根据当前映射匹配
    /// If old_id hasn't been seen, add it to the mapping
    /// 如果还没有见过 old_id，将其添加到映射中
    pub fn check_ids(&mut self, old_id: u32, cur_id: u32) -> bool {
        // ID 0 is special - always matches 0
        // ID 0 是特殊的 - 总是匹配 0
        if old_id == 0 && cur_id == 0 {
            return true;
        }
        if old_id == 0 || cur_id == 0 {
            return false;
        }

        // Check if we've seen this old_id before
        // 检查我们之前是否见过这个 old_id
        if let Some(&idx) = self.old_to_idx.get(&old_id) {
            // Must map to the same cur_id
            // 必须映射到相同的 cur_id
            return self.entries[idx].cur_id == cur_id;
        }

        // New ID - add to mapping if space available
        // 新的 ID - 如果有空间则添加到映射
        if self.entries.len() >= BPF_ID_MAP_SIZE {
            return false; // Too many IDs - ID 太多
        }

        let idx = self.entries.len();
        self.entries.push(IdMapEntry { old_id, cur_id });
        self.old_to_idx.insert(old_id, idx);
        true
    }

    /// Check scalar IDs - used for precision tracking
    /// 检查标量 ID - 用于精度跟踪
    /// Scalar IDs are only compared when both are non-zero
    /// 标量 ID 仅在两者都非零时比较
    pub fn check_scalar_ids(&mut self, old_id: u32, cur_id: u32) -> bool {
        // If old doesn't have ID, cur can have any ID
        // 如果旧的没有 ID，当前的可以有任何 ID
        if old_id == 0 {
            return true;
        }
        // If old has ID but cur doesn't, not equal
        // 如果旧的有 ID 但当前的没有，则不相等
        if cur_id == 0 {
            return false;
        }
        // Both have IDs - they must map
        // 两者都有 ID - 它们必须映射
        self.check_ids(old_id, cur_id)
    }

    /// Get the current ID for an old ID
    /// 获取旧 ID 对应的当前 ID
    pub fn get_cur_id(&self, old_id: u32) -> Option<u32> {
        self.old_to_idx
            .get(&old_id)
            .map(|&idx| self.entries[idx].cur_id)
    }

    /// Get number of mappings
    /// 获取映射数量
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Range comparison for return values
/// 返回值的范围比较
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RetvalRange {
    /// Minimum return value
    /// 最小返回值
    pub minval: i64,
    /// Maximum return value
    /// 最大返回值
    pub maxval: i64,
}

impl RetvalRange {
    /// Create a new return value range
    /// 创建新的返回值范围
    pub fn new(minval: i64, maxval: i64) -> Self {
        Self { minval, maxval }
    }

    /// Check if this range is within another range
    /// 检查此范围是否在另一个范围内
    pub fn within(&self, other: &RetvalRange) -> bool {
        self.minval >= other.minval && self.maxval <= other.maxval
    }

    /// Check if ranges are equal
    /// 检查范围是否相等
    pub fn equal(&self, other: &RetvalRange) -> bool {
        self.minval == other.minval && self.maxval == other.maxval
    }
}

/// Live register bitmap for tracking which registers are live
/// 用于跟踪哪些寄存器是活的的活寄存器位图
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveRegs {
    /// Bitmask of live registers (bit i = register i is live)
    /// 活寄存器的位掩码（位 i = 寄存器 i 是活的）
    pub mask: u16,
}

impl LiveRegs {
    /// Create a new empty live register set
    /// 创建新的空活寄存器集
    pub fn new() -> Self {
        Self { mask: 0 }
    }

    /// Set a register as live
    /// 将寄存器设置为活的
    pub fn set(&mut self, regno: usize) {
        if regno < 16 {
            self.mask |= 1 << regno;
        }
    }

    /// Clear a register
    /// 清除寄存器
    pub fn clear(&mut self, regno: usize) {
        if regno < 16 {
            self.mask &= !(1 << regno);
        }
    }

    /// Check if a register is live
    /// 检查寄存器是否是活的
    pub fn is_live(&self, regno: usize) -> bool {
        if regno < 16 {
            (self.mask & (1 << regno)) != 0
        } else {
            false
        }
    }

    /// Check if any register is live
    /// 检查是否有任何寄存器是活的
    pub fn any_live(&self) -> bool {
        self.mask != 0
    }

    /// Merge with another live set (union)
    /// 与另一个活集合并（并集）
    pub fn merge(&mut self, other: &LiveRegs) {
        self.mask |= other.mask;
    }

    /// Intersect with another live set
    /// 与另一个活集相交
    pub fn intersect(&mut self, other: &LiveRegs) {
        self.mask &= other.mask;
    }
}

/// Read marks for tracking which registers/slots have been read
/// 用于跟踪哪些寄存器/槽已被读取的读取标记
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ReadMark {
    /// Not read
    /// 未读取
    #[default]
    None = 0,
    /// Read in current state
    /// 在当前状态中读取
    Read = 1,
    /// Read in parent state (inherited)
    /// 在父状态中读取（继承）
    ReadParent = 2,
}

impl ReadMark {
    /// Check if this mark indicates the register was read
    /// 检查此标记是否表示寄存器已被读取
    pub fn is_read(&self) -> bool {
        *self != ReadMark::None
    }
}

/// Parent link for state hierarchy
/// 状态层次结构的父链接
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParentLink {
    /// No parent
    /// 无父
    #[default]
    None,
    /// Parent is an explored state at given index
    /// 父是给定索引处的已探索状态
    Explored(usize),
    /// Parent is on the exploration stack at given depth
    /// 父在给定深度的探索栈上
    Stack(usize),
}
