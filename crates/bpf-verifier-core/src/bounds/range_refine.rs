// SPDX-License-Identifier: GPL-2.0

//! Scalar value range refinement on conditional branches.
//! 条件分支上的标量值范围细化
//!
//! This module implements range refinement for scalar values based on
//! conditional branch outcomes. When a branch condition is known to be
//! true or false, the value ranges of the compared registers can be
//! narrowed accordingly.
//! 本模块基于条件分支结果实现标量值的范围细化。当已知分支条件为真或假时，
//! 被比较寄存器的值范围可以相应地缩小。

use crate::bounds::tnum::Tnum;
use crate::core::types::{
    BpfRegType, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT,
    BPF_JSLE, BPF_JSLT,
};
use crate::state::reg_state::BpfRegState;

/// Branch condition for refinement.
/// 用于细化的分支条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchCond {
    /// Equal (JEQ).
    /// 相等（JEQ）
    Eq,
    /// Not equal (JNE).
    /// 不相等（JNE）
    Ne,
    /// Greater than unsigned (JGT).
    /// 大于无符号（JGT）
    Gt,
    /// Greater or equal unsigned (JGE).
    /// 大于等于无符号（JGE）
    Ge,
    /// Less than unsigned (JLT).
    /// 小于无符号（JLT）
    Lt,
    /// Less or equal unsigned (JLE).
    /// 小于等于无符号（JLE）
    Le,
    /// Signed greater than (JSGT).
    /// 有符号大于（JSGT）
    Sgt,
    /// Signed greater or equal (JSGE).
    /// 有符号大于等于（JSGE）
    Sge,
    /// Signed less than (JSLT).
    /// 有符号小于（JSLT）
    Slt,
    /// Signed less or equal (JSLE).
    /// 有符号小于等于（JSLE）
    Sle,
    /// Bit test (JSET).
    /// 位测试（JSET）
    Set,
}

impl BranchCond {
    /// Create from BPF jump opcode.
    /// 从 BPF 跳转操作码创建
    pub fn from_opcode(op: u8) -> Option<Self> {
        match op {
            BPF_JEQ => Some(BranchCond::Eq),
            BPF_JNE => Some(BranchCond::Ne),
            BPF_JGT => Some(BranchCond::Gt),
            BPF_JGE => Some(BranchCond::Ge),
            BPF_JLT => Some(BranchCond::Lt),
            BPF_JLE => Some(BranchCond::Le),
            BPF_JSGT => Some(BranchCond::Sgt),
            BPF_JSGE => Some(BranchCond::Sge),
            BPF_JSLT => Some(BranchCond::Slt),
            BPF_JSLE => Some(BranchCond::Sle),
            BPF_JSET => Some(BranchCond::Set),
            _ => None,
        }
    }

    /// Get the negated condition (for the false branch).
    /// 获取取反的条件（用于假分支）
    pub fn negate(self) -> Self {
        match self {
            BranchCond::Eq => BranchCond::Ne,
            BranchCond::Ne => BranchCond::Eq,
            BranchCond::Gt => BranchCond::Le,
            BranchCond::Ge => BranchCond::Lt,
            BranchCond::Lt => BranchCond::Ge,
            BranchCond::Le => BranchCond::Gt,
            BranchCond::Sgt => BranchCond::Sle,
            BranchCond::Sge => BranchCond::Slt,
            BranchCond::Slt => BranchCond::Sge,
            BranchCond::Sle => BranchCond::Sgt,
            BranchCond::Set => BranchCond::Set, // !JSET doesn't have simple negation
                                                // !JSET 没有简单的取反
        }
    }

    /// Check if this is a signed comparison.
    /// 检查是否为有符号比较
    pub fn is_signed(self) -> bool {
        matches!(
            self,
            BranchCond::Sgt | BranchCond::Sge | BranchCond::Slt | BranchCond::Sle
        )
    }
}

/// Result of range refinement.
/// 范围细化的结果
#[derive(Debug, Clone)]
pub struct RefinementResult {
    /// Whether refinement was applied.
    /// 是否应用了细化
    pub refined: bool,
    /// New unsigned minimum.
    /// 新的无符号最小值
    pub umin: u64,
    /// New unsigned maximum.
    /// 新的无符号最大值
    pub umax: u64,
    /// New signed minimum.
    /// 新的有符号最小值
    pub smin: i64,
    /// New signed maximum.
    /// 新的有符号最大值
    pub smax: i64,
    /// New tnum.
    /// 新的 tnum
    pub var_off: Tnum,
}

impl RefinementResult {
    /// Create from existing register bounds.
    /// 从现有寄存器边界创建
    pub fn from_reg(reg: &BpfRegState) -> Self {
        Self {
            refined: false,
            umin: reg.umin_value,
            umax: reg.umax_value,
            smin: reg.smin_value,
            smax: reg.smax_value,
            var_off: reg.var_off,
        }
    }

    /// Mark as refined.
    /// 标记为已细化
    pub fn mark_refined(&mut self) {
        self.refined = true;
    }

    /// Check if the range is empty (no valid values).
    /// 检查范围是否为空（无有效值）
    pub fn is_empty(&self) -> bool {
        self.umin > self.umax || self.smin > self.smax
    }

    /// Apply refinement to a register.
    /// 将细化应用到寄存器
    pub fn apply_to(&self, reg: &mut BpfRegState) {
        if self.refined {
            reg.umin_value = self.umin;
            reg.umax_value = self.umax;
            reg.smin_value = self.smin;
            reg.smax_value = self.smax;
            reg.var_off = self.var_off;
        }
    }
}

/// Refine register range based on comparison with a constant.
/// 基于与常量的比较细化寄存器范围
pub fn refine_reg_const(
    reg: &BpfRegState,
    val: u64,
    cond: BranchCond,
    branch_taken: bool,
) -> RefinementResult {
    let mut result = RefinementResult::from_reg(reg);

    // Get the effective condition based on branch direction
    // 根据分支方向获取有效条件
    let eff_cond = if branch_taken { cond } else { cond.negate() };

    // Only refine scalar values
    // 仅细化标量值
    if reg.reg_type != BpfRegType::ScalarValue {
        return result;
    }

    let sval = val as i64;

    match eff_cond {
        BranchCond::Eq => {
            // reg == val
            result.umin = val;
            result.umax = val;
            result.smin = sval;
            result.smax = sval;
            result.var_off = Tnum::const_value(val);
            result.mark_refined();
        }
        BranchCond::Ne => {
            // reg != val
            // Can only refine if val is at a boundary
            // 仅当 val 在边界时才能细化
            if result.umin == val && result.umin < result.umax {
                result.umin = val + 1;
                result.mark_refined();
            }
            if result.umax == val && result.umax > result.umin {
                result.umax = val - 1;
                result.mark_refined();
            }
            if result.smin == sval && result.smin < result.smax {
                result.smin = sval + 1;
                result.mark_refined();
            }
            if result.smax == sval && result.smax > result.smin {
                result.smax = sval - 1;
                result.mark_refined();
            }
        }
        BranchCond::Gt => {
            // reg > val (unsigned)
            // reg > val（无符号）
            if val < u64::MAX {
                let new_min = val + 1;
                if new_min > result.umin {
                    result.umin = new_min;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Ge => {
            // reg >= val (unsigned)
            // reg >= val（无符号）
            if val > result.umin {
                result.umin = val;
                result.mark_refined();
            }
        }
        BranchCond::Lt => {
            // reg < val (unsigned)
            // reg < val（无符号）
            if val > 0 {
                let new_max = val - 1;
                if new_max < result.umax {
                    result.umax = new_max;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Le => {
            // reg <= val (unsigned)
            // reg <= val（无符号）
            if val < result.umax {
                result.umax = val;
                result.mark_refined();
            }
        }
        BranchCond::Sgt => {
            // reg > val (signed)
            // reg > val（有符号）
            if sval < i64::MAX {
                let new_min = sval + 1;
                if new_min > result.smin {
                    result.smin = new_min;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Sge => {
            // reg >= val (signed)
            // reg >= val（有符号）
            if sval > result.smin {
                result.smin = sval;
                result.mark_refined();
            }
        }
        BranchCond::Slt => {
            // reg < val (signed)
            // reg < val（有符号）
            if sval > i64::MIN {
                let new_max = sval - 1;
                if new_max < result.smax {
                    result.smax = new_max;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Sle => {
            // reg <= val (signed)
            // reg <= val（有符号）
            if sval < result.smax {
                result.smax = sval;
                result.mark_refined();
            }
        }
        BranchCond::Set => {
            // reg & val != 0 (when taken)
            // reg & val != 0（当跳转时）
            // When taken, at least one bit in the mask must be set
            // 当跳转时，掩码中至少一位必须被设置
            if branch_taken && val != 0 {
                // Can't easily refine range, but we know at least one bit is set
                // 不能轻易细化范围，但我们知道至少有一位被设置
                // Update tnum to reflect this
                // 更新 tnum 以反映这一点
                result.var_off = result.var_off.and(Tnum::const_value(val));
                if result.var_off.value != 0 {
                    result.mark_refined();
                }
            }
        }
    }

    // Synchronize signed and unsigned bounds
    // 同步有符号和无符号边界
    if result.refined {
        sync_bounds(&mut result);
    }

    result
}

/// Refine both registers based on comparison between them.
/// 基于两个寄存器之间的比较细化两者
pub fn refine_reg_reg(
    dst: &BpfRegState,
    src: &BpfRegState,
    cond: BranchCond,
    branch_taken: bool,
) -> (RefinementResult, RefinementResult) {
    let mut dst_result = RefinementResult::from_reg(dst);
    let mut src_result = RefinementResult::from_reg(src);

    // Only refine scalars
    // 仅细化标量
    if dst.reg_type != BpfRegType::ScalarValue || src.reg_type != BpfRegType::ScalarValue {
        return (dst_result, src_result);
    }

    let eff_cond = if branch_taken { cond } else { cond.negate() };

    match eff_cond {
        BranchCond::Eq => {
            // dst == src: ranges must intersect
            // dst == src：范围必须相交
            let new_umin = dst_result.umin.max(src_result.umin);
            let new_umax = dst_result.umax.min(src_result.umax);
            let new_smin = dst_result.smin.max(src_result.smin);
            let new_smax = dst_result.smax.min(src_result.smax);

            if new_umin != dst_result.umin || new_umax != dst_result.umax {
                dst_result.umin = new_umin;
                dst_result.umax = new_umax;
                dst_result.mark_refined();
            }
            if new_smin != dst_result.smin || new_smax != dst_result.smax {
                dst_result.smin = new_smin;
                dst_result.smax = new_smax;
                dst_result.mark_refined();
            }

            // Apply same to src
            // 对 src 应用相同
            if new_umin != src_result.umin || new_umax != src_result.umax {
                src_result.umin = new_umin;
                src_result.umax = new_umax;
                src_result.mark_refined();
            }
            if new_smin != src_result.smin || new_smax != src_result.smax {
                src_result.smin = new_smin;
                src_result.smax = new_smax;
                src_result.mark_refined();
            }
        }
        BranchCond::Ne => {
            // dst != src: limited refinement at boundaries
            // dst != src：在边界处有限细化
            // If src is a constant, refine dst
            // 如果 src 是常量，细化 dst
            if src_result.umin == src_result.umax {
                let const_val = src_result.umin;
                if dst_result.umin == const_val && dst_result.umin < dst_result.umax {
                    dst_result.umin = const_val + 1;
                    dst_result.mark_refined();
                }
                if dst_result.umax == const_val && dst_result.umax > dst_result.umin {
                    dst_result.umax = const_val - 1;
                    dst_result.mark_refined();
                }
            }
            // Similarly for dst constant
            // dst 常量类似
            if dst_result.umin == dst_result.umax {
                let const_val = dst_result.umin;
                if src_result.umin == const_val && src_result.umin < src_result.umax {
                    src_result.umin = const_val + 1;
                    src_result.mark_refined();
                }
                if src_result.umax == const_val && src_result.umax > src_result.umin {
                    src_result.umax = const_val - 1;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Gt => {
            // dst > src (unsigned)
            // dst > src（无符号）
            // dst_min > src_min possible, dst_max > src_max possible
            // dst_min > src_min 可能，dst_max > src_max 可能
            if src_result.umin < u64::MAX {
                let new_dst_min = src_result.umin + 1;
                if new_dst_min > dst_result.umin {
                    dst_result.umin = new_dst_min;
                    dst_result.mark_refined();
                }
            }
            if dst_result.umax > 0 {
                let new_src_max = dst_result.umax - 1;
                if new_src_max < src_result.umax {
                    src_result.umax = new_src_max;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Ge => {
            // dst >= src (unsigned)
            // dst >= src（无符号）
            if src_result.umin > dst_result.umin {
                dst_result.umin = src_result.umin;
                dst_result.mark_refined();
            }
            if dst_result.umax < src_result.umax {
                src_result.umax = dst_result.umax;
                src_result.mark_refined();
            }
        }
        BranchCond::Lt => {
            // dst < src (unsigned)
            // dst < src（无符号）
            if dst_result.umin > 0 {
                let new_src_min = dst_result.umin + 1;
                if new_src_min > src_result.umin {
                    src_result.umin = new_src_min;
                    src_result.mark_refined();
                }
            }
            if src_result.umax > 0 {
                let new_dst_max = src_result.umax - 1;
                if new_dst_max < dst_result.umax {
                    dst_result.umax = new_dst_max;
                    dst_result.mark_refined();
                }
            }
        }
        BranchCond::Le => {
            // dst <= src (unsigned)
            // dst <= src（无符号）
            if dst_result.umin > src_result.umin {
                src_result.umin = dst_result.umin;
                src_result.mark_refined();
            }
            if src_result.umax < dst_result.umax {
                dst_result.umax = src_result.umax;
                dst_result.mark_refined();
            }
        }
        BranchCond::Sgt => {
            // dst > src (signed)
            // dst > src（有符号）
            if src_result.smin < i64::MAX {
                let new_dst_min = src_result.smin + 1;
                if new_dst_min > dst_result.smin {
                    dst_result.smin = new_dst_min;
                    dst_result.mark_refined();
                }
            }
            if dst_result.smax > i64::MIN {
                let new_src_max = dst_result.smax - 1;
                if new_src_max < src_result.smax {
                    src_result.smax = new_src_max;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Sge => {
            // dst >= src (signed)
            // dst >= src（有符号）
            if src_result.smin > dst_result.smin {
                dst_result.smin = src_result.smin;
                dst_result.mark_refined();
            }
            if dst_result.smax < src_result.smax {
                src_result.smax = dst_result.smax;
                src_result.mark_refined();
            }
        }
        BranchCond::Slt => {
            // dst < src (signed)
            // dst < src（有符号）
            if dst_result.smin > i64::MIN {
                let new_src_min = dst_result.smin + 1;
                if new_src_min > src_result.smin {
                    src_result.smin = new_src_min;
                    src_result.mark_refined();
                }
            }
            if src_result.smax > i64::MIN {
                let new_dst_max = src_result.smax - 1;
                if new_dst_max < dst_result.smax {
                    dst_result.smax = new_dst_max;
                    dst_result.mark_refined();
                }
            }
        }
        BranchCond::Sle => {
            // dst <= src (signed)
            // dst <= src（有符号）
            if dst_result.smin > src_result.smin {
                src_result.smin = dst_result.smin;
                src_result.mark_refined();
            }
            if src_result.smax < dst_result.smax {
                dst_result.smax = src_result.smax;
                dst_result.mark_refined();
            }
        }
        BranchCond::Set => {
            // dst & src != 0
            // Limited refinement possible
            // 可能的有限细化
        }
    }

    // Synchronize bounds
    // 同步边界
    if dst_result.refined {
        sync_bounds(&mut dst_result);
    }
    if src_result.refined {
        sync_bounds(&mut src_result);
    }

    (dst_result, src_result)
}

/// Synchronize signed and unsigned bounds.
/// 同步有符号和无符号边界
fn sync_bounds(result: &mut RefinementResult) {
    // If umin/umax fit in signed range, update smin/smax
    // 如果 umin/umax 适合有符号范围，更新 smin/smax
    if result.umax <= i64::MAX as u64 {
        result.smin = result.smin.max(result.umin as i64);
        result.smax = result.smax.min(result.umax as i64);
    }

    // If smin/smax are non-negative, update umin/umax
    // 如果 smin/smax 是非负的，更新 umin/umax
    if result.smin >= 0 {
        result.umin = result.umin.max(result.smin as u64);
        if result.smax >= 0 {
            result.umax = result.umax.min(result.smax as u64);
        }
    }
}

/// Check if a branch condition can be determined statically.
/// 检查分支条件是否可以静态确定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchOutcome {
    /// Branch is always taken.
    /// 分支总是被执行
    AlwaysTaken,
    /// Branch is never taken.
    /// 分支从不被执行
    NeverTaken,
    /// Branch outcome is unknown.
    /// 分支结果未知
    Unknown,
}

/// Determine branch outcome from register ranges.
/// 从寄存器范围确定分支结果
pub fn determine_branch_outcome(
    dst: &BpfRegState,
    src_val: u64,
    cond: BranchCond,
) -> BranchOutcome {
    if dst.reg_type != BpfRegType::ScalarValue {
        return BranchOutcome::Unknown;
    }

    let sval = src_val as i64;

    match cond {
        BranchCond::Eq => {
            if dst.umin_value == dst.umax_value && dst.umin_value == src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value < src_val || dst.umin_value > src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Ne => {
            if dst.umax_value < src_val || dst.umin_value > src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value == dst.umax_value && dst.umin_value == src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Gt => {
            if dst.umin_value > src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value <= src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Ge => {
            if dst.umin_value >= src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value < src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Lt => {
            if dst.umax_value < src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value >= src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Le => {
            if dst.umax_value <= src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value > src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sgt => {
            if dst.smin_value > sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smax_value <= sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sge => {
            if dst.smin_value >= sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smax_value < sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Slt => {
            if dst.smax_value < sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smin_value >= sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sle => {
            if dst.smax_value <= sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smin_value > sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Set => {
            // reg & val != 0
            let known_bits = !dst.var_off.mask;
            let known_value = dst.var_off.value;

            // If we know all bits of (reg & val), we can determine outcome
            // 如果我们知道 (reg & val) 的所有位，我们可以确定结果
            if (known_bits & src_val) == src_val {
                if (known_value & src_val) != 0 {
                    BranchOutcome::AlwaysTaken
                } else {
                    BranchOutcome::NeverTaken
                }
            } else {
                BranchOutcome::Unknown
            }
        }
    }
}

/// Convenience wrapper for register-to-register comparison refinement.
/// 寄存器到寄存器比较细化的便捷包装器
///
/// This refines both registers based on the given condition being true
/// (branch taken). Returns refinement results for both registers.
/// 基于给定条件为真（分支被执行）细化两个寄存器。返回两个寄存器的细化结果。
///
/// # Arguments
/// # 参数
/// * `dst` - Destination register state / 目标寄存器状态
/// * `src` - Source register state / 源寄存器状态
/// * `cond` - The branch condition / 分支条件
/// * `is_32bit` - Whether this is a 32-bit comparison / 是否为 32 位比较
///
/// # Returns
/// # 返回
/// Tuple of (dst_refinement, src_refinement)
/// (dst_细化, src_细化) 的元组
pub fn refine_regs(
    dst: &BpfRegState,
    src: &BpfRegState,
    cond: BranchCond,
    _is_32bit: bool,
) -> (RefinementResult, RefinementResult) {
    // Use refine_reg_reg with branch_taken=true since the condition
    // represents what we know to be true on this path
    // 使用 branch_taken=true 调用 refine_reg_reg，因为条件
    // 代表我们知道在此路径上为真的内容
    refine_reg_reg(dst, src, cond, true)
}
