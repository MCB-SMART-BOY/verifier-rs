// SPDX-License-Identifier: GPL-2.0

//! Tracked numbers (tnum) - representing partially known values
//! 跟踪数（tnum）- 表示部分已知的值
//!
//! A tnum represents a value where some bits are known and others are unknown.
//! It consists of a `value` (known bits) and a `mask` (unknown bits).
//! tnum 表示一个某些位已知而其他位未知的值。
//! 它由 `value`（已知位）和 `mask`（未知位）组成。
//!
//! For any bit position:
//! 对于任何位位置：
//! - If mask bit is 0, the actual value at that position equals the value bit
//! - 如果掩码位为 0，该位置的实际值等于 value 位
//! - If mask bit is 1, the actual value at that position is unknown
//! - 如果掩码位为 1，该位置的实际值是未知的

use core::ops::{BitAnd, BitOr, BitXor};

/// A tracked number with known and unknown bits
/// 具有已知位和未知位的跟踪数
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tnum {
    /// Known bit values (only valid where mask is 0)
    /// 已知位值（仅在掩码为 0 的位置有效）
    pub value: u64,
    /// Mask of unknown bits (1 = unknown, 0 = known)
    /// 未知位的掩码（1 = 未知，0 = 已知）
    pub mask: u64,
}

impl Tnum {
    /// Create a new tnum with given value and mask
    /// 用给定的值和掩码创建新的 tnum
    pub fn new(value: u64, mask: u64) -> Self {
        Self {
            value: value & !mask,
            mask,
        }
    }

    /// Create a tnum representing a constant value (all bits known)
    /// 创建表示常量值的 tnum（所有位已知）
    pub fn const_value(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// Create a tnum representing a completely unknown value
    /// 创建表示完全未知值的 tnum
    pub fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    /// Create a tnum from a range [min, max]
    /// 从范围 [min, max] 创建 tnum
    pub fn range(min: u64, max: u64) -> Self {
        if min > max {
            return Self::unknown();
        }

        let chi = min ^ max;
        // Find the position of the highest differing bit
        // 找到最高差异位的位置
        let bits = if chi == 0 {
            0
        } else {
            64 - chi.leading_zeros()
        };

        // All bits below this position are unknown
        // 此位置以下的所有位都是未知的
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };

        Self {
            value: min & !mask,
            mask,
        }
    }

    /// Check if this tnum represents a constant (all bits known)
    /// 检查此 tnum 是否表示常量（所有位已知）
    pub fn is_const(&self) -> bool {
        self.mask == 0
    }

    /// Check if this tnum represents a completely unknown value (all bits unknown)
    /// 检查此 tnum 是否表示完全未知的值（所有位未知）
    pub fn is_unknown(&self) -> bool {
        self.mask == u64::MAX && self.value == 0
    }

    /// Check if all bits in the subreg (lower 32 bits) are known
    /// 检查子寄存器（低 32 位）中的所有位是否已知
    pub fn subreg_is_const(&self) -> bool {
        (self.mask & 0xFFFF_FFFF) == 0
    }

    /// Get the subreg (lower 32 bits) as a tnum
    /// 获取子寄存器（低 32 位）作为 tnum
    pub fn subreg(&self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// Clear the subreg (set lower 32 bits to zero, preserving upper bits)
    /// 清除子寄存器（将低 32 位设为零，保留高位）
    pub fn clear_subreg(&self) -> Self {
        Self {
            value: self.value & !0xFFFF_FFFF_u64,
            mask: self.mask & !0xFFFF_FFFF_u64,
        }
    }

    /// Create a tnum with const subreg value
    /// 创建具有常量子寄存器值的 tnum
    pub fn const_subreg(base: Tnum, value: u64) -> Self {
        Self {
            value: (base.value & !0xFFFF_FFFF_u64) | (value & 0xFFFF_FFFF),
            mask: base.mask & !0xFFFF_FFFF_u64,
        }
    }

    /// Get the minimum possible value
    /// 获取最小可能值
    pub fn min(&self) -> u64 {
        self.value
    }

    /// Get the maximum possible value
    /// 获取最大可能值
    pub fn max(&self) -> u64 {
        self.value | self.mask
    }

    /// Check if this tnum equals a constant value
    /// 检查此 tnum 是否等于常量值
    pub fn equals_const(&self, val: u64) -> bool {
        self.is_const() && self.value == val
    }

    /// Check if this tnum is within the range of another tnum
    /// 检查此 tnum 是否在另一个 tnum 的范围内
    pub fn is_within(&self, other: &Tnum) -> bool {
        // All known bits in other must match in self where self also knows them
        // other 中所有已知位在 self 也知道的位置必须匹配
        ((self.mask & other.mask) == self.mask)
            && ((self.value & !other.mask) == (other.value & !other.mask))
    }

    /// Check if this tnum is a subset of another (more constrained)
    /// 检查此 tnum 是否是另一个的子集（更受约束）
    /// Returns true if self's possible values are a subset of other's possible values
    /// 如果 self 的可能值是 other 可能值的子集，则返回 true
    pub fn is_subset_of(&self, other: &Tnum) -> bool {
        // self is a subset of other if:
        // self 是 other 的子集如果：
        // 1. self has no unknown bits that other doesn't have
        // 1. self 没有 other 没有的未知位
        // 2. where other has known bits, self must match
        // 2. 在 other 有已知位的地方，self 必须匹配

        // All bits unknown in other must also be unknown in self for this to be a subset
        // 所有在 other 中未知的位在 self 中也必须未知才是子集
        // Actually the opposite: self must have FEWER unknowns
        // 实际上相反：self 必须有更少的未知位
        // self.mask must have 0s everywhere other.mask has 0s
        // self.mask 必须在 other.mask 为 0 的地方都为 0
        if (self.mask & !other.mask) != 0 {
            // self has unknown bits where other has known bits - not a subset
            // self 在 other 有已知位的地方有未知位 - 不是子集
            // Wait, that's wrong. If self knows a bit and other doesn't, that's fine.
            // 等等，这是错的。如果 self 知道一位而 other 不知道，那没问题。
            // The issue is if self could have a value that other can't.
            // 问题是 self 是否可能有 other 不可能有的值。
        }

        // For self to be a subset:
        // 要使 self 成为子集：
        // - Where other knows a bit (mask=0), self must have the same value or also know it
        // - 在 other 知道一位的地方（mask=0），self 必须有相同的值或也知道它
        // - self's possible value range must be within other's range
        // - self 的可能值范围必须在 other 的范围内

        // Check that self's known bits match other's known bits where other knows them
        // 检查 self 的已知位在 other 知道的地方与 other 的已知位匹配
        let other_known_mask = !other.mask;
        if (self.value & other_known_mask) != (other.value & other_known_mask) {
            // self has a different known value where other also knows - conflict
            // self 在 other 也知道的地方有不同的已知值 - 冲突
            // But wait, self might not know that bit
            // 但等等，self 可能不知道那一位
            if (self.mask & other_known_mask) != other_known_mask {
                // self knows some bits that other knows, check they match
                // self 知道 other 知道的一些位，检查它们是否匹配
                let both_known = !self.mask & !other.mask;
                if (self.value & both_known) != (other.value & both_known) {
                    return false;
                }
            }
        }

        // self's range must be within other's range
        // self 的范围必须在 other 的范围内
        self.min() >= other.min() && self.max() <= other.max()
    }

    /// Intersect two tnums (tighten bounds)
    /// 求两个 tnum 的交集（收紧边界）
    pub fn intersect(self, other: Tnum) -> Self {
        let v = self.value | other.value;
        let mu = self.mask & other.mask;
        // Check for conflict: if bits are known in both but differ, result is impossible
        // 检查冲突：如果位在两者中都已知但不同，结果是不可能的
        // We handle this by keeping the intersection mask
        // 我们通过保持交集掩码来处理这个问题
        Self {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Arithmetic right shift
    /// 算术右移
    pub fn arsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: ((self.value as i64) >> shift) as u64,
            mask: ((self.mask as i64) >> shift) as u64,
        }
    }

    /// Logical right shift
    /// 逻辑右移
    pub fn rsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    /// Left shift
    /// 左移
    pub fn lsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: self.value << shift,
            mask: self.mask << shift,
        }
    }

    /// Add two tnums
    /// 两个 tnum 相加
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Tnum) -> Self {
        let sm = self.mask.wrapping_add(other.mask);
        let sv = self.value.wrapping_add(other.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Self {
            value: sv & !mu,
            mask: mu,
        }
    }

    /// Subtract two tnums
    /// 两个 tnum 相减
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Tnum) -> Self {
        let dv = self.value.wrapping_sub(other.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(other.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | other.mask;
        Self {
            value: dv & !mu,
            mask: mu,
        }
    }

    /// Multiply two tnums
    /// 两个 tnum 相乘
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Tnum) -> Self {
        let acc_v = self.value.wrapping_mul(other.value);
        // Multiplication with unknowns is complex; simplify to unknown result
        // 带未知位的乘法很复杂；简化为未知结果
        // if either has unknown bits
        // 如果任一方有未知位
        if self.mask != 0 || other.mask != 0 {
            Self {
                value: 0,
                mask: u64::MAX,
            }
        } else {
            Self {
                value: acc_v,
                mask: 0,
            }
        }
    }

    /// Cast to 32-bit (zero-extend lower 32 bits)
    /// 转换为 32 位（零扩展低 32 位）
    pub fn cast_u32(self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// Sign-extend from 32-bit to 64-bit
    /// 从 32 位符号扩展到 64 位
    pub fn sext32(self) -> Self {
        let value = self.value as i32 as i64 as u64;
        let mask = self.mask as i32 as i64 as u64;
        Self { value, mask }
    }

    /// Check if value might be in the specified range
    /// 检查值是否可能在指定范围内
    pub fn in_range(&self, min: u64, max: u64) -> bool {
        self.min() <= max && self.max() >= min
    }

    /// Get 64-bit unsigned bounds from tnum
    /// 从 tnum 获取 64 位无符号边界
    pub fn u64_bounds(&self) -> (u64, u64) {
        (self.min(), self.max())
    }

    /// Get 64-bit signed bounds from tnum
    /// 从 tnum 获取 64 位有符号边界
    pub fn s64_bounds(&self) -> (i64, i64) {
        // If sign bit is known
        // 如果符号位已知
        if self.mask & (1u64 << 63) == 0 {
            // Sign bit is known
            // 符号位已知
            if self.value & (1u64 << 63) != 0 {
                // Negative: min is most negative, max is least negative
                // 负数：min 是最负的，max 是最不负的
                (self.min() as i64, self.max() as i64)
            } else {
                // Positive
                // 正数
                (self.min() as i64, self.max() as i64)
            }
        } else {
            // Sign bit unknown - could be anything
            // 符号位未知 - 可能是任何值
            (i64::MIN, i64::MAX)
        }
    }

    /// Get 32-bit unsigned bounds from lower 32 bits
    /// 从低 32 位获取 32 位无符号边界
    pub fn u32_bounds(&self) -> (u32, u32) {
        let min = self.value as u32;
        let max = (self.value | self.mask) as u32;
        (min, max)
    }

    /// Get 32-bit signed bounds from lower 32 bits
    /// 从低 32 位获取 32 位有符号边界
    pub fn s32_bounds(&self) -> (i32, i32) {
        let subreg_mask = self.mask as u32;
        let subreg_value = self.value as u32;

        // If sign bit of 32-bit value is known
        // 如果 32 位值的符号位已知
        if subreg_mask & (1u32 << 31) == 0 {
            (subreg_value as i32, (subreg_value | subreg_mask) as i32)
        } else {
            (i32::MIN, i32::MAX)
        }
    }

    /// Truncate to 32 bits (for ALU32 operations)
    /// 截断为 32 位（用于 ALU32 操作）
    pub fn truncate_32(self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// XOR operation (method form for bounds.rs)
    /// XOR 操作（bounds.rs 的方法形式）
    pub fn xor(self, other: Tnum) -> Self {
        self ^ other
    }

    /// OR operation (method form for bounds.rs)
    /// OR 操作（bounds.rs 的方法形式）
    pub fn or(self, other: Tnum) -> Self {
        self | other
    }

    /// AND operation (method form for bounds.rs)
    /// AND 操作（bounds.rs 的方法形式）
    pub fn and(self, other: Tnum) -> Self {
        self & other
    }
}

impl BitAnd for Tnum {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        Self {
            value: v,
            mask: alpha & beta & !v,
        }
    }
}

impl BitOr for Tnum {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        let v = self.value | other.value;
        let mu = self.mask | other.mask;
        Self {
            value: v,
            mask: mu & !v,
        }
    }
}

impl BitXor for Tnum {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        let v = self.value ^ other.value;
        let mu = self.mask | other.mask;
        Self {
            value: v & !mu,
            mask: mu,
        }
    }
}
