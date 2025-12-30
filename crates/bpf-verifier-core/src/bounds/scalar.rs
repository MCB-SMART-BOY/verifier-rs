// SPDX-License-Identifier: GPL-2.0

//! Signed and unsigned bounds tracking
//! 有符号和无符号边界跟踪
//!
//! This module implements comprehensive bounds tracking for scalar values,
//! including signed/unsigned 32-bit and 64-bit bounds with proper cross-inference.
//! 本模块实现标量值的全面边界跟踪，包括有符号/无符号 32 位和 64 位边界以及正确的交叉推断。

use super::tnum::Tnum;
use crate::core::error::{Result, VerifierError};

/// 32-bit and 64-bit bounds for a scalar value
/// 标量值的 32 位和 64 位边界
#[derive(Debug, Clone, Copy)]
pub struct ScalarBounds {
    /// Tracked bits (known value/unknown mask)
    /// 跟踪位（已知值/未知掩码）
    pub var_off: Tnum,
    /// Minimum unsigned 64-bit value
    /// 最小无符号 64 位值
    pub umin_value: u64,
    /// Maximum unsigned 64-bit value
    /// 最大无符号 64 位值
    pub umax_value: u64,
    /// Minimum signed 64-bit value
    /// 最小有符号 64 位值
    pub smin_value: i64,
    /// Maximum signed 64-bit value
    /// 最大有符号 64 位值
    pub smax_value: i64,
    /// Minimum unsigned 32-bit value
    /// 最小无符号 32 位值
    pub u32_min_value: u32,
    /// Maximum unsigned 32-bit value
    /// 最大无符号 32 位值
    pub u32_max_value: u32,
    /// Minimum signed 32-bit value
    /// 最小有符号 32 位值
    pub s32_min_value: i32,
    /// Maximum signed 32-bit value
    /// 最大有符号 32 位值
    pub s32_max_value: i32,
}

impl Default for ScalarBounds {
    fn default() -> Self {
        Self::unknown()
    }
}

impl ScalarBounds {
    /// Create fully unknown bounds
    /// 创建完全未知的边界
    pub fn unknown() -> Self {
        Self {
            var_off: Tnum::unknown(),
            umin_value: 0,
            umax_value: u64::MAX,
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            u32_min_value: 0,
            u32_max_value: u32::MAX,
            s32_min_value: i32::MIN,
            s32_max_value: i32::MAX,
        }
    }

    /// Create bounds for a known constant
    /// 为已知常量创建边界
    pub fn known(val: u64) -> Self {
        Self {
            var_off: Tnum::const_value(val),
            umin_value: val,
            umax_value: val,
            smin_value: val as i64,
            smax_value: val as i64,
            u32_min_value: val as u32,
            u32_max_value: val as u32,
            s32_min_value: val as i32,
            s32_max_value: val as i32,
        }
    }

    /// Check if this is a known constant
    /// 检查是否为已知常量
    pub fn is_const(&self) -> bool {
        self.var_off.is_const() && self.umin_value == self.umax_value
    }

    /// Get the constant value if known
    /// 如果已知则获取常量值
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.umin_value)
        } else {
            None
        }
    }

    /// Check if bounds are sane (min <= max for all)
    /// 检查边界是否合理（所有的 min <= max）
    pub fn is_sane(&self) -> bool {
        self.umin_value <= self.umax_value
            && self.smin_value <= self.smax_value
            && self.u32_min_value <= self.u32_max_value
            && self.s32_min_value <= self.s32_max_value
    }

    /// Update 64-bit unsigned bounds from tnum
    /// 从 tnum 更新 64 位无符号边界
    pub fn update_u64_from_tnum(&mut self) {
        let (min, max) = self.var_off.u64_bounds();
        self.umin_value = self.umin_value.max(min);
        self.umax_value = self.umax_value.min(max);
    }

    /// Update 64-bit signed bounds from tnum
    /// 从 tnum 更新 64 位有符号边界
    pub fn update_s64_from_tnum(&mut self) {
        let (min, max) = self.var_off.s64_bounds();
        self.smin_value = self.smin_value.max(min);
        self.smax_value = self.smax_value.min(max);
    }

    /// Update 32-bit unsigned bounds from tnum
    /// 从 tnum 更新 32 位无符号边界
    pub fn update_u32_from_tnum(&mut self) {
        let (min, max) = self.var_off.u32_bounds();
        self.u32_min_value = self.u32_min_value.max(min);
        self.u32_max_value = self.u32_max_value.min(max);
    }

    /// Update 32-bit signed bounds from tnum
    /// 从 tnum 更新 32 位有符号边界
    pub fn update_s32_from_tnum(&mut self) {
        let (min, max) = self.var_off.s32_bounds();
        self.s32_min_value = self.s32_min_value.max(min);
        self.s32_max_value = self.s32_max_value.min(max);
    }

    /// Deduce all bounds from each other (cross-inference)
    /// 从彼此推断所有边界（交叉推断）
    pub fn deduce_bounds(&mut self) {
        // Update tnum-derived bounds
        // 更新从 tnum 派生的边界
        self.update_u64_from_tnum();
        self.update_s64_from_tnum();
        self.update_u32_from_tnum();
        self.update_s32_from_tnum();

        // Cross-infer between signed and unsigned 64-bit
        // 在有符号和无符号 64 位之间交叉推断
        self.cross_infer_64();

        // Cross-infer between 64-bit and 32-bit
        // 在 64 位和 32 位之间交叉推断
        self.cross_infer_32_64();

        // Update tnum from bounds
        // 从边界更新 tnum
        self.update_tnum_from_bounds();
    }

    /// Cross-infer between signed and unsigned 64-bit bounds
    /// 在有符号和无符号 64 位边界之间交叉推断
    fn cross_infer_64(&mut self) {
        // If both bounds are non-negative, signed and unsigned are same
        // 如果两个边界都是非负的，有符号和无符号是相同的
        if self.smin_value >= 0 {
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            if self.smax_value >= 0 {
                self.umax_value = self.umax_value.min(self.smax_value as u64);
            }
        }

        // If unsigned fits in positive signed range
        // 如果无符号在正有符号范围内
        if self.umax_value <= i64::MAX as u64 {
            self.smin_value = self.smin_value.max(self.umin_value as i64);
            self.smax_value = self.smax_value.min(self.umax_value as i64);
        }

        // If both signed bounds are negative
        // 如果两个有符号边界都是负的
        if self.smax_value < 0 {
            // Values are in high unsigned range
            // 值在高无符号范围内
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            self.umax_value = self.umax_value.min(self.smax_value as u64);
        }
    }

    /// Cross-infer between 64-bit and 32-bit bounds
    /// 在 64 位和 32 位边界之间交叉推断
    fn cross_infer_32_64(&mut self) {
        // If 64-bit value fits in 32-bit unsigned
        // 如果 64 位值适合 32 位无符号
        if self.umax_value <= u32::MAX as u64 {
            self.u32_min_value = self.u32_min_value.max(self.umin_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.umax_value as u32);
        }

        // If 64-bit value fits in 32-bit signed positive
        // 如果 64 位值适合 32 位有符号正数
        if self.smin_value >= 0 && self.smax_value <= i32::MAX as i64 {
            self.s32_min_value = self.s32_min_value.max(self.smin_value as i32);
            self.s32_max_value = self.s32_max_value.min(self.smax_value as i32);
        }

        // If 32-bit is known and no subreg modification
        // 如果 32 位已知且没有子寄存器修改
        if self.u32_min_value == self.u32_max_value && self.umax_value <= u32::MAX as u64 {
            let val = self.u32_min_value as u64;
            self.umin_value = self.umin_value.max(val);
            self.umax_value = self.umax_value.min(val);
        }
    }

    /// Update tnum from bounds
    /// 从边界更新 tnum
    fn update_tnum_from_bounds(&mut self) {
        // If we have a tighter range than tnum suggests, update it
        // 如果我们有比 tnum 建议的更紧的范围，更新它
        if self.umin_value == self.umax_value {
            self.var_off = Tnum::const_value(self.umin_value);
        }
    }

    /// Apply ALU operation and return new bounds
    /// 应用 ALU 操作并返回新边界
    pub fn alu_op(&self, op: u8, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result;

        match op {
            0x00 => {
                // ADD - 加法
                result = self.add(other, is_64)?;
            }
            0x10 => {
                // SUB - 减法
                result = self.sub(other, is_64)?;
            }
            0x20 => {
                // MUL - 乘法
                result = self.mul(other, is_64)?;
            }
            0x30 => {
                // DIV - 除法
                result = self.div(other, is_64)?;
            }
            0x40 => {
                // OR - 或
                result = self.or(other);
            }
            0x50 => {
                // AND - 与
                result = self.and(other);
            }
            0x60 => {
                // LSH - 左移
                result = self.lsh(other, is_64)?;
            }
            0x70 => {
                // RSH - 逻辑右移
                result = self.rsh(other, is_64)?;
            }
            0x80 => {
                // NEG - 取反
                result = self.neg(is_64);
            }
            0x90 => {
                // MOD - 取模
                result = self.mod_op(other, is_64)?;
            }
            0xa0 => {
                // XOR - 异或
                result = self.xor(other);
            }
            0xb0 => {
                // MOV - 移动
                result = *other;
            }
            0xc0 => {
                // ARSH - 算术右移
                result = self.arsh(other, is_64)?;
            }
            _ => {
                return Err(VerifierError::InvalidInstruction(0));
            }
        }

        result.deduce_bounds();
        Ok(result)
    }

    /// Add operation - computes bounds for `self + other`
    /// 加法操作 - 计算 `self + other` 的边界
    pub fn add(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.add(other.var_off);

        // Unsigned addition with overflow check
        // 带溢出检查的无符号加法
        let (umin, umin_overflow) = self.umin_value.overflowing_add(other.umin_value);
        let (umax, umax_overflow) = self.umax_value.overflowing_add(other.umax_value);

        if !umin_overflow && !umax_overflow {
            result.umin_value = umin;
            result.umax_value = umax;
        }

        // Signed addition with overflow check
        // 带溢出检查的有符号加法
        let (smin, smin_overflow) = self.smin_value.overflowing_add(other.smin_value);
        let (smax, smax_overflow) = self.smax_value.overflowing_add(other.smax_value);

        if !smin_overflow && !smax_overflow {
            result.smin_value = smin;
            result.smax_value = smax;
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Subtract operation
    /// 减法操作
    pub fn sub(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.sub(other.var_off);

        // Unsigned subtraction
        // 无符号减法
        if self.umin_value >= other.umax_value {
            result.umin_value = self.umin_value - other.umax_value;
        }
        if self.umax_value >= other.umin_value {
            result.umax_value = self.umax_value - other.umin_value;
        }

        // Signed subtraction
        // 有符号减法
        let (smin, smin_overflow) = self.smin_value.overflowing_sub(other.smax_value);
        let (smax, smax_overflow) = self.smax_value.overflowing_sub(other.smin_value);

        if !smin_overflow {
            result.smin_value = smin;
        }
        if !smax_overflow {
            result.smax_value = smax;
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Multiply operation
    /// 乘法操作
    pub fn mul(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();

        // For multiplication, if both are known constants
        // 对于乘法，如果两者都是已知常量
        if self.is_const() && other.is_const() {
            let val = self.umin_value.wrapping_mul(other.umin_value);
            result = ScalarBounds::known(val);
        } else {
            // Conservative: multiply bounds if no overflow
            // 保守：如果没有溢出则乘以边界
            let (umax, overflow) = self.umax_value.overflowing_mul(other.umax_value);
            if !overflow {
                result.umax_value = umax;
                result.umin_value = self.umin_value.saturating_mul(other.umin_value);
            }
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Division operation
    /// 除法操作
    pub fn div(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        // Check for division by zero
        // 检查除以零
        if other.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }

        let mut result = ScalarBounds::unknown();

        // If divisor is known constant
        // 如果除数是已知常量
        if other.is_const() {
            let divisor = other.umin_value;
            result.umin_value = self.umin_value / divisor;
            result.umax_value = self.umax_value / divisor;
        } else if other.umin_value > 0 {
            // Divisor is positive
            // 除数是正数
            result.umax_value = self.umax_value / other.umin_value;
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// OR operation
    /// 或操作
    pub fn or(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.or(other.var_off);

        // For OR, result >= max(a, b) and result <= a | b (with unknown bits set)
        // 对于 OR，result >= max(a, b) 且 result <= a | b（未知位设置）
        result.umin_value = self.umin_value.max(other.umin_value);

        result
    }

    /// AND operation
    /// 与操作
    pub fn and(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.and(other.var_off);

        // For AND, result <= min(a, b)
        // 对于 AND，result <= min(a, b)
        result.umax_value = self.umax_value.min(other.umax_value);
        result.umin_value = 0;

        result
    }

    /// Left shift operation
    /// 左移操作
    pub fn lsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
        // 如果移位量已知
        if other.is_const() {
            let shift = other.umin_value as u32;
            if shift > max_shift {
                result = ScalarBounds::known(0);
            } else {
                result.var_off = self.var_off.lsh(shift as u8);
                result.umin_value = self.umin_value << shift;
                let (umax, overflow) = self.umax_value.overflowing_shl(shift);
                if !overflow {
                    result.umax_value = umax;
                }
            }
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Right shift operation (logical)
    /// 右移操作（逻辑）
    pub fn rsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
        // 如果移位量已知
        if other.is_const() {
            let shift = other.umin_value as u32;
            if shift > max_shift {
                result = ScalarBounds::known(0);
            } else {
                result.var_off = self.var_off.rsh(shift as u8);
                result.umin_value = self.umin_value >> shift;
                result.umax_value = self.umax_value >> shift;
            }
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Arithmetic right shift
    /// 算术右移
    pub fn arsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
        // 如果移位量已知
        if other.is_const() {
            let shift = other.umin_value as u32;
            if shift <= max_shift {
                result.smin_value = self.smin_value >> shift;
                result.smax_value = self.smax_value >> shift;
            }
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// Negation
    /// 取反
    fn neg(&self, is_64: bool) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();

        // -a for signed values
        // 有符号值的 -a
        if self.smin_value > i64::MIN {
            result.smax_value = -(self.smin_value);
        }
        if self.smax_value > i64::MIN {
            result.smin_value = -(self.smax_value);
        }

        if !is_64 {
            result.truncate_to_32();
        }

        result
    }

    /// Modulo operation
    /// 取模操作
    fn mod_op(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        // Check for mod by zero
        // 检查对零取模
        if other.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }

        let mut result = ScalarBounds::unknown();

        // Result is always less than the divisor
        // 结果总是小于除数
        result.umin_value = 0;
        result.umax_value = other.umax_value - 1;

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// XOR operation
    /// 异或操作
    pub fn xor(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.xor(other.var_off);

        // XOR with self is always 0
        // 与自身异或总是 0
        if self.is_const() && other.is_const() && self.umin_value == other.umin_value {
            return ScalarBounds::known(0);
        }

        result
    }

    /// Truncate bounds to 32-bit
    /// 将边界截断为 32 位
    pub fn truncate_to_32(&mut self) {
        // 64-bit bounds become 32-bit
        // 64 位边界变为 32 位
        self.umin_value &= u32::MAX as u64;
        self.umax_value = (self.umax_value & u32::MAX as u64).min(u32::MAX as u64);
        self.smin_value = (self.smin_value as i32) as i64;
        self.smax_value = (self.smax_value as i32) as i64;

        // 32-bit bounds from original values
        // 从原始值得到 32 位边界
        self.u32_min_value = self.umin_value as u32;
        self.u32_max_value = self.umax_value as u32;
        self.s32_min_value = self.smin_value as i32;
        self.s32_max_value = self.smax_value as i32;

        // Update tnum
        // 更新 tnum
        self.var_off = self.var_off.truncate_32();
    }

    /// Zero-extend 32-bit bounds to 64-bit
    /// 将 32 位边界零扩展为 64 位
    pub fn zext_32_to_64(&mut self) {
        self.umin_value = self.u32_min_value as u64;
        self.umax_value = self.u32_max_value as u64;
        self.smin_value = self.u32_min_value as i64;
        self.smax_value = self.u32_max_value as i64;
    }

    /// Sign-extend 32-bit bounds to 64-bit
    /// 将 32 位边界符号扩展为 64 位
    pub fn sext_32_to_64(&mut self) {
        self.smin_value = self.s32_min_value as i64;
        self.smax_value = self.s32_max_value as i64;

        if self.s32_min_value >= 0 {
            self.umin_value = self.s32_min_value as u64;
            self.umax_value = self.s32_max_value as u64;
        } else if self.s32_max_value < 0 {
            self.umin_value = self.s32_min_value as i64 as u64;
            self.umax_value = self.s32_max_value as i64 as u64;
        } else {
            // Crosses zero - spans large range
            // 跨越零 - 跨越大范围
            self.umin_value = 0;
            self.umax_value = u64::MAX;
        }
    }

    /// Check if value could be negative (signed)
    /// 检查值是否可能为负（有符号）
    pub fn could_be_negative(&self) -> bool {
        self.smin_value < 0
    }

    /// Check if value is definitely non-negative
    /// 检查值是否肯定是非负的
    pub fn is_non_negative(&self) -> bool {
        self.smin_value >= 0
    }

    /// Adjust bounds after conditional jump (value comparison)
    /// 在条件跳转后调整边界（值比较）
    pub fn adjust_for_cmp(&mut self, cmp_val: u64, op: u8, is_jmp_taken: bool) {
        match op {
            0x10 => {
                // JEQ - equal - 相等
                if is_jmp_taken {
                    *self = ScalarBounds::known(cmp_val);
                }
                // If not taken, we know they're not equal (no tight bound change)
                // 如果未跳转，我们知道它们不相等（无紧边界变化）
            }
            0x20 => {
                // JGT - greater than (unsigned) - 大于（无符号）
                if is_jmp_taken {
                    self.umin_value = self.umin_value.max(cmp_val + 1);
                } else {
                    self.umax_value = self.umax_value.min(cmp_val);
                }
            }
            0x30 => {
                // JGE - greater or equal (unsigned) - 大于等于（无符号）
                if is_jmp_taken {
                    self.umin_value = self.umin_value.max(cmp_val);
                } else if cmp_val > 0 {
                    self.umax_value = self.umax_value.min(cmp_val - 1);
                }
            }
            0x50 => {
                // JNE - not equal - 不相等
                if is_jmp_taken {
                    // We know they're not equal
                    // 我们知道它们不相等
                } else {
                    *self = ScalarBounds::known(cmp_val);
                }
            }
            0x60 => {
                // JSGT - greater than (signed) - 大于（有符号）
                if is_jmp_taken {
                    self.smin_value = self.smin_value.max(cmp_val as i64 + 1);
                } else {
                    self.smax_value = self.smax_value.min(cmp_val as i64);
                }
            }
            0x70 => {
                // JSGE - greater or equal (signed) - 大于等于（有符号）
                if is_jmp_taken {
                    self.smin_value = self.smin_value.max(cmp_val as i64);
                } else {
                    self.smax_value = self.smax_value.min(cmp_val as i64 - 1);
                }
            }
            0xa0 => {
                // JLT - less than (unsigned) - 小于（无符号）
                if is_jmp_taken && cmp_val > 0 {
                    self.umax_value = self.umax_value.min(cmp_val - 1);
                } else {
                    self.umin_value = self.umin_value.max(cmp_val);
                }
            }
            0xb0 => {
                // JLE - less or equal (unsigned) - 小于等于（无符号）
                if is_jmp_taken {
                    self.umax_value = self.umax_value.min(cmp_val);
                } else {
                    self.umin_value = self.umin_value.max(cmp_val + 1);
                }
            }
            0xc0 => {
                // JSLT - less than (signed) - 小于（有符号）
                if is_jmp_taken {
                    self.smax_value = self.smax_value.min(cmp_val as i64 - 1);
                } else {
                    self.smin_value = self.smin_value.max(cmp_val as i64);
                }
            }
            0xd0 => {
                // JSLE - less or equal (signed) - 小于等于（有符号）
                if is_jmp_taken {
                    self.smax_value = self.smax_value.min(cmp_val as i64);
                } else {
                    self.smin_value = self.smin_value.max(cmp_val as i64 + 1);
                }
            }
            _ => {}
        }

        self.deduce_bounds();
    }
}
