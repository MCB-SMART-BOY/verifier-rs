//! Signed and unsigned bounds tracking
//!
//! This module implements comprehensive bounds tracking for scalar values,
//! including signed/unsigned 32-bit and 64-bit bounds with proper cross-inference.

use super::tnum::Tnum;
use crate::core::error::{Result, VerifierError};

/// 32-bit and 64-bit bounds for a scalar value
#[derive(Debug, Clone, Copy)]
pub struct ScalarBounds {
    /// Tracked bits (known value/unknown mask)
    pub var_off: Tnum,
    /// Minimum unsigned 64-bit value
    pub umin_value: u64,
    /// Maximum unsigned 64-bit value
    pub umax_value: u64,
    /// Minimum signed 64-bit value
    pub smin_value: i64,
    /// Maximum signed 64-bit value
    pub smax_value: i64,
    /// Minimum unsigned 32-bit value
    pub u32_min_value: u32,
    /// Maximum unsigned 32-bit value
    pub u32_max_value: u32,
    /// Minimum signed 32-bit value
    pub s32_min_value: i32,
    /// Maximum signed 32-bit value
    pub s32_max_value: i32,
}

impl Default for ScalarBounds {
    fn default() -> Self {
        Self::unknown()
    }
}

impl ScalarBounds {
    /// Create fully unknown bounds
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
    pub fn is_const(&self) -> bool {
        self.var_off.is_const() && self.umin_value == self.umax_value
    }

    /// Get the constant value if known
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.umin_value)
        } else {
            None
        }
    }

    /// Check if bounds are sane (min <= max for all)
    pub fn is_sane(&self) -> bool {
        self.umin_value <= self.umax_value
            && self.smin_value <= self.smax_value
            && self.u32_min_value <= self.u32_max_value
            && self.s32_min_value <= self.s32_max_value
    }

    /// Update 64-bit unsigned bounds from tnum
    pub fn update_u64_from_tnum(&mut self) {
        let (min, max) = self.var_off.u64_bounds();
        self.umin_value = self.umin_value.max(min);
        self.umax_value = self.umax_value.min(max);
    }

    /// Update 64-bit signed bounds from tnum
    pub fn update_s64_from_tnum(&mut self) {
        let (min, max) = self.var_off.s64_bounds();
        self.smin_value = self.smin_value.max(min);
        self.smax_value = self.smax_value.min(max);
    }

    /// Update 32-bit unsigned bounds from tnum
    pub fn update_u32_from_tnum(&mut self) {
        let (min, max) = self.var_off.u32_bounds();
        self.u32_min_value = self.u32_min_value.max(min);
        self.u32_max_value = self.u32_max_value.min(max);
    }

    /// Update 32-bit signed bounds from tnum
    pub fn update_s32_from_tnum(&mut self) {
        let (min, max) = self.var_off.s32_bounds();
        self.s32_min_value = self.s32_min_value.max(min);
        self.s32_max_value = self.s32_max_value.min(max);
    }

    /// Deduce all bounds from each other (cross-inference)
    pub fn deduce_bounds(&mut self) {
        // Update tnum-derived bounds
        self.update_u64_from_tnum();
        self.update_s64_from_tnum();
        self.update_u32_from_tnum();
        self.update_s32_from_tnum();

        // Cross-infer between signed and unsigned 64-bit
        self.cross_infer_64();

        // Cross-infer between 64-bit and 32-bit
        self.cross_infer_32_64();

        // Update tnum from bounds
        self.update_tnum_from_bounds();
    }

    /// Cross-infer between signed and unsigned 64-bit bounds
    fn cross_infer_64(&mut self) {
        // If both bounds are non-negative, signed and unsigned are same
        if self.smin_value >= 0 {
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            if self.smax_value >= 0 {
                self.umax_value = self.umax_value.min(self.smax_value as u64);
            }
        }

        // If unsigned fits in positive signed range
        if self.umax_value <= i64::MAX as u64 {
            self.smin_value = self.smin_value.max(self.umin_value as i64);
            self.smax_value = self.smax_value.min(self.umax_value as i64);
        }

        // If both signed bounds are negative
        if self.smax_value < 0 {
            // Values are in high unsigned range
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            self.umax_value = self.umax_value.min(self.smax_value as u64);
        }
    }

    /// Cross-infer between 64-bit and 32-bit bounds
    fn cross_infer_32_64(&mut self) {
        // If 64-bit value fits in 32-bit unsigned
        if self.umax_value <= u32::MAX as u64 {
            self.u32_min_value = self.u32_min_value.max(self.umin_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.umax_value as u32);
        }

        // If 64-bit value fits in 32-bit signed positive
        if self.smin_value >= 0 && self.smax_value <= i32::MAX as i64 {
            self.s32_min_value = self.s32_min_value.max(self.smin_value as i32);
            self.s32_max_value = self.s32_max_value.min(self.smax_value as i32);
        }

        // If 32-bit is known and no subreg modification
        if self.u32_min_value == self.u32_max_value && self.umax_value <= u32::MAX as u64 {
            let val = self.u32_min_value as u64;
            self.umin_value = self.umin_value.max(val);
            self.umax_value = self.umax_value.min(val);
        }
    }

    /// Update tnum from bounds
    fn update_tnum_from_bounds(&mut self) {
        // If we have a tighter range than tnum suggests, update it
        if self.umin_value == self.umax_value {
            self.var_off = Tnum::const_value(self.umin_value);
        }
    }

    /// Apply ALU operation and return new bounds
    pub fn alu_op(&self, op: u8, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result;

        match op {
            0x00 => { // ADD
                result = self.add(other, is_64)?;
            }
            0x10 => { // SUB
                result = self.sub(other, is_64)?;
            }
            0x20 => { // MUL
                result = self.mul(other, is_64)?;
            }
            0x30 => { // DIV
                result = self.div(other, is_64)?;
            }
            0x40 => { // OR
                result = self.or(other);
            }
            0x50 => { // AND
                result = self.and(other);
            }
            0x60 => { // LSH
                result = self.lsh(other, is_64)?;
            }
            0x70 => { // RSH
                result = self.rsh(other, is_64)?;
            }
            0x80 => { // NEG
                result = self.neg(is_64);
            }
            0x90 => { // MOD
                result = self.mod_op(other, is_64)?;
            }
            0xa0 => { // XOR
                result = self.xor(other);
            }
            0xb0 => { // MOV
                result = *other;
            }
            0xc0 => { // ARSH
                result = self.arsh(other, is_64)?;
            }
            _ => {
                return Err(VerifierError::InvalidInstruction(0));
            }
        }

        result.deduce_bounds();
        Ok(result)
    }

    /// Add operation
    fn add(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.add(other.var_off);

        // Unsigned addition with overflow check
        let (umin, umin_overflow) = self.umin_value.overflowing_add(other.umin_value);
        let (umax, umax_overflow) = self.umax_value.overflowing_add(other.umax_value);

        if !umin_overflow && !umax_overflow {
            result.umin_value = umin;
            result.umax_value = umax;
        }

        // Signed addition with overflow check
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
    fn sub(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.sub(other.var_off);

        // Unsigned subtraction
        if self.umin_value >= other.umax_value {
            result.umin_value = self.umin_value - other.umax_value;
        }
        if self.umax_value >= other.umin_value {
            result.umax_value = self.umax_value - other.umin_value;
        }

        // Signed subtraction
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
    fn mul(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();

        // For multiplication, if both are known constants
        if self.is_const() && other.is_const() {
            let val = self.umin_value.wrapping_mul(other.umin_value);
            result = ScalarBounds::known(val);
        } else {
            // Conservative: multiply bounds if no overflow
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
    fn div(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        // Check for division by zero
        if other.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }

        let mut result = ScalarBounds::unknown();

        // If divisor is known constant
        if other.is_const() {
            let divisor = other.umin_value;
            result.umin_value = self.umin_value / divisor;
            result.umax_value = self.umax_value / divisor;
        } else if other.umin_value > 0 {
            // Divisor is positive
            result.umax_value = self.umax_value / other.umin_value;
        }

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// OR operation
    fn or(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.or(other.var_off);

        // For OR, result >= max(a, b) and result <= a | b (with unknown bits set)
        result.umin_value = self.umin_value.max(other.umin_value);

        result
    }

    /// AND operation
    fn and(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.and(other.var_off);

        // For AND, result <= min(a, b)
        result.umax_value = self.umax_value.min(other.umax_value);
        result.umin_value = 0;

        result
    }

    /// Left shift operation
    fn lsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
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
    fn rsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
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
    fn arsh(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        let mut result = ScalarBounds::unknown();
        let max_shift = if is_64 { 63 } else { 31 };

        // If shift amount is known
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
    fn neg(&self, is_64: bool) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();

        // -a for signed values
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
    fn mod_op(&self, other: &ScalarBounds, is_64: bool) -> Result<ScalarBounds> {
        // Check for mod by zero
        if other.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }

        let mut result = ScalarBounds::unknown();

        // Result is always less than the divisor
        result.umin_value = 0;
        result.umax_value = other.umax_value - 1;

        if !is_64 {
            result.truncate_to_32();
        }

        Ok(result)
    }

    /// XOR operation
    fn xor(&self, other: &ScalarBounds) -> ScalarBounds {
        let mut result = ScalarBounds::unknown();
        result.var_off = self.var_off.xor(other.var_off);

        // XOR with self is always 0
        if self.is_const() && other.is_const() && self.umin_value == other.umin_value {
            return ScalarBounds::known(0);
        }

        result
    }

    /// Truncate bounds to 32-bit
    fn truncate_to_32(&mut self) {
        // 64-bit bounds become 32-bit
        self.umin_value &= u32::MAX as u64;
        self.umax_value = (self.umax_value & u32::MAX as u64).min(u32::MAX as u64);
        self.smin_value = (self.smin_value as i32) as i64;
        self.smax_value = (self.smax_value as i32) as i64;

        // 32-bit bounds from original values
        self.u32_min_value = self.umin_value as u32;
        self.u32_max_value = self.umax_value as u32;
        self.s32_min_value = self.smin_value as i32;
        self.s32_max_value = self.smax_value as i32;

        // Update tnum
        self.var_off = self.var_off.truncate_32();
    }

    /// Zero-extend 32-bit bounds to 64-bit
    pub fn zext_32_to_64(&mut self) {
        self.umin_value = self.u32_min_value as u64;
        self.umax_value = self.u32_max_value as u64;
        self.smin_value = self.u32_min_value as i64;
        self.smax_value = self.u32_max_value as i64;
    }

    /// Sign-extend 32-bit bounds to 64-bit
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
            self.umin_value = 0;
            self.umax_value = u64::MAX;
        }
    }

    /// Check if value could be negative (signed)
    pub fn could_be_negative(&self) -> bool {
        self.smin_value < 0
    }

    /// Check if value is definitely non-negative
    pub fn is_non_negative(&self) -> bool {
        self.smin_value >= 0
    }

    /// Adjust bounds after conditional jump (value comparison)
    pub fn adjust_for_cmp(&mut self, cmp_val: u64, op: u8, is_jmp_taken: bool) {
        match op {
            0x10 => { // JEQ - equal
                if is_jmp_taken {
                    *self = ScalarBounds::known(cmp_val);
                }
                // If not taken, we know they're not equal (no tight bound change)
            }
            0x20 => { // JGT - greater than (unsigned)
                if is_jmp_taken {
                    self.umin_value = self.umin_value.max(cmp_val + 1);
                } else {
                    self.umax_value = self.umax_value.min(cmp_val);
                }
            }
            0x30 => { // JGE - greater or equal (unsigned)
                if is_jmp_taken {
                    self.umin_value = self.umin_value.max(cmp_val);
                } else if cmp_val > 0 {
                    self.umax_value = self.umax_value.min(cmp_val - 1);
                }
            }
            0x50 => { // JNE - not equal
                if is_jmp_taken {
                    // We know they're not equal
                } else {
                    *self = ScalarBounds::known(cmp_val);
                }
            }
            0x60 => { // JSGT - greater than (signed)
                if is_jmp_taken {
                    self.smin_value = self.smin_value.max(cmp_val as i64 + 1);
                } else {
                    self.smax_value = self.smax_value.min(cmp_val as i64);
                }
            }
            0x70 => { // JSGE - greater or equal (signed)
                if is_jmp_taken {
                    self.smin_value = self.smin_value.max(cmp_val as i64);
                } else {
                    self.smax_value = self.smax_value.min(cmp_val as i64 - 1);
                }
            }
            0xa0 => { // JLT - less than (unsigned)
                if is_jmp_taken && cmp_val > 0 {
                    self.umax_value = self.umax_value.min(cmp_val - 1);
                } else {
                    self.umin_value = self.umin_value.max(cmp_val);
                }
            }
            0xb0 => { // JLE - less or equal (unsigned)
                if is_jmp_taken {
                    self.umax_value = self.umax_value.min(cmp_val);
                } else {
                    self.umin_value = self.umin_value.max(cmp_val + 1);
                }
            }
            0xc0 => { // JSLT - less than (signed)
                if is_jmp_taken {
                    self.smax_value = self.smax_value.min(cmp_val as i64 - 1);
                } else {
                    self.smin_value = self.smin_value.max(cmp_val as i64);
                }
            }
            0xd0 => { // JSLE - less or equal (signed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_value() {
        let bounds = ScalarBounds::known(42);
        assert!(bounds.is_const());
        assert_eq!(bounds.const_value(), Some(42));
    }

    #[test]
    fn test_unknown_value() {
        let bounds = ScalarBounds::unknown();
        assert!(!bounds.is_const());
        assert_eq!(bounds.umin_value, 0);
        assert_eq!(bounds.umax_value, u64::MAX);
    }

    #[test]
    fn test_add_known() {
        let a = ScalarBounds::known(10);
        let b = ScalarBounds::known(20);
        let result = a.add(&b, true).unwrap();
        assert!(result.is_const());
        assert_eq!(result.const_value(), Some(30));
    }

    #[test]
    fn test_sub_bounds() {
        let mut a = ScalarBounds::unknown();
        a.umin_value = 100;
        a.umax_value = 200;
        
        let b = ScalarBounds::known(50);
        let result = a.sub(&b, true).unwrap();
        
        assert_eq!(result.umin_value, 50);
        assert_eq!(result.umax_value, 150);
    }

    #[test]
    fn test_div_by_zero() {
        let a = ScalarBounds::known(100);
        let b = ScalarBounds::known(0);
        assert!(a.div(&b, true).is_err());
    }

    #[test]
    fn test_and_bounds() {
        let a = ScalarBounds::known(0xFF);
        let b = ScalarBounds::known(0x0F);
        let result = a.and(&b);
        assert_eq!(result.umax_value, 0x0F);
    }

    #[test]
    fn test_lsh_known() {
        let a = ScalarBounds::known(1);
        let b = ScalarBounds::known(4);
        let result = a.lsh(&b, true).unwrap();
        assert!(result.is_const());
        assert_eq!(result.const_value(), Some(16));
    }

    #[test]
    fn test_cross_inference() {
        let mut bounds = ScalarBounds::unknown();
        bounds.smin_value = 0;
        bounds.smax_value = 100;
        bounds.deduce_bounds();
        
        // Since signed is non-negative, unsigned should match
        assert_eq!(bounds.umin_value, 0);
        assert!(bounds.umax_value <= 100 || bounds.umax_value == u64::MAX);
    }

    #[test]
    fn test_adjust_jgt() {
        let mut bounds = ScalarBounds::unknown();
        bounds.umin_value = 0;
        bounds.umax_value = 100;
        
        // After JGT 50 (taken), value > 50
        bounds.adjust_for_cmp(50, 0x20, true);
        assert_eq!(bounds.umin_value, 51);
    }

    #[test]
    fn test_adjust_jle() {
        let mut bounds = ScalarBounds::unknown();
        bounds.umin_value = 0;
        bounds.umax_value = 100;
        
        // After JLE 30 (taken), value <= 30
        bounds.adjust_for_cmp(30, 0xb0, true);
        assert_eq!(bounds.umax_value, 30);
    }

    #[test]
    fn test_truncate_32() {
        let mut bounds = ScalarBounds::known(0x1_0000_0005);
        bounds.truncate_to_32();
        assert_eq!(bounds.u32_min_value, 5);
        assert_eq!(bounds.u32_max_value, 5);
    }

    #[test]
    fn test_sext_negative() {
        let mut bounds = ScalarBounds::unknown();
        bounds.s32_min_value = -10;
        bounds.s32_max_value = -1;
        bounds.sext_32_to_64();
        
        assert_eq!(bounds.smin_value, -10);
        assert_eq!(bounds.smax_value, -1);
    }

    #[test]
    fn test_could_be_negative() {
        let mut bounds = ScalarBounds::unknown();
        bounds.smin_value = -5;
        bounds.smax_value = 10;
        assert!(bounds.could_be_negative());

        bounds.smin_value = 0;
        assert!(!bounds.could_be_negative());
    }
}
