//! Tracked numbers (tnum) - representing partially known values
//!
//! A tnum represents a value where some bits are known and others are unknown.
//! It consists of a `value` (known bits) and a `mask` (unknown bits).
//!
//! For any bit position:
//! - If mask bit is 0, the actual value at that position equals the value bit
//! - If mask bit is 1, the actual value at that position is unknown

use core::ops::{BitAnd, BitOr, BitXor};

/// A tracked number with known and unknown bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tnum {
    /// Known bit values (only valid where mask is 0)
    pub value: u64,
    /// Mask of unknown bits (1 = unknown, 0 = known)
    pub mask: u64,
}

impl Tnum {
    /// Create a new tnum with given value and mask
    pub fn new(value: u64, mask: u64) -> Self {
        Self {
            value: value & !mask,
            mask,
        }
    }

    /// Create a tnum representing a constant value (all bits known)
    pub fn const_value(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// Create a tnum representing a completely unknown value
    pub fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    /// Create a tnum from a range [min, max]
    pub fn range(min: u64, max: u64) -> Self {
        if min > max {
            return Self::unknown();
        }

        let chi = min ^ max;
        // Find the position of the highest differing bit
        let bits = if chi == 0 { 0 } else { 64 - chi.leading_zeros() };

        // All bits below this position are unknown
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
    pub fn is_const(&self) -> bool {
        self.mask == 0
    }

    /// Check if this tnum represents a completely unknown value (all bits unknown)
    pub fn is_unknown(&self) -> bool {
        self.mask == u64::MAX && self.value == 0
    }

    /// Check if all bits in the subreg (lower 32 bits) are known
    pub fn subreg_is_const(&self) -> bool {
        (self.mask & 0xFFFF_FFFF) == 0
    }

    /// Get the subreg (lower 32 bits) as a tnum
    pub fn subreg(&self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// Clear the subreg (set lower 32 bits to zero, preserving upper bits)
    pub fn clear_subreg(&self) -> Self {
        Self {
            value: self.value & !0xFFFF_FFFF_u64,
            mask: self.mask & !0xFFFF_FFFF_u64,
        }
    }

    /// Create a tnum with const subreg value
    pub fn const_subreg(base: Tnum, value: u64) -> Self {
        Self {
            value: (base.value & !0xFFFF_FFFF_u64) | (value & 0xFFFF_FFFF),
            mask: base.mask & !0xFFFF_FFFF_u64,
        }
    }

    /// Get the minimum possible value
    pub fn min(&self) -> u64 {
        self.value
    }

    /// Get the maximum possible value
    pub fn max(&self) -> u64 {
        self.value | self.mask
    }

    /// Check if this tnum equals a constant value
    pub fn equals_const(&self, val: u64) -> bool {
        self.is_const() && self.value == val
    }

    /// Check if this tnum is within the range of another tnum
    pub fn is_within(&self, other: &Tnum) -> bool {
        // All known bits in other must match in self where self also knows them
        ((self.mask & other.mask) == self.mask)
            && ((self.value & !other.mask) == (other.value & !other.mask))
    }

    /// Check if this tnum is a subset of another (more constrained)
    /// Returns true if self's possible values are a subset of other's possible values
    pub fn is_subset_of(&self, other: &Tnum) -> bool {
        // self is a subset of other if:
        // 1. self has no unknown bits that other doesn't have
        // 2. where other has known bits, self must match
        
        // All bits unknown in other must also be unknown in self for this to be a subset
        // Actually the opposite: self must have FEWER unknowns
        // self.mask must have 0s everywhere other.mask has 0s
        if (self.mask & !other.mask) != 0 {
            // self has unknown bits where other has known bits - not a subset
            // Wait, that's wrong. If self knows a bit and other doesn't, that's fine.
            // The issue is if self could have a value that other can't.
        }
        
        // For self to be a subset:
        // - Where other knows a bit (mask=0), self must have the same value or also know it
        // - self's possible value range must be within other's range
        
        // Check that self's known bits match other's known bits where other knows them
        let other_known_mask = !other.mask;
        if (self.value & other_known_mask) != (other.value & other_known_mask) {
            // self has a different known value where other also knows - conflict
            // But wait, self might not know that bit
            if (self.mask & other_known_mask) != other_known_mask {
                // self knows some bits that other knows, check they match
                let both_known = !self.mask & !other.mask;
                if (self.value & both_known) != (other.value & both_known) {
                    return false;
                }
            }
        }
        
        // self's range must be within other's range
        self.min() >= other.min() && self.max() <= other.max()
    }

    /// Intersect two tnums (tighten bounds)
    pub fn intersect(self, other: Tnum) -> Self {
        let v = self.value | other.value;
        let mu = self.mask & other.mask;
        // Check for conflict: if bits are known in both but differ, result is impossible
        // We handle this by keeping the intersection mask
        Self {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Arithmetic right shift
    pub fn arsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: ((self.value as i64) >> shift) as u64,
            mask: ((self.mask as i64) >> shift) as u64,
        }
    }

    /// Logical right shift
    pub fn rsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    /// Left shift
    pub fn lsh(self, shift: u8) -> Self {
        let shift = shift.min(63) as u32;
        Self {
            value: self.value << shift,
            mask: self.mask << shift,
        }
    }

    /// Add two tnums
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
    pub fn mul(self, other: Tnum) -> Self {
        let acc_v = self.value.wrapping_mul(other.value);
        // Multiplication with unknowns is complex; simplify to unknown result
        // if either has unknown bits
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
    pub fn cast_u32(self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// Sign-extend from 32-bit to 64-bit
    pub fn sext32(self) -> Self {
        let value = self.value as i32 as i64 as u64;
        let mask = self.mask as i32 as i64 as u64;
        Self { value, mask }
    }

    /// Check if value might be in the specified range
    pub fn in_range(&self, min: u64, max: u64) -> bool {
        self.min() <= max && self.max() >= min
    }

    /// Get 64-bit unsigned bounds from tnum
    pub fn u64_bounds(&self) -> (u64, u64) {
        (self.min(), self.max())
    }

    /// Get 64-bit signed bounds from tnum
    pub fn s64_bounds(&self) -> (i64, i64) {
        // If sign bit is known
        if self.mask & (1u64 << 63) == 0 {
            // Sign bit is known
            if self.value & (1u64 << 63) != 0 {
                // Negative: min is most negative, max is least negative
                (self.min() as i64, self.max() as i64)
            } else {
                // Positive
                (self.min() as i64, self.max() as i64)
            }
        } else {
            // Sign bit unknown - could be anything
            (i64::MIN, i64::MAX)
        }
    }

    /// Get 32-bit unsigned bounds from lower 32 bits
    pub fn u32_bounds(&self) -> (u32, u32) {
        let min = self.value as u32;
        let max = (self.value | self.mask) as u32;
        (min, max)
    }

    /// Get 32-bit signed bounds from lower 32 bits
    pub fn s32_bounds(&self) -> (i32, i32) {
        let subreg_mask = self.mask as u32;
        let subreg_value = self.value as u32;
        
        // If sign bit of 32-bit value is known
        if subreg_mask & (1u32 << 31) == 0 {
            (subreg_value as i32, (subreg_value | subreg_mask) as i32)
        } else {
            (i32::MIN, i32::MAX)
        }
    }

    /// Truncate to 32 bits (for ALU32 operations)
    pub fn truncate_32(self) -> Self {
        Self {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// XOR operation (method form for bounds.rs)
    pub fn xor(self, other: Tnum) -> Self {
        self ^ other
    }

    /// OR operation (method form for bounds.rs)
    pub fn or(self, other: Tnum) -> Self {
        self | other
    }

    /// AND operation (method form for bounds.rs)
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
        Self { value: v & !mu, mask: mu }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const() {
        let t = Tnum::const_value(42);
        assert!(t.is_const());
        assert_eq!(t.value, 42);
        assert_eq!(t.mask, 0);
    }

    #[test]
    fn test_unknown() {
        let t = Tnum::unknown();
        assert!(!t.is_const());
        assert_eq!(t.mask, u64::MAX);
    }

    #[test]
    fn test_range() {
        let t = Tnum::range(0, 255);
        assert_eq!(t.value, 0);
        assert_eq!(t.mask, 255);

        let t2 = Tnum::range(0, 0);
        assert!(t2.is_const());
        assert_eq!(t2.value, 0);
    }

    #[test]
    fn test_add() {
        let a = Tnum::const_value(5);
        let b = Tnum::const_value(3);
        let c = a.add(b);
        assert!(c.is_const());
        assert_eq!(c.value, 8);
    }

    #[test]
    fn test_and() {
        let a = Tnum::const_value(0xFF);
        let b = Tnum::const_value(0x0F);
        let c = a & b;
        assert!(c.is_const());
        assert_eq!(c.value, 0x0F);
    }

    #[test]
    fn test_or() {
        let a = Tnum::const_value(0xF0);
        let b = Tnum::const_value(0x0F);
        let c = a | b;
        assert!(c.is_const());
        assert_eq!(c.value, 0xFF);
    }

    #[test]
    fn test_intersect() {
        let a = Tnum::new(0x10, 0x0F); // 0x1? where ? is unknown
        let b = Tnum::new(0x12, 0x01); // 0x12 or 0x13
        let c = a.intersect(b);
        assert_eq!(c.value, 0x12);
        assert_eq!(c.mask, 0x01);
    }
}
