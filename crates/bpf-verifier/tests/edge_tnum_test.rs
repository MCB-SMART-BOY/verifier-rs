// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for Tnum (tracked number) operations
//!
//! Tests boundary conditions, overflow behavior, and special values.

use bpf_verifier::bounds::tnum::Tnum;

// ============================================================================
// Boundary Value Tests
// ============================================================================

#[test]
fn test_tnum_max_value() {
    let t = Tnum::const_value(u64::MAX);
    assert!(t.is_const());
    assert_eq!(t.value, u64::MAX);
    assert_eq!(t.mask, 0);
}

#[test]
fn test_tnum_zero() {
    let t = Tnum::const_value(0);
    assert!(t.is_const());
    assert_eq!(t.value, 0);
    assert_eq!(t.mask, 0);
}

#[test]
fn test_tnum_one() {
    let t = Tnum::const_value(1);
    assert!(t.is_const());
    assert_eq!(t.value, 1);
}

// ============================================================================
// Addition Edge Cases
// ============================================================================

#[test]
fn test_add_max_plus_zero() {
    let a = Tnum::const_value(u64::MAX);
    let b = Tnum::const_value(0);
    let c = a.add(b);
    assert!(c.is_const());
    assert_eq!(c.value, u64::MAX);
}

#[test]
fn test_add_overflow_wraps() {
    let a = Tnum::const_value(u64::MAX);
    let b = Tnum::const_value(1);
    let c = a.add(b);
    // Should wrap around to 0 in BPF semantics
    assert_eq!(c.value, 0);
}

#[test]
fn test_add_large_unknowns() {
    let a = Tnum::unknown();
    let b = Tnum::unknown();
    let c = a.add(b);
    // Result should still be unknown
    assert!(!c.is_const());
}

#[test]
fn test_add_partial_known() {
    // Known low bits, unknown high bits
    let a = Tnum::new(0x0F, 0xF0);  // Low nibble known as 0xF
    let b = Tnum::const_value(1);
    let c = a.add(b);
    // Low nibble should be 0 with carry into unknown bits
    assert_eq!(c.value & 0x0F, 0);
}

// ============================================================================
// Subtraction Edge Cases
// ============================================================================

#[test]
fn test_sub_zero_minus_one() {
    let a = Tnum::const_value(0);
    let b = Tnum::const_value(1);
    let c = a.sub(b);
    // 0 - 1 wraps to MAX
    assert_eq!(c.value, u64::MAX);
}

#[test]
fn test_sub_same_value() {
    let a = Tnum::const_value(12345);
    let b = Tnum::const_value(12345);
    let c = a.sub(b);
    assert!(c.is_const());
    assert_eq!(c.value, 0);
}

#[test]
fn test_sub_unknown_from_unknown() {
    let a = Tnum::unknown();
    let b = Tnum::unknown();
    let c = a.sub(b);
    // Unknown - Unknown = Unknown
    assert!(!c.is_const());
}

// ============================================================================
// Multiplication Edge Cases
// ============================================================================

#[test]
fn test_mul_by_zero() {
    let a = Tnum::const_value(u64::MAX);
    let b = Tnum::const_value(0);
    let c = a.mul(b);
    assert!(c.is_const());
    assert_eq!(c.value, 0);
}

#[test]
fn test_mul_by_one() {
    let a = Tnum::const_value(12345);
    let b = Tnum::const_value(1);
    let c = a.mul(b);
    assert!(c.is_const());
    assert_eq!(c.value, 12345);
}

#[test]
fn test_mul_overflow() {
    let a = Tnum::const_value(u64::MAX);
    let b = Tnum::const_value(2);
    let c = a.mul(b);
    // Should wrap according to u64 semantics
    assert_eq!(c.value, u64::MAX.wrapping_mul(2));
}

#[test]
fn test_mul_power_of_two() {
    let a = Tnum::const_value(0x1234);
    let b = Tnum::const_value(16); // 2^4
    let c = a.mul(b);
    assert_eq!(c.value, 0x12340);
}

// ============================================================================
// Bitwise AND Edge Cases
// ============================================================================

#[test]
fn test_and_with_zero() {
    let a = Tnum::const_value(u64::MAX);
    let b = Tnum::const_value(0);
    let c = a & b;
    assert!(c.is_const());
    assert_eq!(c.value, 0);
}

#[test]
fn test_and_with_max() {
    let a = Tnum::const_value(0x12345678);
    let b = Tnum::const_value(u64::MAX);
    let c = a & b;
    assert!(c.is_const());
    assert_eq!(c.value, 0x12345678);
}

#[test]
fn test_and_unknown_with_zero() {
    let a = Tnum::unknown();
    let b = Tnum::const_value(0);
    let c = a & b;
    // AND with 0 always produces 0
    assert!(c.is_const());
    assert_eq!(c.value, 0);
}

#[test]
fn test_and_masks_high_bits() {
    let a = Tnum::const_value(0xFFFF_FFFF_FFFF_FFFF);
    let b = Tnum::const_value(0x0000_0000_FFFF_FFFF);
    let c = a & b;
    assert_eq!(c.value, 0x0000_0000_FFFF_FFFF);
}

// ============================================================================
// Bitwise OR Edge Cases
// ============================================================================

#[test]
fn test_or_with_zero() {
    let a = Tnum::const_value(0x12345678);
    let b = Tnum::const_value(0);
    let c = a | b;
    assert!(c.is_const());
    assert_eq!(c.value, 0x12345678);
}

#[test]
fn test_or_with_max() {
    let a = Tnum::const_value(0);
    let b = Tnum::const_value(u64::MAX);
    let c = a | b;
    assert!(c.is_const());
    assert_eq!(c.value, u64::MAX);
}

#[test]
fn test_or_unknown_with_max() {
    let a = Tnum::unknown();
    let b = Tnum::const_value(u64::MAX);
    let c = a | b;
    // OR with all 1s always produces all 1s
    assert!(c.is_const());
    assert_eq!(c.value, u64::MAX);
}

// ============================================================================
// Bitwise XOR Edge Cases
// ============================================================================

#[test]
fn test_xor_with_zero() {
    let a = Tnum::const_value(0x12345678);
    let b = Tnum::const_value(0);
    let c = a ^ b;
    assert!(c.is_const());
    assert_eq!(c.value, 0x12345678);
}

#[test]
fn test_xor_with_self() {
    let a = Tnum::const_value(0x12345678);
    let c = a ^ a;
    assert!(c.is_const());
    assert_eq!(c.value, 0);
}

#[test]
fn test_xor_with_max() {
    let a = Tnum::const_value(0x12345678);
    let b = Tnum::const_value(u64::MAX);
    let c = a ^ b;
    assert!(c.is_const());
    assert_eq!(c.value, !0x12345678u64);
}

// ============================================================================
// Shift Operation Edge Cases
// ============================================================================

#[test]
fn test_lsh_by_zero() {
    let a = Tnum::const_value(0x12345678);
    let c = a.lsh(0);
    assert!(c.is_const());
    assert_eq!(c.value, 0x12345678);
}

#[test]
fn test_lsh_by_63() {
    let a = Tnum::const_value(1);
    let c = a.lsh(63);
    assert!(c.is_const());
    assert_eq!(c.value, 1u64 << 63);
}

#[test]
fn test_lsh_by_64_clamped() {
    let a = Tnum::const_value(1);
    let c = a.lsh(64);
    // In this implementation, shift amounts are clamped to 63
    // So lsh(64) behaves like lsh(63)
    assert_eq!(c.value, 1u64 << 63);
}

#[test]
fn test_rsh_by_zero() {
    let a = Tnum::const_value(0x12345678);
    let c = a.rsh(0);
    assert!(c.is_const());
    assert_eq!(c.value, 0x12345678);
}

#[test]
fn test_rsh_by_63() {
    let a = Tnum::const_value(u64::MAX);
    let c = a.rsh(63);
    assert!(c.is_const());
    assert_eq!(c.value, 1);
}

#[test]
fn test_rsh_by_64_clamped() {
    let a = Tnum::const_value(u64::MAX);
    let c = a.rsh(64);
    // In this implementation, shift amounts are clamped to 63
    // So rsh(64) behaves like rsh(63), resulting in 1
    assert_eq!(c.value, 1);
}

// ============================================================================
// Range and Intersection Tests
// ============================================================================

#[test]
fn test_range_empty() {
    let t = Tnum::range(5, 5);
    assert!(t.is_const());
    assert_eq!(t.value, 5);
}

#[test]
fn test_range_power_of_two() {
    let t = Tnum::range(0, 255);
    // Should have 8 unknown bits
    assert_eq!(t.mask, 255);
    assert_eq!(t.value, 0);
}

#[test]
fn test_intersect_no_overlap() {
    let a = Tnum::const_value(0);
    let b = Tnum::const_value(1);
    let c = a.intersect(b);
    // These don't overlap, result depends on implementation
    // At minimum, check it doesn't panic
    let _ = c;
}

#[test]
fn test_intersect_same() {
    let a = Tnum::const_value(42);
    let b = Tnum::const_value(42);
    let c = a.intersect(b);
    assert!(c.is_const());
    assert_eq!(c.value, 42);
}

#[test]
fn test_intersect_subset() {
    let a = Tnum::new(0x10, 0x0F);  // 0x1? (16-31)
    let b = Tnum::const_value(0x15);  // exactly 21
    let c = a.intersect(b);
    assert!(c.is_const());
    assert_eq!(c.value, 0x15);
}

// ============================================================================
// Special Pattern Tests
// ============================================================================

#[test]
fn test_alternating_bits() {
    let a = Tnum::const_value(0xAAAA_AAAA_AAAA_AAAA);
    let b = Tnum::const_value(0x5555_5555_5555_5555);
    let c = a | b;
    assert!(c.is_const());
    assert_eq!(c.value, u64::MAX);
    
    let d = a & b;
    assert!(d.is_const());
    assert_eq!(d.value, 0);
}

#[test]
fn test_sign_bit_operations() {
    // Test with sign bit set
    let a = Tnum::const_value(0x8000_0000_0000_0000);
    let b = Tnum::const_value(1);
    let c = a | b;
    assert_eq!(c.value, 0x8000_0000_0000_0001);
}

/// Test value containment using min/max bounds
#[test]
fn test_value_in_bounds() {
    let a = Tnum::new(0x10, 0x0F);  // 0x1? (16-31)
    // Check min/max bounds
    assert_eq!(a.min(), 16);
    assert_eq!(a.max(), 31);
    // Value 16 is within [16, 31]
    assert!(16 >= a.min() && 16 <= a.max());
    // Value 31 is within [16, 31]
    assert!(31 >= a.min() && 31 <= a.max());
    // Value 15 is not within [16, 31]
    assert!(!(15 >= a.min() && 15 <= a.max()));
    // Value 32 is not within [16, 31]
    assert!(!(32 >= a.min() && 32 <= a.max()));
}

#[test]
fn test_min_max_methods() {
    let t = Tnum::new(0x10, 0x0F);  // 0x1? (16-31)
    assert_eq!(t.min(), 16);
    assert_eq!(t.max(), 31);
}

#[test]
fn test_unknown_min_max() {
    let t = Tnum::unknown();
    assert_eq!(t.min(), 0);
    assert_eq!(t.max(), u64::MAX);
}
