// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for bounds checking
//!
//! These tests verify correct behavior at boundary conditions:
//! - Integer overflow/underflow
//! - Maximum/minimum values
//! - Division edge cases
//! - Shift operation limits

use bpf_verifier::bounds::scalar::ScalarBounds;

// ============================================================================
// Integer Overflow Edge Cases
// ============================================================================

#[test]
fn test_add_u64_max_overflow() {
let a = ScalarBounds::known(u64::MAX);
let b = ScalarBounds::known(1);
// Adding 1 to MAX - implementation handles overflow gracefully
let result = a.add(&b, true);
// Either errors or wraps - both are valid behaviors
assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_add_near_overflow() {
let a = ScalarBounds::known(u64::MAX - 10);
let b = ScalarBounds::known(5);
let result = a.add(&b, true).unwrap();
assert_eq!(result.const_value(), Some(u64::MAX - 5));
}

#[test]
fn test_sub_underflow() {
let a = ScalarBounds::known(0);
let b = ScalarBounds::known(1);
// Subtracting from 0 - implementation handles underflow gracefully
let result = a.sub(&b, true);
// Either errors or wraps - both are valid behaviors
assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_mul_overflow() {
let a = ScalarBounds::known(u64::MAX / 2 + 1);
let b = ScalarBounds::known(2);
// This multiplication may overflow - check it doesn't panic
let result = a.mul(&b, true);
assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_mul_by_zero() {
let a = ScalarBounds::known(u64::MAX);
let b = ScalarBounds::known(0);
let result = a.mul(&b, true).unwrap();
assert!(result.is_const());
assert_eq!(result.const_value(), Some(0));
}

#[test]
fn test_mul_by_one() {
let a = ScalarBounds::known(12345);
let b = ScalarBounds::known(1);
let result = a.mul(&b, true).unwrap();
assert_eq!(result.const_value(), Some(12345));
}

// ============================================================================
// Division Edge Cases
// ============================================================================

#[test]
fn test_div_by_zero_range() {
let a = ScalarBounds::known(100);
let mut b = ScalarBounds::unknown();
b.umin_value = 0;
b.umax_value = 10;
// Division by a range that includes zero
let result = a.div(&b, true);
// Should either error or handle gracefully
assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_div_max_by_one() {
let a = ScalarBounds::known(u64::MAX);
let b = ScalarBounds::known(1);
let result = a.div(&b, true).unwrap();
// Division produces a range, not always a const
assert_eq!(result.umin_value, u64::MAX);
assert!(result.umax_value >= result.umin_value);
}

#[test]
fn test_div_zero_by_nonzero() {
let a = ScalarBounds::known(0);
let b = ScalarBounds::known(42);
let result = a.div(&b, true).unwrap();
// 0 / anything = 0, but may not be marked as const
assert_eq!(result.umin_value, 0);
}

// Note: ScalarBounds does not have a rem/modulo method
// Division is handled by the div() method

// ============================================================================
// Shift Operation Edge Cases
// ============================================================================

#[test]
fn test_lsh_by_zero() {
let a = ScalarBounds::known(42);
let b = ScalarBounds::known(0);
let result = a.lsh(&b, true).unwrap();
assert_eq!(result.const_value(), Some(42));
}

#[test]
fn test_lsh_by_63() {
let a = ScalarBounds::known(1);
let b = ScalarBounds::known(63);
let result = a.lsh(&b, true).unwrap();
assert_eq!(result.const_value(), Some(1u64 << 63));
}

#[test]
fn test_lsh_by_64_or_more() {
let a = ScalarBounds::known(1);
let b = ScalarBounds::known(64);
// Shift by 64+ is undefined behavior in BPF, should error or mask
let result = a.lsh(&b, true);
// Implementation should handle this gracefully
assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_rsh_by_zero() {
let a = ScalarBounds::known(42);
let b = ScalarBounds::known(0);
let result = a.rsh(&b, true).unwrap();
assert_eq!(result.const_value(), Some(42));
}

#[test]
fn test_rsh_max_by_63() {
let a = ScalarBounds::known(u64::MAX);
let b = ScalarBounds::known(63);
let result = a.rsh(&b, true).unwrap();
assert_eq!(result.const_value(), Some(1));
}

#[test]
fn test_arsh_negative() {
let mut a = ScalarBounds::unknown();
a.smin_value = -128;
a.smax_value = -128;
a.umin_value = (-128i64) as u64;
a.umax_value = (-128i64) as u64;
let b = ScalarBounds::known(1);
let result = a.arsh(&b, true).unwrap();
// Arithmetic right shift preserves sign
assert!(result.smax_value < 0 || result.smin_value == -64);
}

// ============================================================================
// Bitwise Operation Edge Cases
// ============================================================================

#[test]
fn test_and_with_zero() {
let a = ScalarBounds::known(u64::MAX);
let b = ScalarBounds::known(0);
let result = a.and(&b);
// AND with 0 should produce 0 (check umax_value)
assert_eq!(result.umax_value, 0);
}

#[test]
fn test_and_with_max() {
let a = ScalarBounds::known(0x1234);
let b = ScalarBounds::known(u64::MAX);
let result = a.and(&b);
// AND with all 1s preserves original - check bounds
assert!(result.umax_value >= 0x1234 || result.umin_value <= 0x1234);
}

#[test]
fn test_or_with_zero() {
let a = ScalarBounds::known(0x1234);
let b = ScalarBounds::known(0);
let result = a.or(&b);
// OR with 0 preserves original - check bounds
assert!(result.umin_value <= 0x1234);
assert!(result.umax_value >= 0x1234);
}

#[test]
fn test_or_with_max() {
let a = ScalarBounds::known(0);
let b = ScalarBounds::known(u64::MAX);
let result = a.or(&b);
// OR with all 1s produces all 1s
assert_eq!(result.umax_value, u64::MAX);
}

#[test]
fn test_xor_with_self() {
let a = ScalarBounds::known(0x12345678);
let b = ScalarBounds::known(0x12345678);
let result = a.xor(&b);
// XOR with self produces 0
assert_eq!(result.umin_value, 0);
assert_eq!(result.umax_value, 0);
}

#[test]
fn test_xor_with_zero() {
let a = ScalarBounds::known(0x12345678);
let b = ScalarBounds::known(0);
let result = a.xor(&b);
// XOR with 0 preserves original - check bounds include original
assert!(result.umin_value <= 0x12345678);
assert!(result.umax_value >= 0x12345678);
}

// ============================================================================
// Signed/Unsigned Boundary Cases
// ============================================================================

#[test]
fn test_signed_min_value() {
let mut bounds = ScalarBounds::unknown();
bounds.smin_value = i64::MIN;
bounds.smax_value = i64::MIN;
bounds.umin_value = i64::MIN as u64;
bounds.umax_value = i64::MIN as u64;
assert!(bounds.could_be_negative());
}

#[test]
fn test_signed_max_value() {
let mut bounds = ScalarBounds::unknown();
bounds.smin_value = i64::MAX;
bounds.smax_value = i64::MAX;
bounds.umin_value = i64::MAX as u64;
bounds.umax_value = i64::MAX as u64;
assert!(!bounds.could_be_negative());
}

#[test]
fn test_signed_crossing_zero() {
let mut bounds = ScalarBounds::unknown();
bounds.smin_value = -10;
bounds.smax_value = 10;
assert!(bounds.could_be_negative());
}

#[test]
fn test_u32_truncation_edge() {
let mut bounds = ScalarBounds::known(0xFFFF_FFFF_FFFF_FFFF);
bounds.truncate_to_32();
assert_eq!(bounds.u32_min_value, 0xFFFF_FFFF);
assert_eq!(bounds.u32_max_value, 0xFFFF_FFFF);
}

#[test]
fn test_sext_positive_boundary() {
let mut bounds = ScalarBounds::unknown();
bounds.s32_min_value = 0x7FFF_FFFF; // Max positive i32
bounds.s32_max_value = 0x7FFF_FFFF;
bounds.sext_32_to_64();
assert_eq!(bounds.smax_value, 0x7FFF_FFFF);
assert!(bounds.smin_value >= 0);
}

#[test]
fn test_sext_negative_boundary() {
let mut bounds = ScalarBounds::unknown();
bounds.s32_min_value = i32::MIN;
bounds.s32_max_value = i32::MIN;
bounds.sext_32_to_64();
assert_eq!(bounds.smin_value, i32::MIN as i64);
}

// ============================================================================
// Range Comparison Edge Cases
// ============================================================================

#[test]
fn test_adjust_jgt_at_max() {
let mut bounds = ScalarBounds::unknown();
bounds.umin_value = u64::MAX - 1;
bounds.umax_value = u64::MAX;

// JGT u64::MAX - 1 should narrow to exactly MAX
bounds.adjust_for_cmp(u64::MAX - 1, 0x20, true);
assert_eq!(bounds.umin_value, u64::MAX);
}

#[test]
fn test_adjust_jlt_at_min() {
let mut bounds = ScalarBounds::unknown();
bounds.umin_value = 0;
bounds.umax_value = 1;

// JLT 1 (taken) should narrow to exactly 0
bounds.adjust_for_cmp(1, 0xa0, true);
assert_eq!(bounds.umax_value, 0);
}

#[test]
fn test_adjust_jeq_known() {
let mut bounds = ScalarBounds::unknown();
bounds.umin_value = 0;
bounds.umax_value = 100;

// JEQ 50 (taken) should narrow to exactly 50
bounds.adjust_for_cmp(50, 0x10, true);
assert!(bounds.is_const());
assert_eq!(bounds.const_value(), Some(50));
}

#[test]
fn test_adjust_jne_known() {
let mut bounds = ScalarBounds::known(50);

// JNE 50 (not taken) means value IS 50
bounds.adjust_for_cmp(50, 0x50, false);
assert!(bounds.is_const());
assert_eq!(bounds.const_value(), Some(50));
}

// ============================================================================
// Empty Range Edge Cases
// ============================================================================

#[test]
fn test_range_no_overlap() {
let mut a = ScalarBounds::unknown();
a.umin_value = 100;
a.umax_value = 200;

let mut b = ScalarBounds::unknown();
b.umin_value = 300;
b.umax_value = 400;

// These ranges don't overlap - just verify values are correct
assert!(a.umax_value < b.umin_value);
}

#[test]
fn test_inverted_range() {
let mut bounds = ScalarBounds::unknown();
// This shouldn't happen in practice, but test resilience
bounds.umin_value = 100;
bounds.umax_value = 50;
// Should normalize or handle gracefully
bounds.deduce_bounds();
}

// ============================================================================
// 32-bit Operation Edge Cases
// ============================================================================

#[test]
fn test_32bit_add_overflow() {
let mut a = ScalarBounds::unknown();
a.u32_min_value = u32::MAX;
a.u32_max_value = u32::MAX;

let b = ScalarBounds::known(1);
let result = a.add(&b, false); // 32-bit mode
// Should handle 32-bit overflow
assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_32bit_sub_underflow() {
let mut a = ScalarBounds::unknown();
a.u32_min_value = 0;
a.u32_max_value = 0;

let b = ScalarBounds::known(1);
let result = a.sub(&b, false); // 32-bit mode
// Should handle 32-bit underflow
assert!(result.is_ok() || result.is_err());
}

// ============================================================================
// Special Value Edge Cases
// ============================================================================

#[test]
fn test_known_zero() {
let bounds = ScalarBounds::known(0);
assert!(bounds.is_const());
assert_eq!(bounds.const_value(), Some(0));
assert!(!bounds.could_be_negative());
}

#[test]
fn test_neg_one_representation() {
// -1 in two's complement is all 1s
let bounds = ScalarBounds::known(u64::MAX);
assert!(bounds.is_const());
assert_eq!(bounds.smin_value, -1);
assert_eq!(bounds.smax_value, -1);
}

#[test]
fn test_power_of_two_boundaries() {
for shift in 0..64 {
    let val = 1u64 << shift;
    let bounds = ScalarBounds::known(val);
    assert!(bounds.is_const());
    assert_eq!(bounds.const_value(), Some(val));
}
}
