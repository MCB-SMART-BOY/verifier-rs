// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for ScalarBounds operations
//!
//! Tests boundary conditions, overflow behavior, and cross-inference.

use bpf_verifier::bounds::scalar::ScalarBounds;

// ============================================================================
// Known Constant Tests
// ============================================================================

#[test]
fn test_known_zero() {
    let s = ScalarBounds::known(0);
    assert!(s.is_const());
    assert_eq!(s.const_value(), Some(0));
    assert_eq!(s.umin_value, 0);
    assert_eq!(s.umax_value, 0);
    assert_eq!(s.smin_value, 0);
    assert_eq!(s.smax_value, 0);
}

#[test]
fn test_known_max_u64() {
    let s = ScalarBounds::known(u64::MAX);
    assert!(s.is_const());
    assert_eq!(s.const_value(), Some(u64::MAX));
    assert_eq!(s.umin_value, u64::MAX);
    assert_eq!(s.umax_value, u64::MAX);
    // As i64, u64::MAX is -1
    assert_eq!(s.smin_value, -1);
    assert_eq!(s.smax_value, -1);
}

#[test]
fn test_known_i64_max() {
    let val = i64::MAX as u64;
    let s = ScalarBounds::known(val);
    assert!(s.is_const());
    assert_eq!(s.smin_value, i64::MAX);
    assert_eq!(s.smax_value, i64::MAX);
}

#[test]
fn test_known_i64_min() {
    // i64::MIN as u64 = 0x8000_0000_0000_0000
    let val = i64::MIN as u64;
    let s = ScalarBounds::known(val);
    assert!(s.is_const());
    assert_eq!(s.smin_value, i64::MIN);
    assert_eq!(s.smax_value, i64::MIN);
}

// ============================================================================
// Unknown Value Tests
// ============================================================================

#[test]
fn test_unknown_bounds() {
    let s = ScalarBounds::unknown();
    assert!(!s.is_const());
    assert_eq!(s.const_value(), None);
    assert_eq!(s.umin_value, 0);
    assert_eq!(s.umax_value, u64::MAX);
    assert_eq!(s.smin_value, i64::MIN);
    assert_eq!(s.smax_value, i64::MAX);
    assert_eq!(s.u32_min_value, 0);
    assert_eq!(s.u32_max_value, u32::MAX);
    assert_eq!(s.s32_min_value, i32::MIN);
    assert_eq!(s.s32_max_value, i32::MAX);
}

#[test]
fn test_unknown_is_sane() {
    let s = ScalarBounds::unknown();
    assert!(s.is_sane());
}

// ============================================================================
// Addition Edge Cases
// ============================================================================

#[test]
fn test_add_zero_to_known() {
    let a = ScalarBounds::known(100);
    let b = ScalarBounds::known(0);
    let c = a.add(&b, true).unwrap();
    assert!(c.is_const());
    assert_eq!(c.const_value(), Some(100));
}

#[test]
fn test_add_overflow_u64() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(1);
    let c = a.add(&b, true).unwrap();
    // Overflow causes unknown bounds
    // The result depends on implementation - check sanity
    assert!(c.is_sane());
}

#[test]
fn test_add_known_values() {
    let a = ScalarBounds::known(100);
    let b = ScalarBounds::known(200);
    let c = a.add(&b, true).unwrap();
    assert_eq!(c.umin_value, 300);
    assert_eq!(c.umax_value, 300);
}

#[test]
fn test_add_unknown_preserves_sanity() {
    let a = ScalarBounds::unknown();
    let b = ScalarBounds::unknown();
    let c = a.add(&b, true).unwrap();
    assert!(c.is_sane());
}

// ============================================================================
// Subtraction Edge Cases
// ============================================================================

#[test]
fn test_sub_same_value() {
    let a = ScalarBounds::known(12345);
    let b = ScalarBounds::known(12345);
    let c = a.sub(&b, true).unwrap();
    assert_eq!(c.umin_value, 0);
    assert_eq!(c.umax_value, 0);
}

#[test]
fn test_sub_zero_from_known() {
    let a = ScalarBounds::known(100);
    let b = ScalarBounds::known(0);
    let c = a.sub(&b, true).unwrap();
    assert_eq!(c.umin_value, 100);
    assert_eq!(c.umax_value, 100);
}

#[test]
fn test_sub_underflow() {
    let a = ScalarBounds::known(0);
    let b = ScalarBounds::known(1);
    let c = a.sub(&b, true).unwrap();
    // Underflow wraps - result should be sane
    assert!(c.is_sane());
}

// ============================================================================
// Multiplication Edge Cases
// ============================================================================

#[test]
fn test_mul_by_zero() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(0);
    let c = a.mul(&b, true).unwrap();
    assert!(c.is_const());
    assert_eq!(c.const_value(), Some(0));
}

#[test]
fn test_mul_by_one() {
    let a = ScalarBounds::known(12345);
    let b = ScalarBounds::known(1);
    let c = a.mul(&b, true).unwrap();
    assert!(c.is_const());
    assert_eq!(c.const_value(), Some(12345));
}

#[test]
fn test_mul_overflow() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(2);
    let c = a.mul(&b, true).unwrap();
    // Result wraps
    assert!(c.is_sane());
}

#[test]
fn test_mul_unknown_by_zero() {
    let a = ScalarBounds::unknown();
    let b = ScalarBounds::known(0);
    let c = a.mul(&b, true).unwrap();
    // Multiplication with unknowns goes unknown, but 0 should still be 0
    // Check the result is sane
    assert!(c.is_sane());
}

// ============================================================================
// Division Edge Cases
// ============================================================================

#[test]
fn test_div_by_one() {
    let a = ScalarBounds::known(12345);
    let b = ScalarBounds::known(1);
    let c = a.div(&b, true).unwrap();
    assert_eq!(c.umin_value, 12345);
    assert_eq!(c.umax_value, 12345);
}

#[test]
fn test_div_by_zero_error() {
    let a = ScalarBounds::known(100);
    let mut b = ScalarBounds::known(0);
    b.umax_value = 0; // Ensure max is also 0
    let result = a.div(&b, true);
    assert!(result.is_err());
}

#[test]
fn test_div_zero_by_nonzero() {
    let a = ScalarBounds::known(0);
    let b = ScalarBounds::known(100);
    let c = a.div(&b, true).unwrap();
    assert_eq!(c.umin_value, 0);
    assert_eq!(c.umax_value, 0);
}

#[test]
fn test_div_max_by_max() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(u64::MAX);
    let c = a.div(&b, true).unwrap();
    assert_eq!(c.umin_value, 1);
    assert_eq!(c.umax_value, 1);
}

// ============================================================================
// Bitwise AND Edge Cases
// ============================================================================

#[test]
fn test_and_with_zero() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(0);
    let c = a.and(&b);
    assert_eq!(c.umax_value, 0);
}

#[test]
fn test_and_with_max() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(u64::MAX);
    let c = a.and(&b);
    assert!(c.umax_value >= 0x12345678);
}

#[test]
fn test_and_unknown_with_mask() {
    let a = ScalarBounds::unknown();
    let b = ScalarBounds::known(0xFF);
    let c = a.and(&b);
    // Result should be bounded by the mask
    assert!(c.umax_value <= 0xFF);
}

// ============================================================================
// Bitwise OR Edge Cases
// ============================================================================

#[test]
fn test_or_with_zero() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(0);
    let c = a.or(&b);
    assert!(c.umin_value >= 0x12345678);
}

#[test]
fn test_or_with_max() {
    let a = ScalarBounds::known(0);
    let b = ScalarBounds::known(u64::MAX);
    let c = a.or(&b);
    assert!(c.umin_value >= u64::MAX);
}

// ============================================================================
// Shift Edge Cases
// ============================================================================

#[test]
fn test_lsh_by_zero() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(0);
    let c = a.lsh(&b, true).unwrap();
    assert_eq!(c.umin_value, 0x12345678);
    assert_eq!(c.umax_value, 0x12345678);
}

#[test]
fn test_lsh_by_63() {
    let a = ScalarBounds::known(1);
    let b = ScalarBounds::known(63);
    let c = a.lsh(&b, true).unwrap();
    assert_eq!(c.umin_value, 1u64 << 63);
}

#[test]
fn test_rsh_by_zero() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(0);
    let c = a.rsh(&b, true).unwrap();
    assert_eq!(c.umin_value, 0x12345678);
}

#[test]
fn test_rsh_max_by_63() {
    let a = ScalarBounds::known(u64::MAX);
    let b = ScalarBounds::known(63);
    let c = a.rsh(&b, true).unwrap();
    assert_eq!(c.umin_value, 1);
    assert_eq!(c.umax_value, 1);
}

#[test]
fn test_arsh_negative() {
    // Sign-extended right shift of negative value
    let a = ScalarBounds::known(0x8000_0000_0000_0000); // -2^63 as u64
    let b = ScalarBounds::known(4);
    let c = a.arsh(&b, true).unwrap();
    // Arithmetic shift preserves sign
    assert!(c.smin_value < 0);
}

// ============================================================================
// XOR Edge Cases
// ============================================================================

#[test]
fn test_xor_with_zero() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(0);
    let c = a.xor(&b);
    assert!(c.is_sane());
}

#[test]
fn test_xor_with_self() {
    let a = ScalarBounds::known(0x12345678);
    let c = a.xor(&a);
    assert!(c.is_const());
    assert_eq!(c.const_value(), Some(0));
}

#[test]
fn test_xor_with_max() {
    let a = ScalarBounds::known(0x12345678);
    let b = ScalarBounds::known(u64::MAX);
    let c = a.xor(&b);
    assert!(c.is_sane());
}

// ============================================================================
// 32-bit Truncation Tests
// ============================================================================

#[test]
fn test_truncate_to_32_small() {
    let mut s = ScalarBounds::known(0x12345678);
    s.truncate_to_32();
    assert_eq!(s.umin_value, 0x12345678);
    assert_eq!(s.umax_value, 0x12345678);
    assert_eq!(s.u32_min_value, 0x12345678);
    assert_eq!(s.u32_max_value, 0x12345678);
}

#[test]
fn test_truncate_to_32_large() {
    let mut s = ScalarBounds::known(0xFFFF_FFFF_1234_5678);
    s.truncate_to_32();
    // Lower 32 bits only
    assert_eq!(s.u32_min_value, 0x1234_5678);
    assert_eq!(s.u32_max_value, 0x1234_5678);
}

#[test]
fn test_truncate_32_max() {
    let mut s = ScalarBounds::known(u64::MAX);
    s.truncate_to_32();
    assert_eq!(s.u32_min_value, u32::MAX);
    assert_eq!(s.u32_max_value, u32::MAX);
}

// ============================================================================
// Sign Extension Tests
// ============================================================================

#[test]
fn test_zext_32_to_64() {
    let mut s = ScalarBounds::unknown();
    s.u32_min_value = 100;
    s.u32_max_value = 200;
    s.zext_32_to_64();
    assert_eq!(s.umin_value, 100);
    assert_eq!(s.umax_value, 200);
}

#[test]
fn test_sext_32_to_64_positive() {
    let mut s = ScalarBounds::unknown();
    s.s32_min_value = 100;
    s.s32_max_value = 200;
    s.sext_32_to_64();
    assert_eq!(s.smin_value, 100);
    assert_eq!(s.smax_value, 200);
}

#[test]
fn test_sext_32_to_64_negative() {
    let mut s = ScalarBounds::unknown();
    s.s32_min_value = -100;
    s.s32_max_value = -50;
    s.sext_32_to_64();
    assert_eq!(s.smin_value, -100);
    assert_eq!(s.smax_value, -50);
}

#[test]
fn test_sext_32_to_64_crossing_zero() {
    let mut s = ScalarBounds::unknown();
    s.s32_min_value = -100;
    s.s32_max_value = 100;
    s.sext_32_to_64();
    // When crossing zero, unsigned range is maximized
    assert_eq!(s.smin_value, -100);
    assert_eq!(s.smax_value, 100);
}

// ============================================================================
// Comparison Adjustment Tests
// ============================================================================

#[test]
fn test_adjust_for_jeq_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(42, 0x10, true); // JEQ taken
    assert!(s.is_const());
    assert_eq!(s.const_value(), Some(42));
}

#[test]
fn test_adjust_for_jgt_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(100, 0x20, true); // JGT taken (value > 100)
    assert!(s.umin_value >= 101);
}

#[test]
fn test_adjust_for_jgt_not_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(100, 0x20, false); // JGT not taken (value <= 100)
    assert!(s.umax_value <= 100);
}

#[test]
fn test_adjust_for_jge_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(100, 0x30, true); // JGE taken (value >= 100)
    assert!(s.umin_value >= 100);
}

#[test]
fn test_adjust_for_jlt_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(100, 0xa0, true); // JLT taken (value < 100)
    assert!(s.umax_value <= 99);
}

#[test]
fn test_adjust_for_jle_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(100, 0xb0, true); // JLE taken (value <= 100)
    assert!(s.umax_value <= 100);
}

// ============================================================================
// Signed Comparison Tests
// ============================================================================

#[test]
fn test_adjust_for_jsgt_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(0, 0x60, true); // JSGT taken (svalue > 0)
    assert!(s.smin_value >= 1);
}

#[test]
fn test_adjust_for_jsge_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(0, 0x70, true); // JSGE taken (svalue >= 0)
    assert!(s.smin_value >= 0);
}

#[test]
fn test_adjust_for_jslt_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(0, 0xc0, true); // JSLT taken (svalue < 0)
    assert!(s.smax_value <= -1);
}

#[test]
fn test_adjust_for_jsle_taken() {
    let mut s = ScalarBounds::unknown();
    s.adjust_for_cmp(0, 0xd0, true); // JSLE taken (svalue <= 0)
    assert!(s.smax_value <= 0);
}

// ============================================================================
// Negativity Tests
// ============================================================================

#[test]
fn test_could_be_negative_unknown() {
    let s = ScalarBounds::unknown();
    assert!(s.could_be_negative());
}

#[test]
fn test_could_be_negative_known_positive() {
    let s = ScalarBounds::known(100);
    assert!(!s.could_be_negative());
}

#[test]
fn test_could_be_negative_known_negative() {
    let s = ScalarBounds::known(u64::MAX); // -1 as signed
    assert!(s.could_be_negative());
}

#[test]
fn test_is_non_negative_unknown() {
    let s = ScalarBounds::unknown();
    assert!(!s.is_non_negative());
}

#[test]
fn test_is_non_negative_known_positive() {
    let s = ScalarBounds::known(100);
    assert!(s.is_non_negative());
}

// ============================================================================
// Sanity Tests
// ============================================================================

#[test]
fn test_sane_after_operations() {
    let a = ScalarBounds::unknown();
    let b = ScalarBounds::known(42);
    
    let ops = [
        a.add(&b, true).unwrap(),
        a.sub(&b, true).unwrap(),
        a.mul(&b, true).unwrap(),
        a.and(&b),
        a.or(&b),
        a.xor(&b),
        a.lsh(&b, true).unwrap(),
        a.rsh(&b, true).unwrap(),
    ];
    
    for op_result in ops.iter() {
        assert!(op_result.is_sane(), "Operation result should be sane");
    }
}

#[test]
fn test_deduce_bounds_maintains_sanity() {
    let mut s = ScalarBounds::unknown();
    s.umin_value = 100;
    s.umax_value = 200;
    s.deduce_bounds();
    assert!(s.is_sane());
}
