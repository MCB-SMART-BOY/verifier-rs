// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for BpfRegState (register state tracking)
//!
//! Tests register types, bounds, and state transitions.

use bpf_verifier::state::reg_state::{BpfRegState, RegLiveness, LinkedRegs, BPF_ADD_CONST};
use bpf_verifier::bpf_core::types::*;

// ============================================================================
// Constructor Tests
// ============================================================================

#[test]
fn test_new_not_init() {
    let reg = BpfRegState::new_not_init();
    assert_eq!(reg.reg_type, BpfRegType::NotInit);
    assert!(!reg.is_scalar());
    assert!(!reg.is_pointer());
    assert!(!reg.is_const());
}

#[test]
fn test_new_scalar_unknown() {
    let reg = BpfRegState::new_scalar_unknown(false);
    assert_eq!(reg.reg_type, BpfRegType::ScalarValue);
    assert!(reg.is_scalar());
    assert!(!reg.is_const());
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, u64::MAX);
    assert_eq!(reg.smin_value, i64::MIN);
    assert_eq!(reg.smax_value, i64::MAX);
}

#[test]
fn test_new_scalar_unknown_precise() {
    let reg = BpfRegState::new_scalar_unknown(true);
    assert!(reg.precise);
}

#[test]
fn test_new_ctx_ptr() {
    let reg = BpfRegState::new_ctx_ptr(BpfProgType::Unspec);
    assert_eq!(reg.reg_type, BpfRegType::PtrToCtx);
    assert!(reg.is_pointer());
    assert!(reg.is_const()); // var_off should be const 0
    assert_eq!(reg.var_off.value, 0);
}

#[test]
fn test_new_fp() {
    let reg = BpfRegState::new_fp();
    assert_eq!(reg.reg_type, BpfRegType::PtrToStack);
    assert!(reg.is_pointer());
    assert_eq!(reg.off, 0);
}

#[test]
fn test_default_is_not_init() {
    let reg = BpfRegState::default();
    assert_eq!(reg.reg_type, BpfRegType::NotInit);
}

// ============================================================================
// Mark Known/Unknown Tests
// ============================================================================

#[test]
fn test_mark_known_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known_zero();
    assert!(reg.is_scalar());
    assert!(reg.is_const());
    assert!(reg.is_null());
    assert_eq!(reg.const_value(), 0);
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, 0);
}

#[test]
fn test_mark_known_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(u64::MAX);
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), u64::MAX);
    assert_eq!(reg.umin_value, u64::MAX);
    assert_eq!(reg.umax_value, u64::MAX);
    assert_eq!(reg.smin_value, -1);
    assert_eq!(reg.smax_value, -1);
}

#[test]
fn test_mark_known_arbitrary() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(0x12345678_9ABCDEF0);
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), 0x12345678_9ABCDEF0);
}

#[test]
fn test_mark_unknown() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(42);
    reg.mark_unknown(false);
    assert!(reg.is_scalar());
    assert!(!reg.is_const());
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, u64::MAX);
}

#[test]
fn test_mark_not_init() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_known(42);
    reg.mark_not_init(false);
    assert_eq!(reg.reg_type, BpfRegType::NotInit);
}

#[test]
fn test_mark_const_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_const_zero(true);
    assert!(reg.is_scalar());
    assert!(reg.is_const());
    assert!(reg.precise);
    assert_eq!(reg.const_value(), 0);
}

// ============================================================================
// 32-bit Subreg Tests
// ============================================================================

#[test]
fn test_mark_32_known() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_32_known(0x12345678);
    assert_eq!(reg.u32_min_value, 0x12345678);
    assert_eq!(reg.u32_max_value, 0x12345678);
    assert_eq!(reg.s32_min_value, 0x12345678i32);
    assert_eq!(reg.s32_max_value, 0x12345678i32);
}

#[test]
fn test_mark_32_known_negative() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_32_known(0xFFFFFFFF);
    assert_eq!(reg.u32_min_value, 0xFFFFFFFF);
    assert_eq!(reg.u32_max_value, 0xFFFFFFFF);
    assert_eq!(reg.s32_min_value, -1);
    assert_eq!(reg.s32_max_value, -1);
}

// ============================================================================
// Bounds Tests
// ============================================================================

#[test]
fn test_mark_unbounded() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(100);
    reg.mark_unbounded();
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, u64::MAX);
    assert_eq!(reg.smin_value, i64::MIN);
    assert_eq!(reg.smax_value, i64::MAX);
}

#[test]
fn test_mark_64_unbounded() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(100);
    reg.mark_64_unbounded();
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, u64::MAX);
    // 32-bit bounds should still be set to 100
    assert_eq!(reg.u32_min_value, 100);
    assert_eq!(reg.u32_max_value, 100);
}

#[test]
fn test_mark_32_unbounded() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(100);
    reg.mark_32_unbounded();
    assert_eq!(reg.u32_min_value, 0);
    assert_eq!(reg.u32_max_value, u32::MAX);
    // 64-bit bounds should still be set to 100
    assert_eq!(reg.umin_value, 100);
    assert_eq!(reg.umax_value, 100);
}

// ============================================================================
// Type Check Tests
// ============================================================================

#[test]
fn test_is_null() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known_zero();
    assert!(reg.is_null());
    
    reg.mark_known(1);
    assert!(!reg.is_null());
}

#[test]
fn test_is_scalar() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    assert!(reg.is_scalar());
    
    reg.reg_type = BpfRegType::PtrToStack;
    assert!(!reg.is_scalar());
}

#[test]
fn test_is_pointer_types() {
    let reg_types = [
        (BpfRegType::PtrToCtx, true),
        (BpfRegType::PtrToStack, true),
        (BpfRegType::PtrToMapValue, true),
        (BpfRegType::PtrToMapKey, true),
        (BpfRegType::PtrToMem, true),
        (BpfRegType::ScalarValue, false),
        (BpfRegType::NotInit, false),
    ];
    
    for (reg_type, expected) in reg_types {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = reg_type;
        assert_eq!(reg.is_pointer(), expected, "Failed for {:?}", reg_type);
    }
}

#[test]
fn test_is_ptr_alias() {
    let reg = BpfRegState::new_ctx_ptr(BpfProgType::Unspec);
    assert_eq!(reg.is_ptr(), reg.is_pointer());
}

// ============================================================================
// Bounds Sanity Tests
// ============================================================================

#[test]
fn test_bounds_sanity_check_valid() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_known(100);
    assert!(reg.bounds_sanity_check().is_ok());
}

#[test]
fn test_bounds_sanity_check_invalid_urange() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.umin_value = 100;
    reg.umax_value = 50; // Invalid: min > max
    assert!(reg.bounds_sanity_check().is_err());
}

#[test]
fn test_bounds_sanity_check_invalid_srange() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.smin_value = 100;
    reg.smax_value = -100; // Invalid: min > max
    assert!(reg.bounds_sanity_check().is_err());
}

#[test]
fn test_bounds_sanity_check_invalid_u32range() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.u32_min_value = 100;
    reg.u32_max_value = 50;
    assert!(reg.bounds_sanity_check().is_err());
}

#[test]
fn test_bounds_sanity_check_invalid_s32range() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.s32_min_value = 100;
    reg.s32_max_value = -100;
    assert!(reg.bounds_sanity_check().is_err());
}

// ============================================================================
// Sync Bounds Tests
// ============================================================================

#[test]
fn test_sync_bounds_preserves_const() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(42);
    reg.sync_bounds();
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), 42);
}

#[test]
fn test_sync_bounds_unknown() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.sync_bounds();
    // Should still be sane
    assert!(reg.bounds_sanity_check().is_ok());
}

// ============================================================================
// 32/64 Bit Assignment Tests
// ============================================================================

#[test]
fn test_assign_32_into_64() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.u32_min_value = 100;
    reg.u32_max_value = 200;
    reg.s32_min_value = 100;
    reg.s32_max_value = 200;
    reg.assign_32_into_64();
    assert_eq!(reg.umin_value, 100);
    assert_eq!(reg.umax_value, 200);
    assert_eq!(reg.smin_value, 100);
    assert_eq!(reg.smax_value, 200);
}

#[test]
fn test_assign_32_into_64_full_range() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.u32_min_value = 0;
    reg.u32_max_value = u32::MAX;
    reg.s32_min_value = i32::MIN;
    reg.s32_max_value = i32::MAX;
    reg.assign_32_into_64();
    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.umax_value, u32::MAX as u64);
}

// ============================================================================
// Pointer Offset Tests
// ============================================================================

#[test]
fn test_check_sane_offset_scalar() {
    let reg = BpfRegState::new_scalar_unknown(false);
    // Non-pointers always pass
    assert!(reg.check_sane_offset().is_ok());
}

#[test]
fn test_check_sane_offset_valid_ptr() {
    let mut reg = BpfRegState::new_fp();
    reg.off = 100;
    assert!(reg.check_sane_offset().is_ok());
}

#[test]
fn test_check_sane_offset_invalid_ptr() {
    let mut reg = BpfRegState::new_fp();
    reg.off = 10_000_000; // Way too large
    assert!(reg.check_sane_offset().is_err());
}

#[test]
fn test_check_sane_offset_negative_valid() {
    let mut reg = BpfRegState::new_fp();
    reg.off = -512; // Valid negative offset
    assert!(reg.check_sane_offset().is_ok());
}

// ============================================================================
// Linked Register Tests
// ============================================================================

#[test]
fn test_is_linked_false() {
    let reg = BpfRegState::new_scalar_unknown(false);
    assert!(!reg.is_linked());
}

#[test]
fn test_mark_linked() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_linked(42);
    assert!(reg.is_linked());
    assert_eq!(reg.base_id(), 42);
}

#[test]
fn test_clear_linked() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.mark_linked(42);
    assert!(reg.is_linked());
    reg.clear_linked();
    assert!(!reg.is_linked());
    assert_eq!(reg.id, 42); // Base ID preserved
}

#[test]
fn test_linked_to_same_base() {
    let mut reg1 = BpfRegState::new_scalar_unknown(false);
    let mut reg2 = BpfRegState::new_scalar_unknown(false);
    
    reg1.mark_linked(100);
    reg2.mark_linked(100);
    
    assert!(reg1.linked_to_same_base(&reg2));
}

#[test]
fn test_linked_to_different_base() {
    let mut reg1 = BpfRegState::new_scalar_unknown(false);
    let mut reg2 = BpfRegState::new_scalar_unknown(false);
    
    reg1.mark_linked(100);
    reg2.mark_linked(200);
    
    assert!(!reg1.linked_to_same_base(&reg2));
}

#[test]
fn test_linked_delta() {
    let mut reg1 = BpfRegState::new_scalar_unknown(false);
    let mut reg2 = BpfRegState::new_scalar_unknown(false);
    
    reg1.mark_linked(100);
    reg1.off = 10;
    reg2.mark_linked(100);
    reg2.off = 30;
    
    assert_eq!(reg1.linked_delta(&reg2), Some(-20)); // 10 - 30 = -20
}

#[test]
fn test_linked_delta_not_linked() {
    let reg1 = BpfRegState::new_scalar_unknown(false);
    let reg2 = BpfRegState::new_scalar_unknown(false);
    
    assert_eq!(reg1.linked_delta(&reg2), None);
}

// ============================================================================
// RegLiveness Tests
// ============================================================================

#[test]
fn test_reg_liveness_default() {
    let liveness = RegLiveness::default();
    assert!(!liveness.read);
    assert!(!liveness.written);
    assert!(!liveness.done);
}

// ============================================================================
// LinkedRegs Tests
// ============================================================================

#[test]
fn test_linked_regs_new() {
    let regs = LinkedRegs::new();
    assert_eq!(regs.cnt, 0);
}

#[test]
fn test_linked_regs_add() {
    let mut regs = LinkedRegs::new();
    assert!(regs.add(0, false).is_ok());
    assert_eq!(regs.cnt, 1);
    assert!(regs.contains(0));
}

#[test]
fn test_linked_regs_add_duplicate() {
    let mut regs = LinkedRegs::new();
    regs.add(0, false).unwrap();
    regs.add(0, false).unwrap(); // Duplicate
    assert_eq!(regs.cnt, 1); // Still only 1
}

#[test]
fn test_linked_regs_add_multiple() {
    let mut regs = LinkedRegs::new();
    for i in 0..5 {
        regs.add(i, false).unwrap();
    }
    assert_eq!(regs.cnt, 5);
    for i in 0..5 {
        assert!(regs.contains(i));
    }
}

#[test]
fn test_linked_regs_contains_not_found() {
    let mut regs = LinkedRegs::new();
    regs.add(1, false).unwrap();
    assert!(!regs.contains(0));
    assert!(regs.contains(1));
}

#[test]
fn test_linked_regs_clear() {
    let mut regs = LinkedRegs::new();
    regs.add(0, false).unwrap();
    regs.add(1, false).unwrap();
    regs.clear();
    assert_eq!(regs.cnt, 0);
}

#[test]
fn test_linked_regs_iter() {
    let mut regs = LinkedRegs::new();
    regs.add(0, false).unwrap();
    regs.add(1, true).unwrap();
    
    let items: Vec<_> = regs.iter().collect();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].reg, 0);
    assert!(!items[0].subreg);
    assert_eq!(items[1].reg, 1);
    assert!(items[1].subreg);
}

// ============================================================================
// BTF Info Tests
// ============================================================================

#[test]
fn test_btf_id_default() {
    let reg = BpfRegState::new_scalar_unknown(false);
    assert_eq!(reg.btf_id(), 0);
}

#[test]
fn test_set_btf_id() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.set_btf_id(42);
    assert_eq!(reg.btf_id(), 42);
}

#[test]
fn test_set_btf_id_twice() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.set_btf_id(42);
    reg.set_btf_id(100);
    assert_eq!(reg.btf_id(), 100);
}

// ============================================================================
// ScalarBounds Conversion Tests
// ============================================================================

#[test]
fn test_to_scalar_bounds() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    reg.umin_value = 10;
    reg.umax_value = 100;
    
    let bounds = reg.to_scalar_bounds();
    assert_eq!(bounds.umin_value, 10);
    assert_eq!(bounds.umax_value, 100);
}

#[test]
fn test_apply_scalar_bounds() {
    let mut reg = BpfRegState::new_scalar_unknown(false);
    let bounds = bpf_verifier::bounds::scalar::ScalarBounds::known(42);
    
    reg.apply_scalar_bounds(&bounds);
    assert_eq!(reg.umin_value, 42);
    assert_eq!(reg.umax_value, 42);
}

// ============================================================================
// Edge Cases with Extreme Values
// ============================================================================

#[test]
fn test_mark_known_i64_min() {
    let mut reg = BpfRegState::new_not_init();
    let val = i64::MIN as u64;
    reg.mark_known(val);
    assert!(reg.is_const());
    assert_eq!(reg.smin_value, i64::MIN);
    assert_eq!(reg.smax_value, i64::MIN);
}

#[test]
fn test_mark_known_i64_max() {
    let mut reg = BpfRegState::new_not_init();
    let val = i64::MAX as u64;
    reg.mark_known(val);
    assert!(reg.is_const());
    assert_eq!(reg.smin_value, i64::MAX);
    assert_eq!(reg.smax_value, i64::MAX);
}

#[test]
fn test_bpf_add_const_bit() {
    // Verify the constant is set correctly
    assert_eq!(BPF_ADD_CONST, 1 << 31);
    assert_eq!(BPF_ADD_CONST, 0x80000000);
}
