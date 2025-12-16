// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for memory access verification
//!
//! These tests verify correct behavior at boundary conditions:
//! - Stack boundary access
//! - Register state edge cases
//! - Type flags combinations
//! - Pointer offset handling

use bpf_verifier::core::types::{BpfRegType, BpfStackSlotType, BpfTypeFlag, MAX_BPF_STACK};
use bpf_verifier::state::reg_state::BpfRegState;
use bpf_verifier::state::stack_state::StackState;

// ============================================================================
// Stack State Edge Cases
// ============================================================================

#[test]
fn test_stack_state_new() {
    let stack = StackState::new();
    assert_eq!(stack.allocated_stack, 0);
    assert!(stack.stack.is_empty());
}

#[test]
fn test_stack_state_with_size() {
    let stack = StackState::with_size(64);
    assert!(stack.allocated_stack >= 64);
    assert!(!stack.stack.is_empty());
}

#[test]
fn test_stack_grow_small() {
    let mut stack = StackState::new();
    let result = stack.grow(64);
    assert!(result.is_ok());
    assert!(stack.allocated_stack >= 64);
}

#[test]
fn test_stack_grow_max() {
    let mut stack = StackState::new();
    let result = stack.grow(MAX_BPF_STACK);
    assert!(result.is_ok());
    assert_eq!(stack.allocated_stack, MAX_BPF_STACK);
}

#[test]
fn test_stack_grow_beyond_max() {
    let mut stack = StackState::new();
    let result = stack.grow(MAX_BPF_STACK + 1);
    assert!(result.is_err());
}

#[test]
fn test_stack_grow_incremental() {
    let mut stack = StackState::new();

    stack.grow(64).unwrap();
    assert!(stack.allocated_stack >= 64);

    stack.grow(128).unwrap();
    assert!(stack.allocated_stack >= 128);

    stack.grow(256).unwrap();
    assert!(stack.allocated_stack >= 256);
}

#[test]
fn test_stack_offset_to_slot() {
    let stack = StackState::with_size(64);

    // Valid negative offsets
    assert_eq!(stack.offset_to_slot(-8), Some(0));
    assert_eq!(stack.offset_to_slot(-16), Some(1));
    assert_eq!(stack.offset_to_slot(-24), Some(2));

    // Invalid positive offset
    assert_eq!(stack.offset_to_slot(0), None);
    assert_eq!(stack.offset_to_slot(8), None);

    // Beyond max stack
    assert_eq!(stack.offset_to_slot(-(MAX_BPF_STACK as i32) - 8), None);
}

#[test]
fn test_stack_slot_to_offset() {
    let stack = StackState::with_size(64);

    assert_eq!(stack.slot_to_offset(0), -8);
    assert_eq!(stack.slot_to_offset(1), -16);
    assert_eq!(stack.slot_to_offset(2), -24);
}

#[test]
fn test_stack_get_slot() {
    let stack = StackState::with_size(64);

    // Valid slot
    assert!(stack.get_slot(-8).is_some());
    assert!(stack.get_slot(-16).is_some());

    // Invalid offset
    assert!(stack.get_slot(0).is_none());
    assert!(stack.get_slot(8).is_none());
}

#[test]
fn test_stack_get_slot_mut() {
    let mut stack = StackState::with_size(64);

    // Valid slot - should auto-grow if needed
    assert!(stack.get_slot_mut(-8).is_some());
    assert!(stack.get_slot_mut(-64).is_some());

    // Invalid offset
    assert!(stack.get_slot_mut(0).is_none());
}

// ============================================================================
// Register State Edge Cases
// ============================================================================

#[test]
fn test_reg_state_not_init() {
    let reg = BpfRegState::new_not_init();
    assert_eq!(reg.reg_type, BpfRegType::NotInit);
}

#[test]
fn test_reg_state_scalar_unknown() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_unknown(true);
    assert_eq!(reg.reg_type, BpfRegType::ScalarValue);
    assert!(!reg.is_const());
}

#[test]
fn test_reg_state_scalar_known() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(42);
    assert_eq!(reg.reg_type, BpfRegType::ScalarValue);
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), 42);
}

#[test]
fn test_reg_state_known_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known_zero();
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), 0);
}

#[test]
fn test_reg_state_known_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(u64::MAX);
    assert!(reg.is_const());
    assert_eq!(reg.const_value(), u64::MAX);
}

#[test]
fn test_reg_state_ptr_types() {
    let ptr_types = [
        BpfRegType::PtrToCtx,
        BpfRegType::PtrToStack,
        BpfRegType::PtrToPacket,
        BpfRegType::PtrToPacketEnd,
        BpfRegType::PtrToPacketMeta,
        BpfRegType::PtrToMapValue,
        BpfRegType::PtrToMapKey,
        BpfRegType::ConstPtrToMap,
        BpfRegType::PtrToMem,
        BpfRegType::PtrToBtfId,
    ];

    for ptr_type in ptr_types {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = ptr_type;
        assert!(reg.is_ptr(), "{:?} should be a pointer", ptr_type);
    }
}

#[test]
fn test_reg_state_non_ptr_types() {
    let non_ptr_types = [BpfRegType::NotInit, BpfRegType::ScalarValue];

    for non_ptr_type in non_ptr_types {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = non_ptr_type;
        assert!(!reg.is_ptr(), "{:?} should not be a pointer", non_ptr_type);
    }
}

#[test]
fn test_reg_state_maybe_null() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMem;
    reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
    assert!(reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
}

#[test]
fn test_reg_state_offset_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMapValue;
    reg.off = 0;
    assert_eq!(reg.off, 0);
}

#[test]
fn test_reg_state_offset_negative() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToStack;
    reg.off = -8;
    assert_eq!(reg.off, -8);
}

#[test]
fn test_reg_state_offset_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMapValue;
    reg.off = i32::MAX;
    assert_eq!(reg.off, i32::MAX);
}

#[test]
fn test_reg_state_offset_min() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToStack;
    reg.off = i32::MIN;
    assert_eq!(reg.off, i32::MIN);
}

// ============================================================================
// Memory Size Edge Cases
// ============================================================================

#[test]
fn test_mem_size_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMem;
    reg.mem_size = 0;
    assert_eq!(reg.mem_size, 0);
}

#[test]
fn test_mem_size_one() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMem;
    reg.mem_size = 1;
    assert_eq!(reg.mem_size, 1);
}

#[test]
fn test_mem_size_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMem;
    reg.mem_size = u32::MAX;
    assert_eq!(reg.mem_size, u32::MAX);
}

// ============================================================================
// Reference Tracking Edge Cases
// ============================================================================

#[test]
fn test_ref_obj_id_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.ref_obj_id = 0;
    assert_eq!(reg.ref_obj_id, 0);
}

#[test]
fn test_ref_obj_id_nonzero() {
    let mut reg = BpfRegState::new_not_init();
    reg.ref_obj_id = 42;
    assert_eq!(reg.ref_obj_id, 42);
}

#[test]
fn test_ref_obj_id_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.ref_obj_id = u32::MAX;
    assert_eq!(reg.ref_obj_id, u32::MAX);
}

// ============================================================================
// BTF ID Edge Cases
// ============================================================================

#[test]
fn test_btf_id_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToBtfId;
    reg.set_btf_id(0);
    assert_eq!(reg.btf_id(), 0);
}

#[test]
fn test_btf_id_nonzero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToBtfId;
    reg.set_btf_id(12345);
    assert_eq!(reg.btf_id(), 12345);
}

#[test]
fn test_btf_id_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToBtfId;
    reg.set_btf_id(u32::MAX);
    assert_eq!(reg.btf_id(), u32::MAX);
}

// ============================================================================
// Type Flag Combinations
// ============================================================================

#[test]
fn test_type_flags_empty() {
    let flags = BpfTypeFlag::empty();
    assert!(!flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    assert!(!flags.contains(BpfTypeFlag::MEM_RDONLY));
    assert!(!flags.contains(BpfTypeFlag::MEM_ALLOC));
}

#[test]
fn test_type_flags_maybe_null() {
    let flags = BpfTypeFlag::PTR_MAYBE_NULL;
    assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    assert!(!flags.contains(BpfTypeFlag::PTR_UNTRUSTED));
}

#[test]
fn test_type_flags_combined() {
    let flags = BpfTypeFlag::PTR_MAYBE_NULL | BpfTypeFlag::MEM_RDONLY;
    assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    assert!(flags.contains(BpfTypeFlag::MEM_RDONLY));
    assert!(!flags.contains(BpfTypeFlag::MEM_ALLOC));
}

#[test]
fn test_type_flags_all_dynptr() {
    let all_dynptr = BpfTypeFlag::DYNPTR_TYPE_LOCAL
        | BpfTypeFlag::DYNPTR_TYPE_RINGBUF
        | BpfTypeFlag::DYNPTR_TYPE_SKB
        | BpfTypeFlag::DYNPTR_TYPE_XDP;

    assert!(all_dynptr.contains(BpfTypeFlag::DYNPTR_TYPE_LOCAL));
    assert!(all_dynptr.contains(BpfTypeFlag::DYNPTR_TYPE_RINGBUF));
    assert!(all_dynptr.contains(BpfTypeFlag::DYNPTR_TYPE_SKB));
    assert!(all_dynptr.contains(BpfTypeFlag::DYNPTR_TYPE_XDP));
}

// ============================================================================
// Stack Slot Type Edge Cases
// ============================================================================

#[test]
fn test_stack_slot_types() {
    let slot_types = [
        BpfStackSlotType::Invalid,
        BpfStackSlotType::Spill,
        BpfStackSlotType::Misc,
        BpfStackSlotType::Zero,
        BpfStackSlotType::Dynptr,
        BpfStackSlotType::Iter,
        BpfStackSlotType::IrqFlag,
    ];

    for slot_type in slot_types {
        // Just verify all types exist and can be compared
        assert_eq!(slot_type, slot_type);
    }
}

#[test]
fn test_stack_slot_special() {
    assert!(BpfStackSlotType::Spill.is_special());
    assert!(BpfStackSlotType::Dynptr.is_special());
    assert!(BpfStackSlotType::Iter.is_special());
    assert!(BpfStackSlotType::IrqFlag.is_special());

    assert!(!BpfStackSlotType::Invalid.is_special());
    assert!(!BpfStackSlotType::Misc.is_special());
    assert!(!BpfStackSlotType::Zero.is_special());
}

// ============================================================================
// Map Pointer Edge Cases
// ============================================================================

#[test]
fn test_map_uid_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMapValue;
    reg.map_uid = 0;
    assert_eq!(reg.map_uid, 0);
}

#[test]
fn test_map_uid_nonzero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMapValue;
    reg.map_uid = 42;
    assert_eq!(reg.map_uid, 42);
}

// ============================================================================
// Packet Pointer Edge Cases
// ============================================================================

#[test]
fn test_packet_pointer_types() {
    let mut reg = BpfRegState::new_not_init();

    reg.reg_type = BpfRegType::PtrToPacket;
    assert!(reg.is_pkt_pointer());

    reg.reg_type = BpfRegType::PtrToPacketMeta;
    assert!(reg.is_pkt_pointer());

    reg.reg_type = BpfRegType::PtrToPacketEnd;
    assert!(!reg.is_pkt_pointer()); // PacketEnd is not a pkt pointer

    reg.reg_type = BpfRegType::PtrToMapValue;
    assert!(!reg.is_pkt_pointer());
}

#[test]
fn test_packet_mem_size_zero() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToPacket;
    reg.mem_size = 0;
    assert_eq!(reg.mem_size, 0);
}

#[test]
fn test_packet_mem_size_max() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToPacket;
    reg.mem_size = u32::MAX;
    assert_eq!(reg.mem_size, u32::MAX);
}

// ============================================================================
// Signed/Unsigned Bounds Interaction
// ============================================================================

#[test]
fn test_bounds_min_values() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_unknown(true);

    reg.umin_value = 0;
    reg.smin_value = i64::MIN;

    assert_eq!(reg.umin_value, 0);
    assert_eq!(reg.smin_value, i64::MIN);
}

#[test]
fn test_bounds_max_values() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_unknown(true);

    reg.umax_value = u64::MAX;
    reg.smax_value = i64::MAX;

    assert_eq!(reg.umax_value, u64::MAX);
    assert_eq!(reg.smax_value, i64::MAX);
}

#[test]
fn test_bounds_32bit() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_unknown(true);

    reg.u32_min_value = 0;
    reg.u32_max_value = u32::MAX;
    reg.s32_min_value = i32::MIN;
    reg.s32_max_value = i32::MAX;

    assert_eq!(reg.u32_min_value, 0);
    assert_eq!(reg.u32_max_value, u32::MAX);
    assert_eq!(reg.s32_min_value, i32::MIN);
    assert_eq!(reg.s32_max_value, i32::MAX);
}

// ============================================================================
// Register Clone/Copy Edge Cases
// ============================================================================

#[test]
fn test_reg_state_clone() {
    let mut reg = BpfRegState::new_not_init();
    reg.mark_known(12345);
    reg.ref_obj_id = 42;

    let cloned = reg.clone();
    assert_eq!(cloned.const_value(), 12345);
    assert_eq!(cloned.ref_obj_id, 42);
}

#[test]
fn test_stack_state_clone() {
    let mut stack = StackState::new();
    stack.grow(128).unwrap();

    let cloned = stack.clone();
    assert_eq!(cloned.allocated_stack, stack.allocated_stack);
    assert_eq!(cloned.stack.len(), stack.stack.len());
}
