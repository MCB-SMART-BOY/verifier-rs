// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::timer_kptr

use bpf_verifier::prelude::*;
use bpf_verifier::special::timer_kptr::*;


#[test]
fn test_kptr_type() {
    assert!(!KptrType::Unref.requires_refcount());
    assert!(KptrType::Ref.requires_refcount());
    assert!(KptrType::Percpu.requires_refcount());
    
    assert!(KptrType::Unref.allows_untrusted());
    assert!(!KptrType::Ref.allows_untrusted());
}

#[test]
fn test_special_field_size() {
    assert_eq!(SpecialFieldType::Timer.size(), 16);
    assert_eq!(SpecialFieldType::SpinLock.size(), 4);
    assert_eq!(SpecialFieldType::Kptr(KptrType::Ref).size(), 8);
    assert_eq!(SpecialFieldType::RbNode.size(), 24);
}

#[test]
fn test_timer_state() {
    let mut timer = TimerState::new(1, 0);
    assert!(!timer.initialized);
    
    // Cannot set callback before init
    assert!(timer.set_callback(10).is_err());
    
    timer.init();
    assert!(timer.initialized);
    
    // Can set callback after init
    assert!(timer.set_callback(10).is_ok());
    assert!(timer.callback_set);
    assert_eq!(timer.callback_insn, Some(10));
}

#[test]
fn test_check_timer_arg() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToMapValue;
    reg.map_uid = 1;
    reg.off = 16;
    
    let result = check_timer_arg(&reg, 1);
    assert!(result.is_ok());
    let (map_uid, timer_off) = result.unwrap();
    assert_eq!(map_uid, 1);
    assert_eq!(timer_off, 16);
    
    // Unaligned offset should fail
    reg.off = 17;
    assert!(check_timer_arg(&reg, 1).is_err());
}

#[test]
fn test_check_timer_init_map_arg() {
    let mut timer_reg = BpfRegState::new_not_init();
    timer_reg.reg_type = BpfRegType::PtrToMapValue;
    timer_reg.map_uid = 1;
    
    let mut map_reg = BpfRegState::new_not_init();
    map_reg.reg_type = BpfRegType::ConstPtrToMap;
    map_reg.map_uid = 1;
    
    // Same map_uid should succeed
    assert!(check_timer_init_map_arg(&timer_reg, &map_reg).is_ok());
    
    // Different map_uid should fail
    map_reg.map_uid = 2;
    assert!(check_timer_init_map_arg(&timer_reg, &map_reg).is_err());
}

#[test]
fn test_check_special_field_overlap() {
    let fields = vec![
        SpecialFieldInfo {
            field_type: SpecialFieldType::Timer,
            offset: 16,
            btf_id: None,
        },
        SpecialFieldInfo {
            field_type: SpecialFieldType::SpinLock,
            offset: 32,
            btf_id: None,
        },
    ];
    
    // Access before timer - should succeed
    assert!(check_special_field_overlap(0, 16, &fields).is_ok());
    
    // Access overlapping timer - should fail
    assert!(check_special_field_overlap(12, 8, &fields).is_err());
    
    // Access between timer and spin_lock - should succeed
    assert!(check_special_field_overlap(32, 4, &fields).is_err()); // Hits spin_lock
    
    // Access after special fields - should succeed
    assert!(check_special_field_overlap(36, 8, &fields).is_ok());
}

#[test]
fn test_kptr_load_type() {
    // Not in RCU - just nullable
    let flags = kptr_load_type(KptrType::Ref, false, true);
    assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    assert!(!flags.contains(BpfTypeFlag::MEM_RCU));
    
    // In RCU with RCU-protected kptr
    let flags = kptr_load_type(KptrType::Ref, true, true);
    assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
    assert!(flags.contains(BpfTypeFlag::MEM_RCU));
    assert!(flags.contains(BpfTypeFlag::MEM_ALLOC));
    
    // Percpu kptr in RCU
    let flags = kptr_load_type(KptrType::Percpu, true, true);
    assert!(flags.contains(BpfTypeFlag::MEM_RCU));
    assert!(flags.contains(BpfTypeFlag::MEM_PERCPU));
}

#[test]
fn test_check_timer_context() {
    let refs = ReferenceManager::new();
    
    // Normal context should succeed
    assert!(check_timer_context(&refs, false).is_ok());
    
    // PREEMPT_RT should fail
    assert!(check_timer_context(&refs, true).is_err());
    
    // With lock held should fail
    let mut refs_with_lock = ReferenceManager::new();
    refs_with_lock.acquire_lock(0, 0x1000);
    assert!(check_timer_context(&refs_with_lock, false).is_err());
}

#[test]
fn test_check_timer_callback_registration() {
    // Same map_uid should succeed
    assert!(check_timer_callback_registration(1, 1).is_ok());
    
    // Different map_uid should fail
    assert!(check_timer_callback_registration(1, 2).is_err());
    
    // Zero map_uid (unknown) should succeed
    assert!(check_timer_callback_registration(0, 1).is_ok());
    assert!(check_timer_callback_registration(1, 0).is_ok());
}
