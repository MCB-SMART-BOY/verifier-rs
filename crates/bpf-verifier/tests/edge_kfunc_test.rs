// SPDX-License-Identifier: GPL-2.0
//! Edge case tests for kfunc verification
//!
//! These tests verify correct behavior at boundary conditions:
//! - Maximum kfunc registrations
//! - Invalid BTF IDs
//! - Acquire/release pairing
//! - Sleepable context violations

use bpf_verifier::check::kfunc::{
special_kfuncs, validate_percpu_obj_size, KfuncArgType, KfuncDesc, KfuncFlags,
KfuncParamDesc, KfuncRegistry, KfuncRetType, is_bpf_graph_api_kfunc,
is_bpf_list_api_kfunc, is_bpf_rbtree_api_kfunc, is_irq_kfunc, is_irq_restore_kfunc,
is_irq_save_kfunc, is_kfunc_bpf_preempt_disable, is_kfunc_bpf_preempt_enable,
is_kfunc_bpf_rcu_read_lock, is_kfunc_bpf_rcu_read_unlock, MAX_KFUNC_DESCS,
};
use bpf_verifier::bpf_core::types::{BpfProgType, BPF_GLOBAL_PERCPU_MA_MAX_SIZE};

// ============================================================================
// Registry Limit Edge Cases
// ============================================================================

#[test]
fn test_registry_empty() {
let registry = KfuncRegistry::new();
assert!(registry.find_by_id(0).is_none());
assert!(registry.find_by_id(1).is_none());
assert!(registry.find_by_name("nonexistent").is_none());
}

#[test]
fn test_registry_duplicate_btf_id() {
let mut registry = KfuncRegistry::new();

registry
    .register(KfuncDesc {
        btf_id: 100,
        name: "first".into(),
        ..Default::default()
    })
    .unwrap();

// Register with same BTF ID - should overwrite
registry
    .register(KfuncDesc {
        btf_id: 100,
        name: "second".into(),
        ..Default::default()
    })
    .unwrap();

let desc = registry.find_by_id(100).unwrap();
assert_eq!(desc.name, "second");
}

#[test]
fn test_registry_duplicate_name() {
let mut registry = KfuncRegistry::new();

registry
    .register(KfuncDesc {
        btf_id: 100,
        name: "same_name".into(),
        ..Default::default()
    })
    .unwrap();

registry
    .register(KfuncDesc {
        btf_id: 200,
        name: "same_name".into(),
        ..Default::default()
    })
    .unwrap();

// Name lookup should return the latest
let desc = registry.find_by_name("same_name").unwrap();
assert_eq!(desc.btf_id, 200);
}

#[test]
fn test_registry_max_limit() {
let mut registry = KfuncRegistry::new();

// Register up to limit
for i in 0..MAX_KFUNC_DESCS {
    let result = registry.register(KfuncDesc {
        btf_id: i as u32,
        name: format!("kfunc_{}", i),
        ..Default::default()
    });
    assert!(result.is_ok(), "Should succeed for index {}", i);
}

// One more should fail
let result = registry.register(KfuncDesc {
    btf_id: MAX_KFUNC_DESCS as u32,
    name: "overflow".into(),
    ..Default::default()
});
assert!(result.is_err());
}

// ============================================================================
// BTF ID Edge Cases
// ============================================================================

#[test]
fn test_btf_id_zero() {
let mut registry = KfuncRegistry::new();

registry
    .register(KfuncDesc {
        btf_id: 0,
        name: "zero_id".into(),
        ..Default::default()
    })
    .unwrap();

assert!(registry.find_by_id(0).is_some());
}

#[test]
fn test_btf_id_max() {
let mut registry = KfuncRegistry::new();

registry
    .register(KfuncDesc {
        btf_id: u32::MAX,
        name: "max_id".into(),
        ..Default::default()
    })
    .unwrap();

assert!(registry.find_by_id(u32::MAX).is_some());
}

// ============================================================================
// Kfunc Flags Edge Cases
// ============================================================================

#[test]
fn test_acquire_and_release_both_set() {
// Some kfuncs like kptr_xchg are both acquire and release
let flags = KfuncFlags {
    is_acquire: true,
    is_release: true,
    ..Default::default()
};
assert!(flags.is_acquire);
assert!(flags.is_release);
}

#[test]
fn test_all_flags_set() {
let flags = KfuncFlags {
    is_acquire: true,
    is_release: true,
    trusted_args: true,
    sleepable: true,
    destructive: true,
    rcu: true,
    rcu_protected: true,
    ret_null: true,
};

assert!(flags.is_acquire);
assert!(flags.is_release);
assert!(flags.trusted_args);
assert!(flags.sleepable);
assert!(flags.destructive);
assert!(flags.rcu);
assert!(flags.rcu_protected);
assert!(flags.ret_null);
}

#[test]
fn test_default_flags() {
let flags = KfuncFlags::default();

assert!(!flags.is_acquire);
assert!(!flags.is_release);
assert!(!flags.trusted_args);
assert!(!flags.sleepable);
assert!(!flags.destructive);
assert!(!flags.rcu);
assert!(!flags.rcu_protected);
assert!(!flags.ret_null);
}

// ============================================================================
// Percpu Object Size Edge Cases
// ============================================================================

#[test]
fn test_percpu_obj_size_zero() {
assert!(validate_percpu_obj_size(0, "empty_struct").is_ok());
}

#[test]
fn test_percpu_obj_size_one() {
assert!(validate_percpu_obj_size(1, "tiny_struct").is_ok());
}

#[test]
fn test_percpu_obj_size_exact_max() {
assert!(validate_percpu_obj_size(BPF_GLOBAL_PERCPU_MA_MAX_SIZE, "max_struct").is_ok());
}

#[test]
fn test_percpu_obj_size_one_over_max() {
assert!(validate_percpu_obj_size(BPF_GLOBAL_PERCPU_MA_MAX_SIZE + 1, "too_large").is_err());
}

#[test]
fn test_percpu_obj_size_way_over_max() {
assert!(validate_percpu_obj_size(1024 * 1024, "huge_struct").is_err());
}

// ============================================================================
// Special Kfunc ID Classification
// ============================================================================

#[test]
fn test_rcu_kfunc_classification() {
assert!(is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_LOCK));
assert!(!is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_UNLOCK));
assert!(!is_kfunc_bpf_rcu_read_lock(0));
assert!(!is_kfunc_bpf_rcu_read_lock(u32::MAX));

assert!(is_kfunc_bpf_rcu_read_unlock(special_kfuncs::BPF_RCU_READ_UNLOCK));
assert!(!is_kfunc_bpf_rcu_read_unlock(special_kfuncs::BPF_RCU_READ_LOCK));
}

#[test]
fn test_preempt_kfunc_classification() {
assert!(is_kfunc_bpf_preempt_disable(special_kfuncs::BPF_PREEMPT_DISABLE));
assert!(!is_kfunc_bpf_preempt_disable(special_kfuncs::BPF_PREEMPT_ENABLE));

assert!(is_kfunc_bpf_preempt_enable(special_kfuncs::BPF_PREEMPT_ENABLE));
assert!(!is_kfunc_bpf_preempt_enable(special_kfuncs::BPF_PREEMPT_DISABLE));
}

#[test]
fn test_graph_api_classification() {
// List APIs
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_LIST_PUSH_FRONT));
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_LIST_PUSH_BACK));
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_LIST_POP_FRONT));
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_LIST_POP_BACK));

// Rbtree APIs
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_RBTREE_ADD));
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_RBTREE_REMOVE));
assert!(is_bpf_graph_api_kfunc(special_kfuncs::BPF_RBTREE_FIRST));

// Non-graph APIs
assert!(!is_bpf_graph_api_kfunc(special_kfuncs::BPF_RCU_READ_LOCK));
assert!(!is_bpf_graph_api_kfunc(special_kfuncs::BPF_OBJ_NEW));
}

#[test]
fn test_list_api_classification() {
assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_PUSH_FRONT));
assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_PUSH_BACK));
assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_POP_FRONT));
assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_POP_BACK));

// Rbtree is not list
assert!(!is_bpf_list_api_kfunc(special_kfuncs::BPF_RBTREE_ADD));
}

#[test]
fn test_rbtree_api_classification() {
assert!(is_bpf_rbtree_api_kfunc(special_kfuncs::BPF_RBTREE_ADD));
assert!(is_bpf_rbtree_api_kfunc(special_kfuncs::BPF_RBTREE_REMOVE));
assert!(is_bpf_rbtree_api_kfunc(special_kfuncs::BPF_RBTREE_FIRST));

// List is not rbtree
assert!(!is_bpf_rbtree_api_kfunc(special_kfuncs::BPF_LIST_PUSH_FRONT));
}

#[test]
fn test_irq_kfunc_classification() {
// Save operations
assert!(is_irq_save_kfunc(special_kfuncs::BPF_LOCAL_IRQ_SAVE));
assert!(is_irq_save_kfunc(special_kfuncs::BPF_SPIN_LOCK_IRQSAVE));
assert!(!is_irq_save_kfunc(special_kfuncs::BPF_LOCAL_IRQ_RESTORE));

// Restore operations
assert!(is_irq_restore_kfunc(special_kfuncs::BPF_LOCAL_IRQ_RESTORE));
assert!(is_irq_restore_kfunc(special_kfuncs::BPF_SPIN_UNLOCK_IRQRESTORE));
assert!(!is_irq_restore_kfunc(special_kfuncs::BPF_LOCAL_IRQ_SAVE));

// General IRQ check
assert!(is_irq_kfunc(special_kfuncs::BPF_LOCAL_IRQ_SAVE));
assert!(is_irq_kfunc(special_kfuncs::BPF_LOCAL_IRQ_RESTORE));
assert!(is_irq_kfunc(special_kfuncs::BPF_SPIN_LOCK_IRQSAVE));
assert!(is_irq_kfunc(special_kfuncs::BPF_SPIN_UNLOCK_IRQRESTORE));
assert!(!is_irq_kfunc(special_kfuncs::BPF_RCU_READ_LOCK));
}

// ============================================================================
// Kfunc Argument Type Edge Cases
// ============================================================================

#[test]
fn test_all_arg_types() {
// Just ensure all variants are valid
let types = [
    KfuncArgType::AnyPtr,
    KfuncArgType::PtrToScalar,
    KfuncArgType::PtrToBtfId,
    KfuncArgType::PtrToAlloc,
    KfuncArgType::PtrToRefcountedKptr,
    KfuncArgType::PtrToDynptr,
    KfuncArgType::PtrToIter,
    KfuncArgType::PtrToListHead,
    KfuncArgType::PtrToListNode,
    KfuncArgType::PtrToRbRoot,
    KfuncArgType::PtrToRbNode,
    KfuncArgType::PtrToCtx,
    KfuncArgType::PtrToMem,
    KfuncArgType::PtrToMemSize,
    KfuncArgType::PtrToCallback,
    KfuncArgType::PtrToMap,
    KfuncArgType::PtrToWorkqueue,
    KfuncArgType::PtrToConstStr,
    KfuncArgType::PtrToIrqFlag,
    KfuncArgType::PtrToResSpinLock,
    KfuncArgType::PtrToTaskWork,
    KfuncArgType::PtrToNull,
    KfuncArgType::Scalar,
    KfuncArgType::Any,
];

for arg_type in types {
    let param = KfuncParamDesc {
        arg_type,
        ..Default::default()
    };
    assert_eq!(param.arg_type, arg_type);
}
}

#[test]
fn test_return_types() {
let types = [
    KfuncRetType::Void,
    KfuncRetType::Scalar,
    KfuncRetType::Ptr,
    KfuncRetType::PtrToBtfId,
    KfuncRetType::AcquiredPtr,
];

for ret_type in types {
    let desc = KfuncDesc {
        btf_id: 1,
        name: "test".into(),
        ret_type,
        ..Default::default()
    };
    assert_eq!(desc.ret_type, ret_type);
}
}

// ============================================================================
// Program Type Filtering Edge Cases
// ============================================================================

#[test]
fn test_allowed_prog_types_empty() {
let desc = KfuncDesc {
    btf_id: 1,
    name: "universal".into(),
    allowed_prog_types: vec![],
    ..Default::default()
};

// Empty list means all program types allowed
assert!(desc.is_allowed_for_prog_type(BpfProgType::Kprobe));
assert!(desc.is_allowed_for_prog_type(BpfProgType::Xdp));
assert!(desc.is_allowed_for_prog_type(BpfProgType::SchedCls));
}

#[test]
fn test_allowed_prog_types_single() {
let desc = KfuncDesc {
    btf_id: 1,
    name: "kprobe_only".into(),
    allowed_prog_types: vec![BpfProgType::Kprobe],
    ..Default::default()
};

assert!(desc.is_allowed_for_prog_type(BpfProgType::Kprobe));
assert!(!desc.is_allowed_for_prog_type(BpfProgType::Xdp));
assert!(!desc.is_allowed_for_prog_type(BpfProgType::SchedCls));
}

#[test]
fn test_allowed_prog_types_multiple() {
let desc = KfuncDesc {
    btf_id: 1,
    name: "net_only".into(),
    allowed_prog_types: vec![BpfProgType::Xdp, BpfProgType::SchedCls, BpfProgType::SchedAct],
    ..Default::default()
};

assert!(desc.is_allowed_for_prog_type(BpfProgType::Xdp));
assert!(desc.is_allowed_for_prog_type(BpfProgType::SchedCls));
assert!(desc.is_allowed_for_prog_type(BpfProgType::SchedAct));
assert!(!desc.is_allowed_for_prog_type(BpfProgType::Kprobe));
}

#[test]
fn test_find_by_prog_type() {
let mut registry = KfuncRegistry::new();

registry
    .register(KfuncDesc {
        btf_id: 1,
        name: "kprobe_kfunc".into(),
        allowed_prog_types: vec![BpfProgType::Kprobe],
        ..Default::default()
    })
    .unwrap();

registry
    .register(KfuncDesc {
        btf_id: 2,
        name: "xdp_kfunc".into(),
        allowed_prog_types: vec![BpfProgType::Xdp],
        ..Default::default()
    })
    .unwrap();

assert!(registry
    .find_by_id_for_prog(1, BpfProgType::Kprobe)
    .is_some());
assert!(registry.find_by_id_for_prog(1, BpfProgType::Xdp).is_none());
assert!(registry.find_by_id_for_prog(2, BpfProgType::Xdp).is_some());
assert!(registry
    .find_by_id_for_prog(2, BpfProgType::Kprobe)
    .is_none());
}

// ============================================================================
// Common Kfunc Registration Edge Cases
// ============================================================================

#[test]
fn test_register_common_all_present() {
let mut registry = KfuncRegistry::new();
registry.register_common();

// Core kfuncs
assert!(registry.find_by_name("bpf_rcu_read_lock").is_some());
assert!(registry.find_by_name("bpf_rcu_read_unlock").is_some());
assert!(registry.find_by_name("bpf_obj_new_impl").is_some());
assert!(registry.find_by_name("bpf_obj_drop_impl").is_some());

// List kfuncs
assert!(registry.find_by_name("bpf_list_push_front_impl").is_some());
assert!(registry.find_by_name("bpf_list_push_back_impl").is_some());
assert!(registry.find_by_name("bpf_list_pop_front").is_some());
assert!(registry.find_by_name("bpf_list_pop_back").is_some());

// Rbtree kfuncs
assert!(registry.find_by_name("bpf_rbtree_add_impl").is_some());
assert!(registry.find_by_name("bpf_rbtree_remove").is_some());
assert!(registry.find_by_name("bpf_rbtree_first").is_some());

// Preempt kfuncs
assert!(registry.find_by_name("bpf_preempt_disable").is_some());
assert!(registry.find_by_name("bpf_preempt_enable").is_some());

// Per-CPU kfuncs
assert!(registry.find_by_name("bpf_percpu_obj_new_impl").is_some());
assert!(registry.find_by_name("bpf_percpu_obj_drop_impl").is_some());

// Kernel 6.x kfuncs
assert!(registry.find_by_name("bpf_session_cookie").is_some());
assert!(registry.find_by_name("bpf_arena_alloc_pages").is_some());
assert!(registry.find_by_name("bpf_arena_free_pages").is_some());
}

#[test]
fn test_kfunc_desc_default() {
let desc = KfuncDesc::default();

assert_eq!(desc.btf_id, 0);
assert!(desc.name.is_empty());
assert!(desc.proto.is_none());
assert!(!desc.flags.is_acquire);
assert!(!desc.flags.is_release);
assert!(desc.params.is_empty());
assert!(desc.ret_btf_id.is_none());
assert_eq!(desc.ret_type, KfuncRetType::Void);
assert!(desc.allowed_prog_types.is_empty());
}

#[test]
fn test_kfunc_param_desc_default() {
let param = KfuncParamDesc::default();

assert!(param.name.is_none());
assert_eq!(param.arg_type, KfuncArgType::Any);
assert!(param.btf_id.is_none());
assert!(!param.nullable);
assert!(!param.is_release);
assert!(!param.is_acquire_out);
}
