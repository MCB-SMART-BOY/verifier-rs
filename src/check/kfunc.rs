//! Kernel function (kfunc) support
//!
//! This module implements verification for kernel functions that can be
//! called from BPF programs. Unlike helpers, kfuncs are defined in kernel
//! modules and have BTF-based type information.

#![allow(missing_docs)] // Kfunc internals

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap as HashMap};

use crate::core::types::*;
use crate::btf::btf::BtfFuncProto;
use crate::state::verifier_state::BpfVerifierState;
use crate::state::reference::ReferenceManager;
use crate::core::error::{Result, VerifierError};
use crate::check::sleepable::check_kfunc_sleepable_compat;

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Maximum number of kfunc descriptors
pub const MAX_KFUNC_DESCS: usize = 256;

/// Maximum number of kfunc BTFs
pub const MAX_KFUNC_BTFS: usize = 256;

/// Kfunc flags
#[derive(Debug, Clone, Copy, Default)]
pub struct KfuncFlags {
    /// Function acquires a reference
    pub is_acquire: bool,
    /// Function releases a reference
    pub is_release: bool,
    /// Function requires trusted arguments
    pub trusted_args: bool,
    /// Function may sleep
    pub sleepable: bool,
    /// Function is destructive
    pub destructive: bool,
    /// Function uses RCU
    pub rcu: bool,
    /// Function is RCU protected
    pub rcu_protected: bool,
    /// Function returns NULL on failure
    pub ret_null: bool,
}

/// Kfunc parameter descriptor
#[derive(Debug, Clone)]
pub struct KfuncParamDesc {
    /// Parameter name
    pub name: Option<String>,
    /// Expected argument type
    pub arg_type: KfuncArgType,
    /// BTF type ID (for typed pointers)
    pub btf_id: Option<u32>,
    /// Whether argument is nullable
    pub nullable: bool,
    /// Whether this is a release argument
    pub is_release: bool,
    /// Whether this is an acquire return through out-param
    pub is_acquire_out: bool,
}

impl Default for KfuncParamDesc {
    fn default() -> Self {
        Self {
            name: None,
            arg_type: KfuncArgType::Any,
            btf_id: None,
            nullable: false,
            is_release: false,
            is_acquire_out: false,
        }
    }
}

/// Kfunc descriptor
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct KfuncDesc {
    /// BTF ID of the function
    pub btf_id: u32,
    /// Function name
    pub name: String,
    /// Function prototype
    pub proto: Option<BtfFuncProto>,
    /// Kfunc flags
    pub flags: KfuncFlags,
    /// Immediate value (for patching)
    pub imm: i32,
    /// Offset
    pub off: i16,
    /// Parameter descriptors (for enhanced validation)
    pub params: Vec<KfuncParamDesc>,
    /// Return type BTF ID
    pub ret_btf_id: Option<u32>,
    /// Return type kind
    pub ret_type: KfuncRetType,
    /// Allowed program types (empty = all allowed)
    pub allowed_prog_types: Vec<BpfProgType>,
}

impl KfuncDesc {
    /// Check if this kfunc is allowed for the given program type
    pub fn is_allowed_for_prog_type(&self, prog_type: BpfProgType) -> bool {
        // Empty list means all program types are allowed
        if self.allowed_prog_types.is_empty() {
            return true;
        }
        self.allowed_prog_types.contains(&prog_type)
    }
}

/// Kfunc return type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KfuncRetType {
    /// Returns void
    #[default]
    Void,
    /// Returns a scalar integer
    Scalar,
    /// Returns a pointer (possibly NULL)
    Ptr,
    /// Returns a pointer to BTF object
    PtrToBtfId,
    /// Returns an acquired reference
    AcquiredPtr,
}


/// Kfunc registry
#[derive(Debug, Default)]
pub struct KfuncRegistry {
    /// Kfunc descriptors by BTF ID
    descs: HashMap<u32, KfuncDesc>,
    /// Registered kfunc names
    names: HashMap<String, u32>,
}

impl KfuncRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a kfunc
    pub fn register(&mut self, desc: KfuncDesc) -> Result<()> {
        if self.descs.len() >= MAX_KFUNC_DESCS {
            return Err(VerifierError::ResourceLimitExceeded(
                "too many kfuncs".into()
            ));
        }

        let btf_id = desc.btf_id;
        let name = desc.name.clone();
        
        self.names.insert(name, btf_id);
        self.descs.insert(btf_id, desc);
        
        Ok(())
    }

    /// Find kfunc by BTF ID
    pub fn find_by_id(&self, btf_id: u32) -> Option<&KfuncDesc> {
        self.descs.get(&btf_id)
    }

    /// Find kfunc by name
    pub fn find_by_name(&self, name: &str) -> Option<&KfuncDesc> {
        self.names.get(name)
            .and_then(|id| self.descs.get(id))
    }

    /// Check if kfunc exists
    pub fn contains(&self, btf_id: u32) -> bool {
        self.descs.contains_key(&btf_id)
    }

    /// Find kfunc by BTF ID, checking program type compatibility
    pub fn find_by_id_for_prog(&self, btf_id: u32, prog_type: BpfProgType) -> Option<&KfuncDesc> {
        self.descs.get(&btf_id).filter(|desc| desc.is_allowed_for_prog_type(prog_type))
    }

    /// Find kfunc by name, checking program type compatibility
    pub fn find_by_name_for_prog(&self, name: &str, prog_type: BpfProgType) -> Option<&KfuncDesc> {
        self.names.get(name)
            .and_then(|id| self.descs.get(id))
            .filter(|desc| desc.is_allowed_for_prog_type(prog_type))
    }

    /// Get all kfuncs allowed for a program type
    pub fn get_allowed_for_prog(&self, prog_type: BpfProgType) -> Vec<&KfuncDesc> {
        self.descs.values()
            .filter(|desc| desc.is_allowed_for_prog_type(prog_type))
            .collect()
    }

    /// Register common kfuncs
    pub fn register_common(&mut self) {
        // bpf_rcu_read_lock - no params, no return
        self.register(KfuncDesc {
            btf_id: 1,
            name: "bpf_rcu_read_lock".into(),
            flags: KfuncFlags::default(),
            ret_type: KfuncRetType::Void,
            ..Default::default()
        }).ok();

        // bpf_rcu_read_unlock - no params, no return
        self.register(KfuncDesc {
            btf_id: 2,
            name: "bpf_rcu_read_unlock".into(),
            flags: KfuncFlags::default(),
            ret_type: KfuncRetType::Void,
            ..Default::default()
        }).ok();

        // bpf_obj_new_impl(u64 local_type_id, u64 meta) -> void*
        self.register(KfuncDesc {
            btf_id: 3,
            name: "bpf_obj_new_impl".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            params: vec![
                KfuncParamDesc {
                    name: Some("local_type_id".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
                KfuncParamDesc {
                    name: Some("meta".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
            ],
            ret_type: KfuncRetType::AcquiredPtr,
            ..Default::default()
        }).ok();

        // bpf_obj_drop_impl(void *p, void *meta) -> void
        self.register(KfuncDesc {
            btf_id: 4,
            name: "bpf_obj_drop_impl".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            params: vec![
                KfuncParamDesc {
                    name: Some("p".into()),
                    arg_type: KfuncArgType::PtrToAlloc,
                    is_release: true,
                    ..Default::default()
                },
                KfuncParamDesc {
                    name: Some("meta".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
            ],
            ret_type: KfuncRetType::Void,
            ..Default::default()
        }).ok();

        // bpf_list_push_front
        self.register(KfuncDesc {
            btf_id: 5,
            name: "bpf_list_push_front_impl".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_list_push_back
        self.register(KfuncDesc {
            btf_id: 6,
            name: "bpf_list_push_back_impl".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_list_pop_front
        self.register(KfuncDesc {
            btf_id: 7,
            name: "bpf_list_pop_front".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_list_pop_back
        self.register(KfuncDesc {
            btf_id: 8,
            name: "bpf_list_pop_back".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_spin_lock
        self.register(KfuncDesc {
            btf_id: 9,
            name: "bpf_res_spin_lock".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_spin_unlock
        self.register(KfuncDesc {
            btf_id: 10,
            name: "bpf_res_spin_unlock".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_refcount_acquire
        self.register(KfuncDesc {
            btf_id: 11,
            name: "bpf_refcount_acquire_impl".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_task_acquire
        self.register(KfuncDesc {
            btf_id: 12,
            name: "bpf_task_acquire".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                trusted_args: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_task_release
        self.register(KfuncDesc {
            btf_id: 13,
            name: "bpf_task_release".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_cgroup_acquire
        self.register(KfuncDesc {
            btf_id: 14,
            name: "bpf_cgroup_acquire".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                trusted_args: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_cgroup_release
        self.register(KfuncDesc {
            btf_id: 15,
            name: "bpf_cgroup_release".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_rbtree_add
        self.register(KfuncDesc {
            btf_id: 16,
            name: "bpf_rbtree_add_impl".into(),
            flags: KfuncFlags {
                is_release: true,  // node is released to tree
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_rbtree_remove
        self.register(KfuncDesc {
            btf_id: 17,
            name: "bpf_rbtree_remove".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_rbtree_first
        self.register(KfuncDesc {
            btf_id: 18,
            name: "bpf_rbtree_first".into(),
            flags: KfuncFlags {
                ret_null: true,
                rcu: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_cpumask_create
        self.register(KfuncDesc {
            btf_id: 19,
            name: "bpf_cpumask_create".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_cpumask_release
        self.register(KfuncDesc {
            btf_id: 20,
            name: "bpf_cpumask_release".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_cpumask_set_cpu
        self.register(KfuncDesc {
            btf_id: 21,
            name: "bpf_cpumask_set_cpu".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_cpumask_clear_cpu
        self.register(KfuncDesc {
            btf_id: 22,
            name: "bpf_cpumask_clear_cpu".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_cpumask_test_cpu
        self.register(KfuncDesc {
            btf_id: 23,
            name: "bpf_cpumask_test_cpu".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_kptr_xchg
        self.register(KfuncDesc {
            btf_id: 24,
            name: "bpf_kptr_xchg".into(),
            flags: KfuncFlags {
                is_acquire: true,
                is_release: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_dynptr_from_skb
        self.register(KfuncDesc {
            btf_id: 25,
            name: "bpf_dynptr_from_skb".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_dynptr_from_xdp
        self.register(KfuncDesc {
            btf_id: 26,
            name: "bpf_dynptr_from_xdp".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_dynptr_slice
        self.register(KfuncDesc {
            btf_id: 27,
            name: "bpf_dynptr_slice".into(),
            flags: KfuncFlags {
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_dynptr_slice_rdwr
        self.register(KfuncDesc {
            btf_id: 28,
            name: "bpf_dynptr_slice_rdwr".into(),
            flags: KfuncFlags {
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_iter_num_new
        self.register(KfuncDesc {
            btf_id: 29,
            name: "bpf_iter_num_new".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_iter_num_next
        self.register(KfuncDesc {
            btf_id: 30,
            name: "bpf_iter_num_next".into(),
            flags: KfuncFlags {
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_iter_num_destroy
        self.register(KfuncDesc {
            btf_id: 31,
            name: "bpf_iter_num_destroy".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_throw
        self.register(KfuncDesc {
            btf_id: 32,
            name: "bpf_throw".into(),
            flags: KfuncFlags {
                destructive: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_wq_init
        self.register(KfuncDesc {
            btf_id: 33,
            name: "bpf_wq_init".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_wq_set_callback_impl
        self.register(KfuncDesc {
            btf_id: 34,
            name: "bpf_wq_set_callback_impl".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_wq_start
        self.register(KfuncDesc {
            btf_id: 35,
            name: "bpf_wq_start".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_preempt_disable
        self.register(KfuncDesc {
            btf_id: 36,
            name: "bpf_preempt_disable".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_preempt_enable
        self.register(KfuncDesc {
            btf_id: 37,
            name: "bpf_preempt_enable".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_task_from_pid
        self.register(KfuncDesc {
            btf_id: 38,
            name: "bpf_task_from_pid".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_sock_from_file
        self.register(KfuncDesc {
            btf_id: 39,
            name: "bpf_sock_from_file".into(),
            flags: KfuncFlags {
                ret_null: true,
                ..Default::default()
            },
            ..Default::default()
        }).ok();

        // bpf_get_file_xattr
        self.register(KfuncDesc {
            btf_id: 40,
            name: "bpf_get_file_xattr".into(),
            flags: KfuncFlags::default(),
            ..Default::default()
        }).ok();

        // bpf_percpu_obj_new_impl(u64 local_type_id, u64 meta) -> void*
        // Similar to bpf_obj_new but allocates per-CPU memory
        // Max size is BPF_GLOBAL_PERCPU_MA_MAX_SIZE (512 bytes)
        // Only supports scalar structs (no special fields)
        self.register(KfuncDesc {
            btf_id: 41,
            name: "bpf_percpu_obj_new_impl".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ret_null: true,
                ..Default::default()
            },
            params: vec![
                KfuncParamDesc {
                    name: Some("local_type_id".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
                KfuncParamDesc {
                    name: Some("meta".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
            ],
            ret_type: KfuncRetType::AcquiredPtr,
            ..Default::default()
        }).ok();

        // bpf_percpu_obj_drop_impl(void *p, void *meta) -> void
        // Releases per-CPU allocated memory
        self.register(KfuncDesc {
            btf_id: 42,
            name: "bpf_percpu_obj_drop_impl".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            params: vec![
                KfuncParamDesc {
                    name: Some("p".into()),
                    arg_type: KfuncArgType::PtrToAlloc,
                    is_release: true,
                    ..Default::default()
                },
                KfuncParamDesc {
                    name: Some("meta".into()),
                    arg_type: KfuncArgType::Scalar,
                    ..Default::default()
                },
            ],
            ret_type: KfuncRetType::Void,
            ..Default::default()
        }).ok();
    }
}

/// Kfunc call argument metadata
#[derive(Debug, Clone, Default)]
pub struct KfuncCallMeta {
    /// BTF of the kfunc
    pub btf_id: u32,
    /// Function name
    pub func_name: String,
    /// Flags
    pub flags: KfuncFlags,
    /// Reference object ID (for acquire/release)
    pub ref_obj_id: u32,
    /// Return BTF ID
    pub ret_btf_id: u32,
    /// Whether return is nullable
    pub ret_nullable: bool,
}

/// Check a kfunc call
pub fn check_kfunc_call(
    state: &mut BpfVerifierState,
    registry: &KfuncRegistry,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<KfuncCallMeta> {
    // Get kfunc descriptor
    let btf_id = insn.imm as u32;
    let desc = registry.find_by_id(btf_id)
        .ok_or_else(|| VerifierError::InvalidKfunc(
            format!("unknown kfunc btf_id {}", btf_id)
        ))?;

    let mut meta = KfuncCallMeta {
        btf_id,
        func_name: desc.name.clone(),
        flags: desc.flags,
        ..Default::default()
    };

    // Check sleepable context compatibility
    // Sleepable kfuncs can only be called from sleepable programs
    // and when not in atomic context (no locks, RCU, preempt disabled)
    check_kfunc_sleepable_compat(state, &state.refs, &desc.name, desc.flags.sleepable)?;

    // Check arguments (use state.refs directly)
    check_kfunc_args(state, desc, &mut meta)?;

    // Special validation for bpf_percpu_obj_new_impl
    if desc.name == "bpf_percpu_obj_new_impl" {
        check_percpu_obj_new_constraints(state, &meta)?;
    }

    // Handle acquire functions
    if desc.flags.is_acquire {
        meta.ref_obj_id = state.refs.acquire_ptr(insn_idx);
    }

    // Clear caller-saved registers
    for regno in 0..=5 {
        if let Some(reg) = state.reg_mut(regno) {
            reg.mark_not_init(false);
        }
    }

    // Set return value
    set_kfunc_return(state, desc, &meta)?;

    Ok(meta)
}

/// Expected kfunc argument type
/// 
/// Maps to kernel's enum kfunc_ptr_arg_type (KF_ARG_PTR_TO_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgType {
    /// Any pointer type
    AnyPtr,
    /// Pointer to scalar (for output params)
    PtrToScalar,
    /// Pointer to memory with BTF type info (KF_ARG_PTR_TO_BTF_ID)
    PtrToBtfId,
    /// Pointer to allocated object (KF_ARG_PTR_TO_ALLOC_BTF_ID)
    PtrToAlloc,
    /// Pointer to refcounted kptr (KF_ARG_PTR_TO_REFCOUNTED_KPTR)
    PtrToRefcountedKptr,
    /// Pointer to dynptr (KF_ARG_PTR_TO_DYNPTR)
    PtrToDynptr,
    /// Pointer to iterator (KF_ARG_PTR_TO_ITER)
    PtrToIter,
    /// Pointer to list head (KF_ARG_PTR_TO_LIST_HEAD)
    PtrToListHead,
    /// Pointer to list node (KF_ARG_PTR_TO_LIST_NODE)
    PtrToListNode,
    /// Pointer to rbtree root (KF_ARG_PTR_TO_RB_ROOT)
    PtrToRbRoot,
    /// Pointer to rbtree node (KF_ARG_PTR_TO_RB_NODE)
    PtrToRbNode,
    /// Pointer to context (KF_ARG_PTR_TO_CTX)
    PtrToCtx,
    /// Pointer to memory region (KF_ARG_PTR_TO_MEM)
    PtrToMem,
    /// Pointer to memory with size from next arg (KF_ARG_PTR_TO_MEM_SIZE)
    PtrToMemSize,
    /// Pointer to callback function (KF_ARG_PTR_TO_CALLBACK)
    PtrToCallback,
    /// Pointer to map (KF_ARG_PTR_TO_MAP)
    PtrToMap,
    /// Pointer to workqueue (KF_ARG_PTR_TO_WORKQUEUE)
    PtrToWorkqueue,
    /// Pointer to const string (KF_ARG_PTR_TO_CONST_STR)
    PtrToConstStr,
    /// Pointer to IRQ flag (KF_ARG_PTR_TO_IRQ_FLAG)
    PtrToIrqFlag,
    /// Pointer to resilient spin lock (KF_ARG_PTR_TO_RES_SPIN_LOCK)
    PtrToResSpinLock,
    /// Pointer to task work (KF_ARG_PTR_TO_TASK_WORK)
    PtrToTaskWork,
    /// Pointer to null (KF_ARG_PTR_TO_NULL) - for nullable args with null value
    PtrToNull,
    /// Scalar value (integer)
    Scalar,
    /// Any type (no checking)
    Any,
}

/// Kfunc argument descriptor
#[derive(Debug, Clone)]
pub struct KfuncArgDesc {
    /// Expected type
    pub arg_type: KfuncArgType,
    /// BTF ID for typed pointers
    pub btf_id: Option<u32>,
    /// Whether argument is nullable
    pub nullable: bool,
    /// Whether argument is release
    pub is_release: bool,
    /// Whether argument is owned (transferred)
    pub is_owned: bool,
}

impl Default for KfuncArgDesc {
    fn default() -> Self {
        Self {
            arg_type: KfuncArgType::Any,
            btf_id: None,
            nullable: false,
            is_release: false,
            is_owned: false,
        }
    }
}

/// Check kfunc arguments
fn check_kfunc_args(
    state: &BpfVerifierState,
    desc: &KfuncDesc,
    meta: &mut KfuncCallMeta,
) -> Result<()> {
    // If we have explicit parameter descriptors, use those for validation
    if !desc.params.is_empty() {
        return check_kfunc_args_with_params(state, desc, meta);
    }
    
    // Fall back to BTF prototype if available
    let proto = match &desc.proto {
        Some(p) => p,
        None => {
            // No prototype - just check registers are initialized
            for i in 1..=5 {
                let _reg = state.reg(i)
                    .ok_or(VerifierError::InvalidRegister(i as u8))?;
                // R1-R5 should be initialized or explicitly unused
            }
            return Ok(());
        }
    };

    // Check each parameter
    for (i, (name, _type_id)) in proto.params.iter().enumerate() {
        let regno = i + 1;
        if regno > 5 {
            break;
        }

        let reg = state.reg(regno)
            .ok_or(VerifierError::InvalidRegister(regno as u8))?;

        if reg.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(regno as u8));
        }

        // Check for trusted args requirement
        if desc.flags.trusted_args {
            check_trusted_arg(reg, name.as_deref(), i)?;
        }

        // Check for release args
        if is_release_arg(desc, i) {
            check_release_arg(reg, &state.refs, meta)?;
        }
    }

    Ok(())
}

/// Check kfunc arguments using parameter descriptors
fn check_kfunc_args_with_params(
    state: &BpfVerifierState,
    desc: &KfuncDesc,
    meta: &mut KfuncCallMeta,
) -> Result<()> {
    for (i, param) in desc.params.iter().enumerate() {
        let regno = i + 1;
        if regno > 5 {
            break;
        }

        let reg = state.reg(regno)
            .ok_or(VerifierError::InvalidRegister(regno as u8))?;

        // Check register is initialized
        if reg.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(regno as u8));
        }

        // Validate argument type
        validate_kfunc_arg_type(reg, param, &desc.name, i)?;

        // Check for trusted args requirement
        if desc.flags.trusted_args {
            check_trusted_arg(reg, param.name.as_deref(), i)?;
        }

        // Check for release args
        if param.is_release {
            check_release_arg(reg, &state.refs, meta)?;
        }
    }

    Ok(())
}

/// Validate a kfunc argument matches expected type
fn validate_kfunc_arg_type(
    reg: &crate::state::reg_state::BpfRegState,
    param: &KfuncParamDesc,
    func_name: &str,
    arg_idx: usize,
) -> Result<()> {
    let param_name = param.name.as_deref().unwrap_or("?");
    
    match param.arg_type {
        KfuncArgType::Scalar => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("scalar for kfunc '{}' arg {} ({})", 
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::AnyPtr => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToBtfId => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("BTF pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would additionally verify BTF type ID matches
            if let Some(expected_btf_id) = param.btf_id {
                if reg.btf_id() != expected_btf_id && reg.btf_id() != 0 {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!("BTF type {} for kfunc '{}' arg {} ({})",
                            expected_btf_id, func_name, arg_idx, param_name),
                        got: format!("BTF type {}", reg.btf_id()),
                    });
                }
            }
        }
        KfuncArgType::PtrToAlloc => {
            // Must be a pointer to allocated memory (acquired reference)
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("allocated pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // For release args, must have ref_obj_id
            if param.is_release && reg.ref_obj_id == 0 {
                return Err(VerifierError::InvalidPointer(format!(
                    "kfunc '{}' arg {} ({}) must be an acquired reference",
                    func_name, arg_idx, param_name
                )));
            }
        }
        KfuncArgType::PtrToDynptr => {
            // Must be pointer to stack (dynptrs live on stack)
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("stack pointer (dynptr) for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToRefcountedKptr => {
            // Pointer to refcounted local kptr
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("refcounted kptr for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Must have reference tracking
            if reg.ref_obj_id == 0 {
                return Err(VerifierError::InvalidPointer(format!(
                    "kfunc '{}' arg {} ({}) requires refcounted kptr with reference",
                    func_name, arg_idx, param_name
                )));
            }
        }
        KfuncArgType::PtrToIter => {
            // Pointer to iterator on stack
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("iterator pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would additionally verify iterator state on stack
        }
        KfuncArgType::PtrToListHead | KfuncArgType::PtrToListNode => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("list pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would check BTF type is bpf_list_head or bpf_list_node
        }
        KfuncArgType::PtrToRbRoot | KfuncArgType::PtrToRbNode => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("rbtree pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would check BTF type is bpf_rb_root or bpf_rb_node
        }
        KfuncArgType::PtrToCtx => {
            // Must be context pointer
            if reg.reg_type != BpfRegType::PtrToCtx {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("context pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToMem | KfuncArgType::PtrToMemSize => {
            // Pointer to readable/writable memory
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("memory pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // For PtrToMemSize, the next argument provides the size
        }
        KfuncArgType::PtrToCallback => {
            // Callback function - typically a scalar value representing subprog index
            // or could be a pointer to BTF ID for BPF-to-BPF calls
            match reg.reg_type {
                BpfRegType::ScalarValue | BpfRegType::PtrToBtfId => {
                    // Valid callback representations
                }
                _ => {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!("callback for kfunc '{}' arg {} ({})",
                            func_name, arg_idx, param_name),
                        got: format!("{:?}", reg.reg_type),
                    });
                }
            }
        }
        KfuncArgType::PtrToMap => {
            // Pointer to map
            if reg.reg_type != BpfRegType::ConstPtrToMap {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("map pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToWorkqueue => {
            // Pointer to workqueue embedded in map value
            // Kernel: process_wq_func() validates this
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("map value pointer for workqueue kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Validate the pointer points to a bpf_wq field in the map value
            // This requires checking the BTF type at reg.off within the map's value_type
            if let Some(ref map_info) = reg.map_ptr {
                let field_offset = reg.off as u32;
                // Verify offset is within bounds and aligned
                if field_offset >= map_info.value_size {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "workqueue field offset {} exceeds map value size {}",
                        field_offset, map_info.value_size
                    )));
                }
                // In full implementation, would check BTF to verify bpf_wq type at offset
                // The map_uid is available via reg.map_uid for callers that need it
            }
        }
        KfuncArgType::PtrToConstStr => {
            // Pointer to constant string (map value or rodata)
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("const string pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Typically PTR_TO_MAP_VALUE pointing to rodata section
        }
        KfuncArgType::PtrToIrqFlag => {
            // Pointer to IRQ flag on stack
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("IRQ flag pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToResSpinLock => {
            // Pointer to resilient spin lock
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("res_spin_lock pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would verify BTF type is bpf_res_spin_lock
        }
        KfuncArgType::PtrToTaskWork => {
            // Pointer to task_work embedded in map value
            // Kernel: process_task_work_func() validates this
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("map value pointer for task_work kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Validate the pointer points to a bpf_task_work field in the map value
            if let Some(ref map_info) = reg.map_ptr {
                let field_offset = reg.off as u32;
                // Verify offset is within bounds
                if field_offset >= map_info.value_size {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "task_work field offset {} exceeds map value size {}",
                        field_offset, map_info.value_size
                    )));
                }
                // In full implementation, would check BTF to verify bpf_task_work type at offset
                // The map_uid is available via reg.map_uid for callers that need it
            }
        }
        KfuncArgType::PtrToNull => {
            // Null pointer for nullable arguments
            if !reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) 
                && reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("null pointer for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToScalar => {
            // Output parameter - must be writable pointer
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("pointer (out param) for kfunc '{}' arg {} ({})",
                        func_name, arg_idx, param_name),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::Any => {
            // No type checking required
        }
    }

    // Check nullable
    if !param.nullable && reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
        return Err(VerifierError::InvalidPointer(format!(
            "kfunc '{}' arg {} ({}) cannot be nullable",
            func_name, arg_idx, param_name
        )));
    }

    Ok(())
}

/// Check if argument requires trusted pointer
fn check_trusted_arg(
    reg: &crate::state::reg_state::BpfRegState,
    name: Option<&str>,
    _arg_idx: usize,
) -> Result<()> {
    // Check if pointer is trusted (not maybe-null, not untrusted)
    if reg.is_ptr() {
        if reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            return Err(VerifierError::InvalidPointer(format!(
                "arg '{}' must be trusted, but got maybe-null pointer",
                name.unwrap_or("?")
            )));
        }
        if reg.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
            return Err(VerifierError::InvalidPointer(format!(
                "arg '{}' must be trusted, but got untrusted pointer",
                name.unwrap_or("?")
            )));
        }
    }
    Ok(())
}

/// Check if argument index is a release argument for this kfunc
fn is_release_arg(desc: &KfuncDesc, arg_idx: usize) -> bool {
    // First argument of release kfuncs is typically the release arg
    desc.flags.is_release && arg_idx == 0
}

/// Check release argument
fn check_release_arg(
    reg: &crate::state::reg_state::BpfRegState,
    refs: &ReferenceManager,
    meta: &mut KfuncCallMeta,
) -> Result<()> {
    // Must have a reference ID
    if reg.ref_obj_id == 0 {
        return Err(VerifierError::InvalidPointer(
            "release arg must have reference".into()
        ));
    }

    // Check reference exists
    if !refs.has_ref(reg.ref_obj_id) {
        return Err(VerifierError::InvalidPointer(
            "release arg references non-existent object".into()
        ));
    }

    meta.ref_obj_id = reg.ref_obj_id;
    Ok(())
}

/// Validate kfunc argument type against BTF
pub fn check_kfunc_arg_btf_type(
    reg: &crate::state::reg_state::BpfRegState,
    expected: &KfuncArgDesc,
    btf: &crate::btf::btf::Btf,
) -> Result<()> {
    match expected.arg_type {
        KfuncArgType::Scalar => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "scalar value".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::AnyPtr => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToBtfId => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "BTF pointer".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Would check reg.btf_id against expected.btf_id
            if let Some(expected_btf_id) = expected.btf_id {
                if reg.btf_id() != expected_btf_id {
                    // Check if types are compatible
                    if !btf_types_compatible(btf, reg.btf_id(), expected_btf_id) {
                        return Err(VerifierError::TypeMismatch {
                            expected: format!("BTF type {}", expected_btf_id),
                            got: format!("BTF type {}", reg.btf_id()),
                        });
                    }
                }
            }
        }
        KfuncArgType::PtrToAlloc => {
            if reg.reg_type != BpfRegType::PtrToMem {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to allocated memory".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToDynptr => {
            match reg.reg_type {
                BpfRegType::PtrToStack => {
                    // Dynptrs are stored on stack
                }
                _ => {
                    return Err(VerifierError::TypeMismatch {
                        expected: "pointer to dynptr on stack".into(),
                        got: format!("{:?}", reg.reg_type),
                    });
                }
            }
        }
        KfuncArgType::PtrToRefcountedKptr => {
            if !reg.is_ptr() || reg.ref_obj_id == 0 {
                return Err(VerifierError::TypeMismatch {
                    expected: "refcounted kptr".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToIter => {
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to iterator on stack".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToListHead | KfuncArgType::PtrToListNode |
        KfuncArgType::PtrToRbRoot | KfuncArgType::PtrToRbNode => {
            // Would need specific type checking
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to graph data structure".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToCtx => {
            if reg.reg_type != BpfRegType::PtrToCtx {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to context".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToMem | KfuncArgType::PtrToMemSize => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to memory".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToCallback => {
            match reg.reg_type {
                BpfRegType::ScalarValue | BpfRegType::PtrToBtfId => {
                    // Valid callback representations
                }
                _ => {
                    return Err(VerifierError::TypeMismatch {
                        expected: "callback function".into(),
                        got: format!("{:?}", reg.reg_type),
                    });
                }
            }
        }
        KfuncArgType::PtrToMap => {
            if reg.reg_type != BpfRegType::ConstPtrToMap {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to map".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToWorkqueue | KfuncArgType::PtrToTaskWork | 
        KfuncArgType::PtrToResSpinLock => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to kernel object".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToConstStr => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to const string".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToIrqFlag => {
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to IRQ flag on stack".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::PtrToNull => {
            // This is for nullable args that are actually null
            // Accept scalar 0 or maybe-null pointer
        }
        KfuncArgType::PtrToScalar => {
            if !reg.is_ptr() {
                return Err(VerifierError::TypeMismatch {
                    expected: "pointer to scalar output".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        KfuncArgType::Any => {
            // No type checking required
        }
    }

    // Check nullable
    if !expected.nullable && reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
        return Err(VerifierError::InvalidPointer(
            "argument cannot be nullable".into()
        ));
    }

    Ok(())
}

/// Check if two BTF types are compatible
fn btf_types_compatible(btf: &crate::btf::btf::Btf, got: u32, expected: u32) -> bool {
    if got == expected {
        return true;
    }

    // Resolve both types through modifiers
    let got_ty = btf.resolve_type(got);
    let expected_ty = btf.resolve_type(expected);

    match (got_ty, expected_ty) {
        (Some(g), Some(e)) => {
            // Same kind and same size is often compatible
            g.kind == e.kind && g.size == e.size
        }
        _ => false,
    }
}

/// Set kfunc return value
fn set_kfunc_return(
    state: &mut BpfVerifierState,
    desc: &KfuncDesc,
    meta: &KfuncCallMeta,
) -> Result<()> {
    let r0 = state.reg_mut(BPF_REG_0)
        .ok_or(VerifierError::Internal("no R0".into()))?;

    // Use explicit return type if available
    match desc.ret_type {
        KfuncRetType::Void => {
            // No return value - mark R0 as not init (caller shouldn't use it)
            r0.mark_not_init(false);
        }
        KfuncRetType::Scalar => {
            r0.mark_unknown(false);
            r0.reg_type = BpfRegType::ScalarValue;
        }
        KfuncRetType::Ptr => {
            r0.reg_type = BpfRegType::PtrToMem;
            r0.mark_known_zero();
            if desc.flags.ret_null {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            }
        }
        KfuncRetType::PtrToBtfId => {
            r0.reg_type = BpfRegType::PtrToMem;
            r0.mark_known_zero();
            if let Some(btf_id) = desc.ret_btf_id {
                r0.set_btf_id(btf_id);
            }
            if desc.flags.ret_null {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            }
        }
        KfuncRetType::AcquiredPtr => {
            r0.reg_type = BpfRegType::PtrToMem;
            r0.mark_known_zero();
            r0.ref_obj_id = meta.ref_obj_id;
            r0.id = meta.ref_obj_id;
            if let Some(btf_id) = desc.ret_btf_id {
                r0.set_btf_id(btf_id);
            }
            if desc.flags.ret_null {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            }
        }
    }

    // Legacy path: if ret_type is default (Void) but flags indicate acquire
    if desc.ret_type == KfuncRetType::Void && desc.flags.is_acquire {
        r0.reg_type = BpfRegType::PtrToMem;
        if desc.flags.ret_null {
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        }
        r0.ref_obj_id = meta.ref_obj_id;
        r0.id = meta.ref_obj_id;
        r0.mark_known_zero();
    }

    Ok(())
}

/// Check if instruction is a kfunc call
pub fn is_kfunc_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && 
    insn.src_reg == BPF_PSEUDO_KFUNC_CALL
}

/// Special kfunc IDs for well-known functions
#[allow(missing_docs)]
pub mod special_kfuncs {
    pub const BPF_RCU_READ_LOCK: u32 = 1;
    pub const BPF_RCU_READ_UNLOCK: u32 = 2;
    pub const BPF_OBJ_NEW: u32 = 3;
    pub const BPF_OBJ_DROP: u32 = 4;
    pub const BPF_LIST_PUSH_FRONT: u32 = 5;
    pub const BPF_LIST_PUSH_BACK: u32 = 6;
    pub const BPF_LIST_POP_FRONT: u32 = 7;
    pub const BPF_LIST_POP_BACK: u32 = 8;
    pub const BPF_RES_SPIN_LOCK: u32 = 9;
    pub const BPF_RES_SPIN_UNLOCK: u32 = 10;
    pub const BPF_PREEMPT_DISABLE: u32 = 11;
    pub const BPF_PREEMPT_ENABLE: u32 = 12;
    pub const BPF_THROW: u32 = 13;
    pub const BPF_ITER_NUM_NEW: u32 = 14;
    pub const BPF_ITER_NUM_NEXT: u32 = 15;
    pub const BPF_ITER_NUM_DESTROY: u32 = 16;
    pub const BPF_RBTREE_ADD: u32 = 17;
    pub const BPF_RBTREE_REMOVE: u32 = 18;
    pub const BPF_RBTREE_FIRST: u32 = 19;
    pub const BPF_WQ_SET_CALLBACK: u32 = 20;
    pub const BPF_TASK_WORK_ADD: u32 = 21;
    // IRQ-related kfuncs
    pub const BPF_LOCAL_IRQ_SAVE: u32 = 22;
    pub const BPF_LOCAL_IRQ_RESTORE: u32 = 23;
    pub const BPF_SPIN_LOCK_IRQSAVE: u32 = 24;
    pub const BPF_SPIN_UNLOCK_IRQRESTORE: u32 = 25;
}

/// Check if kfunc is bpf_rcu_read_lock
pub fn is_kfunc_bpf_rcu_read_lock(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_RCU_READ_LOCK
}

/// Check if kfunc is bpf_rcu_read_unlock
pub fn is_kfunc_bpf_rcu_read_unlock(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_RCU_READ_UNLOCK
}

/// Check if kfunc is bpf_preempt_disable
pub fn is_kfunc_bpf_preempt_disable(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_PREEMPT_DISABLE
}

/// Check if kfunc is bpf_preempt_enable
pub fn is_kfunc_bpf_preempt_enable(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_PREEMPT_ENABLE
}

/// Check if kfunc is bpf_throw
pub fn is_bpf_throw_kfunc(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_THROW
}

/// Check if kfunc is bpf_wq_set_callback_impl
pub fn is_bpf_wq_set_callback_impl_kfunc(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_WQ_SET_CALLBACK
}

/// Check if kfunc is task_work_add
pub fn is_task_work_add_kfunc(btf_id: u32) -> bool {
    btf_id == special_kfuncs::BPF_TASK_WORK_ADD
}

/// Check if kfunc is graph API (list/rbtree)
pub fn is_bpf_graph_api_kfunc(btf_id: u32) -> bool {
    matches!(btf_id, 
        special_kfuncs::BPF_LIST_PUSH_FRONT |
        special_kfuncs::BPF_LIST_PUSH_BACK |
        special_kfuncs::BPF_LIST_POP_FRONT |
        special_kfuncs::BPF_LIST_POP_BACK |
        special_kfuncs::BPF_RBTREE_ADD |
        special_kfuncs::BPF_RBTREE_REMOVE |
        special_kfuncs::BPF_RBTREE_FIRST
    )
}

/// Check if kfunc is list API
pub fn is_bpf_list_api_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_LIST_PUSH_FRONT |
        special_kfuncs::BPF_LIST_PUSH_BACK |
        special_kfuncs::BPF_LIST_POP_FRONT |
        special_kfuncs::BPF_LIST_POP_BACK
    )
}

/// Check if kfunc is rbtree API
pub fn is_bpf_rbtree_api_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_RBTREE_ADD |
        special_kfuncs::BPF_RBTREE_REMOVE |
        special_kfuncs::BPF_RBTREE_FIRST
    )
}

/// Check if kfunc is bpf_iter_num API
pub fn is_bpf_iter_num_api_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_ITER_NUM_NEW |
        special_kfuncs::BPF_ITER_NUM_NEXT |
        special_kfuncs::BPF_ITER_NUM_DESTROY
    )
}

/// Check if kfunc requires spin lock
pub fn kfunc_spin_allowed(btf_id: u32) -> bool {
    is_bpf_graph_api_kfunc(btf_id)
}

/// Check if kfunc is sync callback calling (runs immediately)
pub fn is_sync_callback_calling_kfunc(btf_id: u32) -> bool {
    // bpf_rbtree_add with callback, etc.
    btf_id == special_kfuncs::BPF_RBTREE_ADD
}

/// Check if kfunc is async callback calling (runs later)
pub fn is_async_callback_calling_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_WQ_SET_CALLBACK |
        special_kfuncs::BPF_TASK_WORK_ADD
    )
}

/// Check if kfunc calls a callback (sync or async)
pub fn is_callback_calling_kfunc(btf_id: u32) -> bool {
    is_sync_callback_calling_kfunc(btf_id) || is_async_callback_calling_kfunc(btf_id)
}

/// Check if kfunc requires rbtree lock
pub fn is_rbtree_lock_required_kfunc(btf_id: u32) -> bool {
    is_bpf_rbtree_api_kfunc(btf_id)
}

/// Check if kfunc is res_spin_lock API
pub fn is_bpf_res_spin_lock_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_RES_SPIN_LOCK |
        special_kfuncs::BPF_RES_SPIN_UNLOCK
    )
}

/// Check if kfunc is IRQ save operation
pub fn is_irq_save_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_LOCAL_IRQ_SAVE |
        special_kfuncs::BPF_SPIN_LOCK_IRQSAVE
    )
}

/// Check if kfunc is IRQ restore operation
pub fn is_irq_restore_kfunc(btf_id: u32) -> bool {
    matches!(btf_id,
        special_kfuncs::BPF_LOCAL_IRQ_RESTORE |
        special_kfuncs::BPF_SPIN_UNLOCK_IRQRESTORE
    )
}

/// Check if kfunc is IRQ-related
pub fn is_irq_kfunc(btf_id: u32) -> bool {
    is_irq_save_kfunc(btf_id) || is_irq_restore_kfunc(btf_id)
}

/// Get IRQ kfunc class from kfunc ID
pub fn get_irq_kfunc_class(btf_id: u32) -> Option<crate::state::lock_state::IrqKfuncClass> {
    use crate::state::lock_state::IrqKfuncClass;
    match btf_id {
        special_kfuncs::BPF_LOCAL_IRQ_SAVE => Some(IrqKfuncClass::LocalIrqSave),
        special_kfuncs::BPF_LOCAL_IRQ_RESTORE => Some(IrqKfuncClass::LocalIrqRestore),
        special_kfuncs::BPF_SPIN_LOCK_IRQSAVE => Some(IrqKfuncClass::SpinLockIrqSave),
        special_kfuncs::BPF_SPIN_UNLOCK_IRQRESTORE => Some(IrqKfuncClass::SpinUnlockIrqRestore),
        _ => None,
    }
}

/// IRQ native vs lock kfunc classification (for matching save/restore pairs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqKfuncType {
    /// bpf_local_irq_save/restore (native IRQ kfuncs)
    Native,
    /// bpf_spin_lock_irqsave/unlock_irqrestore (lock-based IRQ kfuncs)  
    Lock,
}

/// Get IRQ kfunc type (native vs lock)
pub fn get_irq_kfunc_type(btf_id: u32) -> Option<IrqKfuncType> {
    match btf_id {
        special_kfuncs::BPF_LOCAL_IRQ_SAVE |
        special_kfuncs::BPF_LOCAL_IRQ_RESTORE => Some(IrqKfuncType::Native),
        special_kfuncs::BPF_SPIN_LOCK_IRQSAVE |
        special_kfuncs::BPF_SPIN_UNLOCK_IRQRESTORE => Some(IrqKfuncType::Lock),
        _ => None,
    }
}

/// Process IRQ flag argument for kfunc calls
/// 
/// This handles:
/// - bpf_local_irq_save: marks stack slot as IRQ flag, disables interrupts
/// - bpf_local_irq_restore: validates and clears IRQ flag, restores interrupts
/// - bpf_spin_lock_irqsave: marks stack slot, acquires lock with IRQ disabled
/// - bpf_spin_unlock_irqrestore: validates and clears, releases lock and restores IRQ
pub fn process_irq_flag(
    state: &mut BpfVerifierState,
    irq_state: &mut crate::state::lock_state::IrqState,
    regno: usize,
    btf_id: u32,
    insn_idx: usize,
) -> Result<()> {
    use crate::state::lock_state::{IrqKfuncClass, mark_stack_slot_irq_flag, unmark_stack_slot_irq_flag};
    
    let reg = state.reg(regno)
        .ok_or(VerifierError::InvalidRegister(regno as u8))?;
    
    // IRQ flag must be on stack
    if reg.reg_type != BpfRegType::PtrToStack {
        return Err(VerifierError::InvalidPointer(format!(
            "IRQ flag argument must be pointer to stack, got {:?}",
            reg.reg_type
        )));
    }
    
    // Calculate stack slot index
    let off = reg.off;
    if off >= 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "IRQ flag must be at negative stack offset".into()
        ));
    }
    let spi = ((-off) as usize - 1) / 8;
    
    // Determine kfunc class
    let kfunc_class = get_irq_kfunc_class(btf_id)
        .ok_or(VerifierError::InvalidKfunc(format!(
            "not an IRQ kfunc: btf_id={}",
            btf_id
        )))?;
    
    let kfunc_type = get_irq_kfunc_type(btf_id)
        .ok_or(VerifierError::InvalidKfunc("unknown IRQ kfunc type".into()))?;
    
    match kfunc_class {
        IrqKfuncClass::LocalIrqSave | IrqKfuncClass::SpinLockIrqSave => {
            // Saving IRQ state - mark stack slot
            
            // Validate stack slot is available (not already an IRQ flag)
            if let Some(existing) = irq_state.get_irq_flag(reg.ref_obj_id) {
                return Err(VerifierError::InvalidLock(format!(
                    "stack slot already contains IRQ flag (saved at insn {})",
                    existing.acquired_at
                )));
            }
            
            // Mark stack slot as IRQ flag
            let ref_id = mark_stack_slot_irq_flag(irq_state, insn_idx, spi, kfunc_class)?;
            
            // Update register to track the IRQ flag reference
            if let Some(reg_mut) = state.reg_mut(regno) {
                reg_mut.ref_obj_id = ref_id;
            }
        }
        
        IrqKfuncClass::LocalIrqRestore | IrqKfuncClass::SpinUnlockIrqRestore => {
            // Restoring IRQ state - validate and clear
            
            let ref_obj_id = reg.ref_obj_id;
            if ref_obj_id == 0 {
                return Err(VerifierError::InvalidLock(
                    "IRQ restore without matching save".into()
                ));
            }
            
            // Verify the IRQ flag exists and matches
            let flag = irq_state.get_irq_flag(ref_obj_id)
                .ok_or(VerifierError::InvalidLock(
                    "IRQ flag reference not found".into()
                ))?;
            
            // Verify kfunc class matches (native with native, lock with lock)
            let saved_type = match flag.kfunc_class {
                IrqKfuncClass::LocalIrqSave | IrqKfuncClass::LocalIrqRestore => IrqKfuncType::Native,
                IrqKfuncClass::SpinLockIrqSave | IrqKfuncClass::SpinUnlockIrqRestore => IrqKfuncType::Lock,
            };
            
            if saved_type != kfunc_type {
                let saved_name = if saved_type == IrqKfuncType::Native { "native" } else { "lock" };
                let restore_name = if kfunc_type == IrqKfuncType::Native { "native" } else { "lock" };
                return Err(VerifierError::InvalidLock(format!(
                    "mismatched IRQ save/restore: saved with {} kfunc, restoring with {} kfunc",
                    saved_name, restore_name
                )));
            }
            
            // Unmark the stack slot
            unmark_stack_slot_irq_flag(irq_state, ref_obj_id)?;
        }
    }
    
    Ok(())
}

/// Validate IRQ flag register is valid for initialization (uninit check)
pub fn is_irq_flag_reg_valid_uninit(
    state: &BpfVerifierState,
    regno: usize,
) -> Result<bool> {
    let reg = state.reg(regno)
        .ok_or(VerifierError::InvalidRegister(regno as u8))?;
    
    if reg.reg_type != BpfRegType::PtrToStack {
        return Ok(false);
    }
    
    let off = reg.off;
    if off >= 0 {
        return Ok(false);
    }
    
    // Check stack slot is within bounds and not already used for special types
    let spi = ((-off) as usize - 1) / 8;
    let func_state = state.cur_func()
        .ok_or(VerifierError::Internal("no current frame".into()))?;
    
    if spi >= func_state.stack.allocated_stack / 8 {
        return Ok(false);
    }
    
    // Verify slot is not already a special type (dynptr, iter, or existing IRQ flag)
    let slot = &func_state.stack.stack[spi];
    use crate::core::types::BpfStackSlotType;
    
    for i in 0..8 {
        if slot.slot_type[i] == BpfStackSlotType::IrqFlag {
            return Ok(false); // Already an IRQ flag
        }
    }
    
    Ok(true)
}

/// Mark stack slot as containing IRQ flag after successful save
pub fn mark_irq_flag_stack_slot(
    state: &mut BpfVerifierState,
    spi: usize,
    ref_obj_id: u32,
) -> Result<()> {
    use crate::core::types::BpfStackSlotType;
    
    let func_state = state.cur_func_mut()
        .ok_or(VerifierError::Internal("no current frame".into()))?;
    
    if spi >= func_state.stack.stack.len() {
        return Err(VerifierError::StackOutOfBounds(spi as i32));
    }
    
    // Mark all bytes in the slot as IRQ flag
    for i in 0..8 {
        func_state.stack.stack[spi].slot_type[i] = BpfStackSlotType::IrqFlag;
    }
    
    // Store the reference ID in the spilled register
    func_state.stack.stack[spi].spilled_ptr.ref_obj_id = ref_obj_id;
    
    Ok(())
}

/// Clear IRQ flag from stack slot after successful restore
pub fn clear_irq_flag_stack_slot(
    state: &mut BpfVerifierState,
    spi: usize,
) -> Result<()> {
    use crate::core::types::BpfStackSlotType;
    
    let func_state = state.cur_func_mut()
        .ok_or(VerifierError::Internal("no current frame".into()))?;
    
    if spi >= func_state.stack.stack.len() {
        return Err(VerifierError::StackOutOfBounds(spi as i32));
    }
    
    // Clear all bytes in the slot
    for i in 0..8 {
        func_state.stack.stack[spi].slot_type[i] = BpfStackSlotType::Invalid;
    }
    
    // Clear the reference ID
    func_state.stack.stack[spi].spilled_ptr.ref_obj_id = 0;
    
    Ok(())
}

/// Conditional constraint for kfunc arguments
#[derive(Debug, Clone)]
pub struct KfuncArgConstraint {
    /// Condition: if this argument has this value/property
    pub condition_arg: usize,
    pub condition: ConstraintCondition,
    /// Then this argument must satisfy
    pub target_arg: usize,
    pub requirement: ConstraintRequirement,
}

/// Condition for constraint checking
#[derive(Debug, Clone)]
pub enum ConstraintCondition {
    /// Argument is NULL (value == 0)
    IsNull,
    /// Argument is non-NULL
    IsNonNull,
    /// Argument equals specific value
    Equals(u64),
    /// Argument is in range
    InRange(u64, u64),
}

/// Requirement for constraint satisfaction
#[derive(Debug, Clone)]
pub enum ConstraintRequirement {
    /// Must be NULL
    MustBeNull,
    /// Must be non-NULL
    MustBeNonNull,
    /// Must have specific BTF type
    MustHaveBtfId(u32),
    /// Must be initialized memory of at least this size
    MustHaveSize(u64),
    /// Must be scalar in range
    MustBeInRange(i64, i64),
}

/// Check conditional constraints between kfunc arguments
pub fn check_kfunc_conditional_constraints(
    state: &BpfVerifierState,
    desc: &KfuncDesc,
    constraints: &[KfuncArgConstraint],
) -> Result<()> {
    for constraint in constraints {
        let cond_reg = state.reg(constraint.condition_arg + 1)
            .ok_or(VerifierError::InvalidRegister((constraint.condition_arg + 1) as u8))?;
        
        // Check if condition is met
        let condition_met = match &constraint.condition {
            ConstraintCondition::IsNull => {
                cond_reg.is_const() && cond_reg.const_value() == 0
            }
            ConstraintCondition::IsNonNull => {
                !cond_reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) ||
                (cond_reg.is_const() && cond_reg.const_value() != 0)
            }
            ConstraintCondition::Equals(val) => {
                cond_reg.is_const() && cond_reg.const_value() == *val
            }
            ConstraintCondition::InRange(min, max) => {
                cond_reg.umin_value >= *min && cond_reg.umax_value <= *max
            }
        };
        
        if !condition_met {
            continue; // Condition not met, skip this constraint
        }
        
        // Check requirement on target argument
        let target_reg = state.reg(constraint.target_arg + 1)
            .ok_or(VerifierError::InvalidRegister((constraint.target_arg + 1) as u8))?;
        
        match &constraint.requirement {
            ConstraintRequirement::MustBeNull => {
                if !target_reg.is_const() || target_reg.const_value() != 0 {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "kfunc '{}': when arg{} is null, arg{} must also be null",
                        desc.name, constraint.condition_arg, constraint.target_arg
                    )));
                }
            }
            ConstraintRequirement::MustBeNonNull => {
                if target_reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "kfunc '{}': arg{} must be non-null when arg{} condition is met",
                        desc.name, constraint.target_arg, constraint.condition_arg
                    )));
                }
            }
            ConstraintRequirement::MustHaveBtfId(expected_id) => {
                if target_reg.btf_id() != *expected_id {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!("BTF type {} for kfunc '{}' arg{}",
                            expected_id, desc.name, constraint.target_arg),
                        got: format!("BTF type {}", target_reg.btf_id()),
                    });
                }
            }
            ConstraintRequirement::MustHaveSize(min_size) => {
                // Check memory size constraint
                let size = target_reg.mem_size as u64;
                if size < *min_size {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "kfunc '{}': arg{} must have size >= {}, got {}",
                        desc.name, constraint.target_arg, min_size, size
                    )));
                }
            }
            ConstraintRequirement::MustBeInRange(min, max) => {
                if target_reg.smin_value < *min || target_reg.smax_value > *max {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "kfunc '{}': arg{} must be in range [{}, {}], got [{}, {}]",
                        desc.name, constraint.target_arg, min, max,
                        target_reg.smin_value, target_reg.smax_value
                    )));
                }
            }
        }
    }
    
    Ok(())
}

/// Check RCU protection for kfunc arguments
pub fn check_kfunc_rcu_protection(
    state: &BpfVerifierState,
    desc: &KfuncDesc,
) -> Result<()> {
    // If kfunc requires RCU protection
    if desc.flags.rcu_protected {
        if state.refs.active_rcu_locks == 0 {
            return Err(VerifierError::InvalidKfunc(format!(
                "kfunc '{}' requires RCU read lock, but none held",
                desc.name
            )));
        }
    }
    
    // Check arguments that require RCU protection
    for (i, param) in desc.params.iter().enumerate() {
        if let Some(ref name) = param.name {
            // Parameters with __rcu annotation
            if name.contains("__rcu") || name.ends_with("_rcu") {
                let reg = state.reg(i + 1)
                    .ok_or(VerifierError::InvalidRegister((i + 1) as u8))?;
                
                // Must have MEM_RCU flag or be under RCU lock
                if !reg.type_flags.contains(BpfTypeFlag::MEM_RCU) && 
                   state.refs.active_rcu_locks == 0 {
                    return Err(VerifierError::InvalidKfunc(format!(
                        "kfunc '{}' arg{} ({}) requires RCU protection",
                        desc.name, i, name
                    )));
                }
            }
        }
    }
    
    Ok(())
}

/// Check sleepable context for kfunc
pub fn check_kfunc_sleepable_context(
    state: &BpfVerifierState,
    desc: &KfuncDesc,
    prog_sleepable: bool,
) -> Result<()> {
    if desc.flags.sleepable {
        // Sleepable kfunc requires sleepable program
        if !prog_sleepable {
            return Err(VerifierError::InvalidKfunc(format!(
                "sleepable kfunc '{}' called from non-sleepable program",
                desc.name
            )));
        }
        
        // Cannot hold spin locks when calling sleepable kfunc
        if state.lock_state.has_locks() {
            return Err(VerifierError::InvalidKfunc(format!(
                "sleepable kfunc '{}' called while holding spin lock",
                desc.name
            )));
        }
        
        // Cannot have preemption disabled
        if state.refs.active_preempt_locks > 0 {
            return Err(VerifierError::InvalidKfunc(format!(
                "sleepable kfunc '{}' called with preemption disabled",
                desc.name
            )));
        }
    }
    
    Ok(())
}

/// Check destructive kfunc requirements
pub fn check_kfunc_destructive(
    desc: &KfuncDesc,
    allow_destructive: bool,
) -> Result<()> {
    if desc.flags.destructive && !allow_destructive {
        return Err(VerifierError::InvalidKfunc(format!(
            "destructive kfunc '{}' not allowed in this context",
            desc.name
        )));
    }
    Ok(())
}

/// Check constraints specific to bpf_percpu_obj_new_impl
/// 
/// Per-CPU object allocation has stricter requirements than regular bpf_obj_new:
/// 1. Size must not exceed BPF_GLOBAL_PERCPU_MA_MAX_SIZE (512 bytes)
/// 2. The type must be a struct of scalars only (no special fields like timers, locks)
/// 3. The struct_meta argument must be NULL (no kptr fields allowed)
///
/// These constraints ensure per-CPU allocations are simple and can be safely
/// replicated across all CPUs without complex initialization.
pub fn check_percpu_obj_new_constraints(
    state: &BpfVerifierState,
    _meta: &KfuncCallMeta,
) -> Result<()> {
    // R1 contains the type size (passed as local_type_id which encodes size)
    // In actual verification, we would look up the BTF type and check its size
    // For now, we check if size info is available in the state's BTF context
    
    // The size validation happens during BTF type resolution in the kernel.
    // Here we verify the constraint is respected:
    // - Type must be <= BPF_GLOBAL_PERCPU_MA_MAX_SIZE bytes
    
    // Get the type size from R1 if it's a known constant
    if let Some(reg) = state.reg(1) {
        // If R1 is a known constant (the BTF type ID), we can't directly
        // validate size here - that's done during BTF resolution.
        // However, we can check if the meta has size info cached.
        if reg.is_const() {
            // Size validation will be done during fixups when we have BTF access
            // Here we just ensure the argument is properly typed
        }
    }
    
    // R2 (struct_meta) must be NULL (0) for percpu objects
    // Per-CPU objects cannot have kptr fields, so struct_meta must be NULL
    if let Some(reg) = state.reg(2) {
        if reg.is_const() && reg.const_value() != 0 {
            return Err(VerifierError::InvalidKfunc(
                "bpf_percpu_obj_new: struct_meta must be NULL (no kptr fields allowed)".into()
            ));
        }
    }
    
    // Note: Full size validation is performed in do_misc_fixups when
    // we have access to the BTF type information and can compute actual size.
    // At that point, we verify: type_size <= BPF_GLOBAL_PERCPU_MA_MAX_SIZE
    
    Ok(())
}

/// Validate per-CPU object type size during fixups
/// 
/// This is called from misc_fixups when we have access to the actual type size.
/// Returns an error if the type exceeds BPF_GLOBAL_PERCPU_MA_MAX_SIZE.
pub fn validate_percpu_obj_size(type_size: usize, type_name: &str) -> Result<()> {
    if type_size > BPF_GLOBAL_PERCPU_MA_MAX_SIZE {
        return Err(VerifierError::InvalidKfunc(format!(
            "bpf_percpu_obj_new type '{}' size ({}) exceeds maximum {} bytes",
            type_name, type_size, BPF_GLOBAL_PERCPU_MA_MAX_SIZE
        )));
    }
    Ok(())
}

/// Check special kfunc handling
pub fn check_special_kfunc(
    state: &mut BpfVerifierState,
    refs: &mut ReferenceManager,
    btf_id: u32,
    insn_idx: usize,
) -> Result<bool> {
    match btf_id {
        special_kfuncs::BPF_RCU_READ_LOCK => {
            refs.rcu_lock();
            Ok(true)
        }
        special_kfuncs::BPF_RCU_READ_UNLOCK => {
            refs.rcu_unlock()?;
            Ok(true)
        }
        special_kfuncs::BPF_RES_SPIN_LOCK => {
            // Get lock location from R1 argument (pointer to bpf_spin_lock)
            let reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
            
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_map_value".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            
            let map_uid = reg.map_uid;
            let lock_off = reg.off as u32;
            
            // Acquire the lock
            state.lock_state.acquire(map_uid, lock_off, insn_idx)?;
            
            Ok(true)
        }
        special_kfuncs::BPF_RES_SPIN_UNLOCK => {
            // Get lock location from R1 argument
            let reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
            
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_map_value".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            
            let map_uid = reg.map_uid;
            let lock_off = reg.off as u32;
            
            // Release the lock
            state.lock_state.release(map_uid, lock_off)?;
            
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::reg_state::BpfRegState;
    use crate::btf::btf::{Btf, BtfType, BtfKind};

    #[test]
    fn test_kfunc_registry() {
        let mut registry = KfuncRegistry::new();
        
        registry.register(KfuncDesc {
            btf_id: 100,
            name: "test_kfunc".into(),
            ..Default::default()
        }).unwrap();

        assert!(registry.contains(100));
        assert!(!registry.contains(101));
        
        let desc = registry.find_by_id(100).unwrap();
        assert_eq!(desc.name, "test_kfunc");
        
        let desc2 = registry.find_by_name("test_kfunc").unwrap();
        assert_eq!(desc2.btf_id, 100);
    }

    #[test]
    fn test_register_common() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        assert!(registry.find_by_name("bpf_rcu_read_lock").is_some());
        assert!(registry.find_by_name("bpf_obj_new_impl").is_some());
    }

    #[test]
    fn test_kfunc_flags() {
        let flags = KfuncFlags {
            is_acquire: true,
            ret_null: true,
            ..Default::default()
        };
        
        assert!(flags.is_acquire);
        assert!(flags.ret_null);
        assert!(!flags.is_release);
    }

    #[test]
    fn test_is_kfunc_call() {
        let kfunc_call = BpfInsn::new(
            BPF_JMP | BPF_CALL,
            0,
            BPF_PSEUDO_KFUNC_CALL,
            0,
            100,
        );
        assert!(is_kfunc_call(&kfunc_call));

        let helper_call = BpfInsn::new(
            BPF_JMP | BPF_CALL,
            0,
            0,
            0,
            1,
        );
        assert!(!is_kfunc_call(&helper_call));
    }

    #[test]
    fn test_special_kfuncs() {
        assert!(is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_LOCK));
        assert!(!is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_UNLOCK));
        
        assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_PUSH_FRONT));
        assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_POP_BACK));
        assert!(!is_bpf_list_api_kfunc(special_kfuncs::BPF_OBJ_NEW));
    }

    #[test]
    fn test_kfunc_arg_desc() {
        let desc = KfuncArgDesc {
            arg_type: KfuncArgType::PtrToBtfId,
            btf_id: Some(42),
            nullable: true,
            ..Default::default()
        };
        
        assert_eq!(desc.arg_type, KfuncArgType::PtrToBtfId);
        assert_eq!(desc.btf_id, Some(42));
        assert!(desc.nullable);
        assert!(!desc.is_release);
    }

    #[test]
    fn test_check_kfunc_arg_btf_type_scalar() {
        let btf = Btf::new();
        
        // Scalar register
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        
        let expected = KfuncArgDesc {
            arg_type: KfuncArgType::Scalar,
            ..Default::default()
        };
        
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_ok());
        
        // Wrong type
        reg.reg_type = BpfRegType::PtrToStack;
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_err());
    }

    #[test]
    fn test_check_kfunc_arg_btf_type_ptr() {
        let btf = Btf::new();
        
        // Pointer register
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMem;
        
        let expected = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            ..Default::default()
        };
        
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_ok());
        
        // Scalar is not a pointer
        reg.reg_type = BpfRegType::ScalarValue;
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_err());
    }

    #[test]
    fn test_check_kfunc_arg_nullable() {
        let btf = Btf::new();
        
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMem;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        
        // Non-nullable expected
        let non_nullable = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            nullable: false,
            ..Default::default()
        };
        assert!(check_kfunc_arg_btf_type(&reg, &non_nullable, &btf).is_err());
        
        // Nullable expected
        let nullable = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            nullable: true,
            ..Default::default()
        };
        assert!(check_kfunc_arg_btf_type(&reg, &nullable, &btf).is_ok());
    }

    #[test]
    fn test_btf_types_compatible() {
        let mut btf = Btf::new();
        
        let u32_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u32".into()),
            size: 4,
            ..Default::default()
        });
        
        let int_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("int".into()),
            size: 4,
            ..Default::default()
        });
        
        let u64_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u64".into()),
            size: 8,
            ..Default::default()
        });
        
        // Same type
        assert!(btf_types_compatible(&btf, u32_id, u32_id));
        
        // Compatible (same kind, same size)
        assert!(btf_types_compatible(&btf, u32_id, int_id));
        
        // Incompatible (different size)
        assert!(!btf_types_compatible(&btf, u32_id, u64_id));
    }

    #[test]
    fn test_is_release_arg() {
        let release_desc = KfuncDesc {
            btf_id: 100,
            name: "test_release".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(is_release_arg(&release_desc, 0)); // First arg
        assert!(!is_release_arg(&release_desc, 1)); // Second arg
        
        let acquire_desc = KfuncDesc {
            btf_id: 101,
            name: "test_acquire".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(!is_release_arg(&acquire_desc, 0));
    }

    #[test]
    fn test_percpu_obj_new_registered() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        // Check percpu_obj_new_impl is registered
        let desc = registry.find_by_name("bpf_percpu_obj_new_impl");
        assert!(desc.is_some());
        let desc = desc.unwrap();
        assert!(desc.flags.is_acquire);
        assert!(desc.flags.ret_null);
        assert_eq!(desc.params.len(), 2);
        
        // Check percpu_obj_drop_impl is registered
        let drop_desc = registry.find_by_name("bpf_percpu_obj_drop_impl");
        assert!(drop_desc.is_some());
        let drop_desc = drop_desc.unwrap();
        assert!(drop_desc.flags.is_release);
    }

    #[test]
    fn test_validate_percpu_obj_size() {
        // Valid size (within limit)
        assert!(validate_percpu_obj_size(256, "small_struct").is_ok());
        assert!(validate_percpu_obj_size(512, "max_struct").is_ok());
        
        // Invalid size (exceeds limit)
        let result = validate_percpu_obj_size(513, "too_large_struct");
        assert!(result.is_err());
        
        let result = validate_percpu_obj_size(1024, "very_large_struct");
        assert!(result.is_err());
    }

    #[test]
    fn test_percpu_obj_new_params() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        let desc = registry.find_by_name("bpf_percpu_obj_new_impl").unwrap();
        
        // Verify parameter types
        assert_eq!(desc.params[0].arg_type, KfuncArgType::Scalar); // local_type_id
        assert_eq!(desc.params[1].arg_type, KfuncArgType::Scalar); // meta (must be NULL)
        
        // Return type should be acquired pointer
        assert_eq!(desc.ret_type, KfuncRetType::AcquiredPtr);
    }

    #[test]
    fn test_percpu_obj_drop_params() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        let desc = registry.find_by_name("bpf_percpu_obj_drop_impl").unwrap();
        
        // Verify parameter types
        assert_eq!(desc.params[0].arg_type, KfuncArgType::PtrToAlloc); // p
        assert!(desc.params[0].is_release); // First arg is released
        assert_eq!(desc.params[1].arg_type, KfuncArgType::Scalar); // meta
        
        // Return type should be void
        assert_eq!(desc.ret_type, KfuncRetType::Void);
    }
}
