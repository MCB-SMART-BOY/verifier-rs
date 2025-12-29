// SPDX-License-Identifier: GPL-2.0

//! Special object handling for the BPF verifier.
//!
//! This module contains dynamic pointer support, iterator verification,
//! exception handling, map operations, map type checking, rbtree/graph tracking,
//! struct_ops program support, and timer/kptr validation.

pub mod dynptr;
pub mod exception;
pub mod iter;
pub mod map_ops;
pub mod map_type_check;
pub mod rbtree;
pub mod struct_ops;
pub mod timer_kptr;

pub use dynptr::*;
pub use exception::*;
pub use iter::*;
pub use map_ops::*;
pub use map_type_check::*;
pub use rbtree::*;
pub use struct_ops::{
    check_required_members, is_helper_allowed_in_struct_ops, is_struct_ops_kfunc,
    tcp_congestion_ops, validate_struct_ops_args, validate_struct_ops_map,
    validate_struct_ops_return, StructOpsContext, StructOpsEvent, StructOpsMemberInfo,
    StructOpsRetType, StructOpsState, StructOpsType,
};
pub use timer_kptr::{
    check_kptr_access, check_kptr_xchg, check_special_field_overlap, check_timer_arg,
    check_timer_callback_registration, check_timer_context, check_timer_init_map_arg,
    kptr_load_type, KptrState, KptrType, SpecialFieldInfo, SpecialFieldType, TimerState,
    BPF_KPTR_SIZE, BPF_TIMER_SIZE,
};
