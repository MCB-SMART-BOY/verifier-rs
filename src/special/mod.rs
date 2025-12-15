//! Special object handling for the BPF verifier.
//!
//! This module contains dynamic pointer support, iterator verification,
//! exception handling, map operations, map type checking, rbtree/graph tracking,
//! struct_ops program support, and timer/kptr validation.

pub mod dynptr;
pub mod iter;
pub mod exception;
pub mod map_ops;
pub mod map_type_check;
pub mod rbtree;
pub mod struct_ops;
pub mod timer_kptr;

pub use dynptr::*;
pub use iter::*;
pub use exception::*;
pub use map_ops::*;
pub use map_type_check::*;
pub use rbtree::*;
pub use struct_ops::{
    StructOpsType, StructOpsMemberInfo, StructOpsRetType, StructOpsContext,
    StructOpsState, StructOpsEvent,
    validate_struct_ops_args, validate_struct_ops_return,
    validate_struct_ops_map, check_required_members,
    is_helper_allowed_in_struct_ops, is_struct_ops_kfunc,
    tcp_congestion_ops,
};
pub use timer_kptr::{
    KptrType, SpecialFieldType, SpecialFieldInfo, TimerState, KptrState,
    BPF_TIMER_SIZE, BPF_KPTR_SIZE,
    check_timer_arg, check_timer_init_map_arg, check_kptr_access,
    kptr_load_type, check_timer_context, check_special_field_overlap,
    check_timer_callback_registration, check_kptr_xchg,
};
