// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的特殊对象处理模块
//!
//! Special object handling for the BPF verifier.
//!
//! 本模块包含动态指针支持、迭代器验证、异常处理、映射操作、映射类型检查、
//! 红黑树/图跟踪、struct_ops 程序支持以及定时器/内核指针验证。
//!
//! This module contains dynamic pointer support, iterator verification,
//! exception handling, map operations, map type checking, rbtree/graph tracking,
//! struct_ops program support, and timer/kptr validation.
//!
//! ## 主要组件 / Key Components
//!
//! - `dynptr`: 动态指针 - 提供对动态大小内存的安全访问
//! - `iter`: 迭代器 - 安全遍历内核数据结构
//! - `exception`: 异常处理 - struct_ops 程序的错误处理
//! - `map_ops`: 映射操作 - 映射操作验证
//! - `map_type_check`: 映射类型检查 - 映射-函数兼容性验证
//! - `rbtree`: 红黑树 - 图数据结构节点跟踪
//! - `struct_ops`: 结构体操作 - 内核结构操作程序支持
//! - `timer_kptr`: 定时器和内核指针 - 特殊字段验证

/// 动态指针模块 - 提供对动态大小内存的安全访问
/// Dynamic pointer module - safe access to dynamically-sized memory
pub mod dynptr;
/// 异常处理模块 - struct_ops 程序的错误处理
/// Exception handling module - error handling for struct_ops programs
pub mod exception;
/// 迭代器模块 - 安全遍历内核数据结构
/// Iterator module - safe traversal of kernel data structures
pub mod iter;
/// 映射操作模块 - 映射操作验证
/// Map operations module - map operation validation
pub mod map_ops;
/// 映射类型检查模块 - 映射-函数兼容性验证
/// Map type checking module - map-function compatibility validation
pub mod map_type_check;
/// 红黑树模块 - 图数据结构节点跟踪
/// Rbtree module - graph data structure node tracking
pub mod rbtree;
/// 结构体操作模块 - 内核结构操作程序支持
/// Struct ops module - kernel structure operations program support
pub mod struct_ops;
/// 定时器和内核指针模块 - 特殊字段验证
/// Timer and kptr module - special field validation
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
