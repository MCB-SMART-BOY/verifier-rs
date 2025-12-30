// SPDX-License-Identifier: GPL-2.0

//! BPF 内存访问验证模块
//!
//! Memory access verification for the BPF verifier.
//!
//! 本模块包含 BPF 验证器的内存访问验证逻辑，确保所有内存操作都是安全的。
//!
//! This module contains memory access checking, packet access verification,
//! context access validation, arena memory support, and user memory handling.
//!
//! ## 主要功能模块
//!
//! - `memory`: 核心内存访问验证 - 验证通用内存访问的边界和对齐
//! - `stack_access`: 栈访问验证 - 验证 BPF 栈的读写操作
//! - `packet`: 数据包访问验证 - 验证网络数据包的安全访问
//! - `context`: 上下文访问验证 - 验证 BPF 程序上下文结构的访问
//! - `arena`: 竞技场内存支持 - 验证用户态共享内存区域的访问
//! - `user`: 用户内存处理 - 验证用户空间内存的访问
//!
//! ## 内存安全保证
//!
//! 验证器确保：
//! - 所有内存访问都在有效边界内
//! - 指针算术不会导致溢出
//! - 正确处理不同内存区域的访问权限
//! - 防止推测执行攻击（通过净化模块配合）

pub mod arena;
pub mod context;
pub mod memory;
pub mod packet;
pub mod stack_access;
pub mod user;

// Re-export from memory (excluding duplicates)
pub use memory::{check_map_access_type, check_mem_access, may_access_direct_pkt_data};
// Re-export from packet (MAX_PACKET_OFF is canonical here)
pub use arena::*;
pub use context::*;
pub use packet::*;
// Re-export from stack_access (check_stack_range_initialized is canonical here)
pub use stack_access::*;
// Re-export from user memory
pub use user::{
    apply_user_ptr_propagation,
    check_arena_user_access,
    check_memory_isolation,
    check_user_mem_alignment,
    check_user_mem_direct_access,
    check_user_mem_helper_access,
    check_user_ptr_store,
    check_user_to_kernel_load,
    clear_reg_user_mem,
    get_fault_behavior,
    get_helper_user_access_type,
    get_speculation_protection,
    get_user_read_helper,
    is_user_mem_helper,
    // Basic validation
    is_user_mem_pointer,
    mark_reg_user_mem,
    // Speculation barriers
    needs_speculation_barrier,
    propagate_user_ptr_alu,
    validate_access_pattern,
    validate_copy_from_user_task,
    validate_fault_behavior,
    validate_probe_read_user_dst,
    validate_probe_read_user_src,
    validate_user_mem_access_bounds,
    // Comprehensive validation
    validate_user_mem_access_complete,
    validate_user_ptr_arg,
    // copy_from_user_task
    CopyFromUserTaskContext,
    // Memory isolation
    MemoryIsolation,
    SpecBarrierType,
    // Access patterns
    UserMemAccessPattern,
    // Core types
    UserMemAccessType,
    // Bounds validation
    UserMemBounds,
    UserMemContext,
    UserMemCopyTracker,
    // Fault handling
    UserMemFaultBehavior,
    // Data flow / taint analysis
    UserMemTaint,
    UserMemTaintTracker,
    UserMemValidation,
    // Pointer propagation
    UserPtrPropagation,
};
