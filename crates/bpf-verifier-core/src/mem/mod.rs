// SPDX-License-Identifier: GPL-2.0

//! Memory access verification for the BPF verifier.
//!
//! This module contains memory access checking, packet access verification,
//! context access validation, arena memory support, and user memory handling.

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
