//! Memory access verification for the BPF verifier.
//!
//! This module contains memory access checking, packet access verification,
//! context access validation, arena memory support, and user memory handling.

pub mod memory;
pub mod packet;
pub mod context;
pub mod arena;
pub mod stack_access;
pub mod user;

// Re-export from memory (excluding duplicates)
pub use memory::{
    may_access_direct_pkt_data, check_mem_access, check_map_access_type,
};
// Re-export from packet (MAX_PACKET_OFF is canonical here)
pub use packet::*;
pub use context::*;
pub use arena::*;
// Re-export from stack_access (check_stack_range_initialized is canonical here)
pub use stack_access::*;
// Re-export from user memory
pub use user::{
    // Core types
    UserMemAccessType, UserMemContext, UserMemValidation,
    // Basic validation
    is_user_mem_pointer, check_user_mem_direct_access, check_user_mem_helper_access,
    validate_user_ptr_arg, mark_reg_user_mem, clear_reg_user_mem,
    validate_probe_read_user_dst, validate_probe_read_user_src,
    check_arena_user_access, UserMemCopyTracker,
    // Speculation barriers
    needs_speculation_barrier, get_speculation_protection, SpecBarrierType,
    get_user_read_helper, is_user_mem_helper, get_helper_user_access_type,
    // Pointer propagation
    UserPtrPropagation, propagate_user_ptr_alu, apply_user_ptr_propagation,
    // Bounds validation
    UserMemBounds, validate_user_mem_access_bounds,
    // Memory isolation
    MemoryIsolation, check_memory_isolation, check_user_ptr_store, check_user_to_kernel_load,
    // copy_from_user_task
    CopyFromUserTaskContext, validate_copy_from_user_task,
    // Data flow / taint analysis
    UserMemTaint, UserMemTaintTracker,
    // Access patterns
    UserMemAccessPattern, validate_access_pattern, check_user_mem_alignment,
    // Fault handling
    UserMemFaultBehavior, get_fault_behavior, validate_fault_behavior,
    // Comprehensive validation
    validate_user_mem_access_complete,
};
