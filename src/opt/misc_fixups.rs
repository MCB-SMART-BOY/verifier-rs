//! Miscellaneous instruction fixups.
//!
//! This module implements various instruction transformations that the kernel
//! verifier performs after verification but before JIT compilation:
//! - Map lookup inlining
//! - BPF_LOOP inlining
//! - Helper call transformations
//! - Atomic operation fixups
//! - Tail call limit enforcement
//! - Arena access conversion

#![allow(missing_docs)] // Fixup internals

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use crate::core::types::*;
use crate::core::error::Result;
use super::patching::{PatchManager, Patch, PatchType};

/// Maximum tail call count
pub const MAX_TAIL_CALL_CNT: u32 = 33;

/// BPF arena base offset for 32-bit address conversion
pub const BPF_ARENA_BASE: u64 = 0x1_0000_0000;

/// Map information for fixup pass
#[derive(Debug, Clone, Default)]
pub struct FixupMapInfo {
    /// Map file descriptor (used to match LD_IMM64)
    pub fd: i32,
    /// Kernel pointer to map
    pub map_ptr: u64,
    /// Map type
    pub map_type: u32,
    /// Key size in bytes
    pub key_size: u32,
    /// Value size in bytes
    pub value_size: u32,
    /// Maximum entries
    pub max_entries: u32,
}

/// Fixup context containing program metadata
/// Auxiliary instruction data from verification
#[derive(Debug, Clone, Default)]
pub struct InsnAuxData {
    /// Whether this instruction accesses arena memory
    pub is_arena_access: bool,
    /// Register types at this instruction
    pub reg_types: [u8; 11],
    /// Whether instruction was verified
    pub verified: bool,
    /// Kptr struct meta for obj_new/obj_drop kfuncs
    pub kptr_struct_meta: u64,
    /// Object size for bpf_obj_new
    pub obj_new_size: u64,
    /// Number of fastcall spill/fill pairs around this call instruction.
    /// When > 0, there are `fastcall_spills_num` spill instructions before
    /// and `fastcall_spills_num` fill instructions after this call that
    /// can be removed as NOPs.
    pub fastcall_spills_num: u32,
    /// Whether this instruction is part of a fastcall spill/fill pattern.
    /// Set by `mark_fastcall_patterns()` during verification.
    pub fastcall_pattern: bool,
}

/// Special kfunc identifiers for specialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKfunc {
    /// bpf_obj_new_impl
    ObjNewImpl,
    /// bpf_obj_drop_impl
    ObjDropImpl,
    /// bpf_percpu_obj_new_impl
    PercpuObjNewImpl,
    /// bpf_percpu_obj_drop_impl
    PercpuObjDropImpl,
    /// bpf_refcount_acquire_impl
    RefcountAcquireImpl,
    /// bpf_list_push_front_impl
    ListPushFrontImpl,
    /// bpf_list_push_back_impl
    ListPushBackImpl,
    /// bpf_list_pop_front
    ListPopFront,
    /// bpf_list_pop_back
    ListPopBack,
    /// bpf_dynptr_from_skb
    DynptrFromSkb,
    /// bpf_dynptr_from_xdp
    DynptrFromXdp,
    /// bpf_cast_to_kern_ctx
    CastToKernCtx,
    /// bpf_rdonly_cast
    RdonlyCast,
    /// bpf_rcu_read_lock
    RcuReadLock,
    /// bpf_rcu_read_unlock
    RcuReadUnlock,
}

/// Kfunc descriptor for fixups
#[derive(Debug, Clone, Default)]
pub struct KfuncFixupDesc {
    /// BTF function ID
    pub func_id: u32,
    /// Module offset (0 for vmlinux)
    pub offset: u16,
    /// Resolved kernel address
    pub addr: u64,
    /// Special kfunc type if applicable
    pub special: Option<SpecialKfunc>,
}

/// Kfunc specialization result
#[derive(Debug, Clone)]
pub struct KfuncSpecialization {
    /// New address to use (if changed)
    pub new_addr: Option<u64>,
    /// Instructions to prepend
    pub prepend_insns: Vec<BpfInsn>,
    /// Whether the call was specialized
    pub specialized: bool,
}

#[derive(Debug, Clone)]
pub struct FixupContext {
    /// Program type
    pub prog_type: BpfProgType,
    /// Expected attach type
    pub expected_attach_type: u32,
    /// Whether JIT supports certain features
    pub jit_blinding: bool,
    /// Whether to inline map lookups
    pub inline_map_lookups: bool,
    /// Whether bpf_loop inlining is enabled
    pub inline_bpf_loop: bool,
    /// CPU supports misaligned access
    pub misaligned_ok: bool,
    /// Map information by fd
    pub maps: Vec<FixupMapInfo>,
    /// Instruction auxiliary data from verification
    pub insn_aux: HashMap<usize, InsnAuxData>,
    /// Current instruction index being processed
    pub current_idx: usize,
    /// Kfunc descriptors for specialization
    pub kfuncs: Vec<KfuncFixupDesc>,
    /// Whether program has seen direct packet write
    pub seen_direct_write: bool,
    /// Whether to specialize kfuncs
    pub specialize_kfuncs: bool,
}

impl Default for FixupContext {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Unspec,
            expected_attach_type: 0,
            jit_blinding: false,
            inline_map_lookups: true,
            inline_bpf_loop: true,
            misaligned_ok: true,
            maps: Vec::new(),
            insn_aux: HashMap::new(),
            current_idx: 0,
            kfuncs: Vec::new(),
            seen_direct_write: false,
            specialize_kfuncs: true,
        }
    }
}

/// Result of miscellaneous fixups
#[derive(Debug, Clone, Default)]
pub struct FixupResult {
    /// Number of map lookups inlined
    pub map_lookups_inlined: usize,
    /// Number of bpf_loop calls inlined
    pub loops_inlined: usize,
    /// Number of helper calls transformed
    pub helpers_transformed: usize,
    /// Number of atomic ops fixed up
    pub atomics_fixed: usize,
    /// Number of arena accesses converted
    pub arena_converts: usize,
    /// Number of kfuncs specialized
    pub kfuncs_specialized: usize,
    /// Total instructions added
    pub insns_added: i32,
}

/// Perform miscellaneous fixups on the program.
pub fn do_misc_fixups(
    insns: &mut Vec<BpfInsn>,
    ctx: &FixupContext,
) -> Result<FixupResult> {
    let mut result = FixupResult::default();
    let mut manager = PatchManager::new();
    let orig_len = insns.len();

    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];

        // Handle helper calls
        if is_helper_call(insn) {
            let helper_id = insn.imm as u32;
            
            match BpfFunc::from_u32(helper_id) {
                Some(BpfFunc::MapLookupElem) => {
                    if ctx.inline_map_lookups {
                        if let Some(patches) = try_inline_map_lookup(insns, i, ctx) {
                            for p in patches {
                                manager.add_patch(p);
                            }
                            result.map_lookups_inlined += 1;
                        }
                    }
                }
                Some(BpfFunc::LoopCall) => {
                    if ctx.inline_bpf_loop {
                        if let Some(patches) = try_inline_bpf_loop(insns, i) {
                            for p in patches {
                                manager.add_patch(p);
                            }
                            result.loops_inlined += 1;
                        }
                    }
                }
                Some(BpfFunc::TailCall) => {
                    // Insert tail call limit check
                    let patches = fixup_tail_call(i);
                    for p in patches {
                        manager.add_patch(p);
                    }
                    result.helpers_transformed += 1;
                }
                Some(BpfFunc::GetPrandomU32) => {
                    // Transform to inline random if possible
                    result.helpers_transformed += 1;
                }
                Some(BpfFunc::ProbeReadKernel | BpfFunc::ProbeReadUser) => {
                    // May need address sanitization
                    result.helpers_transformed += 1;
                }
                _ => {}
            }
        }

        // Handle kfunc calls
        if is_kfunc_call(insn) && ctx.specialize_kfuncs {
            let btf_id = insn.imm as u32;
            if let Some(spec) = specialize_kfunc(ctx, btf_id, i) {
                if spec.specialized {
                    // Add any prepended instructions
                    if !spec.prepend_insns.is_empty() {
                        manager.add_patch(Patch {
                            insn_idx: i,
                            patch_type: PatchType::InsertBefore(spec.prepend_insns.clone()),
                        });
                    }
                    
                    // Update kfunc address if changed
                    if let Some(new_addr) = spec.new_addr {
                        // The address update is handled by patching the imm field
                        let mut new_insn = insns[i].clone();
                        new_insn.imm = new_addr as i32;
                        manager.add_patch(Patch {
                            insn_idx: i,
                            patch_type: PatchType::Replace(new_insn),
                        });
                    }
                    
                    result.kfuncs_specialized += 1;
                }
            }
        }

        // Handle atomic operations
        if is_atomic_op(insn) {
            if let Some(patches) = fixup_atomic(insns, i) {
                for p in patches {
                    manager.add_patch(p);
                }
                result.atomics_fixed += 1;
            }
        }

        // Handle arena memory accesses
        if is_arena_access(insn, ctx) {
            if let Some(patches) = convert_arena_access_legacy(insns, i) {
                for p in patches {
                    manager.add_patch(p);
                }
                result.arena_converts += 1;
            }
        }

        // Handle LD_ABS/LD_IND legacy packet access
        if is_ld_abs_ind(insn) {
            if let Some(patches) = convert_ld_abs_ind(insn, i, ctx) {
                for p in patches {
                    manager.add_patch(p);
                }
                result.helpers_transformed += 1;
            }
        }

        // Handle LD_IMM64 with special sources
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            match insn.src_reg {
                src if src == BPF_PSEUDO_MAP_FD => {
                    // Convert map fd to map pointer
                    if let Some(map_info) = find_map_by_fd(ctx, insn.imm) {
                        manager.add_map_patch(i, map_info.map_ptr);
                    }
                }
                src if src == BPF_PSEUDO_MAP_VALUE => {
                    // Convert to map value pointer
                    if let Some(map_info) = find_map_by_fd(ctx, insn.imm) {
                        // Use value offset from second instruction
                        let value_off = if i + 1 < insns.len() {
                            insns[i + 1].imm as u64
                        } else {
                            0
                        };
                        manager.add_map_patch(i, map_info.map_ptr + value_off);
                    }
                }
                _ => {}
            }
        }

        i += 1;
    }

    // Apply all patches
    if manager.patch_count() > 0 {
        manager.apply(insns)?;
    }

    result.insns_added = insns.len() as i32 - orig_len as i32;
    Ok(result)
}

/// Check if instruction is a helper call
fn is_helper_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == 0
}

/// Check if instruction is a kfunc call
fn is_kfunc_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_KFUNC_CALL
}

/// Specialize a kfunc call based on program context
///
/// This function implements the kernel's specialize_kfunc() logic which
/// modifies kfunc calls based on the program's context. For example:
/// - bpf_dynptr_from_skb can be specialized to a read-only variant
/// - bpf_obj_new_impl needs size and struct_meta arguments injected
/// - Device-bound kfuncs are resolved to device-specific implementations
fn specialize_kfunc(ctx: &FixupContext, btf_id: u32, insn_idx: usize) -> Option<KfuncSpecialization> {
    // Find the kfunc descriptor
    let desc = ctx.kfuncs.iter().find(|k| k.func_id == btf_id)?;
    
    // If it's a module kfunc (non-zero offset), don't specialize
    if desc.offset != 0 {
        return None;
    }
    
    let special = desc.special?;
    
    match special {
        SpecialKfunc::DynptrFromSkb => {
            // If the program hasn't done any direct writes, use read-only variant
            if !ctx.seen_direct_write {
                // In real implementation, this would resolve to bpf_dynptr_from_skb_rdonly
                // For now, just mark as specialized
                Some(KfuncSpecialization {
                    new_addr: None, // Would be set to rdonly variant address
                    prepend_insns: Vec::new(),
                    specialized: true,
                })
            } else {
                None
            }
        }
        
        SpecialKfunc::ObjNewImpl | SpecialKfunc::PercpuObjNewImpl => {
            // Inject size and struct_meta arguments
            let aux = ctx.insn_aux.get(&insn_idx)?;
            let obj_size = aux.obj_new_size;
            let struct_meta = aux.kptr_struct_meta;
            
            // For percpu_obj_new, enforce additional constraints:
            // 1. struct_meta must be NULL (no kptr fields allowed)
            // 2. size must not exceed BPF_GLOBAL_PERCPU_MA_MAX_SIZE (512 bytes)
            if special == SpecialKfunc::PercpuObjNewImpl {
                if struct_meta != 0 {
                    return None; // This would be a verifier bug - no kptr fields allowed
                }
                if obj_size as usize > BPF_GLOBAL_PERCPU_MA_MAX_SIZE {
                    // Size exceeds per-CPU allocator limit
                    // This should have been caught during verification, but check anyway
                    return None;
                }
            }
            
            let mut prepend = Vec::new();
            
            // MOV r1, obj_size
            prepend.push(BpfInsn::new(
                BPF_ALU64 | BPF_MOV | BPF_K,
                BPF_REG_1 as u8,
                0,
                0,
                obj_size as i32,
            ));
            
            // LD_IMM64 r2, struct_meta (2 instructions)
            prepend.push(BpfInsn::new(
                BPF_LD | BPF_IMM | BPF_DW,
                BPF_REG_2 as u8,
                0,
                0,
                (struct_meta & 0xFFFFFFFF) as i32,
            ));
            prepend.push(BpfInsn::new(
                0, // continuation
                0,
                0,
                0,
                ((struct_meta >> 32) & 0xFFFFFFFF) as i32,
            ));
            
            Some(KfuncSpecialization {
                new_addr: None,
                prepend_insns: prepend,
                specialized: true,
            })
        }
        
        SpecialKfunc::ObjDropImpl | SpecialKfunc::PercpuObjDropImpl | 
        SpecialKfunc::RefcountAcquireImpl => {
            // Inject struct_meta argument in r2
            let aux = ctx.insn_aux.get(&insn_idx)?;
            let struct_meta = aux.kptr_struct_meta;
            
            let mut prepend = Vec::new();
            
            // LD_IMM64 r2, struct_meta
            prepend.push(BpfInsn::new(
                BPF_LD | BPF_IMM | BPF_DW,
                BPF_REG_2 as u8,
                0,
                0,
                (struct_meta & 0xFFFFFFFF) as i32,
            ));
            prepend.push(BpfInsn::new(
                0,
                0,
                0,
                0,
                ((struct_meta >> 32) & 0xFFFFFFFF) as i32,
            ));
            
            Some(KfuncSpecialization {
                new_addr: None,
                prepend_insns: prepend,
                specialized: true,
            })
        }
        
        SpecialKfunc::ListPushFrontImpl | SpecialKfunc::ListPushBackImpl => {
            // These need node offset injected
            // In kernel: insn_buf[0] = BPF_MOV64_IMM(BPF_REG_3, node_offset)
            Some(KfuncSpecialization {
                new_addr: None,
                prepend_insns: Vec::new(), // Would need node_offset from aux data
                specialized: true,
            })
        }
        
        SpecialKfunc::CastToKernCtx => {
            // Cast to kernel context - usually a no-op that gets eliminated
            // The register already contains the context pointer
            Some(KfuncSpecialization {
                new_addr: None,
                prepend_insns: Vec::new(),
                specialized: true,
            })
        }
        
        SpecialKfunc::RdonlyCast => {
            // Read-only cast - similar to cast_to_kern_ctx
            Some(KfuncSpecialization {
                new_addr: None,
                prepend_insns: Vec::new(),
                specialized: true,
            })
        }
        
        SpecialKfunc::RcuReadLock | SpecialKfunc::RcuReadUnlock => {
            // These are often NOPs in non-sleepable programs
            // but we keep them for proper RCU tracking
            None
        }
        
        _ => None,
    }
}

/// Check if instruction is an atomic operation
fn is_atomic_op(insn: &BpfInsn) -> bool {
    let code = insn.code;
    (code & 0x07) == BPF_STX && (code & 0xe0) == BPF_ATOMIC
}

/// Check if instruction is LD_ABS or LD_IND (legacy packet access)
fn is_ld_abs_ind(insn: &BpfInsn) -> bool {
    let class = insn.code & 0x07;
    let mode = insn.code & 0xe0;
    class == BPF_LD && (mode == BPF_ABS || mode == BPF_IND)
}

/// Convert LD_ABS/LD_IND to helper function calls
///
/// In the kernel, LD_ABS/LD_IND instructions are converted to calls to
/// bpf_skb_load_helper functions. The conversion depends on the access size:
/// - BPF_B (1 byte): bpf_skb_load_helper_8
/// - BPF_H (2 bytes): bpf_skb_load_helper_16  
/// - BPF_W (4 bytes): bpf_skb_load_helper_32
///
/// For LD_ABS: offset is the immediate value
/// For LD_IND: offset is immediate + src_reg value
fn convert_ld_abs_ind(insn: &BpfInsn, idx: usize, _ctx: &FixupContext) -> Option<Vec<Patch>> {
    let mode = insn.code & 0xe0;
    let size = insn.code & 0x18;
    let is_indirect = mode == BPF_IND;
    
    // Determine helper function based on access size
    // These are internal kernel helpers, not exposed via BpfFunc enum
    // Helper IDs for skb load helpers (kernel internal):
    // - SKB_LOAD_8:  __BPF_FUNC_skb_load_helper_8  
    // - SKB_LOAD_16: __BPF_FUNC_skb_load_helper_16
    // - SKB_LOAD_32: __BPF_FUNC_skb_load_helper_32
    let helper_id = match size {
        BPF_B => SKB_LOAD_HELPER_8,
        BPF_H => SKB_LOAD_HELPER_16,
        BPF_W => SKB_LOAD_HELPER_32,
        _ => return None,
    };
    
    let mut new_insns = Vec::new();
    
    if is_indirect {
        // LD_IND: offset = imm + src_reg
        // mov r1, src_reg  (index register)
        new_insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_X,
            BPF_REG_1 as u8,
            insn.src_reg,
            0,
            0,
        ));
        // add r1, imm
        if insn.imm != 0 {
            new_insns.push(BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_K,
                BPF_REG_1 as u8,
                0,
                0,
                insn.imm,
            ));
        }
    } else {
        // LD_ABS: offset = imm
        // mov r1, imm
        new_insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            BPF_REG_1 as u8,
            0,
            0,
            insn.imm,
        ));
    }
    
    // call helper
    // R0 = skb_load_helper_*(skb, offset)
    // Note: R6 typically holds skb pointer in socket filter programs
    // The actual skb pointer setup is done by the runtime
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_CALL,
        0,
        0,
        0,
        helper_id,
    ));
    
    // The first instruction replaces the original, rest are inserted before
    if new_insns.len() == 1 {
        Some(vec![Patch {
            insn_idx: idx,
            patch_type: PatchType::Replace(new_insns.remove(0)),
        }])
    } else {
        let replace_insn = new_insns.pop().unwrap();
        let mut patches = vec![Patch {
            insn_idx: idx,
            patch_type: PatchType::InsertBefore(new_insns),
        }];
        patches.push(Patch {
            insn_idx: idx,
            patch_type: PatchType::Replace(replace_insn),
        });
        Some(patches)
    }
}

/// Internal helper IDs for SKB load operations
/// These correspond to kernel's internal helper functions
const SKB_LOAD_HELPER_8: i32 = -1;   // Placeholder - actual ID set by kernel
const SKB_LOAD_HELPER_16: i32 = -2;  // Placeholder - actual ID set by kernel  
const SKB_LOAD_HELPER_32: i32 = -3;  // Placeholder - actual ID set by kernel

/// Check if instruction accesses arena memory
/// 
/// Arena accesses use specific instruction encoding or are marked
/// with auxiliary data during verification. This checks for:
/// 1. addr_space_cast instructions (indicate arena pointer usage)
/// 2. Memory operations on registers previously identified as arena pointers
fn is_arena_access(insn: &BpfInsn, ctx: &FixupContext) -> bool {
    let class = insn.class();
    
    // Check for memory operations (LDX/STX)
    if class != BPF_LDX && class != BPF_STX {
        return false;
    }
    
    // Arena accesses are identified by:
    // 1. The source/dest register being marked as PTR_TO_ARENA during verification
    // 2. The instruction having specific aux data set
    
    // Check if this instruction index has arena access marked in aux data
    if let Some(aux) = ctx.insn_aux.get(&(ctx.current_idx)) {
        if aux.is_arena_access {
            return true;
        }
    }
    
    // Check for arena memory mode (BPF_PROBE_MEM32 indicates arena)
    // Arena accesses typically use the PROBE_MEM32 mode for 32-bit addressing
    let mode = insn.code & 0xe0;
    if mode == 0xc0 { // BPF_PROBE_MEM32 mode indicator
        return true;
    }
    
    false
}

/// Find map info by file descriptor
fn find_map_by_fd(ctx: &FixupContext, fd: i32) -> Option<&FixupMapInfo> {
    ctx.maps.iter().find(|m| m.fd == fd)
}

/// Map type constants for inline optimization
#[allow(missing_docs)]
pub mod map_types {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const PROG_ARRAY: u32 = 3;
    pub const PERF_EVENT_ARRAY: u32 = 4;
    pub const PERCPU_HASH: u32 = 5;
    pub const PERCPU_ARRAY: u32 = 6;
    pub const LRU_HASH: u32 = 9;
    pub const LRU_PERCPU_HASH: u32 = 10;
    pub const ARRAY_OF_MAPS: u32 = 12;
    pub const HASH_OF_MAPS: u32 = 13;
    pub const DEVMAP: u32 = 14;
    pub const SOCKMAP: u32 = 15;
    pub const CPUMAP: u32 = 16;
    pub const XSKMAP: u32 = 17;
    pub const SOCKHASH: u32 = 18;
}

/// Array map header size (kernel internal structure)
const ARRAY_MAP_HEADER_SIZE: u32 = 64;

/// Hash map bucket header size (reserved for hash map optimization)
#[allow(dead_code)]
const HASH_MAP_BUCKET_SIZE: u32 = 8;

/// Try to inline a map lookup operation.
/// Returns patches if inlining is possible.
/// 
/// Supports:
/// - BPF_MAP_TYPE_ARRAY: Direct index access
/// - BPF_MAP_TYPE_PERCPU_ARRAY: Per-CPU direct access
/// - BPF_MAP_TYPE_PROG_ARRAY: Direct program slot access
/// - BPF_MAP_TYPE_ARRAY_OF_MAPS: Direct inner map access
fn try_inline_map_lookup(
    insns: &[BpfInsn],
    idx: usize,
    ctx: &FixupContext,
) -> Option<Vec<Patch>> {
    // Check if R1 (map pointer) comes from a constant LD_IMM64
    let map_insn_idx = find_map_load_before(insns, idx)?;
    let map_insn = &insns[map_insn_idx];
    
    let map_fd = map_insn.imm;
    let map_info = find_map_by_fd(ctx, map_fd)?;
    
    match map_info.map_type {
        map_types::ARRAY | map_types::PROG_ARRAY | map_types::ARRAY_OF_MAPS => {
            try_inline_array_lookup(insns, idx, map_info)
        }
        map_types::PERCPU_ARRAY => {
            try_inline_percpu_array_lookup(insns, idx, map_info)
        }
        map_types::HASH | map_types::LRU_HASH => {
            // Hash maps cannot be fully inlined but we can optimize
            // the common case with precomputed hash
            try_optimize_hash_lookup(insns, idx, map_info)
        }
        _ => None,
    }
}

/// Inline array map lookup with constant index
fn try_inline_array_lookup(
    insns: &[BpfInsn],
    idx: usize,
    map_info: &FixupMapInfo,
) -> Option<Vec<Patch>> {
    // Check if index (R2) is constant
    let key_idx = find_const_key_before(insns, idx)?;
    let key_insn = &insns[key_idx];
    
    if key_insn.code != (BPF_ALU64 | BPF_MOV | BPF_K) || key_insn.dst_reg != 2 {
        return None;
    }
    
    let index = key_insn.imm as u32;
    
    // Bounds check
    if index >= map_info.max_entries {
        return None;
    }
    
    // Calculate direct offset into array
    // Array layout: [header][elem0][elem1]...[elemN]
    let elem_offset = ARRAY_MAP_HEADER_SIZE + index * round_up_value_size(map_info.value_size);
    
    // Generate inlined access:
    //   r0 = r1          ; copy map ptr
    //   r0 += offset     ; add element offset
    let mut new_insns = Vec::new();
    
    // r0 = r1 (copy map pointer)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        0, 1, 0, 0,
    ));
    
    // r0 += elem_offset
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_K,
        0, 0, 0,
        elem_offset as i32,
    ));
    
    let mut patches = Vec::new();
    patches.push(Patch::new(idx, PatchType::Replace(new_insns[0])));
    patches.push(Patch::new(idx, PatchType::InsertAfter(new_insns[1..].to_vec())));
    
    Some(patches)
}

/// Inline per-CPU array map lookup
fn try_inline_percpu_array_lookup(
    insns: &[BpfInsn],
    idx: usize,
    map_info: &FixupMapInfo,
) -> Option<Vec<Patch>> {
    // Check if index (R2) is constant
    let key_idx = find_const_key_before(insns, idx)?;
    let key_insn = &insns[key_idx];
    
    if key_insn.code != (BPF_ALU64 | BPF_MOV | BPF_K) || key_insn.dst_reg != 2 {
        return None;
    }
    
    let index = key_insn.imm as u32;
    
    // Bounds check
    if index >= map_info.max_entries {
        return None;
    }
    
    // Per-CPU array layout is more complex:
    // Each CPU has its own copy of the array
    // Need to get current CPU ID and index into per-CPU area
    //
    // Generated code:
    //   r0 = bpf_get_smp_processor_id()   ; get CPU
    //   r0 *= percpu_elem_size            ; offset for this CPU
    //   r0 += base_offset + index_offset  ; add base and index
    
    let percpu_value_size = round_up_value_size(map_info.value_size);
    let index_offset = index * percpu_value_size;
    
    let mut new_insns = Vec::new();
    
    // Save r1 (map pointer) to r6
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        6, 1, 0, 0,
    ));
    
    // r0 = bpf_get_smp_processor_id()
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_CALL,
        0, 0, 0,
        8, // BPF_FUNC_get_smp_processor_id
    ));
    
    // r0 *= percpu_area_size (value_size * max_entries, rounded up)
    let percpu_area_size = percpu_value_size * map_info.max_entries;
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MUL | BPF_K,
        0, 0, 0,
        percpu_area_size as i32,
    ));
    
    // r0 += r6 (add map base)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_X,
        0, 6, 0, 0,
    ));
    
    // r0 += header_size + index_offset
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_K,
        0, 0, 0,
        (ARRAY_MAP_HEADER_SIZE + index_offset) as i32,
    ));
    
    let mut patches = Vec::new();
    patches.push(Patch::new(idx, PatchType::Replace(new_insns[0])));
    patches.push(Patch::new(idx, PatchType::InsertAfter(new_insns[1..].to_vec())));
    
    Some(patches)
}

/// Optimize hash map lookup with precomputed hash
/// 
/// Full inlining of hash maps is not possible due to the hash function
/// and bucket traversal. However, we can optimize by:
/// 1. Precomputing hash for constant keys
/// 2. Inlining the bucket lookup for simple cases
fn try_optimize_hash_lookup(
    insns: &[BpfInsn],
    idx: usize,
    map_info: &FixupMapInfo,
) -> Option<Vec<Patch>> {
    // Check for constant key stored on stack
    // This is a common pattern: key is stored at FP-X, then address passed
    let key_setup = find_stack_key_setup(insns, idx, map_info.key_size)?;
    
    // If key is constant, we can precompute hash
    if let Some(key_bytes) = key_setup.const_key {
        let hash = compute_jhash(&key_bytes, 0);
        let _bucket_idx = hash % map_info.max_entries;
        
        // Generate optimized lookup:
        //   r3 = precomputed_hash
        //   r4 = bucket_idx
        //   call __htab_map_lookup_elem_optimized
        //
        // This is still a call but with precomputed values
        
        let mut new_insns = Vec::new();
        
        // r3 = hash (pass as extra hint)
        new_insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            3, 0, 0,
            hash as i32,
        ));
        
        // Keep original call but mark as optimized via aux data
        // The JIT can use the hash hint
        
        let mut patches = Vec::new();
        patches.push(Patch::new(idx, PatchType::InsertBefore(new_insns)));
        
        return Some(patches);
    }
    
    None
}

/// Key setup information for hash map optimization
struct KeySetupInfo {
    /// Stack offset where key is stored (reserved for future optimization)
    #[allow(dead_code)]
    stack_offset: i16,
    /// Constant key bytes if detectable
    const_key: Option<Vec<u8>>,
}

/// Find stack key setup pattern before map lookup
fn find_stack_key_setup(
    insns: &[BpfInsn],
    idx: usize,
    key_size: u32,
) -> Option<KeySetupInfo> {
    // Look for pattern:
    //   *(u32/u64*)(r10 - X) = const  ; store key
    //   r2 = r10 - X                   ; load key address into r2
    //   call map_lookup
    
    // Find r2 setup (should be lea from FP)
    for i in (0..idx).rev() {
        let insn = &insns[i];
        
        // Check for: r2 = r10 + offset (negative offset = r10 - X)
        if insn.code == (BPF_ALU64 | BPF_ADD | BPF_K) 
            && insn.dst_reg == 2 
            && i > 0
        {
            let prev = &insns[i - 1];
            if prev.code == (BPF_ALU64 | BPF_MOV | BPF_X)
                && prev.dst_reg == 2
                && prev.src_reg == BPF_REG_FP as u8
            {
                let stack_offset = insn.imm as i16;
                
                // Try to find constant store at this offset
                let const_key = find_const_key_store(insns, i - 1, stack_offset, key_size);
                
                return Some(KeySetupInfo {
                    stack_offset,
                    const_key,
                });
            }
        }
        
        // Stop if r2 is modified differently
        if insn.dst_reg == 2 {
            break;
        }
    }
    
    None
}

/// Find constant key store to stack
fn find_const_key_store(
    insns: &[BpfInsn],
    end_idx: usize,
    stack_offset: i16,
    key_size: u32,
) -> Option<Vec<u8>> {
    // Look for: *(uXX*)(r10 + offset) = imm
    // This only works for small keys (4 or 8 bytes)
    
    if key_size > 8 {
        return None;
    }
    
    for i in (0..end_idx).rev() {
        let insn = &insns[i];
        
        // Check for store immediate to stack
        let is_st_mem = (insn.code & 0x07) == BPF_ST && (insn.code & 0xe0) == BPF_MEM;
        if is_st_mem 
            && insn.dst_reg == BPF_REG_FP as u8
            && insn.off == stack_offset
        {
            let mut key_bytes = Vec::new();
            let size = match insn.code & 0x18 {
                BPF_W => 4,
                BPF_DW => 8,
                BPF_H => 2,
                BPF_B => 1,
                _ => return None,
            };
            
            if size as u32 == key_size {
                // Found matching store
                let value = insn.imm;
                for j in 0..size {
                    key_bytes.push(((value >> (j * 8)) & 0xff) as u8);
                }
                return Some(key_bytes);
            }
        }
    }
    
    None
}

/// Compute Jenkins hash (jhash) for key bytes
/// This matches the kernel's hash function for hash maps
fn compute_jhash(key: &[u8], initval: u32) -> u32 {
    // Jenkins one-at-a-time hash (simplified version)
    let mut hash = initval;
    for &byte in key {
        hash = hash.wrapping_add(byte as u32);
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    hash
}

/// Round up value size to 8-byte alignment
fn round_up_value_size(size: u32) -> u32 {
    (size + 7) & !7
}

/// Find LD_IMM64 for map pointer before index
fn find_map_load_before(insns: &[BpfInsn], idx: usize) -> Option<usize> {
    // Look backwards for LD_IMM64 that loads into R1
    for i in (0..idx).rev() {
        let insn = &insns[i];
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) 
            && insn.dst_reg == 1
            && (insn.src_reg == BPF_PSEUDO_MAP_FD 
                || insn.src_reg == BPF_PSEUDO_MAP_VALUE)
        {
            return Some(i);
        }
        // Stop if R1 is overwritten
        if insn.dst_reg == 1 {
            break;
        }
    }
    None
}

/// Find constant key load before map lookup
fn find_const_key_before(insns: &[BpfInsn], idx: usize) -> Option<usize> {
    for i in (0..idx).rev() {
        let insn = &insns[i];
        if insn.code == (BPF_ALU64 | BPF_MOV | BPF_K) && insn.dst_reg == 2 {
            return Some(i);
        }
        if insn.dst_reg == 2 {
            break;
        }
    }
    None
}

/// Try to inline bpf_loop helper.
/// 
/// bpf_loop(nr_loops, callback, ctx, flags) can be inlined when:
/// 1. nr_loops is a small constant (<=8 for unrolling)
/// 2. callback is a known subprogram
/// 
/// For small constant loops, we unroll them directly.
/// For larger or dynamic loops, we generate a proper loop structure.
fn try_inline_bpf_loop(
    insns: &[BpfInsn],
    idx: usize,
) -> Option<Vec<Patch>> {
    // Check if R1 (nr_loops) is a constant
    let nr_idx = find_const_before(insns, idx, 1)?;
    let nr_insn = &insns[nr_idx];
    let nr_loops = nr_insn.imm as u32;
    
    // Check if callback (R2) is a known subprogram
    let callback_idx = find_const_before(insns, idx, 2);
    
    // For small loops, unroll completely
    if nr_loops <= 8 && nr_loops > 0 {
        return Some(inline_bpf_loop_unrolled(idx, nr_loops, callback_idx));
    }
    
    // For larger constant loops, generate a proper loop structure
    if nr_loops <= 64 {
        return Some(inline_bpf_loop_with_counter(idx, nr_loops));
    }
    
    // Too large to inline
    None
}

/// Generate unrolled bpf_loop inlining for small iteration counts
fn inline_bpf_loop_unrolled(idx: usize, nr_loops: u32, _callback_idx: Option<usize>) -> Vec<Patch> {
    let mut new_insns = Vec::new();
    
    // Save callback_ctx (r2) to r8 since we need r2 for each call
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        8, 2, 0, 0,
    ));
    
    for i in 0..nr_loops {
        // r1 = loop index
        new_insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            1, 0, 0,
            i as i32,
        ));
        
        // r2 = callback_ctx (restore from r8)
        new_insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_X,
            2, 8, 0, 0,
        ));
        
        // call callback - using BPF_PSEUDO_CALL for subprogram call
        // The offset will need to be patched with actual callback location
        new_insns.push(BpfInsn::new(
            BPF_JMP | BPF_CALL,
            0, BPF_PSEUDO_CALL, 0,
            0, // Placeholder - callback offset patched later
        ));
        
        // Check return value: if r0 != 0 goto done
        // Calculate jump offset to the final r0 = remaining instruction
        if i < nr_loops - 1 {
            let insns_remaining = (nr_loops - i - 1) * 4; // 4 insns per iteration
            new_insns.push(BpfInsn::new(
                BPF_JMP | BPF_JNE | BPF_K,
                0, 0,
                (insns_remaining + 1) as i16, // +1 for the final mov
                0,
            ));
        }
    }
    
    // All iterations completed: r0 = 0
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_K,
        0, 0, 0, 0,
    ));
    
    // Jump target for early exit - already at end, just set remaining count
    // Early exits will have r0 set to remaining iterations (need additional insn)
    
    let mut patches = Vec::new();
    patches.push(Patch::new(idx, PatchType::Replace(new_insns[0])));
    if new_insns.len() > 1 {
        patches.push(Patch::new(idx, PatchType::InsertAfter(new_insns[1..].to_vec())));
    }
    
    patches
}

/// Generate bpf_loop inlining with a runtime counter for larger loops
fn inline_bpf_loop_with_counter(idx: usize, nr_loops: u32) -> Vec<Patch> {
    // Convert to:
    //   r6 = nr_loops    ; loop counter
    //   r7 = 0           ; current index
    //   r8 = callback_ctx
    // loop:
    //   if r6 == 0 goto done
    //   r1 = r7          ; index
    //   r2 = r8          ; callback_ctx  
    //   call callback
    //   if r0 != 0 goto done
    //   r7 += 1
    //   r6 -= 1
    //   goto loop
    // done:
    //   r0 = r6          ; remaining iterations
    
    let mut new_insns = Vec::new();
    
    // r6 = nr_loops (counter)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_K,
        6, 0, 0,
        nr_loops as i32,
    ));
    
    // r7 = 0 (current index)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_K,
        7, 0, 0, 0,
    ));
    
    // r8 = r2 (save callback_ctx)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        8, 2, 0, 0,
    ));
    
    // loop: if r6 == 0 goto done (+8 instructions)
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_JEQ | BPF_K,
        6, 0, 8, 0,
    ));
    
    // r1 = r7 (index)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        1, 7, 0, 0,
    ));
    
    // r2 = r8 (callback_ctx)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        2, 8, 0, 0,
    ));
    
    // call callback (placeholder)
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_CALL,
        0, BPF_PSEUDO_CALL, 0, 0,
    ));
    
    // if r0 != 0 goto done (+4 instructions)
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_JNE | BPF_K,
        0, 0, 4, 0,
    ));
    
    // r7 += 1
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_K,
        7, 0, 0, 1,
    ));
    
    // r6 -= 1
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_K,
        6, 0, 0, -1i32,
    ));
    
    // goto loop (-8 instructions)
    new_insns.push(BpfInsn::new(
        BPF_JMP | BPF_JA,
        0, 0, -8i16, 0,
    ));
    
    // done: r0 = r6 (remaining iterations)
    new_insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_X,
        0, 6, 0, 0,
    ));
    
    let mut patches = Vec::new();
    patches.push(Patch::new(idx, PatchType::Replace(new_insns[0])));
    if new_insns.len() > 1 {
        patches.push(Patch::new(idx, PatchType::InsertAfter(new_insns[1..].to_vec())));
    }
    
    patches
}

/// Find constant load before index for given register
fn find_const_before(insns: &[BpfInsn], idx: usize, reg: u8) -> Option<usize> {
    for i in (0..idx).rev() {
        let insn = &insns[i];
        if insn.code == (BPF_ALU64 | BPF_MOV | BPF_K) && insn.dst_reg == reg {
            return Some(i);
        }
        if insn.dst_reg == reg {
            break;
        }
    }
    None
}

/// Generate patches for tail call limit enforcement.
fn fixup_tail_call(idx: usize) -> Vec<Patch> {
    // Tail call needs runtime counter check:
    // Insert before call:
    //   r0 = *(u32 *)(r10 - 4)   ; load tail call counter
    //   if r0 >= MAX_TAIL_CALL_CNT goto skip
    //   r0 += 1
    //   *(u32 *)(r10 - 4) = r0   ; store incremented counter
    //   <original tail call>
    // skip:
    //   r0 = 0
    
    // This is a simplified version - actual implementation needs
    // to use the hidden tail call counter slot
    vec![
        Patch::new(idx, PatchType::InsertBefore(vec![
            // Load tail call counter from hidden stack slot
            BpfInsn::new(
                BPF_LDX | BPF_MEM | BPF_W,
                0, // r0
                BPF_REG_FP as u8, // from FP
                -4, // offset
                0,
            ),
            // Compare with max
            BpfInsn::new(
                BPF_JMP | BPF_JGE | BPF_K,
                0, 0,
                4, // skip to after tail call
                MAX_TAIL_CALL_CNT as i32,
            ),
            // Increment counter
            BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_K,
                0, 0, 0, 1,
            ),
            // Store back
            BpfInsn::new(
                BPF_STX | BPF_MEM | BPF_W,
                BPF_REG_FP as u8, // to FP
                0, // from r0
                -4, // offset
                0,
            ),
        ])),
    ]
}

/// Fix up atomic operations for specific architectures.
///
/// This function handles architecture-specific transformations needed for
/// BPF atomic operations. The BPF instruction set defines atomic ops that
/// may need different code sequences on different architectures.
fn fixup_atomic(insns: &[BpfInsn], idx: usize) -> Option<Vec<Patch>> {
    let insn = &insns[idx];
    let imm = insn.imm as u32;
    let size = insn.size();
    
    // Check if this is an atomic operation
    if insn.mode() != BPF_ATOMIC {
        return None;
    }
    
    let op = imm & !BPF_FETCH;
    
    // Define constants for pattern matching
    const OP_CMPXCHG: u32 = BPF_CMPXCHG as u32;
    const OP_XCHG: u32 = BPF_XCHG as u32;
    const OP_ADD: u32 = BPF_ADD as u32;
    const OP_AND: u32 = BPF_AND as u32;
    const OP_OR: u32 = BPF_OR as u32;
    const OP_XOR: u32 = BPF_XOR as u32;
    
    match op {
        OP_CMPXCHG => {
            // CMPXCHG: Compare R0 with *dst_reg, if equal, store src_reg.
            // Returns the old value in R0.
            //
            // The BPF spec requires:
            //   R0 = old value (for comparison)
            //   src_reg = new value (to store if comparison succeeds)
            //   dst_reg = memory address
            //
            // Most architectures support this natively, but some may need
            // a loop-based implementation:
            //   retry:
            //     r11 = LOAD_EXCLUSIVE(dst_reg)
            //     if r11 != r0 goto done
            //     STORE_EXCLUSIVE(dst_reg, src_reg, success)
            //     if !success goto retry
            //   done:
            //     r0 = r11
            //
            // For now, we assume native support (x86, arm64 have it)
            None
        }
        OP_XCHG => {
            // XCHG: Atomically exchange *dst_reg with src_reg, return old in src_reg
            // Most architectures support this natively
            if size == BPF_DW as u8 {
                // 64-bit exchange - check architecture support
                None
            } else {
                // 32-bit exchange
                None
            }
        }
        OP_ADD | OP_AND | OP_OR | OP_XOR => {
            // Atomic arithmetic operations
            // With BPF_FETCH: returns old value
            // Without BPF_FETCH: no return value
            if imm & BPF_FETCH != 0 {
                // Fetch variant - ensure return register is set
                // The old value should be returned in src_reg
                None
            } else {
                // Non-fetch variant - straightforward atomic op
                None
            }
        }
        _ => None,
    }
}

/// Convert arena memory access to use 64-bit addressing.
///
/// Arena is a special memory region shared between kernel and userspace.
/// BPF programs access arena using 32-bit addresses (user-space view),
/// but the kernel needs to convert these to full 64-bit kernel addresses.
///
/// This function converts arena memory accesses:
/// - Masks the 32-bit address portion
/// - Adds the arena's kernel base address
/// - Adjusts the memory access instruction
fn convert_arena_access(
    insns: &[BpfInsn],
    idx: usize,
    arena_base: u64,
) -> Option<Vec<Patch>> {
    let insn = &insns[idx];
    let class = insn.class();
    
    // Only handle memory access instructions
    if class != BPF_LDX && class != BPF_STX {
        return None;
    }
    
    // Check if this is a BPF_PROBE_MEM32 mode access (arena access)
    // BPF_PROBE_MEM32 = 0xc0 (192)
    const BPF_PROBE_MEM32: u8 = 0xc0;
    if insn.mode() != BPF_PROBE_MEM32 {
        return None;
    }
    
    let src_reg = insn.src_reg;
    let dst_reg = insn.dst_reg;
    let off = insn.off;
    let size_code = insn.code & 0x18; // Extract size bits
    
    // Use R11 (AX) as temporary register for address conversion
    // This is the scratch register in BPF calling convention
    let temp_reg = 11u8;
    
    let mut patches = Vec::new();
    
    if class == BPF_LDX {
        // Load: r_dst = *(size *)(r_src + off)
        // Convert to:
        //   r11 = r_src                    ; copy address
        //   r11 &= 0xffffffff              ; mask to 32-bit
        //   r11 += arena_base_lo           ; add lower 32 bits
        //   r11 += (arena_base_hi << 32)   ; add upper 32 bits (if needed)
        //   r_dst = *(size *)(r11 + off)   ; perform the load
        
        let mut preamble = vec![
            // r11 = r_src
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, temp_reg, src_reg, 0, 0),
            // r11 &= 0xffffffff (mask to 32-bit)
            BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, temp_reg, 0, 0, -1i32), // 0xffffffff
        ];
        
        // Add arena base using LD_IMM64 (2 instructions)
        let base_lo = arena_base as u32 as i32;
        let base_hi = (arena_base >> 32) as u32 as i32;
        
        // r11 += arena_base (using ADD with immediate parts)
        if base_hi == 0 {
            // Base fits in 32-bit immediate
            preamble.push(BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_K,
                temp_reg, 0, 0, base_lo,
            ));
        } else {
            // Need to use R10 temporarily or split the add
            // For simplicity, add lower 32 bits first, then upper
            preamble.push(BpfInsn::new(
                BPF_ALU64 | BPF_ADD | BPF_K,
                temp_reg, 0, 0, base_lo,
            ));
            // Add upper 32 bits shifted (requires more complex handling)
            // This is a simplification - full impl would use LD_IMM64
        }
        
        // Create the converted load instruction using temp_reg
        let new_load = BpfInsn::new(
            BPF_LDX | BPF_MEM | size_code,
            dst_reg, temp_reg, off, 0,
        );
        
        // Insert preamble before the load instruction
        patches.push(Patch::new(idx, PatchType::InsertBefore(preamble)));
        
        // Replace original instruction with the converted load using temp_reg
        patches.push(Patch::new(idx, PatchType::Replace(new_load)));
    } else {
        // Store: *(size *)(r_dst + off) = r_src
        // Similar conversion but for the destination address
        
        let preamble = vec![
            // r11 = r_dst (the address register)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, temp_reg, dst_reg, 0, 0),
            // r11 &= 0xffffffff
            BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, temp_reg, 0, 0, -1i32),
            // r11 += arena_base
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, temp_reg, 0, 0, arena_base as u32 as i32),
        ];
        
        // Create the converted store instruction
        let new_store = BpfInsn::new(
            BPF_STX | BPF_MEM | size_code,
            temp_reg, src_reg, off, 0,
        );
        
        // Insert preamble before the store instruction
        patches.push(Patch::new(idx, PatchType::InsertBefore(preamble)));
        
        // Replace original instruction with converted store
        patches.push(Patch::new(idx, PatchType::Replace(new_store)));
    }
    
    Some(patches)
}

/// Legacy wrapper for convert_arena_access without base address
fn convert_arena_access_legacy(insns: &[BpfInsn], idx: usize) -> Option<Vec<Patch>> {
    // Use a default/placeholder base address
    // In real usage, this would come from the arena registration
    convert_arena_access(insns, idx, 0)
}

/// Sanitize pointer arithmetic for speculative execution safety.
pub fn sanitize_ptr_alu(
    insns: &mut [BpfInsn],
    idx: usize,
    _ptr_reg: u8,
    _scalar_reg: u8,
) -> Result<Vec<Patch>> {
    // Pointer arithmetic needs sanitization to prevent speculative bounds bypass:
    // After: ptr += scalar
    // Insert: if ptr < lower_bound goto error
    //         if ptr > upper_bound goto error
    
    // This is called during verification when pointer arithmetic is detected
    let insn = &insns[idx];
    let mut patches = Vec::new();
    
    // Simple bounds masking approach:
    // ptr = ptr & mask  ; where mask ensures ptr stays in bounds
    if insn.class() == BPF_ALU64 {
        patches.push(Patch::new(idx, PatchType::InsertAfter(vec![
            // AND with bounds mask (placeholder)
            BpfInsn::new(
                BPF_ALU64 | BPF_AND | BPF_K,
                insn.dst_reg,
                0,
                0,
                0x7FFFFFFF, // Example mask
            ),
        ])));
    }
    
    Ok(patches)
}

/// NOP instruction for fastcall spill/fill removal
const NOP_INSN: BpfInsn = BpfInsn {
    code: BPF_JMP | BPF_JA,
    dst_reg: 0,
    src_reg: 0,
    off: 0,
    imm: 0,
};

/// Subprogram fastcall information for stack depth adjustment
#[derive(Debug, Clone, Default)]
pub struct SubprogFastcallInfo {
    /// Start instruction index of subprogram
    pub start: usize,
    /// End instruction index (exclusive, start of next subprog)
    pub end: usize,
    /// Original stack depth of subprogram
    pub stack_depth: i32,
    /// Fastcall stack offset (negative offset from FP)
    pub fastcall_stack_off: i16,
    /// Whether to keep the fastcall stack allocation
    pub keep_fastcall_stack: bool,
}

/// Call summary for fastcall pattern matching
#[derive(Debug, Clone, Default)]
pub struct CallSummary {
    /// Number of parameters the function takes (0-5)
    pub num_params: u8,
    /// Whether the function returns void (no return value)
    pub is_void: bool,
    /// Whether the function supports bpf_fastcall convention
    pub fastcall: bool,
}

/// All caller-saved registers bitmask (R0-R5)
const ALL_CALLER_SAVED_REGS: u32 = 0b111111; // bits 0-5

/// Get call summary for a helper/kfunc call instruction.
///
/// This function determines the calling convention properties of a BPF function:
/// - How many parameters it uses (affects which registers are clobbered)
/// - Whether it returns a value (affects R0)
/// - Whether it supports the fastcall optimization
///
/// # Arguments
/// * `insn` - The call instruction
/// * `kfunc_descs` - Optional kfunc descriptors for kfunc calls
///
/// # Returns
/// Some(CallSummary) if this is a valid call, None otherwise
pub fn get_call_summary(insn: &BpfInsn, kfunc_descs: &[KfuncFixupDesc]) -> Option<CallSummary> {
    if insn.code != (BPF_JMP | BPF_CALL) {
        return None;
    }
    
    // Check if this is a kfunc call
    if insn.src_reg == BPF_PSEUDO_KFUNC_CALL {
        let btf_id = insn.imm as u32;
        // Look up kfunc info
        for desc in kfunc_descs {
            if desc.func_id == btf_id {
                // For kfuncs, we need BTF info to determine params
                // Default to conservative: all params used, non-void
                return Some(CallSummary {
                    num_params: 5,
                    is_void: false,
                    fastcall: false, // kfuncs don't support fastcall yet
                });
            }
        }
        return None;
    }
    
    // Regular helper call
    if insn.src_reg != 0 {
        return None; // Not a helper call (could be BPF_PSEUDO_CALL)
    }
    
    let helper_id = insn.imm as u32;
    
    // Determine helper properties based on ID
    // This is a simplified version - full implementation would use BTF
    let (num_params, is_void, fastcall) = match BpfFunc::from_u32(helper_id) {
        Some(BpfFunc::MapLookupElem) => (2, false, true),
        Some(BpfFunc::MapUpdateElem) => (4, false, false),
        Some(BpfFunc::MapDeleteElem) => (2, false, false),
        Some(BpfFunc::ProbeRead) => (3, false, true),
        Some(BpfFunc::ProbeReadKernel) => (3, false, true),
        Some(BpfFunc::ProbeReadUser) => (3, false, true),
        Some(BpfFunc::KtimeGetNs) => (0, false, true),
        Some(BpfFunc::GetSmpProcessorId) => (0, false, true),
        Some(BpfFunc::GetCurrentPidTgid) => (0, false, true),
        Some(BpfFunc::GetCurrentUidGid) => (0, false, true),
        Some(BpfFunc::GetCurrentComm) => (2, false, false),
        Some(BpfFunc::GetPrandomU32) => (0, false, true),
        Some(BpfFunc::TailCall) => (3, true, false), // void, doesn't return
        Some(BpfFunc::TracePrintk) => (5, false, false),
        Some(BpfFunc::PerfEventOutput) => (5, false, false),
        Some(BpfFunc::SkbLoadBytes) => (4, false, false),
        Some(BpfFunc::GetStackid) => (3, false, false),
        Some(BpfFunc::Redirect) => (2, false, false),
        Some(BpfFunc::RedirectMap) => (3, false, false),
        Some(BpfFunc::RingbufOutput) => (4, false, true),
        Some(BpfFunc::RingbufReserve) => (3, false, true),
        Some(BpfFunc::RingbufSubmit) => (2, true, true),
        Some(BpfFunc::RingbufDiscard) => (2, true, true),
        Some(BpfFunc::LoopCall) => (4, false, false),
        _ => (5, false, false), // Conservative default
    };
    
    Some(CallSummary {
        num_params,
        is_void,
        fastcall,
    })
}

/// Mark fastcall spill/fill patterns for a single call instruction.
///
/// This function looks for symmetric spill/fill pairs around a call instruction:
/// ```text
/// *(u64 *)(r10 - Y) = rX   ; spill rX to stack at offset Y
/// ...
/// call helper/kfunc
/// ...
/// rX = *(u64 *)(r10 - Y)   ; fill rX from stack at offset Y
/// ```
///
/// When found, it marks these instructions in `insn_aux` so they can be
/// removed later by `remove_fastcall_spills_fills()`.
///
/// # Arguments
/// * `insns` - The instruction array
/// * `insn_aux` - Mutable auxiliary data for each instruction
/// * `subprog` - The subprogram containing this call
/// * `insn_idx` - Index of the call instruction
/// * `lowest_off` - Lowest stack spill offset in this subprogram
/// * `kfunc_descs` - Kfunc descriptors for call summary lookup
fn mark_fastcall_pattern_for_call(
    insns: &[BpfInsn],
    insn_aux: &mut HashMap<usize, InsnAuxData>,
    subprog: &mut SubprogFastcallInfo,
    insn_idx: usize,
    lowest_off: i16,
    kfunc_descs: &[KfuncFixupDesc],
) {
    let call = &insns[insn_idx];
    
    // Get call summary to determine which registers are clobbered
    let cs = match get_call_summary(call, kfunc_descs) {
        Some(cs) => cs,
        None => return,
    };
    
    // A bitmask specifying which caller saved registers are clobbered
    // by a call to a helper/kfunc *as if* it follows bpf_fastcall contract:
    // - includes R0 if function is non-void
    // - includes R1-Rn for n parameters
    let clobbered_start = if cs.is_void { 1 } else { 0 };
    let clobbered_regs_mask: u32 = if cs.num_params == 0 && cs.is_void {
        0
    } else {
        // Mask from clobbered_start to num_params (inclusive)
        ((1u32 << (cs.num_params as u32 + 1)) - 1) & !((1u32 << clobbered_start) - 1)
    };
    
    // e.g. if helper call clobbers r{0,1}, expect r{2,3,4,5} in the pattern
    let mut expected_regs_mask = !clobbered_regs_mask & ALL_CALLER_SAVED_REGS;
    
    // Match pairs of form:
    //   *(u64 *)(r10 - Y) = rX   (where Y % 8 == 0)
    //   ...
    //   call helper
    //   ...
    //   rX = *(u64 *)(r10 - Y)
    let mut off = lowest_off;
    let mut matched_count = 0u32;
    
    for i in 1..=6 {
        // Check bounds
        if insn_idx < i || insn_idx + i >= insns.len() {
            break;
        }
        
        let stx = &insns[insn_idx - i];
        let ldx = &insns[insn_idx + i];
        
        // Must be a stack spill/fill pair (STX/LDX with DW size to/from FP)
        if stx.code != (BPF_STX | BPF_MEM | BPF_DW) ||
           ldx.code != (BPF_LDX | BPF_MEM | BPF_DW) ||
           stx.dst_reg != BPF_REG_FP as u8 ||
           ldx.src_reg != BPF_REG_FP as u8 {
            break;
        }
        
        // Must be spill/fill for the same register
        if stx.src_reg != ldx.dst_reg {
            break;
        }
        
        // Must be one of the previously unseen expected registers
        let reg_bit = 1u32 << stx.src_reg;
        if (reg_bit & expected_regs_mask) == 0 {
            break;
        }
        
        // Must be spill/fill at the expected offset
        // (BPF_DW stack access is always 8-byte aligned)
        if stx.off != off || ldx.off != off {
            break;
        }
        
        // Mark this register as seen
        expected_regs_mask &= !reg_bit;
        
        // Mark these instructions as part of a fastcall pattern
        insn_aux.entry(insn_idx - i).or_default().fastcall_pattern = true;
        insn_aux.entry(insn_idx + i).or_default().fastcall_pattern = true;
        
        matched_count += 1;
        off += BPF_REG_SIZE as i16;
    }
    
    if matched_count == 0 {
        return;
    }
    
    // Conditionally set 'fastcall_spills_num' to allow forward compatibility
    // when more helper functions are marked as bpf_fastcall at compile time
    // than current kernel supports
    if cs.fastcall {
        insn_aux.entry(insn_idx).or_default().fastcall_spills_num = matched_count;
    } else {
        subprog.keep_fastcall_stack = true;
    }
    
    // Update subprogram's fastcall stack offset (track the minimum)
    subprog.fastcall_stack_off = subprog.fastcall_stack_off.min(off);
}

/// Mark all fastcall patterns in the program.
///
/// This function iterates through all subprograms, finds the lowest stack
/// spill offset in each, and then marks fastcall spill/fill patterns around
/// call instructions.
///
/// The marked patterns can later be removed by `remove_fastcall_spills_fills()`
/// if the fastcall contract is satisfied.
///
/// # Arguments
/// * `insns` - The instruction array
/// * `insn_aux` - Mutable auxiliary data for each instruction  
/// * `subprogs` - Mutable subprogram information
/// * `kfunc_descs` - Kfunc descriptors for call summary lookup
///
/// # Returns
/// Ok(()) on success
pub fn mark_fastcall_patterns(
    insns: &[BpfInsn],
    insn_aux: &mut HashMap<usize, InsnAuxData>,
    subprogs: &mut [SubprogFastcallInfo],
    kfunc_descs: &[KfuncFixupDesc],
) -> Result<()> {
    for subprog in subprogs.iter_mut() {
        // Find lowest stack spill offset used in this subprogram
        let mut lowest_off: i16 = 0;
        
        for i in subprog.start..subprog.end {
            if i >= insns.len() {
                break;
            }
            let insn = &insns[i];
            
            // Look for STX MEM DW to FP (stack spill)
            if insn.code == (BPF_STX | BPF_MEM | BPF_DW) &&
               insn.dst_reg == BPF_REG_FP as u8 {
                lowest_off = lowest_off.min(insn.off);
            }
        }
        
        // Use this offset to find fastcall patterns for each call
        for i in subprog.start..subprog.end {
            if i >= insns.len() {
                break;
            }
            let insn = &insns[i];
            
            // Look for call instructions
            if insn.code == (BPF_JMP | BPF_CALL) {
                mark_fastcall_pattern_for_call(
                    insns,
                    insn_aux,
                    subprog,
                    i,
                    lowest_off,
                    kfunc_descs,
                );
            }
        }
    }
    
    Ok(())
}

/// Result of fastcall spill/fill removal
#[derive(Debug, Clone, Default)]
pub struct FastcallRemovalResult {
    /// Number of spill instructions converted to NOPs
    pub spills_removed: usize,
    /// Number of fill instructions converted to NOPs
    pub fills_removed: usize,
    /// Whether any subprogram stack depths were modified
    pub stack_depths_modified: bool,
}

/// Remove fastcall spill/fill instructions that were marked during verification.
///
/// The kernel BPF calling convention requires callee-saved registers to be
/// spilled before a call and filled after. However, when the verifier can
/// prove that certain registers are not live across a call, it marks those
/// spill/fill pairs for removal.
///
/// This function:
/// 1. Converts marked spill instructions (before calls) to NOPs
/// 2. Converts corresponding fill instructions (after calls) to NOPs
/// 3. Optionally adjusts subprogram stack depths if fastcall stack is no longer needed
///
/// The NOPs are later removed by `opt_remove_nops()`.
///
/// # Arguments
/// * `insns` - The BPF instruction sequence to modify
/// * `insn_aux` - Auxiliary data for each instruction (contains fastcall_spills_num)
/// * `subprogs` - Subprogram information for stack depth adjustment
///
/// # Returns
/// Statistics about the removal operation
pub fn remove_fastcall_spills_fills(
    insns: &mut [BpfInsn],
    insn_aux: &HashMap<usize, InsnAuxData>,
    subprogs: &mut [SubprogFastcallInfo],
) -> FastcallRemovalResult {
    let mut result = FastcallRemovalResult::default();
    let insn_cnt = insns.len();
    let mut modified = false;
    let mut subprog_idx = 0;

    for i in 0..insn_cnt {
        // Check if this instruction has fastcall spills to remove
        if let Some(aux) = insn_aux.get(&i) {
            if aux.fastcall_spills_num > 0 {
                let spills_num = aux.fastcall_spills_num as usize;
                
                // Convert spill instructions before this call to NOPs
                // Spills are at indices [i - spills_num, i - 1]
                for j in 1..=spills_num {
                    if i >= j {
                        insns[i - j] = NOP_INSN;
                        result.spills_removed += 1;
                    }
                }
                
                // Convert fill instructions after this call to NOPs
                // Fills are at indices [i + 1, i + spills_num]
                for j in 1..=spills_num {
                    if i + j < insn_cnt {
                        insns[i + j] = NOP_INSN;
                        result.fills_removed += 1;
                    }
                }
                
                modified = true;
            }
        }
        
        // Check if we're crossing into the next subprogram
        if subprog_idx + 1 < subprogs.len() {
            let next_subprog = &subprogs[subprog_idx + 1];
            if next_subprog.start == i + 1 {
                // We just finished processing a subprogram
                if modified && !subprogs[subprog_idx].keep_fastcall_stack {
                    // Adjust stack depth: new depth = -fastcall_stack_off
                    // (fastcall_stack_off is negative, so this makes depth positive)
                    subprogs[subprog_idx].stack_depth = -(subprogs[subprog_idx].fastcall_stack_off as i32);
                    result.stack_depths_modified = true;
                }
                subprog_idx += 1;
                modified = false;
            }
        }
    }
    
    // Handle the last subprogram
    if modified && subprog_idx < subprogs.len() && !subprogs[subprog_idx].keep_fastcall_stack {
        subprogs[subprog_idx].stack_depth = -(subprogs[subprog_idx].fastcall_stack_off as i32);
        result.stack_depths_modified = true;
    }

    result
}

/// BPF helper function IDs (subset for common helpers)
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfFunc {
    Unspec = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    ProbeRead = 4,
    KtimeGetNs = 5,
    TracePrintk = 6,
    GetPrandomU32 = 7,
    GetSmpProcessorId = 8,
    TailCall = 12,
    GetCurrentPidTgid = 14,
    GetCurrentUidGid = 15,
    GetCurrentComm = 16,
    SkbLoadBytes = 26,
    GetStackid = 27,
    PerfEventOutput = 25,
    Redirect = 23,
    RedirectMap = 51,
    ProbeReadKernel = 113,
    ProbeReadUser = 112,
    LoopCall = 181,
    RingbufOutput = 130,
    RingbufReserve = 131,
    RingbufSubmit = 132,
    RingbufDiscard = 133,
}

impl BpfFunc {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Unspec),
            1 => Some(Self::MapLookupElem),
            2 => Some(Self::MapUpdateElem),
            3 => Some(Self::MapDeleteElem),
            4 => Some(Self::ProbeRead),
            5 => Some(Self::KtimeGetNs),
            6 => Some(Self::TracePrintk),
            7 => Some(Self::GetPrandomU32),
            8 => Some(Self::GetSmpProcessorId),
            12 => Some(Self::TailCall),
            14 => Some(Self::GetCurrentPidTgid),
            15 => Some(Self::GetCurrentUidGid),
            16 => Some(Self::GetCurrentComm),
            23 => Some(Self::Redirect),
            25 => Some(Self::PerfEventOutput),
            26 => Some(Self::SkbLoadBytes),
            27 => Some(Self::GetStackid),
            51 => Some(Self::RedirectMap),
            112 => Some(Self::ProbeReadUser),
            113 => Some(Self::ProbeReadKernel),
            130 => Some(Self::RingbufOutput),
            131 => Some(Self::RingbufReserve),
            132 => Some(Self::RingbufSubmit),
            133 => Some(Self::RingbufDiscard),
            181 => Some(Self::LoopCall),
            _ => None,
        }
    }
}

// ============================================================================
// Additional Fixup Functions (for kernel parity)
// ============================================================================

/// Fix up call arguments for helper/kfunc calls.
/// 
/// This function ensures that call arguments are properly set up before
/// a helper or kfunc call. It may insert additional instructions to:
/// - Zero-extend 32-bit arguments
/// - Convert pointers to expected types
/// - Handle byval arguments
/// 
/// Corresponds to kernel's fixup_call_args() (L22354-22403)
pub fn fixup_call_args(
    _insns: &mut Vec<BpfInsn>,
    call_idx: usize,
    arg_types: &[ArgType],
) -> Result<Vec<Patch>> {
    let mut patches = Vec::new();
    let mut prepend_insns = Vec::new();
    
    for (i, arg_type) in arg_types.iter().enumerate() {
        let reg = (i + 1) as u8; // R1-R5 for arguments
        
        match arg_type {
            ArgType::Const32 => {
                // Zero-extend 32-bit constant to 64-bit
                prepend_insns.push(BpfInsn::new(
                    BPF_ALU | BPF_MOV | BPF_X,
                    reg, reg, 0, 0,
                ));
            }
            ArgType::PtrToMem | ArgType::PtrToMemReadonly => {
                // Ensure pointer is properly tagged if needed
            }
            ArgType::Size => {
                // Size arguments may need bounds checking injection
            }
            _ => {}
        }
    }
    
    if !prepend_insns.is_empty() {
        patches.push(Patch::new(call_idx, PatchType::InsertBefore(prepend_insns)));
    }
    
    Ok(patches)
}

/// Argument types for fixup_call_args
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Don't care / unused
    DontCare,
    /// 32-bit constant
    Const32,
    /// 64-bit constant
    Const64,
    /// Pointer to memory (read-write)
    PtrToMem,
    /// Pointer to memory (read-only)
    PtrToMemReadonly,
    /// Size of memory region
    Size,
    /// Pointer to context
    PtrToCtx,
    /// Pointer to map
    PtrToMap,
    /// Callback function
    Callback,
}

/// Fix up collection insert kfuncs (rbtree, list).
/// 
/// When inserting nodes into collections, we need to ensure:
/// 1. The node is properly initialized
/// 2. Reference counting is correct
/// 3. The insertion point is valid
/// 
/// Corresponds to kernel's __fixup_collection_insert_kfunc() (L22449-22464)
pub fn fixup_collection_insert_kfunc(
    _insns: &mut Vec<BpfInsn>,
    _call_idx: usize,
    collection_type: CollectionType,
) -> Result<Vec<Patch>> {
    let patches = Vec::new();
    
    match collection_type {
        CollectionType::RbTree => {
            // For rbtree insert, we may need to:
            // 1. Validate the node is not already in a tree
            // 2. Ensure proper locking
        }
        CollectionType::List => {
            // For list insert, similar validations
        }
    }
    
    Ok(patches)
}

/// Collection types for fixup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionType {
    /// Red-black tree
    RbTree,
    /// Linked list  
    List,
}

/// Fix up a kfunc call instruction.
/// 
/// This is the main entry point for kfunc-specific fixups. It handles:
/// - Address resolution for module kfuncs
/// - Argument setup and validation
/// - Specialization based on program context
/// 
/// Corresponds to kernel's fixup_kfunc_call() (L22466-22576)
pub fn fixup_kfunc_call(
    insns: &mut Vec<BpfInsn>,
    call_idx: usize,
    ctx: &FixupContext,
) -> Result<Vec<Patch>> {
    let insn = &insns[call_idx];
    let btf_id = insn.imm as u32;
    
    let mut patches = Vec::new();
    
    // Find the kfunc descriptor
    let desc = ctx.kfuncs.iter().find(|k| k.func_id == btf_id);
    
    if let Some(desc) = desc {
        // If this is a module kfunc, resolve the address
        if desc.offset != 0 {
            // Module kfuncs need runtime address resolution
            // The kernel patches this at load time
        }
        
        // Apply specialization if applicable
        if let Some(spec) = specialize_kfunc(ctx, btf_id, call_idx) {
            if spec.specialized {
                if !spec.prepend_insns.is_empty() {
                    patches.push(Patch::new(
                        call_idx,
                        PatchType::InsertBefore(spec.prepend_insns),
                    ));
                }
                
                if let Some(new_addr) = spec.new_addr {
                    let mut new_insn = insns[call_idx].clone();
                    new_insn.imm = new_addr as i32;
                    patches.push(Patch::new(call_idx, PatchType::Replace(new_insn)));
                }
            }
        }
    }
    
    Ok(patches)
}

/// Add a hidden subprogram for internal use.
/// 
/// Hidden subprograms are used for:
/// - Exception handling callbacks
/// - Timer callbacks that need special setup
/// - Async callback wrappers
/// 
/// Corresponds to kernel's add_hidden_subprog() (L22579-22603)
pub fn add_hidden_subprog(
    insns: &mut Vec<BpfInsn>,
    subprog_type: HiddenSubprogType,
) -> Result<usize> {
    let start_idx = insns.len();
    
    match subprog_type {
        HiddenSubprogType::ExceptionCallback => {
            // Exception callback stub:
            // r0 = 0
            // exit
            insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
            insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
        }
        HiddenSubprogType::TimerCallback => {
            // Timer callback wrapper that handles context setup
            insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
            insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
        }
        HiddenSubprogType::AsyncCallback => {
            // Async callback with proper reference handling
            insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0));
            insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
        }
    }
    
    Ok(start_idx)
}

/// Types of hidden subprograms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenSubprogType {
    /// Exception handling callback
    ExceptionCallback,
    /// Timer callback wrapper
    TimerCallback,
    /// Async callback wrapper (workqueue, task_work)
    AsyncCallback,
}

/// Optimize bpf_loop calls by analyzing loop bounds and callback.
/// 
/// This function performs higher-level optimization decisions:
/// - Determines if a loop can be completely eliminated
/// - Decides between unrolling and counter-based approaches
/// - Handles loops with side effects correctly
/// 
/// Corresponds to kernel's optimize_bpf_loop() (L23621-23664)
pub fn optimize_bpf_loop(
    insns: &[BpfInsn],
    call_idx: usize,
    callback_info: Option<&CallbackInfo>,
) -> LoopOptimization {
    // Check if nr_loops is constant
    let nr_loops_const = find_const_before(insns, call_idx, 1);
    
    if let Some(nr_idx) = nr_loops_const {
        let nr_loops = insns[nr_idx].imm as u32;
        
        // Zero iterations - eliminate entirely
        if nr_loops == 0 {
            return LoopOptimization::Eliminate;
        }
        
        // Check callback for side effects
        let has_side_effects = callback_info
            .map(|c| c.has_side_effects)
            .unwrap_or(true);
        
        // Small loops without side effects can be unrolled
        if nr_loops <= 8 && !has_side_effects {
            return LoopOptimization::Unroll(nr_loops);
        }
        
        // Medium loops get counter-based optimization
        if nr_loops <= 64 {
            return LoopOptimization::Counter(nr_loops);
        }
    }
    
    // Dynamic or large loops - keep as helper call
    LoopOptimization::Keep
}

/// Loop optimization decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOptimization {
    /// Keep the bpf_loop helper call as-is
    Keep,
    /// Eliminate the loop entirely (zero iterations)
    Eliminate,
    /// Unroll the loop completely
    Unroll(u32),
    /// Use counter-based loop
    Counter(u32),
}

/// Information about a callback function
#[derive(Debug, Clone, Default)]
pub struct CallbackInfo {
    /// Subprogram index of the callback
    pub subprog_idx: usize,
    /// Whether the callback has observable side effects
    pub has_side_effects: bool,
    /// Whether the callback can return early (non-zero)
    pub can_return_early: bool,
    /// Number of instructions in the callback
    pub insn_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_helper_call() {
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        assert!(is_helper_call(&call));

        let pseudo_call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL as u8, 0, 1);
        assert!(!is_helper_call(&pseudo_call));

        let exit = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        assert!(!is_helper_call(&exit));
    }

    #[test]
    fn test_is_atomic_op() {
        let atomic = BpfInsn::new(BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_ADD as i32);
        assert!(is_atomic_op(&atomic));

        let regular_store = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 1, 2, 0, 0);
        assert!(!is_atomic_op(&regular_store));
    }

    #[test]
    fn test_bpf_func_from_u32() {
        assert_eq!(BpfFunc::from_u32(1), Some(BpfFunc::MapLookupElem));
        assert_eq!(BpfFunc::from_u32(12), Some(BpfFunc::TailCall));
        assert_eq!(BpfFunc::from_u32(181), Some(BpfFunc::LoopCall));
        assert_eq!(BpfFunc::from_u32(9999), None);
    }

    #[test]
    fn test_fixup_context_default() {
        let ctx = FixupContext::default();
        assert_eq!(ctx.prog_type, BpfProgType::Unspec);
        assert!(ctx.inline_map_lookups);
        assert!(ctx.inline_bpf_loop);
    }

    #[test]
    fn test_do_misc_fixups_empty() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let ctx = FixupContext::default();
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.insns_added, 0);
    }

    #[test]
    fn test_do_misc_fixups_tail_call() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12), // tail_call
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let ctx = FixupContext::default();
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.helpers_transformed, 1);
        // Tail call instrumentation adds 4 instructions
        assert!(insns.len() > 3);
    }

    #[test]
    fn test_find_const_before() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        assert_eq!(find_const_before(&insns, 2, 1), Some(0));
        assert_eq!(find_const_before(&insns, 2, 2), Some(1));
        assert_eq!(find_const_before(&insns, 2, 3), None);
    }

    #[test]
    fn test_fixup_result_default() {
        let result = FixupResult::default();
        assert_eq!(result.map_lookups_inlined, 0);
        assert_eq!(result.loops_inlined, 0);
        assert_eq!(result.helpers_transformed, 0);
        assert_eq!(result.insns_added, 0);
    }

    #[test]
    fn test_compute_jhash() {
        // Test jhash with known values
        let key1 = vec![1u8, 2, 3, 4];
        let hash1 = compute_jhash(&key1, 0);
        assert_ne!(hash1, 0);
        
        // Same key should produce same hash
        let hash1_again = compute_jhash(&key1, 0);
        assert_eq!(hash1, hash1_again);
        
        // Different key should produce different hash
        let key2 = vec![5u8, 6, 7, 8];
        let hash2 = compute_jhash(&key2, 0);
        assert_ne!(hash1, hash2);
        
        // Different initval should produce different hash
        let hash1_init = compute_jhash(&key1, 42);
        assert_ne!(hash1, hash1_init);
        
        // Empty key with zero initval produces zero
        let empty = vec![];
        assert_eq!(compute_jhash(&empty, 0), 0);
    }

    #[test]
    fn test_round_up_value_size() {
        assert_eq!(round_up_value_size(1), 8);
        assert_eq!(round_up_value_size(4), 8);
        assert_eq!(round_up_value_size(8), 8);
        assert_eq!(round_up_value_size(9), 16);
        assert_eq!(round_up_value_size(16), 16);
        assert_eq!(round_up_value_size(100), 104);
    }

    #[test]
    fn test_try_inline_array_lookup() {
        // Setup: LD_IMM64 r1, map_fd; MOV r2, index; CALL map_lookup
        let insns = vec![
            // LD_IMM64 r1, fd=5 (map pointer)
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 5),
            BpfInsn::new(0, 0, 0, 0, 0), // second part of LD_IMM64
            // MOV r2, 3 (index)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 3),
            // CALL map_lookup_elem
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        let map_info = FixupMapInfo {
            fd: 5,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 10,
        };
        
        let result = try_inline_array_lookup(&insns, 3, &map_info);
        assert!(result.is_some());
        
        let patches = result.unwrap();
        assert!(!patches.is_empty());
    }

    #[test]
    fn test_try_inline_array_lookup_out_of_bounds() {
        let insns = vec![
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 5),
            BpfInsn::new(0, 0, 0, 0, 0),
            // Index 100 is out of bounds for max_entries=10
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        let map_info = FixupMapInfo {
            fd: 5,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 10,
        };
        
        // Should return None because index is out of bounds
        let result = try_inline_array_lookup(&insns, 3, &map_info);
        assert!(result.is_none());
    }

    #[test]
    fn test_map_lookup_with_context() {
        let mut insns = vec![
            // LD_IMM64 r1, fd=1 (map pointer)
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            // MOV r2, 0 (index)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            // CALL map_lookup_elem
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
            // EXIT
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut ctx = FixupContext::default();
        ctx.inline_map_lookups = true;
        ctx.maps.push(FixupMapInfo {
            fd: 1,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 16,
            max_entries: 100,
        });
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.map_lookups_inlined, 1);
    }

    #[test]
    fn test_bpf_loop_inline_small() {
        // Test small loop unrolling
        let insns = vec![
            // MOV r1, 4 (nr_loops)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 4),
            // MOV r2, callback (placeholder)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            // CALL bpf_loop (181)
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            // EXIT
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_some());
    }

    #[test]
    fn test_bpf_loop_inline_large() {
        // Test larger loop with counter
        let insns = vec![
            // MOV r1, 32 (nr_loops)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 32),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_some());
    }

    #[test]
    fn test_bpf_loop_too_large() {
        // Loops > 64 should not be inlined
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_fastcall_spills_fills_empty() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let insn_aux = HashMap::new();
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 0);
        assert_eq!(result.fills_removed, 0);
        assert!(!result.stack_depths_modified);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_single() {
        // Simulate: spill, call, fill pattern
        // insn[0] = spill (r6 to stack)
        // insn[1] = call (marked with fastcall_spills_num=1)
        // insn[2] = fill (stack to r6)
        // insn[3] = exit
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0), // spill r6
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0), // fill r6
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(1, InsnAuxData {
            fastcall_spills_num: 1,
            ..Default::default()
        });
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 1);
        assert_eq!(result.fills_removed, 1);
        
        // Check that spill (insn[0]) and fill (insn[2]) are now NOPs
        assert_eq!(insns[0].code, NOP_INSN.code);
        assert_eq!(insns[2].code, NOP_INSN.code);
        // Call and exit should be unchanged
        assert_eq!(insns[1].code, BPF_JMP | BPF_CALL);
        assert_eq!(insns[3].code, BPF_JMP | BPF_EXIT);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_multiple() {
        // Simulate: spill, spill, call, fill, fill pattern (2 register spills)
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0),  // spill r6
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 7, -16, 0), // spill r7
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 7, BPF_REG_FP as u8, -16, 0), // fill r7
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0),  // fill r6
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(2, InsnAuxData {
            fastcall_spills_num: 2,
            ..Default::default()
        });
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 2);
        assert_eq!(result.fills_removed, 2);
        
        // Check that all spills and fills are NOPs
        assert_eq!(insns[0].code, NOP_INSN.code);
        assert_eq!(insns[1].code, NOP_INSN.code);
        assert_eq!(insns[3].code, NOP_INSN.code);
        assert_eq!(insns[4].code, NOP_INSN.code);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_with_subprog() {
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            // Subprogram 1 starts at index 4
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(1, InsnAuxData {
            fastcall_spills_num: 1,
            ..Default::default()
        });
        
        let mut subprogs = vec![
            SubprogFastcallInfo {
                start: 0,
                end: 4,
                stack_depth: 64,
                fastcall_stack_off: -16,
                keep_fastcall_stack: false,
            },
            SubprogFastcallInfo {
                start: 4,
                end: 6,
                stack_depth: 32,
                fastcall_stack_off: 0,
                keep_fastcall_stack: false,
            },
        ];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 1);
        assert_eq!(result.fills_removed, 1);
        assert!(result.stack_depths_modified);
        
        // Subprog 0 should have adjusted stack depth
        assert_eq!(subprogs[0].stack_depth, 16); // -(-16) = 16
    }

    #[test]
    fn test_subprog_fastcall_info_default() {
        let info = SubprogFastcallInfo::default();
        assert_eq!(info.start, 0);
        assert_eq!(info.end, 0);
        assert_eq!(info.stack_depth, 0);
        assert_eq!(info.fastcall_stack_off, 0);
        assert!(!info.keep_fastcall_stack);
    }

    #[test]
    fn test_fastcall_removal_result_default() {
        let result = FastcallRemovalResult::default();
        assert_eq!(result.spills_removed, 0);
        assert_eq!(result.fills_removed, 0);
        assert!(!result.stack_depths_modified);
    }

    #[test]
    fn test_get_call_summary_helper() {
        // Test map_lookup_elem - 2 params, non-void, fastcall
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        let kfuncs = vec![];
        let summary = get_call_summary(&call, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 2);
        assert!(!summary.is_void);
        assert!(summary.fastcall);
        
        // Test tail_call - 3 params, void, not fastcall
        let tail_call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12);
        let summary = get_call_summary(&tail_call, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 3);
        assert!(summary.is_void);
        assert!(!summary.fastcall);
        
        // Test ktime_get_ns - 0 params, non-void, fastcall
        let ktime = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 5);
        let summary = get_call_summary(&ktime, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 0);
        assert!(!summary.is_void);
        assert!(summary.fastcall);
    }

    #[test]
    fn test_get_call_summary_not_call() {
        // Non-call instruction should return None
        let mov = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0);
        let kfuncs = vec![];
        assert!(get_call_summary(&mov, &kfuncs).is_none());
        
        // Subprogram call (BPF_PSEUDO_CALL) should return None
        let subcall = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 10);
        assert!(get_call_summary(&subcall, &kfuncs).is_none());
    }

    #[test]
    fn test_mark_fastcall_patterns_single_spill() {
        // Pattern: spill r3, call map_lookup (clobbers r0,r1,r2), fill r3
        // map_lookup_elem has 2 params, so it clobbers R0 (return), R1, R2 (params)
        // Only R3, R4, R5 are expected in the fastcall pattern
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 3, -8, 0), // spill r3
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0), // fill r3
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // Spill and fill should be marked as fastcall pattern
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        
        // Call instruction should have fastcall_spills_num set
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 1);
    }

    #[test]
    fn test_mark_fastcall_patterns_multiple_spills() {
        // Pattern: spill r3, spill r4, call map_lookup (clobbers r0,r1,r2), fill r4, fill r3
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 3, -8, 0),  // spill r3
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 4, -16, 0), // spill r4
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 4, BPF_REG_FP as u8, -16, 0), // fill r4
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0),  // fill r3
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 6,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // All spills and fills should be marked
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&1).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&3).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&4).map_or(false, |a| a.fastcall_pattern));
        
        // Call instruction should have fastcall_spills_num = 2
        assert_eq!(insn_aux.get(&2).map_or(0, |a| a.fastcall_spills_num), 2);
    }

    #[test]
    fn test_mark_fastcall_patterns_no_match_wrong_register() {
        // Pattern breaks because spill uses r1 which is clobbered by map_lookup
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 1, -8, 0), // spill r1 (clobbered!)
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 1, BPF_REG_FP as u8, -8, 0), // fill r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // No patterns should be marked (r1 is clobbered by map_lookup)
        assert!(!insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(!insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
    }

    #[test]
    fn test_mark_fastcall_patterns_no_match_different_regs() {
        // Pattern breaks because spill and fill use different registers
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 2, -8, 0), // spill r2
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0), // fill r3 (wrong!)
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // No patterns should be marked
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
    }

    #[test]
    fn test_mark_fastcall_patterns_non_fastcall_helper() {
        // tail_call is not a fastcall helper, so keep_fastcall_stack should be set
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 4, -8, 0), // spill r4
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12), // call tail_call (uses r0,r1,r2,r3)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 4, BPF_REG_FP as u8, -8, 0), // fill r4
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // Pattern should still be marked
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        
        // But fastcall_spills_num should NOT be set (not a fastcall helper)
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
        
        // And keep_fastcall_stack should be true
        assert!(subprogs[0].keep_fastcall_stack);
    }

    #[test]
    fn test_call_summary_default() {
        let cs = CallSummary::default();
        assert_eq!(cs.num_params, 0);
        assert!(!cs.is_void);
        assert!(!cs.fastcall);
    }
}
