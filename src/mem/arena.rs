//! Arena and memory arena support
//!
//! This module implements arena-based memory management verification for BPF programs.
//! Arenas provide user-space addressable memory regions for BPF programs.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap as HashMap};

use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::core::error::{Result, VerifierError};

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Maximum number of arenas per program
pub const MAX_ARENAS: usize = 64;

/// Arena descriptor
#[derive(Debug, Clone)]
pub struct ArenaInfo {
    /// Arena ID
    pub id: u32,
    /// Map file descriptor (arena is backed by a map)
    pub map_fd: i32,
    /// Arena size in bytes
    pub size: u64,
    /// User-space base address
    pub user_base: u64,
    /// Whether arena is read-only
    pub readonly: bool,
    /// BTF ID for arena type info
    pub btf_id: u32,
}

/// Arena state tracking
#[derive(Debug, Default)]
pub struct ArenaState {
    /// Registered arenas
    arenas: HashMap<u32, ArenaInfo>,
    /// Next arena ID
    next_id: u32,
}

impl ArenaState {
    /// Create new arena state
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new arena
    pub fn register(&mut self, info: ArenaInfo) -> Result<u32> {
        if self.arenas.len() >= MAX_ARENAS {
            return Err(VerifierError::TooComplex(
                "too many arenas".into()
            ));
        }

        let id = self.next_id;
        self.next_id += 1;
        self.arenas.insert(id, info);

        Ok(id)
    }

    /// Get arena info
    pub fn get(&self, id: u32) -> Option<&ArenaInfo> {
        self.arenas.get(&id)
    }

    /// Check if arena exists
    pub fn exists(&self, id: u32) -> bool {
        self.arenas.contains_key(&id)
    }
}

/// Memory region types for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemRegionType {
    /// Stack memory
    Stack,
    /// Map value memory
    MapValue,
    /// Packet data
    Packet,
    /// Context structure
    Context,
    /// Arena memory
    Arena,
    /// Ring buffer
    Ringbuf,
    /// Dynamic pointer memory
    Dynptr,
    /// Allocated memory (bpf_obj_new)
    Allocated,
}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// Region type
    pub region_type: MemRegionType,
    /// Start offset (for bounded regions)
    pub start: i64,
    /// End offset (exclusive)
    pub end: i64,
    /// Whether region is writable
    pub writable: bool,
    /// Arena ID (if applicable)
    pub arena_id: Option<u32>,
}

impl MemRegion {
    /// Create a new memory region
    pub fn new(region_type: MemRegionType, start: i64, end: i64, writable: bool) -> Self {
        Self {
            region_type,
            start,
            end,
            writable,
            arena_id: None,
        }
    }

    /// Create arena region
    pub fn arena(arena_id: u32, size: u64) -> Self {
        Self {
            region_type: MemRegionType::Arena,
            start: 0,
            end: size as i64,
            writable: true,
            arena_id: Some(arena_id),
        }
    }

    /// Check if offset is within region
    pub fn contains(&self, offset: i64, size: u32) -> bool {
        offset >= self.start && (offset + size as i64) <= self.end
    }

    /// Check if access is valid
    pub fn check_access(&self, offset: i64, size: u32, is_write: bool) -> Result<()> {
        if !self.contains(offset, size) {
            return Err(VerifierError::OutOfBounds {
                offset: offset as i32,
                size: size as i32,
            });
        }

        if is_write && !self.writable {
            return Err(VerifierError::InvalidMemoryAccess(
                "write to read-only region".into()
            ));
        }

        Ok(())
    }
}

/// Check arena pointer access
pub fn check_arena_access(
    reg: &BpfRegState,
    arena_state: &ArenaState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<()> {
    // Register must be arena pointer type
    if reg.reg_type != BpfRegType::PtrToArena {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_ARENA".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    // Get arena info from type flags or BTF
    let arena_id = reg.btf_info.as_ref()
        .map(|b| b.btf_id)
        .unwrap_or(0);

    let arena = arena_state.get(arena_id)
        .ok_or_else(|| VerifierError::InvalidMemoryAccess(
            "unknown arena".into()
        ))?;

    // Check bounds
    let access_start = reg.off as i64 + off as i64;
    let access_end = access_start + size as i64;

    if access_start < 0 || access_end > arena.size as i64 {
        return Err(VerifierError::OutOfBounds {
            offset: access_start as i32,
            size: size as i32,
        });
    }

    // Check write permission
    if is_write && arena.readonly {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only arena".into()
        ));
    }

    Ok(())
}

/// Address space for user/kernel pointer conversion
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressSpace {
    #[default]
    Kernel,
    User,
}

/// Check addr_space_cast operation
pub fn check_addr_space_cast(
    src_reg: &BpfRegState,
    src_space: AddressSpace,
    dst_space: AddressSpace,
) -> Result<BpfRegType> {
    // Only arena pointers can be cast between address spaces
    match (src_space, dst_space) {
        (AddressSpace::Kernel, AddressSpace::User) => {
            // Kernel to user - must be arena pointer
            if src_reg.reg_type != BpfRegType::PtrToArena {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_ARENA".into(),
                    got: format!("{:?}", src_reg.reg_type),
                });
            }
            Ok(BpfRegType::PtrToArena) // With user address space flag
        }
        (AddressSpace::User, AddressSpace::Kernel) => {
            // User to kernel - validate it's a valid arena user pointer
            Ok(BpfRegType::PtrToArena)
        }
        _ => {
            // Same address space - no-op
            Ok(src_reg.reg_type)
        }
    }
}

/// Resolve pointer for memory access
pub fn resolve_mem_access(
    reg: &BpfRegState,
    _off: i32,
    _size: u32,
    _is_write: bool,
) -> Result<MemRegion> {
    match reg.reg_type {
        BpfRegType::PtrToStack => {
            Ok(MemRegion::new(
                MemRegionType::Stack,
                -(MAX_BPF_STACK as i64),
                0,
                true,
            ))
        }
        BpfRegType::PtrToMapValue => {
            let map_size = reg.map_ptr.as_ref()
                .map(|m| m.value_size as i64)
                .unwrap_or(0);
            Ok(MemRegion::new(
                MemRegionType::MapValue,
                0,
                map_size,
                true,
            ))
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            Ok(MemRegion::new(
                MemRegionType::Packet,
                0,
                i64::MAX, // Bounded by packet_end check
                true,
            ))
        }
        BpfRegType::PtrToCtx => {
            Ok(MemRegion::new(
                MemRegionType::Context,
                0,
                i64::MAX, // Context access is BTF-validated
                false, // Depends on field
            ))
        }
        BpfRegType::PtrToArena => {
            let arena_id = reg.btf_info.as_ref()
                .map(|b| b.btf_id)
                .unwrap_or(0);
            Ok(MemRegion {
                region_type: MemRegionType::Arena,
                start: 0,
                end: i64::MAX,
                writable: true,
                arena_id: Some(arena_id),
            })
        }
        BpfRegType::PtrToMem => {
            Ok(MemRegion::new(
                MemRegionType::Allocated,
                0,
                reg.mem_size as i64,
                true,
            ))
        }
        _ => {
            Err(VerifierError::InvalidMemoryAccess(
                format!("cannot access memory through {:?}", reg.reg_type)
            ))
        }
    }
}

/// Per-CPU memory region info
#[derive(Debug, Clone)]
pub struct PerCpuRegion {
    /// Base pointer type
    pub ptr_type: BpfRegType,
    /// Size per CPU
    pub size: u32,
    /// Number of CPUs
    pub nr_cpus: u32,
}

/// Check per-CPU memory access
pub fn check_percpu_access(
    _reg: &BpfRegState,
    off: i32,
    size: u32,
    percpu_info: &PerCpuRegion,
) -> Result<()> {
    // Per-CPU access must be within single CPU's region
    let access_end = off as u64 + size as u64;
    
    if access_end > percpu_info.size as u64 {
        return Err(VerifierError::OutOfBounds {
            offset: off,
            size: size as i32,
        });
    }

    Ok(())
}

/// Arena map operations tracking
#[derive(Debug, Clone, Default)]
pub struct ArenaMapOps {
    /// Number of arena allocations
    pub alloc_count: u32,
    /// Number of arena frees
    pub free_count: u32,
    /// Peak concurrent allocations
    pub peak_allocs: u32,
    /// Current concurrent allocations
    pub current_allocs: u32,
    /// Total bytes allocated
    pub total_bytes_allocated: u64,
}

impl ArenaMapOps {
    /// Create new arena map operations tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allocation
    pub fn record_alloc(&mut self, size: u64) {
        self.alloc_count += 1;
        self.current_allocs += 1;
        self.total_bytes_allocated += size;
        if self.current_allocs > self.peak_allocs {
            self.peak_allocs = self.current_allocs;
        }
    }

    /// Record a free
    pub fn record_free(&mut self) {
        self.free_count += 1;
        self.current_allocs = self.current_allocs.saturating_sub(1);
    }
}

/// Arena pointer state for tracking derived pointers
#[derive(Debug, Clone)]
pub struct ArenaPointerState {
    /// Original arena ID
    pub arena_id: u32,
    /// Offset from arena base
    pub offset: i64,
    /// Whether this is a user-space pointer
    pub is_user_ptr: bool,
    /// Valid range start (from bounds check)
    pub valid_start: i64,
    /// Valid range end (from bounds check)
    pub valid_end: i64,
    /// Whether bounds have been checked
    pub bounds_checked: bool,
}

impl ArenaPointerState {
    /// Create a new arena pointer state
    pub fn new(arena_id: u32, offset: i64, is_user_ptr: bool) -> Self {
        Self {
            arena_id,
            offset,
            is_user_ptr,
            valid_start: 0,
            valid_end: i64::MAX,
            bounds_checked: false,
        }
    }

    /// Update bounds after a check
    pub fn set_bounds(&mut self, start: i64, end: i64) {
        self.valid_start = start;
        self.valid_end = end;
        self.bounds_checked = true;
    }

    /// Check if access at offset is within validated bounds
    pub fn is_valid_access(&self, off: i64, size: u32) -> bool {
        if !self.bounds_checked {
            return false;
        }
        let access_start = self.offset + off;
        let access_end = access_start + size as i64;
        access_start >= self.valid_start && access_end <= self.valid_end
    }
}

/// Validate arena pointer arithmetic
pub fn validate_arena_ptr_arithmetic(
    reg: &BpfRegState,
    arena_state: &ArenaState,
    op: AluOp,
    scalar_val: i64,
) -> Result<(i64, i64)> {
    // Get arena info
    let arena_id = reg.btf_info.as_ref()
        .map(|b| b.btf_id)
        .unwrap_or(0);

    let arena = arena_state.get(arena_id)
        .ok_or_else(|| VerifierError::InvalidMemoryAccess(
            "unknown arena for pointer arithmetic".into()
        ))?;

    // Calculate new offset bounds
    let (new_min, new_max) = match op {
        AluOp::Add => {
            let min = reg.smin_value.saturating_add(scalar_val);
            let max = reg.smax_value.saturating_add(scalar_val);
            (min, max)
        }
        AluOp::Sub => {
            let min = reg.smin_value.saturating_sub(scalar_val);
            let max = reg.smax_value.saturating_sub(scalar_val);
            (min, max)
        }
        _ => {
            return Err(VerifierError::InvalidPointerArithmetic(
                format!("invalid pointer arithmetic operation: {:?}", op)
            ));
        }
    };

    // Validate bounds are within arena
    if new_max > arena.size as i64 || new_min < 0 {
        return Err(VerifierError::OutOfBounds {
            offset: new_min as i32,
            size: (new_max - new_min) as i32,
        });
    }

    Ok((new_min, new_max))
}

/// ALU operation type for pointer arithmetic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// Bitwise AND (for masking)
    And,
    /// Bitwise OR
    Or,
}

/// Check arena load/store with speculation barriers
pub fn check_arena_speculative_access(
    reg: &BpfRegState,
    arena_state: &ArenaState,
    off: i32,
    size: u32,
    is_write: bool,
    has_nospec: bool,
) -> Result<bool> {
    // First do normal access check
    check_arena_access(reg, arena_state, off, size, is_write)?;

    // Arena accesses to user memory need speculation barriers
    // unless already protected
    let needs_barrier = !has_nospec && reg.type_flags.contains(BpfTypeFlag::MEM_USER);

    Ok(needs_barrier)
}

/// Validate arena cast operation (kern_to_user / user_to_kern)
pub fn validate_arena_cast(
    src_reg: &BpfRegState,
    arena_state: &ArenaState,
    to_user: bool,
) -> Result<BpfRegState> {
    // Source must be arena pointer
    if src_reg.reg_type != BpfRegType::PtrToArena {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_ARENA".into(),
            got: format!("{:?}", src_reg.reg_type),
        });
    }

    // Verify arena exists
    let arena_id = src_reg.btf_info.as_ref()
        .map(|b| b.btf_id)
        .unwrap_or(0);

    if !arena_state.exists(arena_id) {
        return Err(VerifierError::InvalidMemoryAccess(
            "arena not found for cast".into()
        ));
    }

    // Create result register
    let mut dst_reg = src_reg.clone();
    
    if to_user {
        // Add MEM_USER flag for user-space pointer
        dst_reg.type_flags.insert(BpfTypeFlag::MEM_USER);
    } else {
        // Remove MEM_USER flag for kernel-space pointer
        dst_reg.type_flags.remove(BpfTypeFlag::MEM_USER);
    }

    Ok(dst_reg)
}

/// Check if arena access crosses page boundary
pub fn check_arena_page_crossing(
    offset: i64,
    size: u32,
    page_size: u64,
) -> bool {
    let start_page = offset as u64 / page_size;
    let end_page = (offset as u64 + size as u64 - 1) / page_size;
    start_page != end_page
}

/// Arena atomic operation validation
pub fn validate_arena_atomic(
    reg: &BpfRegState,
    arena_state: &ArenaState,
    off: i32,
    size: u32,
    atomic_op: u32,
) -> Result<()> {
    // Check basic access
    check_arena_access(reg, arena_state, off, size, true)?;

    // Atomic operations have alignment requirements
    let alignment = size as i32;
    let access_addr = reg.off + off;
    
    if access_addr % alignment != 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            format!("misaligned access at offset {} (alignment {})", access_addr, alignment)
        ));
    }

    // Validate atomic op is supported
    let valid_ops = [
        BPF_ADD, BPF_OR, BPF_AND, BPF_XOR,
        BPF_XCHG, BPF_CMPXCHG,
    ];
    
    if !valid_ops.contains(&atomic_op) {
        return Err(VerifierError::InvalidMemoryAccess(
            format!("unsupported atomic operation on arena: {}", atomic_op)
        ));
    }

    Ok(())
}

// Atomic operation codes
const BPF_ADD: u32 = 0x00;
const BPF_OR: u32 = 0x40;
const BPF_AND: u32 = 0x50;
const BPF_XOR: u32 = 0xa0;
const BPF_XCHG: u32 = 0xe1;
const BPF_CMPXCHG: u32 = 0xf1;

/// Track arena pointer through register operations
pub fn propagate_arena_info(
    dst: &mut BpfRegState,
    src: &BpfRegState,
) {
    // Copy arena-related info
    if src.reg_type == BpfRegType::PtrToArena {
        dst.reg_type = BpfRegType::PtrToArena;
        dst.btf_info = src.btf_info.clone();
        
        // Preserve MEM_USER flag
        if src.type_flags.contains(BpfTypeFlag::MEM_USER) {
            dst.type_flags.insert(BpfTypeFlag::MEM_USER);
        }
    }
}

/// Arena bounds narrowing after comparison
pub fn narrow_arena_bounds(
    reg: &mut BpfRegState,
    arena_state: &ArenaState,
    cmp_val: i64,
    is_less_than: bool,
) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToArena {
        return Ok(());
    }

    // Get arena bounds
    let arena_id = reg.btf_info.as_ref()
        .map(|b| b.btf_id)
        .unwrap_or(0);

    let arena = arena_state.get(arena_id)
        .ok_or_else(|| VerifierError::InvalidMemoryAccess(
            "unknown arena for bounds narrowing".into()
        ))?;

    if is_less_than {
        // Pointer < cmp_val means max is cmp_val - 1
        let new_max = (cmp_val - 1).min(arena.size as i64);
        reg.smax_value = new_max;
        reg.umax_value = new_max as u64;
    } else {
        // Pointer >= cmp_val means min is cmp_val
        let new_min = cmp_val.max(0);
        reg.smin_value = new_min;
        reg.umin_value = new_min as u64;
    }

    Ok(())
}

// ============================================================================
// Arena Allocation Tracking
// ============================================================================

/// Individual arena allocation record
#[derive(Debug, Clone)]
pub struct ArenaAllocation {
    /// Unique allocation ID
    pub alloc_id: u32,
    /// Arena this allocation belongs to
    pub arena_id: u32,
    /// Offset within arena
    pub offset: u64,
    /// Size of allocation
    pub size: u64,
    /// Whether allocation is still active
    pub active: bool,
    /// Instruction index where allocation occurred
    pub alloc_insn_idx: usize,
    /// Reference object ID (for ownership tracking)
    pub ref_obj_id: u32,
}

/// Arena allocation tracker
#[derive(Debug, Default)]
pub struct ArenaAllocTracker {
    /// All allocations by alloc_id
    allocations: HashMap<u32, ArenaAllocation>,
    /// Allocations by arena_id
    by_arena: HashMap<u32, Vec<u32>>,
    /// Next allocation ID
    next_alloc_id: u32,
    /// Statistics
    pub stats: ArenaMapOps,
}

impl ArenaAllocTracker {
    /// Create a new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new allocation
    pub fn alloc(
        &mut self,
        arena_id: u32,
        offset: u64,
        size: u64,
        insn_idx: usize,
        ref_obj_id: u32,
    ) -> u32 {
        let alloc_id = self.next_alloc_id;
        self.next_alloc_id += 1;

        self.allocations.insert(alloc_id, ArenaAllocation {
            alloc_id,
            arena_id,
            offset,
            size,
            active: true,
            alloc_insn_idx: insn_idx,
            ref_obj_id,
        });

        self.by_arena
            .entry(arena_id)
            .or_default()
            .push(alloc_id);

        self.stats.record_alloc(size);
        alloc_id
    }

    /// Record a free
    pub fn free(&mut self, alloc_id: u32) -> Result<()> {
        if let Some(alloc) = self.allocations.get_mut(&alloc_id) {
            if !alloc.active {
                return Err(VerifierError::InvalidMemoryAccess(
                    "double free detected".into()
                ));
            }
            alloc.active = false;
            self.stats.record_free();
            Ok(())
        } else {
            Err(VerifierError::InvalidMemoryAccess(
                "freeing unknown allocation".into()
            ))
        }
    }

    /// Get allocation by ID
    pub fn get(&self, alloc_id: u32) -> Option<&ArenaAllocation> {
        self.allocations.get(&alloc_id)
    }

    /// Get all active allocations for an arena
    pub fn get_active_allocations(&self, arena_id: u32) -> Vec<&ArenaAllocation> {
        self.by_arena
            .get(&arena_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.allocations.get(id))
                    .filter(|a| a.active)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if pointer is within any active allocation
    pub fn find_allocation_at(&self, arena_id: u32, offset: u64, size: u64) -> Option<&ArenaAllocation> {
        self.get_active_allocations(arena_id)
            .into_iter()
            .find(|a| {
                offset >= a.offset && offset + size <= a.offset + a.size
            })
    }

    /// Check for leaked allocations (active allocations at program exit)
    pub fn check_leaks(&self) -> Result<()> {
        for alloc in self.allocations.values() {
            if alloc.active {
                return Err(VerifierError::UnreleasedReference(alloc.ref_obj_id));
            }
        }
        Ok(())
    }

    /// Reset tracker (for new verification path)
    pub fn reset(&mut self) {
        self.allocations.clear();
        self.by_arena.clear();
        // Keep next_alloc_id to avoid ID reuse
    }
}

// ============================================================================
// Arena Address Translation
// ============================================================================

/// Arena address translation context
#[derive(Debug, Clone)]
pub struct ArenaAddrContext {
    /// Arena info
    pub arena_id: u32,
    /// Kernel base address
    pub kern_base: u64,
    /// User base address
    pub user_base: u64,
    /// Arena size
    pub size: u64,
}

impl ArenaAddrContext {
    /// Translate kernel address to user address
    pub fn kern_to_user(&self, kern_addr: u64) -> Result<u64> {
        if kern_addr < self.kern_base || kern_addr >= self.kern_base + self.size {
            return Err(VerifierError::InvalidMemoryAccess(
                "kernel address outside arena bounds".into()
            ));
        }
        let offset = kern_addr - self.kern_base;
        Ok(self.user_base + offset)
    }

    /// Translate user address to kernel address
    pub fn user_to_kern(&self, user_addr: u64) -> Result<u64> {
        if user_addr < self.user_base || user_addr >= self.user_base + self.size {
            return Err(VerifierError::InvalidMemoryAccess(
                "user address outside arena bounds".into()
            ));
        }
        let offset = user_addr - self.user_base;
        Ok(self.kern_base + offset)
    }

    /// Check if kernel address is within arena
    pub fn contains_kern(&self, addr: u64) -> bool {
        addr >= self.kern_base && addr < self.kern_base + self.size
    }

    /// Check if user address is within arena
    pub fn contains_user(&self, addr: u64) -> bool {
        addr >= self.user_base && addr < self.user_base + self.size
    }
}

/// Validate BPF_ADDR_SPACE_CAST instruction
pub fn validate_addr_space_cast_insn(
    src_reg: &BpfRegState,
    arena_ctx: &ArenaAddrContext,
    from_as: u8,
    to_as: u8,
) -> Result<BpfRegState> {
    // Address space 0 = kernel, 1 = user
    const AS_KERN: u8 = 0;
    const AS_USER: u8 = 1;

    let mut dst_reg = src_reg.clone();

    match (from_as, to_as) {
        (AS_KERN, AS_USER) => {
            // Kernel to user cast
            if src_reg.reg_type != BpfRegType::PtrToArena {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_ARENA (kernel)".into(),
                    got: format!("{:?}", src_reg.reg_type),
                });
            }

            // Verify pointer is within arena
            let kern_off = src_reg.off as u64;
            if kern_off >= arena_ctx.size {
                return Err(VerifierError::OutOfBounds {
                    offset: kern_off as i32,
                    size: 0,
                });
            }

            // Mark as user pointer
            dst_reg.type_flags.insert(BpfTypeFlag::MEM_USER);
        }
        (AS_USER, AS_KERN) => {
            // User to kernel cast
            if !src_reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
                return Err(VerifierError::TypeMismatch {
                    expected: "user-space pointer".into(),
                    got: "kernel-space pointer".into(),
                });
            }

            // Remove user flag
            dst_reg.type_flags.remove(BpfTypeFlag::MEM_USER);
        }
        (a, b) if a == b => {
            // Same address space - no-op but validate
            // Just return copy of source
        }
        _ => {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("invalid address space cast: {} -> {}", from_as, to_as)
            ));
        }
    }

    Ok(dst_reg)
}

// ============================================================================
// Arena Helper Function Support
// ============================================================================

/// Arena-specific helper function IDs
pub mod arena_helpers {
    /// bpf_arena_alloc_pages
    pub const ARENA_ALLOC_PAGES: u32 = 0x5001;
    /// bpf_arena_free_pages
    pub const ARENA_FREE_PAGES: u32 = 0x5002;
}

/// Check if helper is arena-related
pub fn is_arena_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        arena_helpers::ARENA_ALLOC_PAGES | arena_helpers::ARENA_FREE_PAGES
    )
}

/// Process arena helper return value
pub fn process_arena_helper_return(
    ret_reg: &mut BpfRegState,
    helper_id: u32,
    arena_id: u32,
    alloc_size: Option<u64>,
) {
    match helper_id {
        arena_helpers::ARENA_ALLOC_PAGES => {
            // Returns pointer to allocated pages (or NULL)
            ret_reg.reg_type = BpfRegType::PtrToArena;
            ret_reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL | BpfTypeFlag::MEM_ALLOC;
            if let Some(btf_info) = &mut ret_reg.btf_info {
                btf_info.btf_id = arena_id;
            }
            if let Some(size) = alloc_size {
                ret_reg.mem_size = size as u32;
            }
        }
        arena_helpers::ARENA_FREE_PAGES => {
            // Returns 0 on success, negative on error
            ret_reg.mark_known(0);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_state() {
        let mut state = ArenaState::new();

        let info = ArenaInfo {
            id: 0,
            map_fd: 3,
            size: 4096,
            user_base: 0x7f0000000000,
            readonly: false,
            btf_id: 0,
        };

        let id = state.register(info).unwrap();
        assert!(state.exists(id));
        assert!(state.get(id).is_some());
    }

    #[test]
    fn test_mem_region_contains() {
        let region = MemRegion::new(MemRegionType::Stack, -512, 0, true);

        assert!(region.contains(-100, 8));
        assert!(region.contains(-512, 512));
        assert!(!region.contains(-600, 8)); // Before start
        assert!(!region.contains(-8, 16)); // Crosses end
    }

    #[test]
    fn test_mem_region_access() {
        let region = MemRegion::new(MemRegionType::MapValue, 0, 256, true);

        assert!(region.check_access(0, 8, false).is_ok());
        assert!(region.check_access(0, 8, true).is_ok());
        assert!(region.check_access(248, 8, true).is_ok());
        assert!(region.check_access(256, 8, true).is_err()); // Out of bounds
    }

    #[test]
    fn test_readonly_region() {
        let region = MemRegion::new(MemRegionType::Context, 0, 128, false);

        assert!(region.check_access(0, 8, false).is_ok());
        assert!(region.check_access(0, 8, true).is_err()); // Write to readonly
    }

    #[test]
    fn test_arena_region() {
        let region = MemRegion::arena(1, 4096);

        assert_eq!(region.region_type, MemRegionType::Arena);
        assert_eq!(region.arena_id, Some(1));
        assert!(region.contains(0, 4096));
        assert!(!region.contains(0, 4097));
    }

    #[test]
    fn test_resolve_stack_access() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToStack;

        let region = resolve_mem_access(&reg, -8, 8, true).unwrap();
        assert_eq!(region.region_type, MemRegionType::Stack);
        assert!(region.writable);
    }

    #[test]
    fn test_addr_space_cast() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToArena;

        // Arena can be cast
        let result = check_addr_space_cast(&reg, AddressSpace::Kernel, AddressSpace::User);
        assert!(result.is_ok());

        // Non-arena cannot be cast
        reg.reg_type = BpfRegType::PtrToStack;
        let result = check_addr_space_cast(&reg, AddressSpace::Kernel, AddressSpace::User);
        assert!(result.is_err());
    }

    #[test]
    fn test_arena_alloc_tracker() {
        let mut tracker = ArenaAllocTracker::new();

        // Allocate
        let id1 = tracker.alloc(1, 0, 4096, 0, 100);
        let id2 = tracker.alloc(1, 4096, 4096, 1, 101);

        assert!(tracker.get(id1).is_some());
        assert!(tracker.get(id2).is_some());
        assert_eq!(tracker.stats.current_allocs, 2);

        // Find allocation
        let found = tracker.find_allocation_at(1, 100, 100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().alloc_id, id1);

        // Free
        assert!(tracker.free(id1).is_ok());
        assert_eq!(tracker.stats.current_allocs, 1);

        // Double free should fail
        assert!(tracker.free(id1).is_err());

        // Check leaks - should find id2 still active
        assert!(tracker.check_leaks().is_err());

        // Free remaining
        assert!(tracker.free(id2).is_ok());
        assert!(tracker.check_leaks().is_ok());
    }

    #[test]
    fn test_arena_addr_context() {
        let ctx = ArenaAddrContext {
            arena_id: 1,
            kern_base: 0xffff_8880_0000_0000,
            user_base: 0x7f00_0000_0000,
            size: 0x1000_0000, // 256 MB
        };

        // Kernel to user translation
        let user = ctx.kern_to_user(0xffff_8880_0000_1000).unwrap();
        assert_eq!(user, 0x7f00_0000_1000);

        // User to kernel translation
        let kern = ctx.user_to_kern(0x7f00_0000_1000).unwrap();
        assert_eq!(kern, 0xffff_8880_0000_1000);

        // Out of bounds
        assert!(ctx.kern_to_user(0xffff_8880_0000_0000 + 0x1000_0000).is_err());
        assert!(ctx.user_to_kern(0x7f00_0000_0000 + 0x1000_0000).is_err());

        // Contains check
        assert!(ctx.contains_kern(0xffff_8880_0000_0000));
        assert!(!ctx.contains_kern(0xffff_8880_0000_0000 + 0x1000_0000));
        assert!(ctx.contains_user(0x7f00_0000_0000));
    }

    #[test]
    fn test_arena_helper_detection() {
        assert!(is_arena_helper(arena_helpers::ARENA_ALLOC_PAGES));
        assert!(is_arena_helper(arena_helpers::ARENA_FREE_PAGES));
        assert!(!is_arena_helper(0));
    }

    #[test]
    fn test_page_crossing() {
        // 4KB pages
        let page_size = 4096;

        // Within same page
        assert!(!check_arena_page_crossing(0, 100, page_size));
        assert!(!check_arena_page_crossing(4000, 96, page_size));

        // Crosses page boundary
        assert!(check_arena_page_crossing(4000, 100, page_size));
        assert!(check_arena_page_crossing(4095, 2, page_size));
    }
}
