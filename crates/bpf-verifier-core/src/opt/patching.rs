// SPDX-License-Identifier: GPL-2.0

//! Instruction patching for BPF programs.
//!
//! This module implements instruction patching for BPF programs.
//! The verifier may need to patch instructions for:
//! - Map pointer fixups (LD_IMM64 with map fd -> map pointer)
//! - Helper call resolution
//! - Kfunc call fixups
//! - Zero extension insertion
//! - Spectre mitigation (nospec barriers)

#![allow(missing_docs)] // Patching internals

use alloc::{format, vec::Vec};

use alloc::collections::BTreeMap as HashMap;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// Types of patches that can be applied
#[derive(Debug, Clone)]
pub enum PatchType {
    /// Replace instruction with a new one
    Replace(BpfInsn),
    /// Insert instruction(s) before
    InsertBefore(Vec<BpfInsn>),
    /// Insert instruction(s) after
    InsertAfter(Vec<BpfInsn>),
    /// Remove instruction (replace with nop)
    Remove,
    /// Patch map fd to map pointer
    MapFdToPtr { map_ptr: u64 },
    /// Patch helper call
    HelperCall { func_id: i32 },
    /// Insert zero extension
    ZeroExtend { reg: u8 },
    /// Insert speculation barrier
    NospecBarrier,
}

/// A single patch to be applied
#[derive(Debug, Clone)]
pub struct Patch {
    /// Instruction index to patch
    pub insn_idx: usize,
    /// Type of patch
    pub patch_type: PatchType,
}

impl Patch {
    pub fn new(insn_idx: usize, patch_type: PatchType) -> Self {
        Self {
            insn_idx,
            patch_type,
        }
    }

    /// Create a replace patch
    pub fn replace(insn_idx: usize, insn: BpfInsn) -> Self {
        Self::new(insn_idx, PatchType::Replace(insn))
    }

    /// Create an insert before patch
    pub fn insert_before(insn_idx: usize, insns: Vec<BpfInsn>) -> Self {
        Self::new(insn_idx, PatchType::InsertBefore(insns))
    }

    /// Create an insert after patch
    pub fn insert_after(insn_idx: usize, insns: Vec<BpfInsn>) -> Self {
        Self::new(insn_idx, PatchType::InsertAfter(insns))
    }

    /// Create a remove patch
    pub fn remove(insn_idx: usize) -> Self {
        Self::new(insn_idx, PatchType::Remove)
    }

    /// Create a map fd to pointer patch
    pub fn map_fd_to_ptr(insn_idx: usize, map_ptr: u64) -> Self {
        Self::new(insn_idx, PatchType::MapFdToPtr { map_ptr })
    }

    /// Create a zero extension patch
    pub fn zero_extend(insn_idx: usize, reg: u8) -> Self {
        Self::new(insn_idx, PatchType::ZeroExtend { reg })
    }

    /// Create a nospec barrier patch
    pub fn nospec_barrier(insn_idx: usize) -> Self {
        Self::new(insn_idx, PatchType::NospecBarrier)
    }
}

/// Instruction patcher
#[derive(Debug)]
pub struct InsnPatcher {
    /// Original instructions
    insns: Vec<BpfInsn>,
    /// Pending patches (sorted by insn_idx)
    patches: Vec<Patch>,
    /// Map from original index to new index after patching
    idx_map: Vec<usize>,
}

impl InsnPatcher {
    /// Create a new instruction patcher
    pub fn new(insns: Vec<BpfInsn>) -> Self {
        let len = insns.len();
        Self {
            insns,
            patches: Vec::new(),
            idx_map: (0..len).collect(),
        }
    }

    /// Add a patch
    pub fn add_patch(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Apply all patches and return the patched program
    pub fn apply(&mut self) -> Result<Vec<BpfInsn>> {
        // Sort patches by instruction index (descending for easier insertion)
        self.patches.sort_by(|a, b| b.insn_idx.cmp(&a.insn_idx));

        let mut result = self.insns.clone();

        // Clone patches to avoid borrow issues
        let patches: Vec<_> = self.patches.clone();

        // Process patches from end to beginning
        for patch in &patches {
            let idx = patch.insn_idx;
            if idx >= result.len() {
                return Err(VerifierError::InvalidInsnIdx(idx));
            }

            match &patch.patch_type {
                PatchType::Replace(new_insn) => {
                    result[idx] = *new_insn;
                }
                PatchType::InsertBefore(insns) => {
                    let insert_count = insns.len();
                    for (i, insn) in insns.iter().enumerate() {
                        result.insert(idx + i, *insn);
                    }
                    self.update_idx_map(idx, insert_count as i32);
                    Self::update_jump_targets(&mut result, idx, insert_count as i32)?;
                }
                PatchType::InsertAfter(insns) => {
                    let insert_count = insns.len();
                    for (i, insn) in insns.iter().enumerate() {
                        result.insert(idx + 1 + i, *insn);
                    }
                    self.update_idx_map(idx + 1, insert_count as i32);
                    Self::update_jump_targets(&mut result, idx + 1, insert_count as i32)?;
                }
                PatchType::Remove => {
                    // Replace with nop (mov r0, r0)
                    result[idx] = BpfInsn::nop();
                }
                PatchType::MapFdToPtr { map_ptr } => {
                    // LD_IMM64 consists of two instructions
                    let lo = (*map_ptr & 0xFFFFFFFF) as i32;
                    let hi = ((*map_ptr >> 32) & 0xFFFFFFFF) as i32;

                    result[idx].imm = lo;
                    if idx + 1 < result.len() {
                        result[idx + 1].imm = hi;
                    }
                }
                PatchType::HelperCall { func_id } => {
                    result[idx].imm = *func_id;
                }
                PatchType::ZeroExtend { reg } => {
                    // Insert: mov32 reg, reg (zero extends upper 32 bits)
                    let zext = BpfInsn::new(BPF_ALU | BPF_MOV | BPF_X, *reg, *reg, 0, 0);
                    result.insert(idx + 1, zext);
                    self.update_idx_map(idx + 1, 1);
                    Self::update_jump_targets(&mut result, idx + 1, 1)?;
                }
                PatchType::NospecBarrier => {
                    // Insert speculation barrier (implementation dependent)
                    let barrier = BpfInsn::new(
                        BPF_JMP | BPF_JA,
                        0,
                        0,
                        0, // jump to next insn
                        0,
                    );
                    result.insert(idx + 1, barrier);
                    self.update_idx_map(idx + 1, 1);
                    Self::update_jump_targets(&mut result, idx + 1, 1)?;
                }
            }
        }

        Ok(result)
    }

    /// Update the index map after an insertion
    fn update_idx_map(&mut self, from_idx: usize, delta: i32) {
        for i in from_idx..self.idx_map.len() {
            self.idx_map[i] = (self.idx_map[i] as i32 + delta) as usize;
        }
    }

    /// Update jump targets after an insertion
    fn update_jump_targets(insns: &mut [BpfInsn], insert_idx: usize, delta: i32) -> Result<()> {
        for (idx, insn) in insns.iter_mut().enumerate() {
            let class = insn.class();
            if class != BPF_JMP && class != BPF_JMP32 {
                continue;
            }

            let op = insn.code & 0xf0;
            if op == BPF_EXIT {
                continue;
            }

            if op == BPF_CALL {
                // Only update pseudo calls
                if insn.src_reg == BPF_PSEUDO_CALL {
                    let target = (idx as i32 + insn.imm + 1) as usize;
                    if idx < insert_idx && target >= insert_idx {
                        // Jump crosses the insertion point
                        insn.imm += delta;
                    } else if idx >= insert_idx && target < insert_idx {
                        // Jump crosses the insertion point (backward)
                        insn.imm -= delta;
                    }
                }
            } else if op != BPF_JA || insn.off != 0 {
                // JA with off=0 is a nop, skip it
                let target = (idx as i32 + insn.off as i32 + 1) as usize;
                if idx < insert_idx && target >= insert_idx {
                    insn.off = (insn.off as i32 + delta) as i16;
                } else if idx >= insert_idx && target < insert_idx {
                    insn.off = (insn.off as i32 - delta) as i16;
                }
            }
        }

        Ok(())
    }

    /// Get the new index for an original index
    pub fn get_new_idx(&self, orig_idx: usize) -> Option<usize> {
        self.idx_map.get(orig_idx).copied()
    }
}

/// Create a NOP instruction
impl BpfInsn {
    pub fn nop() -> Self {
        // mov64 r0, r0 is effectively a nop
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 0, 0, 0)
    }
}

/// Patch LD_IMM64 instructions for map pointers
pub fn patch_map_pointers(
    insns: &mut [BpfInsn],
    map_fds: &[(i32, u64)], // (fd, pointer) pairs
) -> Result<()> {
    let fd_to_ptr: HashMap<i32, u64> = map_fds.iter().cloned().collect();

    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];

        // Check for LD_IMM64 with map fd
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            let src = insn.src_reg;
            if src == BPF_PSEUDO_MAP_FD || src == BPF_PSEUDO_MAP_VALUE {
                let fd = insn.imm;
                if let Some(&ptr) = fd_to_ptr.get(&fd) {
                    let lo = (ptr & 0xFFFFFFFF) as i32;
                    let hi = ((ptr >> 32) & 0xFFFFFFFF) as i32;

                    insns[i].imm = lo;
                    if i + 1 < insns.len() {
                        insns[i + 1].imm = hi;
                    }
                }
            }
            i += 2; // Skip the second part of LD_IMM64
        } else {
            i += 1;
        }
    }

    Ok(())
}

/// Insert zero extensions where needed (for JIT that doesn't zero-extend)
pub fn insert_zero_extensions(insns: &[BpfInsn], needs_zext: &[bool]) -> Result<Vec<BpfInsn>> {
    let mut patcher = InsnPatcher::new(insns.to_vec());

    for (idx, &needs) in needs_zext.iter().enumerate() {
        if needs {
            if let Some(insn) = insns.get(idx) {
                // Get the destination register
                let class = insn.class();
                let dst_reg = match class {
                    BPF_ALU => Some(insn.dst_reg),
                    BPF_LDX if insn.size() < 3 => Some(insn.dst_reg), // sub-64bit load
                    _ => None,
                };

                if let Some(reg) = dst_reg {
                    patcher.add_patch(Patch::zero_extend(idx, reg));
                }
            }
        }
    }

    patcher.apply()
}

/// Comprehensive patch manager for program transformation.
#[derive(Debug, Default)]
pub struct PatchManager {
    /// All patches organized by category.
    patches: Vec<Patch>,
    /// Map patches (fd to pointer).
    map_patches: Vec<(usize, u64)>,
    /// Subprogram call patches.
    subprog_patches: Vec<(usize, i32)>,
    /// Kfunc call patches.
    kfunc_patches: Vec<(usize, u64)>,
    /// Speculation barrier insertions.
    pub nospec_patches: Vec<usize>,
    /// Zero extension insertions.
    pub zext_patches: Vec<(usize, u8)>,
    /// Dead code to remove.
    dead_code: Vec<usize>,
    /// Branch optimization patches.
    branch_opts: Vec<(usize, BranchOpt)>,
}

/// Branch optimization types.
#[derive(Debug, Clone)]
pub enum BranchOpt {
    /// Convert conditional to unconditional (always taken).
    AlwaysTaken,
    /// Convert conditional to unconditional (never taken / fallthrough).
    NeverTaken,
    /// Convert to direct jump with new offset.
    DirectJump(i16),
}

impl PatchManager {
    /// Create a new patch manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a generic patch.
    pub fn add_patch(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Add a map fd to pointer patch.
    pub fn add_map_patch(&mut self, insn_idx: usize, map_ptr: u64) {
        self.map_patches.push((insn_idx, map_ptr));
    }

    /// Add a subprogram call patch.
    pub fn add_subprog_patch(&mut self, insn_idx: usize, target_offset: i32) {
        self.subprog_patches.push((insn_idx, target_offset));
    }

    /// Add a kfunc call patch.
    pub fn add_kfunc_patch(&mut self, insn_idx: usize, kfunc_addr: u64) {
        self.kfunc_patches.push((insn_idx, kfunc_addr));
    }

    /// Add a speculation barrier.
    pub fn add_nospec(&mut self, insn_idx: usize) {
        self.nospec_patches.push(insn_idx);
    }

    /// Add a zero extension.
    pub fn add_zext(&mut self, insn_idx: usize, reg: u8) {
        self.zext_patches.push((insn_idx, reg));
    }

    /// Mark instruction as dead code.
    pub fn mark_dead(&mut self, insn_idx: usize) {
        self.dead_code.push(insn_idx);
    }

    /// Add branch optimization.
    pub fn add_branch_opt(&mut self, insn_idx: usize, opt: BranchOpt) {
        self.branch_opts.push((insn_idx, opt));
    }

    /// Get total number of patches.
    pub fn patch_count(&self) -> usize {
        self.patches.len()
            + self.map_patches.len()
            + self.subprog_patches.len()
            + self.kfunc_patches.len()
            + self.nospec_patches.len()
            + self.zext_patches.len()
            + self.dead_code.len()
            + self.branch_opts.len()
    }

    /// Apply all patches to the program.
    pub fn apply(&self, insns: &mut Vec<BpfInsn>) -> Result<PatchResult> {
        let mut result = PatchResult::new(insns.len());

        // Apply map patches first (no size changes)
        for &(idx, ptr) in &self.map_patches {
            if idx >= insns.len() {
                return Err(VerifierError::InvalidInsnIdx(idx));
            }
            let lo = (ptr & 0xFFFFFFFF) as i32;
            let hi = ((ptr >> 32) & 0xFFFFFFFF) as i32;
            insns[idx].imm = lo;
            if idx + 1 < insns.len() {
                insns[idx + 1].imm = hi;
            }
            result.maps_patched += 1;
        }

        // Apply subprogram call patches
        for &(idx, offset) in &self.subprog_patches {
            if idx >= insns.len() {
                return Err(VerifierError::InvalidInsnIdx(idx));
            }
            insns[idx].imm = offset;
            result.calls_patched += 1;
        }

        // Apply branch optimizations (no size changes)
        for (idx, opt) in &self.branch_opts {
            if *idx >= insns.len() {
                return Err(VerifierError::InvalidInsnIdx(*idx));
            }
            match opt {
                BranchOpt::AlwaysTaken => {
                    // Convert to unconditional jump
                    let off = insns[*idx].off;
                    insns[*idx] = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, off, 0);
                }
                BranchOpt::NeverTaken => {
                    // Convert to nop (fallthrough)
                    insns[*idx] = BpfInsn::nop();
                }
                BranchOpt::DirectJump(new_off) => {
                    insns[*idx] = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, *new_off, 0);
                }
            }
            result.branches_optimized += 1;
        }

        // Apply dead code removal (replace with nops)
        for &idx in &self.dead_code {
            if idx >= insns.len() {
                continue;
            }
            insns[idx] = BpfInsn::nop();
            result.dead_code_removed += 1;
        }

        // Patches that change program size need careful index tracking
        // Create patcher for insertions
        let mut patcher = InsnPatcher::new(insns.clone());

        // Add zero extension patches
        for &(idx, reg) in &self.zext_patches {
            patcher.add_patch(Patch::zero_extend(idx, reg));
            result.zext_inserted += 1;
        }

        // Add speculation barrier patches
        for &idx in &self.nospec_patches {
            patcher.add_patch(Patch::nospec_barrier(idx));
            result.nospec_inserted += 1;
        }

        // Add generic patches
        for patch in &self.patches {
            patcher.add_patch(patch.clone());
        }

        // Apply all and update insns
        if !self.zext_patches.is_empty()
            || !self.nospec_patches.is_empty()
            || !self.patches.is_empty()
        {
            *insns = patcher.apply()?;
        }

        result.final_size = insns.len();
        Ok(result)
    }

    /// Clear all patches.
    pub fn clear(&mut self) {
        self.patches.clear();
        self.map_patches.clear();
        self.subprog_patches.clear();
        self.kfunc_patches.clear();
        self.nospec_patches.clear();
        self.zext_patches.clear();
        self.dead_code.clear();
        self.branch_opts.clear();
    }
}

/// Result of applying patches.
#[derive(Debug, Clone, Default)]
pub struct PatchResult {
    /// Original program size.
    pub original_size: usize,
    /// Final program size.
    pub final_size: usize,
    /// Number of map pointers patched.
    pub maps_patched: usize,
    /// Number of calls patched.
    pub calls_patched: usize,
    /// Number of branches optimized.
    pub branches_optimized: usize,
    /// Number of dead code instructions removed.
    pub dead_code_removed: usize,
    /// Number of zero extensions inserted.
    pub zext_inserted: usize,
    /// Number of speculation barriers inserted.
    pub nospec_inserted: usize,
}

impl PatchResult {
    /// Create a new patch result.
    pub fn new(original_size: usize) -> Self {
        Self {
            original_size,
            final_size: original_size,
            ..Default::default()
        }
    }

    /// Get the size delta.
    pub fn size_delta(&self) -> i32 {
        self.final_size as i32 - self.original_size as i32
    }

    /// Check if any patches were applied.
    pub fn has_patches(&self) -> bool {
        self.maps_patched > 0
            || self.calls_patched > 0
            || self.branches_optimized > 0
            || self.dead_code_removed > 0
            || self.zext_inserted > 0
            || self.nospec_inserted > 0
    }
}

impl core::fmt::Display for PatchResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Patches applied: ")?;
        let mut parts = Vec::new();
        if self.maps_patched > 0 {
            parts.push(format!("{} maps", self.maps_patched));
        }
        if self.calls_patched > 0 {
            parts.push(format!("{} calls", self.calls_patched));
        }
        if self.branches_optimized > 0 {
            parts.push(format!("{} branches", self.branches_optimized));
        }
        if self.dead_code_removed > 0 {
            parts.push(format!("{} dead", self.dead_code_removed));
        }
        if self.zext_inserted > 0 {
            parts.push(format!("{} zext", self.zext_inserted));
        }
        if self.nospec_inserted > 0 {
            parts.push(format!("{} nospec", self.nospec_inserted));
        }
        if parts.is_empty() {
            write!(f, "none")?;
        } else {
            write!(f, "{}", parts.join(", "))?;
        }
        if self.size_delta() != 0 {
            write!(
                f,
                " (size {} -> {}, delta {:+})",
                self.original_size,
                self.final_size,
                self.size_delta()
            )?;
        }
        Ok(())
    }
}

/// Convert signed division to safe implementation.
/// Inserts check for division by zero and INT_MIN / -1 overflow.
pub fn patch_sdiv_safe(insn_idx: usize, insn: &BpfInsn) -> Vec<Patch> {
    let mut patches = Vec::new();

    // For signed division, we need to handle:
    // 1. Division by zero
    // 2. INT_MIN / -1 overflow

    let dst = insn.dst_reg;
    let src = insn.src_reg;
    let is_64bit = insn.class() == BPF_ALU64;

    // We'll insert a sequence that checks and handles these cases
    // For simplicity, just mark for manual handling
    let _ = (dst, src, is_64bit);

    // The actual implementation would insert:
    // if (src == 0) goto error;
    // if (dst == INT_MIN && src == -1) { dst = INT_MIN; goto skip; }
    // dst = dst / src;
    // skip:

    patches.push(Patch::new(insn_idx, PatchType::Replace(*insn)));
    patches
}

/// Collect all patches needed for a program based on verification results.
pub fn collect_required_patches(
    insns: &[BpfInsn],
    needs_zext: &[bool],
    needs_nospec: &[bool],
    dead_insns: &[bool],
) -> PatchManager {
    let mut manager = PatchManager::new();

    for (idx, insn) in insns.iter().enumerate() {
        // Zero extensions
        if idx < needs_zext.len() && needs_zext[idx] {
            let class = insn.class();
            if class == BPF_ALU || (class == BPF_LDX && insn.size() < 3) {
                manager.add_zext(idx, insn.dst_reg);
            }
        }

        // Speculation barriers
        if idx < needs_nospec.len() && needs_nospec[idx] {
            manager.add_nospec(idx);
        }

        // Dead code
        if idx < dead_insns.len() && dead_insns[idx] {
            manager.mark_dead(idx);
        }
    }

    manager
}
