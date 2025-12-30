// SPDX-License-Identifier: GPL-2.0

//! BPF 程序加载和入口点模块
//!
//! BPF Program Loading and Entry Point.
//!
//! 本模块实现 BPF 程序验证的主入口点（`bpf_check`）及相关加载功能。
//!
//! This module implements the main entry point for BPF program verification
//! (`bpf_check`) and related loading functionality.
//!
//! # 加载过程 / Loading Process
//!
//! 1. 解析和验证程序指令 / Parsing and validating program instructions
//! 2. 解析 map FD 引用 / Resolving map FD references (LD_IMM64 with pseudo src)
//! 3. 解析子程序调用 / Resolving subprogram calls
//! 4. 运行验证器 / Running the verifier
//! 5. 应用验证后修复 / Applying post-verification fixups
//!
//! 对应内核 verifier.c 中的 `bpf_check()` 函数。
//!
//! This corresponds to the kernel's `bpf_check()` function in verifier.c.

#![allow(missing_docs)]

use alloc::{format, string::String, vec::Vec};

use alloc::collections::BTreeMap as HashMap;

use crate::analysis::cfg::ControlFlowGraph;
use crate::core::error::{Result, VerifierError};
use crate::core::log::LogLevel;
use crate::core::types::*;
use crate::opt::misc_fixups::{do_misc_fixups, FixupContext};
use crate::opt::patching::patch_map_pointers;
use crate::state::reg_state::MapInfo;

use super::env::{BpfAttachType, SubprogInfoEntry, VerifierCaps, VerifierEnv};
use super::main_loop::MainVerifier;

/// Information about a BPF map for FD resolution.
#[derive(Debug, Clone)]
pub struct BpfMapInfo {
    /// File descriptor (user-space reference).
    pub fd: i32,
    /// Map type.
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Map flags.
    pub flags: u32,
    /// Kernel-space map pointer (for patching).
    pub map_ptr: u64,
    /// BTF key type ID (if BTF-defined).
    pub btf_key_type_id: u32,
    /// BTF value type ID (if BTF-defined).
    pub btf_value_type_id: u32,
    /// Map name (if available).
    pub name: String,
}

impl BpfMapInfo {
    /// Create a new map info.
    pub fn new(fd: i32, map_type: u32, map_ptr: u64) -> Self {
        Self {
            fd,
            map_type,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            flags: 0,
            map_ptr,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            name: String::new(),
        }
    }

    /// Convert to internal MapInfo for verifier state.
    pub fn to_map_info(&self) -> MapInfo {
        // Convert u32 to BpfMapType enum
        let map_type = match self.map_type {
            1 => BpfMapType::Hash,
            2 => BpfMapType::Array,
            3 => BpfMapType::ProgArray,
            4 => BpfMapType::PerfEventArray,
            5 => BpfMapType::PercpuHash,
            6 => BpfMapType::PercpuArray,
            7 => BpfMapType::StackTrace,
            8 => BpfMapType::CgroupArray,
            9 => BpfMapType::LruHash,
            10 => BpfMapType::LruPercpuHash,
            11 => BpfMapType::LpmTrie,
            12 => BpfMapType::ArrayOfMaps,
            13 => BpfMapType::HashOfMaps,
            14 => BpfMapType::Devmap,
            15 => BpfMapType::Sockmap,
            16 => BpfMapType::Cpumap,
            17 => BpfMapType::Xskmap,
            18 => BpfMapType::Sockhash,
            19 => BpfMapType::CgroupStorage,
            20 => BpfMapType::ReuseportSockarray,
            21 => BpfMapType::PercpuCgroupStorage,
            22 => BpfMapType::Queue,
            23 => BpfMapType::Stack,
            24 => BpfMapType::SkStorage,
            25 => BpfMapType::DevmapHash,
            26 => BpfMapType::StructOps,
            27 => BpfMapType::Ringbuf,
            28 => BpfMapType::InodeStorage,
            29 => BpfMapType::TaskStorage,
            30 => BpfMapType::BloomFilter,
            31 => BpfMapType::UserRingbuf,
            32 => BpfMapType::CgrpStorage,
            33 => BpfMapType::Arena,
            _ => BpfMapType::Unspec,
        };
        MapInfo {
            map_type,
            key_size: self.key_size,
            value_size: self.value_size,
            max_entries: self.max_entries,
        }
    }
}

/// FD array for resolving pseudo LD_IMM64 instructions.
///
/// The kernel passes an array of file descriptors that the verifier
/// uses to resolve BPF_PSEUDO_MAP_FD and BPF_PSEUDO_MAP_VALUE references
/// in LD_IMM64 instructions.
#[derive(Debug, Clone, Default)]
pub struct FdArray {
    /// Map from FD to map info.
    maps: HashMap<i32, BpfMapInfo>,
    /// Map from FD to BTF info (for kfuncs).
    btf_fds: HashMap<i32, u64>,
}

impl FdArray {
    /// Create a new empty FD array.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a map to the FD array.
    pub fn add_map(&mut self, info: BpfMapInfo) {
        self.maps.insert(info.fd, info);
    }

    /// Add a BTF FD reference.
    pub fn add_btf(&mut self, fd: i32, btf_ptr: u64) {
        self.btf_fds.insert(fd, btf_ptr);
    }

    /// Look up a map by FD.
    pub fn get_map(&self, fd: i32) -> Option<&BpfMapInfo> {
        self.maps.get(&fd)
    }

    /// Look up BTF by FD.
    pub fn get_btf(&self, fd: i32) -> Option<u64> {
        self.btf_fds.get(&fd).copied()
    }

    /// Get all map FD to pointer pairs for patching.
    pub fn get_map_fd_ptrs(&self) -> Vec<(i32, u64)> {
        self.maps
            .iter()
            .map(|(fd, info)| (*fd, info.map_ptr))
            .collect()
    }

    /// Number of maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

/// Options for BPF program loading and verification.
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Program type.
    pub prog_type: BpfProgType,
    /// Expected attach type.
    pub expected_attach_type: BpfAttachType,
    /// Whether the program runs in privileged mode.
    pub is_privileged: bool,
    /// Log level for verification output.
    pub log_level: LogLevel,
    /// Verifier capabilities (kernel version dependent).
    pub caps: VerifierCaps,
    /// Whether the program is sleepable.
    pub prog_sleepable: bool,
    /// License string (affects helper availability).
    pub license: String,
    /// Kernel version (for compatibility checks).
    pub kern_version: u32,
    /// BTF ID for the program type.
    pub attach_btf_id: u32,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Unspec,
            expected_attach_type: BpfAttachType::None,
            is_privileged: false,
            log_level: LogLevel::Info,
            caps: VerifierCaps::modern(),
            prog_sleepable: false,
            license: String::new(),
            kern_version: 0,
            attach_btf_id: 0,
        }
    }
}

impl LoadOptions {
    /// Create options for privileged mode with modern capabilities.
    pub fn privileged(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            is_privileged: true,
            caps: VerifierCaps::modern(),
            ..Default::default()
        }
    }

    /// Create options for unprivileged mode.
    pub fn unprivileged(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            is_privileged: false,
            caps: VerifierCaps::modern(),
            ..Default::default()
        }
    }
}

/// Result of BPF program loading/verification.
#[derive(Debug)]
pub struct LoadResult {
    /// Verified and patched program instructions.
    pub insns: Vec<BpfInsn>,
    /// Subprogram information.
    pub subprogs: Vec<SubprogInfoEntry>,
    /// Statistics from verification.
    pub stats: VerifyStats,
    /// Log output from verification.
    pub log: String,
    /// Whether the program was modified (patched).
    pub was_modified: bool,
}

/// Statistics from verification.
#[derive(Debug, Clone, Default)]
pub struct VerifyStats {
    /// Number of instructions processed.
    pub insn_processed: usize,
    /// Peak number of states.
    pub peak_states: usize,
    /// Total states explored.
    pub total_states: usize,
    /// Number of subprograms.
    pub subprog_count: usize,
    /// Maximum stack depth.
    pub max_stack_depth: i32,
    /// Number of maps used.
    pub maps_used: usize,
    /// Whether the program is sleepable.
    pub is_sleepable: bool,
}

/// Resolve map FD references in LD_IMM64 instructions.
///
/// This function scans the program for LD_IMM64 instructions with
/// pseudo source registers (BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE, etc.)
/// and resolves them to actual map pointers.
///
/// Corresponds to the kernel's `resolve_pseudo_ldimm64()`.
pub fn resolve_pseudo_ldimm64(
    insns: &mut [BpfInsn],
    fd_array: &FdArray,
    insn_aux: &mut [super::env::InsnAuxData],
) -> Result<Vec<i32>> {
    let mut used_maps = Vec::new();
    let mut i = 0;

    while i < insns.len() {
        let insn = &insns[i];

        // Check for LD_IMM64 instruction
        if insn.code != (BPF_LD | BPF_IMM | BPF_DW) {
            i += 1;
            continue;
        }

        // Check for pseudo source register
        // Note: For LD_IMM64, the src_reg values have different meanings:
        // - 0: Normal immediate
        // - 1 (BPF_PSEUDO_MAP_FD): Map file descriptor reference
        // - 2 (BPF_PSEUDO_MAP_VALUE): Direct map value access
        // - 3 (BPF_PSEUDO_BTF_ID): BTF type ID for CO-RE
        // - 4 (BPF_PSEUDO_FUNC): Subprogram function pointer
        // - 5 (BPF_PSEUDO_MAP_IDX): Map index reference
        // - 6 (BPF_PSEUDO_MAP_IDX_VALUE): Map index value access
        let src = insn.src_reg;
        match src {
            0 => {
                // Normal immediate - no resolution needed
                i += 2; // Skip both parts of LD_IMM64
                continue;
            }
            1 | 2 => {
                // BPF_PSEUDO_MAP_FD (1) or BPF_PSEUDO_MAP_VALUE (2)
                // Map FD reference
                let fd = insn.imm;
                let map_info = fd_array.get_map(fd).ok_or_else(|| {
                    VerifierError::InvalidMemoryAccess(format!(
                        "map fd {} not found at insn {}",
                        fd, i
                    ))
                })?;

                // Record map usage
                if !used_maps.contains(&fd) {
                    used_maps.push(fd);
                }

                // Store map info in instruction aux data
                if i < insn_aux.len() {
                    insn_aux[i].map_ptr_state = Some(map_info.to_map_info());
                }

                // The actual pointer patching happens later
                // For now, just validate the reference
            }
            3 => {
                // BPF_PSEUDO_BTF_ID - BTF type ID reference
                let _btf_id = insn.imm;
                // Store BTF reference for later validation
            }
            4 => {
                // BPF_PSEUDO_FUNC - Function reference (for BPF-to-BPF calls)
                let target_offset = insn.imm;
                let target = (i as i32 + target_offset + 1) as usize;

                if target >= insns.len() {
                    return Err(VerifierError::InvalidInsnIdx(target));
                }

                // Store call target in aux data
                if i < insn_aux.len() {
                    insn_aux[i].call_target = Some(target);
                }
            }
            5 | 6 => {
                // BPF_PSEUDO_MAP_IDX (5) or BPF_PSEUDO_MAP_IDX_VALUE (6)
                // Map index reference (for map-in-map)
                let _idx = insn.imm;
                // These are resolved differently - via map index
            }
            _ => {
                return Err(VerifierError::InvalidInstruction(i));
            }
        }

        i += 2; // Skip both parts of LD_IMM64
    }

    Ok(used_maps)
}

/// Detect and register subprograms in the instruction stream.
///
/// Subprograms are detected by scanning for BPF_PSEUDO_CALL instructions
/// and finding their targets.
///
/// Corresponds to the kernel's `check_subprogs()`.
pub fn detect_subprogs(env: &mut VerifierEnv) -> Result<()> {
    let insns = &env.insns;
    let len = insns.len();

    // First pass: find all call targets
    let mut call_targets: Vec<usize> = Vec::new();

    for (i, insn) in insns.iter().enumerate() {
        // Check for BPF_CALL with pseudo call (subprogram call)
        if insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_CALL {
            let target = (i as i32 + insn.imm + 1) as usize;

            if target >= len {
                return Err(VerifierError::InvalidInsnIdx(target));
            }

            if !call_targets.contains(&target) {
                call_targets.push(target);
            }
        }

        // Also check LD_IMM64 with BPF_PSEUDO_FUNC
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) && insn.src_reg == BPF_PSEUDO_FUNC {
            let target = (i as i32 + insn.imm + 1) as usize;

            if target >= len {
                return Err(VerifierError::InvalidInsnIdx(target));
            }

            if !call_targets.contains(&target) {
                call_targets.push(target);
            }
        }
    }

    // Sort targets
    call_targets.sort();

    // Add subprograms for each call target
    for target in call_targets {
        // Check if already exists
        let exists = env.subprogs.iter().any(|s| s.start == target);
        if !exists {
            env.add_subprog(target, len);
        }
    }

    // Finalize subprogram boundaries
    finalize_subprog_boundaries(env)?;

    Ok(())
}

/// Finalize subprogram boundaries based on detected entry points.
fn finalize_subprog_boundaries(env: &mut VerifierEnv) -> Result<()> {
    let len = env.insns.len();
    let subprog_count = env.subprogs.len();

    if subprog_count == 0 {
        return Ok(());
    }

    // Sort subprograms by start address
    env.subprogs.sort_by_key(|s| s.start);

    // Set end boundaries
    for i in 0..subprog_count {
        let next_start = if i + 1 < subprog_count {
            env.subprogs[i + 1].start
        } else {
            len
        };
        env.subprogs[i].end = next_start;
    }

    // Validate no overlap and proper boundaries
    for i in 0..subprog_count {
        let subprog = &env.subprogs[i];
        if subprog.start >= subprog.end {
            return Err(VerifierError::InvalidSubprog(format!(
                "subprog {} has empty range [{}, {})",
                i, subprog.start, subprog.end
            )));
        }
    }

    Ok(())
}

/// Mark prune points and jump points in the program.
///
/// Prune points are locations where state caching is beneficial:
/// - Jump targets (merge points)
/// - Loop headers
/// - After calls
///
/// Jump points are where jump history should be recorded:
/// - Conditional branches
/// - Loop back edges
pub fn mark_prune_points(env: &mut VerifierEnv) -> Result<()> {
    let len = env.insns.len();

    // First pass: find all jump targets
    for i in 0..len {
        let insn = &env.insns[i];
        let class = insn.class();

        if class == BPF_JMP || class == BPF_JMP32 {
            let op = insn.code & 0xf0;

            match op {
                BPF_JA => {
                    // Unconditional jump
                    let target = (i as i32 + insn.off as i32 + 1) as usize;
                    if target < len {
                        if let Some(aux) = env.insn_aux.get_mut(target) {
                            aux.prune_point = true;
                        }
                    }
                }
                BPF_EXIT | BPF_CALL => {
                    // Exit and call don't have jump targets
                }
                _ => {
                    // Conditional jumps - both target and fallthrough are prune points
                    let target = (i as i32 + insn.off as i32 + 1) as usize;
                    if target < len {
                        if let Some(aux) = env.insn_aux.get_mut(target) {
                            aux.prune_point = true;
                            aux.jmp_point = true;
                        }
                    }
                    // Fallthrough
                    if i + 1 < len {
                        if let Some(aux) = env.insn_aux.get_mut(i + 1) {
                            aux.prune_point = true;
                        }
                    }
                }
            }
        }
    }

    // Mark subprogram entries as prune points
    for subprog in &env.subprogs {
        if let Some(aux) = env.insn_aux.get_mut(subprog.start) {
            aux.prune_point = true;
            aux.force_prune_point = true;
        }
    }

    Ok(())
}

/// Main entry point for BPF program verification.
///
/// This is the Rust equivalent of the kernel's `bpf_check()` function.
/// It performs the complete verification process:
///
/// 1. Create verifier environment
/// 2. Resolve pseudo LD_IMM64 (map FDs, BTF IDs, etc.)
/// 3. Detect and register subprograms
/// 4. Build control flow graph
/// 5. Mark prune points
/// 6. Run main verification
/// 7. Apply post-verification fixups
/// 8. Patch map pointers
///
/// # Arguments
///
/// * `insns` - Program instructions
/// * `fd_array` - FD array for resolving map references
/// * `options` - Loading and verification options
///
/// # Returns
///
/// * `Ok(LoadResult)` - Verification succeeded
/// * `Err(VerifierError)` - Verification failed
pub fn bpf_check(
    insns: Vec<BpfInsn>,
    fd_array: &FdArray,
    options: &LoadOptions,
) -> Result<LoadResult> {
    // Create verifier environment
    let mut env = VerifierEnv::new(insns, options.prog_type, options.is_privileged)?;

    // Set options
    env.expected_attach_type = options.expected_attach_type;
    env.caps = options.caps;
    env.set_log_level(options.log_level);
    env.prog_sleepable = options.prog_sleepable;

    // Phase 1: Resolve pseudo LD_IMM64 instructions
    let used_maps = resolve_pseudo_ldimm64(&mut env.insns, fd_array, &mut env.insn_aux)?;

    // Phase 2: Detect subprograms
    detect_subprogs(&mut env)?;

    // Phase 3: Build control flow graph
    env.cfg = Some(ControlFlowGraph::build(&env.insns)?);

    // Phase 4: Mark prune points
    mark_prune_points(&mut env)?;

    // Phase 5: Run main verification
    let max_stack_depth = {
        let mut verifier = MainVerifier::new(&mut env);
        verifier.verify()?;
        verifier.max_stack_depth as i32
    };

    // Collect statistics before fixups
    let stats = VerifyStats {
        insn_processed: env.insn_processed,
        peak_states: env.peak_states,
        total_states: env.total_states,
        subprog_count: env.subprogs.len(),
        max_stack_depth,
        maps_used: used_maps.len(),
        is_sleepable: env.prog_sleepable,
    };

    // Phase 6: Apply post-verification fixups
    let fixup_ctx = FixupContext {
        prog_type: env.prog_type,
        expected_attach_type: 0, // Default
        jit_blinding: false,
        inline_map_lookups: true,
        inline_bpf_loop: env.caps.bpf_loop,
        misaligned_ok: true,
        maps: Vec::new(),
        insn_aux: HashMap::new(),
        current_idx: 0,
        kfuncs: Vec::new(),
        seen_direct_write: false, // TODO: track direct packet writes during verification
        specialize_kfuncs: true,
    };
    let fixup_result = do_misc_fixups(&mut env.insns, &fixup_ctx)?;
    let was_modified = fixup_result.insns_added != 0
        || fixup_result.map_lookups_inlined > 0
        || fixup_result.loops_inlined > 0;

    // Phase 7: Patch map pointers
    let map_fd_ptrs = fd_array.get_map_fd_ptrs();
    if !map_fd_ptrs.is_empty() {
        patch_map_pointers(&mut env.insns, &map_fd_ptrs)?;
    }

    // Collect log output
    let log = env.log.buffer.clone();

    Ok(LoadResult {
        insns: env.insns,
        subprogs: env.subprogs,
        stats,
        log,
        was_modified,
    })
}

/// Simplified verification without FD resolution.
///
/// This is useful for testing or when map FDs are already resolved.
///
/// Note: This is named `load_and_verify` to avoid conflict with `verify_program`
/// in main_loop.rs which has a different signature.
pub fn load_and_verify(
    insns: Vec<BpfInsn>,
    prog_type: BpfProgType,
    is_privileged: bool,
) -> Result<LoadResult> {
    let fd_array = FdArray::new();
    let options = if is_privileged {
        LoadOptions::privileged(prog_type)
    } else {
        LoadOptions::unprivileged(prog_type)
    };

    bpf_check(insns, &fd_array, &options)
}

/// Check if a program would be verifiable without actually modifying it.
///
/// This is useful for dry-run verification.
pub fn check_program(
    insns: &[BpfInsn],
    prog_type: BpfProgType,
    is_privileged: bool,
) -> Result<VerifyStats> {
    let result = load_and_verify(insns.to_vec(), prog_type, is_privileged)?;
    Ok(result.stats)
}
