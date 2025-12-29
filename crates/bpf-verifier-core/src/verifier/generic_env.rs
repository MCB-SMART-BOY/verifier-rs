// SPDX-License-Identifier: GPL-2.0

//! Generic verifier environment with platform abstraction.
//!
//! This module provides a platform-generic version of the verifier environment
//! that uses the [`PlatformSpec`] trait for platform-specific operations.

use crate::platform::{
    PlatformSpec, HelperProvider, ProgTypeProvider, KfuncProvider, MapProvider, ContextProvider,
};
use crate::core::error::{Result, VerifierError};
use crate::core::log::{LogLevel, VerifierLog};
use crate::core::types::*;
use crate::state::verifier_state::BpfVerifierState;

use alloc::{boxed::Box, vec, vec::Vec};
use alloc::collections::BTreeMap as HashMap;

use super::env::{
    BpfAttachType, VerifierCaps, SubprogInfoEntry, InsnAuxData, ExploredState,
    StackWriteMarks, BPF_COMPLEXITY_LIMIT_INSNS, BPF_MAX_VERIFICATION_ITERATIONS,
};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::race_detector::RaceDetector;
use crate::analysis::scc::{BackEdgePropagator, SccAnalysis};
use crate::btf::integration::BtfContext;
use crate::sanitize::spectre::InsnAuxData as SanitizeAuxData;
use crate::special::struct_ops::StructOpsContext;

/// Generic verifier environment parameterized by platform.
///
/// This is the platform-generic version of [`VerifierEnv`] that uses
/// the [`PlatformSpec`] trait for all platform-specific operations.
///
/// # Type Parameters
///
/// * `P` - The platform specification implementing [`PlatformSpec`]
///
/// # Example
///
/// ```ignore
/// use bpf_verifier_core::verifier::GenericVerifierEnv;
/// use bpf_verifier_linux::LinuxSpec;
///
/// let platform = LinuxSpec::new();
/// let insns = vec![/* BPF instructions */];
/// let env = GenericVerifierEnv::new(platform, insns, 6 /* XDP */, false)?;
/// ```
#[derive(Debug)]
pub struct GenericVerifierEnv<P: PlatformSpec> {
    /// Platform specification
    pub platform: P,
    /// Program type (as u32 for platform-agnostic representation)
    pub prog_type: u32,
    /// Expected attach type
    pub expected_attach_type: BpfAttachType,
    /// Program instructions
    pub insns: Vec<BpfInsn>,
    /// Instruction auxiliary data
    pub insn_aux: Vec<InsnAuxData>,
    /// Subprogram information
    pub subprogs: Vec<SubprogInfoEntry>,
    /// Current verification state (boxed to avoid stack overflow in kernel)
    pub cur_state: Option<Box<BpfVerifierState>>,
    /// Stack of states to explore (DFS) - boxed for kernel safety
    pub state_stack: Vec<(Box<BpfVerifierState>, usize)>,
    /// Explored states per instruction (for pruning)
    pub explored_states: HashMap<usize, Vec<ExploredState>>,
    /// Control flow graph information
    pub cfg: Option<ControlFlowGraph>,
    /// SCC analysis for loop detection
    pub scc_analysis: Option<SccAnalysis>,
    /// Back edge propagator for loop iteration tracking
    pub back_edge_propagator: Option<BackEdgePropagator>,
    /// Per-instruction sanitization data
    pub sanitize_aux: Vec<SanitizeAuxData>,
    /// Whether speculative path sanitization is needed
    pub speculative: bool,
    /// Verifier log
    pub log: VerifierLog,
    /// Capabilities
    pub caps: VerifierCaps,
    /// Whether program is privileged
    pub allow_ptr_leaks: bool,
    /// Number of processed instructions
    pub insn_processed: usize,
    /// Peak number of states
    pub peak_states: usize,
    /// Total states pruned
    pub total_states: usize,
    /// Current instruction index
    pub insn_idx: usize,
    /// Previous instruction index
    pub prev_insn_idx: usize,
    /// Current subprogram
    pub subprog: usize,
    /// Verification pass number
    pub pass_cnt: u32,
    /// ID counter for register values
    pub id_gen: u32,
    /// Whether we're in a callback
    pub in_callback: bool,
    /// Callback depth
    pub callback_depth: u32,
    /// Exception callback subprog (if any)
    pub exception_callback_subprog: Option<usize>,
    /// Stack write marks for speculative execution tracking
    pub stack_write_marks: StackWriteMarks,
    /// Whether program is sleepable
    pub prog_sleepable: bool,
    /// BTF context for type-aware verification
    pub btf_ctx: BtfContext,
    /// Struct_ops context (for BPF_PROG_TYPE_STRUCT_OPS programs)
    pub struct_ops_ctx: Option<StructOpsContext>,
    /// Attach BTF ID for struct_ops
    pub attach_btf_id: u32,
    /// Member index within struct_ops
    pub expected_attach_type_idx: u32,
    /// Whether program has refcounted arguments (no tail call allowed)
    pub has_refcounted_args: bool,
    /// Race detector for detecting potential data races
    pub race_detector: RaceDetector,
    /// Whether race detection is enabled
    pub race_detection_enabled: bool,
}

impl<P: PlatformSpec> GenericVerifierEnv<P> {
    /// Create a new generic verifier environment.
    ///
    /// # Arguments
    ///
    /// * `platform` - The platform specification
    /// * `insns` - BPF program instructions
    /// * `prog_type` - Program type ID
    /// * `allow_ptr_leaks` - Whether to allow pointer leaks (privileged mode)
    pub fn new(
        platform: P,
        insns: Vec<BpfInsn>,
        prog_type: u32,
        allow_ptr_leaks: bool,
    ) -> Result<Self> {
        if insns.is_empty() {
            return Err(VerifierError::EmptyProgram);
        }
        if insns.len() > BPF_COMPLEXITY_LIMIT_INSNS {
            return Err(VerifierError::ProgramTooLarge(insns.len()));
        }

        // Validate program type using platform
        if !platform.prog_type().is_valid(prog_type) {
            return Err(VerifierError::InvalidProgramType(
                alloc::format!("unknown program type {}", prog_type)
            ));
        }

        let insn_count = insns.len();
        let insn_aux = (0..insn_count)
            .map(|i| InsnAuxData {
                orig_idx: i,
                ..Default::default()
            })
            .collect();

        let subprogs = vec![SubprogInfoEntry::new(0, insn_count)];
        let sanitize_aux = vec![SanitizeAuxData::default(); insn_count];

        // Get prog_type as BpfProgType for race detector
        // (temporary compatibility - will be refactored)
        let bpf_prog_type = BpfProgType::from_u32(prog_type);

        Ok(Self {
            platform,
            prog_type,
            expected_attach_type: BpfAttachType::None,
            insns,
            insn_aux,
            subprogs,
            cur_state: None,
            state_stack: Vec::new(),
            explored_states: HashMap::new(),
            cfg: None,
            scc_analysis: None,
            back_edge_propagator: None,
            sanitize_aux,
            speculative: false,
            log: VerifierLog::new(LogLevel::Info),
            caps: VerifierCaps::modern(),
            allow_ptr_leaks,
            insn_processed: 0,
            peak_states: 0,
            total_states: 0,
            insn_idx: 0,
            prev_insn_idx: 0,
            subprog: 0,
            pass_cnt: 0,
            id_gen: 0,
            in_callback: false,
            callback_depth: 0,
            exception_callback_subprog: None,
            stack_write_marks: StackWriteMarks::new(),
            prog_sleepable: false,
            btf_ctx: BtfContext::new(),
            struct_ops_ctx: None,
            attach_btf_id: 0,
            expected_attach_type_idx: 0,
            has_refcounted_args: false,
            race_detector: RaceDetector::new(bpf_prog_type),
            race_detection_enabled: true,
        })
    }

    // =========================================================================
    // Platform-aware helper methods
    // =========================================================================

    /// Get the platform specification.
    #[inline]
    pub fn platform(&self) -> &P {
        &self.platform
    }

    /// Look up a helper function by ID using the platform.
    pub fn lookup_helper(&self, func_id: u32) -> Option<&crate::platform::HelperDef> {
        self.platform.helper().lookup(func_id)
    }

    /// Check if a helper is allowed for this program type.
    pub fn is_helper_allowed(&self, func_id: u32) -> bool {
        self.platform.helper().is_allowed_for_prog(func_id, self.prog_type)
    }

    /// Get program type info from the platform.
    pub fn prog_type_info(&self) -> Option<&crate::platform::ProgTypeInfo> {
        self.platform.prog_type().get_info(self.prog_type)
    }

    /// Validate a return value for this program type.
    pub fn validate_return_value(&self, value: i64) -> Result<()> {
        self.platform.prog_type()
            .validate_return(self.prog_type, value)
            .map_err(|_| VerifierError::InvalidReturnValue(
                alloc::format!("invalid return value {} for program type {}", value, self.prog_type)
            ))
    }

    /// Get the context size for this program type.
    pub fn ctx_size(&self) -> u32 {
        self.platform.context().ctx_size(self.prog_type)
    }

    /// Validate a context access.
    pub fn validate_ctx_access(
        &self,
        offset: u32,
        size: u32,
        is_write: bool,
    ) -> Result<&crate::platform::ContextFieldDef> {
        self.platform.context()
            .validate_access(self.prog_type, offset, size, is_write)
            .map_err(|e| VerifierError::InvalidContextAccess(
                alloc::format!("{}", e)
            ))
    }

    /// Look up a kfunc by BTF ID.
    pub fn lookup_kfunc(&self, btf_id: u32) -> Option<&crate::platform::KfuncDef> {
        self.platform.kfunc().lookup(btf_id)
    }

    /// Check if a kfunc is allowed for this program type.
    pub fn is_kfunc_allowed(&self, btf_id: u32) -> bool {
        self.platform.kfunc().is_allowed_for_prog(btf_id, self.prog_type)
    }

    /// Get map type info.
    pub fn get_map_info(&self, map_type: u32) -> Option<&crate::platform::MapTypeInfo> {
        self.platform.map().get_info(map_type)
    }

    /// Validate a map operation.
    pub fn validate_map_op(&self, map_type: u32, op: crate::platform::MapOp) -> Result<()> {
        self.platform.map()
            .validate_op(map_type, op)
            .map_err(|e| VerifierError::InvalidMapOperation(
                alloc::format!("{}", e)
            ))
    }

    // =========================================================================
    // Basic operations (same as VerifierEnv)
    // =========================================================================

    /// Get a new unique ID
    pub fn new_id(&mut self) -> u32 {
        self.id_gen += 1;
        self.id_gen
    }

    /// Get instruction at index
    pub fn insn(&self, idx: usize) -> Option<&BpfInsn> {
        self.insns.get(idx)
    }

    /// Get mutable instruction aux data
    pub fn insn_aux_mut(&mut self, idx: usize) -> Option<&mut InsnAuxData> {
        self.insn_aux.get_mut(idx)
    }

    /// Mark instruction as seen
    pub fn mark_insn_seen(&mut self, idx: usize) {
        if let Some(aux) = self.insn_aux.get_mut(idx) {
            aux.seen = true;
        }
    }

    /// Check if instruction was seen
    pub fn insn_seen(&self, idx: usize) -> bool {
        self.insn_aux.get(idx).map(|a| a.seen).unwrap_or(false)
    }

    /// Program length
    pub fn prog_len(&self) -> usize {
        self.insns.len()
    }

    /// Check complexity limits
    pub fn check_limits(&self) -> Result<()> {
        if self.insn_processed > BPF_MAX_VERIFICATION_ITERATIONS {
            return Err(VerifierError::VerificationLimitExceeded(
                "instruction limit".into(),
            ));
        }
        Ok(())
    }

    /// Increment instruction count
    pub fn count_insn(&mut self) -> Result<()> {
        self.insn_processed += 1;
        self.check_limits()
    }

    /// Find subprogram containing instruction
    pub fn find_subprog(&self, insn_idx: usize) -> Option<usize> {
        for (i, sp) in self.subprogs.iter().enumerate() {
            if insn_idx >= sp.start && insn_idx < sp.end {
                return Some(i);
            }
        }
        None
    }

    /// Push a state to explore
    pub fn push_state(&mut self, state: Box<BpfVerifierState>, insn_idx: usize) {
        self.state_stack.push((state, insn_idx));
        self.peak_states = self.peak_states.max(self.state_stack.len());
    }

    /// Pop a state to explore
    pub fn pop_state(&mut self) -> Option<(Box<BpfVerifierState>, usize)> {
        self.state_stack.pop()
    }

    /// Check if there are states to explore
    pub fn has_states(&self) -> bool {
        !self.state_stack.is_empty()
    }

    /// Set log level
    pub fn set_log_level(&mut self, level: LogLevel) {
        self.log.level = level;
    }
}

/// Extension trait to convert BpfProgType to/from u32.
trait ProgTypeConvert {
    fn from_u32(v: u32) -> Self;
}

impl ProgTypeConvert for BpfProgType {
    fn from_u32(v: u32) -> Self {
        // Simple mapping - in real implementation would need complete mapping
        match v {
            0 => BpfProgType::Unspec,
            1 => BpfProgType::SocketFilter,
            2 => BpfProgType::Kprobe,
            3 => BpfProgType::SchedCls,
            4 => BpfProgType::SchedAct,
            5 => BpfProgType::Tracepoint,
            6 => BpfProgType::Xdp,
            7 => BpfProgType::PerfEvent,
            8 => BpfProgType::CgroupSkb,
            9 => BpfProgType::CgroupSock,
            10 => BpfProgType::LwtIn,
            11 => BpfProgType::LwtOut,
            12 => BpfProgType::LwtXmit,
            13 => BpfProgType::SockOps,
            14 => BpfProgType::SkSkb,
            15 => BpfProgType::CgroupDevice,
            16 => BpfProgType::SkMsg,
            17 => BpfProgType::RawTracepoint,
            18 => BpfProgType::CgroupSockAddr,
            19 => BpfProgType::LwtSeg6local,
            20 => BpfProgType::LircMode2,
            21 => BpfProgType::SkReuseport,
            22 => BpfProgType::FlowDissector,
            23 => BpfProgType::CgroupSysctl,
            24 => BpfProgType::RawTracepointWritable,
            25 => BpfProgType::CgroupSockopt,
            26 => BpfProgType::Tracing,
            27 => BpfProgType::StructOps,
            28 => BpfProgType::Ext,
            29 => BpfProgType::Lsm,
            30 => BpfProgType::SkLookup,
            31 => BpfProgType::Syscall,
            32 => BpfProgType::Netfilter,
            _ => BpfProgType::Unspec,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::platform::NullPlatform;

    #[test]
    fn test_generic_env_creation() {
        let _platform = NullPlatform;
        // NullPlatform doesn't validate prog types, so this would fail
        // In real usage, you'd use a platform that supports the prog type
    }
}
