//! Verifier environment
//!
//! This module implements the main verifier environment that holds all
//! verification context, program information, and configuration.

#![allow(missing_docs)] // Many internal types don't need public docs

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::core::log::{VerifierLog, LogLevel};
use crate::state::verifier_state::BpfVerifierState;
use crate::state::reg_state::MapInfo;
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::scc::{SccAnalysis, BackEdgePropagator};
use crate::sanitize::sanitize::InsnAuxData as SanitizeAuxData;
use crate::check::subprog::MAX_CALL_FRAMES;
use crate::btf::integration::{BtfContext, SourceLocation};
use crate::mem::user::UserMemContext;
use crate::special::struct_ops::StructOpsContext;
use crate::analysis::race_detector::RaceDetector;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

/// BPF attach type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfAttachType {
    #[default]
    None,
    CgroupInetIngress,
    CgroupInetEgress,
    CgroupInetSockCreate,
    CgroupSockOps,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    CgroupDevice,
    SkMsgVerdict,
    CgroupInet4Bind,
    CgroupInet6Bind,
    CgroupInet4Connect,
    CgroupInet6Connect,
    CgroupInet4PostBind,
    CgroupInet6PostBind,
    CgroupUdp4Sendmsg,
    CgroupUdp6Sendmsg,
    LircMode2,
    FlowDissector,
    CgroupSysctl,
    CgroupUdp4Recvmsg,
    CgroupUdp6Recvmsg,
    CgroupGetsockopt,
    CgroupSetsockopt,
    TraceRawTp,
    TraceFentry,
    TraceFexit,
    ModifyReturn,
    LsmMac,
    TraceIter,
    CgroupInet4Getpeername,
    CgroupInet6Getpeername,
    CgroupInet4Getsockname,
    CgroupInet6Getsockname,
    XdpDevmap,
    CgroupInetSockRelease,
    XdpCpumap,
    SkLookup,
    Xdp,
    SkSkbVerdict,
    SkReuseportSelect,
    SkReuseportSelectOrMigrate,
    PerfEvent,
    TraceKprobeMulti,
    LsmCgroup,
    StructOps,
    Netfilter,
    TcxIngress,
    TcxEgress,
    TraceUprobeMulti,
    CgroupUnixConnect,
    CgroupUnixSendmsg,
    CgroupUnixRecvmsg,
    CgroupUnixGetpeername,
    CgroupUnixGetsockname,
    Netkit,
}

/// Maximum number of instructions allowed
pub const BPF_COMPLEXITY_LIMIT_INSNS: usize = 1_000_000;

/// Maximum number of states per instruction
pub const BPF_COMPLEXITY_LIMIT_STATES: usize = 64;

/// Maximum verification iterations
pub const BPF_MAX_VERIFICATION_ITERATIONS: usize = 8_000_000;

/// Verifier capabilities (kernel version dependent)
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifierCaps {
    /// Allow bounded loops
    pub bounded_loops: bool,
    /// Allow bpf_loop helper
    pub bpf_loop: bool,
    /// Allow may_goto instruction
    pub may_goto: bool,
    /// Allow open-coded iterators
    pub open_coded_iter: bool,
    /// Allow arena memory
    pub arena: bool,
    /// Allow exceptions (bpf_throw)
    pub exceptions: bool,
    /// Allow kfuncs
    pub kfuncs: bool,
    /// Allow inline spinlocks
    pub inline_spin_lock: bool,
    /// Allow timer and workqueue callbacks
    pub timer_callbacks: bool,
    /// Allow sleepable programs
    pub sleepable: bool,
}

impl VerifierCaps {
    /// Create capabilities for a modern kernel (6.x)
    pub fn modern() -> Self {
        Self {
            bounded_loops: true,
            bpf_loop: true,
            may_goto: true,
            open_coded_iter: true,
            arena: true,
            exceptions: true,
            kfuncs: true,
            inline_spin_lock: true,
            timer_callbacks: true,
            sleepable: true,
        }
    }

    /// Create minimal capabilities (conservative)
    pub fn minimal() -> Self {
        Self::default()
    }
}

/// Subprogram information
#[derive(Debug, Clone)]
/// Information about a subprogram
#[allow(missing_docs)]
pub struct SubprogInfoEntry {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (exclusive)
    pub end: usize,
    /// Stack depth used
    pub stack_depth: i32,
    /// Whether this is an async callback
    pub is_async_cb: bool,
    /// Whether this is an exception callback
    pub is_exception_cb: bool,
    /// BTF function info (if available)
    pub btf_id: Option<u32>,
    /// Number of arguments
    pub arg_cnt: u8,
    /// Whether tail calls can reach this subprogram
    pub tail_call_reachable: bool,
    /// Whether this subprogram changes packet data
    pub changes_pkt_data: bool,
    /// Whether this subprogram might sleep
    pub might_sleep: bool,
    /// Whether this is a global function
    pub is_global: bool,
}

impl SubprogInfoEntry {
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            stack_depth: 0,
            is_async_cb: false,
            is_exception_cb: false,
            btf_id: None,
            arg_cnt: 0,
            tail_call_reachable: false,
            changes_pkt_data: false,
            might_sleep: false,
            is_global: false,
        }
    }
}

/// Per-instruction auxiliary data
#[derive(Debug, Clone, Default)]
pub struct InsnAuxData {
    /// Verified destinations for this instruction
    pub seen: bool,
    /// Instruction is in a pruned path
    pub pruned: bool,
    /// Original instruction (before patching)
    pub orig_idx: usize,
    /// Sanitization state
    pub sanitize_stack_spill: bool,
    /// Whether instruction needs zero extension
    pub zext_dst: bool,
    /// Storage for verification state at this point
    pub verifier_zext: bool,
    /// Pointer type for memory access
    pub ptr_type: BpfRegType,
    /// Map pointer for map operations
    pub map_ptr_state: Option<MapInfo>,
    /// Call destination (for call instructions)
    pub call_target: Option<usize>,
    /// Is this instruction a prune point
    pub prune_point: bool,
    /// Force precision tracking at this point
    pub force_prune_point: bool,
    /// Jmp history recording point
    pub jmp_point: bool,
    /// SCC (Strongly Connected Component) id for loop detection (0 = not in SCC)
    pub scc: u32,
    /// Whether this is an iterator next call instruction
    pub is_iter_next: bool,
    /// Kfunc BTF ID (for kfunc calls)
    pub kfunc_btf_id: u32,
    /// Nospec barrier - stops speculative execution at this point
    pub nospec: bool,
    /// Nospec result - the result of this instruction needs nospec handling
    pub nospec_result: bool,
    /// Needs nospec barrier after this instruction
    pub needs_nospec_barrier: bool,
    /// ALU sanitization state for speculative execution safety
    pub alu_state: u32,
}

/// Explored state for pruning
#[derive(Debug, Clone)]
pub struct ExploredState {
    /// Verifier state at this point
    pub state: BpfVerifierState,
    /// Instruction index
    pub insn_idx: usize,
    /// Whether all paths from here have been explored
    pub all_explored: bool,
}

/// Maximum number of stack slots that can be tracked for write marks
pub const MAX_STACK_SLOTS: usize = 64;

/// Stack write marks for speculative execution safety
/// 
/// This tracks which stack slots have been written during the current
/// instruction execution. Used to ensure speculative writes are properly
/// committed or rolled back.
#[derive(Debug, Clone, Default)]
pub struct StackWriteMarks {
    /// Bitmap of stack slots written during current instruction
    /// One u64 per frame (up to MAX_CALL_FRAMES)
    pub pending: [u64; MAX_CALL_FRAMES],
    /// Bitmap of stack slots whose writes have been committed
    pub committed: [u64; MAX_CALL_FRAMES],
}

impl StackWriteMarks {
    /// Create new empty stack write marks
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Mark a stack slot as written in the given frame
    pub fn mark_write(&mut self, frameno: u32, spi: usize) {
        if frameno < MAX_CALL_FRAMES as u32 && spi < MAX_STACK_SLOTS {
            self.pending[frameno as usize] |= 1u64 << spi;
        }
    }
    
    /// Mark multiple stack slots as written (using a bitmask)
    pub fn mark_write_mask(&mut self, frameno: u32, mask: u64) {
        if frameno < MAX_CALL_FRAMES as u32 {
            self.pending[frameno as usize] |= mask;
        }
    }
    
    /// Reset pending write marks (called before each instruction)
    pub fn reset(&mut self) {
        self.pending = [0; MAX_CALL_FRAMES];
    }
    
    /// Commit pending write marks (called after successful instruction execution)
    /// Returns true if any new slots were committed
    pub fn commit(&mut self) -> bool {
        let mut any_new = false;
        for i in 0..MAX_CALL_FRAMES {
            let new_bits = self.pending[i] & !self.committed[i];
            if new_bits != 0 {
                any_new = true;
                self.committed[i] |= self.pending[i];
            }
        }
        self.pending = [0; MAX_CALL_FRAMES];
        any_new
    }
    
    /// Check if a slot has been written (either pending or committed)
    pub fn is_written(&self, frameno: u32, spi: usize) -> bool {
        if frameno < MAX_CALL_FRAMES as u32 && spi < MAX_STACK_SLOTS {
            let mask = 1u64 << spi;
            (self.pending[frameno as usize] | self.committed[frameno as usize]) & mask != 0
        } else {
            false
        }
    }
    
    /// Clear all marks (for state reset)
    pub fn clear(&mut self) {
        self.pending = [0; MAX_CALL_FRAMES];
        self.committed = [0; MAX_CALL_FRAMES];
    }
}

/// Main verifier environment
#[derive(Debug)]
pub struct VerifierEnv {
    /// Program type
    pub prog_type: BpfProgType,
    /// Expected attach type
    pub expected_attach_type: BpfAttachType,
    /// Program instructions
    pub insns: Vec<BpfInsn>,
    /// Instruction auxiliary data
    pub insn_aux: Vec<InsnAuxData>,
    /// Subprogram information
    pub subprogs: Vec<SubprogInfoEntry>,
    /// Current verification state
    pub cur_state: Option<BpfVerifierState>,
    /// Stack of states to explore (DFS)
    pub state_stack: Vec<(BpfVerifierState, usize)>,
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

impl VerifierEnv {
    /// Create a new verifier environment
    pub fn new(
        insns: Vec<BpfInsn>,
        prog_type: BpfProgType,
        allow_ptr_leaks: bool,
    ) -> Result<Self> {
        if insns.is_empty() {
            return Err(VerifierError::EmptyProgram);
        }
        if insns.len() > BPF_COMPLEXITY_LIMIT_INSNS {
            return Err(VerifierError::ProgramTooLarge(insns.len()));
        }

        let insn_count = insns.len();
        let insn_aux = (0..insn_count)
            .map(|i| InsnAuxData {
                orig_idx: i,
                ..Default::default()
            })
            .collect();

        // Initially, the whole program is one subprogram
        let subprogs = vec![SubprogInfoEntry::new(0, insn_count)];
        
        // Initialize sanitization data
        let sanitize_aux = vec![SanitizeAuxData::default(); insn_count];

        Ok(Self {
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
            race_detector: RaceDetector::new(prog_type),
            race_detection_enabled: true,
        })
    }

    /// Set BTF context for type-aware verification
    pub fn set_btf_context(&mut self, ctx: BtfContext) {
        self.btf_ctx = ctx;
    }

    /// Get source location for an instruction
    pub fn get_source_location(&self, insn_idx: usize) -> Option<SourceLocation> {
        self.btf_ctx.get_source_location(insn_idx)
    }

    /// Format error message with source location if available
    pub fn format_error_with_source(&self, insn_idx: usize, msg: &str) -> String {
        self.btf_ctx.format_error(insn_idx, msg)
    }
    
    /// Reset stack write marks before processing an instruction
    /// 
    /// This should be called at the start of do_check_insn to track
    /// which stack slots are written during speculative execution.
    pub fn reset_stack_write_marks(&mut self) {
        self.stack_write_marks.reset();
    }
    
    /// Commit stack write marks after successful instruction execution
    /// 
    /// This should be called after do_check_insn succeeds to commit
    /// the stack writes for speculative execution safety.
    pub fn commit_stack_write_marks(&mut self) -> bool {
        self.stack_write_marks.commit()
    }
    
    /// Mark a stack slot as written
    /// 
    /// Called during stack write operations to track which slots are modified.
    pub fn mark_stack_write(&mut self, frameno: u32, spi: usize) {
        self.stack_write_marks.mark_write(frameno, spi);
    }

    /// Set log level
    pub fn set_log_level(&mut self, level: LogLevel) {
        self.log.level = level;
    }

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

    /// Find subprogram containing instruction
    pub fn find_subprog(&self, insn_idx: usize) -> Option<usize> {
        for (i, sp) in self.subprogs.iter().enumerate() {
            if insn_idx >= sp.start && insn_idx < sp.end {
                return Some(i);
            }
        }
        None
    }

    /// Add a subprogram
    pub fn add_subprog(&mut self, start: usize, end: usize) -> usize {
        let idx = self.subprogs.len();
        self.subprogs.push(SubprogInfoEntry::new(start, end));
        idx
    }

    /// Push a state to explore
    pub fn push_state(&mut self, state: BpfVerifierState, insn_idx: usize) {
        self.state_stack.push((state, insn_idx));
        self.peak_states = self.peak_states.max(self.state_stack.len());
    }

    /// Pop a state to explore
    pub fn pop_state(&mut self) -> Option<(BpfVerifierState, usize)> {
        self.state_stack.pop()
    }

    /// Check if there are states to explore
    pub fn has_states(&self) -> bool {
        !self.state_stack.is_empty()
    }

    /// Save state for pruning at instruction
    pub fn save_explored_state(&mut self, insn_idx: usize, state: BpfVerifierState) {
        let explored = ExploredState {
            state,
            insn_idx,
            all_explored: false,
        };
        self.explored_states
            .entry(insn_idx)
            .or_default()
            .push(explored);
        self.total_states += 1;
    }

    /// Get explored states at instruction
    pub fn get_explored_states(&self, insn_idx: usize) -> Option<&Vec<ExploredState>> {
        self.explored_states.get(&insn_idx)
    }

    /// Check complexity limits
    pub fn check_limits(&self) -> Result<()> {
        if self.insn_processed > BPF_MAX_VERIFICATION_ITERATIONS {
            return Err(VerifierError::VerificationLimitExceeded(
                "instruction limit".into()
            ));
        }
        Ok(())
    }

    /// Increment instruction count
    pub fn count_insn(&mut self) -> Result<()> {
        self.insn_processed += 1;
        self.check_limits()
    }

    /// Check if instruction is in current subprogram
    pub fn in_current_subprog(&self, insn_idx: usize) -> bool {
        if let Some(sp) = self.subprogs.get(self.subprog) {
            insn_idx >= sp.start && insn_idx < sp.end
        } else {
            false
        }
    }

    /// Get current subprogram info
    pub fn cur_subprog(&self) -> Option<&SubprogInfoEntry> {
        self.subprogs.get(self.subprog)
    }

    /// Check if we should allow speculation
    pub fn allow_speculation(&self) -> bool {
        // In privileged mode, less speculation protection needed
        self.allow_ptr_leaks
    }

    /// Initialize SCC analysis for loop detection
    pub fn init_scc_analysis(&mut self) {
        use crate::analysis::scc::compute_scc;
        
        let analysis = compute_scc(&self.insns);
        
        // Create back edge propagator with default max iterations
        // BPF_MAX_LOOPS from kernel is typically 8 million, but we use per-loop limit
        let propagator = BackEdgePropagator::from_scc_analysis(&analysis, 1024);
        
        // Mark loop headers as prune points for better state caching
        for scc in &analysis.sccs {
            if scc.is_loop {
                for &entry in &scc.entries {
                    if let Some(aux) = self.insn_aux.get_mut(entry) {
                        aux.prune_point = true;
                        aux.force_prune_point = true;
                    }
                }
            }
        }
        
        self.scc_analysis = Some(analysis);
        self.back_edge_propagator = Some(propagator);
    }

    /// Check if instruction is in a loop
    pub fn is_in_loop(&self, insn_idx: usize) -> bool {
        self.scc_analysis
            .as_ref()
            .map(|a| a.is_in_loop(insn_idx))
            .unwrap_or(false)
    }

    /// Check if edge is a back edge (loop iteration)
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.back_edge_propagator
            .as_ref()
            .map(|p| p.is_back_edge(from, to))
            .unwrap_or(false)
    }

    /// Record visit to instruction for loop iteration tracking
    pub fn record_loop_visit(&mut self, insn_idx: usize) -> Result<()> {
        if let Some(ref mut propagator) = self.back_edge_propagator {
            propagator.record_visit(insn_idx)?;
        }
        Ok(())
    }

    /// Get sanitization aux data for instruction
    pub fn sanitize_aux_data(&self, insn_idx: usize) -> Option<&SanitizeAuxData> {
        self.sanitize_aux.get(insn_idx)
    }

    /// Get mutable sanitization aux data
    pub fn sanitize_aux_data_mut(&mut self, insn_idx: usize) -> Option<&mut SanitizeAuxData> {
        self.sanitize_aux.get_mut(insn_idx)
    }

    /// Mark instruction as needing speculation barrier
    pub fn mark_nospec(&mut self, insn_idx: usize) {
        if let Some(aux) = self.sanitize_aux.get_mut(insn_idx) {
            aux.needs_nospec_barrier = true;
        }
    }

    /// Check if instruction needs speculation barrier
    pub fn needs_nospec(&self, insn_idx: usize) -> bool {
        self.sanitize_aux
            .get(insn_idx)
            .map(|a| a.needs_nospec_barrier)
            .unwrap_or(false)
    }

    /// Check if bounded loops are supported
    pub fn bounded_loops_supported(&self) -> bool {
        self.caps.bounded_loops
    }

    /// Program length
    pub fn prog_len(&self) -> usize {
        self.insns.len()
    }

    /// Number of subprograms
    pub fn subprog_count(&self) -> usize {
        self.subprogs.len()
    }

    /// Create a UserMemContext from the current verification environment
    /// 
    /// This provides the proper context for user memory access validation
    /// based on the program's capabilities and current verification state.
    pub fn user_mem_context(&self) -> UserMemContext {
        UserMemContext {
            privileged: self.allow_ptr_leaks,
            sleepable: self.prog_sleepable,
            allow_direct_access: false, // Set per-access based on arena user pointers
            has_nospec: false, // Set per-instruction based on sanitize_aux
            prog_type: self.prog_type,
        }
    }

    /// Create a UserMemContext with nospec status for a specific instruction
    pub fn user_mem_context_for_insn(&self, insn_idx: usize) -> UserMemContext {
        let mut ctx = self.user_mem_context();
        ctx.has_nospec = self.needs_nospec(insn_idx);
        ctx
    }

    // ========================================================================
    // Struct Ops Verification
    // ========================================================================

    /// Check if this is a struct_ops program
    pub fn is_struct_ops(&self) -> bool {
        self.prog_type == BpfProgType::StructOps
    }

    /// Initialize struct_ops context for verification
    /// 
    /// This should be called during program setup when attach_btf_id 
    /// and expected_attach_type are known.
    pub fn init_struct_ops_context(
        &mut self,
        ops_ctx: StructOpsContext,
        attach_btf_id: u32,
        member_idx: u32,
    ) -> Result<()> {
        if !self.is_struct_ops() {
            return Err(VerifierError::InvalidProgramType(format!(
                "init_struct_ops_context called for non-struct_ops program type {:?}",
                self.prog_type
            )));
        }

        self.attach_btf_id = attach_btf_id;
        self.expected_attach_type_idx = member_idx;
        self.struct_ops_ctx = Some(ops_ctx);

        Ok(())
    }

    /// Check struct_ops BTF ID validity
    /// 
    /// This corresponds to the kernel's `check_struct_ops_btf_id()`.
    /// It validates the attach_btf_id and member_idx are valid for
    /// a struct_ops program.
    pub fn check_struct_ops_btf_id(&mut self) -> Result<()> {
        if !self.is_struct_ops() {
            return Ok(()); // Not a struct_ops program
        }

        // Struct_ops programs must be GPL compatible
        // (In a full implementation, we'd check the license)

        // Must have an attach_btf_id
        if self.attach_btf_id == 0 {
            return Err(VerifierError::InvalidProgramType(
                "struct_ops program requires attach_btf_id".into()
            ));
        }

        // Get struct_ops context
        let ctx = self.struct_ops_ctx.as_mut().ok_or_else(|| {
            VerifierError::InvalidProgramType(
                "struct_ops context not initialized".into()
            )
        })?;

        // Validate member index
        let member_idx = self.expected_attach_type_idx as usize;
        if member_idx >= ctx.members.len() {
            return Err(VerifierError::InvalidProgramType(format!(
                "attach to invalid member idx {} of struct_ops (max {})",
                member_idx, ctx.members.len()
            )));
        }

        // Set the current member being verified
        ctx.set_current_member(member_idx)?;

        // Check if member supports sleepable
        if self.prog_sleepable && !ctx.current_supports_sleepable() {
            let member_name = ctx.current_member_info()
                .map(|m| m.name.as_str())
                .unwrap_or("unknown");
            return Err(VerifierError::InvalidProgramType(format!(
                "struct_ops member {} does not support sleepable programs",
                member_name
            )));
        }

        Ok(())
    }

    /// Check if tail calls are allowed for this program
    /// 
    /// Programs with refcounted arguments cannot tail call.
    pub fn check_tail_call_allowed(&self) -> Result<()> {
        if self.has_refcounted_args {
            return Err(VerifierError::InvalidFunctionCall(
                "program with refcounted arguments cannot tail call".into()
            ));
        }
        Ok(())
    }

    /// Validate struct_ops return value
    pub fn validate_struct_ops_return(&self, retval: &crate::state::reg_state::BpfRegState) -> Result<()> {
        if !self.is_struct_ops() {
            return Ok(());
        }

        if let Some(ref ctx) = self.struct_ops_ctx {
            crate::special::struct_ops::validate_struct_ops_return(ctx, retval)?;
        }

        Ok(())
    }

    // ========================================================================
    // Race Detection Methods
    // ========================================================================

    /// Enable or disable race detection
    pub fn set_race_detection(&mut self, enabled: bool) {
        self.race_detection_enabled = enabled;
    }

    /// Record a global variable access for race detection
    pub fn record_global_access(
        &mut self,
        btf_id: u32,
        offset: i32,
        access_type: crate::analysis::race_detector::AccessType,
        size: u32,
    ) {
        if self.race_detection_enabled {
            self.race_detector.record_global_access(
                btf_id,
                offset,
                access_type,
                self.insn_idx,
                size,
            );
        }
    }

    /// Record a map access for race detection
    pub fn record_map_access(
        &mut self,
        map_id: u32,
        key_hash: u64,
        access_type: crate::analysis::race_detector::AccessType,
        size: u32,
    ) {
        if self.race_detection_enabled {
            self.race_detector.record_map_access(
                map_id,
                key_hash,
                access_type,
                self.insn_idx,
                size,
            );
        }
    }

    /// Record a per-CPU variable access for race detection
    pub fn record_percpu_access(
        &mut self,
        var_id: u32,
        offset: i32,
        access_type: crate::analysis::race_detector::AccessType,
        size: u32,
    ) {
        if self.race_detection_enabled {
            self.race_detector.record_percpu_access(
                var_id,
                offset,
                access_type,
                self.insn_idx,
                size,
            );
        }
    }

    /// Update race detector lock state when acquiring a spin lock
    pub fn race_detector_acquire_lock(&mut self, lock_id: u32) {
        if self.race_detection_enabled {
            self.race_detector.acquire_spin_lock(lock_id);
        }
    }

    /// Update race detector lock state when releasing a spin lock
    pub fn race_detector_release_lock(&mut self, lock_id: u32) -> Result<()> {
        if self.race_detection_enabled {
            self.race_detector.release_spin_lock(lock_id)?;
        }
        Ok(())
    }

    /// Update race detector when entering RCU read section
    pub fn race_detector_rcu_lock(&mut self) {
        if self.race_detection_enabled {
            self.race_detector.rcu_read_lock();
        }
    }

    /// Update race detector when exiting RCU read section
    pub fn race_detector_rcu_unlock(&mut self) -> Result<()> {
        if self.race_detection_enabled {
            self.race_detector.rcu_read_unlock()?;
        }
        Ok(())
    }

    /// Update race detector when disabling preemption
    pub fn race_detector_preempt_disable(&mut self) {
        if self.race_detection_enabled {
            self.race_detector.preempt_disable();
        }
    }

    /// Update race detector when enabling preemption
    pub fn race_detector_preempt_enable(&mut self) -> Result<()> {
        if self.race_detection_enabled {
            self.race_detector.preempt_enable()?;
        }
        Ok(())
    }

    /// Mark a global variable as shared for race detection
    pub fn mark_shared_global(&mut self, btf_id: u32) {
        self.race_detector.mark_shared_global(btf_id);
    }

    /// Mark a map as concurrently accessed
    pub fn mark_concurrent_map(&mut self, map_id: u32) {
        self.race_detector.mark_concurrent_map(map_id);
    }

    /// Run race detection analysis and return any errors
    pub fn analyze_races(&mut self) -> Result<()> {
        if !self.race_detection_enabled {
            return Ok(());
        }
        
        let _races = self.race_detector.analyze();
        self.race_detector.validate()
    }

    /// Get detected race warnings (all severities)
    pub fn get_race_warnings(&self) -> &[crate::analysis::race_detector::DataRace] {
        self.race_detector.get_races()
    }

    /// Check if any race errors were detected
    pub fn has_race_errors(&self) -> bool {
        self.race_detector.has_errors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_creation() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true);
        assert!(env.is_ok());
        let env = env.unwrap();
        assert_eq!(env.prog_len(), 2);
        assert_eq!(env.subprogs.len(), 1);
    }

    #[test]
    fn test_empty_program() {
        let env = VerifierEnv::new(vec![], BpfProgType::SocketFilter, true);
        assert!(matches!(env, Err(VerifierError::EmptyProgram)));
    }

    #[test]
    fn test_id_generation() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
        assert_eq!(env.new_id(), 1);
        assert_eq!(env.new_id(), 2);
        assert_eq!(env.new_id(), 3);
    }

    #[test]
    fn test_state_stack() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
        
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();
        
        env.push_state(state1, 0);
        env.push_state(state2, 5);
        
        assert!(env.has_states());
        assert_eq!(env.peak_states, 2);
        
        let (_, idx) = env.pop_state().unwrap();
        assert_eq!(idx, 5);
        
        let (_, idx) = env.pop_state().unwrap();
        assert_eq!(idx, 0);
        
        assert!(!env.has_states());
    }

    #[test]
    fn test_caps() {
        let caps = VerifierCaps::modern();
        assert!(caps.bounded_loops);
        assert!(caps.kfuncs);
        assert!(caps.arena);
        
        let caps = VerifierCaps::minimal();
        assert!(!caps.bounded_loops);
    }

    #[test]
    fn test_insn_seen() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut env = VerifierEnv::new(insns, BpfProgType::SocketFilter, true).unwrap();
        
        assert!(!env.insn_seen(0));
        env.mark_insn_seen(0);
        assert!(env.insn_seen(0));
        assert!(!env.insn_seen(1));
    }
}
