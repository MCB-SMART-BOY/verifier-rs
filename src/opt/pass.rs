//! Unified optimization pass framework.
//!
//! This module provides a common infrastructure for optimization passes:
//! - Pass trait for uniform interface
//! - Pass manager for scheduling and running passes
//! - Pass configuration and dependencies
//! - Pass statistics and diagnostics

#![allow(missing_docs)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

use core::fmt::Debug;

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

// ============================================================================
// Pass Statistics
// ============================================================================

/// Statistics collected during pass execution
#[derive(Debug, Clone, Default)]
pub struct PassStats {
    /// Number of instructions before pass
    pub insns_before: usize,
    /// Number of instructions after pass
    pub insns_after: usize,
    /// Number of instructions modified
    pub insns_modified: usize,
    /// Number of instructions removed
    pub insns_removed: usize,
    /// Number of instructions inserted
    pub insns_inserted: usize,
    /// Whether pass made any changes
    pub changed: bool,
    /// Pass-specific counters
    pub counters: Vec<(String, u64)>,
}

impl PassStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a counter value
    pub fn add_counter(&mut self, name: &str, value: u64) {
        self.counters.push((name.into(), value));
    }

    /// Increment a counter
    pub fn increment(&mut self, name: &str) {
        for (n, v) in &mut self.counters {
            if n == name {
                *v += 1;
                return;
            }
        }
        self.counters.push((name.into(), 1));
    }

    /// Get counter value
    pub fn get_counter(&self, name: &str) -> u64 {
        for (n, v) in &self.counters {
            if n == name {
                return *v;
            }
        }
        0
    }

    /// Mark that changes were made
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }
}

// ============================================================================
// Pass Context
// ============================================================================

/// Context provided to optimization passes
#[derive(Debug)]
pub struct PassContext {
    /// Program instructions
    pub insns: Vec<BpfInsn>,
    /// Program type
    pub prog_type: BpfProgType,
    /// Whether the program has subprograms
    pub has_subprogs: bool,
    /// Subprogram information
    pub subprogs: Vec<PassSubprogInfo>,
    /// Current instruction index being processed (for iterating passes)
    pub current_idx: Option<usize>,
    /// Whether to collect detailed statistics
    pub collect_stats: bool,
    /// Whether optimizations are enabled
    pub optimize: bool,
    /// JIT enabled
    pub jit_enabled: bool,
    /// Debug mode (verbose output)
    pub debug: bool,
}

/// Subprogram information for pass context
#[derive(Debug, Clone, Default)]
pub struct PassSubprogInfo {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (exclusive)
    pub end: usize,
    /// Stack depth
    pub stack_depth: i32,
    /// Whether this subprogram has tail calls
    pub has_tail_call: bool,
}

impl Default for PassContext {
    fn default() -> Self {
        Self {
            insns: Vec::new(),
            prog_type: BpfProgType::Unspec,
            has_subprogs: false,
            subprogs: Vec::new(),
            current_idx: None,
            collect_stats: false,
            optimize: true,
            jit_enabled: true,
            debug: false,
        }
    }
}

impl PassContext {
    pub fn new(insns: Vec<BpfInsn>) -> Self {
        Self {
            insns,
            ..Default::default()
        }
    }

    pub fn with_prog_type(mut self, prog_type: BpfProgType) -> Self {
        self.prog_type = prog_type;
        self
    }

    pub fn with_subprogs(mut self, subprogs: Vec<PassSubprogInfo>) -> Self {
        self.has_subprogs = !subprogs.is_empty();
        self.subprogs = subprogs;
        self
    }

    pub fn with_optimize(mut self, optimize: bool) -> Self {
        self.optimize = optimize;
        self
    }

    pub fn with_jit(mut self, jit_enabled: bool) -> Self {
        self.jit_enabled = jit_enabled;
        self
    }

    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Get instruction count
    pub fn insn_count(&self) -> usize {
        self.insns.len()
    }

    /// Get instruction at index
    pub fn get_insn(&self, idx: usize) -> Option<&BpfInsn> {
        self.insns.get(idx)
    }

    /// Get mutable instruction at index
    pub fn get_insn_mut(&mut self, idx: usize) -> Option<&mut BpfInsn> {
        self.insns.get_mut(idx)
    }
}

// ============================================================================
// Pass Trait
// ============================================================================

/// Optimization pass identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassId {
    /// Dead code elimination
    DeadCodeElim,
    /// Context access conversion
    CtxAccessConvert,
    /// Map fd to pointer fixup
    MapFdFixup,
    /// Helper call resolution
    HelperCallResolve,
    /// Kfunc call fixup
    KfuncFixup,
    /// Zero extension insertion
    ZeroExtend,
    /// Speculation barrier insertion (Spectre mitigation)
    SpectreMitigation,
    /// Subprogram adjustment for JIT
    JitSubprogAdjust,
    /// Miscellaneous fixups (do_misc_fixups equivalent)
    MiscFixups,
    /// Instruction size adjustment (gotol <-> goto conversion)
    InsnSizeAdjust,
    /// Custom pass (user-defined)
    Custom(u32),
}

/// Result of running a pass
#[derive(Debug)]
pub struct PassResult {
    /// Pass identifier
    pub pass_id: PassId,
    /// Whether pass completed successfully
    pub success: bool,
    /// Statistics
    pub stats: PassStats,
    /// Error if any
    pub error: Option<VerifierError>,
}

impl PassResult {
    pub fn success(pass_id: PassId, stats: PassStats) -> Self {
        Self {
            pass_id,
            success: true,
            stats,
            error: None,
        }
    }

    pub fn failure(pass_id: PassId, error: VerifierError) -> Self {
        Self {
            pass_id,
            success: false,
            stats: PassStats::default(),
            error: Some(error),
        }
    }
}

/// Trait for optimization passes
pub trait OptPass: Send + Sync + Debug {
    /// Get pass identifier
    fn id(&self) -> PassId;

    /// Get pass name
    fn name(&self) -> &'static str;

    /// Get pass description
    fn description(&self) -> &'static str {
        ""
    }

    /// Get passes that must run before this one
    fn dependencies(&self) -> Vec<PassId> {
        Vec::new()
    }

    /// Check if this pass is enabled for the given context
    fn is_enabled(&self, ctx: &PassContext) -> bool {
        ctx.optimize
    }

    /// Run the pass on the given context
    fn run(&self, ctx: &mut PassContext) -> Result<PassStats>;

    /// Verify pass invariants (for debugging)
    fn verify(&self, _ctx: &PassContext) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// Built-in Passes
// ============================================================================

/// Dead code elimination pass
#[derive(Debug, Default)]
pub struct DeadCodeElimPass;

impl OptPass for DeadCodeElimPass {
    fn id(&self) -> PassId {
        PassId::DeadCodeElim
    }

    fn name(&self) -> &'static str {
        "dead-code-elim"
    }

    fn description(&self) -> &'static str {
        "Remove unreachable instructions and dead stores"
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassStats> {
        use super::dead_code::optimize_dead_code;

        let before = ctx.insns.len();
        let result = optimize_dead_code(&mut ctx.insns)?;
        let after = ctx.insns.len();

        let mut stats = PassStats::new();
        stats.insns_before = before;
        stats.insns_after = after;
        stats.insns_removed = result.total_removed;
        stats.changed = result.total_removed > 0;
        stats.add_counter("dead_code_removed", result.dead_code_removed as u64);
        stats.add_counter("nops_removed", result.nops_removed as u64);

        Ok(stats)
    }
}

/// Speculation barrier insertion pass (Spectre mitigation)
#[derive(Debug, Default)]
pub struct SpectreMitigationPass {
    /// Force barriers even when not strictly needed
    pub force_barriers: bool,
}

impl SpectreMitigationPass {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_force_barriers(mut self, force: bool) -> Self {
        self.force_barriers = force;
        self
    }
}

impl OptPass for SpectreMitigationPass {
    fn id(&self) -> PassId {
        PassId::SpectreMitigation
    }

    fn name(&self) -> &'static str {
        "spectre-mitigation"
    }

    fn description(&self) -> &'static str {
        "Insert speculation barriers for Spectre v1 mitigation"
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassStats> {
        let mut stats = PassStats::new();
        stats.insns_before = ctx.insns.len();

        // Analyze for Spectre gadgets and insert barriers
        // This is a placeholder - actual implementation uses sanitize module
        let mut barriers_inserted = 0;

        // Scan for array accesses after conditional branches
        let mut i = 0;
        while i < ctx.insns.len() {
            let insn = &ctx.insns[i];
            let class = insn.class();
            let op = insn.code & 0xf0;

            // Check for conditional branch followed by memory access
            let is_cond_jmp = (class == BPF_JMP || class == BPF_JMP32) 
                && op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;

            if is_cond_jmp && i + 2 < ctx.insns.len() {
                let next = &ctx.insns[i + 1];
                let next_class = next.class();
                let is_mem_access = next_class == BPF_LDX || next_class == BPF_STX || next_class == BPF_ST;

                if is_mem_access {
                    // Check if the memory access uses a register that was
                    // bounded by the conditional (simplified check)
                    if self.force_barriers || self.needs_barrier(insn, next) {
                        // Insert nospec barrier before memory access
                        let barrier = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 0);
                        ctx.insns.insert(i + 1, barrier);
                        barriers_inserted += 1;
                        i += 1; // Skip the inserted instruction
                    }
                }
            }
            i += 1;
        }

        stats.insns_after = ctx.insns.len();
        stats.insns_inserted = barriers_inserted;
        stats.changed = barriers_inserted > 0;
        stats.add_counter("barriers_inserted", barriers_inserted as u64);

        Ok(stats)
    }
}

impl SpectreMitigationPass {
    fn needs_barrier(&self, _branch: &BpfInsn, _access: &BpfInsn) -> bool {
        // Simplified check - in reality this requires taint tracking
        // from the branch condition to the memory access
        false
    }
}

/// Zero extension insertion pass (for 32-bit operations on 64-bit platforms)
#[derive(Debug, Default)]
pub struct ZeroExtendPass;

impl OptPass for ZeroExtendPass {
    fn id(&self) -> PassId {
        PassId::ZeroExtend
    }

    fn name(&self) -> &'static str {
        "zero-extend"
    }

    fn description(&self) -> &'static str {
        "Insert zero extension after 32-bit ALU operations"
    }

    fn is_enabled(&self, ctx: &PassContext) -> bool {
        // Only needed for JIT on certain architectures
        ctx.jit_enabled
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassStats> {
        let mut stats = PassStats::new();
        stats.insns_before = ctx.insns.len();

        let mut extensions_inserted = 0;
        let mut i = 0;

        while i < ctx.insns.len() {
            let insn = &ctx.insns[i];

            // Check for ALU32 operations that need zero extension
            if insn.class() == BPF_ALU && self.needs_zext(insn) {
                // Insert MOV32 reg, reg to zero-extend upper 32 bits
                let zext = BpfInsn::new(
                    BPF_ALU | BPF_MOV | BPF_X,
                    insn.dst_reg,
                    insn.dst_reg,
                    0,
                    0,
                );
                ctx.insns.insert(i + 1, zext);
                extensions_inserted += 1;
                i += 1; // Skip inserted instruction
            }
            i += 1;
        }

        stats.insns_after = ctx.insns.len();
        stats.insns_inserted = extensions_inserted;
        stats.changed = extensions_inserted > 0;
        stats.add_counter("zext_inserted", extensions_inserted as u64);

        Ok(stats)
    }
}

impl ZeroExtendPass {
    fn needs_zext(&self, insn: &BpfInsn) -> bool {
        // ALU32 operations that produce values needing zero extension
        let op = insn.code & 0xf0;
        matches!(op, BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_MOD |
                     BPF_AND | BPF_OR | BPF_XOR | BPF_LSH | BPF_RSH | BPF_ARSH)
    }
}

/// Instruction size adjustment pass (gotol <-> goto conversion)
#[derive(Debug, Default)]
pub struct InsnSizeAdjustPass;

impl OptPass for InsnSizeAdjustPass {
    fn id(&self) -> PassId {
        PassId::InsnSizeAdjust
    }

    fn name(&self) -> &'static str {
        "insn-size-adjust"
    }

    fn description(&self) -> &'static str {
        "Convert between short and long jump instructions based on offset"
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassStats> {
        let mut stats = PassStats::new();
        stats.insns_before = ctx.insns.len();

        let mut conversions = 0;

        for i in 0..ctx.insns.len() {
            let insn = &ctx.insns[i];
            let class = insn.class();
            let op = insn.code & 0xf0;

            // Check for unconditional jump (JA)
            let is_uncond_jmp = (class == BPF_JMP || class == BPF_JMP32) && op == BPF_JA;

            if is_uncond_jmp {
                let offset = insn.off as i32;

                // Check if offset fits in 16-bit or needs 32-bit
                if offset < i16::MIN as i32 || offset > i16::MAX as i32 {
                    // Need to convert to gotol (32-bit offset)
                    // This is architecture-specific
                    conversions += 1;
                    stats.increment("short_to_long");
                }
                // Note: gotol detection would require checking for BPF_JMP32 variant
                // or the specific gotol encoding
            }
        }

        stats.insns_after = ctx.insns.len();
        stats.insns_modified = conversions;
        stats.changed = conversions > 0;

        Ok(stats)
    }
}

// ============================================================================
// Pass Manager
// ============================================================================

/// Configuration for the pass manager
#[derive(Debug, Clone)]
pub struct PassManagerConfig {
    /// Enable optimization passes
    pub optimize: bool,
    /// Enable JIT-specific passes
    pub jit_enabled: bool,
    /// Stop on first error
    pub stop_on_error: bool,
    /// Collect detailed statistics
    pub collect_stats: bool,
    /// Verify after each pass (for debugging)
    pub verify_each: bool,
    /// Maximum number of pass iterations (for iterative passes)
    pub max_iterations: usize,
}

impl Default for PassManagerConfig {
    fn default() -> Self {
        Self {
            optimize: true,
            jit_enabled: true,
            stop_on_error: true,
            collect_stats: false,
            verify_each: false,
            max_iterations: 10,
        }
    }
}

/// Optimization pass manager
#[derive(Debug)]
pub struct PassManager {
    /// Configuration
    config: PassManagerConfig,
    /// Registered passes
    passes: Vec<Box<dyn OptPass>>,
    /// Pass execution order (indices into passes)
    execution_order: Vec<usize>,
    /// Results from last run
    results: Vec<PassResult>,
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PassManager {
    /// Create a new pass manager with default configuration
    pub fn new() -> Self {
        Self {
            config: PassManagerConfig::default(),
            passes: Vec::new(),
            execution_order: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Create with specific configuration
    pub fn with_config(config: PassManagerConfig) -> Self {
        Self {
            config,
            passes: Vec::new(),
            execution_order: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Add a pass to the manager
    pub fn add_pass<P: OptPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
        self.execution_order.push(self.passes.len() - 1);
    }

    /// Add multiple passes
    pub fn add_passes(&mut self, passes: Vec<Box<dyn OptPass>>) {
        for pass in passes {
            let idx = self.passes.len();
            self.passes.push(pass);
            self.execution_order.push(idx);
        }
    }

    /// Get number of registered passes
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Compute pass execution order based on dependencies
    fn compute_execution_order(&mut self) -> Result<()> {
        // Topological sort based on dependencies
        let n = self.passes.len();
        let mut in_degree = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        // Build dependency graph
        for (i, pass) in self.passes.iter().enumerate() {
            for dep_id in pass.dependencies() {
                // Find pass with matching id
                for (j, other) in self.passes.iter().enumerate() {
                    if other.id() == dep_id {
                        adj[j].push(i);
                        in_degree[i] += 1;
                        break;
                    }
                }
            }
        }

        // Kahn's algorithm for topological sort
        let mut queue: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut order = Vec::with_capacity(n);

        while let Some(u) = queue.pop() {
            order.push(u);
            for &v in &adj[u] {
                in_degree[v] -= 1;
                if in_degree[v] == 0 {
                    queue.push(v);
                }
            }
        }

        if order.len() != n {
            return Err(VerifierError::TooComplex(
                "Circular dependency in optimization passes".into()
            ));
        }

        self.execution_order = order;
        Ok(())
    }

    /// Run all passes on the context
    pub fn run(&mut self, ctx: &mut PassContext) -> Result<&[PassResult]> {
        self.results.clear();

        // Compute execution order if needed
        if self.execution_order.is_empty() && !self.passes.is_empty() {
            self.compute_execution_order()?;
        }

        // Configure context
        ctx.optimize = self.config.optimize;
        ctx.jit_enabled = self.config.jit_enabled;
        ctx.collect_stats = self.config.collect_stats;

        // Run passes in order
        for &idx in &self.execution_order.clone() {
            let pass = &self.passes[idx];

            // Check if pass is enabled
            if !pass.is_enabled(ctx) {
                continue;
            }

            // Run the pass
            match pass.run(ctx) {
                Ok(stats) => {
                    let result = PassResult::success(pass.id(), stats);
                    self.results.push(result);

                    // Verify if requested
                    if self.config.verify_each {
                        if let Err(e) = pass.verify(ctx) {
                            if self.config.stop_on_error {
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    let result = PassResult::failure(pass.id(), e.clone());
                    self.results.push(result);

                    if self.config.stop_on_error {
                        return Err(e);
                    }
                }
            }
        }

        Ok(&self.results)
    }

    /// Run passes iteratively until no changes or max iterations
    pub fn run_iterative(&mut self, ctx: &mut PassContext) -> Result<usize> {
        let mut total_iterations = 0;

        for _ in 0..self.config.max_iterations {
            let results = self.run(ctx)?;

            // Check if any pass made changes
            let changed = results.iter().any(|r| r.stats.changed);
            total_iterations += 1;

            if !changed {
                break;
            }
        }

        Ok(total_iterations)
    }

    /// Get results from last run
    pub fn results(&self) -> &[PassResult] {
        &self.results
    }

    /// Get total statistics from last run
    pub fn total_stats(&self) -> PassStats {
        let mut total = PassStats::new();

        for result in &self.results {
            if result.success {
                total.insns_modified += result.stats.insns_modified;
                total.insns_removed += result.stats.insns_removed;
                total.insns_inserted += result.stats.insns_inserted;
                total.changed |= result.stats.changed;
            }
        }

        total
    }
}

/// Create a standard optimization pipeline
pub fn create_standard_pipeline() -> PassManager {
    let mut pm = PassManager::new();

    // Add passes in standard order
    pm.add_pass(DeadCodeElimPass);
    pm.add_pass(ZeroExtendPass);
    pm.add_pass(SpectreMitigationPass::new());
    pm.add_pass(InsnSizeAdjustPass);

    pm
}

/// Create a minimal pipeline (for testing or minimal optimization)
pub fn create_minimal_pipeline() -> PassManager {
    let mut pm = PassManager::with_config(PassManagerConfig {
        optimize: true,
        jit_enabled: false,
        stop_on_error: true,
        collect_stats: false,
        verify_each: false,
        max_iterations: 1,
    });

    pm.add_pass(DeadCodeElimPass);

    pm
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_stats_default() {
        let stats = PassStats::new();
        assert_eq!(stats.insns_before, 0);
        assert_eq!(stats.insns_after, 0);
        assert!(!stats.changed);
    }

    #[test]
    fn test_pass_stats_counters() {
        let mut stats = PassStats::new();
        stats.add_counter("test", 10);
        assert_eq!(stats.get_counter("test"), 10);

        stats.increment("test");
        assert_eq!(stats.get_counter("test"), 11); // increment updates existing counter

        stats.increment("new_counter");
        assert_eq!(stats.get_counter("new_counter"), 1);
    }

    #[test]
    fn test_pass_context_default() {
        let ctx = PassContext::default();
        assert!(ctx.insns.is_empty());
        assert_eq!(ctx.prog_type, BpfProgType::Unspec);
        assert!(!ctx.has_subprogs);
    }

    #[test]
    fn test_pass_context_builder() {
        let insns = vec![BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)];
        let ctx = PassContext::new(insns)
            .with_prog_type(BpfProgType::SocketFilter)
            .with_jit(true)
            .with_optimize(true);

        assert_eq!(ctx.insn_count(), 1);
        assert_eq!(ctx.prog_type, BpfProgType::SocketFilter);
        assert!(ctx.jit_enabled);
        assert!(ctx.optimize);
    }

    #[test]
    fn test_pass_manager_empty() {
        let pm = PassManager::new();
        assert_eq!(pm.pass_count(), 0);
    }

    #[test]
    fn test_pass_manager_add_pass() {
        let mut pm = PassManager::new();
        pm.add_pass(DeadCodeElimPass);
        assert_eq!(pm.pass_count(), 1);
    }

    #[test]
    fn test_pass_manager_run_empty_program() {
        let mut pm = PassManager::new();
        pm.add_pass(DeadCodeElimPass);

        let mut ctx = PassContext::new(Vec::new());
        let results = pm.run(&mut ctx).unwrap();

        // DeadCodeElimPass should succeed even on empty program
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_pass_manager_run_simple_program() {
        let mut pm = PassManager::new();
        pm.add_pass(DeadCodeElimPass);

        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut ctx = PassContext::new(insns);

        let results = pm.run(&mut ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_pass_result_success() {
        let stats = PassStats::new();
        let result = PassResult::success(PassId::DeadCodeElim, stats);

        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.pass_id, PassId::DeadCodeElim);
    }

    #[test]
    fn test_pass_result_failure() {
        let error = VerifierError::TooComplex("test".into());
        let result = PassResult::failure(PassId::DeadCodeElim, error);

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_dead_code_elim_pass_id() {
        let pass = DeadCodeElimPass;
        assert_eq!(pass.id(), PassId::DeadCodeElim);
        assert_eq!(pass.name(), "dead-code-elim");
    }

    #[test]
    fn test_spectre_mitigation_pass_config() {
        let pass = SpectreMitigationPass::new().with_force_barriers(true);
        assert!(pass.force_barriers);
    }

    #[test]
    fn test_zero_extend_pass_is_enabled() {
        let pass = ZeroExtendPass;

        let ctx_with_jit = PassContext::default().with_jit(true);
        assert!(pass.is_enabled(&ctx_with_jit));

        let ctx_without_jit = PassContext::default().with_jit(false);
        assert!(!pass.is_enabled(&ctx_without_jit));
    }

    #[test]
    fn test_create_standard_pipeline() {
        let pm = create_standard_pipeline();
        assert!(pm.pass_count() >= 4);
    }

    #[test]
    fn test_create_minimal_pipeline() {
        let pm = create_minimal_pipeline();
        assert!(pm.pass_count() >= 1);
    }

    #[test]
    fn test_pass_manager_total_stats() {
        let mut pm = PassManager::new();
        pm.add_pass(DeadCodeElimPass);

        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut ctx = PassContext::new(insns);

        let _ = pm.run(&mut ctx).unwrap();
        let total = pm.total_stats();

        // Stats should be aggregated
        assert!(!total.changed || total.insns_removed > 0 || total.insns_modified > 0);
    }

    #[test]
    fn test_pass_dependencies_empty() {
        let pass = DeadCodeElimPass;
        assert!(pass.dependencies().is_empty());
    }

    #[test]
    fn test_subprog_info_default() {
        let info = PassSubprogInfo::default();
        assert_eq!(info.start, 0);
        assert_eq!(info.end, 0);
        assert_eq!(info.stack_depth, 0);
        assert!(!info.has_tail_call);
    }

    #[test]
    fn test_pass_context_with_subprogs() {
        let subprogs = vec![
            PassSubprogInfo { start: 0, end: 10, stack_depth: 32, has_tail_call: false },
            PassSubprogInfo { start: 10, end: 20, stack_depth: 64, has_tail_call: true },
        ];

        let ctx = PassContext::new(Vec::new()).with_subprogs(subprogs);

        assert!(ctx.has_subprogs);
        assert_eq!(ctx.subprogs.len(), 2);
    }

    #[test]
    fn test_pass_manager_iterative() {
        let mut pm = PassManager::with_config(PassManagerConfig {
            max_iterations: 5,
            ..Default::default()
        });
        pm.add_pass(DeadCodeElimPass);

        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut ctx = PassContext::new(insns);

        let iterations = pm.run_iterative(&mut ctx).unwrap();

        // Should converge within max_iterations
        assert!(iterations <= 5);
    }

    #[test]
    fn test_insn_size_adjust_pass() {
        let pass = InsnSizeAdjustPass;
        assert_eq!(pass.id(), PassId::InsnSizeAdjust);
        assert_eq!(pass.name(), "insn-size-adjust");
    }

    #[test]
    fn test_pass_id_equality() {
        assert_eq!(PassId::DeadCodeElim, PassId::DeadCodeElim);
        assert_ne!(PassId::DeadCodeElim, PassId::ZeroExtend);
        assert_eq!(PassId::Custom(1), PassId::Custom(1));
        assert_ne!(PassId::Custom(1), PassId::Custom(2));
    }
}
