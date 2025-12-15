//! Verification limits.
//!
//! This module enforces verification limits to prevent denial of service
//! from overly complex programs and tracks resource usage during verification.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use core::time::Duration;

#[cfg(feature = "std")]
use std::time::{Duration, Instant};

use crate::core::error::{Result, VerifierError};

/// Default maximum number of instructions allowed.
pub const DEFAULT_MAX_INSNS: usize = 1_000_000;

/// Default maximum number of states per instruction.
pub const DEFAULT_MAX_STATES_PER_INSN: usize = 64;

/// Default maximum verification complexity (instructions processed).
pub const DEFAULT_MAX_COMPLEXITY: u64 = 1_000_000;

/// Default maximum call stack depth.
pub const DEFAULT_MAX_CALL_DEPTH: u32 = 8;

/// Default maximum number of subprograms.
pub const DEFAULT_MAX_SUBPROGS: usize = 256;

/// Default maximum BPF-to-BPF call chain length.
pub const DEFAULT_MAX_CALL_CHAIN: usize = 32;

/// Default maximum number of tail calls.
pub const DEFAULT_MAX_TAIL_CALLS: u32 = 33;

/// Default maximum number of loops (with bounded iteration).
pub const DEFAULT_MAX_LOOPS: u32 = 8;

/// Default maximum combined loop iterations.
pub const DEFAULT_MAX_LOOP_ITERATIONS: u32 = 1_000_000;

/// Default maximum map entries to check for state pruning.
pub const DEFAULT_MAX_MAP_ENTRIES_CHECK: usize = 16;

/// Default maximum verification time in seconds.
pub const DEFAULT_MAX_VERIFICATION_TIME_SECS: u64 = 60;

/// Default maximum memory usage in bytes.
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024; // 256 MB

/// Default maximum number of BTF types to process.
pub const DEFAULT_MAX_BTF_TYPES: usize = 100_000;

/// Default maximum function arguments.
pub const DEFAULT_MAX_FUNC_ARGS: usize = 5;

/// Default maximum log buffer size.
pub const DEFAULT_MAX_LOG_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// Resource limits configuration.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum number of instructions in the program.
    pub max_insns: usize,
    /// Maximum number of states per instruction for pruning.
    pub max_states_per_insn: usize,
    /// Maximum verification complexity (total instructions processed).
    pub max_complexity: u64,
    /// Maximum call stack depth.
    pub max_call_depth: u32,
    /// Maximum number of subprograms.
    pub max_subprogs: usize,
    /// Maximum BPF-to-BPF call chain length.
    pub max_call_chain: usize,
    /// Maximum number of tail calls.
    pub max_tail_calls: u32,
    /// Maximum number of bounded loops.
    pub max_loops: u32,
    /// Maximum combined loop iterations.
    pub max_loop_iterations: u32,
    /// Maximum map entries to check during state comparison.
    pub max_map_entries_check: usize,
    /// Maximum verification time.
    pub max_verification_time: Duration,
    /// Maximum memory usage.
    pub max_memory_bytes: usize,
    /// Maximum BTF types.
    pub max_btf_types: usize,
    /// Maximum function arguments.
    pub max_func_args: usize,
    /// Maximum log buffer size.
    pub max_log_size: usize,
    /// Whether to enforce strict limits (fail fast) or soft limits (warn).
    pub strict: bool,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
            max_states_per_insn: DEFAULT_MAX_STATES_PER_INSN,
            max_complexity: DEFAULT_MAX_COMPLEXITY,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            max_subprogs: DEFAULT_MAX_SUBPROGS,
            max_call_chain: DEFAULT_MAX_CALL_CHAIN,
            max_tail_calls: DEFAULT_MAX_TAIL_CALLS,
            max_loops: DEFAULT_MAX_LOOPS,
            max_loop_iterations: DEFAULT_MAX_LOOP_ITERATIONS,
            max_map_entries_check: DEFAULT_MAX_MAP_ENTRIES_CHECK,
            max_verification_time: Duration::from_secs(DEFAULT_MAX_VERIFICATION_TIME_SECS),
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_btf_types: DEFAULT_MAX_BTF_TYPES,
            max_func_args: DEFAULT_MAX_FUNC_ARGS,
            max_log_size: DEFAULT_MAX_LOG_SIZE,
            strict: true,
        }
    }
}

impl ResourceLimits {
    /// Create new limits with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create relaxed limits for testing or trusted programs.
    pub fn relaxed() -> Self {
        Self {
            max_insns: 10_000_000,
            max_states_per_insn: 256,
            max_complexity: 10_000_000,
            max_call_depth: 32,
            max_subprogs: 1024,
            max_call_chain: 64,
            max_tail_calls: 64,
            max_loops: 32,
            max_loop_iterations: 10_000_000,
            max_map_entries_check: 64,
            max_verification_time: Duration::from_secs(300),
            max_memory_bytes: 1024 * 1024 * 1024, // 1 GB
            max_btf_types: 1_000_000,
            max_func_args: 12,
            max_log_size: 64 * 1024 * 1024,
            strict: false,
        }
    }

    /// Create strict limits for unprivileged programs.
    pub fn unprivileged() -> Self {
        Self {
            max_insns: 4096,
            max_states_per_insn: 16,
            max_complexity: 100_000,
            max_call_depth: 4,
            max_subprogs: 16,
            max_call_chain: 8,
            max_tail_calls: 8,
            max_loops: 4,
            max_loop_iterations: 10_000,
            max_map_entries_check: 8,
            max_verification_time: Duration::from_secs(10),
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_btf_types: 10_000,
            max_func_args: 5,
            max_log_size: 1024 * 1024,
            strict: true,
        }
    }

    /// Set maximum instructions.
    pub fn with_max_insns(mut self, max: usize) -> Self {
        self.max_insns = max;
        self
    }

    /// Set maximum complexity.
    pub fn with_max_complexity(mut self, max: u64) -> Self {
        self.max_complexity = max;
        self
    }

    /// Set maximum call depth.
    pub fn with_max_call_depth(mut self, max: u32) -> Self {
        self.max_call_depth = max;
        self
    }

    /// Set maximum verification time.
    pub fn with_max_time(mut self, duration: Duration) -> Self {
        self.max_verification_time = duration;
        self
    }

    /// Set strict mode.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }
}

/// Current resource usage during verification.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Number of instructions in the program.
    pub insn_count: usize,
    /// Total instructions processed (complexity).
    pub insns_processed: u64,
    /// Current call stack depth.
    pub call_depth: u32,
    /// Peak call stack depth.
    pub peak_call_depth: u32,
    /// Number of subprograms.
    pub subprog_count: usize,
    /// Current call chain length.
    pub call_chain_len: usize,
    /// Number of tail calls encountered.
    pub tail_calls: u32,
    /// Number of bounded loops.
    pub loop_count: u32,
    /// Total loop iterations.
    pub loop_iterations: u32,
    /// Total states created.
    pub states_created: u64,
    /// States pruned.
    pub states_pruned: u64,
    /// Peak states held in memory.
    pub peak_states: usize,
    /// Current states in memory.
    pub current_states: usize,
    /// Estimated memory usage in bytes.
    pub memory_bytes: usize,
    /// BTF types processed.
    pub btf_types_processed: usize,
    /// Log bytes written.
    pub log_bytes: usize,
    /// Maximum states at any single instruction.
    pub max_states_at_insn: usize,
}

impl ResourceUsage {
    /// Create new empty usage tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an instruction being processed.
    pub fn record_insn_processed(&mut self) {
        self.insns_processed += 1;
    }

    /// Record entering a call frame.
    pub fn record_call_enter(&mut self) {
        self.call_depth += 1;
        if self.call_depth > self.peak_call_depth {
            self.peak_call_depth = self.call_depth;
        }
    }

    /// Record exiting a call frame.
    pub fn record_call_exit(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    /// Record a tail call.
    pub fn record_tail_call(&mut self) {
        self.tail_calls += 1;
    }

    /// Record loop entry.
    pub fn record_loop(&mut self, iterations: u32) {
        self.loop_count += 1;
        self.loop_iterations += iterations;
    }

    /// Record state creation.
    pub fn record_state_created(&mut self) {
        self.states_created += 1;
        self.current_states += 1;
        if self.current_states > self.peak_states {
            self.peak_states = self.current_states;
        }
    }

    /// Record state pruned.
    pub fn record_state_pruned(&mut self) {
        self.states_pruned += 1;
        self.current_states = self.current_states.saturating_sub(1);
    }

    /// Update states at instruction count.
    pub fn update_states_at_insn(&mut self, count: usize) {
        if count > self.max_states_at_insn {
            self.max_states_at_insn = count;
        }
    }

    /// Update memory usage estimate.
    pub fn update_memory(&mut self, bytes: usize) {
        self.memory_bytes = bytes;
    }

    /// Record log bytes written.
    pub fn record_log_bytes(&mut self, bytes: usize) {
        self.log_bytes += bytes;
    }
}

/// Resource limit checker that enforces limits during verification.
#[derive(Debug)]
pub struct LimitChecker {
    /// Configured limits.
    limits: ResourceLimits,
    /// Current usage.
    usage: ResourceUsage,
    /// Start time of verification (only available with std).
    #[cfg(feature = "std")]
    start_time: Option<Instant>,
    /// Warnings generated (for non-strict mode).
    warnings: Vec<LimitWarning>,
}

/// Warning about approaching or exceeding a limit.
#[derive(Debug, Clone)]
pub struct LimitWarning {
    /// Type of limit.
    pub limit_type: LimitType,
    /// Current value.
    pub current: u64,
    /// Maximum allowed.
    pub maximum: u64,
    /// Percentage of limit used.
    pub percentage: f64,
    /// Warning message.
    pub message: String,
}

/// Types of resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    /// Instruction count.
    Instructions,
    /// Verification complexity.
    Complexity,
    /// Call depth.
    CallDepth,
    /// Subprogram count.
    Subprograms,
    /// Call chain length.
    CallChain,
    /// Tail calls.
    TailCalls,
    /// Loop count.
    Loops,
    /// Loop iterations.
    LoopIterations,
    /// States per instruction.
    StatesPerInsn,
    /// Verification time.
    Time,
    /// Memory usage.
    Memory,
    /// BTF types.
    BtfTypes,
    /// Log size.
    LogSize,
}

impl LimitChecker {
    /// Create a new limit checker with given limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            usage: ResourceUsage::new(),
            #[cfg(feature = "std")]
            start_time: None,
            warnings: Vec::new(),
        }
    }

    /// Create with default limits.
    pub fn with_defaults() -> Self {
        Self::new(ResourceLimits::default())
    }

    /// Start tracking time.
    #[cfg(feature = "std")]
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Start tracking time (no-op in no_std).
    #[cfg(not(feature = "std"))]
    pub fn start(&mut self) {
        // No-op in no_std - no Instant available
    }

    /// Get current usage.
    pub fn usage(&self) -> &ResourceUsage {
        &self.usage
    }

    /// Get mutable usage.
    pub fn usage_mut(&mut self) -> &mut ResourceUsage {
        &mut self.usage
    }

    /// Get limits.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Get warnings.
    pub fn warnings(&self) -> &[LimitWarning] {
        &self.warnings
    }

    /// Set initial instruction count.
    pub fn set_insn_count(&mut self, count: usize) -> Result<()> {
        self.usage.insn_count = count;
        self.check_limit(
            LimitType::Instructions,
            count as u64,
            self.limits.max_insns as u64,
        )
    }

    /// Set subprogram count.
    pub fn set_subprog_count(&mut self, count: usize) -> Result<()> {
        self.usage.subprog_count = count;
        self.check_limit(
            LimitType::Subprograms,
            count as u64,
            self.limits.max_subprogs as u64,
        )
    }

    /// Record and check instruction processed.
    pub fn check_insn_processed(&mut self) -> Result<()> {
        self.usage.record_insn_processed();
        self.check_limit(
            LimitType::Complexity,
            self.usage.insns_processed,
            self.limits.max_complexity,
        )?;
        self.check_time()
    }

    /// Record and check call enter.
    pub fn check_call_enter(&mut self) -> Result<()> {
        self.usage.record_call_enter();
        self.check_limit(
            LimitType::CallDepth,
            self.usage.call_depth as u64,
            self.limits.max_call_depth as u64,
        )
    }

    /// Record call exit.
    pub fn record_call_exit(&mut self) {
        self.usage.record_call_exit();
    }

    /// Record and check tail call.
    pub fn check_tail_call(&mut self) -> Result<()> {
        self.usage.record_tail_call();
        self.check_limit(
            LimitType::TailCalls,
            self.usage.tail_calls as u64,
            self.limits.max_tail_calls as u64,
        )
    }

    /// Record and check loop.
    pub fn check_loop(&mut self, iterations: u32) -> Result<()> {
        self.usage.record_loop(iterations);
        self.check_limit(
            LimitType::Loops,
            self.usage.loop_count as u64,
            self.limits.max_loops as u64,
        )?;
        self.check_limit(
            LimitType::LoopIterations,
            self.usage.loop_iterations as u64,
            self.limits.max_loop_iterations as u64,
        )
    }

    /// Record and check states at instruction.
    pub fn check_states_at_insn(&mut self, count: usize) -> Result<()> {
        self.usage.update_states_at_insn(count);
        self.check_limit(
            LimitType::StatesPerInsn,
            count as u64,
            self.limits.max_states_per_insn as u64,
        )
    }

    /// Record state created.
    pub fn record_state_created(&mut self) {
        self.usage.record_state_created();
    }

    /// Record state pruned.
    pub fn record_state_pruned(&mut self) {
        self.usage.record_state_pruned();
    }

    /// Check and update memory usage.
    pub fn check_memory(&mut self, bytes: usize) -> Result<()> {
        self.usage.update_memory(bytes);
        self.check_limit(
            LimitType::Memory,
            bytes as u64,
            self.limits.max_memory_bytes as u64,
        )
    }

    /// Check and update log size.
    pub fn check_log_size(&mut self, bytes: usize) -> Result<()> {
        self.usage.record_log_bytes(bytes);
        self.check_limit(
            LimitType::LogSize,
            self.usage.log_bytes as u64,
            self.limits.max_log_size as u64,
        )
    }

    /// Check BTF types count.
    pub fn check_btf_types(&mut self, count: usize) -> Result<()> {
        self.usage.btf_types_processed = count;
        self.check_limit(
            LimitType::BtfTypes,
            count as u64,
            self.limits.max_btf_types as u64,
        )
    }

    /// Check elapsed time.
    #[cfg(feature = "std")]
    pub fn check_time(&self) -> Result<()> {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed();
            if elapsed > self.limits.max_verification_time {
                return Err(VerifierError::ComplexityLimitExceeded(format!(
                    "verification time {:.2}s exceeds limit of {:.2}s",
                    elapsed.as_secs_f64(),
                    self.limits.max_verification_time.as_secs_f64()
                )));
            }
        }
        Ok(())
    }

    /// Check elapsed time (no-op in no_std).
    #[cfg(not(feature = "std"))]
    pub fn check_time(&self) -> Result<()> {
        Ok(())
    }

    /// Get elapsed time.
    #[cfg(feature = "std")]
    pub fn elapsed(&self) -> Duration {
        self.start_time
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Get elapsed time (always zero in no_std).
    #[cfg(not(feature = "std"))]
    pub fn elapsed(&self) -> Duration {
        Duration::ZERO
    }

    /// Check a limit and return error or warning as appropriate.
    fn check_limit(&mut self, limit_type: LimitType, current: u64, maximum: u64) -> Result<()> {
        if maximum == 0 {
            return Ok(()); // Limit disabled
        }

        let percentage = (current as f64 / maximum as f64) * 100.0;

        if current > maximum {
            if self.limits.strict {
                return Err(self.make_limit_error(limit_type, current, maximum));
            } else {
                self.add_warning(limit_type, current, maximum, percentage);
            }
        } else if percentage >= 90.0 {
            // Warn when approaching limit
            self.add_warning(limit_type, current, maximum, percentage);
        }

        Ok(())
    }

    /// Create limit exceeded error.
    fn make_limit_error(&self, limit_type: LimitType, current: u64, maximum: u64) -> VerifierError {
        let msg = match limit_type {
            LimitType::Instructions => format!(
                "program too large: {} instructions, maximum {}",
                current, maximum
            ),
            LimitType::Complexity => format!(
                "verification complexity {} exceeds limit {}",
                current, maximum
            ),
            LimitType::CallDepth => format!(
                "call depth {} exceeds maximum {}",
                current, maximum
            ),
            LimitType::Subprograms => format!(
                "too many subprograms: {}, maximum {}",
                current, maximum
            ),
            LimitType::CallChain => format!(
                "call chain length {} exceeds maximum {}",
                current, maximum
            ),
            LimitType::TailCalls => format!(
                "too many tail calls: {}, maximum {}",
                current, maximum
            ),
            LimitType::Loops => format!(
                "too many loops: {}, maximum {}",
                current, maximum
            ),
            LimitType::LoopIterations => format!(
                "loop iterations {} exceed maximum {}",
                current, maximum
            ),
            LimitType::StatesPerInsn => format!(
                "states per instruction {} exceeds maximum {}",
                current, maximum
            ),
            LimitType::Time => format!(
                "verification time exceeded ({}s > {}s)",
                current, maximum
            ),
            LimitType::Memory => format!(
                "memory usage {} bytes exceeds limit {} bytes",
                current, maximum
            ),
            LimitType::BtfTypes => format!(
                "BTF types {} exceeds limit {}",
                current, maximum
            ),
            LimitType::LogSize => format!(
                "log size {} bytes exceeds limit {} bytes",
                current, maximum
            ),
        };

        VerifierError::ComplexityLimitExceeded(msg)
    }

    /// Add a warning.
    fn add_warning(&mut self, limit_type: LimitType, current: u64, maximum: u64, percentage: f64) {
        let message = format!(
            "{:?} at {:.1}% of limit ({}/{})",
            limit_type, percentage, current, maximum
        );
        self.warnings.push(LimitWarning {
            limit_type,
            current,
            maximum,
            percentage,
            message,
        });
    }

    /// Get summary of resource usage.
    pub fn summary(&self) -> ResourceSummary {
        ResourceSummary {
            insn_count: self.usage.insn_count,
            insns_processed: self.usage.insns_processed,
            peak_call_depth: self.usage.peak_call_depth,
            subprog_count: self.usage.subprog_count,
            tail_calls: self.usage.tail_calls,
            loop_count: self.usage.loop_count,
            loop_iterations: self.usage.loop_iterations,
            states_created: self.usage.states_created,
            states_pruned: self.usage.states_pruned,
            peak_states: self.usage.peak_states,
            max_states_at_insn: self.usage.max_states_at_insn,
            memory_bytes: self.usage.memory_bytes,
            elapsed: self.elapsed(),
            warning_count: self.warnings.len(),
        }
    }
}

/// Summary of resource usage for reporting.
#[derive(Debug, Clone)]
pub struct ResourceSummary {
    /// Number of instructions.
    pub insn_count: usize,
    /// Instructions processed (complexity).
    pub insns_processed: u64,
    /// Peak call depth.
    pub peak_call_depth: u32,
    /// Number of subprograms.
    pub subprog_count: usize,
    /// Tail calls made.
    pub tail_calls: u32,
    /// Number of loops.
    pub loop_count: u32,
    /// Total loop iterations.
    pub loop_iterations: u32,
    /// States created.
    pub states_created: u64,
    /// States pruned.
    pub states_pruned: u64,
    /// Peak states in memory.
    pub peak_states: usize,
    /// Maximum states at any instruction.
    pub max_states_at_insn: usize,
    /// Memory used.
    pub memory_bytes: usize,
    /// Time elapsed.
    pub elapsed: Duration,
    /// Number of warnings.
    pub warning_count: usize,
}

impl core::fmt::Display for ResourceSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Resource Usage Summary:")?;
        writeln!(f, "  Instructions: {}", self.insn_count)?;
        writeln!(f, "  Complexity (insns processed): {}", self.insns_processed)?;
        writeln!(f, "  Peak call depth: {}", self.peak_call_depth)?;
        writeln!(f, "  Subprograms: {}", self.subprog_count)?;
        writeln!(f, "  Tail calls: {}", self.tail_calls)?;
        writeln!(f, "  Loops: {} ({} iterations)", self.loop_count, self.loop_iterations)?;
        writeln!(f, "  States: {} created, {} pruned, {} peak",
            self.states_created, self.states_pruned, self.peak_states)?;
        writeln!(f, "  Max states at instruction: {}", self.max_states_at_insn)?;
        writeln!(f, "  Memory: {} KB", self.memory_bytes / 1024)?;
        writeln!(f, "  Time: {:.3}s", self.elapsed.as_secs_f64())?;
        if self.warning_count > 0 {
            writeln!(f, "  Warnings: {}", self.warning_count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_insns, DEFAULT_MAX_INSNS);
        assert_eq!(limits.max_complexity, DEFAULT_MAX_COMPLEXITY);
        assert_eq!(limits.max_call_depth, DEFAULT_MAX_CALL_DEPTH);
        assert!(limits.strict);
    }

    #[test]
    fn test_relaxed_limits() {
        let limits = ResourceLimits::relaxed();
        assert!(limits.max_insns > DEFAULT_MAX_INSNS);
        assert!(limits.max_complexity > DEFAULT_MAX_COMPLEXITY);
        assert!(!limits.strict);
    }

    #[test]
    fn test_unprivileged_limits() {
        let limits = ResourceLimits::unprivileged();
        assert!(limits.max_insns < DEFAULT_MAX_INSNS);
        assert!(limits.max_complexity < DEFAULT_MAX_COMPLEXITY);
        assert!(limits.strict);
    }

    #[test]
    fn test_limits_builder() {
        let limits = ResourceLimits::new()
            .with_max_insns(5000)
            .with_max_complexity(500_000)
            .with_max_call_depth(16)
            .with_strict(false);

        assert_eq!(limits.max_insns, 5000);
        assert_eq!(limits.max_complexity, 500_000);
        assert_eq!(limits.max_call_depth, 16);
        assert!(!limits.strict);
    }

    #[test]
    fn test_resource_usage_tracking() {
        let mut usage = ResourceUsage::new();

        usage.record_insn_processed();
        usage.record_insn_processed();
        assert_eq!(usage.insns_processed, 2);

        usage.record_call_enter();
        assert_eq!(usage.call_depth, 1);
        usage.record_call_enter();
        assert_eq!(usage.call_depth, 2);
        assert_eq!(usage.peak_call_depth, 2);

        usage.record_call_exit();
        assert_eq!(usage.call_depth, 1);
        assert_eq!(usage.peak_call_depth, 2); // Peak unchanged

        usage.record_state_created();
        usage.record_state_created();
        assert_eq!(usage.states_created, 2);
        assert_eq!(usage.current_states, 2);
        assert_eq!(usage.peak_states, 2);

        usage.record_state_pruned();
        assert_eq!(usage.states_pruned, 1);
        assert_eq!(usage.current_states, 1);
        assert_eq!(usage.peak_states, 2); // Peak unchanged
    }

    #[test]
    fn test_limit_checker_insn_count() {
        let limits = ResourceLimits::new().with_max_insns(100);
        let mut checker = LimitChecker::new(limits);

        assert!(checker.set_insn_count(50).is_ok());
        assert!(checker.set_insn_count(100).is_ok());
        assert!(checker.set_insn_count(101).is_err());
    }

    #[test]
    fn test_limit_checker_complexity() {
        let limits = ResourceLimits::new().with_max_complexity(10);
        let mut checker = LimitChecker::new(limits);
        checker.start();

        for _ in 0..10 {
            assert!(checker.check_insn_processed().is_ok());
        }
        // 11th should fail
        assert!(checker.check_insn_processed().is_err());
    }

    #[test]
    fn test_limit_checker_call_depth() {
        let limits = ResourceLimits::new().with_max_call_depth(3);
        let mut checker = LimitChecker::new(limits);

        assert!(checker.check_call_enter().is_ok()); // depth 1
        assert!(checker.check_call_enter().is_ok()); // depth 2
        assert!(checker.check_call_enter().is_ok()); // depth 3
        assert!(checker.check_call_enter().is_err()); // depth 4 - exceeds
    }

    #[test]
    fn test_limit_checker_non_strict() {
        let limits = ResourceLimits::new()
            .with_max_insns(100)
            .with_strict(false);
        let mut checker = LimitChecker::new(limits);

        // Should succeed even over limit in non-strict mode
        assert!(checker.set_insn_count(150).is_ok());
        assert!(!checker.warnings().is_empty());
    }

    #[test]
    fn test_limit_checker_warnings() {
        let limits = ResourceLimits::new().with_max_complexity(100);
        let mut checker = LimitChecker::new(limits);
        checker.start();

        // Process 91 instructions (91% of limit)
        for _ in 0..91 {
            let _ = checker.check_insn_processed();
        }

        // Should have warnings about approaching limit
        assert!(!checker.warnings().is_empty());
    }

    #[test]
    fn test_limit_checker_tail_calls() {
        let limits = ResourceLimits::default();
        let mut checker = LimitChecker::new(limits);

        for _ in 0..DEFAULT_MAX_TAIL_CALLS {
            assert!(checker.check_tail_call().is_ok());
        }
        assert!(checker.check_tail_call().is_err());
    }

    #[test]
    fn test_limit_checker_loops() {
        let limits = ResourceLimits::new()
            .with_max_insns(1000);
        let mut checker = LimitChecker::new(limits.clone());

        // Check loop count
        for _ in 0..DEFAULT_MAX_LOOPS {
            assert!(checker.check_loop(10).is_ok());
        }
        assert!(checker.check_loop(10).is_err());
    }

    #[test]
    fn test_limit_checker_states() {
        let limits = ResourceLimits::new();
        let mut checker = LimitChecker::new(limits);

        assert!(checker.check_states_at_insn(32).is_ok());
        assert!(checker.check_states_at_insn(64).is_ok());
        assert!(checker.check_states_at_insn(65).is_err());
    }

    #[test]
    fn test_resource_summary_display() {
        let limits = ResourceLimits::new();
        let mut checker = LimitChecker::new(limits);
        checker.start();
        checker.usage_mut().insn_count = 100;
        checker.usage_mut().insns_processed = 500;
        checker.usage_mut().peak_call_depth = 3;

        let summary = checker.summary();
        let output = format!("{}", summary);

        assert!(output.contains("Instructions: 100"));
        assert!(output.contains("Complexity"));
        assert!(output.contains("Peak call depth: 3"));
    }

    #[test]
    fn test_elapsed_time() {
        let limits = ResourceLimits::new();
        let mut checker = LimitChecker::new(limits);
        
        assert_eq!(checker.elapsed(), Duration::ZERO);
        
        checker.start();
        std::thread::sleep(Duration::from_millis(10));
        
        assert!(checker.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn test_memory_check() {
        let limits = ResourceLimits::new();
        let mut checker = LimitChecker::new(limits);

        assert!(checker.check_memory(100 * 1024 * 1024).is_ok()); // 100 MB
        assert!(checker.check_memory(300 * 1024 * 1024).is_err()); // 300 MB > 256 MB default
    }

    #[test]
    fn test_log_size_check() {
        let limits = ResourceLimits::new();
        let mut checker = LimitChecker::new(limits);

        assert!(checker.check_log_size(1024 * 1024).is_ok()); // 1 MB
        
        // Accumulate to over limit
        for _ in 0..20 {
            let _ = checker.check_log_size(1024 * 1024); // 1 MB each
        }
        
        assert!(checker.usage().log_bytes > DEFAULT_MAX_LOG_SIZE);
    }
}
