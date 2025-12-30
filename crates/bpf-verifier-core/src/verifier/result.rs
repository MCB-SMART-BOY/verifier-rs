// SPDX-License-Identifier: GPL-2.0

//! 验证结果和错误报告模块
//!
//! Verification result and error reporting.
//!
//! 本模块提供结构化的验证结果，包含详细的错误信息、修复建议和综合报告。
//!
//! This module provides structured verification results with detailed
//! error information, suggestions for fixes, and comprehensive reporting.
//!
//! # 结果类型 / Result Types
//!
//! - **成功 / Success**: 包含统计信息、警告和程序属性
//! - **失败 / Failure**: 包含错误、上下文、修复建议
//! - **中止 / Aborted**: 包含中止原因和进度信息

use crate::core::error::VerifierError;
use crate::core::types::*;
use crate::verifier::stats::VerifierStats;
use core::fmt;

use alloc::{format, string::String, vec::Vec};

/// Overall verification result
#[derive(Debug, Clone)]
pub enum VerificationOutcome {
    /// Program passed verification
    Success(SuccessInfo),
    /// Program failed verification
    Failure(FailureInfo),
    /// Verification was aborted (complexity limit, timeout, etc.)
    Aborted(AbortInfo),
}

impl VerificationOutcome {
    /// Check if verification succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, VerificationOutcome::Success(_))
    }

    /// Check if verification failed
    pub fn is_failure(&self) -> bool {
        matches!(self, VerificationOutcome::Failure(_))
    }

    /// Get the error if this is a failure
    pub fn error(&self) -> Option<&VerifierError> {
        match self {
            VerificationOutcome::Failure(info) => Some(&info.error),
            _ => None,
        }
    }
}

/// Information about successful verification
#[derive(Debug, Clone, Default)]
pub struct SuccessInfo {
    /// Verification statistics
    pub stats: VerifierStats,
    /// Warnings generated during verification
    pub warnings: Vec<VerifierWarning>,
    /// Program properties discovered
    pub properties: ProgramProperties,
}

/// Information about failed verification
#[derive(Debug, Clone)]
pub struct FailureInfo {
    /// The error that caused the failure
    pub error: VerifierError,
    /// Instruction index where the error occurred
    pub insn_idx: usize,
    /// Error context (what was being verified)
    pub context: ErrorContext,
    /// Suggestions for fixing the error
    pub suggestions: Vec<String>,
    /// Related errors (if multiple issues detected)
    pub related: Vec<RelatedError>,
    /// Partial statistics (up to the point of failure)
    pub partial_stats: Option<VerifierStats>,
}

impl FailureInfo {
    /// Create a new failure info
    pub fn new(error: VerifierError, insn_idx: usize) -> Self {
        Self {
            error,
            insn_idx,
            context: ErrorContext::Unknown,
            suggestions: Vec::new(),
            related: Vec::new(),
            partial_stats: None,
        }
    }

    /// Add context to the error
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }

    /// Add a suggestion
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    /// Add related error
    pub fn with_related(mut self, error: RelatedError) -> Self {
        self.related.push(error);
        self
    }
}

/// Information about aborted verification
#[derive(Debug, Clone)]
pub struct AbortInfo {
    /// Reason for abort
    pub reason: AbortReason,
    /// Progress made before abort
    pub progress: VerificationProgress,
    /// Partial statistics
    pub partial_stats: Option<VerifierStats>,
}

/// Reason verification was aborted
#[derive(Debug, Clone)]
pub enum AbortReason {
    /// Complexity limit exceeded
    ComplexityLimit {
        /// Maximum allowed complexity
        limit: u64,
        /// Actual complexity reached
        reached: u64,
    },
    /// State limit exceeded
    StateLimit {
        /// Maximum allowed states
        limit: usize,
        /// Actual states reached
        reached: usize,
    },
    /// Timeout
    Timeout {
        /// Timeout limit in milliseconds
        limit_ms: u64,
        /// Elapsed time in milliseconds
        elapsed_ms: u64,
    },
    /// User requested abort
    UserAbort,
    /// Internal error
    InternalError(String),
}

/// Progress made during verification
#[derive(Debug, Clone, Default)]
pub struct VerificationProgress {
    /// Number of instructions verified
    pub insns_verified: usize,
    /// Number of branches explored
    pub branches_explored: usize,
    /// Percentage of program covered (0-100)
    pub coverage_percent: u32,
}

/// Context in which an error occurred
#[derive(Debug, Clone)]
pub enum ErrorContext {
    /// Error during ALU operation
    AluOp {
        /// ALU operation name
        op: &'static str,
        /// Destination register
        dst_reg: u8,
        /// Source operand
        src: AluSource,
    },
    /// Error during memory access
    MemoryAccess {
        /// Type of memory access
        access_type: MemAccessKind,
        /// Register holding pointer
        ptr_reg: u8,
        /// Offset from pointer
        offset: i32,
        /// Access size in bytes
        size: u32,
    },
    /// Error during jump verification
    Jump {
        /// Type of jump
        jump_type: JumpType,
        /// Jump target instruction
        target: usize,
    },
    /// Error during call verification
    Call {
        /// Type of call
        call_type: CallType,
        /// Function ID being called
        func_id: i32,
    },
    /// Error during return verification
    Return {
        /// Current frame depth
        frame_depth: u32,
    },
    /// Error verifying register state
    RegisterState {
        /// Register number
        regno: u8,
        /// Expected state description
        expected: &'static str,
    },
    /// Error during stack access
    StackAccess {
        /// Stack offset
        offset: i32,
        /// Access size
        size: u32,
        /// Whether this is a write access
        is_write: bool,
    },
    /// Unknown context
    Unknown,
}

/// Source of ALU operation
#[derive(Debug, Clone)]
pub enum AluSource {
    /// Source is a register
    Register(u8),
    /// Source is an immediate value
    Immediate(i32),
}

/// Kind of memory access
#[derive(Debug, Clone, Copy)]
pub enum MemAccessKind {
    /// Read from memory
    Read,
    /// Write to memory
    Write,
    /// Atomic operation
    Atomic,
}

/// Type of jump
#[derive(Debug, Clone, Copy)]
pub enum JumpType {
    /// Unconditional jump
    Unconditional,
    /// Conditional branch
    Conditional,
    /// Function call
    Call,
}

/// Type of call
#[derive(Debug, Clone, Copy)]
pub enum CallType {
    /// BPF helper function
    Helper,
    /// Kernel function (kfunc)
    Kfunc,
    /// BPF subprogram
    Subprogram,
    /// Callback function
    Callback,
}

/// Related error (secondary issue)
#[derive(Debug, Clone)]
pub struct RelatedError {
    /// The error
    pub error: VerifierError,
    /// Instruction index
    pub insn_idx: usize,
    /// Brief description
    pub description: String,
}

/// Warning generated during verification
#[derive(Debug, Clone)]
pub struct VerifierWarning {
    /// Warning code
    pub code: WarningCode,
    /// Instruction index (if applicable)
    pub insn_idx: Option<usize>,
    /// Warning message
    pub message: String,
}

/// Warning codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningCode {
    /// Unreachable code detected
    UnreachableCode,
    /// Unused register
    UnusedRegister,
    /// Redundant bounds check
    RedundantBoundsCheck,
    /// Suboptimal instruction sequence
    SuboptimalCode,
    /// Potential performance issue
    PerformanceIssue,
    /// Deprecated feature usage
    DeprecatedFeature,
    /// Unusual pattern detected
    UnusualPattern,
}

/// Properties discovered about the program
#[derive(Debug, Clone, Default)]
pub struct ProgramProperties {
    /// Whether program uses maps
    pub uses_maps: bool,
    /// Whether program uses helpers
    pub uses_helpers: bool,
    /// Whether program uses kfuncs
    pub uses_kfuncs: bool,
    /// Whether program has subprograms
    pub has_subprograms: bool,
    /// Whether program uses packet access
    pub uses_packet_access: bool,
    /// Whether program uses spinlocks
    pub uses_spinlocks: bool,
    /// Whether program uses RCU
    pub uses_rcu: bool,
    /// Whether program uses timers
    pub uses_timers: bool,
    /// Whether program uses ringbuf
    pub uses_ringbuf: bool,
    /// Whether program has bounded loops
    pub has_bounded_loops: bool,
    /// Maximum stack depth used
    pub max_stack_depth: i32,
    /// List of helper IDs used
    pub helpers_used: Vec<u32>,
    /// List of map types used
    pub map_types_used: Vec<BpfMapType>,
}

/// Builder for verification results
#[derive(Debug)]
pub struct ResultBuilder {
    /// Cached outcome if already built
    outcome: Option<VerificationOutcome>,
    /// Verification statistics
    pub stats: VerifierStats,
    warnings: Vec<VerifierWarning>,
    properties: ProgramProperties,
}

impl ResultBuilder {
    /// Create a new result builder
    pub fn new() -> Self {
        Self {
            outcome: None,
            stats: VerifierStats::default(),
            warnings: Vec::new(),
            properties: ProgramProperties::default(),
        }
    }

    /// Set statistics
    pub fn with_stats(mut self, stats: VerifierStats) -> Self {
        self.stats = stats;
        self
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: VerifierWarning) {
        self.warnings.push(warning);
    }

    /// Set a program property
    pub fn set_property(&mut self, setter: impl FnOnce(&mut ProgramProperties)) {
        setter(&mut self.properties);
    }

    /// Record helper usage
    pub fn record_helper(&mut self, helper_id: u32) {
        self.properties.uses_helpers = true;
        if !self.properties.helpers_used.contains(&helper_id) {
            self.properties.helpers_used.push(helper_id);
        }
    }

    /// Record map usage
    pub fn record_map(&mut self, map_type: BpfMapType) {
        self.properties.uses_maps = true;
        if !self.properties.map_types_used.contains(&map_type) {
            self.properties.map_types_used.push(map_type);
        }
    }

    /// Check if the result has already been built
    pub fn is_built(&self) -> bool {
        self.outcome.is_some()
    }

    /// Get the cached outcome if available
    pub fn get_outcome(&self) -> Option<&VerificationOutcome> {
        self.outcome.as_ref()
    }

    /// Build success result
    pub fn success(mut self) -> VerificationOutcome {
        let outcome = VerificationOutcome::Success(SuccessInfo {
            stats: self.stats.clone(),
            warnings: self.warnings.clone(),
            properties: self.properties.clone(),
        });
        self.outcome = Some(outcome.clone());
        outcome
    }

    /// Build failure result
    pub fn failure(mut self, error: VerifierError, insn_idx: usize) -> VerificationOutcome {
        let mut info = FailureInfo::new(error, insn_idx);
        info.partial_stats = Some(self.stats.clone());

        // Add suggestions based on error type
        add_error_suggestions(&mut info);

        let outcome = VerificationOutcome::Failure(info);
        self.outcome = Some(outcome.clone());
        outcome
    }

    /// Build aborted result
    pub fn aborted(
        self,
        reason: AbortReason,
        progress: VerificationProgress,
    ) -> VerificationOutcome {
        VerificationOutcome::Aborted(AbortInfo {
            reason,
            progress,
            partial_stats: Some(self.stats),
        })
    }
}

impl Default for ResultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Add suggestions based on error type
pub fn add_error_suggestions(info: &mut FailureInfo) {
    match &info.error {
        VerifierError::UninitializedRegister(reg) => {
            info.suggestions
                .push(format!("Initialize register R{} before using it", reg));
            info.suggestions
                .push("Check if a previous branch might leave this register uninitialized".into());
        }
        VerifierError::InvalidMemoryAccess(msg) => {
            if msg.contains("stack") {
                info.suggestions
                    .push("Ensure stack offset is within bounds (-512 to 0)".into());
            }
            if msg.contains("packet") {
                info.suggestions
                    .push("Add a bounds check before accessing packet data".into());
                info.suggestions
                    .push("Pattern: if (data + offset > data_end) return XDP_DROP;".into());
            }
        }
        VerifierError::InvalidPointerArithmetic(_) => {
            info.suggestions
                .push("Only add/sub constants or bounded scalars to pointers".into());
            info.suggestions
                .push("Use AND with mask to bound variable offsets".into());
        }
        VerifierError::TypeMismatch { expected, .. } => {
            info.suggestions
                .push(format!("Ensure the value is of type {}", expected));
        }
        VerifierError::UnreleasedReference(_) => {
            info.suggestions
                .push("Call the appropriate release function (e.g., bpf_sk_release)".into());
            info.suggestions
                .push("Ensure all code paths release acquired references".into());
        }
        VerifierError::InvalidLock(_) => {
            info.suggestions
                .push("Ensure locks are released in reverse order of acquisition".into());
            info.suggestions
                .push("Check that all code paths properly release locks".into());
        }
        VerifierError::BackEdgeDetected => {
            info.suggestions
                .push("Use bpf_loop() helper for bounded iteration".into());
            info.suggestions.push("Unroll small loops manually".into());
        }
        VerifierError::TooComplex(_) => {
            info.suggestions
                .push("Simplify program logic or split into multiple programs".into());
            info.suggestions
                .push("Reduce branching and use tail calls for complex flows".into());
        }
        _ => {}
    }
}

/// Format a verification result for display
impl fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationOutcome::Success(info) => {
                writeln!(f, "Verification PASSED")?;
                writeln!(f)?;
                writeln!(f, "Statistics:")?;
                writeln!(
                    f,
                    "  Instructions processed: {}",
                    info.stats.insns_processed
                )?;
                writeln!(f, "  States explored: {}", info.stats.total_states)?;
                writeln!(f, "  States pruned: {}", info.stats.states_pruned)?;

                if !info.warnings.is_empty() {
                    writeln!(f)?;
                    writeln!(f, "Warnings ({}):", info.warnings.len())?;
                    for warning in &info.warnings {
                        if let Some(idx) = warning.insn_idx {
                            writeln!(
                                f,
                                "  [{}] insn {}: {}",
                                warning.code as u8, idx, warning.message
                            )?;
                        } else {
                            writeln!(f, "  [{}] {}", warning.code as u8, warning.message)?;
                        }
                    }
                }

                Ok(())
            }
            VerificationOutcome::Failure(info) => {
                writeln!(f, "Verification FAILED")?;
                writeln!(f)?;
                writeln!(f, "Error at instruction {}: {}", info.insn_idx, info.error)?;

                match &info.context {
                    ErrorContext::MemoryAccess {
                        access_type,
                        ptr_reg,
                        offset,
                        size,
                    } => {
                        writeln!(
                            f,
                            "Context: {:?} access via R{} at offset {} size {}",
                            access_type, ptr_reg, offset, size
                        )?;
                    }
                    ErrorContext::RegisterState { regno, expected } => {
                        writeln!(
                            f,
                            "Context: Register R{} expected to be {}",
                            regno, expected
                        )?;
                    }
                    ErrorContext::Call { call_type, func_id } => {
                        writeln!(f, "Context: {:?} call to function {}", call_type, func_id)?;
                    }
                    _ => {}
                }

                if !info.suggestions.is_empty() {
                    writeln!(f)?;
                    writeln!(f, "Suggestions:")?;
                    for (i, suggestion) in info.suggestions.iter().enumerate() {
                        writeln!(f, "  {}. {}", i + 1, suggestion)?;
                    }
                }

                if !info.related.is_empty() {
                    writeln!(f)?;
                    writeln!(f, "Related issues:")?;
                    for related in &info.related {
                        writeln!(f, "  - insn {}: {}", related.insn_idx, related.description)?;
                    }
                }

                Ok(())
            }
            VerificationOutcome::Aborted(info) => {
                writeln!(f, "Verification ABORTED")?;
                writeln!(f)?;

                match &info.reason {
                    AbortReason::ComplexityLimit { limit, reached } => {
                        writeln!(
                            f,
                            "Reason: Complexity limit exceeded ({} / {})",
                            reached, limit
                        )?;
                    }
                    AbortReason::StateLimit { limit, reached } => {
                        writeln!(f, "Reason: State limit exceeded ({} / {})", reached, limit)?;
                    }
                    AbortReason::Timeout {
                        limit_ms,
                        elapsed_ms,
                    } => {
                        writeln!(f, "Reason: Timeout ({}ms / {}ms)", elapsed_ms, limit_ms)?;
                    }
                    AbortReason::UserAbort => {
                        writeln!(f, "Reason: User requested abort")?;
                    }
                    AbortReason::InternalError(msg) => {
                        writeln!(f, "Reason: Internal error - {}", msg)?;
                    }
                }

                writeln!(f)?;
                writeln!(f, "Progress before abort:")?;
                writeln!(
                    f,
                    "  Instructions verified: {}",
                    info.progress.insns_verified
                )?;
                writeln!(
                    f,
                    "  Branches explored: {}",
                    info.progress.branches_explored
                )?;
                writeln!(f, "  Coverage: {:.1}%", info.progress.coverage_percent)?;

                Ok(())
            }
        }
    }
}
