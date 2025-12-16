// SPDX-License-Identifier: GPL-2.0

//! Error types for the BPF verifier

use crate::stdlib::String;
use core::fmt;

/// Result type alias for verifier operations
pub type Result<T> = core::result::Result<T, VerifierError>;

/// Errors that can occur during BPF program verification
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum VerifierError {
    EmptyProgram,
    ProgramTooLarge(usize),
    InvalidInsnIdx(usize),
    JumpOutOfRange(usize, usize),
    InvalidJumpTarget(usize),
    FallThroughExit,
    VerificationLimitExceeded(String),
    InvalidInstruction(usize),
    InvalidRegister(u8),
    UninitializedRegister(u8),
    InvalidMemoryAccess(String),
    StackOutOfBounds(i32),
    InvalidOffset(i64),
    UnreleasedReference(u32),
    InvalidPointerArithmetic(String),
    TooComplex(String),
    InvalidJumpDestination(i32),
    BackEdgeDetected,
    UnreachableInstruction(usize),
    InvalidHelperCall(String),
    TypeMismatch { expected: String, got: String },
    InvalidPointer(String),
    PermissionDenied(String),
    InvalidMapAccess(String),
    InvalidContextAccess(String),
    PointerLeak,
    DivisionByZero,
    InvalidDynptr(String),
    InvalidIterator(String),
    InvalidLock(String),
    InvalidIrq(String),
    ResourceLimitExceeded(String),
    ComplexityLimitExceeded(String),
    Internal(String),
    OutOfMemory,
    InvalidBtf(String),
    InvalidKfunc(String),
    InvalidProgramType(String),
    SpeculativeViolation,
    BoundsCheckFailed(String),
    TooManySubprogs,
    CallStackOverflow,
    StackOverflow(i32),
    InvalidSubprog(String),
    ExpectedPointer(u8),
    InvalidInsnSize(usize),
    InvalidAtomicOp(u32),
    InvalidState(String),
    InvalidFunctionCall(String),
    OutOfBounds { offset: i32, size: i32 },
    InfiniteLoop(usize),
    InvalidPointerComparison(String),
    InvalidReturnValue(String),
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierError::EmptyProgram => write!(f, "empty program"),
            VerifierError::ProgramTooLarge(n) => write!(f, "program too large: {} instructions", n),
            VerifierError::InvalidInsnIdx(i) => write!(f, "invalid instruction index {}", i),
            VerifierError::JumpOutOfRange(t, l) => {
                write!(f, "jump out of range: target {}, prog_len {}", t, l)
            }
            VerifierError::InvalidJumpTarget(t) => write!(f, "invalid jump target {}", t),
            VerifierError::FallThroughExit => write!(f, "fall through exit"),
            VerifierError::VerificationLimitExceeded(s) => {
                write!(f, "verification limit exceeded: {}", s)
            }
            VerifierError::InvalidInstruction(i) => write!(f, "invalid instruction at index {}", i),
            VerifierError::InvalidRegister(r) => write!(f, "invalid register {}", r),
            VerifierError::UninitializedRegister(r) => write!(f, "register {} not initialized", r),
            VerifierError::InvalidMemoryAccess(s) => write!(f, "invalid memory access: {}", s),
            VerifierError::StackOutOfBounds(o) => {
                write!(f, "out of bounds stack access at offset {}", o)
            }
            VerifierError::InvalidOffset(o) => write!(f, "invalid offset {}", o),
            VerifierError::UnreleasedReference(id) => {
                write!(f, "unreleased reference with id {}", id)
            }
            VerifierError::InvalidPointerArithmetic(s) => {
                write!(f, "invalid pointer arithmetic: {}", s)
            }
            VerifierError::TooComplex(s) => write!(f, "program too complex: {}", s),
            VerifierError::InvalidJumpDestination(d) => write!(f, "invalid jump destination {}", d),
            VerifierError::BackEdgeDetected => write!(f, "back-edge detected, loops not allowed"),
            VerifierError::UnreachableInstruction(i) => {
                write!(f, "unreachable instruction at index {}", i)
            }
            VerifierError::InvalidHelperCall(s) => write!(f, "invalid helper call: {}", s),
            VerifierError::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected {}, got {}", expected, got)
            }
            VerifierError::InvalidPointer(s) => write!(f, "invalid pointer: {}", s),
            VerifierError::PermissionDenied(s) => write!(f, "permission denied: {}", s),
            VerifierError::InvalidMapAccess(s) => write!(f, "invalid map access: {}", s),
            VerifierError::InvalidContextAccess(s) => write!(f, "invalid context access: {}", s),
            VerifierError::PointerLeak => write!(f, "pointer leak in unprivileged mode"),
            VerifierError::DivisionByZero => write!(f, "division by zero"),
            VerifierError::InvalidDynptr(s) => write!(f, "invalid dynptr operation: {}", s),
            VerifierError::InvalidIterator(s) => write!(f, "invalid iterator operation: {}", s),
            VerifierError::InvalidLock(s) => write!(f, "invalid lock operation: {}", s),
            VerifierError::InvalidIrq(s) => write!(f, "invalid IRQ operation: {}", s),
            VerifierError::ResourceLimitExceeded(s) => write!(f, "resource limit exceeded: {}", s),
            VerifierError::ComplexityLimitExceeded(s) => {
                write!(f, "complexity limit exceeded: {}", s)
            }
            VerifierError::Internal(s) => write!(f, "internal error: {}", s),
            VerifierError::OutOfMemory => write!(f, "out of memory"),
            VerifierError::InvalidBtf(s) => write!(f, "invalid BTF: {}", s),
            VerifierError::InvalidKfunc(s) => write!(f, "invalid kfunc: {}", s),
            VerifierError::InvalidProgramType(s) => write!(f, "invalid program type: {}", s),
            VerifierError::SpeculativeViolation => write!(f, "speculative execution violation"),
            VerifierError::BoundsCheckFailed(s) => write!(f, "bounds check failed: {}", s),
            VerifierError::TooManySubprogs => write!(f, "too many subprograms"),
            VerifierError::CallStackOverflow => write!(f, "call stack overflow"),
            VerifierError::StackOverflow(n) => write!(f, "stack overflow: {} bytes", n),
            VerifierError::InvalidSubprog(s) => write!(f, "invalid subprogram: {}", s),
            VerifierError::ExpectedPointer(r) => write!(f, "expected pointer in register {}", r),
            VerifierError::InvalidInsnSize(i) => write!(f, "invalid instruction size at {}", i),
            VerifierError::InvalidAtomicOp(op) => write!(f, "invalid atomic operation {:#x}", op),
            VerifierError::InvalidState(s) => write!(f, "invalid state: {}", s),
            VerifierError::InvalidFunctionCall(s) => write!(f, "invalid function call: {}", s),
            VerifierError::OutOfBounds { offset, size } => write!(
                f,
                "out of bounds access at offset {} with size {}",
                offset, size
            ),
            VerifierError::InfiniteLoop(i) => {
                write!(f, "infinite loop detected at instruction {}", i)
            }
            VerifierError::InvalidPointerComparison(s) => {
                write!(f, "invalid pointer comparison: {}", s)
            }
            VerifierError::InvalidReturnValue(s) => write!(f, "invalid return value: {}", s),
        }
    }
}

impl VerifierError {
    /// Check if this error is recoverable with speculation barrier
    pub fn is_recoverable_with_nospec(&self) -> bool {
        matches!(
            self,
            VerifierError::PermissionDenied(_)
                | VerifierError::InvalidMemoryAccess(_)
                | VerifierError::TypeMismatch { .. }
        )
    }

    /// Convert to kernel errno value
    ///
    /// These correspond to Linux kernel error codes:
    /// - EINVAL (22): Invalid argument
    /// - ENOMEM (12): Out of memory  
    /// - EACCES (13): Permission denied
    /// - E2BIG (7): Argument list too long (used for complexity limits)
    /// - EPERM (1): Operation not permitted
    pub fn to_kernel_errno(&self) -> i32 {
        match self {
            // Memory errors
            VerifierError::OutOfMemory => -12, // ENOMEM

            // Permission/access errors
            VerifierError::PermissionDenied(_) => -1, // EPERM
            VerifierError::PointerLeak => -1,         // EPERM
            VerifierError::InvalidMemoryAccess(_) => -13, // EACCES
            VerifierError::InvalidMapAccess(_) => -13, // EACCES
            VerifierError::InvalidContextAccess(_) => -13, // EACCES

            // Complexity/size limits
            VerifierError::ProgramTooLarge(_) => -7, // E2BIG
            VerifierError::TooComplex(_) => -7,      // E2BIG
            VerifierError::VerificationLimitExceeded(_) => -7, // E2BIG
            VerifierError::ResourceLimitExceeded(_) => -7, // E2BIG
            VerifierError::ComplexityLimitExceeded(_) => -7, // E2BIG
            VerifierError::TooManySubprogs => -7,    // E2BIG
            VerifierError::CallStackOverflow => -7,  // E2BIG
            VerifierError::StackOverflow(_) => -7,   // E2BIG

            // All other errors are EINVAL
            _ => -22, // EINVAL
        }
    }
}
