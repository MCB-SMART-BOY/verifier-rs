// SPDX-License-Identifier: GPL-2.0

//! Error types for the BPF verifier

use crate::stdlib::String;
use core::fmt;

/// Result type alias for verifier operations
pub type Result<T> = core::result::Result<T, VerifierError>;

/// Errors that can occur during BPF program verification
#[derive(Debug, Clone)]
pub enum VerifierError {
    /// Program contains no instructions
    EmptyProgram,
    /// Program exceeds maximum instruction count
    ProgramTooLarge(usize),
    /// Instruction index out of bounds
    InvalidInsnIdx(usize),
    /// Jump target outside program bounds (target, prog_len)
    JumpOutOfRange(usize, usize),
    /// Jump lands on invalid instruction boundary
    InvalidJumpTarget(usize),
    /// Execution falls through exit instruction
    FallThroughExit,
    /// Verification complexity limit exceeded
    VerificationLimitExceeded(String),
    /// Invalid or malformed instruction
    InvalidInstruction(usize),
    /// Register number out of range
    InvalidRegister(u8),
    /// Register used before initialization
    UninitializedRegister(u8),
    /// Invalid memory access (stack, map, context, etc.)
    InvalidMemoryAccess(String),
    /// Stack access out of bounds
    StackOutOfBounds(i32),
    /// Pointer offset exceeds valid range
    InvalidOffset(i64),
    /// Resource reference not released before exit
    UnreleasedReference(u32),
    /// Invalid pointer arithmetic operation
    InvalidPointerArithmetic(String),
    /// Program logic too complex to verify
    TooComplex(String),
    /// Jump destination is invalid
    InvalidJumpDestination(i32),
    /// Unbounded loop detected (back edge)
    BackEdgeDetected,
    /// Dead code detected
    UnreachableInstruction(usize),
    /// Invalid helper function call
    InvalidHelperCall(String),
    /// Type mismatch in operation
    TypeMismatch {
        /// Expected type
        expected: String,
        /// Actual type found
        got: String,
    },
    /// Invalid pointer type or state
    InvalidPointer(String),
    /// Operation not permitted for this program type
    PermissionDenied(String),
    /// Invalid map access
    InvalidMapAccess(String),
    /// Invalid context access
    InvalidContextAccess(String),
    /// Pointer value may be leaked to user space
    PointerLeak,
    /// Division or modulo by zero
    DivisionByZero,
    /// Invalid dynptr operation
    InvalidDynptr(String),
    /// Invalid iterator state or operation
    InvalidIterator(String),
    /// Invalid lock state
    InvalidLock(String),
    /// Invalid IRQ state
    InvalidIrq(String),
    /// Resource limit exceeded
    ResourceLimitExceeded(String),
    /// Complexity limit exceeded
    ComplexityLimitExceeded(String),
    /// Internal verifier error
    Internal(String),
    /// Memory allocation failed
    OutOfMemory,
    /// Invalid BTF data
    InvalidBtf(String),
    /// Invalid kfunc call
    InvalidKfunc(String),
    /// Operation not allowed for program type
    InvalidProgramType(String),
    /// Speculative execution safety violation
    SpeculativeViolation,
    /// Bounds check failed
    BoundsCheckFailed(String),
    /// Too many subprograms
    TooManySubprogs,
    /// Function call stack too deep
    CallStackOverflow,
    /// Stack usage exceeds limit
    StackOverflow(i32),
    /// Invalid subprogram
    InvalidSubprog(String),
    /// Expected pointer type in register
    ExpectedPointer(u8),
    /// Invalid instruction encoding size
    InvalidInsnSize(usize),
    /// Invalid atomic operation
    InvalidAtomicOp(u32),
    /// Invalid verifier state
    InvalidState(String),
    /// Invalid function call
    InvalidFunctionCall(String),
    /// Memory access out of bounds
    OutOfBounds {
        /// Access offset
        offset: i32,
        /// Access size
        size: i32,
    },
    /// Infinite loop detected at instruction
    InfiniteLoop(usize),
    /// Invalid pointer comparison
    InvalidPointerComparison(String),
    /// Invalid return value
    InvalidReturnValue(String),
    /// Program attach failed
    AttachFailed(String),
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
            VerifierError::AttachFailed(s) => write!(f, "attach failed: {}", s),
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
