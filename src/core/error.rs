//! Error types for the BPF verifier

use crate::stdlib::String;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use thiserror::Error;

/// Result type alias for verifier operations
pub type Result<T> = core::result::Result<T, VerifierError>;

/// Errors that can occur during BPF program verification
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum VerifierError {
    #[cfg_attr(feature = "std", error("empty program"))]
    EmptyProgram,

    #[cfg_attr(feature = "std", error("program too large: {0} instructions"))]
    ProgramTooLarge(usize),

    #[cfg_attr(feature = "std", error("invalid instruction index {0}"))]
    InvalidInsnIdx(usize),

    #[cfg_attr(feature = "std", error("jump out of range: target {0}, prog_len {1}"))]
    JumpOutOfRange(usize, usize),

    #[cfg_attr(feature = "std", error("invalid jump target {0}"))]
    InvalidJumpTarget(usize),

    #[cfg_attr(feature = "std", error("fall through exit"))]
    FallThroughExit,

    #[cfg_attr(feature = "std", error("verification limit exceeded: {0}"))]
    VerificationLimitExceeded(String),

    #[cfg_attr(feature = "std", error("invalid instruction at index {0}"))]
    InvalidInstruction(usize),

    #[cfg_attr(feature = "std", error("invalid register {0}"))]
    InvalidRegister(u8),

    #[cfg_attr(feature = "std", error("register {0} not initialized"))]
    UninitializedRegister(u8),

    #[cfg_attr(feature = "std", error("invalid memory access: {0}"))]
    InvalidMemoryAccess(String),

    #[cfg_attr(feature = "std", error("out of bounds stack access at offset {0}"))]
    StackOutOfBounds(i32),

    #[cfg_attr(feature = "std", error("invalid offset {0}"))]
    InvalidOffset(i64),

    #[cfg_attr(feature = "std", error("unreleased reference with id {0}"))]
    UnreleasedReference(u32),

    #[cfg_attr(feature = "std", error("invalid pointer arithmetic: {0}"))]
    InvalidPointerArithmetic(String),

    #[cfg_attr(feature = "std", error("program too complex: {0}"))]
    TooComplex(String),

    #[cfg_attr(feature = "std", error("invalid jump destination {0}"))]
    InvalidJumpDestination(i32),

    #[cfg_attr(feature = "std", error("back-edge detected, loops not allowed"))]
    BackEdgeDetected,

    #[cfg_attr(feature = "std", error("unreachable instruction at index {0}"))]
    UnreachableInstruction(usize),

    #[cfg_attr(feature = "std", error("invalid helper call: {0}"))]
    InvalidHelperCall(String),

    #[cfg_attr(feature = "std", error("type mismatch: expected {expected}, got {got}"))]
    TypeMismatch { expected: String, got: String },

    #[cfg_attr(feature = "std", error("invalid pointer: {0}"))]
    InvalidPointer(String),

    #[cfg_attr(feature = "std", error("permission denied: {0}"))]
    PermissionDenied(String),

    #[cfg_attr(feature = "std", error("invalid map access: {0}"))]
    InvalidMapAccess(String),

    #[cfg_attr(feature = "std", error("invalid context access: {0}"))]
    InvalidContextAccess(String),

    #[cfg_attr(feature = "std", error("pointer leak in unprivileged mode"))]
    PointerLeak,

    #[cfg_attr(feature = "std", error("division by zero"))]
    DivisionByZero,

    #[cfg_attr(feature = "std", error("invalid dynptr operation: {0}"))]
    InvalidDynptr(String),

    #[cfg_attr(feature = "std", error("invalid iterator operation: {0}"))]
    InvalidIterator(String),

    #[cfg_attr(feature = "std", error("invalid lock operation: {0}"))]
    InvalidLock(String),

    #[cfg_attr(feature = "std", error("invalid IRQ operation: {0}"))]
    InvalidIrq(String),

    #[cfg_attr(feature = "std", error("resource limit exceeded: {0}"))]
    ResourceLimitExceeded(String),

    #[cfg_attr(feature = "std", error("complexity limit exceeded: {0}"))]
    ComplexityLimitExceeded(String),

    #[cfg_attr(feature = "std", error("internal error: {0}"))]
    Internal(String),

    #[cfg_attr(feature = "std", error("out of memory"))]
    OutOfMemory,

    #[cfg_attr(feature = "std", error("invalid BTF: {0}"))]
    InvalidBtf(String),

    #[cfg_attr(feature = "std", error("invalid kfunc: {0}"))]
    InvalidKfunc(String),

    #[cfg_attr(feature = "std", error("invalid program type: {0}"))]
    InvalidProgramType(String),

    #[cfg_attr(feature = "std", error("speculative execution violation"))]
    SpeculativeViolation,

    #[cfg_attr(feature = "std", error("bounds check failed: {0}"))]
    BoundsCheckFailed(String),

    #[cfg_attr(feature = "std", error("too many subprograms"))]
    TooManySubprogs,

    #[cfg_attr(feature = "std", error("call stack overflow"))]
    CallStackOverflow,

    #[cfg_attr(feature = "std", error("stack overflow: {0} bytes"))]
    StackOverflow(i32),

    #[cfg_attr(feature = "std", error("invalid subprogram: {0}"))]
    InvalidSubprog(String),

    #[cfg_attr(feature = "std", error("expected pointer in register {0}"))]
    ExpectedPointer(u8),

    #[cfg_attr(feature = "std", error("invalid instruction size at {0}"))]
    InvalidInsnSize(usize),

    #[cfg_attr(feature = "std", error("invalid atomic operation {0:#x}"))]
    InvalidAtomicOp(u32),

    #[cfg_attr(feature = "std", error("invalid state: {0}"))]
    InvalidState(String),

    #[cfg_attr(feature = "std", error("invalid function call: {0}"))]
    InvalidFunctionCall(String),

    #[cfg_attr(feature = "std", error("out of bounds access at offset {offset} with size {size}"))]
    OutOfBounds { offset: i32, size: i32 },

    #[cfg_attr(feature = "std", error("infinite loop detected at instruction {0}"))]
    InfiniteLoop(usize),

    #[cfg_attr(feature = "std", error("invalid pointer comparison: {0}"))]
    InvalidPointerComparison(String),

    #[cfg_attr(feature = "std", error("invalid return value: {0}"))]
    InvalidReturnValue(String),
}

// Manual Display implementation for no_std
#[cfg(not(feature = "std"))]
impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierError::EmptyProgram => write!(f, "empty program"),
            VerifierError::ProgramTooLarge(n) => write!(f, "program too large: {} instructions", n),
            VerifierError::InvalidInsnIdx(i) => write!(f, "invalid instruction index {}", i),
            VerifierError::JumpOutOfRange(t, l) => write!(f, "jump out of range: target {}, prog_len {}", t, l),
            VerifierError::InvalidJumpTarget(t) => write!(f, "invalid jump target {}", t),
            VerifierError::FallThroughExit => write!(f, "fall through exit"),
            VerifierError::VerificationLimitExceeded(s) => write!(f, "verification limit exceeded: {}", s),
            VerifierError::InvalidInstruction(i) => write!(f, "invalid instruction at index {}", i),
            VerifierError::InvalidRegister(r) => write!(f, "invalid register {}", r),
            VerifierError::UninitializedRegister(r) => write!(f, "register {} not initialized", r),
            VerifierError::InvalidMemoryAccess(s) => write!(f, "invalid memory access: {}", s),
            VerifierError::StackOutOfBounds(o) => write!(f, "out of bounds stack access at offset {}", o),
            VerifierError::InvalidOffset(o) => write!(f, "invalid offset {}", o),
            VerifierError::UnreleasedReference(id) => write!(f, "unreleased reference with id {}", id),
            VerifierError::InvalidPointerArithmetic(s) => write!(f, "invalid pointer arithmetic: {}", s),
            VerifierError::TooComplex(s) => write!(f, "program too complex: {}", s),
            VerifierError::InvalidJumpDestination(d) => write!(f, "invalid jump destination {}", d),
            VerifierError::BackEdgeDetected => write!(f, "back-edge detected, loops not allowed"),
            VerifierError::UnreachableInstruction(i) => write!(f, "unreachable instruction at index {}", i),
            VerifierError::InvalidHelperCall(s) => write!(f, "invalid helper call: {}", s),
            VerifierError::TypeMismatch { expected, got } => write!(f, "type mismatch: expected {}, got {}", expected, got),
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
            VerifierError::ComplexityLimitExceeded(s) => write!(f, "complexity limit exceeded: {}", s),
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
            VerifierError::OutOfBounds { offset, size } => write!(f, "out of bounds access at offset {} with size {}", offset, size),
            VerifierError::InfiniteLoop(i) => write!(f, "infinite loop detected at instruction {}", i),
            VerifierError::InvalidPointerComparison(s) => write!(f, "invalid pointer comparison: {}", s),
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

    /// Convert to kernel errno value (for kernel module use)
    /// 
    /// These correspond to Linux kernel error codes:
    /// - EINVAL (22): Invalid argument
    /// - ENOMEM (12): Out of memory  
    /// - EACCES (13): Permission denied
    /// - E2BIG (7): Argument list too long (used for complexity limits)
    /// - EPERM (1): Operation not permitted
    #[cfg(feature = "kernel")]
    pub fn to_kernel_errno(&self) -> i32 {
        match self {
            // Memory errors
            VerifierError::OutOfMemory => -12, // ENOMEM

            // Permission/access errors
            VerifierError::PermissionDenied(_) => -1,  // EPERM
            VerifierError::PointerLeak => -1,          // EPERM
            VerifierError::InvalidMemoryAccess(_) => -13, // EACCES
            VerifierError::InvalidMapAccess(_) => -13,    // EACCES
            VerifierError::InvalidContextAccess(_) => -13, // EACCES

            // Complexity/size limits
            VerifierError::ProgramTooLarge(_) => -7,           // E2BIG
            VerifierError::TooComplex(_) => -7,                // E2BIG
            VerifierError::VerificationLimitExceeded(_) => -7, // E2BIG
            VerifierError::ResourceLimitExceeded(_) => -7,     // E2BIG
            VerifierError::ComplexityLimitExceeded(_) => -7,   // E2BIG
            VerifierError::TooManySubprogs => -7,              // E2BIG
            VerifierError::CallStackOverflow => -7,            // E2BIG
            VerifierError::StackOverflow(_) => -7,             // E2BIG

            // All other errors are EINVAL
            _ => -22, // EINVAL
        }
    }

    /// Create from kernel errno (for kernel module use)
    #[cfg(feature = "kernel")]
    pub fn from_kernel_errno(errno: i32) -> Self {
        match errno {
            -12 => VerifierError::OutOfMemory,
            -1 => VerifierError::PermissionDenied(String::from("operation not permitted")),
            -13 => VerifierError::InvalidMemoryAccess(String::from("access denied")),
            -7 => VerifierError::TooComplex(String::from("program too complex")),
            _ => VerifierError::Internal(String::from("unknown error")),
        }
    }
}
