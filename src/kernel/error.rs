// SPDX-License-Identifier: GPL-2.0

//! Kernel error types for the BPF verifier.
//!
//! This module provides error handling that integrates with the kernel's
//! error reporting mechanisms. Errors are represented as negative errno
//! values, matching the kernel's convention.
//!
//! # Kernel Integration
//!
//! When building as part of the kernel, this module uses `kernel::error::Error`.
//! For standalone testing, it provides a compatible implementation.

use crate::stdlib::String;
use core::fmt;

// ============================================================================
// Errno values from include/uapi/asm-generic/errno-base.h
// ============================================================================

/// Operation not permitted
pub const EPERM: i32 = 1;
/// No such file or directory
pub const ENOENT: i32 = 2;
/// No such process
pub const ESRCH: i32 = 3;
/// Interrupted system call
pub const EINTR: i32 = 4;
/// I/O error
pub const EIO: i32 = 5;
/// No such device or address
pub const ENXIO: i32 = 6;
/// Argument list too long
pub const E2BIG: i32 = 7;
/// Exec format error
pub const ENOEXEC: i32 = 8;
/// Bad file number
pub const EBADF: i32 = 9;
/// No child processes
pub const ECHILD: i32 = 10;
/// Try again
pub const EAGAIN: i32 = 11;
/// Out of memory
pub const ENOMEM: i32 = 12;
/// Permission denied
pub const EACCES: i32 = 13;
/// Bad address
pub const EFAULT: i32 = 14;
/// Block device required
pub const ENOTBLK: i32 = 15;
/// Device or resource busy
pub const EBUSY: i32 = 16;
/// File exists
pub const EEXIST: i32 = 17;
/// Cross-device link
pub const EXDEV: i32 = 18;
/// No such device
pub const ENODEV: i32 = 19;
/// Not a directory
pub const ENOTDIR: i32 = 20;
/// Is a directory
pub const EISDIR: i32 = 21;
/// Invalid argument
pub const EINVAL: i32 = 22;
/// File table overflow
pub const ENFILE: i32 = 23;
/// Too many open files
pub const EMFILE: i32 = 24;
/// Not a typewriter
pub const ENOTTY: i32 = 25;
/// Text file busy
pub const ETXTBSY: i32 = 26;
/// File too large
pub const EFBIG: i32 = 27;
/// No space left on device
pub const ENOSPC: i32 = 28;
/// Illegal seek
pub const ESPIPE: i32 = 29;
/// Read-only file system
pub const EROFS: i32 = 30;
/// Too many links
pub const EMLINK: i32 = 31;
/// Broken pipe
pub const EPIPE: i32 = 32;
/// Math argument out of domain of func
pub const EDOM: i32 = 33;
/// Math result not representable
pub const ERANGE: i32 = 34;

// Extended errno values
/// Resource deadlock would occur
pub const EDEADLK: i32 = 35;
/// File name too long
pub const ENAMETOOLONG: i32 = 36;
/// No record locks available
pub const ENOLCK: i32 = 37;
/// Invalid system call number
pub const ENOSYS: i32 = 38;
/// Directory not empty
pub const ENOTEMPTY: i32 = 39;
/// Too many symbolic links encountered
pub const ELOOP: i32 = 40;
/// No message of desired type
pub const ENOMSG: i32 = 42;

// ============================================================================
// Kernel Error Type
// ============================================================================

/// Kernel-compatible error type.
///
/// This represents an error as a negative errno value, matching the
/// kernel's convention. When integrated with the kernel crate, this
/// should be replaced with `kernel::error::Error`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KernelError(i32);

impl KernelError {
    /// Create a new error from an errno value.
    ///
    /// The value should be positive; it will be stored as negative internally.
    #[inline]
    pub const fn new(errno: i32) -> Self {
        debug_assert!(errno > 0 && errno < 4096);
        Self(-errno)
    }

    /// Create from a raw negative errno value.
    #[inline]
    pub const fn from_raw(raw: i32) -> Self {
        debug_assert!(raw < 0 && raw > -4096);
        Self(raw)
    }

    /// Get the raw errno value (negative).
    #[inline]
    pub const fn raw(&self) -> i32 {
        self.0
    }

    /// Get the errno value (positive).
    #[inline]
    pub const fn errno(&self) -> i32 {
        -self.0
    }

    // Common error constructors

    /// Invalid argument (EINVAL)
    pub const EINVAL: Self = Self::new(EINVAL);
    /// Out of memory (ENOMEM)
    pub const ENOMEM: Self = Self::new(ENOMEM);
    /// Permission denied (EACCES)
    pub const EACCES: Self = Self::new(EACCES);
    /// Bad address (EFAULT)
    pub const EFAULT: Self = Self::new(EFAULT);
    /// Operation not permitted (EPERM)
    pub const EPERM: Self = Self::new(EPERM);
    /// Argument list too long (E2BIG) - used for complexity limit
    pub const E2BIG: Self = Self::new(E2BIG);
    /// No such device (ENODEV)
    pub const ENODEV: Self = Self::new(ENODEV);
    /// Not supported (ENOTSUPP is 524 in kernel, but we use ENOSYS here)
    pub const ENOSYS: Self = Self::new(ENOSYS);
}

impl fmt::Debug for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KernelError({})", self.errno())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.errno() {
            EPERM => "EPERM",
            ENOENT => "ENOENT",
            EIO => "EIO",
            E2BIG => "E2BIG",
            ENOMEM => "ENOMEM",
            EACCES => "EACCES",
            EFAULT => "EFAULT",
            EBUSY => "EBUSY",
            EINVAL => "EINVAL",
            ENOSYS => "ENOSYS",
            _ => "UNKNOWN",
        };
        write!(f, "{} ({})", name, self.errno())
    }
}

// ============================================================================
// Conversion from VerifierError to KernelError
// ============================================================================

use crate::core::error::VerifierError;

impl From<VerifierError> for KernelError {
    fn from(err: VerifierError) -> Self {
        match err {
            // Invalid program structure
            VerifierError::EmptyProgram => KernelError::EINVAL,
            VerifierError::ProgramTooLarge(_) => KernelError::E2BIG,
            VerifierError::InvalidInsnIdx(_) => KernelError::EINVAL,
            VerifierError::JumpOutOfRange(_, _) => KernelError::EINVAL,
            VerifierError::InvalidJumpTarget(_) => KernelError::EINVAL,
            VerifierError::InvalidJumpDestination(_) => KernelError::EINVAL,
            VerifierError::FallThroughExit => KernelError::EINVAL,
            VerifierError::InvalidInstruction(_) => KernelError::EINVAL,
            VerifierError::BackEdgeDetected => KernelError::EINVAL,
            VerifierError::UnreachableInstruction(_) => KernelError::EINVAL,

            // Memory errors
            VerifierError::InvalidMemoryAccess(_) => KernelError::EACCES,
            VerifierError::StackOutOfBounds(_) => KernelError::EACCES,
            VerifierError::InvalidOffset(_) => KernelError::EACCES,

            // Register errors
            VerifierError::InvalidRegister(_) => KernelError::EINVAL,
            VerifierError::UninitializedRegister(_) => KernelError::EINVAL,
            VerifierError::TypeMismatch { .. } => KernelError::EINVAL,
            VerifierError::InvalidPointer(_) => KernelError::EINVAL,
            VerifierError::InvalidPointerArithmetic(_) => KernelError::EINVAL,
            VerifierError::BoundsCheckFailed(_) => KernelError::EACCES,

            // Resource errors
            VerifierError::UnreleasedReference(_) => KernelError::EINVAL,
            VerifierError::InvalidLock(_) => KernelError::EINVAL,
            VerifierError::InvalidIrq(_) => KernelError::EINVAL,
            VerifierError::PointerLeak => KernelError::EACCES,

            // Complexity errors
            VerifierError::VerificationLimitExceeded(_) => KernelError::E2BIG,
            VerifierError::TooComplex(_) => KernelError::E2BIG,
            VerifierError::ComplexityLimitExceeded(_) => KernelError::E2BIG,
            VerifierError::ResourceLimitExceeded(_) => KernelError::E2BIG,

            // Division errors
            VerifierError::DivisionByZero => KernelError::EINVAL,

            // Helper/kfunc errors
            VerifierError::InvalidHelperCall(_) => KernelError::EINVAL,
            VerifierError::InvalidKfunc(_) => KernelError::EINVAL,

            // BTF errors
            VerifierError::InvalidBtf(_) => KernelError::EINVAL,

            // Map/context errors
            VerifierError::InvalidMapAccess(_) => KernelError::EACCES,
            VerifierError::InvalidContextAccess(_) => KernelError::EACCES,
            VerifierError::PermissionDenied(_) => KernelError::EACCES,

            // Dynptr/iterator errors
            VerifierError::InvalidDynptr(_) => KernelError::EINVAL,
            VerifierError::InvalidIterator(_) => KernelError::EINVAL,

            // Program type errors
            VerifierError::InvalidProgramType(_) => KernelError::EINVAL,
            VerifierError::SpeculativeViolation => KernelError::EACCES,

            // Internal/allocation errors
            VerifierError::Internal(_) => KernelError::EFAULT,
            VerifierError::OutOfMemory => KernelError::ENOMEM,

            // Subprog/call errors
            VerifierError::TooManySubprogs => KernelError::E2BIG,
            VerifierError::CallStackOverflow => KernelError::E2BIG,
            VerifierError::StackOverflow(_) => KernelError::E2BIG,
            VerifierError::InvalidSubprog(_) => KernelError::EINVAL,
            VerifierError::InvalidFunctionCall(_) => KernelError::EINVAL,

            // Type/value errors
            VerifierError::ExpectedPointer(_) => KernelError::EINVAL,
            VerifierError::InvalidInsnSize(_) => KernelError::EINVAL,
            VerifierError::InvalidAtomicOp(_) => KernelError::EINVAL,
            VerifierError::InvalidState(_) => KernelError::EINVAL,
            VerifierError::OutOfBounds { .. } => KernelError::EACCES,
            VerifierError::InfiniteLoop(_) => KernelError::EINVAL,
            VerifierError::InvalidPointerComparison(_) => KernelError::EINVAL,
            VerifierError::InvalidReturnValue(_) => KernelError::EINVAL,
            VerifierError::AttachFailed(_) => KernelError::EINVAL,
        }
    }
}

// ============================================================================
// Result type
// ============================================================================

/// Kernel-compatible result type.
pub type KernelResult<T> = core::result::Result<T, KernelError>;

/// Extension trait for converting verifier results to kernel results.
pub trait IntoKernelResult<T> {
    /// Convert to a kernel result.
    fn into_kernel_result(self) -> KernelResult<T>;
}

impl<T> IntoKernelResult<T> for crate::core::error::Result<T> {
    fn into_kernel_result(self) -> KernelResult<T> {
        self.map_err(KernelError::from)
    }
}

// ============================================================================
// Verifier-specific error codes
// ============================================================================

/// BPF verifier rejection reasons.
///
/// These provide more specific error information that can be logged
/// for debugging purposes.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum VerifierRejectReason {
    /// Invalid instruction at given index
    InvalidInsn { idx: usize, reason: String },
    /// Register type mismatch
    TypeMismatch {
        reg: u8,
        expected: &'static str,
        got: &'static str,
    },
    /// Memory access out of bounds
    OutOfBounds { access_type: &'static str, off: i64 },
    /// Uninitialized register usage
    UninitializedReg { reg: u8 },
    /// Resource leak at exit
    ResourceLeak { ref_count: u32 },
    /// Complexity limit exceeded
    TooComplex { insns: u64, limit: u64 },
    /// Unreachable instruction
    UnreachableInsn { idx: usize },
    /// Invalid helper call
    InvalidHelper { func_id: i32 },
    /// Stack overflow
    StackOverflow { depth: u32 },
}

impl VerifierRejectReason {
    /// Get the errno for this rejection reason.
    pub fn to_errno(&self) -> i32 {
        match self {
            VerifierRejectReason::TooComplex { .. } => E2BIG,
            VerifierRejectReason::OutOfBounds { .. } => EACCES,
            _ => EINVAL,
        }
    }
}
