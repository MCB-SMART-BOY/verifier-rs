// SPDX-License-Identifier: GPL-2.0

//! Platform-agnostic type definitions.
//!
//! These types are used across all platform implementations and provide
//! a common vocabulary for the verifier.

use crate::core::types::{BpfArgType, BpfRetType};

/// Result type for platform operations
pub type PlatformResult<T> = core::result::Result<T, PlatformError>;

/// Platform-level errors
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PlatformError {
    /// Helper function not found
    HelperNotFound(u32),
    /// Helper not allowed for program type
    HelperNotAllowed { helper_id: u32, prog_type: u32 },
    /// Program type not found
    ProgTypeNotFound(u32),
    /// Invalid return value for program type
    InvalidReturnValue { prog_type: u32, value: i64 },
    /// Kfunc not found
    KfuncNotFound(u32),
    /// Kfunc not allowed for program type
    KfuncNotAllowed { kfunc_id: u32, prog_type: u32 },
    /// Map type not found
    MapTypeNotFound(u32),
    /// Map operation not allowed
    MapOpNotAllowed { map_type: u32, op: &'static str },
    /// Context access denied
    ContextAccessDenied { prog_type: u32, offset: u32, size: u32 },
    /// Context field not found
    ContextFieldNotFound { prog_type: u32, offset: u32 },
    /// Invalid access mode (read vs write)
    InvalidAccessMode { expected: &'static str, actual: &'static str },
    /// Generic error with message
    Other(&'static str),
}

impl core::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HelperNotFound(id) => write!(f, "helper function {} not found", id),
            Self::HelperNotAllowed { helper_id, prog_type } => {
                write!(f, "helper {} not allowed for prog type {}", helper_id, prog_type)
            }
            Self::ProgTypeNotFound(pt) => write!(f, "program type {} not found", pt),
            Self::InvalidReturnValue { prog_type, value } => {
                write!(f, "invalid return value {} for prog type {}", value, prog_type)
            }
            Self::KfuncNotFound(id) => write!(f, "kfunc {} not found", id),
            Self::KfuncNotAllowed { kfunc_id, prog_type } => {
                write!(f, "kfunc {} not allowed for prog type {}", kfunc_id, prog_type)
            }
            Self::MapTypeNotFound(mt) => write!(f, "map type {} not found", mt),
            Self::MapOpNotAllowed { map_type, op } => {
                write!(f, "operation {} not allowed for map type {}", op, map_type)
            }
            Self::ContextAccessDenied { prog_type, offset, size } => {
                write!(f, "context access denied at offset {} size {} for prog type {}", 
                       offset, size, prog_type)
            }
            Self::ContextFieldNotFound { prog_type, offset } => {
                write!(f, "context field not found at offset {} for prog type {}", offset, prog_type)
            }
            Self::InvalidAccessMode { expected, actual } => {
                write!(f, "invalid access mode: expected {}, got {}", expected, actual)
            }
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Argument type descriptor for platform-agnostic representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgTypeDesc {
    /// The base argument type
    pub base: BpfArgType,
    /// Optional size constraint
    pub size: Option<u32>,
    /// Whether the argument is optional
    pub optional: bool,
}

impl ArgTypeDesc {
    /// Create a new argument type descriptor
    pub const fn new(base: BpfArgType) -> Self {
        Self {
            base,
            size: None,
            optional: false,
        }
    }

    /// Create with size constraint
    pub const fn with_size(base: BpfArgType, size: u32) -> Self {
        Self {
            base,
            size: Some(size),
            optional: false,
        }
    }

    /// Mark as optional
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

/// Return type descriptor for platform-agnostic representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetTypeDesc {
    /// The base return type
    pub base: BpfRetType,
    /// Whether the return can be null
    pub may_be_null: bool,
}

impl RetTypeDesc {
    /// Create a new return type descriptor
    pub const fn new(base: BpfRetType) -> Self {
        Self {
            base,
            may_be_null: false,
        }
    }

    /// Mark as may-be-null
    pub const fn nullable(mut self) -> Self {
        self.may_be_null = true;
        self
    }
}

/// Return value range for program types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetvalRange {
    /// Minimum allowed return value
    pub min: i64,
    /// Maximum allowed return value
    pub max: i64,
}

impl RetvalRange {
    /// Create a new return value range
    pub const fn new(min: i64, max: i64) -> Self {
        Self { min, max }
    }

    /// Check if a value is within range
    pub fn contains(&self, value: i64) -> bool {
        value >= self.min && value <= self.max
    }

    /// Single value range
    pub const fn single(value: i64) -> Self {
        Self { min: value, max: value }
    }

    /// Range for boolean return (0 or 1)
    pub const fn boolean() -> Self {
        Self { min: 0, max: 1 }
    }

    /// Range for any 32-bit value
    pub const fn any_i32() -> Self {
        Self { min: i32::MIN as i64, max: i32::MAX as i64 }
    }
}

impl Default for RetvalRange {
    fn default() -> Self {
        Self::new(0, 0)
    }
}
