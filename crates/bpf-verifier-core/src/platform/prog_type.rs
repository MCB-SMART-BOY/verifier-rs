// SPDX-License-Identifier: GPL-2.0

//! Program type provider trait and types.
//!
//! This module defines the platform-agnostic interface for BPF program types.
//! Each platform implements [`ProgTypeProvider`] to define its supported
//! program types and their capabilities.

use super::types::{PlatformError, PlatformResult, RetvalRange};

/// Capabilities and restrictions for a program type.
///
/// These flags indicate what features and operations are available
/// to programs of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProgCapabilities {
    /// Program can access packet data directly (data/data_end pointers)
    pub direct_packet_access: bool,
    /// Program can perform tail calls to other programs
    pub tail_call: bool,
    /// Program can use bpf_spin_lock
    pub spinlock: bool,
    /// Program runs in a sleepable context
    pub sleepable: bool,
    /// Program can access kernel memory directly
    pub kernel_mem_access: bool,
    /// Program can use timers
    pub timer: bool,
    /// Program can use RCU protected pointers
    pub rcu: bool,
    /// Program can use arena memory
    pub arena: bool,
    /// Program can throw exceptions
    pub exceptions: bool,
    /// Program supports private stack
    pub private_stack: bool,
}

impl ProgCapabilities {
    /// Create with no capabilities
    pub const fn none() -> Self {
        Self {
            direct_packet_access: false,
            tail_call: false,
            spinlock: false,
            sleepable: false,
            kernel_mem_access: false,
            timer: false,
            rcu: false,
            arena: false,
            exceptions: false,
            private_stack: false,
        }
    }

    /// Create with common networking capabilities
    pub const fn networking() -> Self {
        Self {
            direct_packet_access: true,
            tail_call: true,
            spinlock: true,
            ..Self::none()
        }
    }

    /// Create with tracing capabilities
    pub const fn tracing() -> Self {
        Self {
            kernel_mem_access: true,
            sleepable: false,
            ..Self::none()
        }
    }

    /// Builder: enable direct packet access
    pub const fn with_pkt_access(mut self) -> Self {
        self.direct_packet_access = true;
        self
    }

    /// Builder: enable tail calls
    pub const fn with_tail_call(mut self) -> Self {
        self.tail_call = true;
        self
    }

    /// Builder: enable spinlock
    pub const fn with_spinlock(mut self) -> Self {
        self.spinlock = true;
        self
    }

    /// Builder: enable sleepable context
    pub const fn with_sleepable(mut self) -> Self {
        self.sleepable = true;
        self
    }

    /// Builder: enable kernel memory access
    pub const fn with_kernel_mem(mut self) -> Self {
        self.kernel_mem_access = true;
        self
    }
}

/// Information about a BPF program type.
///
/// This structure contains all metadata needed to verify programs
/// of a specific type, including context size, allowed return values,
/// and capabilities.
#[derive(Debug, Clone)]
pub struct ProgTypeInfo {
    /// Numeric program type ID
    pub prog_type: u32,
    /// Human-readable name (e.g., "XDP", "SOCKET_FILTER")
    pub name: &'static str,
    /// Size of the context structure in bytes
    pub ctx_size: u32,
    /// Valid return value range
    pub ret_range: RetvalRange,
    /// Program capabilities
    pub capabilities: ProgCapabilities,
    /// Maximum allowed instructions
    pub max_insns: u32,
    /// Description of the program type
    pub description: &'static str,
    /// List of helper function IDs allowed for this program type
    /// (empty means use default/all allowed)
    pub allowed_helpers: &'static [u32],
}

impl ProgTypeInfo {
    /// Create a new program type info.
    pub const fn new(
        prog_type: u32,
        name: &'static str,
        ctx_size: u32,
        ret_range: RetvalRange,
    ) -> Self {
        Self {
            prog_type,
            name,
            ctx_size,
            ret_range,
            capabilities: ProgCapabilities::none(),
            max_insns: 1_000_000,
            description: "",
            allowed_helpers: &[],
        }
    }

    /// Builder: set capabilities
    pub const fn with_capabilities(mut self, caps: ProgCapabilities) -> Self {
        self.capabilities = caps;
        self
    }

    /// Builder: set max instructions
    pub const fn with_max_insns(mut self, max: u32) -> Self {
        self.max_insns = max;
        self
    }

    /// Builder: set description
    pub const fn with_description(mut self, desc: &'static str) -> Self {
        self.description = desc;
        self
    }

    /// Builder: set allowed helpers
    pub const fn with_helpers(mut self, helpers: &'static [u32]) -> Self {
        self.allowed_helpers = helpers;
        self
    }

    /// Check if a return value is valid for this program type.
    pub fn is_valid_return(&self, value: i64) -> bool {
        self.ret_range.contains(value)
    }

    /// Check if a helper is allowed for this program type.
    pub fn is_helper_allowed(&self, helper_id: u32) -> bool {
        if self.allowed_helpers.is_empty() {
            true // Empty means all allowed (checked elsewhere)
        } else {
            self.allowed_helpers.contains(&helper_id)
        }
    }

    /// Check if program has direct packet access
    pub fn has_packet_access(&self) -> bool {
        self.capabilities.direct_packet_access
    }

    /// Check if program can tail call
    pub fn can_tail_call(&self) -> bool {
        self.capabilities.tail_call
    }

    /// Check if program is sleepable
    pub fn is_sleepable(&self) -> bool {
        self.capabilities.sleepable
    }
}

impl Default for ProgTypeInfo {
    fn default() -> Self {
        Self {
            prog_type: 0,
            name: "UNSPEC",
            ctx_size: 0,
            ret_range: RetvalRange::new(0, 0),
            capabilities: ProgCapabilities::none(),
            max_insns: 1_000_000,
            description: "Unspecified program type",
            allowed_helpers: &[],
        }
    }
}

/// Provider trait for BPF program types.
///
/// Platform implementations must implement this trait to define
/// their supported program types and their properties.
///
/// # Example
///
/// ```ignore
/// struct LinuxProgTypeProvider;
///
/// impl ProgTypeProvider for LinuxProgTypeProvider {
///     fn get_info(&self, prog_type: u32) -> Option<&ProgTypeInfo> {
///         LINUX_PROG_TYPES.iter().find(|p| p.prog_type == prog_type)
///     }
///     
///     fn is_valid(&self, prog_type: u32) -> bool {
///         self.get_info(prog_type).is_some()
///     }
///     
///     // ... other methods
/// }
/// ```
pub trait ProgTypeProvider: Clone + Send + Sync {
    /// Get information about a program type.
    ///
    /// Returns `None` if the program type is not supported.
    fn get_info(&self, prog_type: u32) -> Option<&ProgTypeInfo>;

    /// Check if a program type is valid/supported.
    fn is_valid(&self, prog_type: u32) -> bool {
        self.get_info(prog_type).is_some()
    }

    /// Validate a return value for a program type.
    fn validate_return(&self, prog_type: u32, value: i64) -> PlatformResult<()> {
        let info = self.get_info(prog_type)
            .ok_or(PlatformError::ProgTypeNotFound(prog_type))?;
        
        if info.is_valid_return(value) {
            Ok(())
        } else {
            Err(PlatformError::InvalidReturnValue { prog_type, value })
        }
    }

    /// Get the context size for a program type.
    fn ctx_size(&self, prog_type: u32) -> Option<u32> {
        self.get_info(prog_type).map(|i| i.ctx_size)
    }

    /// Get the capabilities for a program type.
    fn capabilities(&self, prog_type: u32) -> Option<ProgCapabilities> {
        self.get_info(prog_type).map(|i| i.capabilities)
    }

    /// Get the return value range for a program type.
    fn ret_range(&self, prog_type: u32) -> Option<RetvalRange> {
        self.get_info(prog_type).map(|i| i.ret_range)
    }

    /// Get the allowed helpers for a program type.
    ///
    /// Returns an empty slice if no restrictions (all helpers allowed,
    /// subject to helper-level restrictions).
    fn allowed_helpers(&self, prog_type: u32) -> &[u32] {
        self.get_info(prog_type)
            .map(|i| i.allowed_helpers)
            .unwrap_or(&[])
    }

    /// Check if a helper is allowed for a program type.
    fn is_helper_allowed(&self, prog_type: u32, helper_id: u32) -> bool {
        self.get_info(prog_type)
            .map(|i| i.is_helper_allowed(helper_id))
            .unwrap_or(false)
    }

    /// Get the maximum instruction count for a program type.
    fn max_insns(&self, prog_type: u32) -> u32 {
        self.get_info(prog_type)
            .map(|i| i.max_insns)
            .unwrap_or(1_000_000)
    }

    /// Iterate over all supported program types.
    fn iter(&self) -> impl Iterator<Item = &ProgTypeInfo>;

    /// Get the count of supported program types.
    fn count(&self) -> usize {
        self.iter().count()
    }
}
