// SPDX-License-Identifier: GPL-2.0

//! Helper function provider trait and types.
//!
//! This module defines the platform-agnostic interface for BPF helper functions.
//! Each platform (Linux, custom OS) implements [`HelperProvider`] to provide
//! its own set of helper function definitions.

use crate::core::types::{BpfArgType, BpfRetType};
use super::types::PlatformResult;

/// Flags describing helper function characteristics.
///
/// These flags indicate special behaviors and requirements of helper functions
/// that the verifier needs to track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HelperFlags {
    /// Function requires elevated privileges (CAP_SYS_ADMIN, CAP_PERFMON, etc.)
    pub privileged: bool,
    /// Function may sleep (not allowed in atomic contexts)
    pub may_sleep: bool,
    /// Function acquires a reference that must be released
    pub acquires_ref: bool,
    /// Function releases a reference
    pub releases_ref: bool,
    /// Function is only available to specific program types
    pub restricted: bool,
    /// Function performs packet data access
    pub pkt_access: bool,
    /// Function modifies packet data
    pub pkt_modify: bool,
    /// Function returns a pointer that may be NULL
    pub returns_null: bool,
    /// Function is a callback setter
    pub callback: bool,
}

impl HelperFlags {
    /// Create default (no flags set)
    pub const fn none() -> Self {
        Self {
            privileged: false,
            may_sleep: false,
            acquires_ref: false,
            releases_ref: false,
            restricted: false,
            pkt_access: false,
            pkt_modify: false,
            returns_null: false,
            callback: false,
        }
    }

    /// Create with privileged flag
    pub const fn privileged() -> Self {
        Self {
            privileged: true,
            ..Self::none()
        }
    }

    /// Create with may_sleep flag
    pub const fn sleepable() -> Self {
        Self {
            may_sleep: true,
            ..Self::none()
        }
    }

    /// Create with acquires_ref flag
    pub const fn acquire() -> Self {
        Self {
            acquires_ref: true,
            ..Self::none()
        }
    }

    /// Create with releases_ref flag
    pub const fn release() -> Self {
        Self {
            releases_ref: true,
            ..Self::none()
        }
    }

    /// Create with packet access flag
    pub const fn pkt() -> Self {
        Self {
            pkt_access: true,
            ..Self::none()
        }
    }

    /// Builder: set privileged
    pub const fn with_privileged(mut self) -> Self {
        self.privileged = true;
        self
    }

    /// Builder: set may_sleep
    pub const fn with_sleep(mut self) -> Self {
        self.may_sleep = true;
        self
    }

    /// Builder: set acquires_ref
    pub const fn with_acquire(mut self) -> Self {
        self.acquires_ref = true;
        self
    }

    /// Builder: set releases_ref
    pub const fn with_release(mut self) -> Self {
        self.releases_ref = true;
        self
    }

    /// Builder: set returns_null
    pub const fn with_null_ret(mut self) -> Self {
        self.returns_null = true;
        self
    }
}

/// Definition of a BPF helper function.
///
/// This structure contains all information needed to verify calls to
/// a helper function, including argument types, return type, and
/// behavioral flags.
#[derive(Debug, Clone)]
pub struct HelperDef {
    /// Unique function ID
    pub func_id: u32,
    /// Human-readable function name (e.g., "bpf_map_lookup_elem")
    pub name: &'static str,
    /// Return type
    pub ret_type: BpfRetType,
    /// Argument types (up to 5 arguments)
    pub arg_types: [BpfArgType; 5],
    /// Behavioral flags
    pub flags: HelperFlags,
    /// Program types that can use this helper (empty = all types allowed)
    pub allowed_prog_types: &'static [u32],
}

impl HelperDef {
    /// Create a new helper definition.
    pub const fn new(
        func_id: u32,
        name: &'static str,
        ret_type: BpfRetType,
        arg_types: [BpfArgType; 5],
    ) -> Self {
        Self {
            func_id,
            name,
            ret_type,
            arg_types,
            flags: HelperFlags::none(),
            allowed_prog_types: &[],
        }
    }

    /// Builder: set flags
    pub const fn with_flags(mut self, flags: HelperFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Builder: restrict to specific program types
    pub const fn for_prog_types(mut self, types: &'static [u32]) -> Self {
        self.allowed_prog_types = types;
        self.flags.restricted = true;
        self
    }

    /// Check if this helper is allowed for a given program type.
    pub fn is_allowed_for(&self, prog_type: u32) -> bool {
        if self.allowed_prog_types.is_empty() {
            true // No restrictions = allowed for all
        } else {
            self.allowed_prog_types.contains(&prog_type)
        }
    }

    /// Get the number of arguments this helper takes.
    pub fn arg_count(&self) -> usize {
        self.arg_types
            .iter()
            .position(|&t| t == BpfArgType::DontCare)
            .unwrap_or(5)
    }

    /// Check if this helper acquires a reference.
    pub fn acquires_ref(&self) -> bool {
        self.flags.acquires_ref
    }

    /// Check if this helper releases a reference.
    pub fn releases_ref(&self) -> bool {
        self.flags.releases_ref
    }

    /// Check if this helper may return NULL.
    pub fn may_return_null(&self) -> bool {
        self.flags.returns_null || matches!(
            self.ret_type,
            BpfRetType::PtrToMapValueOrNull
            | BpfRetType::PtrToSocketOrNull
            | BpfRetType::PtrToAllocMemOrNull
            | BpfRetType::PtrToMemOrNull
            | BpfRetType::PtrToBtfIdOrNull
        )
    }
}

/// Provider trait for BPF helper functions.
///
/// Platform implementations must implement this trait to provide
/// their set of available helper functions.
///
/// # Example
///
/// ```ignore
/// struct LinuxHelperProvider;
///
/// impl HelperProvider for LinuxHelperProvider {
///     fn lookup(&self, func_id: u32) -> Option<&HelperDef> {
///         LINUX_HELPER_DB.iter().find(|h| h.func_id == func_id)
///     }
///     
///     fn is_allowed_for_prog(&self, func_id: u32, prog_type: u32) -> bool {
///         self.lookup(func_id)
///             .map(|h| h.is_allowed_for(prog_type))
///             .unwrap_or(false)
///     }
///     
///     // ... other methods
/// }
/// ```
pub trait HelperProvider: Clone + Send + Sync {
    /// Look up a helper function by its ID.
    ///
    /// Returns `None` if no helper with the given ID exists.
    fn lookup(&self, func_id: u32) -> Option<&HelperDef>;

    /// Check if a helper is allowed for a specific program type.
    ///
    /// Returns `false` if the helper doesn't exist or isn't allowed.
    fn is_allowed_for_prog(&self, func_id: u32, prog_type: u32) -> bool {
        self.lookup(func_id)
            .map(|h| h.is_allowed_for(prog_type))
            .unwrap_or(false)
    }

    /// Get the total number of registered helpers.
    fn count(&self) -> usize;

    /// Look up a helper by name.
    ///
    /// Default implementation iterates through all helpers.
    fn lookup_by_name(&self, name: &str) -> Option<&HelperDef> {
        self.iter().find(|h| h.name == name)
    }

    /// Iterate over all registered helper functions.
    fn iter(&self) -> impl Iterator<Item = &HelperDef>;

    /// Get all helpers allowed for a specific program type.
    fn helpers_for_prog(&self, prog_type: u32) -> impl Iterator<Item = &HelperDef> {
        self.iter().filter(move |h| h.is_allowed_for(prog_type))
    }

    /// Validate a helper call (basic validation).
    ///
    /// This performs basic validation that the helper exists and is
    /// allowed for the program type. More detailed argument validation
    /// is done by the verifier.
    fn validate_call(&self, func_id: u32, prog_type: u32) -> PlatformResult<&HelperDef> {
        let helper = self.lookup(func_id)
            .ok_or(super::types::PlatformError::HelperNotFound(func_id))?;
        
        if !helper.is_allowed_for(prog_type) {
            return Err(super::types::PlatformError::HelperNotAllowed {
                helper_id: func_id,
                prog_type,
            });
        }
        
        Ok(helper)
    }
}

/// Convenience macro for defining helper arrays.
///
/// # Example
///
/// ```ignore
/// helpers! {
///     MapLookupElem(1) -> PtrToMapValueOrNull {
///         args: [ConstMapPtr, PtrToMapKey],
///         flags: none(),
///     },
///     MapUpdateElem(2) -> Integer {
///         args: [ConstMapPtr, PtrToMapKey, PtrToMapValue, Anything],
///         flags: none(),
///     },
/// }
/// ```
#[macro_export]
macro_rules! define_helpers {
    (
        $(
            $name:ident($id:expr) -> $ret:ident {
                args: [$($arg:ident),* $(,)?],
                flags: $flags:expr $(,)?
            }
        ),* $(,)?
    ) => {
        &[
            $(
                $crate::platform::HelperDef::new(
                    $id,
                    stringify!($name),
                    $crate::core::types::BpfRetType::$ret,
                    $crate::platform::helper::_make_args!($($arg),*),
                ).with_flags($flags)
            ),*
        ]
    };
}

/// Internal macro for creating argument arrays
#[doc(hidden)]
#[macro_export]
macro_rules! _make_args {
    () => {
        [$crate::core::types::BpfArgType::DontCare; 5]
    };
    ($a0:ident) => {
        [
            $crate::core::types::BpfArgType::$a0,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
        ]
    };
    ($a0:ident, $a1:ident) => {
        [
            $crate::core::types::BpfArgType::$a0,
            $crate::core::types::BpfArgType::$a1,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
        ]
    };
    ($a0:ident, $a1:ident, $a2:ident) => {
        [
            $crate::core::types::BpfArgType::$a0,
            $crate::core::types::BpfArgType::$a1,
            $crate::core::types::BpfArgType::$a2,
            $crate::core::types::BpfArgType::DontCare,
            $crate::core::types::BpfArgType::DontCare,
        ]
    };
    ($a0:ident, $a1:ident, $a2:ident, $a3:ident) => {
        [
            $crate::core::types::BpfArgType::$a0,
            $crate::core::types::BpfArgType::$a1,
            $crate::core::types::BpfArgType::$a2,
            $crate::core::types::BpfArgType::$a3,
            $crate::core::types::BpfArgType::DontCare,
        ]
    };
    ($a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident) => {
        [
            $crate::core::types::BpfArgType::$a0,
            $crate::core::types::BpfArgType::$a1,
            $crate::core::types::BpfArgType::$a2,
            $crate::core::types::BpfArgType::$a3,
            $crate::core::types::BpfArgType::$a4,
        ]
    };
}


