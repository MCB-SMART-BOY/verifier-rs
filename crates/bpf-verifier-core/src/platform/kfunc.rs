// SPDX-License-Identifier: GPL-2.0

//! 内核函数 (kfunc) 提供者 trait 和类型定义模块
//!
//! Kernel Function (kfunc) Provider Trait and Types.
//!
//! 本模块定义了 BPF 内核函数的平台无关接口。
//! Kfunc 是可以从 BPF 程序直接调用的内核函数，提供比辅助函数更大的灵活性。
//!
//! This module defines the platform-agnostic interface for BPF kernel functions.
//! Kfuncs are kernel functions that can be called directly from BPF programs,
//! providing more flexibility than helper functions.
//!
//! # 主要组件 / Main Components
//!
//! - **`KfuncDef`**: 内核函数定义，包含 BTF ID、参数类型和标志
//!   Kernel function definition with BTF ID, parameter types, and flags
//! - **`KfuncFlags`**: 内核函数特性标志（获取/释放引用、可信参数、可睡眠等）
//!   Kfunc characteristic flags (acquire/release ref, trusted args, sleepable, etc.)
//! - **`KfuncParamType`**: 内核函数参数类型枚举
//!   Kfunc parameter type enumeration
//! - **`KfuncProvider`**: 平台必须实现的 trait，用于提供内核函数
//!   Trait that platforms must implement to provide kernel functions

use super::types::{PlatformError, PlatformResult};

/// Flags describing kfunc characteristics.
///
/// These flags indicate special behaviors and requirements of kernel functions
/// that the verifier needs to track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KfuncFlags {
    /// Kfunc acquires a reference that must be released
    pub acquire: bool,
    /// Kfunc releases a reference
    pub release: bool,
    /// Kfunc requires trusted (kernel-provided) arguments
    pub trusted_args: bool,
    /// Kfunc may sleep (not allowed in atomic contexts)
    pub sleepable: bool,
    /// Kfunc is destructive (e.g., frees memory)
    pub destructive: bool,
    /// Kfunc operates on RCU-protected data
    pub rcu_protected: bool,
    /// Kfunc returns a nullable pointer
    pub ret_null: bool,
    /// Kfunc is a constructor (allocates new object)
    pub constructor: bool,
    /// Kfunc modifies its arguments
    pub mutates_args: bool,
}

impl KfuncFlags {
    /// Create with no flags set
    pub const fn none() -> Self {
        Self {
            acquire: false,
            release: false,
            trusted_args: false,
            sleepable: false,
            destructive: false,
            rcu_protected: false,
            ret_null: false,
            constructor: false,
            mutates_args: false,
        }
    }

    /// Create acquire kfunc flags
    pub const fn acquire() -> Self {
        Self {
            acquire: true,
            ..Self::none()
        }
    }

    /// Create release kfunc flags
    pub const fn release() -> Self {
        Self {
            release: true,
            ..Self::none()
        }
    }

    /// Builder: set acquire flag
    pub const fn with_acquire(mut self) -> Self {
        self.acquire = true;
        self
    }

    /// Builder: set release flag
    pub const fn with_release(mut self) -> Self {
        self.release = true;
        self
    }

    /// Builder: set trusted_args flag
    pub const fn with_trusted_args(mut self) -> Self {
        self.trusted_args = true;
        self
    }

    /// Builder: set sleepable flag
    pub const fn with_sleepable(mut self) -> Self {
        self.sleepable = true;
        self
    }

    /// Builder: set destructive flag
    pub const fn with_destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    /// Builder: set rcu_protected flag
    pub const fn with_rcu(mut self) -> Self {
        self.rcu_protected = true;
        self
    }

    /// Builder: set ret_null flag
    pub const fn with_ret_null(mut self) -> Self {
        self.ret_null = true;
        self
    }

    /// Builder: set constructor flag
    pub const fn with_constructor(mut self) -> Self {
        self.constructor = true;
        self
    }
}

/// Parameter type for kfunc arguments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncParamType {
    /// Scalar value (integer)
    Scalar,
    /// Pointer to BTF-typed object
    PtrToBtfId,
    /// Pointer to memory region
    PtrToMem,
    /// Pointer to allocated memory
    PtrToAlloc,
    /// Pointer to list head/node
    PtrToList,
    /// Pointer to rbtree root/node
    PtrToRbtree,
    /// Pointer to refcounted local object
    PtrToRefcountedLocal,
    /// Pointer to dynptr
    PtrToDynptr,
    /// Context pointer
    PtrToCtx,
    /// Any type (for polymorphic kfuncs)
    Any,
    /// Callback function pointer
    Callback,
}

/// Definition of a kernel function (kfunc).
///
/// This structure contains all information needed to verify calls to
/// a kernel function.
#[derive(Debug, Clone)]
pub struct KfuncDef {
    /// BTF ID of the kfunc
    pub btf_id: u32,
    /// Function name (e.g., "bpf_obj_new_impl")
    pub name: &'static str,
    /// Behavioral flags
    pub flags: KfuncFlags,
    /// Program types that can use this kfunc (empty = all types)
    pub allowed_prog_types: &'static [u32],
    /// Parameter types (up to 5)
    pub param_types: &'static [KfuncParamType],
    /// Return type (if any)
    pub ret_type: Option<KfuncParamType>,
    /// BTF ID of return type (for PtrToBtfId returns)
    pub ret_btf_id: Option<u32>,
}

impl KfuncDef {
    /// Create a new kfunc definition.
    pub const fn new(btf_id: u32, name: &'static str) -> Self {
        Self {
            btf_id,
            name,
            flags: KfuncFlags::none(),
            allowed_prog_types: &[],
            param_types: &[],
            ret_type: None,
            ret_btf_id: None,
        }
    }

    /// Builder: set flags
    pub const fn with_flags(mut self, flags: KfuncFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Builder: set allowed program types
    pub const fn for_prog_types(mut self, types: &'static [u32]) -> Self {
        self.allowed_prog_types = types;
        self
    }

    /// Builder: set parameter types
    pub const fn with_params(mut self, params: &'static [KfuncParamType]) -> Self {
        self.param_types = params;
        self
    }

    /// Builder: set return type
    pub const fn with_ret(mut self, ret: KfuncParamType) -> Self {
        self.ret_type = Some(ret);
        self
    }

    /// Builder: set return BTF ID
    pub const fn with_ret_btf_id(mut self, btf_id: u32) -> Self {
        self.ret_btf_id = Some(btf_id);
        self
    }

    /// Check if this kfunc is allowed for a given program type.
    pub fn is_allowed_for(&self, prog_type: u32) -> bool {
        if self.allowed_prog_types.is_empty() {
            true
        } else {
            self.allowed_prog_types.contains(&prog_type)
        }
    }

    /// Check if this kfunc acquires a reference.
    pub fn is_acquire(&self) -> bool {
        self.flags.acquire
    }

    /// Check if this kfunc releases a reference.
    pub fn is_release(&self) -> bool {
        self.flags.release
    }

    /// Check if this kfunc requires trusted arguments.
    pub fn requires_trusted_args(&self) -> bool {
        self.flags.trusted_args
    }

    /// Check if this kfunc is sleepable.
    pub fn is_sleepable(&self) -> bool {
        self.flags.sleepable
    }

    /// Get the number of parameters.
    pub fn param_count(&self) -> usize {
        self.param_types.len()
    }
}

/// Provider trait for kernel functions (kfuncs).
///
/// Platform implementations must implement this trait to define
/// their set of available kernel functions.
///
/// # Example
///
/// ```ignore
/// struct LinuxKfuncProvider {
///     kfuncs: Vec<KfuncDef>,
/// }
///
/// impl KfuncProvider for LinuxKfuncProvider {
///     fn lookup(&self, btf_id: u32) -> Option<&KfuncDef> {
///         self.kfuncs.iter().find(|k| k.btf_id == btf_id)
///     }
///     
///     fn lookup_by_name(&self, name: &str) -> Option<&KfuncDef> {
///         self.kfuncs.iter().find(|k| k.name == name)
///     }
///     
///     // ... other methods
/// }
/// ```
pub trait KfuncProvider: Clone + Send + Sync {
    /// Look up a kfunc by its BTF ID.
    fn lookup(&self, btf_id: u32) -> Option<&KfuncDef>;

    /// Look up a kfunc by its name.
    fn lookup_by_name(&self, name: &str) -> Option<&KfuncDef>;

    /// Check if a kfunc is allowed for a specific program type.
    fn is_allowed_for_prog(&self, btf_id: u32, prog_type: u32) -> bool {
        self.lookup(btf_id)
            .map(|k| k.is_allowed_for(prog_type))
            .unwrap_or(false)
    }

    /// Iterate over all registered kfuncs.
    fn iter(&self) -> impl Iterator<Item = &KfuncDef>;

    /// Get the count of registered kfuncs.
    fn count(&self) -> usize {
        self.iter().count()
    }

    /// Validate a kfunc call.
    fn validate_call(&self, btf_id: u32, prog_type: u32) -> PlatformResult<&KfuncDef> {
        let kfunc = self.lookup(btf_id)
            .ok_or(PlatformError::KfuncNotFound(btf_id))?;
        
        if !kfunc.is_allowed_for(prog_type) {
            return Err(PlatformError::KfuncNotAllowed {
                kfunc_id: btf_id,
                prog_type,
            });
        }
        
        Ok(kfunc)
    }

    /// Get all kfuncs that are acquire functions.
    fn acquire_kfuncs(&self) -> impl Iterator<Item = &KfuncDef> {
        self.iter().filter(|k| k.is_acquire())
    }

    /// Get all kfuncs that are release functions.
    fn release_kfuncs(&self) -> impl Iterator<Item = &KfuncDef> {
        self.iter().filter(|k| k.is_release())
    }

    /// Check if a kfunc exists by name.
    fn has_kfunc(&self, name: &str) -> bool {
        self.lookup_by_name(name).is_some()
    }
}
