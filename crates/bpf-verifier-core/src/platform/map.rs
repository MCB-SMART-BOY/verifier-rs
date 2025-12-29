// SPDX-License-Identifier: GPL-2.0

//! Map provider trait and types.
//!
//! This module defines the platform-agnostic interface for BPF maps.
//! Each platform implements [`MapProvider`] to define its supported
//! map types and their capabilities.

use super::types::{PlatformError, PlatformResult};

/// Operations that can be performed on maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapOp {
    /// Look up a value by key
    Lookup,
    /// Update/insert a key-value pair
    Update,
    /// Delete a key-value pair
    Delete,
    /// Push to stack/queue
    Push,
    /// Pop from stack/queue
    Pop,
    /// Peek at stack/queue top
    Peek,
    /// Get next key
    GetNextKey,
    /// Lookup and delete atomically
    LookupAndDelete,
}

impl MapOp {
    /// Get the operation name for error messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Push => "push",
            Self::Pop => "pop",
            Self::Peek => "peek",
            Self::GetNextKey => "get_next_key",
            Self::LookupAndDelete => "lookup_and_delete",
        }
    }
}

/// Capabilities of a map type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapCapabilities {
    /// Supports lookup operation
    pub lookup: bool,
    /// Supports update operation
    pub update: bool,
    /// Supports delete operation
    pub delete: bool,
    /// Supports push operation (stack/queue)
    pub push: bool,
    /// Supports pop operation (stack/queue)
    pub pop: bool,
    /// Supports peek operation (stack/queue)
    pub peek: bool,
    /// Is per-CPU map
    pub percpu: bool,
    /// Has special fields (timer, spinlock, etc.)
    pub has_special_fields: bool,
    /// Supports lookup-and-delete
    pub lookup_and_delete: bool,
    /// Is a memory-mapped map (e.g., arena)
    pub mmap: bool,
}

impl MapCapabilities {
    /// Create with no capabilities
    pub const fn none() -> Self {
        Self {
            lookup: false,
            update: false,
            delete: false,
            push: false,
            pop: false,
            peek: false,
            percpu: false,
            has_special_fields: false,
            lookup_and_delete: false,
            mmap: false,
        }
    }

    /// Create with standard hash/array capabilities
    pub const fn standard() -> Self {
        Self {
            lookup: true,
            update: true,
            delete: true,
            push: false,
            pop: false,
            peek: false,
            percpu: false,
            has_special_fields: false,
            lookup_and_delete: true,
            mmap: false,
        }
    }

    /// Create with array capabilities (no delete)
    pub const fn array() -> Self {
        Self {
            lookup: true,
            update: true,
            delete: false, // Arrays don't support delete
            push: false,
            pop: false,
            peek: false,
            percpu: false,
            has_special_fields: false,
            lookup_and_delete: false,
            mmap: false,
        }
    }

    /// Create with stack/queue capabilities
    pub const fn stack_queue() -> Self {
        Self {
            lookup: false,
            update: false,
            delete: false,
            push: true,
            pop: true,
            peek: true,
            percpu: false,
            has_special_fields: false,
            lookup_and_delete: false,
            mmap: false,
        }
    }

    /// Builder: set percpu flag
    pub const fn with_percpu(mut self) -> Self {
        self.percpu = true;
        self
    }

    /// Builder: set special fields flag
    pub const fn with_special_fields(mut self) -> Self {
        self.has_special_fields = true;
        self
    }

    /// Builder: set mmap flag
    pub const fn with_mmap(mut self) -> Self {
        self.mmap = true;
        self
    }

    /// Check if an operation is supported.
    pub fn supports_op(&self, op: MapOp) -> bool {
        match op {
            MapOp::Lookup => self.lookup,
            MapOp::Update => self.update,
            MapOp::Delete => self.delete,
            MapOp::Push => self.push,
            MapOp::Pop => self.pop,
            MapOp::Peek => self.peek,
            MapOp::GetNextKey => self.lookup, // Usually available with lookup
            MapOp::LookupAndDelete => self.lookup_and_delete,
        }
    }
}

/// Special field types that can appear in map values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialFieldType {
    /// bpf_timer field
    Timer,
    /// bpf_spin_lock field
    SpinLock,
    /// kptr (kernel pointer)
    Kptr,
    /// list_head for intrusive linked list
    ListHead,
    /// list_node for intrusive linked list
    ListNode,
    /// rb_root for red-black tree
    RbtreeRoot,
    /// rb_node for red-black tree
    RbtreeNode,
    /// refcount field
    Refcount,
    /// workqueue field
    Workqueue,
}

/// Information about a special field in map value.
#[derive(Debug, Clone)]
pub struct SpecialFieldInfo {
    /// Offset from value start
    pub offset: u32,
    /// Size of the field
    pub size: u32,
    /// Type of special field
    pub field_type: SpecialFieldType,
}

/// Information about a BPF map type.
#[derive(Debug, Clone)]
pub struct MapTypeInfo {
    /// Numeric map type ID
    pub map_type: u32,
    /// Human-readable name (e.g., "HASH", "ARRAY")
    pub name: &'static str,
    /// Map capabilities
    pub capabilities: MapCapabilities,
    /// Description of the map type
    pub description: &'static str,
    /// Helper functions that work with this map type
    pub allowed_helpers: &'static [u32],
}

impl MapTypeInfo {
    /// Create a new map type info.
    pub const fn new(map_type: u32, name: &'static str, capabilities: MapCapabilities) -> Self {
        Self {
            map_type,
            name,
            capabilities,
            description: "",
            allowed_helpers: &[],
        }
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

    /// Check if an operation is supported.
    pub fn supports_op(&self, op: MapOp) -> bool {
        self.capabilities.supports_op(op)
    }

    /// Check if a helper is allowed for this map type.
    pub fn is_helper_allowed(&self, helper_id: u32) -> bool {
        if self.allowed_helpers.is_empty() {
            true // No restrictions
        } else {
            self.allowed_helpers.contains(&helper_id)
        }
    }
}

impl Default for MapTypeInfo {
    fn default() -> Self {
        Self {
            map_type: 0,
            name: "UNSPEC",
            capabilities: MapCapabilities::none(),
            description: "Unspecified map type",
            allowed_helpers: &[],
        }
    }
}

/// Provider trait for BPF map types.
///
/// Platform implementations must implement this trait to define
/// their supported map types and their properties.
pub trait MapProvider: Clone + Send + Sync {
    /// Get information about a map type.
    fn get_info(&self, map_type: u32) -> Option<&MapTypeInfo>;

    /// Check if a map type is valid/supported.
    fn is_valid(&self, map_type: u32) -> bool {
        self.get_info(map_type).is_some()
    }

    /// Validate a map operation.
    fn validate_op(&self, map_type: u32, op: MapOp) -> PlatformResult<()> {
        let info = self.get_info(map_type)
            .ok_or(PlatformError::MapTypeNotFound(map_type))?;
        
        if info.supports_op(op) {
            Ok(())
        } else {
            Err(PlatformError::MapOpNotAllowed {
                map_type,
                op: op.name(),
            })
        }
    }

    /// Get capabilities for a map type.
    fn capabilities(&self, map_type: u32) -> Option<MapCapabilities> {
        self.get_info(map_type).map(|i| i.capabilities)
    }

    /// Get allowed helpers for a map type.
    fn allowed_helpers(&self, map_type: u32) -> &[u32] {
        self.get_info(map_type)
            .map(|i| i.allowed_helpers)
            .unwrap_or(&[])
    }

    /// Check if a helper is allowed for a map type.
    fn is_helper_allowed(&self, map_type: u32, helper_id: u32) -> bool {
        self.get_info(map_type)
            .map(|i| i.is_helper_allowed(helper_id))
            .unwrap_or(false)
    }

    /// Iterate over all supported map types.
    fn iter(&self) -> impl Iterator<Item = &MapTypeInfo>;

    /// Get the count of supported map types.
    fn count(&self) -> usize {
        self.iter().count()
    }

    /// Get special fields for a specific map (runtime query).
    ///
    /// This may depend on the specific map instance, not just the type.
    /// Default implementation returns empty.
    fn get_special_fields(&self, _map_type: u32) -> &[SpecialFieldInfo] {
        &[]
    }
}
