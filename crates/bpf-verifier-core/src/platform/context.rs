// SPDX-License-Identifier: GPL-2.0

//! Context provider trait and types.
//!
//! This module defines the platform-agnostic interface for BPF program
//! context structures. Each program type has a specific context structure
//! that provides access to program-specific data (e.g., packet data for XDP,
//! socket buffer for socket filter).

use super::types::{PlatformError, PlatformResult};
use crate::core::types::BpfRegType;

/// Field access mode in context structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldAccessMode {
    /// Field can only be read
    Read,
    /// Field can only be written
    Write,
    /// Field can be read and written
    ReadWrite,
    /// Field access is denied
    Denied,
}

impl FieldAccessMode {
    /// Check if read access is allowed.
    pub fn can_read(&self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Check if write access is allowed.
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    /// Check if the requested access is allowed.
    pub fn allows(&self, is_write: bool) -> bool {
        if is_write {
            self.can_write()
        } else {
            self.can_read()
        }
    }
}

/// Result type of accessing a context field.
///
/// When a context field is accessed, the verifier needs to know
/// what register type the result should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldResultType {
    /// Result is a scalar value
    Scalar,
    /// Result is a pointer to packet data
    PtrToPacket,
    /// Result is a pointer to packet end
    PtrToPacketEnd,
    /// Result is a pointer to packet metadata
    PtrToPacketMeta,
    /// Result is a pointer to flow keys
    PtrToFlowKeys,
    /// Result is a pointer to socket
    PtrToSocket,
    /// Result is a pointer to BTF-typed object
    PtrToBtfId(u32),
    /// Result keeps current type (for writeable fields)
    Unchanged,
}

impl FieldResultType {
    /// Convert to BpfRegType.
    pub fn to_reg_type(&self) -> Option<BpfRegType> {
        match self {
            Self::Scalar => Some(BpfRegType::ScalarValue),
            Self::PtrToPacket => Some(BpfRegType::PtrToPacket),
            Self::PtrToPacketEnd => Some(BpfRegType::PtrToPacketEnd),
            Self::PtrToPacketMeta => Some(BpfRegType::PtrToPacketMeta),
            Self::PtrToFlowKeys => Some(BpfRegType::PtrToFlowKeys),
            Self::PtrToSocket => Some(BpfRegType::PtrToSocket),
            Self::PtrToBtfId(_) => Some(BpfRegType::PtrToBtfId),
            Self::Unchanged => None,
        }
    }
}

/// Definition of a context field.
///
/// Each field in a program's context structure is described by this
/// structure, including its location, access permissions, and the
/// resulting register type when accessed.
#[derive(Debug, Clone)]
pub struct ContextFieldDef {
    /// Offset from context base
    pub offset: u32,
    /// Size of the field in bytes
    pub size: u32,
    /// Access permissions
    pub access: FieldAccessMode,
    /// Human-readable field name
    pub name: &'static str,
    /// Register type when this field is read
    pub result_type: FieldResultType,
    /// Whether this field requires special handling
    pub special: bool,
    /// Required alignment for access
    pub alignment: u32,
    /// Whether narrow (sub-word) access is allowed
    pub allow_narrow: bool,
}

impl ContextFieldDef {
    /// Create a new context field definition.
    pub const fn new(
        offset: u32,
        size: u32,
        access: FieldAccessMode,
        name: &'static str,
    ) -> Self {
        Self {
            offset,
            size,
            access,
            name,
            result_type: FieldResultType::Scalar,
            special: false,
            alignment: 4,
            allow_narrow: false,
        }
    }

    /// Builder: set result type
    pub const fn with_result(mut self, result: FieldResultType) -> Self {
        self.result_type = result;
        self
    }

    /// Builder: mark as special
    pub const fn with_special(mut self) -> Self {
        self.special = true;
        self
    }

    /// Builder: set alignment
    pub const fn with_alignment(mut self, align: u32) -> Self {
        self.alignment = align;
        self
    }

    /// Builder: allow narrow access
    pub const fn with_narrow(mut self) -> Self {
        self.allow_narrow = true;
        self
    }

    /// Check if an access at given offset and size is valid.
    pub fn check_access(&self, off: u32, size: u32, is_write: bool) -> bool {
        // Check bounds
        if off < self.offset || off + size > self.offset + self.size {
            return false;
        }

        // Check access mode
        if !self.access.allows(is_write) {
            return false;
        }

        // Check alignment
        if (off - self.offset) % self.alignment != 0 {
            return false;
        }

        // Check narrow access
        if size < self.size && !self.allow_narrow {
            return false;
        }

        true
    }

    /// Get the end offset (exclusive) of this field.
    pub fn end_offset(&self) -> u32 {
        self.offset + self.size
    }
}

/// Context structure definition for a program type.
#[derive(Debug, Clone)]
pub struct ContextDef {
    /// Program type this context belongs to
    pub prog_type: u32,
    /// Total size of the context structure
    pub size: u32,
    /// Fields in the context
    pub fields: &'static [ContextFieldDef],
    /// Whether narrow access is allowed by default
    pub allow_narrow_default: bool,
    /// Default alignment requirement
    pub default_alignment: u32,
}

impl ContextDef {
    /// Create a new context definition.
    pub const fn new(prog_type: u32, size: u32, fields: &'static [ContextFieldDef]) -> Self {
        Self {
            prog_type,
            size,
            fields,
            allow_narrow_default: false,
            default_alignment: 4,
        }
    }

    /// Find a field containing the given offset.
    pub fn find_field(&self, offset: u32) -> Option<&ContextFieldDef> {
        self.fields.iter().find(|f| {
            offset >= f.offset && offset < f.end_offset()
        })
    }

    /// Check if access at offset+size spans multiple fields.
    pub fn spans_fields(&self, offset: u32, size: u32) -> bool {
        let end = offset + size;
        let mut in_field = false;
        
        for field in self.fields {
            let field_start = field.offset;
            let field_end = field.end_offset();
            
            // Check if access overlaps with this field
            if offset < field_end && end > field_start {
                if in_field {
                    return true; // Already in a field, now in another
                }
                in_field = true;
                
                // If access extends past this field, it spans
                if end > field_end {
                    return true;
                }
            }
        }
        
        false
    }
}

/// Provider trait for program context structures.
///
/// Platform implementations must implement this trait to define
/// the context structure for each program type.
pub trait ContextProvider: Clone + Send + Sync {
    /// Get the context definition for a program type.
    fn get_context(&self, prog_type: u32) -> Option<&ContextDef>;

    /// Get the context size for a program type.
    fn ctx_size(&self, prog_type: u32) -> u32 {
        self.get_context(prog_type).map(|c| c.size).unwrap_or(0)
    }

    /// Get a specific field in the context.
    fn get_field(&self, prog_type: u32, offset: u32) -> Option<&ContextFieldDef> {
        self.get_context(prog_type)?.find_field(offset)
    }

    /// Validate a context access.
    fn validate_access(
        &self,
        prog_type: u32,
        offset: u32,
        size: u32,
        is_write: bool,
    ) -> PlatformResult<&ContextFieldDef> {
        let ctx = self.get_context(prog_type)
            .ok_or(PlatformError::ProgTypeNotFound(prog_type))?;

        // Check if access is within context bounds
        if offset + size > ctx.size {
            return Err(PlatformError::ContextAccessDenied {
                prog_type,
                offset,
                size,
            });
        }

        // Check if access spans multiple fields
        if ctx.spans_fields(offset, size) {
            return Err(PlatformError::ContextAccessDenied {
                prog_type,
                offset,
                size,
            });
        }

        // Find the field being accessed
        let field = ctx.find_field(offset)
            .ok_or(PlatformError::ContextFieldNotFound { prog_type, offset })?;

        // Validate the access
        if !field.check_access(offset, size, is_write) {
            return Err(PlatformError::ContextAccessDenied {
                prog_type,
                offset,
                size,
            });
        }

        Ok(field)
    }

    /// Get all fields for a program type's context.
    fn fields(&self, prog_type: u32) -> &[ContextFieldDef] {
        self.get_context(prog_type)
            .map(|c| c.fields)
            .unwrap_or(&[])
    }

    /// Check if a program type has context access.
    fn has_context(&self, prog_type: u32) -> bool {
        self.get_context(prog_type).is_some()
    }

    /// Iterate over all context definitions.
    fn iter(&self) -> impl Iterator<Item = &ContextDef>;
}
