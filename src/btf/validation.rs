//! BTF-based type validation.
//!
//! This module provides type-aware verification using BPF Type Format (BTF)
//! information. BTF enables the verifier to understand struct layouts,
//! function signatures, and type relationships for more precise validation.

#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use crate::core::error::{Result, VerifierError};

/// BTF type kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BtfKind {
    /// Unknown/invalid type.
    Unknown = 0,
    /// Integer type.
    Int = 1,
    /// Pointer type.
    Ptr = 2,
    /// Array type.
    Array = 3,
    /// Struct type.
    Struct = 4,
    /// Union type.
    Union = 5,
    /// Enum type.
    Enum = 6,
    /// Forward declaration.
    Fwd = 7,
    /// Typedef.
    Typedef = 8,
    /// Volatile qualifier.
    Volatile = 9,
    /// Const qualifier.
    Const = 10,
    /// Restrict qualifier.
    Restrict = 11,
    /// Function type.
    Func = 12,
    /// Function prototype.
    FuncProto = 13,
    /// Variable.
    Var = 14,
    /// Data section.
    Datasec = 15,
    /// Floating point.
    Float = 16,
    /// Decl tag.
    DeclTag = 17,
    /// Type tag.
    TypeTag = 18,
    /// 64-bit enum.
    Enum64 = 19,
}

impl From<u32> for BtfKind {
    fn from(val: u32) -> Self {
        match val {
            1 => BtfKind::Int,
            2 => BtfKind::Ptr,
            3 => BtfKind::Array,
            4 => BtfKind::Struct,
            5 => BtfKind::Union,
            6 => BtfKind::Enum,
            7 => BtfKind::Fwd,
            8 => BtfKind::Typedef,
            9 => BtfKind::Volatile,
            10 => BtfKind::Const,
            11 => BtfKind::Restrict,
            12 => BtfKind::Func,
            13 => BtfKind::FuncProto,
            14 => BtfKind::Var,
            15 => BtfKind::Datasec,
            16 => BtfKind::Float,
            17 => BtfKind::DeclTag,
            18 => BtfKind::TypeTag,
            19 => BtfKind::Enum64,
            _ => BtfKind::Unknown,
        }
    }
}

/// BTF integer encoding flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfIntEncoding {
    /// Whether the integer is signed.
    pub is_signed: bool,
    /// Whether this is a char type.
    pub is_char: bool,
    /// Whether this is a bool type.
    pub is_bool: bool,
    /// Bit offset within the storage unit.
    pub offset: u8,
    /// Number of bits used.
    pub bits: u8,
}

impl BtfIntEncoding {
    /// Parse from BTF int encoding value.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            is_signed: (raw & 0x01) != 0,
            is_char: (raw & 0x02) != 0,
            is_bool: (raw & 0x04) != 0,
            offset: ((raw >> 16) & 0xff) as u8,
            bits: ((raw >> 24) & 0xff) as u8,
        }
    }
}

/// BTF struct/union member.
#[derive(Debug, Clone)]
pub struct BtfMember {
    /// Name of the member.
    pub name: String,
    /// Type ID of the member.
    pub type_id: u32,
    /// Offset in bits (for bitfields) or bytes.
    pub offset: u32,
    /// Whether this uses bitfield offset encoding.
    pub bitfield: bool,
}

/// BTF function parameter.
#[derive(Debug, Clone)]
pub struct BtfParam {
    /// Parameter name.
    pub name: String,
    /// Type ID.
    pub type_id: u32,
}

/// BTF array info.
#[derive(Debug, Clone)]
pub struct BtfArray {
    /// Element type ID.
    pub elem_type: u32,
    /// Index type ID.
    pub index_type: u32,
    /// Number of elements.
    pub nelems: u32,
}

/// BTF enum value.
#[derive(Debug, Clone)]
pub struct BtfEnumValue {
    /// Enum value name.
    pub name: String,
    /// Value (32-bit).
    pub val: i32,
}

/// BTF 64-bit enum value.
#[derive(Debug, Clone)]
pub struct BtfEnum64Value {
    /// Enum value name.
    pub name: String,
    /// Value (64-bit).
    pub val: i64,
}

/// Variable linkage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtfVarLinkage {
    /// Static variable.
    Static = 0,
    /// Global allocated variable.
    GlobalAlloc = 1,
    /// Global external variable.
    GlobalExtern = 2,
}

/// BTF type representation.
#[derive(Debug, Clone)]
pub enum BtfType {
    /// Void type (type_id 0).
    Void,
    /// Integer type.
    Int {
        /// Type name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Encoding information.
        encoding: BtfIntEncoding,
    },
    /// Pointer type.
    Ptr {
        /// Target type ID.
        target: u32,
    },
    /// Array type.
    Array(BtfArray),
    /// Struct type.
    Struct {
        /// Struct name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Members.
        members: Vec<BtfMember>,
    },
    /// Union type.
    Union {
        /// Union name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Members.
        members: Vec<BtfMember>,
    },
    /// Enum type.
    Enum {
        /// Enum name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Values.
        values: Vec<BtfEnumValue>,
        /// Whether signed.
        is_signed: bool,
    },
    /// Forward declaration.
    Fwd {
        /// Type name.
        name: String,
        /// Whether this is a union (vs struct).
        is_union: bool,
    },
    /// Typedef.
    Typedef {
        /// Typedef name.
        name: String,
        /// Target type ID.
        target: u32,
    },
    /// Volatile qualifier.
    Volatile {
        /// Target type ID.
        target: u32,
    },
    /// Const qualifier.
    Const {
        /// Target type ID.
        target: u32,
    },
    /// Restrict qualifier.
    Restrict {
        /// Target type ID.
        target: u32,
    },
    /// Function.
    Func {
        /// Function name.
        name: String,
        /// Prototype type ID.
        proto: u32,
        /// Function linkage.
        linkage: u32,
    },
    /// Function prototype.
    FuncProto {
        /// Return type ID.
        ret_type: u32,
        /// Parameters.
        params: Vec<BtfParam>,
    },
    /// Variable.
    Var {
        /// Variable name.
        name: String,
        /// Type ID.
        type_id: u32,
        /// Linkage.
        linkage: BtfVarLinkage,
    },
    /// Data section.
    Datasec {
        /// Section name.
        name: String,
        /// Size.
        size: u32,
        /// Variables in section.
        vars: Vec<(u32, u32, u32)>, // (type_id, offset, size)
    },
    /// Float type.
    Float {
        /// Type name.
        name: String,
        /// Size in bytes.
        size: u32,
    },
    /// 64-bit enum.
    Enum64 {
        /// Enum name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Values.
        values: Vec<BtfEnum64Value>,
        /// Whether signed.
        is_signed: bool,
    },
    /// Declaration tag.
    DeclTag {
        /// Tag value.
        value: String,
        /// Target type ID.
        target: u32,
        /// Component index (-1 for type itself).
        component_idx: i32,
    },
    /// Type tag.
    TypeTag {
        /// Tag value.
        value: String,
        /// Target type ID.
        target: u32,
    },
}

impl BtfType {
    /// Get the kind of this type.
    pub fn kind(&self) -> BtfKind {
        match self {
            BtfType::Void => BtfKind::Unknown,
            BtfType::Int { .. } => BtfKind::Int,
            BtfType::Ptr { .. } => BtfKind::Ptr,
            BtfType::Array(_) => BtfKind::Array,
            BtfType::Struct { .. } => BtfKind::Struct,
            BtfType::Union { .. } => BtfKind::Union,
            BtfType::Enum { .. } => BtfKind::Enum,
            BtfType::Fwd { .. } => BtfKind::Fwd,
            BtfType::Typedef { .. } => BtfKind::Typedef,
            BtfType::Volatile { .. } => BtfKind::Volatile,
            BtfType::Const { .. } => BtfKind::Const,
            BtfType::Restrict { .. } => BtfKind::Restrict,
            BtfType::Func { .. } => BtfKind::Func,
            BtfType::FuncProto { .. } => BtfKind::FuncProto,
            BtfType::Var { .. } => BtfKind::Var,
            BtfType::Datasec { .. } => BtfKind::Datasec,
            BtfType::Float { .. } => BtfKind::Float,
            BtfType::DeclTag { .. } => BtfKind::DeclTag,
            BtfType::TypeTag { .. } => BtfKind::TypeTag,
            BtfType::Enum64 { .. } => BtfKind::Enum64,
        }
    }

    /// Get the name of this type, if any.
    pub fn name(&self) -> Option<&str> {
        match self {
            BtfType::Int { name, .. } => Some(name),
            BtfType::Struct { name, .. } => Some(name),
            BtfType::Union { name, .. } => Some(name),
            BtfType::Enum { name, .. } => Some(name),
            BtfType::Fwd { name, .. } => Some(name),
            BtfType::Typedef { name, .. } => Some(name),
            BtfType::Func { name, .. } => Some(name),
            BtfType::Var { name, .. } => Some(name),
            BtfType::Datasec { name, .. } => Some(name),
            BtfType::Float { name, .. } => Some(name),
            BtfType::Enum64 { name, .. } => Some(name),
            _ => None,
        }
    }
}

/// BTF type database.
#[derive(Debug, Default)]
pub struct BtfTypes {
    /// Types indexed by ID.
    types: Vec<BtfType>,
    /// Name to type ID mapping.
    name_map: HashMap<String, Vec<u32>>,
    /// Struct/union member offset cache.
    member_cache: HashMap<(u32, String), (u32, u32)>, // (type_id, field) -> (offset, type_id)
}

impl BtfTypes {
    /// Create a new empty BTF type database.
    pub fn new() -> Self {
        let mut db = Self::default();
        // Type ID 0 is always void
        db.types.push(BtfType::Void);
        db
    }

    /// Add a type and return its ID.
    pub fn add_type(&mut self, ty: BtfType) -> u32 {
        let id = self.types.len() as u32;
        if let Some(name) = ty.name() {
            if !name.is_empty() {
                self.name_map
                    .entry(name.to_string())
                    .or_default()
                    .push(id);
            }
        }
        self.types.push(ty);
        id
    }

    /// Get a type by ID.
    pub fn get(&self, id: u32) -> Option<&BtfType> {
        self.types.get(id as usize)
    }

    /// Get types by name.
    pub fn get_by_name(&self, name: &str) -> Vec<u32> {
        self.name_map.get(name).cloned().unwrap_or_default()
    }

    /// Get number of types.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Check if empty (only void type).
    pub fn is_empty(&self) -> bool {
        self.types.len() <= 1
    }

    /// Resolve through modifiers (const, volatile, typedef, etc.) to base type.
    pub fn resolve_type(&self, mut id: u32) -> u32 {
        let mut seen = HashSet::new();
        while let Some(ty) = self.get(id) {
            if !seen.insert(id) {
                break; // Cycle detected
            }
            match ty {
                BtfType::Typedef { target, .. }
                | BtfType::Volatile { target }
                | BtfType::Const { target }
                | BtfType::Restrict { target }
                | BtfType::TypeTag { target, .. } => {
                    id = *target;
                }
                _ => break,
            }
        }
        id
    }

    /// Get the size of a type in bytes.
    pub fn type_size(&self, id: u32) -> Option<u32> {
        let resolved = self.resolve_type(id);
        match self.get(resolved)? {
            BtfType::Void => Some(0),
            BtfType::Int { size, .. } => Some(*size),
            BtfType::Ptr { .. } => Some(8), // Assume 64-bit
            BtfType::Array(arr) => {
                let elem_size = self.type_size(arr.elem_type)?;
                Some(elem_size * arr.nelems)
            }
            BtfType::Struct { size, .. } => Some(*size),
            BtfType::Union { size, .. } => Some(*size),
            BtfType::Enum { size, .. } => Some(*size),
            BtfType::Float { size, .. } => Some(*size),
            BtfType::Enum64 { size, .. } => Some(*size),
            _ => None,
        }
    }

    /// Find a struct member by name and return (offset, type_id).
    pub fn find_member(&mut self, struct_id: u32, field: &str) -> Option<(u32, u32)> {
        let cache_key = (struct_id, field.to_string());
        if let Some(&result) = self.member_cache.get(&cache_key) {
            return Some(result);
        }

        let resolved = self.resolve_type(struct_id);
        let members = match self.get(resolved)? {
            BtfType::Struct { members, .. } => members.clone(),
            BtfType::Union { members, .. } => members.clone(),
            _ => return None,
        };

        for member in &members {
            if member.name == field {
                let offset = if member.bitfield {
                    member.offset / 8 // Convert bit offset to bytes
                } else {
                    member.offset
                };
                let result = (offset, member.type_id);
                self.member_cache.insert(cache_key, result);
                return Some(result);
            }
        }
        None
    }

    /// Check if type is a pointer.
    pub fn is_pointer(&self, id: u32) -> bool {
        let resolved = self.resolve_type(id);
        matches!(self.get(resolved), Some(BtfType::Ptr { .. }))
    }

    /// Check if type is an integer.
    pub fn is_integer(&self, id: u32) -> bool {
        let resolved = self.resolve_type(id);
        matches!(self.get(resolved), Some(BtfType::Int { .. }))
    }

    /// Check if type is a struct.
    pub fn is_struct(&self, id: u32) -> bool {
        let resolved = self.resolve_type(id);
        matches!(self.get(resolved), Some(BtfType::Struct { .. }))
    }

    /// Check if type is a function.
    pub fn is_func(&self, id: u32) -> bool {
        matches!(self.get(id), Some(BtfType::Func { .. }))
    }

    /// Get pointer target type.
    pub fn ptr_target(&self, id: u32) -> Option<u32> {
        let resolved = self.resolve_type(id);
        match self.get(resolved)? {
            BtfType::Ptr { target } => Some(*target),
            _ => None,
        }
    }

    /// Get function prototype for a function type.
    pub fn func_proto(&self, func_id: u32) -> Option<&BtfType> {
        match self.get(func_id)? {
            BtfType::Func { proto, .. } => self.get(*proto),
            _ => None,
        }
    }
}

/// BTF type validator.
#[derive(Debug)]
pub struct BtfValidator {
    /// BTF type database.
    types: BtfTypes,
}

impl BtfValidator {
    /// Create a new BTF validator.
    pub fn new(types: BtfTypes) -> Self {
        Self { types }
    }

    /// Create a validator with no types (validation will be permissive).
    pub fn empty() -> Self {
        Self {
            types: BtfTypes::new(),
        }
    }

    /// Get the underlying type database.
    pub fn types(&self) -> &BtfTypes {
        &self.types
    }

    /// Get mutable access to the type database.
    pub fn types_mut(&mut self) -> &mut BtfTypes {
        &mut self.types
    }

    /// Validate that a memory access at offset is valid for a type.
    pub fn validate_access(
        &mut self,
        type_id: u32,
        offset: u32,
        size: u32,
        is_write: bool,
    ) -> Result<AccessInfo> {
        if self.types.is_empty() {
            // No BTF info, allow all accesses
            return Ok(AccessInfo {
                field_type: 0,
                field_offset: offset,
                is_bitfield: false,
            });
        }

        let resolved = self.types.resolve_type(type_id);
        let ty = self.types.get(resolved).ok_or_else(|| {
            VerifierError::InvalidMemoryAccess(format!("unknown BTF type {}", type_id))
        })?;

        match ty {
            BtfType::Struct {
                size: struct_size,
                members,
                ..
            }
            | BtfType::Union {
                size: struct_size,
                members,
                ..
            } => {
                // Check bounds
                if offset + size > *struct_size {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "access at offset {} size {} exceeds struct size {}",
                        offset, size, struct_size
                    )));
                }

                // Find the member containing this offset
                let members = members.clone();
                for member in &members {
                    let member_offset = if member.bitfield {
                        member.offset / 8
                    } else {
                        member.offset
                    };
                    let member_size = self.types.type_size(member.type_id).unwrap_or(0);

                    if offset >= member_offset && offset < member_offset + member_size {
                        return Ok(AccessInfo {
                            field_type: member.type_id,
                            field_offset: offset - member_offset,
                            is_bitfield: member.bitfield,
                        });
                    }
                }

                // Access to padding or unknown area
                if is_write {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "write to padding/unknown field at offset {}",
                        offset
                    )));
                }
                Ok(AccessInfo {
                    field_type: 0,
                    field_offset: offset,
                    is_bitfield: false,
                })
            }
            BtfType::Array(arr) => {
                let elem_size = self.types.type_size(arr.elem_type).unwrap_or(0);
                if elem_size == 0 {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "array element size is zero".to_string(),
                    ));
                }
                let total_size = elem_size * arr.nelems;
                if offset + size > total_size {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "array access at offset {} size {} exceeds array size {}",
                        offset, size, total_size
                    )));
                }
                Ok(AccessInfo {
                    field_type: arr.elem_type,
                    field_offset: offset % elem_size,
                    is_bitfield: false,
                })
            }
            BtfType::Int {
                size: int_size, ..
            } => {
                if offset + size > *int_size {
                    return Err(VerifierError::InvalidMemoryAccess(format!(
                        "integer access at offset {} size {} exceeds int size {}",
                        offset, size, int_size
                    )));
                }
                Ok(AccessInfo {
                    field_type: type_id,
                    field_offset: offset,
                    is_bitfield: false,
                })
            }
            _ => {
                // For other types, just check basic bounds if we have size info
                if let Some(type_size) = self.types.type_size(type_id) {
                    if offset + size > type_size {
                        return Err(VerifierError::InvalidMemoryAccess(format!(
                            "access at offset {} size {} exceeds type size {}",
                            offset, size, type_size
                        )));
                    }
                }
                Ok(AccessInfo {
                    field_type: type_id,
                    field_offset: offset,
                    is_bitfield: false,
                })
            }
        }
    }

    /// Validate function call argument types.
    pub fn validate_func_args(
        &self,
        func_id: u32,
        arg_types: &[u32],
    ) -> Result<()> {
        let proto = match self.types.func_proto(func_id) {
            Some(BtfType::FuncProto { params, .. }) => params,
            _ => return Ok(()), // No prototype info, allow
        };

        if arg_types.len() != proto.len() {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "expected {} arguments, got {}",
                proto.len(),
                arg_types.len()
            )));
        }

        for (i, (expected, actual)) in proto.iter().zip(arg_types.iter()).enumerate() {
            if !self.types_compatible(expected.type_id, *actual) {
                return Err(VerifierError::InvalidFunctionCall(format!(
                    "argument {} type mismatch: expected BTF type {}, got {}",
                    i, expected.type_id, actual
                )));
            }
        }

        Ok(())
    }

    /// Check if two types are compatible.
    pub fn types_compatible(&self, expected: u32, actual: u32) -> bool {
        if expected == actual {
            return true;
        }

        let exp_resolved = self.types.resolve_type(expected);
        let act_resolved = self.types.resolve_type(actual);

        if exp_resolved == act_resolved {
            return true;
        }

        // Get the base types
        let exp_ty = match self.types.get(exp_resolved) {
            Some(t) => t,
            None => return false,
        };
        let act_ty = match self.types.get(act_resolved) {
            Some(t) => t,
            None => return false,
        };

        // Same kind compatibility
        match (exp_ty, act_ty) {
            // Integers of same size are compatible
            (
                BtfType::Int {
                    size: s1,
                    encoding: e1,
                    ..
                },
                BtfType::Int {
                    size: s2,
                    encoding: e2,
                    ..
                },
            ) => *s1 == *s2 && e1.is_signed == e2.is_signed,

            // Pointers - check if targets are compatible
            (BtfType::Ptr { target: t1 }, BtfType::Ptr { target: t2 }) => {
                // void* is compatible with any pointer
                let t1_resolved = self.types.resolve_type(*t1);
                let t2_resolved = self.types.resolve_type(*t2);
                matches!(self.types.get(t1_resolved), Some(BtfType::Void))
                    || matches!(self.types.get(t2_resolved), Some(BtfType::Void))
                    || self.types_compatible(*t1, *t2)
            }

            // Enums of same size
            (BtfType::Enum { size: s1, .. }, BtfType::Enum { size: s2, .. }) => s1 == s2,
            (BtfType::Enum64 { size: s1, .. }, BtfType::Enum64 { size: s2, .. }) => s1 == s2,

            // Enum and int of same size
            (BtfType::Enum { size, .. }, BtfType::Int { size: int_size, .. })
            | (BtfType::Int { size: int_size, .. }, BtfType::Enum { size, .. }) => size == int_size,

            _ => false,
        }
    }

    /// Validate return type matches expected.
    pub fn validate_return_type(&self, func_id: u32, actual: u32) -> Result<()> {
        let expected = match self.types.func_proto(func_id) {
            Some(BtfType::FuncProto { ret_type, .. }) => *ret_type,
            _ => return Ok(()), // No prototype info
        };

        if self.types_compatible(expected, actual) {
            Ok(())
        } else {
            Err(VerifierError::InvalidFunctionCall(format!(
                "return type mismatch: expected BTF type {}, got {}",
                expected, actual
            )))
        }
    }

    /// Get the expected argument types for a function.
    pub fn get_func_arg_types(&self, func_id: u32) -> Vec<u32> {
        match self.types.func_proto(func_id) {
            Some(BtfType::FuncProto { params, .. }) => {
                params.iter().map(|p| p.type_id).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Get the return type for a function.
    pub fn get_func_return_type(&self, func_id: u32) -> Option<u32> {
        match self.types.func_proto(func_id) {
            Some(BtfType::FuncProto { ret_type, .. }) => Some(*ret_type),
            _ => None,
        }
    }
}

/// Information about a validated access.
#[derive(Debug, Clone)]
pub struct AccessInfo {
    /// Type ID of the accessed field.
    pub field_type: u32,
    /// Offset within the field.
    pub field_offset: u32,
    /// Whether this is a bitfield access.
    pub is_bitfield: bool,
}

/// Create common kernel BTF types for testing.
pub fn create_kernel_btf() -> BtfTypes {
    let mut types = BtfTypes::new();

    // Add basic integer types
    types.add_type(BtfType::Int {
        name: "int".to_string(),
        size: 4,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 32,
        },
    });

    types.add_type(BtfType::Int {
        name: "unsigned int".to_string(),
        size: 4,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 32,
        },
    });

    types.add_type(BtfType::Int {
        name: "long".to_string(),
        size: 8,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 64,
        },
    });

    types.add_type(BtfType::Int {
        name: "unsigned long".to_string(),
        size: 8,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 64,
        },
    });

    types.add_type(BtfType::Int {
        name: "char".to_string(),
        size: 1,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: true,
            is_bool: false,
            offset: 0,
            bits: 8,
        },
    });

    types.add_type(BtfType::Int {
        name: "_Bool".to_string(),
        size: 1,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: true,
            offset: 0,
            bits: 8,
        },
    });

    // u8, u16, u32, u64
    types.add_type(BtfType::Int {
        name: "u8".to_string(),
        size: 1,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 8,
        },
    });

    types.add_type(BtfType::Int {
        name: "u16".to_string(),
        size: 2,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 16,
        },
    });

    types.add_type(BtfType::Int {
        name: "u32".to_string(),
        size: 4,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 32,
        },
    });

    types.add_type(BtfType::Int {
        name: "u64".to_string(),
        size: 8,
        encoding: BtfIntEncoding {
            is_signed: false,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 64,
        },
    });

    // s8, s16, s32, s64
    types.add_type(BtfType::Int {
        name: "s8".to_string(),
        size: 1,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 8,
        },
    });

    types.add_type(BtfType::Int {
        name: "s16".to_string(),
        size: 2,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 16,
        },
    });

    types.add_type(BtfType::Int {
        name: "s32".to_string(),
        size: 4,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 32,
        },
    });

    types.add_type(BtfType::Int {
        name: "s64".to_string(),
        size: 8,
        encoding: BtfIntEncoding {
            is_signed: true,
            is_char: false,
            is_bool: false,
            offset: 0,
            bits: 64,
        },
    });

    types
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btf_kind_from_u32() {
        assert_eq!(BtfKind::from(1), BtfKind::Int);
        assert_eq!(BtfKind::from(4), BtfKind::Struct);
        assert_eq!(BtfKind::from(13), BtfKind::FuncProto);
        assert_eq!(BtfKind::from(100), BtfKind::Unknown);
    }

    #[test]
    fn test_btf_int_encoding() {
        let enc = BtfIntEncoding::from_raw(0x20000001);
        assert!(enc.is_signed);
        assert!(!enc.is_char);
        assert!(!enc.is_bool);
        assert_eq!(enc.offset, 0);
        assert_eq!(enc.bits, 32);
    }

    #[test]
    fn test_btf_types_basic() {
        let mut types = BtfTypes::new();
        assert_eq!(types.len(), 1); // void

        let id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });
        assert_eq!(id, 1);
        assert_eq!(types.len(), 2);

        let ty = types.get(1).unwrap();
        assert_eq!(ty.kind(), BtfKind::Int);
        assert_eq!(ty.name(), Some("int"));
    }

    #[test]
    fn test_btf_type_size() {
        let types = create_kernel_btf();
        
        // Check integer sizes
        let int_ids = types.get_by_name("int");
        assert!(!int_ids.is_empty());
        assert_eq!(types.type_size(int_ids[0]), Some(4));

        let u64_ids = types.get_by_name("u64");
        assert!(!u64_ids.is_empty());
        assert_eq!(types.type_size(u64_ids[0]), Some(8));
    }

    #[test]
    fn test_btf_struct() {
        let mut types = BtfTypes::new();
        
        // Add u32 type
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        // Add struct
        let _struct_id = types.add_type(BtfType::Struct {
            name: "test_struct".to_string(),
            size: 12,
            members: vec![
                BtfMember {
                    name: "a".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "b".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
                BtfMember {
                    name: "c".to_string(),
                    type_id: u32_id,
                    offset: 8,
                    bitfield: false,
                },
            ],
        });

        let struct_ids = types.get_by_name("test_struct");
        assert_eq!(struct_ids.len(), 1);
        assert_eq!(types.type_size(struct_ids[0]), Some(12));
    }

    #[test]
    fn test_btf_find_member() {
        let mut types = BtfTypes::new();
        
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let struct_id = types.add_type(BtfType::Struct {
            name: "point".to_string(),
            size: 8,
            members: vec![
                BtfMember {
                    name: "x".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "y".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
            ],
        });

        let (offset, type_id) = types.find_member(struct_id, "x").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(type_id, u32_id);

        let (offset, type_id) = types.find_member(struct_id, "y").unwrap();
        assert_eq!(offset, 4);
        assert_eq!(type_id, u32_id);

        assert!(types.find_member(struct_id, "z").is_none());
    }

    #[test]
    fn test_btf_resolve_type() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let typedef_id = types.add_type(BtfType::Typedef {
            name: "my_int".to_string(),
            target: int_id,
        });

        let const_id = types.add_type(BtfType::Const { target: typedef_id });

        // Resolve through const -> typedef -> int
        assert_eq!(types.resolve_type(const_id), int_id);
        assert_eq!(types.resolve_type(typedef_id), int_id);
        assert_eq!(types.resolve_type(int_id), int_id);
    }

    #[test]
    fn test_btf_validator_access() {
        let mut types = BtfTypes::new();
        
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let struct_id = types.add_type(BtfType::Struct {
            name: "test".to_string(),
            size: 8,
            members: vec![
                BtfMember {
                    name: "a".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "b".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
            ],
        });

        let mut validator = BtfValidator::new(types);

        // Valid access to field a
        let info = validator.validate_access(struct_id, 0, 4, false).unwrap();
        assert_eq!(info.field_type, u32_id);
        assert_eq!(info.field_offset, 0);

        // Valid access to field b
        let info = validator.validate_access(struct_id, 4, 4, false).unwrap();
        assert_eq!(info.field_type, u32_id);
        assert_eq!(info.field_offset, 0);

        // Out of bounds access
        assert!(validator.validate_access(struct_id, 8, 4, false).is_err());
    }

    #[test]
    fn test_btf_types_compatible() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let s32_id = types.add_type(BtfType::Int {
            name: "s32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let validator = BtfValidator::new(types);

        // Same type
        assert!(validator.types_compatible(int_id, int_id));

        // Same size and signedness
        assert!(validator.types_compatible(int_id, s32_id));

        // Different signedness
        assert!(!validator.types_compatible(int_id, u32_id));
    }

    #[test]
    fn test_btf_func_proto() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let proto_id = types.add_type(BtfType::FuncProto {
            ret_type: int_id,
            params: vec![
                BtfParam {
                    name: "a".to_string(),
                    type_id: int_id,
                },
                BtfParam {
                    name: "b".to_string(),
                    type_id: int_id,
                },
            ],
        });

        let func_id = types.add_type(BtfType::Func {
            name: "add".to_string(),
            proto: proto_id,
            linkage: 0,
        });

        let validator = BtfValidator::new(types);

        let arg_types = validator.get_func_arg_types(func_id);
        assert_eq!(arg_types.len(), 2);
        assert_eq!(arg_types[0], int_id);
        assert_eq!(arg_types[1], int_id);

        let ret_type = validator.get_func_return_type(func_id);
        assert_eq!(ret_type, Some(int_id));
    }

    #[test]
    fn test_btf_pointer_types() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let ptr_id = types.add_type(BtfType::Ptr { target: int_id });
        let void_ptr_id = types.add_type(BtfType::Ptr { target: 0 }); // void*

        assert!(types.is_pointer(ptr_id));
        assert!(types.is_integer(int_id));
        assert!(!types.is_pointer(int_id));

        assert_eq!(types.ptr_target(ptr_id), Some(int_id));
        assert_eq!(types.ptr_target(void_ptr_id), Some(0));

        // Pointer size is 8 bytes (64-bit)
        assert_eq!(types.type_size(ptr_id), Some(8));
    }

    #[test]
    fn test_btf_array_access() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let arr_id = types.add_type(BtfType::Array(BtfArray {
            elem_type: int_id,
            index_type: int_id,
            nelems: 10,
        }));

        assert_eq!(types.type_size(arr_id), Some(40)); // 10 * 4 bytes

        let mut validator = BtfValidator::new(types);

        // Valid access
        let info = validator.validate_access(arr_id, 0, 4, false).unwrap();
        assert_eq!(info.field_type, int_id);

        // Access at element 5
        let info = validator.validate_access(arr_id, 20, 4, false).unwrap();
        assert_eq!(info.field_type, int_id);

        // Out of bounds
        assert!(validator.validate_access(arr_id, 40, 4, false).is_err());
    }

    #[test]
    fn test_create_kernel_btf() {
        let types = create_kernel_btf();
        
        // Should have common types
        assert!(!types.get_by_name("int").is_empty());
        assert!(!types.get_by_name("u32").is_empty());
        assert!(!types.get_by_name("u64").is_empty());
        assert!(!types.get_by_name("s32").is_empty());
        assert!(!types.get_by_name("char").is_empty());
        assert!(!types.get_by_name("_Bool").is_empty());
    }

    #[test]
    fn test_btf_validator_empty() {
        let mut validator = BtfValidator::empty();

        // Empty validator should allow all accesses
        let info = validator.validate_access(999, 100, 8, true).unwrap();
        assert_eq!(info.field_offset, 100);
    }

    // ========================================================================
    // Enum64 Tests
    // ========================================================================

    #[test]
    fn test_btf_enum64_basic() {
        let mut types = BtfTypes::new();

        // Add a 64-bit enum with large values
        let enum_id = types.add_type(BtfType::Enum64 {
            name: "large_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "VAL_MIN".to_string(),
                    val: i64::MIN,
                },
                BtfEnum64Value {
                    name: "VAL_NEG".to_string(),
                    val: -0x100000000i64,
                },
                BtfEnum64Value {
                    name: "VAL_ZERO".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "VAL_LARGE".to_string(),
                    val: 0x123456789ABCDEFi64,
                },
                BtfEnum64Value {
                    name: "VAL_MAX".to_string(),
                    val: i64::MAX,
                },
            ],
            is_signed: true,
        });

        let ty = types.get(enum_id).unwrap();
        assert_eq!(ty.kind(), BtfKind::Enum64);
        assert_eq!(ty.name(), Some("large_enum"));
        assert_eq!(types.type_size(enum_id), Some(8));
    }

    #[test]
    fn test_btf_enum64_unsigned() {
        let mut types = BtfTypes::new();

        // Unsigned 64-bit enum
        let enum_id = types.add_type(BtfType::Enum64 {
            name: "flags64".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "FLAG_NONE".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "FLAG_HIGH".to_string(),
                    val: 0x8000000000000000u64 as i64, // High bit set
                },
                BtfEnum64Value {
                    name: "FLAG_ALL".to_string(),
                    val: -1i64, // All bits set (0xFFFFFFFFFFFFFFFF)
                },
            ],
            is_signed: false,
        });

        let ty = types.get(enum_id).unwrap();
        assert_eq!(ty.kind(), BtfKind::Enum64);
        
        if let BtfType::Enum64 { is_signed, .. } = ty {
            assert!(!is_signed);
        } else {
            panic!("Expected Enum64 type");
        }
    }

    #[test]
    fn test_btf_enum64_kind_conversion() {
        // Test that kind 19 maps to Enum64
        assert_eq!(BtfKind::from(19), BtfKind::Enum64);
    }

    #[test]
    fn test_btf_enum_vs_enum64_size() {
        let mut types = BtfTypes::new();

        // 32-bit enum
        let enum32_id = types.add_type(BtfType::Enum {
            name: "small_enum".to_string(),
            size: 4,
            values: vec![
                BtfEnumValue {
                    name: "A".to_string(),
                    val: 0,
                },
                BtfEnumValue {
                    name: "B".to_string(),
                    val: i32::MAX,
                },
            ],
            is_signed: true,
        });

        // 64-bit enum
        let enum64_id = types.add_type(BtfType::Enum64 {
            name: "big_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "X".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "Y".to_string(),
                    val: i64::MAX,
                },
            ],
            is_signed: true,
        });

        // Verify sizes
        assert_eq!(types.type_size(enum32_id), Some(4));
        assert_eq!(types.type_size(enum64_id), Some(8));

        // Verify kinds
        assert_eq!(types.get(enum32_id).unwrap().kind(), BtfKind::Enum);
        assert_eq!(types.get(enum64_id).unwrap().kind(), BtfKind::Enum64);
    }

    #[test]
    fn test_btf_enum64_compatibility() {
        let mut types = BtfTypes::new();

        // Two Enum64 types with same size should be compatible
        let enum1_id = types.add_type(BtfType::Enum64 {
            name: "enum_a".to_string(),
            size: 8,
            values: vec![BtfEnum64Value {
                name: "VAL".to_string(),
                val: 1,
            }],
            is_signed: true,
        });

        let enum2_id = types.add_type(BtfType::Enum64 {
            name: "enum_b".to_string(),
            size: 8,
            values: vec![BtfEnum64Value {
                name: "OTHER".to_string(),
                val: 2,
            }],
            is_signed: true,
        });

        // Both should have same size
        assert_eq!(types.type_size(enum1_id), types.type_size(enum2_id));
    }

    #[test]
    fn test_btf_enum64_value_lookup() {
        let mut types = BtfTypes::new();

        let enum_id = types.add_type(BtfType::Enum64 {
            name: "test_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "FIRST".to_string(),
                    val: 100,
                },
                BtfEnum64Value {
                    name: "SECOND".to_string(),
                    val: 0x100000000i64,
                },
                BtfEnum64Value {
                    name: "THIRD".to_string(),
                    val: -500,
                },
            ],
            is_signed: true,
        });

        let ty = types.get(enum_id).unwrap();
        if let BtfType::Enum64 { values, .. } = ty {
            assert_eq!(values.len(), 3);
            assert_eq!(values[0].name, "FIRST");
            assert_eq!(values[0].val, 100);
            assert_eq!(values[1].name, "SECOND");
            assert_eq!(values[1].val, 0x100000000i64);
            assert_eq!(values[2].name, "THIRD");
            assert_eq!(values[2].val, -500);
        } else {
            panic!("Expected Enum64 type");
        }
    }
}
