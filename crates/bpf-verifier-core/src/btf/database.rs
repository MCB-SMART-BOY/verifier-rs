// SPDX-License-Identifier: GPL-2.0

//! BTF（BPF 类型格式）支持模块
//!
//! BTF (BPF Type Format) support module.
//!
//! 本模块为验证器提供基本的 BTF 类型处理。BTF 用于类型安全的内存访问和调试。
//!
//! This module provides basic BTF type handling for the verifier.
//! BTF is used for type-safe memory access and debugging.
//!
//! # BTF 类型种类 / BTF Type Kinds
//!
//! - `Int/Float`: 整数/浮点类型 / Integer/float types
//! - `Ptr`: 指针类型 / Pointer type
//! - `Array`: 数组类型 / Array type
//! - `Struct/Union`: 结构体/联合体 / Struct/union
//! - `Func/FuncProto`: 函数/函数原型 / Function/prototype

#![allow(missing_docs)] // BTF types have complex internal structure

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Maximum depth for type resolution to prevent infinite loops in typedef chains
pub const MAX_RESOLVE_DEPTH: usize = 32;

use alloc::collections::BTreeMap as HashMap;

/// BTF type kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BtfKind {
    #[default]
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

/// BTF integer encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BtfIntEncoding {
    pub encoding: u8,
    pub offset: u8,
    pub bits: u8,
}

impl BtfIntEncoding {
    pub const SIGNED: u8 = 1 << 0;
    pub const CHAR: u8 = 1 << 1;
    pub const BOOL: u8 = 1 << 2;

    pub fn is_signed(&self) -> bool {
        self.encoding & Self::SIGNED != 0
    }
}

/// A BTF type
#[derive(Debug, Clone)]
pub struct BtfType {
    /// Type ID
    pub id: u32,
    /// Type kind
    pub kind: BtfKind,
    /// Type name (if any)
    pub name: Option<String>,
    /// Size in bytes (for sized types)
    pub size: u32,
    /// Reference to another type (for ptr, typedef, etc.)
    pub type_ref: u32,
    /// Integer encoding (for int types)
    pub int_encoding: Option<BtfIntEncoding>,
    /// Struct/union members
    pub members: Vec<BtfMember>,
    /// Function parameters
    pub params: Vec<BtfParam>,
    /// Array dimensions
    pub array_info: Option<BtfArray>,
}

impl Default for BtfType {
    fn default() -> Self {
        Self {
            id: 0,
            kind: BtfKind::Unknown,
            name: None,
            size: 0,
            type_ref: 0,
            int_encoding: None,
            members: Vec::new(),
            params: Vec::new(),
            array_info: None,
        }
    }
}

/// BTF struct/union member
#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name: Option<String>,
    pub type_id: u32,
    pub offset: u32, // in bits
}

/// BTF function parameter
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct BtfParam {
    pub name: Option<String>,
    pub type_id: u32,
}

/// BTF array info
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct BtfArray {
    pub elem_type: u32,
    pub index_type: u32,
    pub nelems: u32,
}

/// BTF type database
#[derive(Debug, Default)]
pub struct Btf {
    /// All types by ID
    types: HashMap<u32, BtfType>,
    /// Types by name (for lookup)
    by_name: HashMap<String, Vec<u32>>,
    /// Next type ID to assign
    next_id: u32,
    /// String table for BTF
    string_table: BtfStringTable,
}

/// BTF String Table
///
/// The string table stores all strings used in BTF types.
/// Strings are stored contiguously with null terminators.
/// Offset 0 always points to an empty string.
#[derive(Debug, Clone, Default)]
pub struct BtfStringTable {
    /// Raw string data (null-terminated strings)
    data: Vec<u8>,
    /// Offset index for deduplication (string -> offset)
    index: HashMap<String, u32>,
}

impl BtfStringTable {
    /// Create a new string table with initial empty string
    pub fn new() -> Self {
        let mut table = Self {
            data: Vec::new(),
            index: HashMap::new(),
        };
        // Offset 0 is always the empty string
        table.data.push(0);
        table.index.insert(String::new(), 0);
        table
    }

    /// Add a string to the table and return its offset
    ///
    /// If the string already exists, returns the existing offset (deduplication)
    pub fn add(&mut self, s: &str) -> u32 {
        // Check for existing string
        if let Some(&offset) = self.index.get(s) {
            return offset;
        }

        // Add new string
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0); // null terminator
        self.index.insert(s.to_string(), offset);
        offset
    }

    /// Get a string by offset
    pub fn get(&self, offset: u32) -> Option<&str> {
        let start = offset as usize;
        if start >= self.data.len() {
            return None;
        }

        // Find null terminator
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| start + pos)?;

        // Convert to str
        core::str::from_utf8(&self.data[start..end]).ok()
    }

    /// Get the total size of the string table
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string table is empty (only contains empty string)
    pub fn is_empty(&self) -> bool {
        self.data.len() <= 1
    }

    /// Get raw data for serialization
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Create from raw bytes (for parsing)
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut index = HashMap::new();
        let mut offset = 0u32;

        while (offset as usize) < data.len() {
            let start = offset as usize;
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| start + pos)
                .unwrap_or(data.len());

            if let Ok(s) = core::str::from_utf8(&data[start..end]) {
                index.insert(s.to_string(), offset);
            }

            offset = (end + 1) as u32; // skip past null terminator
        }

        Self { data, index }
    }
}

impl Btf {
    pub fn new() -> Self {
        let mut btf = Self {
            types: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 1, // ID 0 is void
            string_table: BtfStringTable::new(),
        };

        // Add void type
        btf.types.insert(
            0,
            BtfType {
                id: 0,
                kind: BtfKind::Unknown,
                name: Some("void".into()),
                ..Default::default()
            },
        );

        btf
    }

    /// Add a type to the BTF
    pub fn add_type(&mut self, mut ty: BtfType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        ty.id = id;

        if let Some(ref name) = ty.name {
            self.by_name.entry(name.clone()).or_default().push(id);
        }

        self.types.insert(id, ty);
        id
    }

    /// Get a type by ID
    pub fn get_type(&self, id: u32) -> Option<&BtfType> {
        self.types.get(&id)
    }

    /// Find types by name
    pub fn find_by_name(&self, name: &str) -> &[u32] {
        self.by_name.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Resolve a type through modifiers (const, volatile, typedef, etc.)
    pub fn resolve_type(&self, id: u32) -> Option<&BtfType> {
        let mut current = id;
        let mut depth = 0;

        while depth < MAX_RESOLVE_DEPTH {
            let ty = self.types.get(&current)?;
            match ty.kind {
                BtfKind::Typedef
                | BtfKind::Volatile
                | BtfKind::Const
                | BtfKind::Restrict
                | BtfKind::TypeTag => {
                    current = ty.type_ref;
                    depth += 1;
                }
                _ => return Some(ty),
            }
        }
        None // Too deep, probably a cycle
    }

    /// Get the size of a type
    pub fn type_size(&self, id: u32) -> Option<u32> {
        let ty = self.resolve_type(id)?;
        match ty.kind {
            BtfKind::Int
            | BtfKind::Struct
            | BtfKind::Union
            | BtfKind::Enum
            | BtfKind::Float
            | BtfKind::Enum64 => Some(ty.size),
            BtfKind::Ptr => Some(8), // 64-bit pointers
            BtfKind::Array => {
                let arr = ty.array_info.as_ref()?;
                let elem_size = self.type_size(arr.elem_type)?;
                Some(elem_size * arr.nelems)
            }
            _ => None,
        }
    }

    /// Check if a type is a pointer
    pub fn is_ptr(&self, id: u32) -> bool {
        self.resolve_type(id)
            .map(|t| t.kind == BtfKind::Ptr)
            .unwrap_or(false)
    }

    /// Check if a type is an integer
    pub fn is_int(&self, id: u32) -> bool {
        self.resolve_type(id)
            .map(|t| t.kind == BtfKind::Int)
            .unwrap_or(false)
    }

    /// Check if a type is a struct
    pub fn is_struct(&self, id: u32) -> bool {
        self.resolve_type(id)
            .map(|t| t.kind == BtfKind::Struct)
            .unwrap_or(false)
    }

    /// Get the pointee type for a pointer
    pub fn ptr_target(&self, id: u32) -> Option<u32> {
        let ty = self.resolve_type(id)?;
        if ty.kind == BtfKind::Ptr {
            Some(ty.type_ref)
        } else {
            None
        }
    }

    /// Find a member in a struct/union by name
    pub fn find_member(&self, struct_id: u32, name: &str) -> Option<&BtfMember> {
        let ty = self.resolve_type(struct_id)?;
        if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
            return None;
        }
        ty.members.iter().find(|m| m.name.as_deref() == Some(name))
    }

    /// Find a member in a struct/union by offset
    pub fn find_member_at_offset(&self, struct_id: u32, bit_offset: u32) -> Option<&BtfMember> {
        let ty = self.resolve_type(struct_id)?;
        if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
            return None;
        }
        ty.members.iter().find(|m| m.offset == bit_offset)
    }

    /// Add common kernel types
    pub fn add_kernel_types(&mut self) {
        // Add basic integer types
        self.add_int_type("u8", 1, false);
        self.add_int_type("u16", 2, false);
        self.add_int_type("u32", 4, false);
        self.add_int_type("u64", 8, false);
        self.add_int_type("s8", 1, true);
        self.add_int_type("s16", 2, true);
        self.add_int_type("s32", 4, true);
        self.add_int_type("s64", 8, true);
        self.add_int_type("char", 1, true);
        self.add_int_type("int", 4, true);
        self.add_int_type("long", 8, true);
        self.add_int_type("unsigned int", 4, false);
        self.add_int_type("unsigned long", 8, false);
    }

    // ========================================================================
    // String Table Methods
    // ========================================================================

    /// Get a string from the string table by offset
    pub fn get_string(&self, offset: u32) -> Option<&str> {
        self.string_table.get(offset)
    }

    /// Add a string to the string table and return its offset
    pub fn add_string(&mut self, s: &str) -> u32 {
        self.string_table.add(s)
    }

    /// Get the string table for serialization
    pub fn string_table_bytes(&self) -> &[u8] {
        self.string_table.as_bytes()
    }

    /// Get string table size
    pub fn string_table_len(&self) -> usize {
        self.string_table.len()
    }

    fn add_int_type(&mut self, name: &str, size: u32, signed: bool) -> u32 {
        self.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some(name.into()),
            size,
            int_encoding: Some(BtfIntEncoding {
                encoding: if signed { BtfIntEncoding::SIGNED } else { 0 },
                offset: 0,
                bits: (size * 8) as u8,
            }),
            ..Default::default()
        })
    }
}

/// BTF-based field access info
#[derive(Debug, Clone)]
pub struct BtfFieldAccess {
    /// Type being accessed
    pub type_id: u32,
    /// Offset from base (bytes)
    pub offset: u32,
    /// Size of access (bytes)
    pub size: u32,
    /// Type of the field
    pub field_type: u32,
    /// Whether field is a pointer
    pub is_ptr: bool,
    /// Whether access is read-only
    pub rdonly: bool,
}

/// Check if BTF access is valid
pub fn check_btf_access(btf: &Btf, type_id: u32, offset: i32, size: u32) -> Option<BtfFieldAccess> {
    if offset < 0 {
        return None;
    }
    let offset = offset as u32;

    let ty = btf.resolve_type(type_id)?;

    // Check bounds
    if ty.kind == BtfKind::Struct || ty.kind == BtfKind::Union {
        if offset + size > ty.size {
            return None;
        }

        // Find the field at this offset
        let bit_offset = offset * 8;
        if let Some(member) = btf.find_member_at_offset(type_id, bit_offset) {
            let field_type = btf.resolve_type(member.type_id)?;
            return Some(BtfFieldAccess {
                type_id,
                offset,
                size,
                field_type: member.type_id,
                is_ptr: field_type.kind == BtfKind::Ptr,
                rdonly: false,
            });
        }

        // Allow access even without exact field match for raw access
        return Some(BtfFieldAccess {
            type_id,
            offset,
            size,
            field_type: 0,
            is_ptr: false,
            rdonly: false,
        });
    }

    None
}

/// BTF function prototype
#[derive(Debug, Clone)]
pub struct BtfFuncProto {
    /// Function type ID
    pub type_id: u32,
    /// Return type ID  
    pub ret_type: u32,
    /// Parameter types
    pub params: Vec<(Option<String>, u32)>,
}

impl Btf {
    /// Get function prototype
    pub fn get_func_proto(&self, func_id: u32) -> Option<BtfFuncProto> {
        let func = self.get_type(func_id)?;
        if func.kind != BtfKind::Func {
            return None;
        }

        let proto = self.get_type(func.type_ref)?;
        if proto.kind != BtfKind::FuncProto {
            return None;
        }

        Some(BtfFuncProto {
            type_id: func_id,
            ret_type: proto.type_ref,
            params: proto
                .params
                .iter()
                .map(|p| (p.name.clone(), p.type_id))
                .collect(),
        })
    }
}

/// Result of BTF type compatibility check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtfTypeCompat {
    /// Types are exactly compatible
    Exact,
    /// Types are compatible with implicit conversion
    Compatible,
    /// Types are incompatible
    Incompatible,
}

/// Check if two BTF types are compatible for assignment/argument passing
pub fn check_type_compat(btf: &Btf, src_id: u32, dst_id: u32) -> BtfTypeCompat {
    // Resolve through modifiers
    let src = match btf.resolve_type(src_id) {
        Some(t) => t,
        None => return BtfTypeCompat::Incompatible,
    };
    let dst = match btf.resolve_type(dst_id) {
        Some(t) => t,
        None => return BtfTypeCompat::Incompatible,
    };

    // Same type
    if src.id == dst.id {
        return BtfTypeCompat::Exact;
    }

    // Same kind checks
    if src.kind == dst.kind {
        match src.kind {
            BtfKind::Int => {
                // Integers of same size are compatible
                if src.size == dst.size {
                    return BtfTypeCompat::Compatible;
                }
            }
            BtfKind::Ptr => {
                // void* is compatible with any pointer
                let src_target = btf.resolve_type(src.type_ref);
                let dst_target = btf.resolve_type(dst.type_ref);

                if let (Some(s), Some(d)) = (src_target, dst_target) {
                    // void* accepts any pointer
                    if s.kind == BtfKind::Unknown || d.kind == BtfKind::Unknown {
                        return BtfTypeCompat::Compatible;
                    }
                    // Same struct/union
                    if s.kind == d.kind && s.name == d.name {
                        return BtfTypeCompat::Exact;
                    }
                }
            }
            BtfKind::Struct | BtfKind::Union => {
                // Same name means compatible
                if src.name == dst.name {
                    return BtfTypeCompat::Exact;
                }
            }
            _ => {}
        }
    }

    // int <-> ptr not allowed in strict mode but allowed in some cases
    // For now, mark as incompatible
    BtfTypeCompat::Incompatible
}

/// BTF verification result for a function call
#[derive(Debug, Clone)]
pub struct BtfCallVerify {
    /// Whether call is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Return type (for valid calls)
    pub ret_type: Option<u32>,
}

/// Verify a kfunc call against BTF
pub fn verify_kfunc_call(btf: &Btf, func_name: &str, arg_types: &[u32]) -> BtfCallVerify {
    // Find function by name
    let func_ids = btf.find_by_name(func_name);
    if func_ids.is_empty() {
        return BtfCallVerify {
            valid: false,
            error: Some(format!("kfunc '{}' not found in BTF", func_name)),
            ret_type: None,
        };
    }

    // Get function prototype
    let func_id = func_ids[0];
    let proto = match btf.get_func_proto(func_id) {
        Some(p) => p,
        None => {
            return BtfCallVerify {
                valid: false,
                error: Some(format!("'{}' is not a function", func_name)),
                ret_type: None,
            };
        }
    };

    // Check argument count
    if arg_types.len() != proto.params.len() {
        return BtfCallVerify {
            valid: false,
            error: Some(format!(
                "kfunc '{}' expects {} args, got {}",
                func_name,
                proto.params.len(),
                arg_types.len()
            )),
            ret_type: None,
        };
    }

    // Check each argument type
    for (i, ((_name, expected_type), actual_type)) in
        proto.params.iter().zip(arg_types.iter()).enumerate()
    {
        let compat = check_type_compat(btf, *actual_type, *expected_type);
        if compat == BtfTypeCompat::Incompatible {
            return BtfCallVerify {
                valid: false,
                error: Some(format!("kfunc '{}' arg {} type mismatch", func_name, i)),
                ret_type: None,
            };
        }
    }

    BtfCallVerify {
        valid: true,
        error: None,
        ret_type: Some(proto.ret_type),
    }
}

/// Check if a type is a trusted pointer (for kfunc safety)
pub fn is_trusted_ptr(btf: &Btf, type_id: u32) -> bool {
    let ty = match btf.resolve_type(type_id) {
        Some(t) => t,
        None => return false,
    };

    if ty.kind != BtfKind::Ptr {
        return false;
    }

    // Check if pointee is a known kernel type
    let target = match btf.resolve_type(ty.type_ref) {
        Some(t) => t,
        None => return false,
    };

    // Trusted types are structs with known kernel names
    if target.kind == BtfKind::Struct {
        if let Some(ref name) = target.name {
            // Common trusted kernel types
            return matches!(
                name.as_str(),
                "task_struct"
                    | "file"
                    | "inode"
                    | "socket"
                    | "sock"
                    | "sk_buff"
                    | "net_device"
                    | "bpf_map"
                    | "bpf_prog"
                    | "cgroup"
                    | "pid"
                    | "user_namespace"
                    | "net"
            );
        }
    }

    false
}

/// Check if type can be acquired (has refcount)
pub fn type_may_be_acquired(btf: &Btf, type_id: u32) -> bool {
    let ty = match btf.resolve_type(type_id) {
        Some(t) => t,
        None => return false,
    };

    if ty.kind != BtfKind::Ptr {
        return false;
    }

    let target = match btf.resolve_type(ty.type_ref) {
        Some(t) => t,
        None => return false,
    };

    // Types that may be acquired (have reference counting)
    if target.kind == BtfKind::Struct {
        if let Some(ref name) = target.name {
            return matches!(
                name.as_str(),
                "task_struct"
                    | "cgroup"
                    | "file"
                    | "sock"
                    | "socket"
                    | "bpf_rb_node"
                    | "bpf_list_node"
                    | "bpf_refcount"
            );
        }
    }

    false
}

/// Check if type is a dynptr
pub fn is_dynptr_type(btf: &Btf, type_id: u32) -> bool {
    let ty = match btf.resolve_type(type_id) {
        Some(t) => t,
        None => return false,
    };

    if ty.kind == BtfKind::Struct {
        if let Some(ref name) = ty.name {
            return name == "bpf_dynptr";
        }
    }

    false
}

/// Validate BTF struct access with field matching
pub fn validate_struct_access(
    btf: &Btf,
    struct_id: u32,
    offset: u32,
    size: u32,
    write: bool,
) -> Result<BtfFieldAccess, String> {
    let ty = btf
        .resolve_type(struct_id)
        .ok_or_else(|| "type not found".to_string())?;

    if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
        return Err("not a struct or union".to_string());
    }

    // Bounds check
    if offset + size > ty.size {
        return Err(format!(
            "access at offset {} size {} exceeds struct size {}",
            offset, size, ty.size
        ));
    }

    // Find matching member
    let bit_offset = offset * 8;
    let member = ty.members.iter().find(|m| m.offset == bit_offset);

    if let Some(member) = member {
        let field_ty = btf.resolve_type(member.type_id);
        let is_ptr = field_ty.map(|t| t.kind == BtfKind::Ptr).unwrap_or(false);

        // Check write access to read-only fields (future: use BTF tags)
        let rdonly = false; // Would check decl_tag for __attribute__((btf_rdonly))

        if write && rdonly {
            return Err("write to read-only field".to_string());
        }

        Ok(BtfFieldAccess {
            type_id: struct_id,
            offset,
            size,
            field_type: member.type_id,
            is_ptr,
            rdonly,
        })
    } else {
        // Allow raw access without exact field match
        Ok(BtfFieldAccess {
            type_id: struct_id,
            offset,
            size,
            field_type: 0,
            is_ptr: false,
            rdonly: false,
        })
    }
}

/// Bitfield information for struct members
#[derive(Debug, Clone, Default)]
pub struct BitfieldInfo {
    /// Offset in bits from the start of the containing storage unit
    pub bit_offset: u32,
    /// Size in bits
    pub bit_size: u32,
}

/// Compute bitfield offset for a struct member
pub fn compute_bitfield_offset(member: &BtfMember, btf: &Btf) -> Option<BitfieldInfo> {
    // BTF encodes bitfield info in the offset field
    // For bitfields: offset = (bit_offset << 24) | bit_size
    // Check if this is a bitfield by examining the member type size
    let member_type = btf.resolve_type(member.type_id)?;

    if member_type.kind == BtfKind::Int {
        if let Some(encoding) = &member_type.int_encoding {
            // Check if bits < size * 8, indicating a bitfield
            let type_bits = member_type.size * 8;
            if (encoding.bits as u32) < type_bits {
                return Some(BitfieldInfo {
                    bit_offset: member.offset,
                    bit_size: encoding.bits as u32,
                });
            }
        }
    }

    None
}

/// Validate bitfield access
pub fn validate_bitfield_access(
    btf: &Btf,
    struct_id: u32,
    bit_offset: u32,
    bit_size: u32,
) -> Result<(), String> {
    let ty = btf
        .resolve_type(struct_id)
        .ok_or_else(|| "type not found".to_string())?;

    if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
        return Err("not a struct or union".to_string());
    }

    // Find the member containing this bitfield
    for member in &ty.members {
        if let Some(bf) = compute_bitfield_offset(member, btf) {
            if bf.bit_offset == bit_offset && bf.bit_size == bit_size {
                return Ok(());
            }
        }
    }

    // Check bounds
    let struct_bits = ty.size * 8;
    if bit_offset + bit_size > struct_bits {
        return Err(format!(
            "bitfield access at bit {} size {} exceeds struct size {} bits",
            bit_offset, bit_size, struct_bits
        ));
    }

    Ok(())
}

/// Forward reference resolution state
#[derive(Debug, Clone, Default)]
pub struct ForwardRefState {
    /// Pending forward references (name -> list of type IDs waiting)
    pending: HashMap<String, Vec<u32>>,
    /// Resolved forward references (fwd type ID -> resolved type ID)
    resolved: HashMap<u32, u32>,
}

impl ForwardRefState {
    /// Create new forward reference state
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a forward reference
    pub fn add_forward_ref(&mut self, name: &str, fwd_id: u32) {
        self.pending
            .entry(name.to_string())
            .or_default()
            .push(fwd_id);
    }

    /// Resolve a forward reference
    pub fn resolve(&mut self, name: &str, resolved_id: u32) {
        if let Some(fwd_ids) = self.pending.remove(name) {
            for fwd_id in fwd_ids {
                self.resolved.insert(fwd_id, resolved_id);
            }
        }
    }

    /// Get resolved type for a forward reference
    pub fn get_resolved(&self, fwd_id: u32) -> Option<u32> {
        self.resolved.get(&fwd_id).copied()
    }

    /// Check if there are unresolved forward references
    pub fn has_unresolved(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get all unresolved forward reference names
    pub fn unresolved_names(&self) -> Vec<&str> {
        self.pending.keys().map(|s| s.as_str()).collect()
    }
}

impl Btf {
    /// Resolve a type including forward references
    pub fn resolve_type_with_fwd(&self, id: u32, fwd_state: &ForwardRefState) -> Option<&BtfType> {
        let ty = self.get_type(id)?;

        if ty.kind == BtfKind::Fwd {
            // Check if forward reference is resolved
            if let Some(resolved_id) = fwd_state.get_resolved(id) {
                return self.get_type(resolved_id);
            }
        }

        // Normal resolution through modifiers
        self.resolve_type(id)
    }

    /// Check type compatibility with forward reference support
    pub fn types_compatible_fwd(
        &self,
        src_id: u32,
        dst_id: u32,
        fwd_state: &ForwardRefState,
    ) -> bool {
        let src = match self.resolve_type_with_fwd(src_id, fwd_state) {
            Some(t) => t,
            None => return false,
        };
        let dst = match self.resolve_type_with_fwd(dst_id, fwd_state) {
            Some(t) => t,
            None => return false,
        };

        // Same type
        if src.id == dst.id {
            return true;
        }

        // Check forward reference compatibility
        if src.kind == BtfKind::Fwd || dst.kind == BtfKind::Fwd {
            // Forward references are compatible with matching names
            if src.name == dst.name && src.name.is_some() {
                return true;
            }
        }

        // Same kind and name
        if src.kind == dst.kind && src.name == dst.name {
            return true;
        }

        false
    }
}

/// Enum64 value representation
#[derive(Debug, Clone)]
pub struct Enum64Value {
    /// Enum member name
    pub name: String,
    /// Low 32 bits of value
    pub val_lo32: u32,
    /// High 32 bits of value
    pub val_hi32: u32,
}

impl Enum64Value {
    /// Get full 64-bit value
    pub fn value(&self) -> i64 {
        ((self.val_hi32 as i64) << 32) | (self.val_lo32 as i64)
    }

    /// Get unsigned 64-bit value
    pub fn uvalue(&self) -> u64 {
        ((self.val_hi32 as u64) << 32) | (self.val_lo32 as u64)
    }
}

/// Extended BTF type with Enum64 support
#[derive(Debug, Clone, Default)]
pub struct BtfTypeExt {
    /// Base BTF type
    pub base: BtfType,
    /// Enum64 values (if kind is Enum64)
    pub enum64_values: Vec<Enum64Value>,
    /// Variable linkage (if kind is Var)
    pub var_linkage: VarLinkage,
    /// Data section variables (if kind is DataSec)
    pub datasec_vars: Vec<DataSecVar>,
    /// Declaration tag info (if kind is DeclTag)
    pub decl_tag: Option<DeclTagInfo>,
}

/// Variable linkage type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum VarLinkage {
    #[default]
    Static = 0,
    Global = 1,
    Extern = 2,
}

/// Data section variable info
#[derive(Debug, Clone)]
pub struct DataSecVar {
    /// Type ID of the variable
    pub type_id: u32,
    /// Offset within section
    pub offset: u32,
    /// Size in bytes
    pub size: u32,
}

/// Declaration tag info
#[derive(Debug, Clone)]
pub struct DeclTagInfo {
    /// Type/member being tagged
    pub target_type_id: u32,
    /// Component index (-1 for type, >= 0 for member)
    pub component_idx: i32,
    /// Tag string
    pub tag: String,
}

// ============================================================================
// Declaration Tag (DeclTag) Permission Extraction
// ============================================================================

/// Known BTF declaration tags for permissions
pub mod decl_tags {
    /// Read-only field/type marker
    pub const BTF_RDONLY: &str = "btf_rdonly";
    /// Trusted pointer marker
    pub const BTF_TRUSTED: &str = "btf_trusted";
    /// RCU-protected pointer marker
    pub const BTF_RCU: &str = "rcu";
    /// Percpu pointer marker
    pub const BTF_PERCPU: &str = "percpu";
    /// Nullable pointer marker
    pub const BTF_NULLABLE: &str = "nullable";
    /// User pointer marker
    pub const BTF_USER: &str = "user";
    /// Arena pointer marker
    pub const BTF_ARENA: &str = "arena";
}

/// Permissions extracted from DeclTags
#[derive(Debug, Clone, Default)]
pub struct BtfPermissions {
    /// Field/type is read-only
    pub rdonly: bool,
    /// Pointer is trusted
    pub trusted: bool,
    /// Pointer is RCU-protected
    pub rcu: bool,
    /// Pointer is percpu
    pub percpu: bool,
    /// Pointer may be null
    pub nullable: bool,
    /// Pointer is to user memory
    pub user: bool,
    /// Pointer is to arena memory
    pub arena: bool,
}

impl BtfPermissions {
    /// Parse a DeclTag string into permissions
    pub fn from_tag(tag: &str) -> Self {
        let mut perms = Self::default();
        match tag {
            decl_tags::BTF_RDONLY => perms.rdonly = true,
            decl_tags::BTF_TRUSTED => perms.trusted = true,
            decl_tags::BTF_RCU => perms.rcu = true,
            decl_tags::BTF_PERCPU => perms.percpu = true,
            decl_tags::BTF_NULLABLE => perms.nullable = true,
            decl_tags::BTF_USER => perms.user = true,
            decl_tags::BTF_ARENA => perms.arena = true,
            _ => {}
        }
        perms
    }

    /// Merge another permission set into this one
    pub fn merge(&mut self, other: &BtfPermissions) {
        self.rdonly |= other.rdonly;
        self.trusted |= other.trusted;
        self.rcu |= other.rcu;
        self.percpu |= other.percpu;
        self.nullable |= other.nullable;
        self.user |= other.user;
        self.arena |= other.arena;
    }
}

/// DeclTag storage in BTF
#[derive(Debug, Default)]
pub struct DeclTagStore {
    /// Tags by target type ID
    type_tags: HashMap<u32, Vec<DeclTagInfo>>,
    /// Tags by (type_id, member_index)
    member_tags: HashMap<(u32, i32), Vec<DeclTagInfo>>,
}

impl DeclTagStore {
    /// Create a new DeclTag store
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a declaration tag
    pub fn add_tag(&mut self, tag: DeclTagInfo) {
        if tag.component_idx < 0 {
            // Type-level tag
            self.type_tags
                .entry(tag.target_type_id)
                .or_default()
                .push(tag);
        } else {
            // Member-level tag
            self.member_tags
                .entry((tag.target_type_id, tag.component_idx))
                .or_default()
                .push(tag);
        }
    }

    /// Get permissions for a type
    pub fn get_type_permissions(&self, type_id: u32) -> BtfPermissions {
        let mut perms = BtfPermissions::default();
        if let Some(tags) = self.type_tags.get(&type_id) {
            for tag in tags {
                perms.merge(&BtfPermissions::from_tag(&tag.tag));
            }
        }
        perms
    }

    /// Get permissions for a struct/union member
    pub fn get_member_permissions(&self, type_id: u32, member_idx: i32) -> BtfPermissions {
        let mut perms = BtfPermissions::default();
        if let Some(tags) = self.member_tags.get(&(type_id, member_idx)) {
            for tag in tags {
                perms.merge(&BtfPermissions::from_tag(&tag.tag));
            }
        }
        perms
    }

    /// Check if a member has a specific tag
    pub fn member_has_tag(&self, type_id: u32, member_idx: i32, tag_name: &str) -> bool {
        if let Some(tags) = self.member_tags.get(&(type_id, member_idx)) {
            return tags.iter().any(|t| t.tag == tag_name);
        }
        false
    }

    /// Check if a type has a specific tag
    pub fn type_has_tag(&self, type_id: u32, tag_name: &str) -> bool {
        if let Some(tags) = self.type_tags.get(&type_id) {
            return tags.iter().any(|t| t.tag == tag_name);
        }
        false
    }
}

/// Validate enum value is within range
pub fn validate_enum_value(btf: &Btf, enum_id: u32, value: i64) -> Result<(), String> {
    let ty = btf
        .resolve_type(enum_id)
        .ok_or_else(|| "enum type not found".to_string())?;

    if ty.kind != BtfKind::Enum && ty.kind != BtfKind::Enum64 {
        return Err("not an enum type".to_string());
    }

    // For regular enum (32-bit signed)
    if ty.kind == BtfKind::Enum
        && (value < i64::from(i32::MIN) || value > i64::from(i32::MAX))
    {
        return Err(format!("value {} out of range for 32-bit enum", value));
    }

    Ok(())
}

/// Check if a type is a variable-length struct (last member is flexible array)
pub fn is_variable_length_struct(btf: &Btf, struct_id: u32) -> bool {
    let ty = match btf.resolve_type(struct_id) {
        Some(t) => t,
        None => return false,
    };

    if ty.kind != BtfKind::Struct {
        return false;
    }

    // Check if last member is an array with 0 or 1 elements
    if let Some(last_member) = ty.members.last() {
        if let Some(member_type) = btf.resolve_type(last_member.type_id) {
            if member_type.kind == BtfKind::Array {
                if let Some(ref arr) = member_type.array_info {
                    return arr.nelems <= 1;
                }
            }
        }
    }

    false
}

/// Validate function prototype parameters
pub fn validate_func_proto(btf: &Btf, func_id: u32) -> Result<(), String> {
    let func = btf
        .get_type(func_id)
        .ok_or_else(|| "function not found".to_string())?;

    if func.kind != BtfKind::Func {
        return Err("not a function".to_string());
    }

    let proto = btf
        .get_type(func.type_ref)
        .ok_or_else(|| "function prototype not found".to_string())?;

    if proto.kind != BtfKind::FuncProto {
        return Err("invalid function prototype".to_string());
    }

    // Validate return type exists
    if proto.type_ref != 0 {
        btf.get_type(proto.type_ref)
            .ok_or_else(|| "return type not found".to_string())?;
    }

    // Validate parameter types
    for (i, param) in proto.params.iter().enumerate() {
        if param.type_id != 0 {
            btf.get_type(param.type_id)
                .ok_or_else(|| format!("parameter {} type not found", i))?;
        }
    }

    Ok(())
}

/// Check integer encoding compatibility
pub fn int_encoding_compatible(src: &BtfIntEncoding, dst: &BtfIntEncoding) -> bool {
    // Same signedness required
    if src.is_signed() != dst.is_signed() {
        return false;
    }

    // Bits must be compatible (src can be smaller or equal)
    if src.bits > dst.bits {
        return false;
    }

    true
}

/// Validate nested struct/union access
pub fn validate_nested_access(
    btf: &Btf,
    base_type_id: u32,
    access_path: &[(String, u32)], // (field_name, offset)
) -> Result<u32, String> {
    let mut current_type_id = base_type_id;

    for (field_name, expected_offset) in access_path {
        let ty = btf
            .resolve_type(current_type_id)
            .ok_or_else(|| format!("type {} not found", current_type_id))?;

        if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
            return Err(format!("expected struct/union, got {:?}", ty.kind));
        }

        // Find the field
        let member = ty
            .members
            .iter()
            .find(|m| m.name.as_deref() == Some(field_name.as_str()))
            .ok_or_else(|| format!("field '{}' not found", field_name))?;

        // Verify offset matches
        if member.offset / 8 != *expected_offset {
            return Err(format!(
                "field '{}' offset mismatch: expected {}, got {}",
                field_name,
                expected_offset,
                member.offset / 8
            ));
        }

        current_type_id = member.type_id;
    }

    Ok(current_type_id)
}

// ============================================================================
// Union Variant Tracking
// ============================================================================

/// Union variant state for tracking which variant is active
#[derive(Debug, Clone, Default)]
pub struct UnionVariantState {
    /// Active variant index (-1 means unknown/any)
    pub active_variant: i32,
    /// Size of the active variant
    pub active_size: u32,
    /// Type ID of the active variant
    pub active_type_id: u32,
}

impl UnionVariantState {
    /// Create a new unknown union state
    pub fn unknown() -> Self {
        Self {
            active_variant: -1,
            active_size: 0,
            active_type_id: 0,
        }
    }

    /// Create a new state with known variant
    pub fn with_variant(variant_idx: i32, size: u32, type_id: u32) -> Self {
        Self {
            active_variant: variant_idx,
            active_size: size,
            active_type_id: type_id,
        }
    }

    /// Check if variant is known
    pub fn is_known(&self) -> bool {
        self.active_variant >= 0
    }
}

/// Union access tracker for validating consistent union access
#[derive(Debug, Default)]
pub struct UnionAccessTracker {
    /// Tracked union states by (base_ptr_id, offset)
    states: HashMap<(u32, u32), UnionVariantState>,
}

impl UnionAccessTracker {
    /// Create a new union access tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a union access
    pub fn record_access(
        &mut self,
        ptr_id: u32,
        offset: u32,
        variant_idx: i32,
        variant_size: u32,
        variant_type_id: u32,
    ) -> Result<(), String> {
        let key = (ptr_id, offset);

        if let Some(existing) = self.states.get(&key) {
            if existing.is_known() && existing.active_variant != variant_idx {
                // Accessing different variant than what was written
                return Err(format!(
                    "union variant mismatch: accessing variant {} but variant {} was written",
                    variant_idx, existing.active_variant
                ));
            }
        }

        self.states.insert(
            key,
            UnionVariantState::with_variant(variant_idx, variant_size, variant_type_id),
        );

        Ok(())
    }

    /// Get the current variant state for a union
    pub fn get_state(&self, ptr_id: u32, offset: u32) -> Option<&UnionVariantState> {
        self.states.get(&(ptr_id, offset))
    }

    /// Clear tracking for a pointer (e.g., when pointer is invalidated)
    pub fn clear_ptr(&mut self, ptr_id: u32) {
        self.states.retain(|(pid, _), _| *pid != ptr_id);
    }

    /// Reset all tracking
    pub fn reset(&mut self) {
        self.states.clear();
    }
}

// ============================================================================
// Complete Nested Structure Chain Validation
// ============================================================================

/// Result of nested access chain validation
#[derive(Debug, Clone)]
pub struct NestedAccessResult {
    /// Whether access is valid
    pub valid: bool,
    /// Final field type ID
    pub field_type_id: u32,
    /// Total offset from base (bytes)
    pub total_offset: u32,
    /// Access size
    pub size: u32,
    /// Accumulated permissions from all levels
    pub permissions: BtfPermissions,
    /// Whether any level contains a union
    pub contains_union: bool,
    /// Union variant info if applicable
    pub union_variant: Option<(i32, u32)>, // (variant_idx, type_id)
    /// Error message if invalid
    pub error: Option<String>,
    /// Full access path for diagnostics
    pub path: Vec<String>,
}

/// Nested access chain validator
pub struct NestedAccessValidator<'a> {
    btf: &'a Btf,
    decl_tags: Option<&'a DeclTagStore>,
    max_depth: usize,
}

impl<'a> NestedAccessValidator<'a> {
    /// Create a new validator
    pub fn new(btf: &'a Btf) -> Self {
        Self {
            btf,
            decl_tags: None,
            max_depth: 32,
        }
    }

    /// Set DeclTag store for permission checking
    pub fn with_decl_tags(mut self, tags: &'a DeclTagStore) -> Self {
        self.decl_tags = Some(tags);
        self
    }

    /// Set maximum nesting depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Validate access at offset through nested structures
    pub fn validate_access_at_offset(
        &self,
        base_type_id: u32,
        offset: u32,
        size: u32,
        is_write: bool,
    ) -> NestedAccessResult {
        let mut result = NestedAccessResult {
            valid: false,
            field_type_id: 0,
            total_offset: offset,
            size,
            permissions: BtfPermissions::default(),
            contains_union: false,
            union_variant: None,
            error: None,
            path: Vec::new(),
        };

        // Traverse the type hierarchy to find the field at this offset
        match self.find_field_at_offset_recursive(
            base_type_id,
            offset,
            size,
            0,
            &mut result,
            is_write,
        ) {
            Ok(()) => {
                result.valid = true;
            }
            Err(e) => {
                result.error = Some(e);
            }
        }

        result
    }

    fn find_field_at_offset_recursive(
        &self,
        type_id: u32,
        remaining_offset: u32,
        size: u32,
        depth: usize,
        result: &mut NestedAccessResult,
        is_write: bool,
    ) -> Result<(), String> {
        if depth > self.max_depth {
            return Err("nested structure too deep".to_string());
        }

        let ty = self
            .btf
            .resolve_type(type_id)
            .ok_or_else(|| format!("type {} not found", type_id))?;

        // Collect type-level permissions
        if let Some(tags) = self.decl_tags {
            let perms = tags.get_type_permissions(type_id);
            result.permissions.merge(&perms);
        }

        match ty.kind {
            BtfKind::Struct | BtfKind::Union => {
                if ty.kind == BtfKind::Union {
                    result.contains_union = true;
                }

                // Bounds check
                if remaining_offset + size > ty.size {
                    return Err(format!(
                        "access at offset {} size {} exceeds {} size {}",
                        remaining_offset,
                        size,
                        if ty.kind == BtfKind::Union {
                            "union"
                        } else {
                            "struct"
                        },
                        ty.size
                    ));
                }

                // Find the member containing this offset
                let _bit_offset = remaining_offset * 8;

                for (member_idx, member) in ty.members.iter().enumerate() {
                    let member_byte_offset = member.offset / 8;
                    let member_size = self.btf.type_size(member.type_id).unwrap_or(0);

                    // For unions, all members start at offset 0
                    let effective_offset = if ty.kind == BtfKind::Union {
                        0
                    } else {
                        member_byte_offset
                    };

                    // Check if access falls within this member
                    if remaining_offset >= effective_offset
                        && remaining_offset < effective_offset + member_size
                    {
                        // Found the containing member
                        if let Some(ref name) = member.name {
                            result.path.push(name.clone());
                        }

                        // Collect member-level permissions
                        if let Some(tags) = self.decl_tags {
                            let perms = tags.get_member_permissions(type_id, member_idx as i32);
                            result.permissions.merge(&perms);
                        }

                        // Check write permission
                        if is_write && result.permissions.rdonly {
                            return Err(format!(
                                "write to read-only field at path {}",
                                result.path.join(".")
                            ));
                        }

                        // For unions, track the variant
                        if ty.kind == BtfKind::Union {
                            result.union_variant = Some((member_idx as i32, member.type_id));
                        }

                        // Calculate offset relative to this member
                        let new_offset = remaining_offset - effective_offset;

                        // Check if we need to recurse into nested struct/union
                        let member_ty = self.btf.resolve_type(member.type_id);
                        if let Some(mt) = member_ty {
                            if matches!(mt.kind, BtfKind::Struct | BtfKind::Union) {
                                // Always recurse into nested struct/union to find the actual field
                                return self.find_field_at_offset_recursive(
                                    member.type_id,
                                    new_offset,
                                    size,
                                    depth + 1,
                                    result,
                                    is_write,
                                );
                            }
                        }

                        // Leaf field found
                        result.field_type_id = member.type_id;

                        // Validate size against field type
                        if size > member_size {
                            return Err(format!(
                                "access size {} exceeds field size {}",
                                size, member_size
                            ));
                        }

                        return Ok(());
                    }
                }

                // No exact field match - allow raw access if within bounds
                result.field_type_id = 0; // Unknown field type
                Ok(())
            }
            BtfKind::Array => {
                if let Some(ref arr) = ty.array_info {
                    let elem_size = self.btf.type_size(arr.elem_type).unwrap_or(0);
                    if elem_size == 0 {
                        return Err("array element size is 0".to_string());
                    }

                    let elem_idx = remaining_offset / elem_size;
                    if elem_idx >= arr.nelems {
                        return Err(format!(
                            "array index {} out of bounds (array size {})",
                            elem_idx, arr.nelems
                        ));
                    }

                    result.path.push(format!("[{}]", elem_idx));

                    let new_offset = remaining_offset % elem_size;

                    // Recurse into element type
                    let elem_ty = self.btf.resolve_type(arr.elem_type);
                    if let Some(et) = elem_ty {
                        if matches!(et.kind, BtfKind::Struct | BtfKind::Union) {
                            return self.find_field_at_offset_recursive(
                                arr.elem_type,
                                new_offset,
                                size,
                                depth + 1,
                                result,
                                is_write,
                            );
                        }
                    }

                    result.field_type_id = arr.elem_type;
                    Ok(())
                } else {
                    Err("array type missing array_info".to_string())
                }
            }
            BtfKind::Ptr => {
                // Cannot traverse through pointer automatically
                // The caller must dereference the pointer first
                result.field_type_id = type_id;
                if remaining_offset > 0 {
                    Err("cannot access past pointer without dereference".to_string())
                } else {
                    Ok(())
                }
            }
            _ => {
                // Scalar or other leaf type
                result.field_type_id = type_id;
                let type_size = self.btf.type_size(type_id).unwrap_or(0);
                if remaining_offset + size > type_size {
                    Err(format!(
                        "access at offset {} size {} exceeds type size {}",
                        remaining_offset, size, type_size
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Validate a complete access path (field names)
    pub fn validate_access_path(
        &self,
        base_type_id: u32,
        path: &[&str],
        size: u32,
        is_write: bool,
    ) -> NestedAccessResult {
        let mut result = NestedAccessResult {
            valid: false,
            field_type_id: base_type_id,
            total_offset: 0,
            size,
            permissions: BtfPermissions::default(),
            contains_union: false,
            union_variant: None,
            error: None,
            path: Vec::new(),
        };

        let mut current_type_id = base_type_id;
        let mut current_offset: u32 = 0;

        for (depth, field_name) in path.iter().enumerate() {
            if depth > self.max_depth {
                result.error = Some("access path too deep".to_string());
                return result;
            }

            let ty = match self.btf.resolve_type(current_type_id) {
                Some(t) => t,
                None => {
                    result.error = Some(format!("type {} not found", current_type_id));
                    return result;
                }
            };

            // Collect type permissions
            if let Some(tags) = self.decl_tags {
                result
                    .permissions
                    .merge(&tags.get_type_permissions(current_type_id));
            }

            if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
                result.error = Some(format!(
                    "cannot access field '{}' on non-struct type {:?}",
                    field_name, ty.kind
                ));
                return result;
            }

            if ty.kind == BtfKind::Union {
                result.contains_union = true;
            }

            // Find the field
            let mut found = false;
            for (member_idx, member) in ty.members.iter().enumerate() {
                if member.name.as_deref() == Some(*field_name) {
                    result.path.push(field_name.to_string());

                    // Collect member permissions
                    if let Some(tags) = self.decl_tags {
                        result.permissions.merge(
                            &tags.get_member_permissions(current_type_id, member_idx as i32),
                        );
                    }

                    // For unions, track variant
                    if ty.kind == BtfKind::Union {
                        result.union_variant = Some((member_idx as i32, member.type_id));
                        // Union members don't add to offset
                    } else {
                        current_offset += member.offset / 8;
                    }

                    current_type_id = member.type_id;
                    found = true;
                    break;
                }
            }

            if !found {
                result.error = Some(format!(
                    "field '{}' not found in {}",
                    field_name,
                    ty.name.as_deref().unwrap_or("<anonymous>")
                ));
                return result;
            }
        }

        // Check final write permission
        if is_write && result.permissions.rdonly {
            result.error = Some(format!(
                "write to read-only field at path {}",
                result.path.join(".")
            ));
            return result;
        }

        // Validate final field size
        let field_size = self.btf.type_size(current_type_id).unwrap_or(0);
        if size > field_size {
            result.error = Some(format!(
                "access size {} exceeds field size {}",
                size, field_size
            ));
            return result;
        }

        result.valid = true;
        result.field_type_id = current_type_id;
        result.total_offset = current_offset;
        result
    }
}

// ============================================================================
// Advanced BTF Type Walking
// ============================================================================

/// BTF type walker for traversing complex type hierarchies
pub struct BtfTypeWalker<'a> {
    btf: &'a Btf,
    /// Maximum depth to prevent infinite recursion
    max_depth: usize,
    /// Current path (for error reporting)
    path: Vec<String>,
    /// Visited type IDs (for cycle detection)
    visited: Vec<u32>,
}

impl<'a> BtfTypeWalker<'a> {
    /// Create a new type walker
    pub fn new(btf: &'a Btf) -> Self {
        Self {
            btf,
            max_depth: 32,
            path: Vec::new(),
            visited: Vec::new(),
        }
    }

    /// Walk a type and collect all fields with their offsets
    pub fn walk_type(&mut self, type_id: u32) -> Result<Vec<FieldPath>, String> {
        self.path.clear();
        self.visited.clear();
        self.walk_type_impl(type_id, 0, 0)
    }

    fn walk_type_impl(
        &mut self,
        type_id: u32,
        bit_offset: u32,
        depth: usize,
    ) -> Result<Vec<FieldPath>, String> {
        if depth > self.max_depth {
            return Err("type hierarchy too deep".to_string());
        }

        // Cycle detection
        if self.visited.contains(&type_id) {
            return Err("cyclic type reference detected".to_string());
        }
        self.visited.push(type_id);

        let ty = self
            .btf
            .resolve_type(type_id)
            .ok_or_else(|| format!("type {} not found", type_id))?;

        let mut fields = Vec::new();

        match ty.kind {
            BtfKind::Struct | BtfKind::Union => {
                for member in &ty.members {
                    let member_offset = if ty.kind == BtfKind::Union {
                        bit_offset // Union members start at same offset
                    } else {
                        bit_offset + member.offset
                    };

                    // Add this field
                    fields.push(FieldPath {
                        name: member.name.clone().unwrap_or_default(),
                        type_id: member.type_id,
                        bit_offset: member_offset,
                        byte_offset: member_offset / 8,
                        is_bitfield: self.is_bitfield(member, type_id),
                        path: self.path.clone(),
                    });

                    // Recurse into nested structs/unions
                    if let Some(member_ty) = self.btf.resolve_type(member.type_id) {
                        if matches!(member_ty.kind, BtfKind::Struct | BtfKind::Union) {
                            if let Some(ref name) = member.name {
                                self.path.push(name.clone());
                            }
                            let nested =
                                self.walk_type_impl(member.type_id, member_offset, depth + 1)?;
                            fields.extend(nested);
                            if member.name.is_some() {
                                self.path.pop();
                            }
                        }
                    }
                }
            }
            BtfKind::Array => {
                if let Some(ref arr) = ty.array_info {
                    let elem_size = self.btf.type_size(arr.elem_type).unwrap_or(0) * 8;
                    for i in 0..arr.nelems.min(64) {
                        // Limit array expansion
                        let elem_offset = bit_offset + i * elem_size;
                        fields.push(FieldPath {
                            name: format!("[{}]", i),
                            type_id: arr.elem_type,
                            bit_offset: elem_offset,
                            byte_offset: elem_offset / 8,
                            is_bitfield: false,
                            path: self.path.clone(),
                        });
                    }
                }
            }
            _ => {
                // Leaf type
                fields.push(FieldPath {
                    name: String::new(),
                    type_id,
                    bit_offset,
                    byte_offset: bit_offset / 8,
                    is_bitfield: false,
                    path: self.path.clone(),
                });
            }
        }

        self.visited.pop();
        Ok(fields)
    }

    /// Check if a member is a bitfield
    fn is_bitfield(&self, member: &BtfMember, _parent_id: u32) -> bool {
        if let Some(member_ty) = self.btf.resolve_type(member.type_id) {
            if member_ty.kind == BtfKind::Int {
                if let Some(ref encoding) = member_ty.int_encoding {
                    let type_bits = member_ty.size * 8;
                    return (encoding.bits as u32) < type_bits;
                }
            }
        }
        false
    }

    /// Find a field at a specific byte offset
    pub fn find_field_at_offset(
        &mut self,
        type_id: u32,
        byte_offset: u32,
    ) -> Result<Option<FieldPath>, String> {
        let fields = self.walk_type(type_id)?;
        let bit_offset = byte_offset * 8;

        Ok(fields.into_iter().find(|f| f.bit_offset == bit_offset))
    }

    /// Validate access at a specific offset and size
    pub fn validate_access(
        &mut self,
        type_id: u32,
        offset: u32,
        size: u32,
    ) -> Result<AccessValidation, String> {
        let ty = self
            .btf
            .resolve_type(type_id)
            .ok_or_else(|| "type not found".to_string())?;

        // Bounds check
        if offset + size > ty.size {
            return Ok(AccessValidation {
                valid: false,
                field: None,
                reason: Some(format!(
                    "access at {}+{} exceeds type size {}",
                    offset, size, ty.size
                )),
            });
        }

        // Find the field
        let field = self.find_field_at_offset(type_id, offset)?;

        Ok(AccessValidation {
            valid: true,
            field,
            reason: None,
        })
    }
}

/// Result of field walking
#[derive(Debug, Clone)]
pub struct FieldPath {
    /// Field name
    pub name: String,
    /// Field type ID
    pub type_id: u32,
    /// Offset in bits from struct start
    pub bit_offset: u32,
    /// Offset in bytes from struct start
    pub byte_offset: u32,
    /// Whether this is a bitfield
    pub is_bitfield: bool,
    /// Path to this field (for nested structs)
    pub path: Vec<String>,
}

impl FieldPath {
    /// Get full path string
    pub fn full_path(&self) -> String {
        if self.path.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.path.join("."), self.name)
        }
    }
}

/// Result of access validation
#[derive(Debug, Clone)]
pub struct AccessValidation {
    /// Whether access is valid
    pub valid: bool,
    /// Field at this offset (if found)
    pub field: Option<FieldPath>,
    /// Reason for invalidity
    pub reason: Option<String>,
}

// ============================================================================
// Kfunc BTF Integration
// ============================================================================

/// Kfunc metadata extracted from BTF
#[derive(Debug, Clone)]
pub struct KfuncMeta {
    /// Function name
    pub name: String,
    /// BTF function ID
    pub func_id: u32,
    /// Return type
    pub ret_type: KfuncReturnType,
    /// Parameters
    pub params: Vec<KfuncParam>,
    /// Flags
    pub flags: KfuncFlags,
}

/// Kfunc return type classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KfuncReturnType {
    /// Returns void
    Void,
    /// Returns a scalar value
    Scalar { size: u32, signed: bool },
    /// Returns a pointer (may be null)
    Pointer { target_id: u32, may_be_null: bool },
    /// Returns an acquired pointer (caller must release)
    AcquiredPointer { target_id: u32 },
    /// Returns a borrowed reference
    BorrowedRef { target_id: u32 },
}

/// Kfunc parameter information
#[derive(Debug, Clone)]
pub struct KfuncParam {
    /// Parameter name
    pub name: String,
    /// Parameter type ID
    pub type_id: u32,
    /// Parameter classification
    pub kind: KfuncParamKind,
}

/// Kfunc parameter classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KfuncParamKind {
    /// Scalar value
    Scalar,
    /// Pointer to memory
    PtrToMem { size: Option<u32>, rdonly: bool },
    /// Pointer to BTF type
    PtrToBtfId { btf_id: u32, nullable: bool },
    /// Pointer to context
    PtrToCtx,
    /// Pointer to dynptr
    PtrToDynptr,
    /// Pointer to iterator
    PtrToIter,
    /// Callback function
    Callback,
    /// Release parameter (pointer to be released)
    ReleasePtr { btf_id: u32 },
    /// Acquire output parameter
    AcquireOut { btf_id: u32 },
}

bitflags::bitflags! {
    /// Kfunc flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KfuncFlags: u32 {
        /// Kfunc acquires a reference
        const ACQUIRE = 1 << 0;
        /// Kfunc releases a reference
        const RELEASE = 1 << 1;
        /// Kfunc returns null on failure
        const RET_NULL = 1 << 2;
        /// Kfunc is sleepable
        const SLEEPABLE = 1 << 3;
        /// Kfunc is destructive (modifies kernel state)
        const DESTRUCTIVE = 1 << 4;
        /// Kfunc is trusted
        const TRUSTED = 1 << 5;
        /// Kfunc operates on RCU-protected data
        const RCU = 1 << 6;
    }
}

impl Default for KfuncFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Extract kfunc metadata from BTF
pub fn extract_kfunc_meta(btf: &Btf, func_name: &str) -> Option<KfuncMeta> {
    let func_ids = btf.find_by_name(func_name);
    if func_ids.is_empty() {
        return None;
    }

    let func_id = func_ids[0];
    let proto = btf.get_func_proto(func_id)?;

    // Analyze return type
    let ret_type = classify_kfunc_return(btf, proto.ret_type);

    // Analyze parameters
    let mut params = Vec::new();
    for (name, type_id) in proto.params {
        let kind = classify_kfunc_param(btf, type_id);
        params.push(KfuncParam {
            name: name.unwrap_or_default(),
            type_id,
            kind,
        });
    }

    // Determine flags from annotations (simplified)
    let flags = infer_kfunc_flags(func_name, &ret_type, &params);

    Some(KfuncMeta {
        name: func_name.to_string(),
        func_id,
        ret_type,
        params,
        flags,
    })
}

/// Classify kfunc return type
fn classify_kfunc_return(btf: &Btf, type_id: u32) -> KfuncReturnType {
    if type_id == 0 {
        return KfuncReturnType::Void;
    }

    let ty = match btf.resolve_type(type_id) {
        Some(t) => t,
        None => return KfuncReturnType::Void,
    };

    match ty.kind {
        BtfKind::Int => {
            let signed = ty
                .int_encoding
                .as_ref()
                .map(|e| e.is_signed())
                .unwrap_or(false);
            KfuncReturnType::Scalar {
                size: ty.size,
                signed,
            }
        }
        BtfKind::Ptr => {
            let target_id = ty.type_ref;
            // Determine if pointer may be null or is acquired
            // This would normally come from BTF annotations
            KfuncReturnType::Pointer {
                target_id,
                may_be_null: true, // Conservative default
            }
        }
        _ => KfuncReturnType::Void,
    }
}

/// Classify kfunc parameter
fn classify_kfunc_param(btf: &Btf, type_id: u32) -> KfuncParamKind {
    let ty = match btf.resolve_type(type_id) {
        Some(t) => t,
        None => return KfuncParamKind::Scalar,
    };

    match ty.kind {
        BtfKind::Int | BtfKind::Enum | BtfKind::Enum64 => KfuncParamKind::Scalar,
        BtfKind::Ptr => {
            let target = btf.resolve_type(ty.type_ref);
            match target {
                Some(t) if t.kind == BtfKind::Struct => {
                    // Check for special types
                    if let Some(ref name) = t.name {
                        if name == "bpf_dynptr" {
                            return KfuncParamKind::PtrToDynptr;
                        }
                        if name.contains("iter") {
                            return KfuncParamKind::PtrToIter;
                        }
                    }
                    KfuncParamKind::PtrToBtfId {
                        btf_id: ty.type_ref,
                        nullable: false,
                    }
                }
                Some(t) if t.kind == BtfKind::FuncProto => KfuncParamKind::Callback,
                _ => {
                    // Generic pointer to memory
                    KfuncParamKind::PtrToMem {
                        size: None,
                        rdonly: false,
                    }
                }
            }
        }
        _ => KfuncParamKind::Scalar,
    }
}

/// Infer kfunc flags from name and signature
fn infer_kfunc_flags(name: &str, ret_type: &KfuncReturnType, params: &[KfuncParam]) -> KfuncFlags {
    let mut flags = KfuncFlags::empty();

    // Check for acquire/release patterns in name
    if name.contains("_acquire") || name.contains("_get") || name.contains("_new") {
        flags.insert(KfuncFlags::ACQUIRE);
    }
    if name.contains("_release") || name.contains("_put") || name.contains("_destroy") {
        flags.insert(KfuncFlags::RELEASE);
    }

    // Check return type
    if matches!(
        ret_type,
        KfuncReturnType::Pointer {
            may_be_null: true,
            ..
        }
    ) {
        flags.insert(KfuncFlags::RET_NULL);
    }
    if matches!(ret_type, KfuncReturnType::AcquiredPointer { .. }) {
        flags.insert(KfuncFlags::ACQUIRE);
    }

    // Check parameters
    for param in params {
        if matches!(param.kind, KfuncParamKind::ReleasePtr { .. }) {
            flags.insert(KfuncFlags::RELEASE);
        }
    }

    // Check for RCU patterns
    if name.contains("_rcu") || name.contains("rcu_") {
        flags.insert(KfuncFlags::RCU);
    }

    flags
}

/// Validate kfunc call arguments against BTF
pub fn validate_kfunc_call(
    btf: &Btf,
    meta: &KfuncMeta,
    arg_regs: &[BtfArgInfo],
) -> Result<KfuncCallValidation, String> {
    if arg_regs.len() != meta.params.len() {
        return Err(format!(
            "kfunc '{}' expects {} args, got {}",
            meta.name,
            meta.params.len(),
            arg_regs.len()
        ));
    }

    let mut validation = KfuncCallValidation {
        valid: true,
        errors: Vec::new(),
        acquire_ref: meta.flags.contains(KfuncFlags::ACQUIRE),
        release_ref: meta.flags.contains(KfuncFlags::RELEASE),
        release_arg_idx: None,
    };

    for (i, (param, arg)) in meta.params.iter().zip(arg_regs.iter()).enumerate() {
        if let Err(e) = validate_arg_against_param(btf, param, arg) {
            validation.valid = false;
            validation.errors.push(format!("arg {}: {}", i, e));
        }

        // Track release argument
        if matches!(param.kind, KfuncParamKind::ReleasePtr { .. }) {
            validation.release_arg_idx = Some(i);
        }
    }

    Ok(validation)
}

/// Argument info for validation
#[derive(Debug, Clone)]
pub struct BtfArgInfo {
    /// BTF type ID of the argument
    pub type_id: u32,
    /// Whether the argument is null
    pub is_null: bool,
    /// Reference ID if this is an acquired reference
    pub ref_id: Option<u32>,
}

/// Kfunc call validation result
#[derive(Debug, Clone)]
pub struct KfuncCallValidation {
    /// Whether call is valid
    pub valid: bool,
    /// Error messages
    pub errors: Vec<String>,
    /// Whether this call acquires a reference
    pub acquire_ref: bool,
    /// Whether this call releases a reference
    pub release_ref: bool,
    /// Index of the argument being released (if any)
    pub release_arg_idx: Option<usize>,
}

/// Validate a single argument against parameter specification
fn validate_arg_against_param(
    btf: &Btf,
    param: &KfuncParam,
    arg: &BtfArgInfo,
) -> Result<(), String> {
    match &param.kind {
        KfuncParamKind::Scalar => {
            // Accept any scalar
            Ok(())
        }
        KfuncParamKind::PtrToBtfId { btf_id, nullable } => {
            if arg.is_null {
                if *nullable {
                    Ok(())
                } else {
                    Err("null pointer not allowed".to_string())
                }
            } else {
                // Check type compatibility
                let compat = check_type_compat(btf, arg.type_id, *btf_id);
                if compat == BtfTypeCompat::Incompatible {
                    Err(format!("type mismatch: expected BTF ID {}", btf_id))
                } else {
                    Ok(())
                }
            }
        }
        KfuncParamKind::ReleasePtr { btf_id } => {
            // Must have a valid ref_id
            if arg.ref_id.is_none() {
                return Err("release argument must be an acquired reference".to_string());
            }
            // Type must match
            let compat = check_type_compat(btf, arg.type_id, *btf_id);
            if compat == BtfTypeCompat::Incompatible {
                Err(format!("release type mismatch: expected BTF ID {}", btf_id))
            } else {
                Ok(())
            }
        }
        KfuncParamKind::PtrToDynptr => {
            // Check it's actually a dynptr
            if !is_dynptr_type(btf, arg.type_id) {
                Err("expected bpf_dynptr".to_string())
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}
