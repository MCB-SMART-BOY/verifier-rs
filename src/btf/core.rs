// SPDX-License-Identifier: GPL-2.0

//! BTF CO-RE (Compile Once - Run Everywhere) support
//!
//! This module implements CO-RE relocation support, allowing BPF programs
//! compiled against one kernel's BTF to run on different kernels.
//!
//! CO-RE relocations allow the verifier/loader to:
//! - Adjust field offsets for struct layout differences
//! - Handle field existence checks
//! - Resolve type IDs across different BTF databases
//! - Handle enum value differences

#![allow(missing_docs)]

use alloc::{format, string::String, vec::Vec};

use alloc::collections::BTreeMap as HashMap;

use super::database::{Btf, BtfKind, BtfMember, BtfType, MAX_RESOLVE_DEPTH};
use super::func_info::{BpfCoreRelo, BpfCoreReloKind};
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// Maximum number of access path components
const MAX_ACCESS_DEPTH: usize = 256;

/// CO-RE access specification
///
/// Parsed from the access string in a CO-RE relocation.
/// Format: "0:1:2" means field index 0, then field index 1, then field index 2
#[derive(Debug, Clone)]
pub struct CoreAccessSpec {
    /// Type ID being accessed
    pub type_id: u32,
    /// Access path (field indices or array indices)
    pub access: Vec<CoreAccessComponent>,
    /// Total bit offset from the base
    pub bit_offset: u64,
}

/// A single component in the CO-RE access path
#[derive(Debug, Clone)]
pub enum CoreAccessComponent {
    /// Field access by index
    Field {
        /// Field index in the struct
        index: u32,
        /// Field name (for matching)
        name: Option<String>,
    },
    /// Array element access
    Array {
        /// Element index
        index: u32,
    },
}

/// Result of a CO-RE relocation
#[derive(Debug, Clone, Default)]
pub struct CoreReloResult {
    /// Whether relocation succeeded
    pub success: bool,
    /// New value for the instruction immediate
    pub new_val: u64,
    /// Whether the target exists
    pub exists: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// CO-RE relocation context
pub struct CoreReloContext<'a> {
    /// Local BTF (from the BPF program)
    pub local_btf: &'a Btf,
    /// Target BTF (from the running kernel)
    pub target_btf: &'a Btf,
    /// Cache of type mappings (local type ID -> target type ID)
    type_map: HashMap<u32, Option<u32>>,
}

impl<'a> CoreReloContext<'a> {
    /// Create a new CO-RE relocation context
    pub fn new(local_btf: &'a Btf, target_btf: &'a Btf) -> Self {
        Self {
            local_btf,
            target_btf,
            type_map: HashMap::new(),
        }
    }

    /// Process a single CO-RE relocation
    pub fn process_relo(&mut self, relo: &BpfCoreRelo) -> Result<CoreReloResult> {
        let kind = BpfCoreReloKind::try_from(relo.kind).map_err(|_| {
            VerifierError::InvalidBtf(format!("invalid CO-RE relo kind {}", relo.kind))
        })?;

        // Parse the access string
        let access_str = self
            .local_btf
            .get_string(relo.access_str_off)
            .ok_or_else(|| VerifierError::InvalidBtf("invalid access string offset".into()))?;

        let local_spec = self.parse_access_spec(self.local_btf, relo.type_id, access_str)?;

        // Find matching type in target BTF
        let target_type_id = self.find_target_type(relo.type_id)?;

        match kind {
            BpfCoreReloKind::FieldByteOffset => {
                self.relo_field_byte_offset(&local_spec, target_type_id)
            }
            BpfCoreReloKind::FieldByteSize => {
                self.relo_field_byte_size(&local_spec, target_type_id)
            }
            BpfCoreReloKind::FieldExists => self.relo_field_exists(&local_spec, target_type_id),
            BpfCoreReloKind::FieldSigned => self.relo_field_signed(&local_spec, target_type_id),
            BpfCoreReloKind::FieldLshift => self.relo_field_lshift(&local_spec, target_type_id),
            BpfCoreReloKind::FieldRshift => self.relo_field_rshift(&local_spec, target_type_id),
            BpfCoreReloKind::TypeIdLocal => Ok(CoreReloResult {
                success: true,
                new_val: relo.type_id as u64,
                exists: true,
                error: None,
            }),
            BpfCoreReloKind::TypeIdTarget => self.relo_type_id_target(relo.type_id),
            BpfCoreReloKind::TypeExists => self.relo_type_exists(relo.type_id),
            BpfCoreReloKind::TypeSize => self.relo_type_size(relo.type_id),
            BpfCoreReloKind::TypeMatches => self.relo_type_matches(relo.type_id, target_type_id),
            BpfCoreReloKind::EnumvalExists => self.relo_enumval_exists(&local_spec, target_type_id),
            BpfCoreReloKind::EnumvalValue => self.relo_enumval_value(&local_spec, target_type_id),
        }
    }

    /// Parse an access specification string
    fn parse_access_spec(
        &self,
        btf: &Btf,
        type_id: u32,
        access_str: &str,
    ) -> Result<CoreAccessSpec> {
        let mut access = Vec::new();
        let mut current_type = type_id;
        let mut bit_offset = 0u64;

        if access_str.is_empty() {
            return Ok(CoreAccessSpec {
                type_id,
                access,
                bit_offset: 0,
            });
        }

        for (i, part) in access_str.split(':').enumerate() {
            if i >= MAX_ACCESS_DEPTH {
                return Err(VerifierError::InvalidBtf("access spec too deep".into()));
            }

            let idx: u32 = part.parse().map_err(|_| {
                VerifierError::InvalidBtf(format!("invalid access index '{}'", part))
            })?;

            let ty = btf.resolve_type(current_type).ok_or_else(|| {
                VerifierError::InvalidBtf(format!("type {} not found", current_type))
            })?;

            match ty.kind {
                BtfKind::Struct | BtfKind::Union => {
                    if idx as usize >= ty.members.len() {
                        return Err(VerifierError::InvalidBtf(format!(
                            "field index {} out of range for type {}",
                            idx, current_type
                        )));
                    }

                    let member = &ty.members[idx as usize];
                    bit_offset += member.offset as u64;

                    access.push(CoreAccessComponent::Field {
                        index: idx,
                        name: member.name.clone(),
                    });

                    current_type = member.type_id;
                }
                BtfKind::Array => {
                    if let Some(ref arr) = ty.array_info {
                        let elem_size = btf.type_size(arr.elem_type).unwrap_or(0);
                        bit_offset += (idx as u64) * (elem_size as u64) * 8;

                        access.push(CoreAccessComponent::Array { index: idx });
                        current_type = arr.elem_type;
                    } else {
                        return Err(VerifierError::InvalidBtf(
                            "array type missing array info".into(),
                        ));
                    }
                }
                BtfKind::Ptr => {
                    // Pointer dereference
                    current_type = ty.type_ref;
                    access.push(CoreAccessComponent::Field {
                        index: idx,
                        name: None,
                    });
                }
                _ => {
                    return Err(VerifierError::InvalidBtf(format!(
                        "cannot access into type {:?}",
                        ty.kind
                    )));
                }
            }
        }

        Ok(CoreAccessSpec {
            type_id,
            access,
            bit_offset,
        })
    }

    /// Find a matching type in the target BTF
    fn find_target_type(&mut self, local_type_id: u32) -> Result<Option<u32>> {
        // Check cache first
        if let Some(&cached) = self.type_map.get(&local_type_id) {
            return Ok(cached);
        }

        let local_type = match self.local_btf.resolve_type(local_type_id) {
            Some(t) => t,
            None => {
                self.type_map.insert(local_type_id, None);
                return Ok(None);
            }
        };

        // Find by name in target BTF
        let target_id = if let Some(ref name) = local_type.name {
            let candidates = self.target_btf.find_by_name(name);

            // Find matching kind
            candidates
                .iter()
                .filter_map(|&id| self.target_btf.get_type(id))
                .find(|t| t.kind == local_type.kind)
                .map(|t| t.id)
        } else {
            None
        };

        self.type_map.insert(local_type_id, target_id);
        Ok(target_id)
    }

    /// Find a field in the target type by name
    fn find_target_field(
        &self,
        target_type_id: u32,
        field_name: &str,
    ) -> Option<(usize, &BtfMember)> {
        let ty = self.target_btf.resolve_type(target_type_id)?;

        if ty.kind != BtfKind::Struct && ty.kind != BtfKind::Union {
            return None;
        }

        ty.members
            .iter()
            .enumerate()
            .find(|(_, m)| m.name.as_deref() == Some(field_name))
    }

    /// Relocate: field byte offset
    fn relo_field_byte_offset(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Trace through access path in target BTF
        let mut current_type = target_id;
        let mut bit_offset = 0u64;
        let mut depth = 0usize;

        for component in &local_spec.access {
            // Prevent infinite loops in type resolution
            depth += 1;
            if depth > MAX_RESOLVE_DEPTH {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("access path too deep".into()),
                });
            }
            match component {
                CoreAccessComponent::Field { name, .. } => {
                    let field_name = match name {
                        Some(n) => n,
                        None => {
                            return Ok(CoreReloResult {
                                success: false,
                                new_val: 0,
                                exists: false,
                                error: Some("anonymous field in access path".into()),
                            });
                        }
                    };

                    match self.find_target_field(current_type, field_name) {
                        Some((_, member)) => {
                            bit_offset += member.offset as u64;
                            current_type = member.type_id;
                        }
                        None => {
                            return Ok(CoreReloResult {
                                success: false,
                                new_val: 0,
                                exists: false,
                                error: Some(format!("field '{}' not found in target", field_name)),
                            });
                        }
                    }
                }
                CoreAccessComponent::Array { index } => {
                    let ty = self.target_btf.resolve_type(current_type);
                    if let Some(ty) = ty {
                        if let Some(ref arr) = ty.array_info {
                            let elem_size = self.target_btf.type_size(arr.elem_type).unwrap_or(0);
                            bit_offset += (*index as u64) * (elem_size as u64) * 8;
                            current_type = arr.elem_type;
                        }
                    }
                }
            }
        }

        // Convert bit offset to byte offset
        let byte_offset = bit_offset / 8;

        Ok(CoreReloResult {
            success: true,
            new_val: byte_offset,
            exists: true,
            error: None,
        })
    }

    /// Relocate: field byte size
    fn relo_field_byte_size(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Get the final field type and its size
        let mut current_type = target_id;

        for component in &local_spec.access {
            match component {
                CoreAccessComponent::Field { name, .. } => {
                    if let Some(name) = name {
                        if let Some((_, member)) = self.find_target_field(current_type, name) {
                            current_type = member.type_id;
                        } else {
                            return Ok(CoreReloResult {
                                success: false,
                                new_val: 0,
                                exists: false,
                                error: Some(format!("field '{}' not found", name)),
                            });
                        }
                    }
                }
                CoreAccessComponent::Array { .. } => {
                    let ty = self.target_btf.resolve_type(current_type);
                    if let Some(ty) = ty {
                        if let Some(ref arr) = ty.array_info {
                            current_type = arr.elem_type;
                        }
                    }
                }
            }
        }

        let size = self.target_btf.type_size(current_type).unwrap_or(0);

        Ok(CoreReloResult {
            success: true,
            new_val: size as u64,
            exists: true,
            error: None,
        })
    }

    /// Relocate: field exists
    pub fn relo_field_exists(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: true,
                    new_val: 0,
                    exists: false,
                    error: None,
                });
            }
        };

        // Check if all fields in the access path exist
        let mut current_type = target_id;

        for component in &local_spec.access {
            match component {
                CoreAccessComponent::Field { name, .. } => {
                    if let Some(name) = name {
                        match self.find_target_field(current_type, name) {
                            Some((_, member)) => {
                                current_type = member.type_id;
                            }
                            None => {
                                return Ok(CoreReloResult {
                                    success: true,
                                    new_val: 0,
                                    exists: false,
                                    error: None,
                                });
                            }
                        }
                    }
                }
                CoreAccessComponent::Array { .. } => {
                    let ty = self.target_btf.resolve_type(current_type);
                    if let Some(ty) = ty {
                        if let Some(ref arr) = ty.array_info {
                            current_type = arr.elem_type;
                        } else {
                            return Ok(CoreReloResult {
                                success: true,
                                new_val: 0,
                                exists: false,
                                error: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(CoreReloResult {
            success: true,
            new_val: 1,
            exists: true,
            error: None,
        })
    }

    /// Relocate: field signedness
    fn relo_field_signed(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Get the final field type
        let mut current_type = target_id;

        for component in &local_spec.access {
            if let CoreAccessComponent::Field {
                name: Some(name), ..
            } = component
            {
                if let Some((_, member)) = self.find_target_field(current_type, name) {
                    current_type = member.type_id;
                }
            }
        }

        // Check if it's a signed integer
        let ty = self.target_btf.resolve_type(current_type);
        let is_signed = ty
            .and_then(|t| t.int_encoding.as_ref())
            .map(|enc| enc.is_signed())
            .unwrap_or(false);

        Ok(CoreReloResult {
            success: true,
            new_val: if is_signed { 1 } else { 0 },
            exists: true,
            error: None,
        })
    }

    /// Relocate: field left shift (for bitfields)
    ///
    /// For bitfields, calculates how many bits to left-shift to align the field
    /// to the MSB of the containing load size.
    pub fn relo_field_lshift(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Get bitfield info from target
        let bitfield_info = self.get_target_bitfield_info(local_spec, target_id)?;

        match bitfield_info {
            Some((bit_offset, bit_size, load_size)) => {
                // Calculate left shift to align bitfield to MSB
                // lshift = load_size * 8 - (bit_offset % (load_size * 8)) - bit_size
                let load_bits = load_size * 8;
                let bit_off_in_load = bit_offset % load_bits;
                let lshift = load_bits - bit_off_in_load - bit_size;

                Ok(CoreReloResult {
                    success: true,
                    new_val: lshift,
                    exists: true,
                    error: None,
                })
            }
            None => {
                // Not a bitfield, no shift needed
                Ok(CoreReloResult {
                    success: true,
                    new_val: 0,
                    exists: true,
                    error: None,
                })
            }
        }
    }

    /// Relocate: field right shift (for bitfields)
    ///
    /// For bitfields, calculates how many bits to right-shift after left-shifting
    /// to extract the field value.
    pub fn relo_field_rshift(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Get bitfield info from target
        let bitfield_info = self.get_target_bitfield_info(local_spec, target_id)?;

        match bitfield_info {
            Some((_, bit_size, load_size)) => {
                // Right shift = load_size * 8 - bit_size (to bring value to LSB)
                let load_bits = load_size * 8;
                let rshift = load_bits - bit_size;

                Ok(CoreReloResult {
                    success: true,
                    new_val: rshift,
                    exists: true,
                    error: None,
                })
            }
            None => {
                // Not a bitfield, no shift needed
                Ok(CoreReloResult {
                    success: true,
                    new_val: 0,
                    exists: true,
                    error: None,
                })
            }
        }
    }

    /// Get bitfield information for a field in the target BTF
    ///
    /// Returns (bit_offset, bit_size, load_size) if the field is a bitfield,
    /// None otherwise.
    fn get_target_bitfield_info(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: u32,
    ) -> Result<Option<(u64, u64, u64)>> {
        let mut current_type = target_type_id;
        let mut total_bit_offset = 0u64;
        let mut last_member: Option<&BtfMember> = None;

        for component in &local_spec.access {
            match component {
                CoreAccessComponent::Field { name, .. } => {
                    let field_name = match name {
                        Some(n) => n,
                        None => continue,
                    };

                    match self.find_target_field(current_type, field_name) {
                        Some((_, member)) => {
                            total_bit_offset += member.offset as u64;
                            last_member = Some(member);
                            current_type = member.type_id;
                        }
                        None => return Ok(None),
                    }
                }
                CoreAccessComponent::Array { index } => {
                    let ty = self.target_btf.resolve_type(current_type);
                    if let Some(ty) = ty {
                        if let Some(ref arr) = ty.array_info {
                            let elem_size = self.target_btf.type_size(arr.elem_type).unwrap_or(0);
                            total_bit_offset += (*index as u64) * (elem_size as u64) * 8;
                            current_type = arr.elem_type;
                        }
                    }
                }
            }
        }

        // Check if the final type is a bitfield (int with bitfield encoding)
        if let Some(member) = last_member {
            let ty = self.target_btf.resolve_type(member.type_id);
            if let Some(ty) = ty {
                if ty.kind == BtfKind::Int {
                    if let Some(ref enc) = ty.int_encoding {
                        let bit_size = enc.bits as u64;
                        let type_size = ty.size as u64;

                        // It's a bitfield if the bit size is less than type size * 8
                        // or if there's a bit offset within the type
                        if bit_size < type_size * 8 || enc.offset > 0 {
                            let load_size = type_size.max(1);
                            // Include the encoding offset in the total bit offset
                            let actual_bit_offset = total_bit_offset + enc.offset as u64;
                            return Ok(Some((actual_bit_offset, bit_size, load_size)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Relocate: target type ID
    fn relo_type_id_target(&mut self, local_type_id: u32) -> Result<CoreReloResult> {
        match self.find_target_type(local_type_id)? {
            Some(target_id) => Ok(CoreReloResult {
                success: true,
                new_val: target_id as u64,
                exists: true,
                error: None,
            }),
            None => Ok(CoreReloResult {
                success: false,
                new_val: 0,
                exists: false,
                error: Some("target type not found".into()),
            }),
        }
    }

    /// Relocate: type exists
    pub fn relo_type_exists(&mut self, local_type_id: u32) -> Result<CoreReloResult> {
        let exists = self.find_target_type(local_type_id)?.is_some();

        Ok(CoreReloResult {
            success: true,
            new_val: if exists { 1 } else { 0 },
            exists,
            error: None,
        })
    }

    /// Relocate: type size
    pub fn relo_type_size(&mut self, local_type_id: u32) -> Result<CoreReloResult> {
        match self.find_target_type(local_type_id)? {
            Some(target_id) => {
                let size = self.target_btf.type_size(target_id).unwrap_or(0);
                Ok(CoreReloResult {
                    success: true,
                    new_val: size as u64,
                    exists: true,
                    error: None,
                })
            }
            None => Ok(CoreReloResult {
                success: false,
                new_val: 0,
                exists: false,
                error: Some("target type not found".into()),
            }),
        }
    }

    /// Relocate: type matches
    pub fn relo_type_matches(
        &mut self,
        local_type_id: u32,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: true,
                    new_val: 0,
                    exists: false,
                    error: None,
                });
            }
        };

        // Compare types for compatibility
        let local_ty = self.local_btf.resolve_type(local_type_id);
        let target_ty = self.target_btf.resolve_type(target_id);

        let matches = match (local_ty, target_ty) {
            (Some(l), Some(t)) => {
                // Same kind and compatible structure
                l.kind == t.kind && self.types_compatible(l, t)
            }
            _ => false,
        };

        Ok(CoreReloResult {
            success: true,
            new_val: if matches { 1 } else { 0 },
            exists: matches,
            error: None,
        })
    }

    /// Check if two types are structurally compatible
    fn types_compatible(&self, local: &BtfType, target: &BtfType) -> bool {
        if local.kind != target.kind {
            return false;
        }

        match local.kind {
            BtfKind::Int => {
                // Same size and signedness
                local.size == target.size
            }
            BtfKind::Struct | BtfKind::Union => {
                // Same name (for named types)
                local.name == target.name
            }
            BtfKind::Ptr => true, // Pointers are always compatible
            BtfKind::Array => {
                // Same element type and count
                match (&local.array_info, &target.array_info) {
                    (Some(l), Some(t)) => l.nelems == t.nelems,
                    _ => false,
                }
            }
            _ => true,
        }
    }

    /// Relocate: enum value exists
    pub fn relo_enumval_exists(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: true,
                    new_val: 0,
                    exists: false,
                    error: None,
                });
            }
        };

        // Get enum value name from local spec
        let local_ty = self.local_btf.resolve_type(local_spec.type_id);
        let local_enum = match local_ty {
            Some(t) if t.kind == BtfKind::Enum || t.kind == BtfKind::Enum64 => t,
            _ => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("not an enum type".into()),
                });
            }
        };

        // Get the enum value index from access spec
        let value_idx = local_spec
            .access
            .first()
            .and_then(|c| match c {
                CoreAccessComponent::Field { index, .. } => Some(*index as usize),
                _ => None,
            })
            .unwrap_or(0);

        // Get the enum value name
        let _enum_name = local_enum.name.as_deref();

        // Check if the enum value exists in target
        let target_ty = self.target_btf.resolve_type(target_id);
        let exists = target_ty
            .map(|t| value_idx < t.members.len())
            .unwrap_or(false);

        Ok(CoreReloResult {
            success: true,
            new_val: if exists { 1 } else { 0 },
            exists,
            error: None,
        })
    }

    /// Relocate: enum value
    fn relo_enumval_value(
        &self,
        local_spec: &CoreAccessSpec,
        target_type_id: Option<u32>,
    ) -> Result<CoreReloResult> {
        let target_id = match target_type_id {
            Some(id) => id,
            None => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("target type not found".into()),
                });
            }
        };

        // Get enum value name from local spec
        let local_ty = self.local_btf.resolve_type(local_spec.type_id);
        let _local_enum = match local_ty {
            Some(t) if t.kind == BtfKind::Enum || t.kind == BtfKind::Enum64 => t,
            _ => {
                return Ok(CoreReloResult {
                    success: false,
                    new_val: 0,
                    exists: false,
                    error: Some("not an enum type".into()),
                });
            }
        };

        // Get the enum value index
        let value_idx = local_spec
            .access
            .first()
            .and_then(|c| match c {
                CoreAccessComponent::Field { index, .. } => Some(*index as usize),
                _ => None,
            })
            .unwrap_or(0);

        // Get the enum value from target
        let target_ty = self.target_btf.resolve_type(target_id);
        match target_ty {
            Some(t) if t.kind == BtfKind::Enum || t.kind == BtfKind::Enum64 => {
                // For enums, the "members" contain enum values
                // The offset field stores the enum value
                if value_idx < t.members.len() {
                    let value = t.members[value_idx].offset as u64;
                    Ok(CoreReloResult {
                        success: true,
                        new_val: value,
                        exists: true,
                        error: None,
                    })
                } else {
                    Ok(CoreReloResult {
                        success: false,
                        new_val: 0,
                        exists: false,
                        error: Some("enum value index out of range".into()),
                    })
                }
            }
            _ => Ok(CoreReloResult {
                success: false,
                new_val: 0,
                exists: false,
                error: Some("target is not an enum".into()),
            }),
        }
    }
}

/// Apply CO-RE relocations to BPF instructions
pub fn apply_core_relos(
    insns: &mut [BpfInsn],
    relos: &[BpfCoreRelo],
    local_btf: &Btf,
    target_btf: &Btf,
) -> Result<CoreReloStats> {
    let mut ctx = CoreReloContext::new(local_btf, target_btf);
    let mut stats = CoreReloStats::default();

    for relo in relos {
        let insn_idx = (relo.insn_off / 8) as usize;
        if insn_idx >= insns.len() {
            return Err(VerifierError::InvalidBtf(format!(
                "CO-RE relo insn offset {} out of range",
                relo.insn_off
            )));
        }

        let result = ctx.process_relo(relo)?;

        if result.success {
            // Apply the relocation to the instruction
            apply_relo_to_insn(&mut insns[insn_idx], relo, &result)?;
            stats.succeeded += 1;
        } else {
            stats.failed += 1;
            if let Some(ref err) = result.error {
                stats.errors.push(format!("insn {}: {}", insn_idx, err));
            }
        }
    }

    Ok(stats)
}

/// Apply a single relocation result to an instruction
fn apply_relo_to_insn(
    insn: &mut BpfInsn,
    relo: &BpfCoreRelo,
    result: &CoreReloResult,
) -> Result<()> {
    let kind = BpfCoreReloKind::try_from(relo.kind)
        .map_err(|_| VerifierError::InvalidBtf("invalid relo kind".into()))?;

    match kind {
        BpfCoreReloKind::FieldByteOffset
        | BpfCoreReloKind::FieldByteSize
        | BpfCoreReloKind::TypeSize
        | BpfCoreReloKind::EnumvalValue => {
            // Update the immediate value
            insn.imm = result.new_val as i32;
        }
        BpfCoreReloKind::FieldExists
        | BpfCoreReloKind::TypeExists
        | BpfCoreReloKind::TypeMatches
        | BpfCoreReloKind::EnumvalExists => {
            // For existence checks, the value is 0 or 1
            insn.imm = result.new_val as i32;
        }
        BpfCoreReloKind::FieldSigned => {
            // Signedness: 0 or 1
            insn.imm = result.new_val as i32;
        }
        BpfCoreReloKind::FieldLshift | BpfCoreReloKind::FieldRshift => {
            // Shift amounts for bitfields
            insn.imm = result.new_val as i32;
        }
        BpfCoreReloKind::TypeIdLocal | BpfCoreReloKind::TypeIdTarget => {
            // Type ID values
            insn.imm = result.new_val as i32;
        }
    }

    Ok(())
}

/// Statistics from CO-RE relocation processing
#[derive(Debug, Clone, Default)]
pub struct CoreReloStats {
    /// Number of successful relocations
    pub succeeded: usize,
    /// Number of failed relocations
    pub failed: usize,
    /// Error messages for failed relocations
    pub errors: Vec<String>,
}

impl CoreReloStats {
    /// Check if all relocations succeeded
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0
    }
}

// Note: String table methods (get_string, add_string, etc.) are defined in btf.rs
