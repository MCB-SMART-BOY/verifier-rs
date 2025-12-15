//! BTF function and line info verification
//!
//! This module implements verification of BTF function info, line info,
//! and CO-RE relocations. These correspond to the kernel's check_btf_func(),
//! check_btf_line(), and check_core_relo() functions.

#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use super::btf::{Btf, BtfKind};

/// Minimum size of bpf_func_info structure
pub const MIN_BPF_FUNCINFO_SIZE: usize = 8;
/// Maximum size of func info record
pub const MAX_FUNCINFO_REC_SIZE: usize = 256;

/// Minimum size of bpf_line_info structure
pub const MIN_BPF_LINEINFO_SIZE: usize = 16;
/// Maximum size of line info record
pub const MAX_LINEINFO_REC_SIZE: usize = 256;

/// Minimum size of bpf_core_relo structure
pub const MIN_CORE_RELO_SIZE: usize = 16;
/// Maximum size of CO-RE relo record
pub const MAX_CORE_RELO_SIZE: usize = 256;

/// Function info entry
#[derive(Debug, Clone, Default)]
pub struct BpfFuncInfo {
    /// Instruction offset (in bytes, must be 8-byte aligned)
    pub insn_off: u32,
    /// BTF type ID of the function
    pub type_id: u32,
}

/// Line info entry
#[derive(Debug, Clone, Default)]
pub struct BpfLineInfo {
    /// Instruction offset
    pub insn_off: u32,
    /// File name offset in BTF string table
    pub file_name_off: u32,
    /// Line number (with column encoded in high bits)
    pub line_off: u32,
    /// Column info
    pub line_col: u32,
}

impl BpfLineInfo {
    /// Get line number
    pub fn line_num(&self) -> u32 {
        self.line_off >> 10
    }

    /// Get column number
    pub fn col_num(&self) -> u32 {
        self.line_col & 0x3ff
    }
}

/// CO-RE relocation kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfCoreReloKind {
    /// Field byte offset
    FieldByteOffset = 0,
    /// Field byte size
    FieldByteSize = 1,
    /// Field existence
    FieldExists = 2,
    /// Field signedness
    FieldSigned = 3,
    /// Field left shift (for bitfields)
    FieldLshift = 4,
    /// Field right shift (for bitfields)
    FieldRshift = 5,
    /// Type ID (local)
    TypeIdLocal = 6,
    /// Type ID (target)
    TypeIdTarget = 7,
    /// Type existence
    TypeExists = 8,
    /// Type size
    TypeSize = 9,
    /// Enum value existence
    EnumvalExists = 10,
    /// Enum value
    EnumvalValue = 11,
    /// Type matches
    TypeMatches = 12,
}

impl TryFrom<u32> for BpfCoreReloKind {
    type Error = ();

    fn try_from(value: u32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(BpfCoreReloKind::FieldByteOffset),
            1 => Ok(BpfCoreReloKind::FieldByteSize),
            2 => Ok(BpfCoreReloKind::FieldExists),
            3 => Ok(BpfCoreReloKind::FieldSigned),
            4 => Ok(BpfCoreReloKind::FieldLshift),
            5 => Ok(BpfCoreReloKind::FieldRshift),
            6 => Ok(BpfCoreReloKind::TypeIdLocal),
            7 => Ok(BpfCoreReloKind::TypeIdTarget),
            8 => Ok(BpfCoreReloKind::TypeExists),
            9 => Ok(BpfCoreReloKind::TypeSize),
            10 => Ok(BpfCoreReloKind::EnumvalExists),
            11 => Ok(BpfCoreReloKind::EnumvalValue),
            12 => Ok(BpfCoreReloKind::TypeMatches),
            _ => Err(()),
        }
    }
}

/// CO-RE relocation entry
#[derive(Debug, Clone, Default)]
pub struct BpfCoreRelo {
    /// Instruction offset
    pub insn_off: u32,
    /// Type ID in local BTF
    pub type_id: u32,
    /// Access string offset in BTF string table
    pub access_str_off: u32,
    /// Relocation kind
    pub kind: u32,
}

/// Verified function info
#[derive(Debug, Clone)]
pub struct VerifiedFuncInfo {
    /// Subprogram index
    pub subprog_idx: usize,
    /// BTF function type
    pub btf_id: u32,
    /// Number of parameters
    pub nr_params: usize,
    /// Parameter types
    pub param_btf_ids: Vec<u32>,
    /// Return type
    pub ret_btf_id: u32,
    /// Function name
    pub name: String,
}

/// BTF info verifier
pub struct BtfInfoVerifier<'a> {
    /// Reference to BTF data
    btf: Option<&'a Btf>,
    /// Program instructions
    insns: &'a [BpfInsn],
    /// Subprogram info
    subprogs: &'a [SubprogInfo],
    /// Verified function info
    func_info: Vec<VerifiedFuncInfo>,
    /// Line info (instruction index -> line info)
    line_info: HashMap<usize, BpfLineInfo>,
}

/// Subprogram information (simplified)
#[derive(Debug, Clone)]
pub struct SubprogInfo {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (exclusive)
    pub end: usize,
    /// Stack depth
    pub stack_depth: i32,
    /// Is global function
    pub is_global: bool,
    /// Is async callback
    pub is_async_cb: bool,
    /// Is exception callback
    pub is_exception_cb: bool,
}

impl<'a> BtfInfoVerifier<'a> {
    /// Create a new BTF info verifier
    pub fn new(
        btf: Option<&'a Btf>,
        insns: &'a [BpfInsn],
        subprogs: &'a [SubprogInfo],
    ) -> Self {
        Self {
            btf,
            insns,
            subprogs,
            func_info: Vec::new(),
            line_info: HashMap::new(),
        }
    }

    /// Check BTF function info (early pass)
    ///
    /// This corresponds to kernel's check_btf_func_early().
    /// Validates that func_info entries are properly formatted and
    /// correspond to valid subprogram boundaries.
    pub fn check_btf_func_early(
        &mut self,
        func_info: &[BpfFuncInfo],
        func_info_rec_size: usize,
    ) -> Result<()> {
        if func_info.is_empty() {
            return Ok(());
        }

        // Validate record size
        if func_info_rec_size < MIN_BPF_FUNCINFO_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "func_info_rec_size {} too small, min {}",
                func_info_rec_size, MIN_BPF_FUNCINFO_SIZE
            )));
        }
        if func_info_rec_size > MAX_FUNCINFO_REC_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "func_info_rec_size {} too large, max {}",
                func_info_rec_size, MAX_FUNCINFO_REC_SIZE
            )));
        }

        let btf = self.btf.ok_or_else(|| {
            VerifierError::InvalidBtf("func_info requires BTF".into())
        })?;

        // First entry must be at instruction 0
        if func_info[0].insn_off != 0 {
            return Err(VerifierError::InvalidBtf(
                "first func_info must be at insn 0".into()
            ));
        }

        let mut prev_off = 0u32;
        for (i, info) in func_info.iter().enumerate() {
            // Check alignment
            if info.insn_off % 8 != 0 {
                return Err(VerifierError::InvalidBtf(format!(
                    "func_info[{}].insn_off {} not 8-byte aligned",
                    i, info.insn_off
                )));
            }

            // Check ordering (must be strictly increasing)
            if i > 0 && info.insn_off <= prev_off {
                return Err(VerifierError::InvalidBtf(format!(
                    "func_info[{}].insn_off {} not greater than previous {}",
                    i, info.insn_off, prev_off
                )));
            }
            prev_off = info.insn_off;

            // Convert byte offset to instruction index
            let insn_idx = (info.insn_off / 8) as usize;
            if insn_idx >= self.insns.len() {
                return Err(VerifierError::InvalidBtf(format!(
                    "func_info[{}].insn_off {} out of range",
                    i, info.insn_off
                )));
            }

            // Check type ID points to a BTF_KIND_FUNC
            let btf_type = btf.get_type(info.type_id).ok_or_else(|| {
                VerifierError::InvalidBtf(format!(
                    "func_info[{}].type_id {} not found",
                    i, info.type_id
                ))
            })?;

            if btf_type.kind != BtfKind::Func {
                return Err(VerifierError::InvalidBtf(format!(
                    "func_info[{}].type_id {} is {:?}, expected FUNC",
                    i, info.type_id, btf_type.kind
                )));
            }
        }

        Ok(())
    }

    /// Check BTF function info (full pass)
    ///
    /// This corresponds to kernel's check_btf_func().
    /// Validates function signatures match actual subprogram usage.
    pub fn check_btf_func(
        &mut self,
        func_info: &[BpfFuncInfo],
    ) -> Result<()> {
        if func_info.is_empty() {
            return Ok(());
        }

        let btf = self.btf.ok_or_else(|| {
            VerifierError::InvalidBtf("func_info requires BTF".into())
        })?;

        // Number of func_info entries should match subprogram count
        if func_info.len() != self.subprogs.len() {
            return Err(VerifierError::InvalidBtf(format!(
                "func_info count {} != subprog count {}",
                func_info.len(), self.subprogs.len()
            )));
        }

        for (i, info) in func_info.iter().enumerate() {
            let insn_idx = (info.insn_off / 8) as usize;
            
            // Find corresponding subprog
            let subprog_idx = self.subprogs.iter()
                .position(|sp| sp.start == insn_idx)
                .ok_or_else(|| {
                    VerifierError::InvalidBtf(format!(
                        "func_info[{}] at insn {} doesn't match any subprog start",
                        i, insn_idx
                    ))
                })?;

            // Get function type
            let func_type = btf.get_type(info.type_id).ok_or_else(|| {
                VerifierError::InvalidBtf(format!(
                    "func_info[{}].type_id {} not found",
                    i, info.type_id
                ))
            })?;

            // Get function prototype
            let proto_type = btf.get_type(func_type.type_ref).ok_or_else(|| {
                VerifierError::InvalidBtf(format!(
                    "func {} proto type {} not found",
                    info.type_id, func_type.type_ref
                ))
            })?;

            if proto_type.kind != BtfKind::FuncProto {
                return Err(VerifierError::InvalidBtf(format!(
                    "func {} proto {} is {:?}, expected FUNC_PROTO",
                    info.type_id, func_type.type_ref, proto_type.kind
                )));
            }

            // Extract parameter types
            let param_btf_ids: Vec<u32> = proto_type.params
                .iter()
                .map(|p| p.type_id)
                .collect();

            // Store verified info
            self.func_info.push(VerifiedFuncInfo {
                subprog_idx,
                btf_id: info.type_id,
                nr_params: proto_type.params.len(),
                param_btf_ids,
                ret_btf_id: proto_type.type_ref,
                name: func_type.name.clone().unwrap_or_default(),
            });
        }

        Ok(())
    }

    /// Check BTF line info
    ///
    /// This corresponds to kernel's check_btf_line().
    pub fn check_btf_line(
        &mut self,
        line_info: &[BpfLineInfo],
        line_info_rec_size: usize,
    ) -> Result<()> {
        if line_info.is_empty() {
            return Ok(());
        }

        // Validate record size
        if line_info_rec_size < MIN_BPF_LINEINFO_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "line_info_rec_size {} too small, min {}",
                line_info_rec_size, MIN_BPF_LINEINFO_SIZE
            )));
        }
        if line_info_rec_size > MAX_LINEINFO_REC_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "line_info_rec_size {} too large, max {}",
                line_info_rec_size, MAX_LINEINFO_REC_SIZE
            )));
        }

        if self.btf.is_none() {
            return Err(VerifierError::InvalidBtf(
                "line_info requires BTF".into()
            ));
        }

        let mut prev_off = 0u32;
        let mut prev_subprog = 0usize;

        for (i, info) in line_info.iter().enumerate() {
            // Check alignment
            if info.insn_off % 8 != 0 {
                return Err(VerifierError::InvalidBtf(format!(
                    "line_info[{}].insn_off {} not 8-byte aligned",
                    i, info.insn_off
                )));
            }

            let insn_idx = (info.insn_off / 8) as usize;
            if insn_idx >= self.insns.len() {
                return Err(VerifierError::InvalidBtf(format!(
                    "line_info[{}].insn_off {} out of range",
                    i, info.insn_off
                )));
            }

            // Find which subprog this belongs to
            let subprog = self.subprogs.iter()
                .enumerate()
                .find(|(_, sp)| insn_idx >= sp.start && insn_idx < sp.end)
                .map(|(idx, _)| idx)
                .unwrap_or(0);

            // Line info must be ordered within each subprog
            if subprog == prev_subprog {
                if i > 0 && info.insn_off < prev_off {
                    return Err(VerifierError::InvalidBtf(format!(
                        "line_info[{}].insn_off {} < previous {} in same subprog",
                        i, info.insn_off, prev_off
                    )));
                }
            }

            prev_off = info.insn_off;
            prev_subprog = subprog;

            // Store line info
            self.line_info.insert(insn_idx, info.clone());
        }

        Ok(())
    }

    /// Check CO-RE relocations
    ///
    /// This corresponds to kernel's check_core_relo().
    pub fn check_core_relo(
        &self,
        relos: &[BpfCoreRelo],
        relo_rec_size: usize,
    ) -> Result<()> {
        if relos.is_empty() {
            return Ok(());
        }

        // Validate record size
        if relo_rec_size < MIN_CORE_RELO_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "core_relo_rec_size {} too small, min {}",
                relo_rec_size, MIN_CORE_RELO_SIZE
            )));
        }
        if relo_rec_size > MAX_CORE_RELO_SIZE {
            return Err(VerifierError::InvalidBtf(format!(
                "core_relo_rec_size {} too large, max {}",
                relo_rec_size, MAX_CORE_RELO_SIZE
            )));
        }

        let btf = self.btf.ok_or_else(|| {
            VerifierError::InvalidBtf("core_relo requires BTF".into())
        })?;

        for (i, relo) in relos.iter().enumerate() {
            // Validate instruction offset
            if relo.insn_off % 8 != 0 {
                return Err(VerifierError::InvalidBtf(format!(
                    "core_relo[{}].insn_off {} not 8-byte aligned",
                    i, relo.insn_off
                )));
            }

            let insn_idx = (relo.insn_off / 8) as usize;
            if insn_idx >= self.insns.len() {
                return Err(VerifierError::InvalidBtf(format!(
                    "core_relo[{}].insn_off {} out of range",
                    i, relo.insn_off
                )));
            }

            // Validate type ID
            if relo.type_id == 0 {
                return Err(VerifierError::InvalidBtf(format!(
                    "core_relo[{}].type_id is 0",
                    i
                )));
            }

            btf.get_type(relo.type_id).ok_or_else(|| {
                VerifierError::InvalidBtf(format!(
                    "core_relo[{}].type_id {} not found",
                    i, relo.type_id
                ))
            })?;

            // Validate relocation kind
            BpfCoreReloKind::try_from(relo.kind).map_err(|_| {
                VerifierError::InvalidBtf(format!(
                    "core_relo[{}].kind {} invalid",
                    i, relo.kind
                ))
            })?;
        }

        Ok(())
    }

    /// Get verified function info for a subprogram
    pub fn get_func_info(&self, subprog_idx: usize) -> Option<&VerifiedFuncInfo> {
        self.func_info.iter().find(|f| f.subprog_idx == subprog_idx)
    }

    /// Get line info for an instruction
    pub fn get_line_info(&self, insn_idx: usize) -> Option<&BpfLineInfo> {
        self.line_info.get(&insn_idx)
    }

    /// Get all verified function info
    pub fn all_func_info(&self) -> &[VerifiedFuncInfo] {
        &self.func_info
    }
}

/// Adjust BTF function info after instruction patching
///
/// This corresponds to kernel's adjust_btf_func().
pub fn adjust_btf_func(
    func_info: &mut [BpfFuncInfo],
    off: usize,
    delta: i32,
) {
    let off_bytes = (off * 8) as u32;
    
    for info in func_info.iter_mut() {
        if info.insn_off > off_bytes {
            if delta > 0 {
                info.insn_off += (delta * 8) as u32;
            } else {
                info.insn_off -= ((-delta) * 8) as u32;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_func_info_basic() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let subprogs = vec![SubprogInfo {
            start: 0,
            end: 2,
            stack_depth: 0,
            is_global: false,
            is_async_cb: false,
            is_exception_cb: false,
        }];

        let mut verifier = BtfInfoVerifier::new(None, &insns, &subprogs);
        
        // Empty func_info should pass
        let result = verifier.check_btf_func_early(&[], MIN_BPF_FUNCINFO_SIZE);
        assert!(result.is_ok());
    }

    #[test]
    fn test_line_info_alignment() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let subprogs = vec![SubprogInfo {
            start: 0,
            end: 2,
            stack_depth: 0,
            is_global: false,
            is_async_cb: false,
            is_exception_cb: false,
        }];

        let mut verifier = BtfInfoVerifier::new(None, &insns, &subprogs);
        
        // Misaligned offset should fail
        let bad_line_info = vec![BpfLineInfo {
            insn_off: 3, // Not 8-byte aligned
            file_name_off: 0,
            line_off: 0,
            line_col: 0,
        }];
        
        let result = verifier.check_btf_line(&bad_line_info, MIN_BPF_LINEINFO_SIZE);
        assert!(result.is_err());
    }

    #[test]
    fn test_core_relo_kind() {
        assert_eq!(
            BpfCoreReloKind::try_from(0),
            Ok(BpfCoreReloKind::FieldByteOffset)
        );
        assert_eq!(
            BpfCoreReloKind::try_from(9),
            Ok(BpfCoreReloKind::TypeSize)
        );
        assert!(BpfCoreReloKind::try_from(100).is_err());
    }
}
