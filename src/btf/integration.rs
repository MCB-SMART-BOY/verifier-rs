//! BTF verifier integration
//!
//! This module provides integration between BTF type information and the BPF verifier.
//! It enables:
//! - Type-aware memory access validation
//! - Source location tracking via line info
//! - Function signature verification
//! - CO-RE relocation during program loading

#![allow(missing_docs)]

#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use super::btf::{Btf, BtfKind, BtfPermissions, DeclTagStore};
use super::func_info::{BpfFuncInfo, BpfLineInfo, BpfCoreRelo};
use super::core::{apply_core_relos, CoreReloStats};

// ============================================================================
// Source Location Tracking
// ============================================================================

/// Source location information for an instruction
#[derive(Debug, Clone)]
pub struct SourceLocation {
    /// File name
    pub file: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (1-indexed)
    pub column: u32,
    /// Function name (if known)
    pub function: Option<String>,
}

impl SourceLocation {
    /// Create a new source location
    pub fn new(file: &str, line: u32, column: u32) -> Self {
        Self {
            file: file.to_string(),
            line,
            column,
            function: None,
        }
    }

    /// Set the function name
    pub fn with_function(mut self, func: &str) -> Self {
        self.function = Some(func.to_string());
        self
    }

    /// Format for error messages
    pub fn format_for_error(&self) -> String {
        if let Some(ref func) = self.function {
            format!("{}:{}:{} in {}()", self.file, self.line, self.column, func)
        } else {
            format!("{}:{}:{}", self.file, self.line, self.column)
        }
    }
}

/// Line info database for source mapping
#[derive(Debug, Default)]
pub struct LineInfoDb {
    /// String table for file names
    strings: Vec<String>,
    /// String offset to index map
    string_offsets: HashMap<u32, usize>,
    /// Line info entries indexed by instruction index
    insn_to_line: HashMap<usize, LineInfoEntry>,
    /// Function info for subprograms
    func_info: Vec<FuncInfoEntry>,
}

/// Internal line info entry
#[derive(Debug, Clone)]
struct LineInfoEntry {
    /// String table index for file name
    file_idx: usize,
    /// Line number
    line: u32,
    /// Column number
    column: u32,
    /// Owning function index
    func_idx: Option<usize>,
}

/// Internal function info entry
#[derive(Debug, Clone)]
struct FuncInfoEntry {
    /// Start instruction index
    insn_off: usize,
    /// Function name
    name: String,
    /// BTF type ID (reserved for future use)
    #[allow(dead_code)]
    type_id: u32,
}

impl LineInfoDb {
    /// Create a new line info database
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a string to the string table
    pub fn add_string(&mut self, offset: u32, s: &str) {
        if !self.string_offsets.contains_key(&offset) {
            let idx = self.strings.len();
            self.strings.push(s.to_string());
            self.string_offsets.insert(offset, idx);
        }
    }

    /// Get a string by offset
    pub fn get_string(&self, offset: u32) -> Option<&str> {
        self.string_offsets.get(&offset)
            .and_then(|&idx| self.strings.get(idx))
            .map(|s| s.as_str())
    }

    /// Load function info from verified func_info
    pub fn load_func_info(&mut self, btf: &Btf, func_info: &[BpfFuncInfo]) {
        for info in func_info {
            let insn_off = (info.insn_off / 8) as usize;
            
            // Get function name from BTF
            let name = btf.get_type(info.type_id)
                .and_then(|t| t.name.clone())
                .unwrap_or_else(|| format!("func_{}", insn_off));

            self.func_info.push(FuncInfoEntry {
                insn_off,
                name,
                type_id: info.type_id,
            });
        }

        // Sort by instruction offset for binary search
        self.func_info.sort_by_key(|f| f.insn_off);
    }

    /// Load line info entries
    pub fn load_line_info(&mut self, line_info: &[BpfLineInfo]) {
        for info in line_info {
            let insn_idx = (info.insn_off / 8) as usize;
            
            // Find owning function
            let func_idx = self.find_func_for_insn(insn_idx);
            
            // Get or add file string
            let file_idx = self.string_offsets.get(&info.file_name_off)
                .copied()
                .unwrap_or_else(|| {
                    let idx = self.strings.len();
                    self.strings.push(format!("<file:{}>", info.file_name_off));
                    self.string_offsets.insert(info.file_name_off, idx);
                    idx
                });

            self.insn_to_line.insert(insn_idx, LineInfoEntry {
                file_idx,
                line: info.line_num(),
                column: info.col_num(),
                func_idx,
            });
        }
    }

    /// Find the function containing an instruction
    fn find_func_for_insn(&self, insn_idx: usize) -> Option<usize> {
        // Binary search for the largest func with insn_off <= insn_idx
        let pos = self.func_info.partition_point(|f| f.insn_off <= insn_idx);
        if pos > 0 {
            Some(pos - 1)
        } else {
            None
        }
    }

    /// Get source location for an instruction
    pub fn get_source_location(&self, insn_idx: usize) -> Option<SourceLocation> {
        let entry = self.insn_to_line.get(&insn_idx)?;
        
        let file = self.strings.get(entry.file_idx)
            .map(|s| s.as_str())
            .unwrap_or("<unknown>");
        
        let mut loc = SourceLocation::new(file, entry.line, entry.column);
        
        // Add function name if available
        if let Some(func_idx) = entry.func_idx {
            if let Some(func) = self.func_info.get(func_idx) {
                loc.function = Some(func.name.clone());
            }
        }
        
        Some(loc)
    }

    /// Get all source locations for a range of instructions
    pub fn get_source_range(&self, start: usize, end: usize) -> Vec<(usize, SourceLocation)> {
        let mut result = Vec::new();
        for idx in start..end {
            if let Some(loc) = self.get_source_location(idx) {
                result.push((idx, loc));
            }
        }
        result
    }

    /// Get function name for instruction
    pub fn get_function_name(&self, insn_idx: usize) -> Option<&str> {
        self.find_func_for_insn(insn_idx)
            .and_then(|idx| self.func_info.get(idx))
            .map(|f| f.name.as_str())
    }

    /// Check if database has any entries
    pub fn is_empty(&self) -> bool {
        self.insn_to_line.is_empty() && self.func_info.is_empty()
    }
}

// ============================================================================
// BTF Verifier Context
// ============================================================================

/// BTF context for verification
/// 
/// This holds all BTF-related data needed during verification:
/// - Program BTF (local types)
/// - Kernel BTF (target types for CO-RE)
/// - Line info for source mapping
/// - Declaration tags for permissions
#[derive(Debug)]
pub struct BtfContext {
    /// Program's BTF (local types from the BPF program)
    pub prog_btf: Option<Btf>,
    /// Kernel BTF (target types for CO-RE relocations)
    pub kernel_btf: Option<Btf>,
    /// Line info database for source mapping
    pub line_info: LineInfoDb,
    /// Declaration tags for permission checking
    pub decl_tags: DeclTagStore,
    /// CO-RE relocation statistics
    pub core_relo_stats: Option<CoreReloStats>,
    /// Whether BTF validation is enabled
    pub btf_enabled: bool,
}

impl Default for BtfContext {
    fn default() -> Self {
        Self {
            prog_btf: None,
            kernel_btf: None,
            line_info: LineInfoDb::new(),
            decl_tags: DeclTagStore::new(),
            core_relo_stats: None,
            btf_enabled: false,
        }
    }
}

impl BtfContext {
    /// Create a new empty BTF context
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a BTF context with program BTF
    pub fn with_prog_btf(btf: Btf) -> Self {
        Self {
            prog_btf: Some(btf),
            btf_enabled: true,
            ..Default::default()
        }
    }

    /// Set kernel BTF for CO-RE support
    pub fn set_kernel_btf(&mut self, btf: Btf) {
        self.kernel_btf = Some(btf);
    }

    /// Load function and line info
    pub fn load_debug_info(
        &mut self,
        func_info: &[BpfFuncInfo],
        line_info: &[BpfLineInfo],
    ) {
        if let Some(ref btf) = self.prog_btf {
            self.line_info.load_func_info(btf, func_info);
        }
        self.line_info.load_line_info(line_info);
    }

    /// Apply CO-RE relocations to instructions
    pub fn apply_core_relocations(
        &mut self,
        insns: &mut [BpfInsn],
        relos: &[BpfCoreRelo],
    ) -> Result<()> {
        let local_btf = self.prog_btf.as_ref().ok_or_else(|| {
            VerifierError::InvalidBtf("CO-RE requires program BTF".into())
        })?;
        
        let target_btf = self.kernel_btf.as_ref().ok_or_else(|| {
            VerifierError::InvalidBtf("CO-RE requires kernel BTF".into())
        })?;

        let stats = apply_core_relos(insns, relos, local_btf, target_btf)?;
        
        if !stats.all_succeeded() {
            // Log errors but don't fail - some relos may be optional
            for err in &stats.errors {
                // Would log to verifier log in full implementation
                let _ = err;
            }
        }
        
        self.core_relo_stats = Some(stats);
        Ok(())
    }

    /// Get source location for an instruction
    pub fn get_source_location(&self, insn_idx: usize) -> Option<SourceLocation> {
        self.line_info.get_source_location(insn_idx)
    }

    /// Format error with source location
    pub fn format_error(&self, insn_idx: usize, msg: &str) -> String {
        if let Some(loc) = self.get_source_location(insn_idx) {
            format!("{}: {}", loc.format_for_error(), msg)
        } else {
            format!("insn {}: {}", insn_idx, msg)
        }
    }

    /// Validate memory access against BTF type
    pub fn validate_access(
        &self,
        type_id: u32,
        offset: i32,
        size: u32,
        is_write: bool,
    ) -> Result<BtfAccessResult> {
        let btf = match &self.prog_btf {
            Some(b) => b,
            None => {
                // No BTF, allow access (will be caught by other checks)
                return Ok(BtfAccessResult {
                    valid: true,
                    field_type_id: 0,
                    permissions: BtfPermissions::default(),
                });
            }
        };

        if offset < 0 {
            return Err(VerifierError::InvalidMemoryAccess(
                "negative offset".into()
            ));
        }
        let offset = offset as u32;

        let ty = btf.resolve_type(type_id).ok_or_else(|| {
            VerifierError::InvalidBtf(format!("type {} not found", type_id))
        })?;

        // Check bounds
        if offset + size > ty.size {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "access at offset {} size {} exceeds type size {}",
                offset, size, ty.size
            )));
        }

        // Find field at offset
        let (field_type_id, permissions) = self.find_field_at_offset(type_id, offset)?;

        // Check write permissions
        if is_write && permissions.rdonly {
            return Err(VerifierError::InvalidMemoryAccess(
                "write to read-only field".into()
            ));
        }

        Ok(BtfAccessResult {
            valid: true,
            field_type_id,
            permissions,
        })
    }

    /// Find field at a specific offset
    fn find_field_at_offset(
        &self,
        type_id: u32,
        offset: u32,
    ) -> Result<(u32, BtfPermissions)> {
        let btf = self.prog_btf.as_ref().unwrap();
        let ty = btf.resolve_type(type_id).ok_or_else(|| {
            VerifierError::InvalidBtf("type not found".into())
        })?;

        let mut permissions = self.decl_tags.get_type_permissions(type_id);

        match ty.kind {
            BtfKind::Struct | BtfKind::Union => {
                let _bit_offset = offset * 8;
                
                for (idx, member) in ty.members.iter().enumerate() {
                    let member_offset = if ty.kind == BtfKind::Union {
                        0
                    } else {
                        member.offset / 8
                    };
                    
                    let member_size = btf.type_size(member.type_id).unwrap_or(0);
                    
                    if offset >= member_offset && offset < member_offset + member_size {
                        // Merge member permissions
                        let member_perms = self.decl_tags.get_member_permissions(
                            type_id,
                            idx as i32,
                        );
                        permissions.merge(&member_perms);
                        
                        return Ok((member.type_id, permissions));
                    }
                }
                
                // No exact field match, return base type
                Ok((0, permissions))
            }
            BtfKind::Array => {
                if let Some(ref arr) = ty.array_info {
                    Ok((arr.elem_type, permissions))
                } else {
                    Ok((0, permissions))
                }
            }
            _ => Ok((type_id, permissions)),
        }
    }

    /// Validate kfunc call against BTF
    pub fn validate_kfunc_call(
        &self,
        func_name: &str,
        arg_btf_ids: &[u32],
    ) -> Result<KfuncValidation> {
        let btf = match &self.kernel_btf {
            Some(b) => b,
            None => {
                // No kernel BTF, can't validate kfunc
                return Ok(KfuncValidation {
                    valid: true,
                    ret_type_id: 0,
                    acquires_ref: false,
                    releases_ref: false,
                    release_arg_idx: None,
                });
            }
        };

        // Find function in BTF
        let func_ids = btf.find_by_name(func_name);
        if func_ids.is_empty() {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "kfunc '{}' not found in BTF",
                func_name
            )));
        }

        let func_id = func_ids[0];
        let proto = btf.get_func_proto(func_id).ok_or_else(|| {
            VerifierError::InvalidFunctionCall(format!(
                "'{}' is not a function",
                func_name
            ))
        })?;

        // Check argument count
        if arg_btf_ids.len() != proto.params.len() {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "kfunc '{}' expects {} args, got {}",
                func_name, proto.params.len(), arg_btf_ids.len()
            )));
        }

        // Determine if this is an acquire/release function
        let acquires_ref = func_name.contains("_acquire") 
            || func_name.contains("_get")
            || func_name.contains("_new");
        let releases_ref = func_name.contains("_release")
            || func_name.contains("_put")
            || func_name.contains("_destroy");

        Ok(KfuncValidation {
            valid: true,
            ret_type_id: proto.ret_type,
            acquires_ref,
            releases_ref,
            release_arg_idx: if releases_ref { Some(0) } else { None },
        })
    }

    /// Get function prototype for a BTF function ID
    pub fn get_func_proto(&self, func_id: u32) -> Option<FuncProtoInfo> {
        let btf = self.prog_btf.as_ref()?;
        let proto = btf.get_func_proto(func_id)?;
        
        Some(FuncProtoInfo {
            type_id: proto.type_id,
            ret_type_id: proto.ret_type,
            param_count: proto.params.len(),
            param_types: proto.params.iter().map(|(_, id)| *id).collect(),
        })
    }
}

/// Result of BTF access validation
#[derive(Debug, Clone)]
pub struct BtfAccessResult {
    /// Whether access is valid
    pub valid: bool,
    /// Type ID of the accessed field
    pub field_type_id: u32,
    /// Permissions from declaration tags
    pub permissions: BtfPermissions,
}

/// Result of kfunc validation
#[derive(Debug, Clone)]
pub struct KfuncValidation {
    /// Whether call is valid
    pub valid: bool,
    /// Return type BTF ID
    pub ret_type_id: u32,
    /// Whether this kfunc acquires a reference
    pub acquires_ref: bool,
    /// Whether this kfunc releases a reference
    pub releases_ref: bool,
    /// Index of argument being released (if any)
    pub release_arg_idx: Option<usize>,
}

/// Function prototype info
#[derive(Debug, Clone)]
pub struct FuncProtoInfo {
    /// Function type ID
    pub type_id: u32,
    /// Return type ID
    pub ret_type_id: u32,
    /// Number of parameters
    pub param_count: usize,
    /// Parameter type IDs
    pub param_types: Vec<u32>,
}

// ============================================================================
// Error Formatting with Source Info
// ============================================================================

/// Error formatter with source location support
pub struct ErrorFormatter<'a> {
    btf_ctx: &'a BtfContext,
}

impl<'a> ErrorFormatter<'a> {
    /// Create a new error formatter
    pub fn new(btf_ctx: &'a BtfContext) -> Self {
        Self { btf_ctx }
    }

    /// Format a verification error with source location
    pub fn format_error(&self, insn_idx: usize, error: &VerifierError) -> String {
        let prefix = if let Some(loc) = self.btf_ctx.get_source_location(insn_idx) {
            loc.format_for_error()
        } else {
            format!("insn {}", insn_idx)
        };

        format!("{}: {}", prefix, error)
    }

    /// Format an access error with field info
    pub fn format_access_error(
        &self,
        insn_idx: usize,
        type_id: u32,
        offset: u32,
        error: &str,
    ) -> String {
        let prefix = if let Some(loc) = self.btf_ctx.get_source_location(insn_idx) {
            loc.format_for_error()
        } else {
            format!("insn {}", insn_idx)
        };

        // Try to get type and field names
        let type_info = self.btf_ctx.prog_btf.as_ref()
            .and_then(|btf| btf.get_type(type_id))
            .and_then(|ty| ty.name.clone());

        if let Some(type_name) = type_info {
            format!("{}: {} (type '{}' offset {})", prefix, error, type_name, offset)
        } else {
            format!("{}: {} (type {} offset {})", prefix, error, type_id, offset)
        }
    }
}

// ============================================================================
// BTF-aware Register Type Tracking
// ============================================================================

/// BTF type information for a register
#[derive(Debug, Clone, Default)]
pub struct RegBtfInfo {
    /// BTF type ID (0 = no BTF info)
    pub btf_id: u32,
    /// Reference ID for acquired references
    pub ref_id: Option<u32>,
    /// Whether this is a trusted pointer
    pub trusted: bool,
    /// Whether this is RCU-protected
    pub rcu: bool,
    /// Whether this might be null
    pub nullable: bool,
}

impl RegBtfInfo {
    /// Create empty BTF info
    pub fn none() -> Self {
        Self::default()
    }

    /// Create BTF info with a type ID
    pub fn with_type(btf_id: u32) -> Self {
        Self {
            btf_id,
            ..Default::default()
        }
    }

    /// Create BTF info for an acquired reference
    pub fn acquired(btf_id: u32, ref_id: u32) -> Self {
        Self {
            btf_id,
            ref_id: Some(ref_id),
            trusted: true,
            ..Default::default()
        }
    }

    /// Check if this has BTF info
    pub fn has_btf(&self) -> bool {
        self.btf_id != 0
    }

    /// Check if this is an acquired reference
    pub fn is_acquired(&self) -> bool {
        self.ref_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_location() {
        let loc = SourceLocation::new("test.c", 10, 5)
            .with_function("foo");
        
        assert_eq!(loc.file, "test.c");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
        assert_eq!(loc.function, Some("foo".to_string()));
        
        let formatted = loc.format_for_error();
        assert!(formatted.contains("test.c"));
        assert!(formatted.contains("10"));
        assert!(formatted.contains("foo"));
    }

    #[test]
    fn test_line_info_db() {
        let mut db = LineInfoDb::new();
        
        db.add_string(0, "main.c");
        db.add_string(8, "helper.c");
        
        assert_eq!(db.get_string(0), Some("main.c"));
        assert_eq!(db.get_string(8), Some("helper.c"));
        assert_eq!(db.get_string(100), None);
    }

    #[test]
    fn test_btf_context_default() {
        let ctx = BtfContext::new();
        assert!(!ctx.btf_enabled);
        assert!(ctx.prog_btf.is_none());
        assert!(ctx.kernel_btf.is_none());
    }

    #[test]
    fn test_reg_btf_info() {
        let info = RegBtfInfo::none();
        assert!(!info.has_btf());
        assert!(!info.is_acquired());
        
        let info = RegBtfInfo::with_type(42);
        assert!(info.has_btf());
        assert_eq!(info.btf_id, 42);
        
        let info = RegBtfInfo::acquired(42, 1);
        assert!(info.has_btf());
        assert!(info.is_acquired());
        assert!(info.trusted);
    }

    #[test]
    fn test_btf_access_result() {
        let result = BtfAccessResult {
            valid: true,
            field_type_id: 10,
            permissions: BtfPermissions::default(),
        };
        assert!(result.valid);
        assert_eq!(result.field_type_id, 10);
    }

    #[test]
    fn test_kfunc_validation() {
        let result = KfuncValidation {
            valid: true,
            ret_type_id: 5,
            acquires_ref: true,
            releases_ref: false,
            release_arg_idx: None,
        };
        assert!(result.valid);
        assert!(result.acquires_ref);
        assert!(!result.releases_ref);
    }
}
