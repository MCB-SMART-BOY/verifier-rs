//!

//! This module implements verification for BPF map operations including

//! lookup, update, delete, and iteration.



use alloc::{format, vec::Vec};

use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::error::{Result, VerifierError};


/// Map operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapOpType {
    /// Lookup a key in the map
    Lookup,
    /// Update a key-value pair
    Update,
    /// Delete a key
    Delete,
    /// Get next key
    GetNextKey,
    /// Push element (stack/queue)
    Push,
    /// Pop element (stack/queue)
    Pop,
    /// Peek at element (stack/queue)
    Peek,
    /// Lookup and delete
    LookupAndDelete,
    /// Lookup percpu element
    LookupPercpu,
    /// Update percpu element
    UpdatePercpu,
    /// Redirect map lookup
    RedirectMap,
}

/// Map capabilities for verification
#[derive(Debug, Clone, Default)]
pub struct MapCapabilities {
    /// Whether map supports lookup
    pub can_lookup: bool,
    /// Whether map supports update
    pub can_update: bool,
    /// Whether map supports delete
    pub can_delete: bool,
    /// Whether map is read-only
    pub readonly: bool,
    /// Whether map values can contain pointers
    pub has_ptr_values: bool,
    /// Whether map values can contain timers
    pub has_timer: bool,
    /// Whether map values can contain spin locks
    pub has_spin_lock: bool,
    /// Whether map is per-cpu
    pub is_percpu: bool,
    /// Whether map requires BTF for values
    pub btf_value: bool,
}

impl MapCapabilities {
    /// Create capabilities for a map type
    pub fn for_map_type(map_type: BpfMapType) -> Self {
        match map_type {
            BpfMapType::Hash | BpfMapType::LruHash => Self {
                can_lookup: true,
                can_update: true,
                can_delete: true,
                ..Default::default()
            },
            BpfMapType::Array => Self {
                can_lookup: true,
                can_update: true,
                can_delete: false, // Arrays don't support delete
                ..Default::default()
            },
            BpfMapType::PercpuHash | BpfMapType::LruPercpuHash => Self {
                can_lookup: true,
                can_update: true,
                can_delete: true,
                is_percpu: true,
                ..Default::default()
            },
            BpfMapType::PercpuArray => Self {
                can_lookup: true,
                can_update: true,
                can_delete: false,
                is_percpu: true,
                ..Default::default()
            },
            BpfMapType::PerfEventArray => Self {
                can_lookup: false,
                can_update: true, // For output
                can_delete: false,
                ..Default::default()
            },
            BpfMapType::Stack | BpfMapType::Queue => Self {
                can_lookup: true, // peek
                can_update: true, // push
                can_delete: true, // pop
                ..Default::default()
            },
            BpfMapType::Ringbuf => Self {
                can_lookup: false,
                can_update: true, // reserve/submit
                can_delete: false,
                ..Default::default()
            },
            BpfMapType::ArrayOfMaps | BpfMapType::HashOfMaps => Self {
                can_lookup: true,
                can_update: true,
                can_delete: true,
                has_ptr_values: true, // Values are map FDs
                ..Default::default()
            },
            _ => Self {
                can_lookup: true,
                can_update: true,
                can_delete: true,
                ..Default::default()
            },
        }
    }
}

/// Check if map operation is valid for the map type
pub fn check_map_op_allowed(
    map_type: BpfMapType,
    op: MapOpType,
) -> Result<()> {
    let caps = MapCapabilities::for_map_type(map_type);

    match op {
        MapOpType::Lookup | MapOpType::LookupPercpu | MapOpType::LookupAndDelete => {
            if !caps.can_lookup {
                return Err(VerifierError::InvalidMapAccess(
                    format!("{:?} does not support lookup", map_type)
                ));
            }
        }
        MapOpType::Update | MapOpType::UpdatePercpu | MapOpType::Push => {
            if !caps.can_update {
                return Err(VerifierError::InvalidMapAccess(
                    format!("{:?} does not support update", map_type)
                ));
            }
            if caps.readonly {
                return Err(VerifierError::InvalidMapAccess(
                    "map is read-only".into()
                ));
            }
        }
        MapOpType::Delete | MapOpType::Pop => {
            if !caps.can_delete {
                return Err(VerifierError::InvalidMapAccess(
                    format!("{:?} does not support delete", map_type)
                ));
            }
        }
        MapOpType::GetNextKey => {
            // Most maps support iteration
        }
        MapOpType::Peek => {
            if !matches!(map_type, BpfMapType::Stack | BpfMapType::Queue) {
                return Err(VerifierError::InvalidMapAccess(
                    "peek only supported for stack/queue".into()
                ));
            }
        }
        MapOpType::RedirectMap => {
            // Redirect maps have special requirements
        }
    }

    Ok(())
}

/// Map lookup result tracking
#[derive(Debug, Clone)]
pub struct MapLookupResult {
    /// The map that was looked up
    pub map_type: BpfMapType,
    /// Whether result could be NULL
    pub could_be_null: bool,
    /// Value size
    pub value_size: u32,
    /// Whether value contains special fields
    pub has_special_fields: bool,
}

/// Check map lookup helper call
pub fn check_map_lookup(
    state: &mut BpfVerifierState,
    map_reg: usize,
    key_reg: usize,
    value_size: u32,
) -> Result<MapLookupResult> {
    // Map register must be CONST_PTR_TO_MAP
    let map = state.reg(map_reg)
        .ok_or(VerifierError::InvalidRegister(map_reg as u8))?;
    
    if map.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "CONST_PTR_TO_MAP".into(),
            got: format!("{:?}", map.reg_type),
        });
    }

    // Key register must be a valid pointer
    let key = state.reg(key_reg)
        .ok_or(VerifierError::InvalidRegister(key_reg as u8))?;
    
    if !key.is_pointer() {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to key".into(),
            got: format!("{:?}", key.reg_type),
        });
    }

    let map_type = map.map_ptr.as_ref()
        .map(|m| m.map_type)
        .unwrap_or(BpfMapType::Unspec);
    let map_ptr_clone = map.map_ptr.clone();

    check_map_op_allowed(map_type, MapOpType::Lookup)?;

    // Result goes in R0 as PTR_TO_MAP_VALUE_OR_NULL
    if let Some(r0) = state.reg_mut(BPF_REG_0) {
        r0.reg_type = BpfRegType::PtrToMapValue;
        r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        r0.map_ptr = map_ptr_clone;
        r0.off = 0;
    }

    Ok(MapLookupResult {
        map_type,
        could_be_null: true,
        value_size,
        has_special_fields: false,
    })
}

/// Check map update helper call
pub fn check_map_update(
    state: &BpfVerifierState,
    map_reg: usize,
    key_reg: usize,
    value_reg: usize,
    flags_reg: usize,
) -> Result<()> {
    // Map register must be CONST_PTR_TO_MAP
    let map = state.reg(map_reg)
        .ok_or(VerifierError::InvalidRegister(map_reg as u8))?;
    
    if map.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "CONST_PTR_TO_MAP".into(),
            got: format!("{:?}", map.reg_type),
        });
    }

    // Key and value must be valid pointers
    let key = state.reg(key_reg)
        .ok_or(VerifierError::InvalidRegister(key_reg as u8))?;
    let value = state.reg(value_reg)
        .ok_or(VerifierError::InvalidRegister(value_reg as u8))?;
    
    if !key.is_pointer() {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to key".into(),
            got: format!("{:?}", key.reg_type),
        });
    }
    
    if !value.is_pointer() {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to value".into(),
            got: format!("{:?}", value.reg_type),
        });
    }

    // Flags must be scalar
    let flags = state.reg(flags_reg)
        .ok_or(VerifierError::InvalidRegister(flags_reg as u8))?;
    
    if flags.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar flags".into(),
            got: format!("{:?}", flags.reg_type),
        });
    }

    let map_type = map.map_ptr.as_ref()
        .map(|m| m.map_type)
        .unwrap_or(BpfMapType::Unspec);

    check_map_op_allowed(map_type, MapOpType::Update)?;

    Ok(())
}

/// Check map delete helper call
pub fn check_map_delete(
    state: &BpfVerifierState,
    map_reg: usize,
    key_reg: usize,
) -> Result<()> {
    let map = state.reg(map_reg)
        .ok_or(VerifierError::InvalidRegister(map_reg as u8))?;
    
    if map.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "CONST_PTR_TO_MAP".into(),
            got: format!("{:?}", map.reg_type),
        });
    }

    let key = state.reg(key_reg)
        .ok_or(VerifierError::InvalidRegister(key_reg as u8))?;
    
    if !key.is_pointer() {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer to key".into(),
            got: format!("{:?}", key.reg_type),
        });
    }

    let map_type = map.map_ptr.as_ref()
        .map(|m| m.map_type)
        .unwrap_or(BpfMapType::Unspec);

    check_map_op_allowed(map_type, MapOpType::Delete)?;

    Ok(())
}

/// Map value field types for special handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapValueFieldType {
    /// Regular data field
    Data,
    /// Spin lock field
    SpinLock,
    /// Timer field
    Timer,
    /// Workqueue field
    Workqueue,
    /// Kptr field (kernel pointer)
    Kptr,
    /// List head field
    ListHead,
    /// List node field
    ListNode,
    /// Rbtree root field
    RbtreeRoot,
    /// Rbtree node field
    RbtreeNode,
    /// Refcount field
    Refcount,
}

/// Special field in map value
#[derive(Debug, Clone)]
pub struct MapValueField {
    /// Offset in value
    pub offset: u32,
    /// Size of field
    pub size: u32,
    /// Field type
    pub field_type: MapValueFieldType,
    /// BTF ID if applicable
    pub btf_id: Option<u32>,
}

/// Map value descriptor with special fields
#[derive(Debug, Clone, Default)]
pub struct MapValueDesc {
    /// Total value size
    pub size: u32,
    /// Special fields in value
    pub fields: Vec<MapValueField>,
}

impl MapValueDesc {
    /// Check if offset is within a special field
    pub fn get_field_at(&self, offset: u32, size: u32) -> Option<&MapValueField> {
        self.fields.iter().find(|&field| offset >= field.offset && offset + size <= field.offset + field.size).map(|v| v as _)
    }

    /// Check if access would cross a special field boundary
    pub fn check_access(&self, offset: u32, size: u32, is_write: bool) -> Result<()> {
        for field in &self.fields {
            let field_end = field.offset + field.size;
            let access_end = offset + size;

            // Check for overlap
            if offset < field_end && access_end > field.offset {
                // Access overlaps with special field
                match field.field_type {
                    MapValueFieldType::SpinLock => {
                        if is_write {
                            return Err(VerifierError::InvalidMapAccess(
                                "cannot write directly to spin_lock field".into()
                            ));
                        }
                    }
                    MapValueFieldType::Timer => {
                        return Err(VerifierError::InvalidMapAccess(
                            "cannot access timer field directly".into()
                        ));
                    }
                    MapValueFieldType::Kptr => {
                        // Kptr access requires special handling
                        if is_write && (offset != field.offset || size != field.size) {
                            return Err(VerifierError::InvalidMapAccess(
                                "partial kptr access not allowed".into()
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

/// Check map value access
pub fn check_map_value_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    value_desc: Option<&MapValueDesc>,
) -> Result<()> {
    // Must be PTR_TO_MAP_VALUE
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_MAP_VALUE".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    let value_size = reg.map_ptr.as_ref()
        .map(|m| m.value_size)
        .unwrap_or(0);

    let access_off = reg.off + off;
    let access_end = access_off + size as i32;

    // Check bounds
    if access_off < 0 || access_end > value_size as i32 {
        return Err(VerifierError::OutOfBounds {
            offset: access_off,
            size: size as i32,
        });
    }

    // Check special field access
    if let Some(desc) = value_desc {
        desc.check_access(access_off as u32, size, is_write)?;
    }

    Ok(())
}

/// For-each map element callback info
#[derive(Debug, Clone)]
pub struct MapForEachInfo {
    /// Map type
    pub map_type: BpfMapType,
    /// Key size
    pub key_size: u32,
    /// Value size
    pub value_size: u32,
    /// Callback instruction index
    pub callback_insn: usize,
}

/// Check bpf_for_each_map_elem call
pub fn check_for_each_map_elem(
    state: &BpfVerifierState,
    map_reg: usize,
    callback_reg: usize,
    ctx_reg: usize,
    _flags_reg: usize,
) -> Result<MapForEachInfo> {
    let map = state.reg(map_reg)
        .ok_or(VerifierError::InvalidRegister(map_reg as u8))?;
    
    if map.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "CONST_PTR_TO_MAP".into(),
            got: format!("{:?}", map.reg_type),
        });
    }

    // Callback should be a known constant (instruction index)
    let callback = state.reg(callback_reg)
        .ok_or(VerifierError::InvalidRegister(callback_reg as u8))?;
    
    if callback.reg_type != BpfRegType::ScalarValue || !callback.is_const() {
        return Err(VerifierError::TypeMismatch {
            expected: "constant callback index".into(),
            got: format!("{:?}", callback.reg_type),
        });
    }

    // Context can be any pointer or NULL
    let ctx = state.reg(ctx_reg)
        .ok_or(VerifierError::InvalidRegister(ctx_reg as u8))?;
    
    if !ctx.is_pointer() && ctx.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "pointer or NULL".into(),
            got: format!("{:?}", ctx.reg_type),
        });
    }

    let map_info = map.map_ptr.as_ref();
    
    Ok(MapForEachInfo {
        map_type: map_info.map(|m| m.map_type).unwrap_or(BpfMapType::Unspec),
        key_size: map_info.map(|m| m.key_size).unwrap_or(0),
        value_size: map_info.map(|m| m.value_size).unwrap_or(0),
        callback_insn: callback.const_value() as usize,
    })
}

/// Track map value pointer after null check
pub fn track_map_value_after_null_check(
    state: &mut BpfVerifierState,
    regno: usize,
    is_not_null: bool,
) -> Result<()> {
    let reg = state.reg_mut(regno)
        .ok_or(VerifierError::InvalidRegister(regno as u8))?;

    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Ok(()); // Only applies to map value pointers
    }

    if is_not_null {
        // Remove PTR_MAYBE_NULL flag
        reg.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
    } else {
        // Pointer is NULL - mark as scalar 0
        reg.mark_const_zero(false);
    }

    Ok(())
}

/// Adjust map value pointer offset
pub fn adjust_map_value_ptr(
    reg: &mut BpfRegState,
    adjustment: i32,
    value_size: u32,
) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_MAP_VALUE".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    let new_off = reg.off.checked_add(adjustment)
        .ok_or_else(|| VerifierError::InvalidPointerArithmetic(
            "offset overflow".into()
        ))?;

    // Check bounds
    if new_off < 0 || new_off >= value_size as i32 {
        return Err(VerifierError::OutOfBounds {
            offset: new_off,
            size: 0,
        });
    }

    reg.off = new_off;
    Ok(())
}

/// Map value pointer range tracking
#[derive(Debug, Clone)]
pub struct MapValueRange {
    /// Minimum valid offset
    pub min_off: i32,
    /// Maximum valid offset (exclusive)  
    pub max_off: i32,
    /// Whether range is variable (depends on runtime value)
    pub is_variable: bool,
}

impl MapValueRange {
    /// Create a fixed range
    pub fn fixed(min: i32, max: i32) -> Self {
        Self {
            min_off: min,
            max_off: max,
            is_variable: false,
        }
    }

    /// Create range for entire value
    pub fn full(value_size: u32) -> Self {
        Self::fixed(0, value_size as i32)
    }

    /// Check if access is within range
    pub fn check_access(&self, off: i32, size: u32) -> bool {
        off >= self.min_off && (off + size as i32) <= self.max_off
    }

    /// Narrow range after bounds check
    pub fn narrow(&self, min: i32, max: i32) -> Self {
        Self {
            min_off: self.min_off.max(min),
            max_off: self.max_off.min(max),
            is_variable: self.is_variable,
        }
    }
}

/// Track map value pointer with variable offset
pub fn track_map_value_var_off(
    reg: &mut BpfRegState,
    var_off_min: i64,
    var_off_max: i64,
    value_size: u32,
) -> Result<MapValueRange> {
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_MAP_VALUE".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    let base_off = reg.off as i64;
    let min_off = base_off + var_off_min;
    let max_off = base_off + var_off_max;

    // Check for potential out-of-bounds
    if min_off < 0 || max_off >= value_size as i64 {
        return Err(VerifierError::OutOfBounds {
            offset: min_off as i32,
            size: (max_off - min_off) as i32,
        });
    }

    Ok(MapValueRange {
        min_off: min_off as i32,
        max_off: max_off as i32 + 1, // exclusive
        is_variable: var_off_min != var_off_max,
    })
}

/// Propagate map pointer info when copying registers
pub fn propagate_map_ptr_info(
    dst: &mut BpfRegState,
    src: &BpfRegState,
) {
    if src.reg_type == BpfRegType::PtrToMapValue || 
       src.reg_type == BpfRegType::ConstPtrToMap {
        dst.map_ptr = src.map_ptr.clone();
    }
}

/// Check if two map value pointers could alias
pub fn map_ptrs_may_alias(
    reg1: &BpfRegState,
    reg2: &BpfRegState,
) -> bool {
    // Different types don't alias
    if reg1.reg_type != reg2.reg_type {
        return false;
    }

    // Only map value pointers can alias
    if reg1.reg_type != BpfRegType::PtrToMapValue {
        return false;
    }

    // If map_uid is set and different, no alias
    if reg1.map_uid != 0 && reg2.map_uid != 0 && reg1.map_uid != reg2.map_uid {
        return false;
    }

    // If offsets are definitely different, no alias (simplified)
    // Full implementation would use var_off intersection
    if reg1.off != reg2.off {
        return true; // Conservative: might still overlap
    }

    true
}
