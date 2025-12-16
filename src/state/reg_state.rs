//! Register state tracking
//!
//! This module implements the core register state tracking for the BPF verifier.
//! Each register tracks its type, bounds (for scalars), and other metadata.


use alloc::{format, vec::Vec};

use crate::bounds::tnum::Tnum;
use crate::bounds::bounds::ScalarBounds;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// State of a single BPF register
#[derive(Debug, Clone)]
pub struct BpfRegState {
    /// Type of the register
    pub reg_type: BpfRegType,
    /// Type flags (nullable, rdonly, etc.)
    pub type_flags: BpfTypeFlag,
    /// Offset from pointer base
    pub off: i32,
    /// Unique ID for this register value
    pub id: u32,
    /// Reference object ID (for acquired references)
    pub ref_obj_id: u32,
    /// Tracked number for known/unknown bits
    pub var_off: Tnum,
    /// Minimum signed 64-bit value
    pub smin_value: i64,
    /// Maximum signed 64-bit value
    pub smax_value: i64,
    /// Minimum unsigned 64-bit value
    pub umin_value: u64,
    /// Maximum unsigned 64-bit value
    pub umax_value: u64,
    /// Minimum signed 32-bit value
    pub s32_min_value: i32,
    /// Maximum signed 32-bit value
    pub s32_max_value: i32,
    /// Minimum unsigned 32-bit value
    pub u32_min_value: u32,
    /// Maximum unsigned 32-bit value
    pub u32_max_value: u32,
    /// Frame number for PTR_TO_STACK
    pub frameno: u32,
    /// Subreg definition instruction index
    pub subreg_def: u32,
    /// Whether this register requires precise tracking
    pub precise: bool,
    /// Live state flags
    pub live: RegLiveness,
    /// For PTR_TO_MAP_VALUE: pointer to map
    pub map_ptr: Option<MapInfo>,
    /// For PTR_TO_BTF_ID: BTF info
    pub btf_info: Option<BtfInfo>,
    /// For CONST_PTR_TO_DYNPTR: dynptr info
    pub dynptr: DynptrInfo,
    /// For iterator slots
    pub iter: IterInfo,
    /// For IRQ flag slots
    pub irq: IrqInfo,
    /// Memory size (for PTR_TO_MEM)
    pub mem_size: u32,
    /// Dynptr ID for slices
    pub dynptr_id: u32,
    /// Map UID for timer/workqueue
    pub map_uid: u32,
}

/// Liveness tracking for registers
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegLiveness {
    pub read: bool,
    pub written: bool,
    pub done: bool,
}

/// Map information for PTR_TO_MAP_VALUE
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct MapInfo {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// BTF information for PTR_TO_BTF_ID
#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub struct BtfInfo {
    /// The BTF type ID
    pub btf_id: u32,
    /// Cached pointer field offsets within this type
    pub ptr_field_offsets: Vec<u32>,
    /// Cached nullable field offsets (fields that may be NULL)
    pub nullable_field_offsets: Vec<u32>,
}

impl BtfInfo {
    /// Create new BtfInfo with just the type ID
    pub fn new(btf_id: u32) -> Self {
        Self {
            btf_id,
            ptr_field_offsets: Vec::new(),
            nullable_field_offsets: Vec::new(),
        }
    }

    /// Check if the given offset is a pointer field
    pub fn is_ptr_field(&self, offset: u32) -> bool {
        self.ptr_field_offsets.contains(&offset)
    }

    /// Check if the given offset is a nullable field
    pub fn is_nullable_field(&self, offset: u32) -> bool {
        self.nullable_field_offsets.contains(&offset)
    }

    /// Add a pointer field at the given offset
    pub fn add_ptr_field(&mut self, offset: u32, nullable: bool) {
        if !self.ptr_field_offsets.contains(&offset) {
            self.ptr_field_offsets.push(offset);
        }
        if nullable && !self.nullable_field_offsets.contains(&offset) {
            self.nullable_field_offsets.push(offset);
        }
    }
}

/// Dynptr information
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DynptrInfo {
    pub dynptr_type: BpfDynptrType,
    pub first_slot: bool,
}

/// Iterator information
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IterInfo {
    pub btf_id: u32,
    pub state: BpfIterState,
    pub depth: u32,
}

/// IRQ flag information
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqInfo {
    pub kfunc_class: IrqKfuncClass,
}

impl Default for BpfRegState {
    fn default() -> Self {
        Self::new_not_init()
    }
}

impl BpfRegState {
    /// Create an uninitialized register state
    pub fn new_not_init() -> Self {
        Self {
            reg_type: BpfRegType::NotInit,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::unknown(),
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
            s32_min_value: i32::MIN,
            s32_max_value: i32::MAX,
            u32_min_value: 0,
            u32_max_value: u32::MAX,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a context pointer register
    pub fn new_ctx_ptr(_prog_type: BpfProgType) -> Self {
        Self {
            reg_type: BpfRegType::PtrToCtx,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::const_value(0),
            smin_value: 0,
            smax_value: 0,
            umin_value: 0,
            umax_value: 0,
            s32_min_value: 0,
            s32_max_value: 0,
            u32_min_value: 0,
            u32_max_value: 0,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a frame pointer register (R10)
    pub fn new_fp() -> Self {
        Self {
            reg_type: BpfRegType::PtrToStack,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::const_value(0),
            smin_value: 0,
            smax_value: 0,
            umin_value: 0,
            umax_value: 0,
            s32_min_value: 0,
            s32_max_value: 0,
            u32_min_value: 0,
            u32_max_value: 0,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a scalar register with unknown value
    pub fn new_scalar_unknown(precise: bool) -> Self {
        Self {
            reg_type: BpfRegType::ScalarValue,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::unknown(),
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
            s32_min_value: i32::MIN,
            s32_max_value: i32::MAX,
            u32_min_value: 0,
            u32_max_value: u32::MAX,
            frameno: 0,
            subreg_def: 0,
            precise,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Mark register as known zero (scalar)
    pub fn mark_known_zero(&mut self) {
        self.mark_known(0);
    }

    /// Mark register as known constant value
    pub fn mark_known(&mut self, imm: u64) {
        self.reg_type = BpfRegType::ScalarValue;
        self.type_flags = BpfTypeFlag::empty();
        self.var_off = Tnum::const_value(imm);
        self.smin_value = imm as i64;
        self.smax_value = imm as i64;
        self.umin_value = imm;
        self.umax_value = imm;
        self.s32_min_value = imm as i32;
        self.s32_max_value = imm as i32;
        self.u32_min_value = imm as u32;
        self.u32_max_value = imm as u32;
        self.id = 0;
        self.ref_obj_id = 0;
        self.off = 0;
    }

    /// Mark register as completely unknown scalar
    pub fn mark_unknown(&mut self, precise: bool) {
        self.reg_type = BpfRegType::ScalarValue;
        self.type_flags = BpfTypeFlag::empty();
        self.off = 0;
        self.id = 0;
        self.ref_obj_id = 0;
        self.var_off = Tnum::unknown();
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
        self.precise = precise;
        self.frameno = 0;
    }

    /// Mark register as uninitialized
    pub fn mark_not_init(&mut self, precise: bool) {
        self.mark_unknown(precise);
        self.reg_type = BpfRegType::NotInit;
    }

    /// Mark register as const zero scalar
    pub fn mark_const_zero(&mut self, precise: bool) {
        self.mark_known(0);
        self.reg_type = BpfRegType::ScalarValue;
        self.precise = precise;
    }

    /// Mark the 32-bit subreg as known
    pub fn mark_32_known(&mut self, imm: u64) {
        self.var_off = Tnum::const_subreg(self.var_off, imm);
        self.s32_min_value = imm as i32;
        self.s32_max_value = imm as i32;
        self.u32_min_value = imm as u32;
        self.u32_max_value = imm as u32;
    }

    /// Reset min/max bounds to unbounded
    pub fn mark_unbounded(&mut self) {
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
    }

    /// Reset 64-bit bounds only
    pub fn mark_64_unbounded(&mut self) {
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
    }

    /// Reset 32-bit bounds only
    pub fn mark_32_unbounded(&mut self) {
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
    }

    /// Check if this register is null
    pub fn is_null(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue && self.var_off.equals_const(0)
    }

    /// Check if this register is a scalar value
    pub fn is_scalar(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue
    }

    /// Check if this is a constant register
    pub fn is_const(&self) -> bool {
        self.var_off.is_const()
    }

    /// Get the constant value (only valid if is_const() returns true)
    pub fn const_value(&self) -> u64 {
        self.var_off.value
    }

    /// Check if this register is definitely not null
    pub fn is_not_null(&self) -> bool {
        if self.type_flags.may_be_null() {
            return false;
        }
        match self.reg_type {
            BpfRegType::PtrToSocket
            | BpfRegType::PtrToTcpSock
            | BpfRegType::PtrToMapValue
            | BpfRegType::PtrToMapKey
            | BpfRegType::PtrToSockCommon
            | BpfRegType::ConstPtrToMap => true,
            BpfRegType::PtrToBtfId => self.is_trusted(),
            BpfRegType::PtrToMem => !self.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED),
            _ => false,
        }
    }

    /// Check if this is a trusted pointer
    pub fn is_trusted(&self) -> bool {
        if self.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
            return false;
        }
        if self.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            return false;
        }
        match self.reg_type {
            BpfRegType::PtrToBtfId => {
                !self.type_flags.contains(BpfTypeFlag::NON_OWN_REF)
            }
            _ => false,
        }
    }

    /// Check if this is an RCU-protected pointer
    pub fn is_rcu(&self) -> bool {
        self.type_flags.contains(BpfTypeFlag::MEM_RCU)
    }

    /// Check if type may be null
    pub fn may_be_null(&self) -> bool {
        self.type_flags.may_be_null()
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        self.reg_type.is_pointer()
    }

    /// Alias for is_pointer (shorter name)
    pub fn is_ptr(&self) -> bool {
        self.is_pointer()
    }

    /// Get BTF ID for typed pointers
    pub fn btf_id(&self) -> u32 {
        self.btf_info.as_ref().map(|b| b.btf_id).unwrap_or(0)
    }

    /// Set BTF ID for typed pointers
    pub fn set_btf_id(&mut self, btf_id: u32) {
        if let Some(ref mut info) = self.btf_info {
            info.btf_id = btf_id;
        } else {
            self.btf_info = Some(BtfInfo::new(btf_id));
        }
    }

    /// Check if this is a packet pointer
    pub fn is_pkt_pointer(&self) -> bool {
        self.reg_type.is_pkt_pointer()
    }

    /// Check if this may point to a spin lock
    pub fn may_point_to_spin_lock(&self) -> bool {
        // Would need BTF record check in full implementation
        false
    }

    /// Update bounds from var_off
    pub fn update_bounds(&mut self) {
        self.update_32_bounds();
        self.update_64_bounds();
    }

    /// Update 32-bit bounds from var_off
    pub fn update_32_bounds(&mut self) {
        let var32_off = self.var_off.subreg();

        // min signed is max(sign bit) | min(other bits)
        let smin = (var32_off.value | (var32_off.mask & 0x8000_0000)) as i32;
        self.s32_min_value = self.s32_min_value.max(smin);

        // max signed is min(sign bit) | max(other bits)
        let smax = (var32_off.value | (var32_off.mask & 0x7FFF_FFFF)) as i32;
        self.s32_max_value = self.s32_max_value.min(smax);

        self.u32_min_value = self.u32_min_value.max(var32_off.value as u32);
        self.u32_max_value = self.u32_max_value.min((var32_off.value | var32_off.mask) as u32);
    }

    /// Update 64-bit bounds from var_off
    pub fn update_64_bounds(&mut self) {
        // min signed is max(sign bit) | min(other bits)
        let smin = (self.var_off.value | (self.var_off.mask & (1u64 << 63))) as i64;
        self.smin_value = self.smin_value.max(smin);

        // max signed is min(sign bit) | max(other bits)
        let smax = (self.var_off.value | (self.var_off.mask & !(1u64 << 63))) as i64;
        self.smax_value = self.smax_value.min(smax);

        self.umin_value = self.umin_value.max(self.var_off.value);
        self.umax_value = self.umax_value.min(self.var_off.value | self.var_off.mask);
    }

    /// Deduce bounds from signed/unsigned relationships
    pub fn deduce_bounds(&mut self) {
        self.deduce_32_bounds();
        self.deduce_64_bounds();
        self.deduce_mixed_bounds();
    }

    /// Deduce 32-bit bounds
    fn deduce_32_bounds(&mut self) {
        // If upper 32 bits of u64 range are same, we can use lower 32 for u32/s32
        if (self.umin_value >> 32) == (self.umax_value >> 32) {
            self.u32_min_value = self.u32_min_value.max(self.umin_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.umax_value as u32);

            if (self.umin_value as i32) <= (self.umax_value as i32) {
                self.s32_min_value = self.s32_min_value.max(self.umin_value as i32);
                self.s32_max_value = self.s32_max_value.min(self.umax_value as i32);
            }
        }

        // Similar for s64 range
        if (self.smin_value >> 32) == (self.smax_value >> 32) {
            if (self.smin_value as u32) <= (self.smax_value as u32) {
                self.u32_min_value = self.u32_min_value.max(self.smin_value as u32);
                self.u32_max_value = self.u32_max_value.min(self.smax_value as u32);
            }
            if (self.smin_value as i32) <= (self.smax_value as i32) {
                self.s32_min_value = self.s32_min_value.max(self.smin_value as i32);
                self.s32_max_value = self.s32_max_value.min(self.smax_value as i32);
            }
        }

        // If u32 range forms valid s32 range, tighten s32
        if (self.u32_min_value as i32) <= (self.u32_max_value as i32) {
            self.s32_min_value = self.s32_min_value.max(self.u32_min_value as i32);
            self.s32_max_value = self.s32_max_value.min(self.u32_max_value as i32);
        }

        // If s32 range forms valid u32 range, tighten u32
        if (self.s32_min_value as u32) <= (self.s32_max_value as u32) {
            self.u32_min_value = self.u32_min_value.max(self.s32_min_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.s32_max_value as u32);
        }
    }

    /// Deduce 64-bit bounds
    fn deduce_64_bounds(&mut self) {
        // If u64 range forms valid s64 range (same sign), tighten s64
        if (self.umin_value as i64) <= (self.umax_value as i64) {
            self.smin_value = self.smin_value.max(self.umin_value as i64);
            self.smax_value = self.smax_value.min(self.umax_value as i64);
        }

        // If s64 range forms valid u64 range, tighten u64
        if (self.smin_value as u64) <= (self.smax_value as u64) {
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            self.umax_value = self.umax_value.min(self.smax_value as u64);
        }
    }

    /// Deduce mixed 32/64 bounds
    fn deduce_mixed_bounds(&mut self) {
        // Try to tighten 64-bit bounds from 32-bit knowledge
        let new_umin = (self.umin_value & !0xFFFF_FFFF) | self.u32_min_value as u64;
        let new_umax = (self.umax_value & !0xFFFF_FFFF) | self.u32_max_value as u64;
        self.umin_value = self.umin_value.max(new_umin);
        self.umax_value = self.umax_value.min(new_umax);

        let new_smin = (self.smin_value & !0xFFFF_FFFF_i64) | self.u32_min_value as i64;
        let new_smax = (self.smax_value & !0xFFFF_FFFF_i64) | self.u32_max_value as i64;
        self.smin_value = self.smin_value.max(new_smin);
        self.smax_value = self.smax_value.min(new_smax);
    }

    /// Update var_off based on bounds
    pub fn bound_offset(&mut self) {
        let var64_off = self.var_off.intersect(Tnum::range(self.umin_value, self.umax_value));
        let var32_off = var64_off
            .subreg()
            .intersect(Tnum::range(self.u32_min_value as u64, self.u32_max_value as u64));
        self.var_off = var64_off.clear_subreg() | var32_off;
    }

    /// Synchronize all bounds
    pub fn sync_bounds(&mut self) {
        self.update_bounds();
        self.deduce_bounds();
        self.deduce_bounds();
        self.deduce_bounds();
        self.bound_offset();
        self.update_bounds();
    }

    /// Sanity check bounds consistency
    pub fn bounds_sanity_check(&self) -> Result<()> {
        if self.umin_value > self.umax_value
            || self.smin_value > self.smax_value
            || self.u32_min_value > self.u32_max_value
            || self.s32_min_value > self.s32_max_value
        {
            return Err(VerifierError::BoundsCheckFailed(
                "range bounds violation".into(),
            ));
        }

        if self.var_off.is_const() {
            let uval = self.var_off.value;
            let sval = uval as i64;
            if self.umin_value != uval
                || self.umax_value != uval
                || self.smin_value != sval
                || self.smax_value != sval
            {
                return Err(VerifierError::BoundsCheckFailed(
                    "const tnum out of sync with range bounds".into(),
                ));
            }
        }

        if self.var_off.subreg_is_const() {
            let uval32 = self.var_off.subreg().value as u32;
            let sval32 = uval32 as i32;
            if self.u32_min_value != uval32
                || self.u32_max_value != uval32
                || self.s32_min_value != sval32
                || self.s32_max_value != sval32
            {
                return Err(VerifierError::BoundsCheckFailed(
                    "const subreg tnum out of sync".into(),
                ));
            }
        }

        Ok(())
    }

    /// Assign 32-bit bounds into 64-bit bounds (for zero-extension)
    pub fn assign_32_into_64(&mut self) {
        self.umin_value = self.u32_min_value as u64;
        self.umax_value = self.u32_max_value as u64;

        // Try to use 32-bit signed bounds for 64-bit if they're non-negative
        // (can be safely zero-extended to 64-bit)
        if self.s32_min_value >= 0 {
            self.smin_value = self.s32_min_value as i64;
            self.smax_value = self.s32_max_value as i64;
        } else {
            self.smin_value = 0;
            self.smax_value = u32::MAX as i64;
        }
    }

    /// Check if offset is sane for this pointer type
    pub fn check_sane_offset(&self) -> Result<()> {
        if !self.is_pointer() {
            return Ok(());
        }

        // Check for obviously bad offsets
        if self.off < -1_000_000 || self.off > 1_000_000 {
            return Err(VerifierError::InvalidPointerArithmetic(format!(
                "offset {} is out of sane range",
                self.off
            )));
        }

        // Check var_off bounds
        if self.var_off.value as i64 > 1_000_000
            || (self.var_off.value | self.var_off.mask) > 1_000_000_000
        {
            return Err(VerifierError::InvalidPointerArithmetic(
                "variable offset out of sane range".into(),
            ));
        }

        Ok(())
    }

    /// Clear the nullable/trusted flags
    pub fn clear_trusted_flags(&mut self) {
        self.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
    }

    /// Mark pointer as not null (after null check)
    pub fn mark_ptr_not_null(&mut self) {
        self.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
        
        // Handle special map value cases would go here
        // For now, just clear the flag
    }

    /// Set up register as a dynptr
    pub fn mark_dynptr(&mut self, dynptr_type: BpfDynptrType, first_slot: bool, dynptr_id: u32) {
        self.mark_known_zero();
        self.reg_type = BpfRegType::ConstPtrToDynptr;
        self.id = dynptr_id;
        self.dynptr.dynptr_type = dynptr_type;
        self.dynptr.first_slot = first_slot;
    }

    /// Convert register bounds to ScalarBounds
    pub fn to_scalar_bounds(&self) -> ScalarBounds {
        ScalarBounds {
            var_off: self.var_off,
            umin_value: self.umin_value,
            umax_value: self.umax_value,
            smin_value: self.smin_value,
            smax_value: self.smax_value,
            u32_min_value: self.u32_min_value,
            u32_max_value: self.u32_max_value,
            s32_min_value: self.s32_min_value,
            s32_max_value: self.s32_max_value,
        }
    }

    /// Apply ScalarBounds to this register
    pub fn apply_scalar_bounds(&mut self, bounds: &ScalarBounds) {
        self.var_off = bounds.var_off;
        self.umin_value = bounds.umin_value;
        self.umax_value = bounds.umax_value;
        self.smin_value = bounds.smin_value;
        self.smax_value = bounds.smax_value;
        self.u32_min_value = bounds.u32_min_value;
        self.u32_max_value = bounds.u32_max_value;
        self.s32_min_value = bounds.s32_min_value;
        self.s32_max_value = bounds.s32_max_value;
    }

    /// Apply ALU operation and update bounds
    pub fn scalar_alu_op(&mut self, op: u8, other: &BpfRegState, is_64bit: bool) -> Result<()> {
        let dst_bounds = self.to_scalar_bounds();
        let src_bounds = other.to_scalar_bounds();
        
        let result = dst_bounds.alu_op(op, &src_bounds, is_64bit)?;
        self.apply_scalar_bounds(&result);
        
        if !is_64bit {
            self.subreg_def = 1;
        }
        
        Ok(())
    }
}

/// Check if a value would be a pointer in unprivileged context
pub fn is_pointer_value(allow_ptr_leaks: bool, reg: &BpfRegState) -> bool {
    if allow_ptr_leaks {
        return false;
    }
    reg.is_pointer()
}
