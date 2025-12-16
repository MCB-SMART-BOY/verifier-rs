//! Map-Function Compatibility Checking
//!
//! This module provides comprehensive type checking for BPF map operations,
//! ensuring that key and value types match map specifications, and that
//! operations are valid for specific map types.
//!
//! The core function `check_map_func_compatibility` implements a two-way check:
//! 1. From the map perspective: what helper functions can this map be used with?
//! 2. From the function perspective: what map types can this helper accept?

#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::{BpfFuncId, BpfMapType, BpfProgType, BpfRegType};
use crate::state::reg_state::{BpfRegState, MapInfo};

// ============================================================================
// Map-Function Compatibility Check (from kernel's check_map_func_compatibility)
// ============================================================================

/// Context for map-function compatibility checking.
#[derive(Debug)]
pub struct MapFuncCompatContext {
    /// Program type being verified.
    pub prog_type: BpfProgType,
    /// Number of subprograms (for tail_call check).
    pub subprog_cnt: usize,
    /// Whether JIT supports tail calls in subprograms.
    pub jit_supports_subprog_tailcalls: bool,
}

impl Default for MapFuncCompatContext {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Unspec,
            subprog_cnt: 1,
            jit_supports_subprog_tailcalls: false,
        }
    }
}

impl MapFuncCompatContext {
    /// Create a new context.
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            subprog_cnt: 1,
            jit_supports_subprog_tailcalls: false,
        }
    }

    /// Check if tail calls in subprograms are allowed.
    fn allow_tail_call_in_subprogs(&self) -> bool {
        self.jit_supports_subprog_tailcalls
    }

    /// Check if this program type may update sockmap.
    fn may_update_sockmap(&self, func_id: BpfFuncId) -> bool {
        if func_id != BpfFuncId::MapUpdateElem && func_id != BpfFuncId::MapDeleteElem {
            return false;
        }
        // Allow updates from specific program types
        matches!(
            self.prog_type,
            BpfProgType::SocketFilter
                | BpfProgType::SchedCls
                | BpfProgType::SchedAct
                | BpfProgType::Xdp
                | BpfProgType::SkSkb
                | BpfProgType::SkMsg
                | BpfProgType::Tracing
                | BpfProgType::SockOps
                | BpfProgType::SkReuseport
        )
    }
}

/// Check map type to helper function compatibility.
///
/// This implements the kernel's `check_map_func_compatibility` function,
/// performing a two-way compatibility check:
/// 1. From map perspective: which functions can use this map type?
/// 2. From function perspective: which map types does this function accept?
pub fn check_map_func_compatibility(
    ctx: &MapFuncCompatContext,
    map_type: BpfMapType,
    func_id: BpfFuncId,
) -> Result<()> {
    // First check: from the map's perspective - what functions can use this map?
    check_map_allows_func(ctx, map_type, func_id)?;

    // Second check: from the function's perspective - what maps can it use?
    check_func_requires_map(ctx, map_type, func_id)?;

    Ok(())
}

/// Check if the map type allows the given helper function.
fn check_map_allows_func(
    ctx: &MapFuncCompatContext,
    map_type: BpfMapType,
    func_id: BpfFuncId,
) -> Result<()> {
    match map_type {
        BpfMapType::ProgArray => {
            if func_id != BpfFuncId::TailCall {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::PerfEventArray => {
            if !matches!(
                func_id,
                BpfFuncId::PerfEventRead
                    | BpfFuncId::PerfEventOutput
                    | BpfFuncId::SkbOutput
                    | BpfFuncId::PerfEventReadValue
                    | BpfFuncId::XdpOutput
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Ringbuf => {
            if !matches!(
                func_id,
                BpfFuncId::RingbufOutput
                    | BpfFuncId::RingbufReserve
                    | BpfFuncId::RingbufQuery
                    | BpfFuncId::RingbufReserveDynptr
                    | BpfFuncId::RingbufSubmitDynptr
                    | BpfFuncId::RingbufDiscardDynptr
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::UserRingbuf => {
            if func_id != BpfFuncId::UserRingbufDrain {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::StackTrace => {
            if func_id != BpfFuncId::GetStackid {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::CgroupArray => {
            if !matches!(
                func_id,
                BpfFuncId::SkbUnderCgroup | BpfFuncId::CurrentTaskUnderCgroup
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::CgroupStorage | BpfMapType::PercpuCgroupStorage => {
            if func_id != BpfFuncId::GetLocalStorage {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Devmap | BpfMapType::DevmapHash => {
            if !matches!(func_id, BpfFuncId::RedirectMap | BpfFuncId::MapLookupElem) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Cpumap => {
            if func_id != BpfFuncId::RedirectMap {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Xskmap => {
            if !matches!(func_id, BpfFuncId::RedirectMap | BpfFuncId::MapLookupElem) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::ArrayOfMaps | BpfMapType::HashOfMaps => {
            if func_id != BpfFuncId::MapLookupElem {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Sockmap => {
            if !matches!(
                func_id,
                BpfFuncId::SkRedirectMap
                    | BpfFuncId::SockMapUpdate
                    | BpfFuncId::MsgRedirectMap
                    | BpfFuncId::SkSelectReuseport
                    | BpfFuncId::MapLookupElem
            ) && !ctx.may_update_sockmap(func_id)
            {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Sockhash => {
            if !matches!(
                func_id,
                BpfFuncId::SkRedirectHash
                    | BpfFuncId::SockHashUpdate
                    | BpfFuncId::MsgRedirectHash
                    | BpfFuncId::SkSelectReuseport
                    | BpfFuncId::MapLookupElem
            ) && !ctx.may_update_sockmap(func_id)
            {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::ReuseportSockarray => {
            if func_id != BpfFuncId::SkSelectReuseport {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::Queue | BpfMapType::Stack => {
            if !matches!(
                func_id,
                BpfFuncId::MapPeekElem | BpfFuncId::MapPopElem | BpfFuncId::MapPushElem
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::SkStorage => {
            if !matches!(
                func_id,
                BpfFuncId::SkStorageGet | BpfFuncId::SkStorageDelete | BpfFuncId::KptrXchg
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::InodeStorage => {
            if !matches!(
                func_id,
                BpfFuncId::InodeStorageGet | BpfFuncId::InodeStorageDelete | BpfFuncId::KptrXchg
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::TaskStorage => {
            if !matches!(
                func_id,
                BpfFuncId::TaskStorageGet | BpfFuncId::TaskStorageDelete | BpfFuncId::KptrXchg
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::CgrpStorage => {
            if !matches!(
                func_id,
                BpfFuncId::CgrpStorageGet | BpfFuncId::CgrpStorageDelete | BpfFuncId::KptrXchg
            ) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        BpfMapType::BloomFilter => {
            if !matches!(func_id, BpfFuncId::MapPeekElem | BpfFuncId::MapPushElem) {
                return Err(map_func_compat_error(map_type, func_id));
            }
        }

        // Generic map types that work with standard helpers
        BpfMapType::Hash
        | BpfMapType::Array
        | BpfMapType::PercpuHash
        | BpfMapType::PercpuArray
        | BpfMapType::LruHash
        | BpfMapType::LruPercpuHash
        | BpfMapType::LpmTrie
        | BpfMapType::StructOps
        | BpfMapType::Arena => {
            // These map types work with generic map helpers
        }

        BpfMapType::Unspec => {
            return Err(VerifierError::InvalidMapAccess(
                "unspecified map type".to_string(),
            ));
        }
    }

    Ok(())
}

/// Check if the helper function can work with the given map type.
fn check_func_requires_map(
    ctx: &MapFuncCompatContext,
    map_type: BpfMapType,
    func_id: BpfFuncId,
) -> Result<()> {
    match func_id {
        BpfFuncId::TailCall => {
            if map_type != BpfMapType::ProgArray {
                return Err(func_map_compat_error(func_id, map_type));
            }
            // Check for mixing of tail_calls and bpf-to-bpf calls
            if ctx.subprog_cnt > 1 && !ctx.allow_tail_call_in_subprogs() {
                return Err(VerifierError::InvalidHelperCall(
                    "mixing of tail_calls and bpf-to-bpf calls is not supported".to_string(),
                ));
            }
        }

        BpfFuncId::PerfEventRead
        | BpfFuncId::PerfEventOutput
        | BpfFuncId::PerfEventReadValue
        | BpfFuncId::SkbOutput
        | BpfFuncId::XdpOutput => {
            if map_type != BpfMapType::PerfEventArray {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::RingbufOutput
        | BpfFuncId::RingbufReserve
        | BpfFuncId::RingbufQuery
        | BpfFuncId::RingbufReserveDynptr
        | BpfFuncId::RingbufSubmitDynptr
        | BpfFuncId::RingbufDiscardDynptr => {
            if map_type != BpfMapType::Ringbuf {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::UserRingbufDrain => {
            if map_type != BpfMapType::UserRingbuf {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::GetStackid => {
            if map_type != BpfMapType::StackTrace {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::CurrentTaskUnderCgroup | BpfFuncId::SkbUnderCgroup => {
            if map_type != BpfMapType::CgroupArray {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::RedirectMap => {
            if !matches!(
                map_type,
                BpfMapType::Devmap | BpfMapType::DevmapHash | BpfMapType::Cpumap | BpfMapType::Xskmap
            ) {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::SkRedirectMap | BpfFuncId::MsgRedirectMap | BpfFuncId::SockMapUpdate => {
            if map_type != BpfMapType::Sockmap {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::SkRedirectHash | BpfFuncId::MsgRedirectHash | BpfFuncId::SockHashUpdate => {
            if map_type != BpfMapType::Sockhash {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::GetLocalStorage => {
            if !matches!(
                map_type,
                BpfMapType::CgroupStorage | BpfMapType::PercpuCgroupStorage
            ) {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::SkSelectReuseport => {
            if !matches!(
                map_type,
                BpfMapType::ReuseportSockarray | BpfMapType::Sockmap | BpfMapType::Sockhash
            ) {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::MapPeekElem | BpfFuncId::MapPopElem | BpfFuncId::MapPushElem => {
            if !matches!(
                map_type,
                BpfMapType::Queue | BpfMapType::Stack | BpfMapType::BloomFilter
            ) {
                // Note: bloom filter only supports peek and push, not pop
                if func_id == BpfFuncId::MapPopElem && map_type == BpfMapType::BloomFilter {
                    return Err(func_map_compat_error(func_id, map_type));
                }
                if !matches!(map_type, BpfMapType::Queue | BpfMapType::Stack) {
                    return Err(func_map_compat_error(func_id, map_type));
                }
            }
        }

        BpfFuncId::SkStorageGet | BpfFuncId::SkStorageDelete => {
            if map_type != BpfMapType::SkStorage {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::InodeStorageGet | BpfFuncId::InodeStorageDelete => {
            if map_type != BpfMapType::InodeStorage {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::TaskStorageGet | BpfFuncId::TaskStorageDelete => {
            if map_type != BpfMapType::TaskStorage {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        BpfFuncId::CgrpStorageGet | BpfFuncId::CgrpStorageDelete => {
            if map_type != BpfMapType::CgrpStorage {
                return Err(func_map_compat_error(func_id, map_type));
            }
        }

        // Generic map operations work with most map types
        BpfFuncId::MapLookupElem
        | BpfFuncId::MapUpdateElem
        | BpfFuncId::MapDeleteElem
        | BpfFuncId::MapLookupPercpuElem
        | BpfFuncId::ForEachMapElem
        | BpfFuncId::KptrXchg => {
            // These are generally allowed, specific restrictions are handled
            // by check_map_allows_func
        }

        _ => {
            // Other helpers don't have map-specific requirements
        }
    }

    Ok(())
}

/// Create an error for map type not allowing a function.
fn map_func_compat_error(map_type: BpfMapType, func_id: BpfFuncId) -> VerifierError {
    VerifierError::InvalidMapAccess(format!(
        "cannot use helper {:?} with map type {:?}",
        func_id, map_type
    ))
}

/// Create an error for function not accepting a map type.
fn func_map_compat_error(func_id: BpfFuncId, map_type: BpfMapType) -> VerifierError {
    VerifierError::InvalidMapAccess(format!(
        "helper {:?} requires different map type, got {:?}",
        func_id, map_type
    ))
}

/// Quick check if a map type requires special handling.
pub fn is_special_map_type(map_type: BpfMapType) -> bool {
    matches!(
        map_type,
        BpfMapType::ProgArray
            | BpfMapType::PerfEventArray
            | BpfMapType::Ringbuf
            | BpfMapType::UserRingbuf
            | BpfMapType::StackTrace
            | BpfMapType::CgroupArray
            | BpfMapType::CgroupStorage
            | BpfMapType::PercpuCgroupStorage
            | BpfMapType::Devmap
            | BpfMapType::DevmapHash
            | BpfMapType::Cpumap
            | BpfMapType::Xskmap
            | BpfMapType::ArrayOfMaps
            | BpfMapType::HashOfMaps
            | BpfMapType::Sockmap
            | BpfMapType::Sockhash
            | BpfMapType::ReuseportSockarray
            | BpfMapType::SkStorage
            | BpfMapType::InodeStorage
            | BpfMapType::TaskStorage
            | BpfMapType::CgrpStorage
            | BpfMapType::BloomFilter
    )
}

/// Get the list of allowed helper functions for a map type.
pub fn get_allowed_funcs_for_map(map_type: BpfMapType) -> &'static [BpfFuncId] {
    match map_type {
        BpfMapType::ProgArray => &[BpfFuncId::TailCall],
        BpfMapType::PerfEventArray => &[
            BpfFuncId::PerfEventRead,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::SkbOutput,
            BpfFuncId::PerfEventReadValue,
            BpfFuncId::XdpOutput,
        ],
        BpfMapType::Ringbuf => &[
            BpfFuncId::RingbufOutput,
            BpfFuncId::RingbufReserve,
            BpfFuncId::RingbufQuery,
            BpfFuncId::RingbufReserveDynptr,
            BpfFuncId::RingbufSubmitDynptr,
            BpfFuncId::RingbufDiscardDynptr,
        ],
        BpfMapType::UserRingbuf => &[BpfFuncId::UserRingbufDrain],
        BpfMapType::StackTrace => &[BpfFuncId::GetStackid],
        BpfMapType::CgroupArray => {
            &[BpfFuncId::SkbUnderCgroup, BpfFuncId::CurrentTaskUnderCgroup]
        }
        BpfMapType::CgroupStorage | BpfMapType::PercpuCgroupStorage => {
            &[BpfFuncId::GetLocalStorage]
        }
        BpfMapType::Devmap | BpfMapType::DevmapHash => {
            &[BpfFuncId::RedirectMap, BpfFuncId::MapLookupElem]
        }
        BpfMapType::Cpumap => &[BpfFuncId::RedirectMap],
        BpfMapType::Xskmap => &[BpfFuncId::RedirectMap, BpfFuncId::MapLookupElem],
        BpfMapType::ArrayOfMaps | BpfMapType::HashOfMaps => &[BpfFuncId::MapLookupElem],
        BpfMapType::ReuseportSockarray => &[BpfFuncId::SkSelectReuseport],
        BpfMapType::Queue | BpfMapType::Stack => &[
            BpfFuncId::MapPeekElem,
            BpfFuncId::MapPopElem,
            BpfFuncId::MapPushElem,
        ],
        BpfMapType::BloomFilter => &[BpfFuncId::MapPeekElem, BpfFuncId::MapPushElem],
        BpfMapType::SkStorage => &[
            BpfFuncId::SkStorageGet,
            BpfFuncId::SkStorageDelete,
            BpfFuncId::KptrXchg,
        ],
        BpfMapType::InodeStorage => &[
            BpfFuncId::InodeStorageGet,
            BpfFuncId::InodeStorageDelete,
            BpfFuncId::KptrXchg,
        ],
        BpfMapType::TaskStorage => &[
            BpfFuncId::TaskStorageGet,
            BpfFuncId::TaskStorageDelete,
            BpfFuncId::KptrXchg,
        ],
        BpfMapType::CgrpStorage => &[
            BpfFuncId::CgrpStorageGet,
            BpfFuncId::CgrpStorageDelete,
            BpfFuncId::KptrXchg,
        ],
        // Generic map types - allow standard operations
        _ => &[
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
        ],
    }
}

// ============================================================================
// Map Operation Types
// ============================================================================

/// Key type requirements for map operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyTypeReq {
    /// Fixed size scalar key.
    Scalar(u32),
    /// Pointer to key data.
    PtrToKey(u32),
    /// Any valid pointer.
    AnyPtr,
    /// No key required (e.g., stack/queue peek).
    None,
}

/// Value type requirements for map operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueTypeReq {
    /// Returns pointer to value in map.
    PtrToValue(u32),
    /// Value is copied out.
    CopiedValue(u32),
    /// Pointer to buffer for value.
    PtrToBuffer(u32),
    /// No value (e.g., delete).
    None,
}

/// Map operation signature describing key/value requirements.
#[derive(Debug, Clone)]
pub struct MapOpSignature {
    /// Operation name.
    pub name: &'static str,
    /// Helper function ID.
    pub func_id: BpfFuncId,
    /// Key requirement.
    pub key_req: KeyTypeReq,
    /// Value requirement.
    pub value_req: ValueTypeReq,
    /// Whether operation modifies the map.
    pub modifies_map: bool,
    /// Whether operation can return NULL.
    pub can_return_null: bool,
    /// Required map flags.
    pub required_flags: u32,
}

impl MapOpSignature {
    /// Create a lookup operation signature.
    pub fn lookup(value_size: u32, key_size: u32) -> Self {
        Self {
            name: "map_lookup_elem",
            func_id: BpfFuncId::MapLookupElem,
            key_req: KeyTypeReq::PtrToKey(key_size),
            value_req: ValueTypeReq::PtrToValue(value_size),
            modifies_map: false,
            can_return_null: true,
            required_flags: 0,
        }
    }

    /// Create an update operation signature.
    pub fn update(value_size: u32, key_size: u32) -> Self {
        Self {
            name: "map_update_elem",
            func_id: BpfFuncId::MapUpdateElem,
            key_req: KeyTypeReq::PtrToKey(key_size),
            value_req: ValueTypeReq::PtrToBuffer(value_size),
            modifies_map: true,
            can_return_null: false,
            required_flags: 0,
        }
    }

    /// Create a delete operation signature.
    pub fn delete(key_size: u32) -> Self {
        Self {
            name: "map_delete_elem",
            func_id: BpfFuncId::MapDeleteElem,
            key_req: KeyTypeReq::PtrToKey(key_size),
            value_req: ValueTypeReq::None,
            modifies_map: true,
            can_return_null: false,
            required_flags: 0,
        }
    }

    /// Create a push operation signature (stack/queue).
    pub fn push(value_size: u32) -> Self {
        Self {
            name: "map_push_elem",
            func_id: BpfFuncId::MapPushElem,
            key_req: KeyTypeReq::None,
            value_req: ValueTypeReq::PtrToBuffer(value_size),
            modifies_map: true,
            can_return_null: false,
            required_flags: 0,
        }
    }

    /// Create a pop operation signature (stack/queue).
    pub fn pop(value_size: u32) -> Self {
        Self {
            name: "map_pop_elem",
            func_id: BpfFuncId::MapPopElem,
            key_req: KeyTypeReq::None,
            value_req: ValueTypeReq::PtrToBuffer(value_size),
            modifies_map: true,
            can_return_null: false,
            required_flags: 0,
        }
    }

    /// Create a peek operation signature (stack/queue).
    pub fn peek(value_size: u32) -> Self {
        Self {
            name: "map_peek_elem",
            func_id: BpfFuncId::MapPeekElem,
            key_req: KeyTypeReq::None,
            value_req: ValueTypeReq::PtrToBuffer(value_size),
            modifies_map: false,
            can_return_null: false,
            required_flags: 0,
        }
    }
}

/// Map type checker for validating operations.
#[derive(Debug)]
pub struct MapTypeChecker {
    /// Map information.
    map_info: MapInfo,
    /// Whether strict type checking is enabled.
    strict: bool,
}

impl MapTypeChecker {
    /// Create a new type checker for a map.
    pub fn new(map_info: MapInfo) -> Self {
        Self {
            map_info,
            strict: true,
        }
    }

    /// Set strict mode.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Get map info.
    pub fn map_info(&self) -> &MapInfo {
        &self.map_info
    }

    /// Check if an operation is valid for this map type.
    pub fn check_operation(&self, op: BpfFuncId) -> Result<MapOpSignature> {
        let _map_type = self.map_info.map_type;
        let key_size = self.map_info.key_size;
        let value_size = self.map_info.value_size;

        match op {
            BpfFuncId::MapLookupElem => {
                self.check_supports_lookup()?;
                Ok(MapOpSignature::lookup(value_size, key_size))
            }
            BpfFuncId::MapUpdateElem => {
                self.check_supports_update()?;
                Ok(MapOpSignature::update(value_size, key_size))
            }
            BpfFuncId::MapDeleteElem => {
                self.check_supports_delete()?;
                Ok(MapOpSignature::delete(key_size))
            }
            BpfFuncId::MapPushElem => {
                self.check_is_stack_or_queue()?;
                Ok(MapOpSignature::push(value_size))
            }
            BpfFuncId::MapPopElem => {
                self.check_is_stack_or_queue()?;
                Ok(MapOpSignature::pop(value_size))
            }
            BpfFuncId::MapPeekElem => {
                self.check_is_stack_or_queue()?;
                Ok(MapOpSignature::peek(value_size))
            }
            _ => Err(VerifierError::InvalidMapAccess(format!(
                "helper {:?} is not a map operation",
                op
            ))),
        }
    }

    /// Validate key argument for a map operation.
    pub fn validate_key(&self, reg: &BpfRegState, sig: &MapOpSignature) -> Result<()> {
        match &sig.key_req {
            KeyTypeReq::None => {
                // No key needed
                Ok(())
            }
            KeyTypeReq::Scalar(size) => {
                // Must be a scalar of exact size
                if reg.reg_type != BpfRegType::ScalarValue {
                    return Err(VerifierError::TypeMismatch {
                        expected: "scalar".to_string(),
                        got: format!("{:?}", reg.reg_type),
                    });
                }
                // Check size if we can determine it
                let _ = size; // Size check would happen at value level
                Ok(())
            }
            KeyTypeReq::PtrToKey(expected_size) => {
                // Must be a pointer to readable memory of key_size
                self.check_ptr_to_mem(reg, *expected_size, false)?;
                Ok(())
            }
            KeyTypeReq::AnyPtr => {
                if !reg.is_ptr() {
                    return Err(VerifierError::TypeMismatch {
                        expected: "pointer".to_string(),
                        got: format!("{:?}", reg.reg_type),
                    });
                }
                Ok(())
            }
        }
    }

    /// Validate value argument for a map operation.
    pub fn validate_value(&self, reg: &BpfRegState, sig: &MapOpSignature) -> Result<()> {
        match &sig.value_req {
            ValueTypeReq::None => Ok(()),
            ValueTypeReq::PtrToValue(_size) => {
                // Return type validation - reg is the destination
                Ok(())
            }
            ValueTypeReq::CopiedValue(_size) => {
                // Value is returned directly
                Ok(())
            }
            ValueTypeReq::PtrToBuffer(expected_size) => {
                // Must be writable memory of value_size
                self.check_ptr_to_mem(reg, *expected_size, true)?;
                Ok(())
            }
        }
    }

    /// Check that a register is a pointer to memory.
    fn check_ptr_to_mem(&self, reg: &BpfRegState, size: u32, writable: bool) -> Result<()> {
        match reg.reg_type {
            BpfRegType::PtrToStack => {
                // Stack is always readable and writable
                // Size check would be done by stack bounds checking
                Ok(())
            }
            BpfRegType::PtrToMapValue => {
                // Map value pointer
                if writable {
                    // Check if map allows writes
                    // For now, allow - specific map check would be needed
                }
                let _ = size;
                Ok(())
            }
            BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
                if writable && self.strict {
                    return Err(VerifierError::InvalidMapAccess(
                        "cannot use packet pointer as writable map argument".to_string(),
                    ));
                }
                Ok(())
            }
            BpfRegType::PtrToCtx => {
                if writable && self.strict {
                    return Err(VerifierError::InvalidMapAccess(
                        "cannot use context pointer as writable map argument".to_string(),
                    ));
                }
                Ok(())
            }
            BpfRegType::PtrToMem => {
                // Generic memory pointer
                Ok(())
            }
            BpfRegType::ScalarValue if !self.strict => {
                // In non-strict mode, allow scalars (they might be validated pointers)
                Ok(())
            }
            _ => Err(VerifierError::TypeMismatch {
                expected: "pointer to memory".to_string(),
                got: format!("{:?}", reg.reg_type),
            }),
        }
    }

    /// Check if map supports lookup.
    fn check_supports_lookup(&self) -> Result<()> {
        match self.map_info.map_type {
            BpfMapType::PerfEventArray | BpfMapType::CgroupStorage => {
                Err(VerifierError::InvalidMapAccess(format!(
                    "{:?} does not support lookup",
                    self.map_info.map_type
                )))
            }
            _ => Ok(()),
        }
    }

    /// Check if map supports update.
    fn check_supports_update(&self) -> Result<()> {
        // Most maps support update
        Ok(())
    }

    /// Check if map supports delete.
    fn check_supports_delete(&self) -> Result<()> {
        match self.map_info.map_type {
            BpfMapType::Array
            | BpfMapType::PercpuArray
            | BpfMapType::PerfEventArray
            | BpfMapType::CgroupArray
            | BpfMapType::ArrayOfMaps
            | BpfMapType::ProgArray => Err(VerifierError::InvalidMapAccess(format!(
                "{:?} does not support delete",
                self.map_info.map_type
            ))),
            _ => Ok(()),
        }
    }

    /// Check if map is a stack or queue.
    fn check_is_stack_or_queue(&self) -> Result<()> {
        match self.map_info.map_type {
            BpfMapType::Stack | BpfMapType::Queue => Ok(()),
            _ => Err(VerifierError::InvalidMapAccess(format!(
                "{:?} is not a stack or queue",
                self.map_info.map_type
            ))),
        }
    }
}

/// Result of validating a map operation.
#[derive(Debug, Clone)]
pub struct MapOpValidation {
    /// Whether the operation is valid.
    pub valid: bool,
    /// The operation signature.
    pub signature: Option<MapOpSignature>,
    /// Errors encountered.
    pub errors: Vec<String>,
    /// Warnings.
    pub warnings: Vec<String>,
}

impl MapOpValidation {
    /// Create a successful validation.
    pub fn success(signature: MapOpSignature) -> Self {
        Self {
            valid: true,
            signature: Some(signature),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a failed validation.
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            signature: None,
            errors: vec![error],
            warnings: Vec::new(),
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Validate a complete map operation with all arguments.
pub fn validate_map_operation(
    op: BpfFuncId,
    map_reg: &BpfRegState,
    key_reg: Option<&BpfRegState>,
    value_reg: Option<&BpfRegState>,
    _flags_reg: Option<&BpfRegState>,
) -> MapOpValidation {
    // Check map register
    let map_info = match &map_reg.map_ptr {
        Some(info) => info.clone(),
        None => {
            return MapOpValidation::failure(
                "map argument does not contain map information".to_string(),
            )
        }
    };

    let checker = MapTypeChecker::new(map_info);

    // Check operation is valid for this map type
    let signature = match checker.check_operation(op) {
        Ok(sig) => sig,
        Err(e) => return MapOpValidation::failure(format!("{}", e)),
    };

    let mut validation = MapOpValidation::success(signature.clone());

    // Validate key if required
    if let Some(key) = key_reg {
        if let Err(e) = checker.validate_key(key, &signature) {
            validation.errors.push(format!("key validation: {}", e));
            validation.valid = false;
        }
    } else if !matches!(signature.key_req, KeyTypeReq::None) {
        validation.errors.push("key argument required but not provided".to_string());
        validation.valid = false;
    }

    // Validate value if required
    if let Some(value) = value_reg {
        if let Err(e) = checker.validate_value(value, &signature) {
            validation.errors.push(format!("value validation: {}", e));
            validation.valid = false;
        }
    }

    // Add warnings for potentially dangerous operations
    if signature.modifies_map && checker.map_info().map_type == BpfMapType::ProgArray {
        validation = validation.with_warning(
            "modifying prog_array may affect tail call behavior".to_string(),
        );
    }

    validation
}

/// Check if two map types are compatible for value transfer.
pub fn map_types_compatible(src: BpfMapType, dst: BpfMapType) -> bool {
    // Same type is always compatible
    if src == dst {
        return true;
    }

    // Hash variants are compatible
    let hash_types = [
        BpfMapType::Hash,
        BpfMapType::LruHash,
        BpfMapType::PercpuHash,
        BpfMapType::LruPercpuHash,
    ];
    if hash_types.contains(&src) && hash_types.contains(&dst) {
        return true;
    }

    // Array variants are compatible
    let array_types = [BpfMapType::Array, BpfMapType::PercpuArray];
    if array_types.contains(&src) && array_types.contains(&dst) {
        return true;
    }

    false
}

/// Get the expected return type for a map operation.
/// Returns (register type, can_be_null).
pub fn get_map_op_return_type(
    op: BpfFuncId,
    map_info: &MapInfo,
) -> (BpfRegType, bool) {
    match op {
        BpfFuncId::MapLookupElem => {
            // Returns pointer to map value or NULL
            // We use PtrToMapValue and indicate it can be null via the bool
            (BpfRegType::PtrToMapValue, true)
        }
        BpfFuncId::MapUpdateElem | BpfFuncId::MapDeleteElem => {
            // Returns 0 on success, negative error on failure
            (BpfRegType::ScalarValue, false)
        }
        BpfFuncId::MapPushElem
        | BpfFuncId::MapPopElem
        | BpfFuncId::MapPeekElem => {
            // Returns 0 on success, negative error on failure
            (BpfRegType::ScalarValue, false)
        }
        _ => {
            let _ = map_info;
            (BpfRegType::ScalarValue, false)
        }
    }
}

/// Constraints for map value access.
#[derive(Debug, Clone)]
pub struct MapValueConstraints {
    /// Minimum valid offset.
    pub min_offset: i32,
    /// Maximum valid offset.
    pub max_offset: i32,
    /// Alignment requirement.
    pub alignment: u32,
    /// Whether the value contains special fields.
    pub has_special_fields: bool,
    /// Offset of timer if present.
    pub timer_offset: Option<u32>,
    /// Offset of spin lock if present.
    pub spin_lock_offset: Option<u32>,
    /// Offsets of pointers in value.
    pub ptr_offsets: Vec<u32>,
}

impl MapValueConstraints {
    /// Create constraints for a map value.
    pub fn for_map(map_info: &MapInfo) -> Self {
        Self {
            min_offset: 0,
            max_offset: map_info.value_size as i32,
            alignment: 8, // Default 8-byte alignment
            has_special_fields: false,
            timer_offset: None,
            spin_lock_offset: None,
            ptr_offsets: Vec::new(),
        }
    }

    /// Check if an access is within bounds.
    pub fn check_access(&self, offset: i32, size: u32) -> Result<()> {
        if offset < self.min_offset {
            return Err(VerifierError::InvalidMapAccess(format!(
                "negative offset {} in map value",
                offset
            )));
        }
        if offset + size as i32 > self.max_offset {
            return Err(VerifierError::InvalidMapAccess(format!(
                "access at offset {} size {} exceeds value size {}",
                offset, size, self.max_offset
            )));
        }

        // Check alignment
        if self.alignment > 1 && (offset as u32) % self.alignment != 0 {
            return Err(VerifierError::InvalidMapAccess(format!(
                "unaligned access at offset {} (alignment {})",
                offset, self.alignment
            )));
        }

        // Check for special field overlap
        if let Some(timer_off) = self.timer_offset {
            if self.ranges_overlap(offset as u32, size, timer_off, 16) {
                return Err(VerifierError::InvalidMapAccess(
                    "access overlaps with timer field".to_string(),
                ));
            }
        }
        if let Some(lock_off) = self.spin_lock_offset {
            if self.ranges_overlap(offset as u32, size, lock_off, 4) {
                return Err(VerifierError::InvalidMapAccess(
                    "access overlaps with spin lock field".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn ranges_overlap(&self, off1: u32, size1: u32, off2: u32, size2: u32) -> bool {
        off1 < off2 + size2 && off2 < off1 + size1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map_info(map_type: BpfMapType, key_size: u32, value_size: u32) -> MapInfo {
        MapInfo {
            map_type,
            key_size,
            value_size,
            max_entries: 100,
        }
    }

    #[test]
    fn test_map_op_signature_lookup() {
        let sig = MapOpSignature::lookup(64, 4);
        assert_eq!(sig.name, "map_lookup_elem");
        assert!(!sig.modifies_map);
        assert!(sig.can_return_null);
        assert!(matches!(sig.key_req, KeyTypeReq::PtrToKey(4)));
        assert!(matches!(sig.value_req, ValueTypeReq::PtrToValue(64)));
    }

    #[test]
    fn test_map_op_signature_update() {
        let sig = MapOpSignature::update(32, 8);
        assert_eq!(sig.name, "map_update_elem");
        assert!(sig.modifies_map);
        assert!(!sig.can_return_null);
    }

    #[test]
    fn test_map_type_checker_hash() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapLookupElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapUpdateElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapDeleteElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPushElem).is_err());
    }

    #[test]
    fn test_map_type_checker_array() {
        let info = make_map_info(BpfMapType::Array, 4, 64);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapLookupElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapUpdateElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapDeleteElem).is_err());
    }

    #[test]
    fn test_map_type_checker_stack() {
        let info = make_map_info(BpfMapType::Stack, 0, 16);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapPushElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPopElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPeekElem).is_ok());
    }

    #[test]
    fn test_validate_key_ptr_to_stack() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);
        let sig = MapOpSignature::lookup(32, 4);

        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToStack;

        assert!(checker.validate_key(&reg, &sig).is_ok());
    }

    #[test]
    fn test_validate_key_wrong_type() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);
        let sig = MapOpSignature::lookup(32, 4);

        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::NotInit;

        assert!(checker.validate_key(&reg, &sig).is_err());
    }

    #[test]
    fn test_map_types_compatible() {
        assert!(map_types_compatible(BpfMapType::Hash, BpfMapType::Hash));
        assert!(map_types_compatible(BpfMapType::Hash, BpfMapType::LruHash));
        assert!(map_types_compatible(BpfMapType::Array, BpfMapType::PercpuArray));
        assert!(!map_types_compatible(BpfMapType::Hash, BpfMapType::Array));
    }

    #[test]
    fn test_get_map_op_return_type() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);

        let (ret_type, can_null) = get_map_op_return_type(BpfFuncId::MapLookupElem, &info);
        assert_eq!(ret_type, BpfRegType::PtrToMapValue);
        assert!(can_null);

        let (ret_type, can_null) = get_map_op_return_type(BpfFuncId::MapUpdateElem, &info);
        assert_eq!(ret_type, BpfRegType::ScalarValue);
        assert!(!can_null);
    }

    #[test]
    fn test_map_value_constraints() {
        let info = make_map_info(BpfMapType::Hash, 4, 64);
        let constraints = MapValueConstraints::for_map(&info);

        assert!(constraints.check_access(0, 4).is_ok());
        assert!(constraints.check_access(56, 8).is_ok()); // Aligned access
        assert!(constraints.check_access(64, 4).is_err()); // Out of bounds
        assert!(constraints.check_access(-4, 4).is_err()); // Negative offset
    }

    #[test]
    fn test_map_value_constraints_special_fields() {
        let info = make_map_info(BpfMapType::Hash, 4, 64);
        let mut constraints = MapValueConstraints::for_map(&info);
        constraints.timer_offset = Some(16);
        constraints.spin_lock_offset = Some(32);

        // Access to timer field should fail
        assert!(constraints.check_access(16, 8).is_err());
        assert!(constraints.check_access(20, 4).is_err()); // Overlaps timer

        // Access to spin lock field should fail
        assert!(constraints.check_access(32, 4).is_err());

        // Other accesses should be ok
        assert!(constraints.check_access(0, 8).is_ok());
        assert!(constraints.check_access(40, 8).is_ok());
    }

    #[test]
    fn test_validate_map_operation_success() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::Hash, 4, 32));

        let mut key_reg = BpfRegState::new_not_init();
        key_reg.reg_type = BpfRegType::PtrToStack;

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            Some(&key_reg),
            None,
            None,
        );

        assert!(validation.valid);
        assert!(validation.signature.is_some());
        assert!(validation.errors.is_empty());
    }

    #[test]
    fn test_validate_map_operation_no_map_info() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        // No map_ptr set

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            None,
            None,
            None,
        );

        assert!(!validation.valid);
        assert!(!validation.errors.is_empty());
    }

    #[test]
    fn test_validate_map_operation_missing_key() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::Hash, 4, 32));

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            None, // Missing key
            None,
            None,
        );

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|e| e.contains("key")));
    }

    #[test]
    fn test_validation_with_warning() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::ProgArray, 4, 4));

        let mut key_reg = BpfRegState::new_not_init();
        key_reg.reg_type = BpfRegType::PtrToStack;

        let mut value_reg = BpfRegState::new_not_init();
        value_reg.reg_type = BpfRegType::PtrToStack;

        let validation = validate_map_operation(
            BpfFuncId::MapUpdateElem,
            &map_reg,
            Some(&key_reg),
            Some(&value_reg),
            None,
        );

        assert!(validation.valid);
        assert!(!validation.warnings.is_empty());
        assert!(validation.warnings[0].contains("prog_array"));
    }

    // ========================================================================
    // Tests for check_map_func_compatibility
    // ========================================================================

    #[test]
    fn test_prog_array_tail_call_compat() {
        let ctx = MapFuncCompatContext::default();

        // prog_array only works with tail_call
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::MapLookupElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::MapUpdateElem).is_err());

        // tail_call only works with prog_array
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::TailCall).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::TailCall).is_err());
    }

    #[test]
    fn test_perf_event_array_compat() {
        let ctx = MapFuncCompatContext::default();

        // perf_event_array works with perf event functions
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::PerfEventOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::PerfEventRead).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::SkbOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::XdpOutput).is_ok());

        // but not with generic map functions
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::MapLookupElem).is_err());
    }

    #[test]
    fn test_ringbuf_compat() {
        let ctx = MapFuncCompatContext::default();

        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufReserve).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufQuery).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::MapLookupElem).is_err());

        // ringbuf functions require ringbuf map
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::RingbufOutput).is_err());
    }

    #[test]
    fn test_stack_queue_compat() {
        let ctx = MapFuncCompatContext::default();

        // Stack/queue maps work with push/pop/peek
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPushElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPopElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPeekElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapPushElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapPopElem).is_ok());

        // but not with lookup/update/delete
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapLookupElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapUpdateElem).is_err());
    }

    #[test]
    fn test_storage_maps_compat() {
        let ctx = MapFuncCompatContext::default();

        // SK storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::SkStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::SkStorageDelete).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::MapLookupElem).is_err());

        // Task storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::TaskStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::TaskStorageDelete).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::SkStorageGet).is_err());

        // Inode storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::InodeStorage, BpfFuncId::InodeStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::InodeStorage, BpfFuncId::InodeStorageDelete).is_ok());

        // Cgroup storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgrpStorage, BpfFuncId::CgrpStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgrpStorage, BpfFuncId::CgrpStorageDelete).is_ok());
    }

    #[test]
    fn test_redirect_map_compat() {
        let ctx = MapFuncCompatContext::default();

        // redirect_map works with devmap, cpumap, xskmap
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Devmap, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::DevmapHash, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Cpumap, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Xskmap, BpfFuncId::RedirectMap).is_ok());

        // but not with regular maps
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::RedirectMap).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::RedirectMap).is_err());
    }

    #[test]
    fn test_sockmap_compat() {
        let ctx = MapFuncCompatContext::new(BpfProgType::SkSkb);

        // sockmap operations
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SkRedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SockMapUpdate).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::MapLookupElem).is_ok());

        // sockhash operations
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SkRedirectHash).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SockHashUpdate).is_ok());

        // wrong function for wrong map type
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SkRedirectHash).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SkRedirectMap).is_err());
    }

    #[test]
    fn test_cgroup_storage_compat() {
        let ctx = MapFuncCompatContext::default();

        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgroupStorage, BpfFuncId::GetLocalStorage).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PercpuCgroupStorage, BpfFuncId::GetLocalStorage).is_ok());

        // get_local_storage requires cgroup storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::GetLocalStorage).is_err());
    }

    #[test]
    fn test_array_of_maps_compat() {
        let ctx = MapFuncCompatContext::default();

        // Only lookup is allowed for map-of-maps
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ArrayOfMaps, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::HashOfMaps, BpfFuncId::MapLookupElem).is_ok());

        assert!(check_map_func_compatibility(&ctx, BpfMapType::ArrayOfMaps, BpfFuncId::MapUpdateElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::HashOfMaps, BpfFuncId::MapDeleteElem).is_err());
    }

    #[test]
    fn test_bloom_filter_compat() {
        let ctx = MapFuncCompatContext::default();

        // Bloom filter supports peek (check) and push (add)
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPeekElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPushElem).is_ok());

        // But not pop (no removal from bloom filter)
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPopElem).is_err());
    }

    #[test]
    fn test_tail_call_subprog_restriction() {
        let mut ctx = MapFuncCompatContext::new(BpfProgType::Xdp);
        ctx.subprog_cnt = 2; // Has subprograms
        ctx.jit_supports_subprog_tailcalls = false;

        // Tail call with subprograms and no JIT support should fail
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_err());

        // With JIT support it should work
        ctx.jit_supports_subprog_tailcalls = true;
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_ok());
    }

    #[test]
    fn test_generic_hash_array_compat() {
        let ctx = MapFuncCompatContext::default();

        // Generic hash map works with standard helpers
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapUpdateElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapDeleteElem).is_ok());

        // Array map works with standard helpers
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::MapUpdateElem).is_ok());
    }

    #[test]
    fn test_is_special_map_type() {
        assert!(is_special_map_type(BpfMapType::ProgArray));
        assert!(is_special_map_type(BpfMapType::Ringbuf));
        assert!(is_special_map_type(BpfMapType::SkStorage));
        assert!(!is_special_map_type(BpfMapType::Hash));
        assert!(!is_special_map_type(BpfMapType::Array));
    }

    #[test]
    fn test_get_allowed_funcs_for_map() {
        let funcs = get_allowed_funcs_for_map(BpfMapType::ProgArray);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0], BpfFuncId::TailCall);

        let funcs = get_allowed_funcs_for_map(BpfMapType::Stack);
        assert_eq!(funcs.len(), 3);
        assert!(funcs.contains(&BpfFuncId::MapPushElem));
        assert!(funcs.contains(&BpfFuncId::MapPopElem));
        assert!(funcs.contains(&BpfFuncId::MapPeekElem));

        let funcs = get_allowed_funcs_for_map(BpfMapType::Hash);
        assert!(funcs.contains(&BpfFuncId::MapLookupElem));
        assert!(funcs.contains(&BpfFuncId::MapUpdateElem));
        assert!(funcs.contains(&BpfFuncId::MapDeleteElem));
    }
}
