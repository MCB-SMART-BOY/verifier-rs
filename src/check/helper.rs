//! Helper function verification
//!
//! This module implements argument type checking and return value
//! handling for BPF helper functions.

#[cfg(not(feature = "std"))]
use alloc::format;

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::mem::user::{
    UserMemContext, is_user_mem_helper, get_helper_user_access_type,
    check_user_mem_helper_access, validate_probe_read_user_dst, 
    validate_probe_read_user_src,
};
use crate::check::sleepable::check_helper_sleepable_compat;

/// Metadata about a helper function call
#[derive(Debug, Clone, Default)]
pub struct HelperCallMeta {
    /// Map pointer from argument
    pub map_ptr: Option<usize>,
    /// Whether raw memory access is allowed
    pub raw_mode: bool,
    /// Whether packet access is performed
    pub pkt_access: bool,
    /// Register that releases a reference
    pub release_regno: Option<usize>,
    /// Current argument register being checked
    pub regno: usize,
    /// Access size for memory arguments
    pub access_size: i32,
    /// Memory size
    pub mem_size: i32,
    /// Maximum memory size (from bounds)
    pub msize_max_value: u64,
    /// Reference object ID
    pub ref_obj_id: u32,
    /// Function ID
    pub func_id: BpfFuncId,
    /// Constant map key (if known)
    pub const_map_key: Option<i64>,
}

/// Helper function prototype
#[derive(Debug, Clone)]
pub struct HelperProto {
    /// Function ID
    pub func_id: BpfFuncId,
    /// Return type
    pub ret_type: BpfRetType,
    /// Argument types (up to 5)
    pub arg_types: [BpfArgType; 5],
    /// Whether function is privileged-only
    pub privileged_only: bool,
    /// Whether function may sleep
    pub may_sleep: bool,
}

impl HelperProto {
    /// Create a simple helper prototype
    pub fn new(func_id: BpfFuncId, ret_type: BpfRetType, args: &[BpfArgType]) -> Self {
        let mut arg_types = [BpfArgType::DontCare; 5];
        for (i, &arg) in args.iter().enumerate().take(5) {
            arg_types[i] = arg;
        }
        Self {
            func_id,
            ret_type,
            arg_types,
            privileged_only: false,
            may_sleep: false,
        }
    }
}

/// Get the prototype for a helper function
pub fn get_helper_proto(func_id: BpfFuncId) -> Option<HelperProto> {
    match func_id {
        BpfFuncId::MapLookupElem => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey],
        )),
        BpfFuncId::MapUpdateElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::ConstMapPtr,
                BpfArgType::PtrToMapKey,
                BpfArgType::PtrToMapValue,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::MapDeleteElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey],
        )),
        BpfFuncId::ProbeRead => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToUninitMem,
                BpfArgType::ConstSize,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::KtimeGetNs => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::TracePrintk => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToMem,
                BpfArgType::ConstSize,
            ],
        )),
        BpfFuncId::GetPrandomU32 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetSmpProcessorId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::TailCall => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::ConstMapPtr,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::GetCurrentPidTgid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetCurrentUidGid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetCurrentComm => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SkLookupTcp => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::PtrToMem,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::SkLookupUdp => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::PtrToMem,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::SkRelease => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::RingbufReserve => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToAllocMemOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::RingbufSubmit => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToAllocMem, BpfArgType::Anything],
        )),
        BpfFuncId::RingbufDiscard => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToAllocMem, BpfArgType::Anything],
        )),
        BpfFuncId::SpinLock => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToMapValue],
        )),
        BpfFuncId::SpinUnlock => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToMapValue],
        )),
        // Probe read/write helpers
        BpfFuncId::ProbeReadKernel => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ProbeReadUser => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ProbeReadStr => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ProbeReadKernelStr => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ProbeReadUserStr => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Cgroup/socket helpers
        BpfFuncId::GetSocketCookie => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::GetCurrentCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetCgroupClassid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // Perf event helpers
        BpfFuncId::PerfEventOutput => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::ConstMapPtr,
                BpfArgType::Anything,
                BpfArgType::PtrToMem,
                BpfArgType::ConstSize,
            ],
        )),
        BpfFuncId::PerfEventRead => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // SKB helpers
        BpfFuncId::SkbLoadBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::Anything,
                BpfArgType::PtrToUninitMem,
                BpfArgType::ConstSize,
            ],
        )),
        BpfFuncId::SkbStoreBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::Anything,
                BpfArgType::PtrToMem,
                BpfArgType::ConstSize,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::SkbPullData => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::SkbChangeType => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::SkbChangeTail => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkbChangeHead => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkbGetTunnelKey => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::PtrToUninitMem,
                BpfArgType::ConstSize,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::SkbSetTunnelKey => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::PtrToMem,
                BpfArgType::ConstSize,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::SkbVlanPush => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkbVlanPop => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // XDP helpers
        BpfFuncId::XdpAdjustHead => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::XdpAdjustTail => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::XdpAdjustMeta => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        // Redirect helpers  
        BpfFuncId::Redirect => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::RedirectMap => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Csum helpers
        BpfFuncId::CsumDiff => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToMemRdonly,
                BpfArgType::ConstSizeOrZero,
                BpfArgType::PtrToMemRdonly,
                BpfArgType::ConstSizeOrZero,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::L3CsumReplace => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
            ],
        )),
        BpfFuncId::L4CsumReplace => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[
                BpfArgType::PtrToCtx,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
                BpfArgType::Anything,
            ],
        )),
        // Map-in-map
        BpfFuncId::MapLookupPercpuElem => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        // Timer helpers
        BpfFuncId::TimerInit => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMapValue, BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        BpfFuncId::TimerSetCallback => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMapValue, BpfArgType::Anything], // callback func
        )),
        BpfFuncId::TimerStart => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMapValue, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::TimerCancel => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMapValue],
        )),
        // Dynptr helpers
        BpfFuncId::DynptrFromMem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::PtrToDynptr],
        )),
        BpfFuncId::DynptrRead => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::PtrToDynptr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::DynptrWrite => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToDynptr, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::DynptrData => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull,
            &[BpfArgType::PtrToDynptr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Ringbuf output
        BpfFuncId::RingbufOutput => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Task helpers
        BpfFuncId::GetCurrentTask => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetCurrentTaskBtf => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull, // PTR_TO_BTF_ID
            &[],
        )),
        // String helpers
        BpfFuncId::Snprintf => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::PtrToMemRdonly, BpfArgType::PtrToMemRdonly, BpfArgType::ConstSizeOrZero],
        )),
        BpfFuncId::SnprintfBtf => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Iterator helpers (bpf_loop)
        BpfFuncId::Loop => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToStack, BpfArgType::Anything],
        )),
        // Kptr helpers
        BpfFuncId::KptrXchg => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull,
            &[BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        // User ringbuf helpers
        BpfFuncId::UserRingbufDrain => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToStack, BpfArgType::Anything],
        )),
        // Find VMA helper (sleepable)
        BpfFuncId::FindVma => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToStack, BpfArgType::Anything],
        )),
        // Trace vprintk
        BpfFuncId::TraceVprintk => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // Get function IP (for profiling)
        BpfFuncId::GetFuncIp => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // Set return value
        BpfFuncId::SetRetval => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything],
        )),
        // Get return value
        BpfFuncId::GetRetval => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        // Copy from user
        BpfFuncId::CopyFromUser => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Copy from user task
        BpfFuncId::CopyFromUserTask => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Per-CPU helpers
        BpfFuncId::PerCpuPtr => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull,
            &[BpfArgType::PtrToMem, BpfArgType::Anything],
        )),
        BpfFuncId::ThisCpuPtr => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull,
            &[BpfArgType::PtrToMem],
        )),
        // Ktime helpers
        BpfFuncId::KtimeGetBootNs => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::KtimeGetCoarseNs => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::KtimeGetTaiNs => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        // Cgroup helpers
        BpfFuncId::GetCurrentAncestorCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything],
        )),
        BpfFuncId::SkCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::SkAncestorCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        // Socket ops helpers
        BpfFuncId::SockOpsCbFlagsSet => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::SkbLoadBytesRelative => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        // Map push/pop/peek
        BpfFuncId::MapPushElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        BpfFuncId::MapPopElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapValue],
        )),
        BpfFuncId::MapPeekElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToMapValue],
        )),
        // SKB adjust room
        BpfFuncId::SkbAdjustRoom => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Clone redirect
        BpfFuncId::CloneRedirect => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Get hash recalc
        BpfFuncId::GetHashRecalc => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::SetHashInvalid => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::SetHash => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        // Get route realm
        BpfFuncId::GetRouteRealm => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // FIB lookup
        BpfFuncId::FibLookup => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Setsockopt/getsockopt
        BpfFuncId::Setsockopt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::Getsockopt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        // Get listener socket
        BpfFuncId::GetListenerSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToCtx],
        )),
        // Check MTU
        BpfFuncId::CheckMtu => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Send signal
        BpfFuncId::SendSignal => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything],
        )),
        BpfFuncId::SendSignalThread => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything],
        )),
        // Override return
        BpfFuncId::OverrideReturn => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        // Read branch records
        BpfFuncId::ReadBranchRecords => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // Get stack
        BpfFuncId::GetStack => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::GetStackid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // Jiffies64
        BpfFuncId::Jiffies64 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        // Skc lookup
        BpfFuncId::SkcLookupTcp => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkAssign => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToSocket, BpfArgType::Anything],
        )),
        // Bind
        BpfFuncId::Bind => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::Anything],
        )),
        // Seq helpers
        BpfFuncId::SeqWrite => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SeqPrintf => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::PtrToMem, BpfArgType::ConstSizeOrZero],
        )),
        BpfFuncId::SeqPrintfBtf => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // D-path
        BpfFuncId::DPath => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // Sock hash/map update
        BpfFuncId::SockMapUpdate => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        BpfFuncId::SockHashUpdate => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        // Msg redirect
        BpfFuncId::MsgRedirectMap => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::MsgRedirectHash => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        // Sk redirect
        BpfFuncId::SkRedirectMap => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkRedirectHash => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        // For each map elem
        BpfFuncId::ForEachMapElem => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToStack, BpfArgType::Anything],
        )),
        // Sys BPF
        BpfFuncId::SysBpf => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // Kallsyms lookup
        BpfFuncId::KallsymsLookupName => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::PtrToMem],
        )),
        // Ima helpers
        BpfFuncId::ImaInodeHash => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::ImaFileHash => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        // Cgroup storage helpers
        BpfFuncId::CgrpStorageGet => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        BpfFuncId::CgrpStorageDelete => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // Socket/task/inode storage helpers
        BpfFuncId::SkStorageGet => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToSocket, BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        BpfFuncId::SkStorageDelete => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::PtrToSocket],
        )),
        BpfFuncId::TaskStorageGet => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        BpfFuncId::TaskStorageDelete => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        BpfFuncId::InodeStorageGet => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValueOrNull,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToMapValue, BpfArgType::Anything],
        )),
        BpfFuncId::InodeStorageDelete => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // String comparison
        BpfFuncId::Strncmp => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize, BpfArgType::PtrToMemRdonly],
        )),
        // Get function arguments (tracing)
        BpfFuncId::GetFuncArg => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem],
        )),
        BpfFuncId::GetFuncRet => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem],
        )),
        BpfFuncId::GetFuncArgCnt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // Ringbuf dynptr helpers
        BpfFuncId::RingbufReserveDynptr => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToDynptr],
        )),
        BpfFuncId::RingbufSubmitDynptr => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToDynptr, BpfArgType::Anything],
        )),
        BpfFuncId::RingbufDiscardDynptr => Some(HelperProto::new(
            func_id,
            BpfRetType::Void,
            &[BpfArgType::PtrToDynptr, BpfArgType::Anything],
        )),
        // XDP buffer helpers
        BpfFuncId::XdpGetBuffLen => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::XdpLoadBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::XdpStoreBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // TCP syncookie helpers
        BpfFuncId::TcpRawGenSyncookieIpv4 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::TcpRawGenSyncookieIpv6 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::TcpRawCheckSyncookieIpv4 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::TcpRawCheckSyncookieIpv6 => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMem, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // Get attach cookie
        BpfFuncId::GetAttachCookie => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        // Task pt_regs
        BpfFuncId::TaskPtRegs => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMemOrNull,
            &[BpfArgType::Anything],
        )),
        // Get branch snapshot
        BpfFuncId::GetBranchSnapshot => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // SKB timestamp
        BpfFuncId::SkbSetTstamp => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // =========== Additional SKB helpers ===========
        BpfFuncId::SkbCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::SkbAncestorCgroupId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::SkbCgroupClassid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::SkbChangeProto => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkbUnderCgroup => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        BpfFuncId::SkbGetTunnelOpt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SkbSetTunnelOpt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SkbGetXfrmState => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::SkbOutput => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SkbEcnSetCe => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::XdpOutput => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // =========== Socket conversion helpers ===========
        BpfFuncId::SkFullsock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::TcpSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToTcpSockOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToTcpSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToTcpSockOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToTcp6Sock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToTcpSockOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToUdp6Sock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToTcpTimewaitSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToTcpSockOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToTcpRequestSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToTcpSockOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToUnixSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SkcToMptcpSock => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::PtrToSocket],
        )),
        BpfFuncId::SockFromFile => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToSocketOrNull,
            &[BpfArgType::Anything], // file pointer
        )),
        // =========== TCP helpers ===========
        BpfFuncId::TcpCheckSyncookie => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToSocket, BpfArgType::PtrToMem, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::Anything],
        )),
        BpfFuncId::TcpGenSyncookie => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToSocket, BpfArgType::PtrToMem, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::Anything],
        )),
        BpfFuncId::TcpSendAck => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        // =========== MSG helpers ===========
        BpfFuncId::MsgApplyBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::MsgCorkBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::MsgPullData => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::MsgPushData => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::MsgPopData => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // =========== LWT helpers ===========
        BpfFuncId::LwtPushEncap => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::LwtSeg6StoreBytes => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::LwtSeg6AdjustSrh => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::LwtSeg6Action => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize],
        )),
        // =========== Sysctl helpers ===========
        BpfFuncId::SysctlGetName => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSizeOrZero, BpfArgType::Anything],
        )),
        BpfFuncId::SysctlGetCurrentValue => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SysctlGetNewValue => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::SysctlSetNewValue => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize],
        )),
        // =========== String helpers ===========
        BpfFuncId::Strtol => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::PtrToStack],
        )),
        BpfFuncId::Strtoul => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::PtrToStack],
        )),
        // =========== Socket header option helpers ===========
        BpfFuncId::LoadHdrOpt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::StoreHdrOpt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ReserveHdrOpt => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        // =========== Redirect helpers ===========
        BpfFuncId::RedirectNeigh => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::RedirectPeer => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SkSelectReuseport => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::ConstMapPtr, BpfArgType::PtrToMapKey, BpfArgType::Anything],
        )),
        // =========== Cgroup helpers ===========
        BpfFuncId::CurrentTaskUnderCgroup => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        BpfFuncId::GetLocalStorage => Some(HelperProto::new(
            func_id,
            BpfRetType::PtrToMapValue,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // =========== Perf event helpers ===========
        BpfFuncId::PerfEventReadValue => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::PerfProgReadValue => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        // =========== Misc helpers ===========
        BpfFuncId::GetNumaNodeId => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[],
        )),
        BpfFuncId::GetSocketUid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::GetNetnsCookie => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::GetNsCurrentPidTgid => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize],
        )),
        BpfFuncId::GetTaskStack => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToUninitMem, BpfArgType::ConstSize, BpfArgType::Anything],
        )),
        BpfFuncId::ProbeWriteUser => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize],
        )),
        BpfFuncId::CsumUpdate => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::CsumLevel => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything],
        )),
        BpfFuncId::RingbufQuery => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::ConstMapPtr, BpfArgType::Anything],
        )),
        // =========== Remote control helpers ===========
        BpfFuncId::RcRepeat => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx],
        )),
        BpfFuncId::RcKeydown => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::RcPointerRel => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToCtx, BpfArgType::Anything, BpfArgType::Anything],
        )),
        // =========== BTF/Sys helpers ===========
        BpfFuncId::BtfFindByNameKind => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::PtrToMemRdonly, BpfArgType::ConstSize, BpfArgType::Anything, BpfArgType::Anything],
        )),
        BpfFuncId::SysClose => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything],
        )),
        BpfFuncId::BprmOptsSet => Some(HelperProto::new(
            func_id,
            BpfRetType::Integer,
            &[BpfArgType::Anything, BpfArgType::Anything],
        )),
        // Unspec is not a real helper
        BpfFuncId::Unspec => None,
    }
}

/// Check a helper function call
pub fn check_helper_call(
    state: &mut BpfVerifierState,
    id_gen: &mut u32,
    func_id: BpfFuncId,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<()> {
    // Create default user memory context - caller should use check_helper_call_with_ctx
    // for proper user memory validation
    let user_ctx = UserMemContext::default();
    check_helper_call_with_ctx(state, id_gen, func_id, insn_idx, allow_ptr_leaks, &user_ctx)
}

/// Check a helper function call with user memory context
pub fn check_helper_call_with_ctx(
    state: &mut BpfVerifierState,
    id_gen: &mut u32,
    func_id: BpfFuncId,
    insn_idx: usize,
    allow_ptr_leaks: bool,
    user_ctx: &UserMemContext,
) -> Result<()> {
    let proto = get_helper_proto(func_id).ok_or_else(|| {
        VerifierError::InvalidHelperCall(format!("unknown helper {:?}", func_id))
    })?;

    let mut meta = HelperCallMeta::default();
    meta.func_id = func_id;

    // Check sleepable context compatibility
    // This validates that sleepable helpers are only called from sleepable programs
    // and that we're not in an atomic context (holding locks, RCU, preempt disabled)
    let helper_name = format!("{:?}", func_id);
    check_helper_sleepable_compat(state, &state.refs, func_id as u32, &helper_name, proto.may_sleep)?;

    // Check each argument
    for (i, &arg_type) in proto.arg_types.iter().enumerate() {
        if arg_type == BpfArgType::DontCare {
            break;
        }

        let regno = i + 1; // Arguments are R1-R5
        meta.regno = regno;

        check_func_arg(state, regno, arg_type, &mut meta, allow_ptr_leaks)?;
    }

    // Validate user memory helper calls
    if is_user_mem_helper(func_id) {
        check_user_mem_helper(state, func_id, &meta, user_ctx)?;
    }

    // Handle acquire functions
    if func_id.is_acquire() {
        meta.ref_obj_id = state.refs.acquire_ptr(insn_idx);
    }

    // Handle spin lock/unlock
    if func_id == BpfFuncId::SpinLock || func_id == BpfFuncId::SpinUnlock {
        handle_spin_lock_helper(state, func_id, insn_idx)?;
    }

    // Clear caller-saved registers
    for regno in 0..=5 {
        if let Some(reg) = state.reg_mut(regno) {
            reg.mark_not_init(false);
        }
    }

    // Set return value
    set_helper_return(state, id_gen, &proto, &meta)?;

    Ok(())
}

/// Handle bpf_spin_lock/bpf_spin_unlock helper calls
fn handle_spin_lock_helper(
    state: &mut BpfVerifierState,
    func_id: BpfFuncId,
    insn_idx: usize,
) -> Result<()> {
    // R1 contains pointer to bpf_spin_lock field in map value
    let reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
    
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_map_value".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    let map_uid = reg.map_uid;
    let lock_off = reg.off as u32;
    
    match func_id {
        BpfFuncId::SpinLock => {
            state.lock_state.acquire(map_uid, lock_off, insn_idx)?;
        }
        BpfFuncId::SpinUnlock => {
            state.lock_state.release(map_uid, lock_off)?;
        }
        _ => {}
    }
    
    Ok(())
}

/// Check user memory helper function calls
/// 
/// This validates helpers that access user-space memory:
/// - bpf_probe_read_user / bpf_probe_read_user_str
/// - bpf_probe_write_user
/// - bpf_copy_from_user / bpf_copy_from_user_task
fn check_user_mem_helper(
    state: &BpfVerifierState,
    func_id: BpfFuncId,
    meta: &HelperCallMeta,
    user_ctx: &UserMemContext,
) -> Result<()> {
    // Get the access type for this helper
    let access_type = get_helper_user_access_type(func_id)
        .ok_or_else(|| VerifierError::Internal(
            format!("is_user_mem_helper returned true but no access type for {:?}", func_id)
        ))?;

    // Get the size argument (R2 for probe_read_user, etc.)
    let size = meta.access_size as u32;
    if size == 0 {
        // Try to get from msize_max_value if access_size not set
        if meta.msize_max_value > 0 && meta.msize_max_value <= u32::MAX as u64 {
            let size = meta.msize_max_value as u32;
            validate_user_mem_helper_args(state, func_id, size, user_ctx, access_type)?;
        }
        // Size of 0 may be allowed for some helpers - let check_user_mem_helper_access decide
    } else {
        validate_user_mem_helper_args(state, func_id, size, user_ctx, access_type)?;
    }

    Ok(())
}

/// Validate arguments for user memory helpers
fn validate_user_mem_helper_args(
    state: &BpfVerifierState,
    func_id: BpfFuncId,
    size: u32,
    user_ctx: &UserMemContext,
    access_type: crate::mem::user::UserMemAccessType,
) -> Result<()> {
    match func_id {
        BpfFuncId::ProbeReadUser | BpfFuncId::ProbeReadUserStr | BpfFuncId::ProbeReadKernel | BpfFuncId::ProbeReadKernelStr => {
            // R1 = dst (kernel buffer), R2 = size, R3 = src (user address)
            let dst_reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
            let src_reg = state.reg(3).ok_or(VerifierError::InvalidRegister(3))?;

            // Validate destination buffer
            validate_probe_read_user_dst(dst_reg, size)?;

            // Validate source address (for user variants)
            if func_id == BpfFuncId::ProbeReadUser || func_id == BpfFuncId::ProbeReadUserStr {
                validate_probe_read_user_src(src_reg)?;
            }

            // Check user memory access permissions
            check_user_mem_helper_access(src_reg, user_ctx, access_type, size)?;
        }

        BpfFuncId::ProbeWriteUser => {
            // R1 = dst (user address), R2 = src (kernel buffer), R3 = size
            let dst_reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;

            // Validate destination is a valid user address
            validate_probe_read_user_src(dst_reg)?; // Same validation - check it's user addr

            // Check user memory access permissions (write requires privilege)
            check_user_mem_helper_access(dst_reg, user_ctx, access_type, size)?;
        }

        BpfFuncId::CopyFromUser => {
            // R1 = dst (kernel buffer), R2 = size, R3 = src (user address)
            let dst_reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
            let src_reg = state.reg(3).ok_or(VerifierError::InvalidRegister(3))?;

            // Validate destination buffer
            validate_probe_read_user_dst(dst_reg, size)?;

            // Validate source address
            validate_probe_read_user_src(src_reg)?;

            // Check user memory access permissions (requires sleepable)
            check_user_mem_helper_access(src_reg, user_ctx, access_type, size)?;
        }

        BpfFuncId::CopyFromUserTask => {
            // R1 = dst, R2 = size, R3 = src (user addr), R4 = task, R5 = flags
            let dst_reg = state.reg(1).ok_or(VerifierError::InvalidRegister(1))?;
            let src_reg = state.reg(3).ok_or(VerifierError::InvalidRegister(3))?;

            // Validate destination buffer
            validate_probe_read_user_dst(dst_reg, size)?;

            // Validate source address
            validate_probe_read_user_src(src_reg)?;

            // Check user memory access permissions
            check_user_mem_helper_access(src_reg, user_ctx, access_type, size)?;
        }

        _ => {
            // Other helpers don't have specific user memory validation
        }
    }

    Ok(())
}

/// Check a single function argument
fn check_func_arg(
    state: &BpfVerifierState,
    regno: usize,
    arg_type: BpfArgType,
    meta: &mut HelperCallMeta,
    _allow_ptr_leaks: bool,
) -> Result<()> {
    let reg = state.reg(regno).ok_or(VerifierError::InvalidRegister(regno as u8))?;

    // Check register is initialized
    if reg.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(regno as u8));
    }

    match arg_type {
        BpfArgType::DontCare | BpfArgType::Anything => {
            // Any value is acceptable
            Ok(())
        }
        BpfArgType::ConstMapPtr => {
            if reg.reg_type != BpfRegType::ConstPtrToMap {
                return Err(VerifierError::TypeMismatch {
                    expected: "const_ptr_to_map".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Extract map pointer register for later use
            meta.map_ptr = Some(regno);
            Ok(())
        }
        BpfArgType::PtrToMapKey => {
            check_mem_arg(reg, "map_key")?;
            // Record the memory pointer for size validation
            meta.mem_size = get_ptr_size(reg);
            Ok(())
        }
        BpfArgType::PtrToMapValue => {
            check_mem_arg(reg, "map_value")?;
            meta.mem_size = get_ptr_size(reg);
            Ok(())
        }
        BpfArgType::PtrToMem | BpfArgType::PtrToMemRdonly => {
            check_mem_arg(reg, "memory")?;
            meta.mem_size = get_ptr_size(reg);
            Ok(())
        }
        BpfArgType::PtrToUninitMem => {
            check_mem_arg(reg, "uninit_memory")?;
            meta.mem_size = get_ptr_size(reg);
            Ok(())
        }
        BpfArgType::PtrToCtx => {
            if reg.reg_type != BpfRegType::PtrToCtx {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_ctx".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            Ok(())
        }
        BpfArgType::PtrToSocket => {
            if reg.reg_type != BpfRegType::PtrToSocket {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_socket".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Check for release
            if meta.func_id == BpfFuncId::SkRelease {
                meta.release_regno = Some(regno);
                meta.ref_obj_id = reg.ref_obj_id;
            }
            Ok(())
        }
        BpfArgType::PtrToStack => {
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_stack".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            Ok(())
        }
        BpfArgType::ConstSize | BpfArgType::ConstSizeOrZero => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "scalar".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            
            // Check size bounds
            let zero_allowed = arg_type == BpfArgType::ConstSizeOrZero;
            check_mem_size_bounds(reg, meta, zero_allowed)?;
            
            Ok(())
        }
        BpfArgType::PtrToAllocMem => {
            if reg.reg_type != BpfRegType::PtrToMem || 
               !reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_alloc_mem".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            Ok(())
        }
        BpfArgType::PtrToDynptr => {
            // Dynptr must be on stack with correct slot type
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_dynptr (stack)".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Dynptr takes 16 bytes (2 stack slots)
            // Check offset is valid and aligned
            let stack_off = reg.off;
            if stack_off > 0 || stack_off < -(MAX_BPF_STACK as i32) + 16 {
                return Err(VerifierError::InvalidHelperCall(
                    format!("R{} dynptr at invalid stack offset {}", regno, stack_off)
                ));
            }
            if (stack_off % 8) != 0 {
                return Err(VerifierError::InvalidHelperCall(
                    format!("R{} dynptr at unaligned stack offset {}", regno, stack_off)
                ));
            }
            Ok(())
        }
        BpfArgType::PtrToBtfId => {
            // Must be a BTF-typed pointer
            if reg.reg_type != BpfRegType::PtrToBtfId {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_btf_id".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // BTF ID should match what the helper expects (checked separately)
            Ok(())
        }
        BpfArgType::PtrToTimer => {
            // Timer must be embedded in map value
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_timer (in map value)".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Timer offset within map value should be validated
            // The offset should point to a bpf_timer struct
            Ok(())
        }
        BpfArgType::PtrToKptr => {
            // Kptr must be in map value at correct offset
            if reg.reg_type != BpfRegType::PtrToMapValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "ptr_to_kptr (in map value)".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Kptr field offset validation would be done via BTF
            Ok(())
        }
        BpfArgType::ConstAllocSizeOrZero => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::TypeMismatch {
                    expected: "scalar".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
            // Similar to ConstSizeOrZero but for allocation
            check_mem_size_bounds(reg, meta, true)?;
            Ok(())
        }
    }
}

/// Get the accessible size of a pointer
///
/// Returns the maximum number of bytes that can be safely accessed
/// starting from the current pointer position.
fn get_ptr_size(reg: &BpfRegState) -> i32 {
    match reg.reg_type {
        BpfRegType::PtrToStack => {
            // Stack access size depends on offset from frame pointer
            // Stack grows downward: FP points to top, valid range is [FP-512, FP)
            // If reg.off = -16, we can access 16 bytes (from -16 to 0)
            let stack_off = reg.off;
            if stack_off >= 0 {
                0 // Invalid: above frame pointer
            } else if stack_off < -(MAX_BPF_STACK as i32) {
                0 // Invalid: below stack limit
            } else {
                // Accessible size is from current offset to 0 (frame pointer)
                (-stack_off) as i32
            }
        }
        BpfRegType::PtrToMapValue => {
            // Get size from map metadata if available
            if let Some(ref map_info) = reg.map_ptr {
                let remaining = (map_info.value_size as i32) - reg.off;
                if remaining > 0 { remaining } else { 0 }
            } else {
                // No map info available - use variable offset tracking
                // If we have bounds on the offset, use them
                if reg.var_off.is_const() {
                    // Constant offset but unknown map size
                    i32::MAX
                } else {
                    i32::MAX
                }
            }
        }
        BpfRegType::PtrToMapKey => {
            // Get key size from map metadata if available
            if let Some(ref map_info) = reg.map_ptr {
                let remaining = (map_info.key_size as i32) - reg.off;
                if remaining > 0 { remaining } else { 0 }
            } else {
                i32::MAX
            }
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            // Packet access bounds are tracked via range comparisons
            // The packet_end register holds the end of accessible data
            // Use the tracked bounds if available
            // Packet pointers use var_off to track the variable portion
            // and off for the fixed offset from packet start
            if reg.var_off.is_const() {
                // Constant offset - can compute exact remaining size
                // but we don't know packet length at verify time
                i32::MAX
            } else if reg.umax_value < i32::MAX as u64 && reg.umax_value > 0 {
                // Use tracked unsigned max as upper bound hint
                reg.umax_value as i32
            } else {
                // No range info - bounds will be checked dynamically via
                // comparison with pkt_end before access
                i32::MAX
            }
        }
        BpfRegType::PtrToPacketEnd => {
            // packet_end itself shouldn't be dereferenced
            0
        }
        BpfRegType::PtrToCtx => {
            // Context size depends on program type
            // This is validated by check_ctx_access separately
            i32::MAX
        }
        BpfRegType::PtrToMem => {
            // Generic memory pointer - check mem_size field
            if reg.mem_size > 0 {
                let remaining = (reg.mem_size as i32) - reg.off;
                if remaining > 0 { remaining } else { 0 }
            } else {
                i32::MAX
            }
        }
        BpfRegType::PtrToBtfId => {
            // BTF-typed pointer - size comes from BTF type info
            // Would need to look up the type size from BTF
            i32::MAX
        }
        _ => i32::MAX, // Unknown pointer types - allow but may be checked elsewhere
    }
}

/// Check memory size argument bounds
fn check_mem_size_bounds(
    reg: &BpfRegState,
    meta: &mut HelperCallMeta,
    zero_allowed: bool,
) -> Result<()> {
    // Store the max size for return value bounds later
    meta.msize_max_value = reg.umax_value;
    
    if reg.is_const() {
        let size = reg.const_value() as i64;
        
        // Check for negative size (signed interpretation)
        if size < 0 {
            return Err(VerifierError::InvalidHelperCall(
                format!("R{} has negative size {}", meta.regno, size)
            ));
        }
        
        // Check for zero when not allowed
        if size == 0 && !zero_allowed {
            return Err(VerifierError::InvalidHelperCall(
                format!("R{} has zero size but zero is not allowed", meta.regno)
            ));
        }
        
        meta.access_size = size as i32;
        
        // Verify against the memory buffer size from the previous argument
        if meta.mem_size > 0 && size > meta.mem_size as i64 {
            return Err(VerifierError::InvalidHelperCall(
                format!(
                    "size {} exceeds memory buffer size {}",
                    size, meta.mem_size
                )
            ));
        }
    } else {
        // Variable size - check bounds
        
        // Minimum must not be negative
        if reg.smin_value < 0 {
            return Err(VerifierError::InvalidHelperCall(
                format!(
                    "R{} min value {} is negative",
                    meta.regno, reg.smin_value
                )
            ));
        }
        
        // If zero not allowed, minimum must be > 0
        if !zero_allowed && reg.umin_value == 0 {
            return Err(VerifierError::InvalidHelperCall(
                format!(
                    "R{} may be zero but zero size is not allowed",
                    meta.regno
                )
            ));
        }
        
        // Check maximum against buffer size
        if meta.mem_size > 0 && reg.umax_value > meta.mem_size as u64 {
            return Err(VerifierError::InvalidHelperCall(
                format!(
                    "R{} unbounded memory access, max size {} exceeds buffer {}",
                    meta.regno, reg.umax_value, meta.mem_size
                )
            ));
        }
        
        // For unprivileged mode, require bounded access
        // The kernel requires exact bounds or marked initialization
        if reg.umax_value == u64::MAX {
            return Err(VerifierError::InvalidHelperCall(
                format!(
                    "R{} has unbounded size, cannot determine memory access bounds",
                    meta.regno
                )
            ));
        }
        
        meta.access_size = reg.umax_value as i32;
    }
    
    Ok(())
}

/// Check memory argument type
fn check_mem_arg(reg: &BpfRegState, expected: &str) -> Result<()> {
    match reg.reg_type {
        BpfRegType::PtrToStack |
        BpfRegType::PtrToMapValue |
        BpfRegType::PtrToMapKey |
        BpfRegType::PtrToMem |
        BpfRegType::PtrToPacket |
        BpfRegType::PtrToPacketMeta => Ok(()),
        BpfRegType::ScalarValue if reg.is_null() => Ok(()), // NULL is OK for some
        _ => Err(VerifierError::TypeMismatch {
            expected: expected.into(),
            got: format!("{:?}", reg.reg_type),
        }),
    }
}

/// Set the return value from a helper function
fn set_helper_return(
    state: &mut BpfVerifierState,
    env_id_gen: &mut u32,
    proto: &HelperProto,
    meta: &HelperCallMeta,
) -> Result<()> {
    // Get map_ptr from the map argument register if available
    let map_ptr = if let Some(map_regno) = meta.map_ptr {
        state.reg(map_regno).and_then(|r| r.map_ptr.clone())
    } else {
        None
    };
    
    let map_uid = if let Some(map_regno) = meta.map_ptr {
        state.reg(map_regno).map(|r| r.map_uid).unwrap_or(0)
    } else {
        0
    };

    let r0 = state.reg_mut(BPF_REG_0).ok_or(VerifierError::Internal(
        "no R0".into(),
    ))?;

    match proto.ret_type {
        BpfRetType::Void => {
            r0.mark_not_init(false);
        }
        BpfRetType::Integer => {
            r0.mark_unknown(false);
            r0.reg_type = BpfRegType::ScalarValue;
        }
        BpfRetType::PtrToMapValueOrNull | BpfRetType::PtrToMapValue => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToMapValue;
            
            // Propagate map metadata for bounds checking
            r0.map_ptr = map_ptr;
            r0.map_uid = map_uid;
            
            if proto.ret_type == BpfRetType::PtrToMapValueOrNull {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
                // Assign unique ID for NULL tracking
                *env_id_gen += 1;
                r0.id = *env_id_gen;
            } else {
                r0.type_flags = BpfTypeFlag::empty();
            }
        }
        BpfRetType::PtrToSocketOrNull | BpfRetType::PtrToSocket => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToSocket;
            
            if proto.ret_type == BpfRetType::PtrToSocketOrNull {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
                r0.ref_obj_id = meta.ref_obj_id;
                *env_id_gen += 1;
                r0.id = *env_id_gen;
            } else {
                r0.type_flags = BpfTypeFlag::empty();
            }
        }
        BpfRetType::PtrToTcpSockOrNull => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToTcpSock;
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            *env_id_gen += 1;
            r0.id = *env_id_gen;
        }
        BpfRetType::PtrToSockCommonOrNull => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToSockCommon;
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            *env_id_gen += 1;
            r0.id = *env_id_gen;
        }
        BpfRetType::PtrToMemOrNull | BpfRetType::PtrToMem => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToMem;
            // Track memory size from the size argument
            r0.mem_size = meta.msize_max_value as u32;
            
            if proto.ret_type == BpfRetType::PtrToMemOrNull {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
                *env_id_gen += 1;
                r0.id = *env_id_gen;
            } else {
                r0.type_flags = BpfTypeFlag::empty();
            }
        }
        BpfRetType::PtrToAllocMemOrNull => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToMem;
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL | BpfTypeFlag::MEM_ALLOC;
            r0.ref_obj_id = meta.ref_obj_id;
            *env_id_gen += 1;
            r0.id = *env_id_gen;
            // Track allocated size
            r0.mem_size = meta.msize_max_value as u32;
        }
        BpfRetType::PtrToBtfIdOrNull | BpfRetType::PtrToBtfId => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToBtfId;
            // BTF ID would be set from meta.ret_btf_id if we had it
            
            if proto.ret_type == BpfRetType::PtrToBtfIdOrNull {
                r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
                *env_id_gen += 1;
                r0.id = *env_id_gen;
            } else {
                r0.type_flags = BpfTypeFlag::empty();
            }
        }
        BpfRetType::PtrToMemOrBtfId => {
            // This depends on the BTF type - for now treat as memory
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToMem;
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            r0.mem_size = meta.msize_max_value as u32;
            *env_id_gen += 1;
            r0.id = *env_id_gen;
        }
        BpfRetType::PtrToDynptrMemOrNull => {
            r0.mark_known_zero();
            r0.reg_type = BpfRegType::PtrToMem;
            r0.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
            r0.mem_size = meta.msize_max_value as u32;
            // dynptr_id would be set from meta.dynptr_id
            *env_id_gen += 1;
            r0.id = *env_id_gen;
        }
    }

    Ok(())
}

/// Check map and function compatibility
pub fn check_map_func_compatibility(
    map_type: BpfMapType,
    func_id: BpfFuncId,
) -> Result<()> {
    // Some helpers only work with specific map types
    match func_id {
        BpfFuncId::TailCall => {
            if map_type != BpfMapType::ProgArray {
                return Err(VerifierError::InvalidHelperCall(
                    "tail_call requires PROG_ARRAY map".into(),
                ));
            }
        }
        BpfFuncId::PerfEventOutput | BpfFuncId::PerfEventRead => {
            if map_type != BpfMapType::PerfEventArray {
                return Err(VerifierError::InvalidHelperCall(
                    "perf_event helpers require PERF_EVENT_ARRAY map".into(),
                ));
            }
        }
        BpfFuncId::RingbufReserve | BpfFuncId::RingbufOutput => {
            if map_type != BpfMapType::Ringbuf {
                return Err(VerifierError::InvalidHelperCall(
                    "ringbuf helpers require RINGBUF map".into(),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_helper_proto() {
        let proto = get_helper_proto(BpfFuncId::MapLookupElem);
        assert!(proto.is_some());
        
        let proto = proto.unwrap();
        assert_eq!(proto.arg_types[0], BpfArgType::ConstMapPtr);
        assert_eq!(proto.arg_types[1], BpfArgType::PtrToMapKey);
    }

    #[test]
    fn test_helper_proto_construction() {
        let proto = HelperProto::new(
            BpfFuncId::KtimeGetNs,
            BpfRetType::Integer,
            &[],
        );
        
        assert_eq!(proto.arg_types[0], BpfArgType::DontCare);
    }

    #[test]
    fn test_check_mem_arg() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        
        assert!(check_mem_arg(&reg, "memory").is_ok());
        
        reg.reg_type = BpfRegType::PtrToCtx;
        assert!(check_mem_arg(&reg, "memory").is_err());
    }
}
