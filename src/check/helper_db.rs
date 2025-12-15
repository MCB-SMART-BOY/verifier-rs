//! Comprehensive BPF helper function database
//!
//! This module provides complete prototypes for all BPF helper functions,
//! including argument types, return types, and special characteristics.

use crate::core::types::*;
use super::helper::HelperProto;

/// Helper function flags
#[derive(Debug, Clone, Copy, Default)]
pub struct HelperFlags {
    /// Function requires CAP_SYS_ADMIN or CAP_PERFMON
    pub privileged: bool,
    /// Function may sleep (not allowed in some contexts)
    pub may_sleep: bool,
    /// Function acquires a reference that must be released
    pub acquires_ref: bool,
    /// Function releases a reference
    pub releases_ref: bool,
    /// Function is only available to specific program types
    pub restricted: bool,
    /// Function performs packet access
    pub pkt_access: bool,
    /// Function modifies packet data
    pub pkt_modify: bool,
}

impl HelperFlags {
    /// Privileged helper
    pub const fn privileged() -> Self {
        Self {
            privileged: true,
            ..Self::default_const()
        }
    }
    
    /// Sleepable helper
    pub const fn sleepable() -> Self {
        Self {
            may_sleep: true,
            ..Self::default_const()
        }
    }
    
    /// Reference acquiring helper
    pub const fn acquire() -> Self {
        Self {
            acquires_ref: true,
            ..Self::default_const()
        }
    }
    
    /// Reference releasing helper
    pub const fn release() -> Self {
        Self {
            releases_ref: true,
            ..Self::default_const()
        }
    }
    
    /// Packet-accessing helper
    pub const fn pkt() -> Self {
        Self {
            pkt_access: true,
            ..Self::default_const()
        }
    }
    
    const fn default_const() -> Self {
        Self {
            privileged: false,
            may_sleep: false,
            acquires_ref: false,
            releases_ref: false,
            restricted: false,
            pkt_access: false,
            pkt_modify: false,
        }
    }
}

/// Extended helper prototype with full metadata
#[derive(Debug, Clone)]
pub struct HelperDef {
    /// Function ID
    pub func_id: BpfFuncId,
    /// Human-readable name
    pub name: &'static str,
    /// Return type
    pub ret_type: BpfRetType,
    /// Argument types (up to 5)
    pub arg_types: [BpfArgType; 5],
    /// Helper flags
    pub flags: HelperFlags,
    /// Program types that can use this helper (empty = all)
    pub allowed_prog_types: &'static [BpfProgType],
}

impl HelperDef {
    /// Create a new helper definition
    const fn new(
        func_id: BpfFuncId,
        name: &'static str,
        ret_type: BpfRetType,
        args: [BpfArgType; 5],
    ) -> Self {
        Self {
            func_id,
            name,
            ret_type,
            arg_types: args,
            flags: HelperFlags::default_const(),
            allowed_prog_types: &[],
        }
    }
    
    /// Create helper with flags
    const fn with_flags(mut self, flags: HelperFlags) -> Self {
        self.flags = flags;
        self
    }
    
    /// Create helper with program type restrictions
    #[allow(dead_code)]
    const fn for_progs(mut self, progs: &'static [BpfProgType]) -> Self {
        self.allowed_prog_types = progs;
        self
    }
    
    /// Convert to HelperProto
    pub fn to_proto(&self) -> HelperProto {
        HelperProto {
            func_id: self.func_id,
            ret_type: self.ret_type,
            arg_types: self.arg_types,
            privileged_only: self.flags.privileged,
            may_sleep: self.flags.may_sleep,
        }
    }
}

/// Shorthand for creating argument arrays
const fn args(a0: BpfArgType, a1: BpfArgType, a2: BpfArgType, a3: BpfArgType, a4: BpfArgType) -> [BpfArgType; 5] {
    [a0, a1, a2, a3, a4]
}

/// No arguments
const NO_ARGS: [BpfArgType; 5] = [BpfArgType::DontCare; 5];

/// Alias for common argument types
const MAP: BpfArgType = BpfArgType::ConstMapPtr;
const KEY: BpfArgType = BpfArgType::PtrToMapKey;
const VAL: BpfArgType = BpfArgType::PtrToMapValue;
const CTX: BpfArgType = BpfArgType::PtrToCtx;
const MEM: BpfArgType = BpfArgType::PtrToMem;
const MEMRD: BpfArgType = BpfArgType::PtrToMemRdonly;
const UNINIT: BpfArgType = BpfArgType::PtrToUninitMem;
const SIZE: BpfArgType = BpfArgType::ConstSize;
const SIZE0: BpfArgType = BpfArgType::ConstSizeOrZero;
const ANY: BpfArgType = BpfArgType::Anything;
const NONE: BpfArgType = BpfArgType::DontCare;
const SOCK: BpfArgType = BpfArgType::PtrToSocket;
const STK: BpfArgType = BpfArgType::PtrToStack;
const ALLOC: BpfArgType = BpfArgType::PtrToAllocMem;
const BTF: BpfArgType = BpfArgType::PtrToBtfId;
const DYNPTR: BpfArgType = BpfArgType::PtrToDynptr;
const TIMER: BpfArgType = BpfArgType::PtrToTimer;
// Note: PtrToFunc/callback is represented as PtrToBtfId for function pointers
const FUNC: BpfArgType = BpfArgType::PtrToBtfId;

/// Return type aliases  
const INT: BpfRetType = BpfRetType::Integer;
const VOID: BpfRetType = BpfRetType::Void;
const MAP_VAL: BpfRetType = BpfRetType::PtrToMapValue;
const MAP_VAL_NULL: BpfRetType = BpfRetType::PtrToMapValueOrNull;
const SOCK_NULL: BpfRetType = BpfRetType::PtrToSocketOrNull;
const ALLOC_NULL: BpfRetType = BpfRetType::PtrToAllocMemOrNull;
const MEM_NULL: BpfRetType = BpfRetType::PtrToMemOrNull;
#[allow(dead_code)]
const BTF_NULL: BpfRetType = BpfRetType::PtrToBtfIdOrNull;

/// Complete database of BPF helper functions
pub static HELPER_DB: &[HelperDef] = &[
    // =========== Map Operations ===========
    HelperDef::new(BpfFuncId::MapLookupElem, "map_lookup_elem", MAP_VAL_NULL,
        args(MAP, KEY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MapUpdateElem, "map_update_elem", INT,
        args(MAP, KEY, VAL, ANY, NONE)),
    HelperDef::new(BpfFuncId::MapDeleteElem, "map_delete_elem", INT,
        args(MAP, KEY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MapPushElem, "map_push_elem", INT,
        args(MAP, VAL, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::MapPopElem, "map_pop_elem", INT,
        args(MAP, VAL, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MapPeekElem, "map_peek_elem", INT,
        args(MAP, VAL, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MapLookupPercpuElem, "map_lookup_percpu_elem", MAP_VAL_NULL,
        args(MAP, KEY, ANY, NONE, NONE)),
        
    // =========== Probe/Tracing ===========
    HelperDef::new(BpfFuncId::ProbeRead, "probe_read", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE))
        .with_flags(HelperFlags::privileged()),
    HelperDef::new(BpfFuncId::ProbeReadStr, "probe_read_str", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE))
        .with_flags(HelperFlags::privileged()),
    HelperDef::new(BpfFuncId::ProbeReadUser, "probe_read_user", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::ProbeReadKernel, "probe_read_kernel", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::ProbeReadUserStr, "probe_read_user_str", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::ProbeReadKernelStr, "probe_read_kernel_str", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::ProbeWriteUser, "probe_write_user", INT,
        args(ANY, MEMRD, SIZE, NONE, NONE))
        .with_flags(HelperFlags::privileged()),
        
    // =========== Time ===========
    HelperDef::new(BpfFuncId::KtimeGetNs, "ktime_get_ns", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::KtimeGetBootNs, "ktime_get_boot_ns", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::KtimeGetCoarseNs, "ktime_get_coarse_ns", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::Jiffies64, "jiffies64", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::KtimeGetTaiNs, "ktime_get_tai_ns", INT, NO_ARGS),
    
    // =========== Random ===========
    HelperDef::new(BpfFuncId::GetPrandomU32, "get_prandom_u32", INT, NO_ARGS),
    
    // =========== CPU/NUMA ===========
    HelperDef::new(BpfFuncId::GetSmpProcessorId, "get_smp_processor_id", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::GetNumaNodeId, "get_numa_node_id", INT, NO_ARGS),
    
    // =========== Process Info ===========
    HelperDef::new(BpfFuncId::GetCurrentPidTgid, "get_current_pid_tgid", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::GetCurrentUidGid, "get_current_uid_gid", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::GetCurrentComm, "get_current_comm", INT,
        args(UNINIT, SIZE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetCurrentTask, "get_current_task", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::GetCurrentCgroupId, "get_current_cgroup_id", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::GetCurrentAncestorCgroupId, "get_current_ancestor_cgroup_id", INT,
        args(ANY, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetNsCurrentPidTgid, "get_ns_current_pid_tgid", INT,
        args(ANY, ANY, UNINIT, SIZE, NONE)),
    HelperDef::new(BpfFuncId::GetTaskStack, "get_task_stack", INT,
        args(BTF, UNINIT, SIZE, ANY, NONE)),
        
    // =========== Cgroup ===========
    HelperDef::new(BpfFuncId::GetCgroupClassid, "get_cgroup_classid", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbCgroupId, "skb_cgroup_id", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbAncestorCgroupId, "skb_ancestor_cgroup_id", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkCgroupId, "sk_cgroup_id", INT,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkAncestorCgroupId, "sk_ancestor_cgroup_id", INT,
        args(SOCK, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::CurrentTaskUnderCgroup, "current_task_under_cgroup", INT,
        args(MAP, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbUnderCgroup, "skb_under_cgroup", INT,
        args(CTX, MAP, ANY, NONE, NONE)),
        
    // =========== Output/Tracing ===========
    HelperDef::new(BpfFuncId::TracePrintk, "trace_printk", INT,
        args(MEMRD, SIZE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::PerfEventOutput, "perf_event_output", INT,
        args(CTX, MAP, ANY, MEM, SIZE)),
    HelperDef::new(BpfFuncId::PerfEventRead, "perf_event_read", INT,
        args(MAP, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::PerfEventReadValue, "perf_event_read_value", INT,
        args(MAP, ANY, UNINIT, SIZE, NONE)),
    HelperDef::new(BpfFuncId::PerfProgReadValue, "perf_prog_read_value", INT,
        args(CTX, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetStackid, "get_stackid", INT,
        args(CTX, MAP, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetStack, "get_stack", INT,
        args(CTX, UNINIT, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::ReadBranchRecords, "read_branch_records", INT,
        args(CTX, UNINIT, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::SeqPrintf, "seq_printf", INT,
        args(BTF, MEMRD, SIZE, MEM, SIZE)),
    HelperDef::new(BpfFuncId::SeqWrite, "seq_write", INT,
        args(BTF, MEMRD, SIZE, NONE, NONE)),
        
    // =========== Ringbuf ===========
    HelperDef::new(BpfFuncId::RingbufOutput, "ringbuf_output", INT,
        args(MAP, MEM, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::RingbufReserve, "ringbuf_reserve", ALLOC_NULL,
        args(MAP, ANY, ANY, NONE, NONE))
        .with_flags(HelperFlags::acquire()),
    HelperDef::new(BpfFuncId::RingbufSubmit, "ringbuf_submit", VOID,
        args(ALLOC, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::release()),
    HelperDef::new(BpfFuncId::RingbufDiscard, "ringbuf_discard", VOID,
        args(ALLOC, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::release()),
    HelperDef::new(BpfFuncId::RingbufQuery, "ringbuf_query", INT,
        args(MAP, ANY, NONE, NONE, NONE)),
        
    // =========== Tail Call ===========
    HelperDef::new(BpfFuncId::TailCall, "tail_call", VOID,
        args(CTX, MAP, ANY, NONE, NONE)),
        
    // =========== SKB Operations ===========
    HelperDef::new(BpfFuncId::SkbStoreBytes, "skb_store_bytes", INT,
        args(CTX, ANY, MEM, SIZE, ANY))
        .with_flags(HelperFlags::pkt()),
    HelperDef::new(BpfFuncId::SkbLoadBytes, "skb_load_bytes", INT,
        args(CTX, ANY, UNINIT, SIZE, NONE))
        .with_flags(HelperFlags::pkt()),
    HelperDef::new(BpfFuncId::SkbLoadBytesRelative, "skb_load_bytes_relative", INT,
        args(CTX, ANY, UNINIT, SIZE, ANY))
        .with_flags(HelperFlags::pkt()),
    HelperDef::new(BpfFuncId::SkbPullData, "skb_pull_data", INT,
        args(CTX, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::pkt()),
    HelperDef::new(BpfFuncId::SkbChangeType, "skb_change_type", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbChangeProto, "skb_change_proto", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbChangeTail, "skb_change_tail", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbChangeHead, "skb_change_head", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbAdjustRoom, "skb_adjust_room", INT,
        args(CTX, ANY, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::SkbVlanPush, "skb_vlan_push", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbVlanPop, "skb_vlan_pop", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbGetTunnelKey, "skb_get_tunnel_key", INT,
        args(CTX, UNINIT, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::SkbSetTunnelKey, "skb_set_tunnel_key", INT,
        args(CTX, MEM, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::SkbGetTunnelOpt, "skb_get_tunnel_opt", INT,
        args(CTX, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbSetTunnelOpt, "skb_set_tunnel_opt", INT,
        args(CTX, MEM, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkbGetXfrmState, "skb_get_xfrm_state", INT,
        args(CTX, ANY, UNINIT, SIZE, ANY)),
    HelperDef::new(BpfFuncId::SkbOutput, "skb_output", INT,
        args(CTX, MAP, ANY, MEM, SIZE)),
    HelperDef::new(BpfFuncId::SkbEcnSetCe, "skb_ecn_set_ce", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
        
    // =========== Checksum ===========
    HelperDef::new(BpfFuncId::L3CsumReplace, "l3_csum_replace", INT,
        args(CTX, ANY, ANY, ANY, ANY)),
    HelperDef::new(BpfFuncId::L4CsumReplace, "l4_csum_replace", INT,
        args(CTX, ANY, ANY, ANY, ANY)),
    HelperDef::new(BpfFuncId::CsumDiff, "csum_diff", INT,
        args(MEM, SIZE, MEM, SIZE, ANY)),
    HelperDef::new(BpfFuncId::CsumUpdate, "csum_update", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::CsumLevel, "csum_level", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
        
    // =========== Redirect ===========
    HelperDef::new(BpfFuncId::Redirect, "redirect", INT,
        args(ANY, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::RedirectMap, "redirect_map", INT,
        args(MAP, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::CloneRedirect, "clone_redirect", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkRedirectMap, "sk_redirect_map", INT,
        args(CTX, MAP, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::SkRedirectHash, "sk_redirect_hash", INT,
        args(CTX, MAP, KEY, ANY, NONE)),
    HelperDef::new(BpfFuncId::MsgRedirectMap, "msg_redirect_map", INT,
        args(CTX, MAP, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::MsgRedirectHash, "msg_redirect_hash", INT,
        args(CTX, MAP, KEY, ANY, NONE)),
        
    // =========== XDP ===========
    HelperDef::new(BpfFuncId::XdpAdjustHead, "xdp_adjust_head", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::XdpAdjustTail, "xdp_adjust_tail", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::XdpAdjustMeta, "xdp_adjust_meta", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::XdpOutput, "xdp_output", INT,
        args(CTX, MAP, ANY, MEM, SIZE)),
        
    // =========== Socket Lookup ===========
    HelperDef::new(BpfFuncId::SkLookupTcp, "sk_lookup_tcp", SOCK_NULL,
        args(CTX, MEM, ANY, ANY, ANY))
        .with_flags(HelperFlags::acquire()),
    HelperDef::new(BpfFuncId::SkLookupUdp, "sk_lookup_udp", SOCK_NULL,
        args(CTX, MEM, ANY, ANY, ANY))
        .with_flags(HelperFlags::acquire()),
    HelperDef::new(BpfFuncId::SkcLookupTcp, "skc_lookup_tcp", SOCK_NULL,
        args(CTX, MEM, ANY, ANY, ANY))
        .with_flags(HelperFlags::acquire()),
    HelperDef::new(BpfFuncId::SkRelease, "sk_release", INT,
        args(SOCK, NONE, NONE, NONE, NONE))
        .with_flags(HelperFlags::release()),
    HelperDef::new(BpfFuncId::SkFullsock, "sk_fullsock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::TcpSock, "tcp_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetListenerSock, "get_listener_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkAssign, "sk_assign", INT,
        args(CTX, SOCK, ANY, NONE, NONE)),
        
    // =========== Socket Type Conversion ===========
    HelperDef::new(BpfFuncId::SkcToTcpSock, "skc_to_tcp_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkcToTcp6Sock, "skc_to_tcp6_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkcToUdp6Sock, "skc_to_udp6_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkcToTcpTimewaitSock, "skc_to_tcp_timewait_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkcToTcpRequestSock, "skc_to_tcp_request_sock", SOCK_NULL,
        args(SOCK, NONE, NONE, NONE, NONE)),
        
    // =========== Socket Options ===========
    HelperDef::new(BpfFuncId::Setsockopt, "setsockopt", INT,
        args(CTX, ANY, ANY, MEM, SIZE)),
    HelperDef::new(BpfFuncId::Getsockopt, "getsockopt", INT,
        args(CTX, ANY, ANY, UNINIT, SIZE)),
    HelperDef::new(BpfFuncId::GetSocketCookie, "get_socket_cookie", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetSocketUid, "get_socket_uid", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetNetnsCookie, "get_netns_cookie", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
        
    // =========== Hash/Routing ===========
    HelperDef::new(BpfFuncId::GetHashRecalc, "get_hash_recalc", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SetHash, "set_hash", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SetHashInvalid, "set_hash_invalid", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetRouteRealm, "get_route_realm", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::FibLookup, "fib_lookup", INT,
        args(CTX, MEM, SIZE, ANY, NONE)),
        
    // =========== Sock Map/Hash ===========
    HelperDef::new(BpfFuncId::SockMapUpdate, "sock_map_update", INT,
        args(CTX, MAP, KEY, ANY, NONE)),
    HelperDef::new(BpfFuncId::SockHashUpdate, "sock_hash_update", INT,
        args(CTX, MAP, KEY, ANY, NONE)),
        
    // =========== Socket Ops ===========
    HelperDef::new(BpfFuncId::SockOpsCbFlagsSet, "sock_ops_cb_flags_set", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::LoadHdrOpt, "load_hdr_opt", INT,
        args(CTX, UNINIT, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::StoreHdrOpt, "store_hdr_opt", INT,
        args(CTX, MEM, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::ReserveHdrOpt, "reserve_hdr_opt", INT,
        args(CTX, SIZE, ANY, NONE, NONE)),
        
    // =========== TCP ===========
    HelperDef::new(BpfFuncId::TcpCheckSyncookie, "tcp_check_syncookie", INT,
        args(SOCK, MEM, ANY, MEM, ANY)),
    HelperDef::new(BpfFuncId::TcpGenSyncookie, "tcp_gen_syncookie", INT,
        args(SOCK, MEM, ANY, MEM, ANY)),
    HelperDef::new(BpfFuncId::TcpSendAck, "tcp_send_ack", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
        
    // =========== MSG Operations ===========
    HelperDef::new(BpfFuncId::MsgApplyBytes, "msg_apply_bytes", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MsgCorkBytes, "msg_cork_bytes", INT,
        args(CTX, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::MsgPullData, "msg_pull_data", INT,
        args(CTX, ANY, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::MsgPushData, "msg_push_data", INT,
        args(CTX, ANY, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::MsgPopData, "msg_pop_data", INT,
        args(CTX, ANY, ANY, ANY, NONE)),
        
    // =========== LWT/Encap ===========
    HelperDef::new(BpfFuncId::LwtPushEncap, "lwt_push_encap", INT,
        args(CTX, ANY, MEM, SIZE, NONE)),
    HelperDef::new(BpfFuncId::LwtSeg6StoreBytes, "lwt_seg6_store_bytes", INT,
        args(CTX, ANY, MEM, SIZE, NONE)),
    HelperDef::new(BpfFuncId::LwtSeg6AdjustSrh, "lwt_seg6_adjust_srh", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::LwtSeg6Action, "lwt_seg6_action", INT,
        args(CTX, ANY, MEM, SIZE, NONE)),
        
    // =========== Spin Lock ===========
    HelperDef::new(BpfFuncId::SpinLock, "spin_lock", VOID,
        args(VAL, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SpinUnlock, "spin_unlock", VOID,
        args(VAL, NONE, NONE, NONE, NONE)),
        
    // =========== Signal ===========
    HelperDef::new(BpfFuncId::SendSignal, "send_signal", INT,
        args(ANY, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SendSignalThread, "send_signal_thread", INT,
        args(ANY, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::OverrideReturn, "override_return", INT,
        args(CTX, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::privileged()),
        
    // =========== Sysctl ===========
    HelperDef::new(BpfFuncId::SysctlGetName, "sysctl_get_name", INT,
        args(CTX, UNINIT, SIZE0, ANY, NONE)),
    HelperDef::new(BpfFuncId::SysctlGetCurrentValue, "sysctl_get_current_value", INT,
        args(CTX, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SysctlGetNewValue, "sysctl_get_new_value", INT,
        args(CTX, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SysctlSetNewValue, "sysctl_set_new_value", INT,
        args(CTX, MEMRD, SIZE, NONE, NONE)),
        
    // =========== String ===========
    HelperDef::new(BpfFuncId::Strtol, "strtol", INT,
        args(MEMRD, SIZE, ANY, STK, NONE)),
    HelperDef::new(BpfFuncId::Strtoul, "strtoul", INT,
        args(MEMRD, SIZE, ANY, STK, NONE)),
        
    // =========== Storage ===========
    HelperDef::new(BpfFuncId::SkStorageGet, "sk_storage_get", MAP_VAL_NULL,
        args(MAP, SOCK, VAL, ANY, NONE)),
    HelperDef::new(BpfFuncId::SkStorageDelete, "sk_storage_delete", INT,
        args(MAP, SOCK, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::InodeStorageGet, "inode_storage_get", MAP_VAL_NULL,
        args(MAP, BTF, VAL, ANY, NONE)),
    HelperDef::new(BpfFuncId::InodeStorageDelete, "inode_storage_delete", INT,
        args(MAP, BTF, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::TaskStorageGet, "task_storage_get", MAP_VAL_NULL,
        args(MAP, BTF, VAL, ANY, NONE)),
    HelperDef::new(BpfFuncId::TaskStorageDelete, "task_storage_delete", INT,
        args(MAP, BTF, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetLocalStorage, "get_local_storage", MAP_VAL,
        args(MAP, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::CgrpStorageGet, "cgroup_storage_get", MAP_VAL_NULL,
        args(MAP, BTF, VAL, ANY, NONE)),
    HelperDef::new(BpfFuncId::CgrpStorageDelete, "cgroup_storage_delete", INT,
        args(MAP, BTF, NONE, NONE, NONE)),
        
    // =========== Copy ===========
    HelperDef::new(BpfFuncId::CopyFromUser, "copy_from_user", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE))
        .with_flags(HelperFlags::sleepable()),
    HelperDef::new(BpfFuncId::CopyFromUserTask, "copy_from_user_task", INT,
        args(UNINIT, SIZE, ANY, BTF, ANY))
        .with_flags(HelperFlags::sleepable()),
        
    // =========== Path ===========
    HelperDef::new(BpfFuncId::DPath, "d_path", INT,
        args(BTF, UNINIT, SIZE, NONE, NONE))
        .with_flags(HelperFlags::sleepable()),
        
    // =========== Bind/Select ===========
    HelperDef::new(BpfFuncId::Bind, "bind", INT,
        args(CTX, MEM, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::SkSelectReuseport, "sk_select_reuseport", INT,
        args(CTX, MAP, KEY, ANY, NONE)),
        
    // =========== Remote Control ===========
    HelperDef::new(BpfFuncId::RcRepeat, "rc_repeat", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::RcKeydown, "rc_keydown", INT,
        args(CTX, ANY, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::RcPointerRel, "rc_pointer_rel", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
        
    // =========== Timer ===========
    HelperDef::new(BpfFuncId::TimerInit, "timer_init", INT,
        args(TIMER, MAP, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::TimerSetCallback, "timer_set_callback", INT,
        args(TIMER, FUNC, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::TimerStart, "timer_start", INT,
        args(TIMER, ANY, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::TimerCancel, "timer_cancel", INT,
        args(TIMER, NONE, NONE, NONE, NONE)),
        
    // =========== Dynptr ===========
    HelperDef::new(BpfFuncId::DynptrFromMem, "dynptr_from_mem", INT,
        args(MEM, SIZE, ANY, DYNPTR, NONE)),
    HelperDef::new(BpfFuncId::DynptrRead, "dynptr_read", INT,
        args(UNINIT, SIZE, DYNPTR, ANY, ANY)),
    HelperDef::new(BpfFuncId::DynptrWrite, "dynptr_write", INT,
        args(DYNPTR, ANY, MEM, SIZE, ANY)),
    HelperDef::new(BpfFuncId::DynptrData, "dynptr_data", MEM_NULL,
        args(DYNPTR, ANY, SIZE, NONE, NONE)),
        
    // =========== Snprintf ===========
    HelperDef::new(BpfFuncId::Snprintf, "snprintf", INT,
        args(UNINIT, SIZE, MEMRD, SIZE, ANY)),
    HelperDef::new(BpfFuncId::SnprintfBtf, "snprintf_btf", INT,
        args(UNINIT, SIZE, BTF, SIZE, ANY)),
        
    // =========== Misc ===========
    HelperDef::new(BpfFuncId::GetFuncIp, "get_func_ip", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetAttachCookie, "get_attach_cookie", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetBranchSnapshot, "get_branch_snapshot", INT,
        args(UNINIT, SIZE, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetRetval, "get_retval", INT, NO_ARGS),
    HelperDef::new(BpfFuncId::SetRetval, "set_retval", INT,
        args(ANY, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::FindVma, "find_vma", INT,
        args(BTF, ANY, FUNC, ANY, ANY))
        .with_flags(HelperFlags::sleepable()),
    HelperDef::new(BpfFuncId::Loop, "loop", INT,
        args(ANY, FUNC, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::ForEachMapElem, "for_each_map_elem", INT,
        args(MAP, FUNC, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::UserRingbufDrain, "user_ringbuf_drain", INT,
        args(MAP, FUNC, ANY, ANY, NONE)),
    HelperDef::new(BpfFuncId::CheckMtu, "check_mtu", INT,
        args(CTX, ANY, STK, ANY, ANY)),
    HelperDef::new(BpfFuncId::ImaInodeHash, "ima_inode_hash", INT,
        args(BTF, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::ImaFileHash, "ima_file_hash", INT,
        args(BTF, UNINIT, SIZE, NONE, NONE)),
    HelperDef::new(BpfFuncId::KptrXchg, "kptr_xchg", INT,
        args(VAL, BTF, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::KallsymsLookupName, "kallsyms_lookup_name", INT,
        args(MEMRD, SIZE, ANY, STK, NONE))
        .with_flags(HelperFlags::privileged()),
    HelperDef::new(BpfFuncId::SysBpf, "sys_bpf", INT,
        args(ANY, MEM, SIZE, NONE, NONE))
        .with_flags(HelperFlags::sleepable()),
    HelperDef::new(BpfFuncId::SysClose, "sys_close", INT,
        args(ANY, NONE, NONE, NONE, NONE))
        .with_flags(HelperFlags::sleepable()),
        
    // =========== Additional Helpers (completing coverage) ===========
    
    // Seq printf BTF
    HelperDef::new(BpfFuncId::SeqPrintfBtf, "seq_printf_btf", INT,
        args(BTF, BTF, SIZE, ANY, NONE)),
        
    // SKB cgroup classid
    HelperDef::new(BpfFuncId::SkbCgroupClassid, "skb_cgroup_classid", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
        
    // Redirect neighbors
    HelperDef::new(BpfFuncId::RedirectNeigh, "redirect_neigh", INT,
        args(ANY, MEM, SIZE, ANY, NONE)),
    HelperDef::new(BpfFuncId::RedirectPeer, "redirect_peer", INT,
        args(ANY, ANY, NONE, NONE, NONE)),
        
    // Per-CPU pointers
    HelperDef::new(BpfFuncId::PerCpuPtr, "per_cpu_ptr", MEM_NULL,
        args(BTF, ANY, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::ThisCpuPtr, "this_cpu_ptr", MEM_NULL,
        args(BTF, NONE, NONE, NONE, NONE)),
        
    // Current task BTF
    HelperDef::new(BpfFuncId::GetCurrentTaskBtf, "get_current_task_btf", MEM_NULL, NO_ARGS),
        
    // Bprm opts
    HelperDef::new(BpfFuncId::BprmOptsSet, "bprm_opts_set", INT,
        args(BTF, ANY, NONE, NONE, NONE)),
        
    // Sock from file
    HelperDef::new(BpfFuncId::SockFromFile, "sock_from_file", SOCK_NULL,
        args(BTF, NONE, NONE, NONE, NONE)),
        
    // BTF find by name/kind
    HelperDef::new(BpfFuncId::BtfFindByNameKind, "btf_find_by_name_kind", INT,
        args(MEMRD, SIZE, ANY, ANY, NONE))
        .with_flags(HelperFlags::sleepable()),
        
    // Task pt_regs
    HelperDef::new(BpfFuncId::TaskPtRegs, "task_pt_regs", MEM_NULL,
        args(BTF, NONE, NONE, NONE, NONE)),
        
    // Trace vprintk
    HelperDef::new(BpfFuncId::TraceVprintk, "trace_vprintk", INT,
        args(MEMRD, SIZE, MEM, SIZE, NONE)),
        
    // Skc to unix sock
    HelperDef::new(BpfFuncId::SkcToUnixSock, "skc_to_unix_sock", SOCK_NULL,
        args(BTF, NONE, NONE, NONE, NONE)),
        
    // String compare
    HelperDef::new(BpfFuncId::Strncmp, "strncmp", INT,
        args(MEMRD, SIZE, MEMRD, NONE, NONE)),
        
    // Get function argument/return
    HelperDef::new(BpfFuncId::GetFuncArg, "get_func_arg", INT,
        args(CTX, ANY, STK, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetFuncRet, "get_func_ret", INT,
        args(CTX, STK, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::GetFuncArgCnt, "get_func_arg_cnt", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
        
    // XDP buffer operations
    HelperDef::new(BpfFuncId::XdpGetBuffLen, "xdp_get_buff_len", INT,
        args(CTX, NONE, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::XdpLoadBytes, "xdp_load_bytes", INT,
        args(CTX, ANY, UNINIT, SIZE, NONE)),
    HelperDef::new(BpfFuncId::XdpStoreBytes, "xdp_store_bytes", INT,
        args(CTX, ANY, MEM, SIZE, NONE)),
        
    // SKB timestamp
    HelperDef::new(BpfFuncId::SkbSetTstamp, "skb_set_tstamp", INT,
        args(CTX, ANY, ANY, NONE, NONE)),
        
    // Skc to MPTCP sock
    HelperDef::new(BpfFuncId::SkcToMptcpSock, "skc_to_mptcp_sock", SOCK_NULL,
        args(BTF, NONE, NONE, NONE, NONE)),
        
    // Ringbuf dynptr operations
    HelperDef::new(BpfFuncId::RingbufReserveDynptr, "ringbuf_reserve_dynptr", INT,
        args(MAP, ANY, ANY, DYNPTR, NONE))
        .with_flags(HelperFlags::acquire()),
    HelperDef::new(BpfFuncId::RingbufSubmitDynptr, "ringbuf_submit_dynptr", VOID,
        args(DYNPTR, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::release()),
    HelperDef::new(BpfFuncId::RingbufDiscardDynptr, "ringbuf_discard_dynptr", VOID,
        args(DYNPTR, ANY, NONE, NONE, NONE))
        .with_flags(HelperFlags::release()),
        
    // TCP raw syncookie operations
    HelperDef::new(BpfFuncId::TcpRawGenSyncookieIpv4, "tcp_raw_gen_syncookie_ipv4", INT,
        args(MEM, MEM, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::TcpRawGenSyncookieIpv6, "tcp_raw_gen_syncookie_ipv6", INT,
        args(MEM, MEM, ANY, NONE, NONE)),
    HelperDef::new(BpfFuncId::TcpRawCheckSyncookieIpv4, "tcp_raw_check_syncookie_ipv4", INT,
        args(MEM, MEM, NONE, NONE, NONE)),
    HelperDef::new(BpfFuncId::TcpRawCheckSyncookieIpv6, "tcp_raw_check_syncookie_ipv6", INT,
        args(MEM, MEM, NONE, NONE, NONE)),
];

/// Lookup a helper definition by function ID
pub fn lookup_helper(func_id: BpfFuncId) -> Option<&'static HelperDef> {
    HELPER_DB.iter().find(|h| h.func_id == func_id)
}

/// Lookup a helper definition by name
pub fn lookup_helper_by_name(name: &str) -> Option<&'static HelperDef> {
    HELPER_DB.iter().find(|h| h.name == name)
}

/// Check if a helper is available for a program type
pub fn helper_available_for_prog(helper: &HelperDef, prog_type: BpfProgType) -> bool {
    if helper.allowed_prog_types.is_empty() {
        return true; // Available to all program types
    }
    helper.allowed_prog_types.contains(&prog_type)
}

/// Get all helpers available for a program type
pub fn helpers_for_prog_type(prog_type: BpfProgType) -> impl Iterator<Item = &'static HelperDef> {
    HELPER_DB.iter().filter(move |h| helper_available_for_prog(h, prog_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_helper() {
        let helper = lookup_helper(BpfFuncId::MapLookupElem);
        assert!(helper.is_some());
        let helper = helper.unwrap();
        assert_eq!(helper.name, "map_lookup_elem");
        assert_eq!(helper.arg_types[0], BpfArgType::ConstMapPtr);
        assert_eq!(helper.arg_types[1], BpfArgType::PtrToMapKey);
    }

    #[test]
    fn test_lookup_by_name() {
        let helper = lookup_helper_by_name("ktime_get_ns");
        assert!(helper.is_some());
        assert_eq!(helper.unwrap().func_id, BpfFuncId::KtimeGetNs);
    }

    #[test]
    fn test_acquire_release_flags() {
        let reserve = lookup_helper(BpfFuncId::RingbufReserve).unwrap();
        assert!(reserve.flags.acquires_ref);
        
        let submit = lookup_helper(BpfFuncId::RingbufSubmit).unwrap();
        assert!(submit.flags.releases_ref);
    }

    #[test]
    fn test_privileged_helpers() {
        let probe_read = lookup_helper(BpfFuncId::ProbeRead).unwrap();
        assert!(probe_read.flags.privileged);
        
        let ktime = lookup_helper(BpfFuncId::KtimeGetNs).unwrap();
        assert!(!ktime.flags.privileged);
    }

    #[test]
    fn test_sleepable_helpers() {
        let copy_user = lookup_helper(BpfFuncId::CopyFromUser).unwrap();
        assert!(copy_user.flags.may_sleep);
    }

    #[test]
    fn test_helper_count() {
        // Ensure we have a substantial number of helpers
        assert!(HELPER_DB.len() >= 150);
    }

    #[test]
    fn test_to_proto() {
        let helper = lookup_helper(BpfFuncId::MapUpdateElem).unwrap();
        let proto = helper.to_proto();
        
        assert_eq!(proto.func_id, BpfFuncId::MapUpdateElem);
        assert_eq!(proto.ret_type, BpfRetType::Integer);
        assert_eq!(proto.arg_types[0], BpfArgType::ConstMapPtr);
    }

    #[test]
    fn test_no_duplicate_helpers() {
        // Check for duplicates by comparing func_id values as u32
        let mut seen: Vec<u32> = Vec::new();
        for helper in HELPER_DB.iter() {
            let id = helper.func_id as u32;
            assert!(
                !seen.contains(&id),
                "Duplicate helper: {:?}",
                helper.func_id
            );
            seen.push(id);
        }
    }
}
