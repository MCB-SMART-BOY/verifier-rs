// SPDX-License-Identifier: GPL-2.0

//! 程序类型特定验证模块
//!
//! Program type specific validation module.
//!
//! 本模块提供每种 BPF 程序类型特定的验证逻辑。不同的程序类型有不同的
//! 上下文结构、允许的辅助函数、返回值要求和访问权限。
//!
//! This module provides validation logic specific to each BPF program type.
//! Different program types have different context structures, allowed helpers,
//! return value requirements, and access permissions.
//!
//! # 支持的程序类型 / Supported Program Types
//!
//! - **XDP**: 网络数据包处理 / Network packet processing
//! - **TC (SchedCls/SchedAct)**: 流量控制 / Traffic control
//! - **Kprobe/Uprobe**: 内核/用户空间探针 / Kernel/userspace probes
//! - **Tracepoint**: 静态追踪点 / Static tracepoints
//! - **Perf Event**: 性能事件处理 / Performance event handling
//! - **Cgroup**: 控制组策略 / Cgroup policies

use alloc::{format, string::String, vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::{BpfFuncId, BpfProgType, BpfRetvalRange};

/// Context field access permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldAccess {
    /// Field can be read.
    Read,
    /// Field can be written.
    Write,
    /// Field can be both read and written.
    ReadWrite,
    /// Field access is denied.
    Denied,
}

/// Context field descriptor.
#[derive(Debug, Clone)]
pub struct ContextField {
    /// Offset from context base.
    pub offset: u32,
    /// Size of the field in bytes.
    pub size: u32,
    /// Access permissions.
    pub access: FieldAccess,
    /// Field name for error messages.
    pub name: &'static str,
    /// Whether this field requires special handling (e.g., packet pointers).
    pub special: bool,
}

/// Program type capabilities and restrictions.
#[derive(Debug, Clone)]
pub struct ProgTypeInfo {
    /// The program type.
    pub prog_type: BpfProgType,
    /// Size of the context structure.
    pub ctx_size: u32,
    /// Context fields accessible by this program type.
    pub ctx_fields: Vec<ContextField>,
    /// Allowed helper function IDs.
    pub allowed_helpers: Vec<BpfFuncId>,
    /// Valid return value range.
    pub ret_range: BpfRetvalRange,
    /// Whether program can access packet data directly.
    pub has_direct_packet_access: bool,
    /// Whether program can call other BPF programs (tail call).
    pub can_tail_call: bool,
    /// Whether program can use bpf_spin_lock.
    pub can_use_spinlock: bool,
    /// Whether program runs in sleepable context.
    pub is_sleepable: bool,
    /// Whether program can access kernel memory.
    pub can_access_kernel_mem: bool,
    /// Maximum program size in instructions.
    pub max_insns: u32,
    /// Description of the program type.
    pub description: &'static str,
}

impl Default for ProgTypeInfo {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Unspec,
            ctx_size: 0,
            ctx_fields: Vec::new(),
            allowed_helpers: Vec::new(),
            ret_range: BpfRetvalRange::new(0, 0),
            has_direct_packet_access: false,
            can_tail_call: false,
            can_use_spinlock: false,
            is_sleepable: false,
            can_access_kernel_mem: false,
            max_insns: 1_000_000,
            description: "Unknown program type",
        }
    }
}

/// XDP return codes.
pub mod xdp_action {
    /// Pass the packet up to the network stack.
    pub const XDP_PASS: i32 = 2;
    /// Drop the packet.
    pub const XDP_DROP: i32 = 1;
    /// Abort and drop with error.
    pub const XDP_ABORTED: i32 = 0;
    /// Redirect to another interface/CPU/socket.
    pub const XDP_REDIRECT: i32 = 4;
    /// Transmit packet back out the same interface.
    pub const XDP_TX: i32 = 3;
}

/// Socket filter return codes.
pub mod sk_filter_action {
    /// Accept the packet.
    pub const SK_PASS: i32 = 1;
    /// Drop the packet.
    pub const SK_DROP: i32 = 0;
}

/// TC (traffic control) return codes.
pub mod tc_action {
    /// Continue to the next action.
    pub const TC_ACT_UNSPEC: i32 = -1;
    /// Accept/pass packet.
    pub const TC_ACT_OK: i32 = 0;
    /// Reclassify packet.
    pub const TC_ACT_RECLASSIFY: i32 = 1;
    /// Drop packet.
    pub const TC_ACT_SHOT: i32 = 2;
    /// Continue in pipeline.
    pub const TC_ACT_PIPE: i32 = 3;
    /// Stolen - packet consumed.
    pub const TC_ACT_STOLEN: i32 = 4;
    /// Queued for later.
    pub const TC_ACT_QUEUED: i32 = 5;
    /// Repeat classification.
    pub const TC_ACT_REPEAT: i32 = 6;
    /// Redirect packet.
    pub const TC_ACT_REDIRECT: i32 = 7;
}

/// XDP metadata context offsets.
pub mod xdp_md {
    /// Pointer to packet data start.
    pub const DATA: u32 = 0;
    /// Pointer to packet data end.
    pub const DATA_END: u32 = 4;
    /// Pointer to packet metadata.
    pub const DATA_META: u32 = 8;
    /// Ingress interface index.
    pub const INGRESS_IFINDEX: u32 = 12;
    /// RX queue index.
    pub const RX_QUEUE_INDEX: u32 = 16;
    /// Egress interface index.
    pub const EGRESS_IFINDEX: u32 = 20;
}

/// __sk_buff context offsets (simplified).
pub mod sk_buff {
    /// Packet length.
    pub const LEN: u32 = 0;
    /// Protocol.
    pub const PROTOCOL: u32 = 4;
    /// Packet mark.
    pub const MARK: u32 = 8;
    /// Interface index.
    pub const IFINDEX: u32 = 12;
    /// Queue mapping.
    pub const QUEUE_MAPPING: u32 = 16;
    /// VLAN TCI.
    pub const VLAN_TCI: u32 = 20;
    /// VLAN present flag.
    pub const VLAN_PRESENT: u32 = 24;
    /// Packet type.
    pub const PKT_TYPE: u32 = 28;
    /// Traffic class.
    pub const TC_INDEX: u32 = 32;
    /// Hash value.
    pub const HASH: u32 = 36;
    /// TC classid.
    pub const TC_CLASSID: u32 = 40;
    /// Pointer to packet data.
    pub const DATA: u32 = 44;
    /// Pointer to packet data end.
    pub const DATA_END: u32 = 48;
    /// NAT type.
    pub const NAPI_ID: u32 = 52;
    /// cgroup classid.
    pub const CGROUP_CLASSID: u32 = 56;
    /// CB (control buffer) array start.
    pub const CB_START: u32 = 60;
    /// CB array end (5 u32 values).
    pub const CB_END: u32 = 80;
    /// Data meta pointer.
    pub const DATA_META: u32 = 80;
}

/// Get program type information.
pub fn get_prog_type_info(prog_type: BpfProgType) -> ProgTypeInfo {
    match prog_type {
        BpfProgType::SocketFilter => socket_filter_info(),
        BpfProgType::Kprobe => kprobe_info(),
        BpfProgType::SchedCls => sched_cls_info(),
        BpfProgType::SchedAct => sched_act_info(),
        BpfProgType::Tracepoint => tracepoint_info(),
        BpfProgType::Xdp => xdp_info(),
        BpfProgType::PerfEvent => perf_event_info(),
        BpfProgType::CgroupSkb => cgroup_skb_info(),
        BpfProgType::CgroupSock => cgroup_sock_info(),
        BpfProgType::LwtIn => lwt_in_info(),
        BpfProgType::LwtOut => lwt_out_info(),
        BpfProgType::LwtXmit => lwt_xmit_info(),
        BpfProgType::SockOps => sock_ops_info(),
        BpfProgType::SkSkb => sk_skb_info(),
        BpfProgType::CgroupDevice => cgroup_device_info(),
        BpfProgType::SkMsg => sk_msg_info(),
        BpfProgType::RawTracepoint => raw_tracepoint_info(),
        BpfProgType::CgroupSockAddr => cgroup_sock_addr_info(),
        BpfProgType::LwtSeg6local => lwt_seg6local_info(),
        BpfProgType::LircMode2 => lirc_mode2_info(),
        BpfProgType::SkReuseport => sk_reuseport_info(),
        BpfProgType::FlowDissector => flow_dissector_info(),
        BpfProgType::CgroupSysctl => cgroup_sysctl_info(),
        BpfProgType::RawTracepointWritable => raw_tracepoint_writable_info(),
        BpfProgType::CgroupSockopt => cgroup_sockopt_info(),
        BpfProgType::Tracing => tracing_info(),
        BpfProgType::StructOps => struct_ops_info(),
        BpfProgType::Ext => ext_info(),
        BpfProgType::Lsm => lsm_info(),
        BpfProgType::SkLookup => sk_lookup_info(),
        BpfProgType::Syscall => syscall_info(),
        BpfProgType::Netfilter => netfilter_info(),
        _ => ProgTypeInfo::default(),
    }
}

fn socket_filter_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SocketFilter,
        ctx_size: 84, // __sk_buff size
        ctx_fields: vec![
            ContextField {
                offset: sk_buff::LEN,
                size: 4,
                access: FieldAccess::Read,
                name: "len",
                special: false,
            },
            ContextField {
                offset: sk_buff::PROTOCOL,
                size: 4,
                access: FieldAccess::Read,
                name: "protocol",
                special: false,
            },
            ContextField {
                offset: sk_buff::MARK,
                size: 4,
                access: FieldAccess::Read,
                name: "mark",
                special: false,
            },
            ContextField {
                offset: sk_buff::DATA,
                size: 4,
                access: FieldAccess::Read,
                name: "data",
                special: true,
            },
            ContextField {
                offset: sk_buff::DATA_END,
                size: 4,
                access: FieldAccess::Read,
                name: "data_end",
                special: true,
            },
        ],
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
        ],
        ret_range: BpfRetvalRange::new(0, u16::MAX as i32),
        has_direct_packet_access: true,
        can_tail_call: true,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 4096,
        description: "Socket filter for packet filtering",
    }
}

fn kprobe_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Kprobe,
        ctx_size: 0, // pt_regs size varies by arch
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::ProbeReadStr,
            BpfFuncId::GetStack,
            BpfFuncId::GetStackid,
            BpfFuncId::ProbeReadUser,
            BpfFuncId::ProbeReadKernel,
            BpfFuncId::ProbeReadUserStr,
            BpfFuncId::ProbeReadKernelStr,
        ],
        ret_range: BpfRetvalRange::new(0, 0),
        has_direct_packet_access: false,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Kernel probe for dynamic tracing",
    }
}

fn sched_cls_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SchedCls,
        ctx_size: 84,
        ctx_fields: vec![
            ContextField {
                offset: sk_buff::LEN,
                size: 4,
                access: FieldAccess::Read,
                name: "len",
                special: false,
            },
            ContextField {
                offset: sk_buff::PROTOCOL,
                size: 4,
                access: FieldAccess::Read,
                name: "protocol",
                special: false,
            },
            ContextField {
                offset: sk_buff::MARK,
                size: 4,
                access: FieldAccess::ReadWrite,
                name: "mark",
                special: false,
            },
            ContextField {
                offset: sk_buff::TC_INDEX,
                size: 4,
                access: FieldAccess::ReadWrite,
                name: "tc_index",
                special: false,
            },
            ContextField {
                offset: sk_buff::TC_CLASSID,
                size: 4,
                access: FieldAccess::ReadWrite,
                name: "tc_classid",
                special: false,
            },
            ContextField {
                offset: sk_buff::DATA,
                size: 4,
                access: FieldAccess::Read,
                name: "data",
                special: true,
            },
            ContextField {
                offset: sk_buff::DATA_END,
                size: 4,
                access: FieldAccess::Read,
                name: "data_end",
                special: true,
            },
        ],
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::SkbStoreBytes,
            BpfFuncId::L3CsumReplace,
            BpfFuncId::L4CsumReplace,
            BpfFuncId::CloneRedirect,
            BpfFuncId::Redirect,
            BpfFuncId::RedirectMap,
            BpfFuncId::SkbVlanPush,
            BpfFuncId::SkbVlanPop,
            BpfFuncId::SkbChangeProto,
            BpfFuncId::SkbChangeType,
            BpfFuncId::SkbChangeTail,
            BpfFuncId::SkbChangeHead,
            BpfFuncId::SkbPullData,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::CsumDiff,
            BpfFuncId::CsumUpdate,
            BpfFuncId::SetHashInvalid,
            BpfFuncId::SkbAdjustRoom,
            BpfFuncId::FibLookup,
            BpfFuncId::SkbEcnSetCe,
            BpfFuncId::SkbCgroupId,
            BpfFuncId::PerfEventOutput,
        ],
        ret_range: BpfRetvalRange::new(tc_action::TC_ACT_UNSPEC, tc_action::TC_ACT_REDIRECT),
        has_direct_packet_access: true,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Traffic control classifier",
    }
}

fn sched_act_info() -> ProgTypeInfo {
    let mut info = sched_cls_info();
    info.prog_type = BpfProgType::SchedAct;
    info.description = "Traffic control action";
    info
}

fn tracepoint_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Tracepoint,
        ctx_size: 0, // Varies per tracepoint
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::GetStack,
            BpfFuncId::GetStackid,
        ],
        ret_range: BpfRetvalRange::new(0, 0),
        has_direct_packet_access: false,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Tracepoint handler",
    }
}

fn xdp_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Xdp,
        ctx_size: 24, // xdp_md size
        ctx_fields: vec![
            ContextField {
                offset: xdp_md::DATA,
                size: 4,
                access: FieldAccess::Read,
                name: "data",
                special: true,
            },
            ContextField {
                offset: xdp_md::DATA_END,
                size: 4,
                access: FieldAccess::Read,
                name: "data_end",
                special: true,
            },
            ContextField {
                offset: xdp_md::DATA_META,
                size: 4,
                access: FieldAccess::Read,
                name: "data_meta",
                special: true,
            },
            ContextField {
                offset: xdp_md::INGRESS_IFINDEX,
                size: 4,
                access: FieldAccess::Read,
                name: "ingress_ifindex",
                special: false,
            },
            ContextField {
                offset: xdp_md::RX_QUEUE_INDEX,
                size: 4,
                access: FieldAccess::Read,
                name: "rx_queue_index",
                special: false,
            },
            ContextField {
                offset: xdp_md::EGRESS_IFINDEX,
                size: 4,
                access: FieldAccess::Read,
                name: "egress_ifindex",
                special: false,
            },
        ],
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::Redirect,
            BpfFuncId::RedirectMap,
            BpfFuncId::XdpAdjustHead,
            BpfFuncId::XdpAdjustTail,
            BpfFuncId::XdpAdjustMeta,
            BpfFuncId::FibLookup,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::CsumDiff,
        ],
        ret_range: BpfRetvalRange::new(xdp_action::XDP_ABORTED, xdp_action::XDP_REDIRECT),
        has_direct_packet_access: true,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Express Data Path handler",
    }
}

fn perf_event_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::PerfEvent,
        ctx_size: 0, // bpf_perf_event_data size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::PerfEventRead,
            BpfFuncId::GetStack,
            BpfFuncId::GetStackid,
            BpfFuncId::ReadBranchRecords,
        ],
        ret_range: BpfRetvalRange::new(0, 0),
        has_direct_packet_access: false,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Perf event handler",
    }
}

fn cgroup_skb_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupSkb,
        ctx_size: 84,
        ctx_fields: vec![
            ContextField {
                offset: sk_buff::LEN,
                size: 4,
                access: FieldAccess::Read,
                name: "len",
                special: false,
            },
            ContextField {
                offset: sk_buff::PROTOCOL,
                size: 4,
                access: FieldAccess::Read,
                name: "protocol",
                special: false,
            },
            ContextField {
                offset: sk_buff::DATA,
                size: 4,
                access: FieldAccess::Read,
                name: "data",
                special: true,
            },
            ContextField {
                offset: sk_buff::DATA_END,
                size: 4,
                access: FieldAccess::Read,
                name: "data_end",
                special: true,
            },
        ],
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::SkbCgroupId,
            BpfFuncId::GetLocalStorage,
            BpfFuncId::PerfEventOutput,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup socket buffer filter",
    }
}

fn cgroup_sock_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupSock,
        ctx_size: 64, // bpf_sock size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetLocalStorage,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup socket operations",
    }
}

fn lwt_in_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::LwtIn,
        ctx_size: 84,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::SkbPullData,
            BpfFuncId::CsumDiff,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Lightweight tunnel input",
    }
}

fn lwt_out_info() -> ProgTypeInfo {
    let mut info = lwt_in_info();
    info.prog_type = BpfProgType::LwtOut;
    info.description = "Lightweight tunnel output";
    info
}

fn lwt_xmit_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::LwtXmit,
        ctx_size: 84,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::SkbPullData,
            BpfFuncId::SkbStoreBytes,
            BpfFuncId::SkbChangeHead,
            BpfFuncId::SkbChangeTail,
            BpfFuncId::CsumDiff,
            BpfFuncId::CsumUpdate,
            BpfFuncId::Redirect,
            BpfFuncId::CloneRedirect,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Lightweight tunnel transmit",
    }
}

fn sock_ops_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SockOps,
        ctx_size: 88, // bpf_sock_ops size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::SockHashUpdate,
            BpfFuncId::SockMapUpdate,
            BpfFuncId::SockOpsCbFlagsSet,
            BpfFuncId::TcpSock,
            BpfFuncId::GetLocalStorage,
            BpfFuncId::PerfEventOutput,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Socket operations callback",
    }
}

fn sk_skb_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SkSkb,
        ctx_size: 84,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::SkbLoadBytes,
            BpfFuncId::SkbPullData,
            BpfFuncId::SkbStoreBytes,
            BpfFuncId::SkRedirectMap,
            BpfFuncId::SkRedirectHash,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Socket SKB redirect",
    }
}

fn cgroup_device_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupDevice,
        ctx_size: 16, // bpf_cgroup_dev_ctx size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup device access control",
    }
}

fn sk_msg_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SkMsg,
        ctx_size: 32, // sk_msg_md size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::MsgRedirectMap,
            BpfFuncId::MsgRedirectHash,
            BpfFuncId::MsgApplyBytes,
            BpfFuncId::MsgCorkBytes,
            BpfFuncId::MsgPullData,
            BpfFuncId::MsgPushData,
            BpfFuncId::MsgPopData,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Socket message redirect",
    }
}

fn raw_tracepoint_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::RawTracepoint,
        ctx_size: 0,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TailCall,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::GetStack,
            BpfFuncId::GetStackid,
            BpfFuncId::ProbeReadUser,
            BpfFuncId::ProbeReadKernel,
        ],
        ret_range: BpfRetvalRange::new(0, 0),
        has_direct_packet_access: false,
        can_tail_call: true,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Raw tracepoint handler",
    }
}

fn cgroup_sock_addr_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupSockAddr,
        ctx_size: 56, // bpf_sock_addr size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetLocalStorage,
            BpfFuncId::Bind,
            BpfFuncId::SkLookupTcp,
            BpfFuncId::SkLookupUdp,
            BpfFuncId::SkRelease,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup socket address operations",
    }
}

fn lwt_seg6local_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::LwtSeg6local,
        ctx_size: 84,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::LwtSeg6StoreBytes,
            BpfFuncId::LwtSeg6AdjustSrh,
            BpfFuncId::LwtSeg6Action,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "LWT Segment Routing local handler",
    }
}

fn lirc_mode2_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::LircMode2,
        ctx_size: 4, // u32 sample
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::RcRepeat,
            BpfFuncId::RcKeydown,
            BpfFuncId::RcPointerRel,
        ],
        ret_range: BpfRetvalRange::new(0, 0),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "LIRC infrared decoder",
    }
}

fn sk_reuseport_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SkReuseport,
        ctx_size: 40, // sk_reuseport_md size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::SkSelectReuseport,
            BpfFuncId::SkbLoadBytes,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Socket reuseport selector",
    }
}

fn flow_dissector_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::FlowDissector,
        ctx_size: 24, // __sk_buff flow dissector ctx
        ctx_fields: Vec::new(),
        allowed_helpers: vec![BpfFuncId::SkbLoadBytes],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Flow dissector for packet parsing",
    }
}

fn cgroup_sysctl_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupSysctl,
        ctx_size: 8, // bpf_sysctl size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::SysctlGetName,
            BpfFuncId::SysctlGetCurrentValue,
            BpfFuncId::SysctlGetNewValue,
            BpfFuncId::SysctlSetNewValue,
            BpfFuncId::Strtol,
            BpfFuncId::Strtoul,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup sysctl filter",
    }
}

fn raw_tracepoint_writable_info() -> ProgTypeInfo {
    let mut info = raw_tracepoint_info();
    info.prog_type = BpfProgType::RawTracepointWritable;
    info.description = "Raw tracepoint with write access";
    info
}

fn cgroup_sockopt_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::CgroupSockopt,
        ctx_size: 32, // bpf_sockopt size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetLocalStorage,
            BpfFuncId::TcpSock,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Cgroup socket option filter",
    }
}

fn tracing_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Tracing,
        ctx_size: 0, // Varies
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::GetStack,
            BpfFuncId::GetStackid,
            BpfFuncId::ProbeReadUser,
            BpfFuncId::ProbeReadKernel,
            BpfFuncId::ProbeReadUserStr,
            BpfFuncId::ProbeReadKernelStr,
            BpfFuncId::RingbufOutput,
            BpfFuncId::RingbufReserve,
            BpfFuncId::RingbufSubmit,
        ],
        ret_range: BpfRetvalRange::new(i32::MIN, i32::MAX),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: true, // Can be sleepable
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "BTF-enabled tracing",
    }
}

fn struct_ops_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::StructOps,
        ctx_size: 0, // Varies based on struct
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
        ],
        ret_range: BpfRetvalRange::new(i32::MIN, i32::MAX),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Kernel struct_ops implementation",
    }
}

fn ext_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Ext,
        ctx_size: 0,
        ctx_fields: Vec::new(),
        allowed_helpers: Vec::new(), // Inherits from target
        ret_range: BpfRetvalRange::new(i32::MIN, i32::MAX),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Extension program (freplace)",
    }
}

fn lsm_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Lsm,
        ctx_size: 0, // Varies per hook
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::ProbeRead,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::TracePrintk,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::GetCurrentPidTgid,
            BpfFuncId::GetCurrentUidGid,
            BpfFuncId::GetCurrentComm,
            BpfFuncId::GetCurrentTask,
            BpfFuncId::PerfEventOutput,
            BpfFuncId::RingbufOutput,
            BpfFuncId::RingbufReserve,
            BpfFuncId::RingbufSubmit,
        ],
        ret_range: BpfRetvalRange::new(i32::MIN, i32::MAX),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: true,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Linux Security Module hook",
    }
}

fn sk_lookup_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::SkLookup,
        ctx_size: 32, // bpf_sk_lookup size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::SkAssign,
            BpfFuncId::SkRelease,
        ],
        ret_range: BpfRetvalRange::new(0, 1),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: false,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Socket lookup for connection steering",
    }
}

fn syscall_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Syscall,
        ctx_size: 0,
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
            BpfFuncId::TracePrintk,
        ],
        ret_range: BpfRetvalRange::new(i32::MIN, i32::MAX),
        has_direct_packet_access: false,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: true,
        can_access_kernel_mem: true,
        max_insns: 1_000_000,
        description: "Syscall program (bpf() syscall handler)",
    }
}

fn netfilter_info() -> ProgTypeInfo {
    ProgTypeInfo {
        prog_type: BpfProgType::Netfilter,
        ctx_size: 24, // bpf_nf_ctx size
        ctx_fields: Vec::new(),
        allowed_helpers: vec![
            BpfFuncId::MapLookupElem,
            BpfFuncId::MapUpdateElem,
            BpfFuncId::MapDeleteElem,
            BpfFuncId::KtimeGetNs,
            BpfFuncId::GetPrandomU32,
            BpfFuncId::GetSmpProcessorId,
        ],
        ret_range: BpfRetvalRange::new(0, 1), // NF_DROP or NF_ACCEPT
        has_direct_packet_access: true,
        can_tail_call: false,
        can_use_spinlock: true,
        is_sleepable: false,
        can_access_kernel_mem: false,
        max_insns: 1_000_000,
        description: "Netfilter hook",
    }
}

/// Validator for program type specific rules.
#[derive(Debug)]
pub struct ProgTypeValidator {
    info: ProgTypeInfo,
}

impl ProgTypeValidator {
    /// Create a new validator for the given program type.
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            info: get_prog_type_info(prog_type),
        }
    }

    /// Get the program type info.
    pub fn info(&self) -> &ProgTypeInfo {
        &self.info
    }

    /// Check if a helper is allowed for this program type.
    pub fn is_helper_allowed(&self, func_id: BpfFuncId) -> bool {
        // Map operations are generally allowed for all program types
        if matches!(
            func_id,
            BpfFuncId::MapLookupElem | BpfFuncId::MapUpdateElem | BpfFuncId::MapDeleteElem
        ) {
            return true;
        }
        self.info.allowed_helpers.contains(&func_id)
    }

    /// Validate a return value.
    pub fn validate_return_value(&self, value: i32) -> Result<()> {
        if value >= self.info.ret_range.minval && value <= self.info.ret_range.maxval {
            Ok(())
        } else {
            Err(VerifierError::InvalidFunctionCall(format!(
                "return value {} out of range [{}, {}] for {:?}",
                value, self.info.ret_range.minval, self.info.ret_range.maxval, self.info.prog_type
            )))
        }
    }

    /// Check if the return value range is valid.
    pub fn validate_return_range(&self, min: i32, max: i32) -> Result<()> {
        if min > self.info.ret_range.maxval || max < self.info.ret_range.minval {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "return range [{}, {}] doesn't overlap with allowed range [{}, {}] for {:?}",
                min,
                max,
                self.info.ret_range.minval,
                self.info.ret_range.maxval,
                self.info.prog_type
            )));
        }
        Ok(())
    }

    /// Check if context access at the given offset is valid.
    pub fn validate_ctx_access(
        &self,
        offset: u32,
        size: u32,
        is_write: bool,
    ) -> Result<FieldAccess> {
        // Check if within context size
        if self.info.ctx_size > 0 && offset + size > self.info.ctx_size {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "context access at offset {} size {} exceeds ctx_size {}",
                offset, size, self.info.ctx_size
            )));
        }

        // Find matching field
        for field in &self.info.ctx_fields {
            if offset >= field.offset && offset + size <= field.offset + field.size {
                match field.access {
                    FieldAccess::Denied => {
                        return Err(VerifierError::InvalidMemoryAccess(format!(
                            "access to field '{}' at offset {} is denied",
                            field.name, offset
                        )));
                    }
                    FieldAccess::Read if is_write => {
                        return Err(VerifierError::InvalidMemoryAccess(format!(
                            "write to read-only field '{}' at offset {}",
                            field.name, offset
                        )));
                    }
                    FieldAccess::Write if !is_write => {
                        return Err(VerifierError::InvalidMemoryAccess(format!(
                            "read from write-only field '{}' at offset {}",
                            field.name, offset
                        )));
                    }
                    access => return Ok(access),
                }
            }
        }

        // Default: allow reads if within bounds
        if !is_write {
            Ok(FieldAccess::Read)
        } else {
            Err(VerifierError::InvalidMemoryAccess(format!(
                "write to unknown context field at offset {}",
                offset
            )))
        }
    }

    /// Check if program size is within limits.
    pub fn validate_program_size(&self, insn_count: usize) -> Result<()> {
        if insn_count as u32 > self.info.max_insns {
            return Err(VerifierError::ProgramTooLarge(insn_count));
        }
        Ok(())
    }

    /// Check if tail calls are allowed.
    pub fn can_tail_call(&self) -> bool {
        self.info.can_tail_call
    }

    /// Check if spin locks can be used.
    pub fn can_use_spinlock(&self) -> bool {
        self.info.can_use_spinlock
    }

    /// Check if program runs in sleepable context.
    pub fn is_sleepable(&self) -> bool {
        self.info.is_sleepable
    }

    /// Check if direct packet access is available.
    pub fn has_direct_packet_access(&self) -> bool {
        self.info.has_direct_packet_access
    }

    /// Check if kernel memory can be accessed.
    pub fn can_access_kernel_mem(&self) -> bool {
        self.info.can_access_kernel_mem
    }

    /// Validate attach type compatibility
    pub fn validate_attach_type(&self, attach_type: BpfAttachType) -> Result<()> {
        let allowed = get_allowed_attach_types(self.info.prog_type);
        if allowed.contains(&attach_type) {
            Ok(())
        } else {
            Err(VerifierError::TypeMismatch {
                expected: format!("valid attach type for {:?}", self.info.prog_type),
                got: format!("{:?}", attach_type),
            })
        }
    }

    /// Validate kfunc call based on program type
    pub fn validate_kfunc_call(&self, kfunc_caps: KfuncCapabilities) -> Result<()> {
        // Check sleepable kfuncs
        if kfunc_caps.contains(KfuncCapabilities::SLEEPABLE) && !self.info.is_sleepable {
            return Err(VerifierError::InvalidFunctionCall(
                "sleepable kfunc called from non-sleepable program".into(),
            ));
        }

        // Check destructive kfuncs require CAP_SYS_BOOT
        if kfunc_caps.contains(KfuncCapabilities::DESTRUCTIVE) {
            return Err(VerifierError::PermissionDenied(
                "destructive kfunc requires CAP_SYS_BOOT".into(),
            ));
        }

        Ok(())
    }

    /// Check if a specific feature is enabled for this program type
    pub fn has_feature(&self, feature: ProgFeature) -> bool {
        match feature {
            ProgFeature::BpfToKernel => self.info.can_access_kernel_mem,
            ProgFeature::DirectPacketAccess => self.info.has_direct_packet_access,
            ProgFeature::TailCall => self.info.can_tail_call,
            ProgFeature::SpinLock => self.info.can_use_spinlock,
            ProgFeature::Sleepable => self.info.is_sleepable,
            ProgFeature::BtfFunc => true, // All modern program types support BTF
            ProgFeature::GlobalFuncs => true,
            ProgFeature::BoundedLoops => true,
            ProgFeature::Kfunc => matches!(
                self.info.prog_type,
                BpfProgType::Tracing
                    | BpfProgType::Lsm
                    | BpfProgType::StructOps
                    | BpfProgType::Syscall
                    | BpfProgType::SchedCls
                    | BpfProgType::Xdp
            ),
            ProgFeature::Arena => matches!(
                self.info.prog_type,
                BpfProgType::Syscall | BpfProgType::Tracing
            ),
        }
    }
}

/// BPF attach types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum BpfAttachType {
    CgroupInetIngress,
    CgroupInetEgress,
    CgroupInetSockCreate,
    CgroupSockOps,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    CgroupDevice,
    SkMsgVerdict,
    CgroupInet4Bind,
    CgroupInet6Bind,
    CgroupInet4Connect,
    CgroupInet6Connect,
    CgroupInet4PostBind,
    CgroupInet6PostBind,
    CgroupUdp4Sendmsg,
    CgroupUdp6Sendmsg,
    LircMode2,
    FlowDissector,
    CgroupSysctl,
    CgroupUdp4Recvmsg,
    CgroupUdp6Recvmsg,
    CgroupGetsockopt,
    CgroupSetsockopt,
    TraceRawTp,
    TraceFentry,
    TraceFexit,
    ModifyReturn,
    LsmMac,
    TraceIter,
    CgroupInet4Getpeername,
    CgroupInet6Getpeername,
    CgroupInet4Getsockname,
    CgroupInet6Getsockname,
    XdpDevmap,
    CgroupInetSockRelease,
    XdpCpumap,
    SkLookup,
    Xdp,
    SkSkbVerdict,
    SkReuseportSelect,
    SkReuseportSelectOrMigrate,
    PerfEvent,
    TraceKprobeMulti,
    LsmCgroup,
    StructOps,
    Netfilter,
    TcxIngress,
    TcxEgress,
    TraceUprobeMulti,
    NetkitPrimary,
    NetkitPeer,
}

/// Get allowed attach types for a program type
pub fn get_allowed_attach_types(prog_type: BpfProgType) -> Vec<BpfAttachType> {
    match prog_type {
        BpfProgType::CgroupSkb => vec![
            BpfAttachType::CgroupInetIngress,
            BpfAttachType::CgroupInetEgress,
        ],
        BpfProgType::CgroupSock => vec![
            BpfAttachType::CgroupInetSockCreate,
            BpfAttachType::CgroupInetSockRelease,
            BpfAttachType::CgroupInet4PostBind,
            BpfAttachType::CgroupInet6PostBind,
        ],
        BpfProgType::CgroupSockAddr => vec![
            BpfAttachType::CgroupInet4Bind,
            BpfAttachType::CgroupInet6Bind,
            BpfAttachType::CgroupInet4Connect,
            BpfAttachType::CgroupInet6Connect,
            BpfAttachType::CgroupUdp4Sendmsg,
            BpfAttachType::CgroupUdp6Sendmsg,
            BpfAttachType::CgroupUdp4Recvmsg,
            BpfAttachType::CgroupUdp6Recvmsg,
            BpfAttachType::CgroupInet4Getpeername,
            BpfAttachType::CgroupInet6Getpeername,
            BpfAttachType::CgroupInet4Getsockname,
            BpfAttachType::CgroupInet6Getsockname,
        ],
        BpfProgType::SockOps => vec![BpfAttachType::CgroupSockOps],
        BpfProgType::SkSkb => vec![
            BpfAttachType::SkSkbStreamParser,
            BpfAttachType::SkSkbStreamVerdict,
            BpfAttachType::SkSkbVerdict,
        ],
        BpfProgType::SkMsg => vec![BpfAttachType::SkMsgVerdict],
        BpfProgType::CgroupDevice => vec![BpfAttachType::CgroupDevice],
        BpfProgType::CgroupSysctl => vec![BpfAttachType::CgroupSysctl],
        BpfProgType::CgroupSockopt => vec![
            BpfAttachType::CgroupGetsockopt,
            BpfAttachType::CgroupSetsockopt,
        ],
        BpfProgType::Tracing => vec![
            BpfAttachType::TraceFentry,
            BpfAttachType::TraceFexit,
            BpfAttachType::ModifyReturn,
            BpfAttachType::TraceIter,
            BpfAttachType::TraceRawTp,
        ],
        BpfProgType::Lsm => vec![BpfAttachType::LsmMac, BpfAttachType::LsmCgroup],
        BpfProgType::FlowDissector => vec![BpfAttachType::FlowDissector],
        BpfProgType::SkLookup => vec![BpfAttachType::SkLookup],
        BpfProgType::Xdp => vec![
            BpfAttachType::Xdp,
            BpfAttachType::XdpDevmap,
            BpfAttachType::XdpCpumap,
        ],
        BpfProgType::SkReuseport => vec![
            BpfAttachType::SkReuseportSelect,
            BpfAttachType::SkReuseportSelectOrMigrate,
        ],
        BpfProgType::PerfEvent => vec![BpfAttachType::PerfEvent],
        BpfProgType::Kprobe => vec![BpfAttachType::TraceKprobeMulti],
        BpfProgType::StructOps => vec![BpfAttachType::StructOps],
        BpfProgType::Netfilter => vec![BpfAttachType::Netfilter],
        BpfProgType::SchedCls => vec![BpfAttachType::TcxIngress, BpfAttachType::TcxEgress],
        _ => Vec::new(), // Other types don't require specific attach type
    }
}

bitflags::bitflags! {
    /// Capability flags for kfuncs (used for program type validation)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KfuncCapabilities: u32 {
        /// Kfunc may sleep
        const SLEEPABLE = 1 << 0;
        /// Kfunc is destructive (e.g., crash_kexec)
        const DESTRUCTIVE = 1 << 1;
        /// Kfunc acquires a reference
        const ACQUIRE = 1 << 2;
        /// Kfunc releases a reference
        const RELEASE = 1 << 3;
        /// Kfunc returns a null-able pointer
        const RET_NULL = 1 << 4;
        /// Kfunc is trusted (can access kernel memory)
        const TRUSTED_ARGS = 1 << 5;
        /// Kfunc modifies its arguments
        const RCU = 1 << 6;
    }
}

/// Program features that can be checked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgFeature {
    /// Can call into kernel functions
    BpfToKernel,
    /// Can access packet data directly
    DirectPacketAccess,
    /// Can make tail calls
    TailCall,
    /// Can use spin locks
    SpinLock,
    /// Runs in sleepable context
    Sleepable,
    /// Supports BTF function info
    BtfFunc,
    /// Supports global functions
    GlobalFuncs,
    /// Supports bounded loops
    BoundedLoops,
    /// Can call kfuncs
    Kfunc,
    /// Can use arena memory
    Arena,
}

/// Comprehensive program validation result
#[derive(Debug, Clone)]
pub struct ProgValidationResult {
    /// Program type
    pub prog_type: BpfProgType,
    /// Number of instructions
    pub insn_count: usize,
    /// Number of subprograms
    pub subprog_count: usize,
    /// Helper functions used
    pub helpers_used: Vec<BpfFuncId>,
    /// Features enabled
    pub features_used: Vec<ProgFeature>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

impl ProgValidationResult {
    /// Create new validation result
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            insn_count: 0,
            subprog_count: 0,
            helpers_used: Vec::new(),
            features_used: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add a warning
    pub fn add_warning(&mut self, msg: String) {
        self.warnings.push(msg);
    }

    /// Record helper usage
    pub fn record_helper(&mut self, func_id: BpfFuncId) {
        if !self.helpers_used.contains(&func_id) {
            self.helpers_used.push(func_id);
        }
    }

    /// Record feature usage
    pub fn record_feature(&mut self, feature: ProgFeature) {
        if !self.features_used.contains(&feature) {
            self.features_used.push(feature);
        }
    }
}

/// Validate program type compatibility for extension/freplace
pub fn validate_extension_target(
    ext_prog_type: BpfProgType,
    target_prog_type: BpfProgType,
) -> Result<()> {
    // Extension programs must match target's capabilities
    if ext_prog_type != BpfProgType::Ext {
        return Err(VerifierError::TypeMismatch {
            expected: "BPF_PROG_TYPE_EXT".into(),
            got: format!("{:?}", ext_prog_type),
        });
    }

    // Target must be a valid program type for extension
    match target_prog_type {
        BpfProgType::Xdp
        | BpfProgType::SchedCls
        | BpfProgType::SchedAct
        | BpfProgType::Tracing
        | BpfProgType::SocketFilter => Ok(()),
        _ => Err(VerifierError::TypeMismatch {
            expected: "valid extension target".into(),
            got: format!("{:?}", target_prog_type),
        }),
    }
}

/// Validate struct_ops program requirements
pub fn validate_struct_ops_prog(prog_type: BpfProgType, func_proto: &str) -> Result<()> {
    if prog_type != BpfProgType::StructOps {
        return Err(VerifierError::TypeMismatch {
            expected: "BPF_PROG_TYPE_STRUCT_OPS".into(),
            got: format!("{:?}", prog_type),
        });
    }

    // Validate function prototype format
    if func_proto.is_empty() {
        return Err(VerifierError::InvalidFunctionCall(
            "struct_ops requires BTF function prototype".into(),
        ));
    }

    Ok(())
}
