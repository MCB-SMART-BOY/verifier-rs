// SPDX-License-Identifier: GPL-2.0

//! BPF 程序上下文访问优化模块
//!
//! Context access optimization for BPF programs.
//!
//! 本模块将上下文字段访问转换为实际的内存操作。不同的 BPF 程序类型有不同的
//! 上下文结构（sk_buff、xdp_buff 等），此优化遍将通用的上下文字段读写重写为
//! 特定架构的加载/存储序列。
//!
//! This module converts context field accesses to actual memory operations.
//! Different BPF program types have different context structures (sk_buff, xdp_buff, etc.)
//! and this pass rewrites generic context field reads/writes to architecture-specific
//! load/store sequences.
//!
//! # 优化功能 / Optimization Features
//!
//! - **访问模式分析 / Access pattern analysis**: 检测常见访问模式（顺序、跨步）
//! - **字段合并 / Field coalescing**: 将多个小访问合并为较大的访问
//! - **推测性转换 / Speculative conversion**: 预转换可能访问的字段
//! - **缓存感知排序 / Cache-aware ordering**: 重排访问以获得更好的缓存行为
//! - **死访问消除 / Dead access elimination**: 移除结果未使用的访问
//!
//! # 支持的程序类型 / Supported Program Types
//!
//! - `SocketFilter`: 套接字过滤器，使用 `__sk_buff` 上下文
//! - `XDP`: XDP 程序，使用 `xdp_md` 上下文
//! - `SchedCls/SchedAct`: TC 分类器/动作，使用 `__sk_buff`
//! - `CgroupSkb`: Cgroup 数据包过滤，使用 `__sk_buff`
//! - `SockOps`: Socket 操作，使用 `bpf_sock_ops`
//! - `SkMsg`: Socket 消息，使用 `sk_msg_md`
//! - `Tracing`: 跟踪程序，使用 BTF 基础访问

use alloc::{format, vec, vec::Vec};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use super::patching::{Patch, PatchManager, PatchType};
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// Context field access information
#[derive(Debug, Clone)]
pub struct CtxFieldAccess {
    /// Field offset in the context structure
    pub ctx_off: u32,
    /// Size of the access (1, 2, 4, or 8 bytes)
    pub size: u32,
    /// Whether this is a write operation
    pub is_write: bool,
    /// Converted field offset (after conversion)
    pub converted_off: i32,
    /// Conversion type
    pub conv_type: CtxConvType,
}

/// Types of context access conversions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxConvType {
    /// Direct access - no conversion needed
    Direct,
    /// Load from different offset
    LoadOffset(i32),
    /// Load with byte swap (endianness conversion)
    LoadSwap,
    /// Load via helper function
    LoadHelper(u32),
    /// Computed access (requires runtime calculation)
    Computed,
    /// Access denied
    Denied,
}

/// Context conversion configuration for different program types
#[derive(Debug, Clone)]
pub struct CtxConvConfig {
    /// Program type
    pub prog_type: BpfProgType,
    /// Field mappings
    pub field_map: Vec<CtxFieldMapping>,
    /// Whether narrow loads are allowed
    pub narrow_load_ok: bool,
    /// Whether writes are allowed
    pub write_ok: bool,
}

/// Mapping from context offset to actual memory access
#[derive(Debug, Clone)]
pub struct CtxFieldMapping {
    /// Context field offset
    pub ctx_off: u32,
    /// Context field size
    pub ctx_size: u32,
    /// Target offset in actual structure
    pub target_off: i32,
    /// Target size (may differ from ctx_size)
    pub target_size: u32,
    /// Whether field is read-only
    pub read_only: bool,
    /// Conversion required
    pub conv: CtxConvType,
}

impl CtxConvConfig {
    /// Create config for socket filter programs (sk_buff context)
    pub fn for_socket_filter() -> Self {
        Self {
            prog_type: BpfProgType::SocketFilter,
            narrow_load_ok: true,
            write_ok: false,
            field_map: vec![
                // __sk_buff fields -> sk_buff fields
                CtxFieldMapping {
                    ctx_off: 0, // len
                    ctx_size: 4,
                    target_off: offset_of_skb_len(),
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 4, // pkt_type
                    ctx_size: 4,
                    target_off: offset_of_skb_pkt_type(),
                    target_size: 1,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 8, // mark
                    ctx_size: 4,
                    target_off: offset_of_skb_mark(),
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 12, // queue_mapping
                    ctx_size: 4,
                    target_off: offset_of_skb_queue_mapping(),
                    target_size: 2,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 16, // protocol
                    ctx_size: 4,
                    target_off: offset_of_skb_protocol(),
                    target_size: 2,
                    read_only: true,
                    conv: CtxConvType::LoadSwap, // Network byte order
                },
                CtxFieldMapping {
                    ctx_off: 20, // vlan_present
                    ctx_size: 4,
                    target_off: offset_of_skb_vlan_present(),
                    target_size: 1,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 24, // vlan_tci
                    ctx_size: 4,
                    target_off: offset_of_skb_vlan_tci(),
                    target_size: 2,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 28, // vlan_proto
                    ctx_size: 4,
                    target_off: offset_of_skb_vlan_proto(),
                    target_size: 2,
                    read_only: true,
                    conv: CtxConvType::LoadSwap,
                },
                CtxFieldMapping {
                    ctx_off: 32, // priority
                    ctx_size: 4,
                    target_off: offset_of_skb_priority(),
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                // Data pointers
                CtxFieldMapping {
                    ctx_off: 76, // data
                    ctx_size: 4,
                    target_off: offset_of_skb_data(),
                    target_size: 8, // Pointer
                    read_only: true,
                    conv: CtxConvType::Computed, // Needs special handling
                },
                CtxFieldMapping {
                    ctx_off: 80, // data_end
                    ctx_size: 4,
                    target_off: offset_of_skb_data_end(),
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
            ],
        }
    }

    /// Create config for XDP programs
    pub fn for_xdp() -> Self {
        Self {
            prog_type: BpfProgType::Xdp,
            narrow_load_ok: true,
            write_ok: false,
            field_map: vec![
                // xdp_md fields -> xdp_buff fields
                CtxFieldMapping {
                    ctx_off: 0, // data
                    ctx_size: 4,
                    target_off: 0, // xdp_buff.data
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 4, // data_end
                    ctx_size: 4,
                    target_off: 8, // xdp_buff.data_end
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 8, // data_meta
                    ctx_size: 4,
                    target_off: 16, // xdp_buff.data_meta
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 12, // ingress_ifindex
                    ctx_size: 4,
                    target_off: 24,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed, // Via rxq
                },
                CtxFieldMapping {
                    ctx_off: 16, // rx_queue_index
                    ctx_size: 4,
                    target_off: 28,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 20, // egress_ifindex
                    ctx_size: 4,
                    target_off: 32,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
            ],
        }
    }

    /// Create config for tracing programs
    pub fn for_tracing() -> Self {
        Self {
            prog_type: BpfProgType::Tracing,
            narrow_load_ok: true,
            write_ok: false,
            field_map: Vec::new(), // Tracing uses BTF-based access
        }
    }

    /// Create config for cgroup programs
    pub fn for_cgroup_skb() -> Self {
        // Similar to socket filter but with additional fields
        let mut config = Self::for_socket_filter();
        config.prog_type = BpfProgType::CgroupSkb;
        config.write_ok = true; // Some fields writable
        config
    }

    /// Create config for TC classifier (sched_cls) programs
    pub fn for_sched_cls() -> Self {
        // TC programs use __sk_buff like socket filter, but with TC-specific fields
        let mut config = Self::for_socket_filter();
        config.prog_type = BpfProgType::SchedCls;
        config.write_ok = true; // Can modify packet

        // Add TC-specific fields
        config.field_map.extend(vec![
            CtxFieldMapping {
                ctx_off: 36, // tc_index
                ctx_size: 4,
                target_off: offset_of_skb_tc_index(),
                target_size: 2,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 40, // cb[0]
                ctx_size: 4,
                target_off: offset_of_skb_cb(),
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 44, // cb[1]
                ctx_size: 4,
                target_off: offset_of_skb_cb() + 4,
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 48, // cb[2]
                ctx_size: 4,
                target_off: offset_of_skb_cb() + 8,
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 52, // cb[3]
                ctx_size: 4,
                target_off: offset_of_skb_cb() + 12,
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 56, // cb[4]
                ctx_size: 4,
                target_off: offset_of_skb_cb() + 16,
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 60, // hash
                ctx_size: 4,
                target_off: offset_of_skb_hash(),
                target_size: 4,
                read_only: true,
                conv: CtxConvType::Direct,
            },
            CtxFieldMapping {
                ctx_off: 64, // tc_classid
                ctx_size: 4,
                target_off: offset_of_skb_tc_classid(),
                target_size: 4,
                read_only: false,
                conv: CtxConvType::Computed, // Via qdisc_skb_cb
            },
        ]);
        config
    }

    /// Create config for TC action (sched_act) programs
    pub fn for_sched_act() -> Self {
        // Same as sched_cls
        let mut config = Self::for_sched_cls();
        config.prog_type = BpfProgType::SchedAct;
        config
    }

    /// Create config for LWT (Lightweight Tunnel) programs
    pub fn for_lwt() -> Self {
        // LWT programs use __sk_buff context
        let mut config = Self::for_socket_filter();
        config.prog_type = BpfProgType::LwtIn;
        config.write_ok = false;
        config
    }

    /// Create config for sock_ops programs
    pub fn for_sock_ops() -> Self {
        Self {
            prog_type: BpfProgType::SockOps,
            narrow_load_ok: true,
            write_ok: true,
            field_map: vec![
                // bpf_sock_ops fields
                CtxFieldMapping {
                    ctx_off: 0, // op
                    ctx_size: 4,
                    target_off: 0,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 4, // family
                    ctx_size: 4,
                    target_off: 4,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed, // From socket
                },
                CtxFieldMapping {
                    ctx_off: 8, // remote_ip4
                    ctx_size: 4,
                    target_off: 8,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 12, // local_ip4
                    ctx_size: 4,
                    target_off: 12,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 16, // remote_ip6[0]
                    ctx_size: 4,
                    target_off: 16,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 32, // local_ip6[0]
                    ctx_size: 4,
                    target_off: 32,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 48, // remote_port
                    ctx_size: 4,
                    target_off: 48,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 52, // local_port
                    ctx_size: 4,
                    target_off: 52,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 56, // is_fullsock
                    ctx_size: 4,
                    target_off: 56,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 60, // snd_cwnd
                    ctx_size: 4,
                    target_off: 60,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed, // From tcp_sock
                },
                CtxFieldMapping {
                    ctx_off: 64, // srtt_us
                    ctx_size: 4,
                    target_off: 64,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 68, // bpf_sock_ops_cb_flags
                    ctx_size: 4,
                    target_off: 68,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 72, // state
                    ctx_size: 4,
                    target_off: 72,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 76, // rtt_min
                    ctx_size: 4,
                    target_off: 76,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 80, // snd_ssthresh
                    ctx_size: 4,
                    target_off: 80,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 84, // rcv_nxt
                    ctx_size: 4,
                    target_off: 84,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 88, // snd_nxt
                    ctx_size: 4,
                    target_off: 88,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 92, // snd_una
                    ctx_size: 4,
                    target_off: 92,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 96, // mss_cache
                    ctx_size: 4,
                    target_off: 96,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 100, // ecn_flags
                    ctx_size: 4,
                    target_off: 100,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 104, // rate_delivered
                    ctx_size: 4,
                    target_off: 104,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 108, // rate_interval_us
                    ctx_size: 4,
                    target_off: 108,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 112, // packets_out
                    ctx_size: 4,
                    target_off: 112,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 116, // retrans_out
                    ctx_size: 4,
                    target_off: 116,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 120, // total_retrans
                    ctx_size: 4,
                    target_off: 120,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 124, // segs_in
                    ctx_size: 4,
                    target_off: 124,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 128, // data_segs_in
                    ctx_size: 4,
                    target_off: 128,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 132, // segs_out
                    ctx_size: 4,
                    target_off: 132,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 136, // data_segs_out
                    ctx_size: 4,
                    target_off: 136,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 140, // lost_out
                    ctx_size: 4,
                    target_off: 140,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 144, // sacked_out
                    ctx_size: 4,
                    target_off: 144,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 148, // sk_txhash
                    ctx_size: 4,
                    target_off: 148,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 152, // bytes_received
                    ctx_size: 8,
                    target_off: 152,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 160, // bytes_acked
                    ctx_size: 8,
                    target_off: 160,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
            ],
        }
    }

    /// Create config for sk_msg programs
    pub fn for_sk_msg() -> Self {
        Self {
            prog_type: BpfProgType::SkMsg,
            narrow_load_ok: true,
            write_ok: false,
            field_map: vec![
                // sk_msg_md fields
                CtxFieldMapping {
                    ctx_off: 0, // data
                    ctx_size: 8,
                    target_off: 0,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 8, // data_end
                    ctx_size: 8,
                    target_off: 8,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 16, // family
                    ctx_size: 4,
                    target_off: 16,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 20, // remote_ip4
                    ctx_size: 4,
                    target_off: 20,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 24, // local_ip4
                    ctx_size: 4,
                    target_off: 24,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 28, // remote_ip6[0]
                    ctx_size: 16,
                    target_off: 28,
                    target_size: 16,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 44, // local_ip6[0]
                    ctx_size: 16,
                    target_off: 44,
                    target_size: 16,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 60, // remote_port
                    ctx_size: 4,
                    target_off: 60,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 64, // local_port
                    ctx_size: 4,
                    target_off: 64,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 68, // size
                    ctx_size: 4,
                    target_off: 68,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
            ],
        }
    }

    /// Create config for sk_skb programs (stream parser/verdict)
    pub fn for_sk_skb() -> Self {
        // Uses __sk_buff context like socket filter
        let mut config = Self::for_socket_filter();
        config.prog_type = BpfProgType::SkSkb;
        config.write_ok = false;
        config
    }

    /// Create config for cgroup_sock programs
    pub fn for_cgroup_sock() -> Self {
        Self {
            prog_type: BpfProgType::CgroupSock,
            narrow_load_ok: true,
            write_ok: true,
            field_map: vec![
                // bpf_sock fields
                CtxFieldMapping {
                    ctx_off: 0, // bound_dev_if
                    ctx_size: 4,
                    target_off: 0,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 4, // family
                    ctx_size: 4,
                    target_off: 4,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 8, // type
                    ctx_size: 4,
                    target_off: 8,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 12, // protocol
                    ctx_size: 4,
                    target_off: 12,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 16, // mark
                    ctx_size: 4,
                    target_off: 16,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 20, // priority
                    ctx_size: 4,
                    target_off: 20,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 24, // src_ip4
                    ctx_size: 4,
                    target_off: 24,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 28, // src_ip6[0]
                    ctx_size: 16,
                    target_off: 28,
                    target_size: 16,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 44, // src_port
                    ctx_size: 4,
                    target_off: 44,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 48, // dst_port
                    ctx_size: 4,
                    target_off: 48,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 52, // dst_ip4
                    ctx_size: 4,
                    target_off: 52,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 56, // dst_ip6[0]
                    ctx_size: 16,
                    target_off: 56,
                    target_size: 16,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 72, // state
                    ctx_size: 4,
                    target_off: 72,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 76, // rx_queue_mapping
                    ctx_size: 4,
                    target_off: 76,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
            ],
        }
    }

    /// Create config for cgroup_sock_addr programs
    pub fn for_cgroup_sock_addr() -> Self {
        Self {
            prog_type: BpfProgType::CgroupSockAddr,
            narrow_load_ok: true,
            write_ok: true,
            field_map: vec![
                // bpf_sock_addr fields
                CtxFieldMapping {
                    ctx_off: 0, // user_family
                    ctx_size: 4,
                    target_off: 0,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 4, // user_ip4
                    ctx_size: 4,
                    target_off: 4,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 8, // user_ip6[0]
                    ctx_size: 16,
                    target_off: 8,
                    target_size: 16,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 24, // user_port
                    ctx_size: 4,
                    target_off: 24,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::LoadSwap, // Network byte order
                },
                CtxFieldMapping {
                    ctx_off: 28, // family
                    ctx_size: 4,
                    target_off: 28,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 32, // type
                    ctx_size: 4,
                    target_off: 32,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 36, // protocol
                    ctx_size: 4,
                    target_off: 36,
                    target_size: 4,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 40, // msg_src_ip4
                    ctx_size: 4,
                    target_off: 40,
                    target_size: 4,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
                CtxFieldMapping {
                    ctx_off: 44, // msg_src_ip6[0]
                    ctx_size: 16,
                    target_off: 44,
                    target_size: 16,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
            ],
        }
    }

    /// Create config for flow dissector programs
    pub fn for_flow_dissector() -> Self {
        Self {
            prog_type: BpfProgType::FlowDissector,
            narrow_load_ok: true,
            write_ok: true,
            field_map: vec![
                // __sk_buff subset for flow dissector
                CtxFieldMapping {
                    ctx_off: 0, // data
                    ctx_size: 8,
                    target_off: 0,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 8, // data_end
                    ctx_size: 8,
                    target_off: 8,
                    target_size: 8,
                    read_only: true,
                    conv: CtxConvType::Computed,
                },
                CtxFieldMapping {
                    ctx_off: 16, // flow_keys
                    ctx_size: 8,
                    target_off: 16,
                    target_size: 8,
                    read_only: false,
                    conv: CtxConvType::Direct,
                },
            ],
        }
    }

    /// Get config for a specific program type
    pub fn for_prog_type(prog_type: BpfProgType) -> Option<Self> {
        match prog_type {
            BpfProgType::SocketFilter => Some(Self::for_socket_filter()),
            BpfProgType::Xdp => Some(Self::for_xdp()),
            BpfProgType::SchedCls => Some(Self::for_sched_cls()),
            BpfProgType::SchedAct => Some(Self::for_sched_act()),
            BpfProgType::CgroupSkb => Some(Self::for_cgroup_skb()),
            BpfProgType::CgroupSock => Some(Self::for_cgroup_sock()),
            BpfProgType::CgroupSockAddr => Some(Self::for_cgroup_sock_addr()),
            BpfProgType::SockOps => Some(Self::for_sock_ops()),
            BpfProgType::SkSkb => Some(Self::for_sk_skb()),
            BpfProgType::SkMsg => Some(Self::for_sk_msg()),
            BpfProgType::LwtIn
            | BpfProgType::LwtOut
            | BpfProgType::LwtXmit
            | BpfProgType::LwtSeg6local => Some(Self::for_lwt()),
            BpfProgType::FlowDissector => Some(Self::for_flow_dissector()),
            BpfProgType::Tracing => Some(Self::for_tracing()),
            _ => None, // Other types use BTF-based access or don't have context
        }
    }

    /// Find field mapping for a given offset and size
    pub fn find_mapping(&self, off: u32, size: u32) -> Option<&CtxFieldMapping> {
        self.field_map
            .iter()
            .find(|m| off >= m.ctx_off && off + size <= m.ctx_off + m.ctx_size)
    }
}

/// sk_buff structure field offsets.
/// These vary by kernel version and architecture.
#[derive(Debug, Clone, Copy)]
pub struct SkbOffsets {
    /// Offset of len field
    pub len: i32,
    /// Offset of pkt_type field
    pub pkt_type: i32,
    /// Offset of mark field
    pub mark: i32,
    /// Offset of queue_mapping field
    pub queue_mapping: i32,
    /// Offset of protocol field
    pub protocol: i32,
    /// Offset of vlan_present field (or vlan_all on newer kernels)
    pub vlan_present: i32,
    /// Offset of vlan_tci field
    pub vlan_tci: i32,
    /// Offset of vlan_proto field
    pub vlan_proto: i32,
    /// Offset of priority field
    pub priority: i32,
    /// Offset of data pointer
    pub data: i32,
    /// Offset of tail (used to compute data_end)
    pub tail: i32,
    /// Offset of tc_index field (TC classifier index)
    pub tc_index: i32,
    /// Offset of hash field
    pub hash: i32,
    /// Offset of cb (control buffer) array
    pub cb: i32,
    /// Offset of tc_classid (populated by cls_bpf)
    pub tc_classid: i32,
}

impl Default for SkbOffsets {
    /// Default offsets for Linux 6.x on x86_64
    fn default() -> Self {
        Self::linux_6_x_x86_64()
    }
}

impl SkbOffsets {
    /// Offsets for Linux 6.x on x86_64
    pub const fn linux_6_x_x86_64() -> Self {
        Self {
            len: 104,
            pkt_type: 108, // Part of bitfield at offset 108
            mark: 112,
            queue_mapping: 116,
            protocol: 118,
            vlan_present: 120, // __vlan_present_offset in newer kernels
            vlan_tci: 122,
            vlan_proto: 124,
            priority: 126,
            data: 192,
            tail: 200,
            tc_index: 130,
            hash: 132,
            cb: 40,         // Control buffer starts at offset 40
            tc_classid: 60, // Part of cb area, offset 40 + 20
        }
    }

    /// Offsets for Linux 5.x on x86_64
    pub const fn linux_5_x_x86_64() -> Self {
        Self {
            len: 104,
            pkt_type: 76,
            mark: 80,
            queue_mapping: 84,
            protocol: 86,
            vlan_present: 88,
            vlan_tci: 90,
            vlan_proto: 92,
            priority: 94,
            data: 128,
            tail: 136,
            tc_index: 98,
            hash: 100,
            cb: 40,
            tc_classid: 60,
        }
    }

    /// Offsets for Linux 4.x on x86_64
    pub const fn linux_4_x_x86_64() -> Self {
        Self {
            len: 96,
            pkt_type: 72,
            mark: 76,
            queue_mapping: 80,
            protocol: 82,
            vlan_present: 84,
            vlan_tci: 86,
            vlan_proto: 88,
            priority: 90,
            data: 112,
            tail: 120,
            tc_index: 94,
            hash: 96,
            cb: 40,
            tc_classid: 60,
        }
    }

    /// Offsets for Linux 6.x on aarch64
    pub const fn linux_6_x_aarch64() -> Self {
        // ARM64 may have different alignment
        Self {
            len: 104,
            pkt_type: 108,
            mark: 112,
            queue_mapping: 116,
            protocol: 118,
            vlan_present: 120,
            vlan_tci: 122,
            vlan_proto: 124,
            priority: 126,
            data: 192,
            tail: 200,
            tc_index: 130,
            hash: 132,
            cb: 40,
            tc_classid: 60,
        }
    }

    /// Create custom offsets
    #[allow(clippy::too_many_arguments)]
    pub const fn custom(
        len: i32,
        pkt_type: i32,
        mark: i32,
        queue_mapping: i32,
        protocol: i32,
        vlan_present: i32,
        vlan_tci: i32,
        vlan_proto: i32,
        priority: i32,
        data: i32,
        tail: i32,
        tc_index: i32,
        hash: i32,
        cb: i32,
        tc_classid: i32,
    ) -> Self {
        Self {
            len,
            pkt_type,
            mark,
            queue_mapping,
            protocol,
            vlan_present,
            vlan_tci,
            vlan_proto,
            priority,
            data,
            tail,
            tc_index,
            hash,
            cb,
            tc_classid,
        }
    }
}

/// xdp_buff structure field offsets.
#[derive(Debug, Clone, Copy)]
pub struct XdpOffsets {
    /// Offset of data pointer
    pub data: i32,
    /// Offset of data_end pointer
    pub data_end: i32,
    /// Offset of data_meta pointer
    pub data_meta: i32,
    /// Offset of rxq pointer
    pub rxq: i32,
}

impl Default for XdpOffsets {
    fn default() -> Self {
        Self::linux_6_x()
    }
}

impl XdpOffsets {
    /// Offsets for Linux 6.x
    pub const fn linux_6_x() -> Self {
        Self {
            data: 0,
            data_end: 8,
            data_meta: 16,
            rxq: 24,
        }
    }

    /// Offsets for Linux 5.x
    pub const fn linux_5_x() -> Self {
        Self {
            data: 0,
            data_end: 8,
            data_meta: 16,
            rxq: 24,
        }
    }
}

/// Combined kernel offsets configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelOffsets {
    /// sk_buff offsets
    pub skb: SkbOffsets,
    /// xdp_buff offsets
    pub xdp: XdpOffsets,
}

impl KernelOffsets {
    /// Create offsets for a specific kernel version
    pub fn for_kernel(major: u32, minor: u32, arch: &str) -> Self {
        let skb = match (major, arch) {
            (6.., "x86_64") => SkbOffsets::linux_6_x_x86_64(),
            (6.., "aarch64") => SkbOffsets::linux_6_x_aarch64(),
            (5, "x86_64") | (5, "aarch64") => SkbOffsets::linux_5_x_x86_64(),
            (4, _) => SkbOffsets::linux_4_x_x86_64(),
            _ => SkbOffsets::default(),
        };

        let xdp = match major {
            6.. => XdpOffsets::linux_6_x(),
            5 => XdpOffsets::linux_5_x(),
            _ => XdpOffsets::default(),
        };

        // Suppress unused warning for minor version (reserved for future use)
        let _ = minor;

        Self { skb, xdp }
    }

    /// Detect offsets for current running kernel (placeholder)
    pub fn detect() -> Self {
        // In a real implementation, this would read from /proc/kallsyms
        // or use BTF to determine actual offsets
        Self::default()
    }
}

// Helper functions that use thread-local or global configuration
// For now, use defaults. In production, these would be configurable.
fn offset_of_skb_len() -> i32 {
    SkbOffsets::default().len
}
fn offset_of_skb_pkt_type() -> i32 {
    SkbOffsets::default().pkt_type
}
fn offset_of_skb_mark() -> i32 {
    SkbOffsets::default().mark
}
fn offset_of_skb_queue_mapping() -> i32 {
    SkbOffsets::default().queue_mapping
}
fn offset_of_skb_protocol() -> i32 {
    SkbOffsets::default().protocol
}
fn offset_of_skb_vlan_present() -> i32 {
    SkbOffsets::default().vlan_present
}
fn offset_of_skb_vlan_tci() -> i32 {
    SkbOffsets::default().vlan_tci
}
fn offset_of_skb_vlan_proto() -> i32 {
    SkbOffsets::default().vlan_proto
}
fn offset_of_skb_priority() -> i32 {
    SkbOffsets::default().priority
}
fn offset_of_skb_data() -> i32 {
    SkbOffsets::default().data
}
fn offset_of_skb_data_end() -> i32 {
    SkbOffsets::default().tail
}
fn offset_of_skb_tc_index() -> i32 {
    SkbOffsets::default().tc_index
}
fn offset_of_skb_hash() -> i32 {
    SkbOffsets::default().hash
}
fn offset_of_skb_cb() -> i32 {
    SkbOffsets::default().cb
}
fn offset_of_skb_tc_classid() -> i32 {
    SkbOffsets::default().tc_classid
}

/// Result of context access conversion
#[derive(Debug, Clone, Default)]
pub struct CtxConvResult {
    /// Number of accesses converted
    pub accesses_converted: usize,
    /// Number of accesses that required helpers
    pub helper_calls_added: usize,
    /// Number of accesses that required byte swap
    pub swaps_added: usize,
    /// Total instructions added
    pub insns_added: i32,
}

/// Convert context accesses in the program
pub fn convert_ctx_accesses(
    insns: &mut Vec<BpfInsn>,
    config: &CtxConvConfig,
    ctx_accesses: &[CtxAccessInfo],
) -> Result<CtxConvResult> {
    let mut result = CtxConvResult::default();
    let mut manager = PatchManager::new();
    let orig_len = insns.len();

    for access in ctx_accesses {
        let idx = access.insn_idx;
        if idx >= insns.len() {
            continue;
        }

        let insn = &insns[idx];

        // Find the field mapping
        let mapping = match config.find_mapping(access.off, access.size) {
            Some(m) => m,
            None => {
                // No mapping found - may be an error or BTF-based access
                continue;
            }
        };

        // Check write permission
        if access.is_write && mapping.read_only {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "write to read-only context field at offset {}",
                access.off
            )));
        }

        // Generate conversion patches based on conversion type
        let patches = match mapping.conv {
            CtxConvType::Direct => convert_direct_access(insn, idx, access, mapping)?,
            CtxConvType::LoadOffset(extra_off) => {
                convert_offset_access(insn, idx, access, mapping, extra_off)?
            }
            CtxConvType::LoadSwap => {
                result.swaps_added += 1;
                convert_swap_access(insn, idx, access, mapping)?
            }
            CtxConvType::LoadHelper(helper_id) => {
                result.helper_calls_added += 1;
                convert_helper_access(insn, idx, access, helper_id)?
            }
            CtxConvType::Computed => convert_computed_access(insn, idx, access, mapping)?,
            CtxConvType::Denied => {
                return Err(VerifierError::InvalidMemoryAccess(format!(
                    "access to denied context field at offset {}",
                    access.off
                )));
            }
        };

        for patch in patches {
            manager.add_patch(patch);
        }
        result.accesses_converted += 1;
    }

    // Apply all patches
    if manager.patch_count() > 0 {
        manager.apply(insns)?;
    }

    result.insns_added = insns.len() as i32 - orig_len as i32;
    Ok(result)
}

/// Information about a context access discovered during verification
#[derive(Debug, Clone)]
pub struct CtxAccessInfo {
    /// Instruction index
    pub insn_idx: usize,
    /// Offset in context
    pub off: u32,
    /// Access size
    pub size: u32,
    /// Whether this is a write
    pub is_write: bool,
    /// Register used for context pointer
    pub ctx_reg: u8,
}

/// Convert direct access - just adjust offset
fn convert_direct_access(
    insn: &BpfInsn,
    idx: usize,
    access: &CtxAccessInfo,
    mapping: &CtxFieldMapping,
) -> Result<Vec<Patch>> {
    // Calculate the new offset
    let delta = access.off as i32 - mapping.ctx_off as i32;
    let new_off = mapping.target_off + delta;

    // Handle size mismatch (narrow load)
    let new_size = if access.size < mapping.target_size {
        // Narrow load - keep original size
        access.size
    } else {
        mapping.target_size
    };

    // Create new instruction with adjusted offset
    let size_code = match new_size {
        1 => BPF_B,
        2 => BPF_H,
        4 => BPF_W,
        8 => BPF_DW,
        _ => {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "invalid access size {}",
                new_size
            )))
        }
    };

    let class = insn.class();
    let new_insn = BpfInsn::new(
        class | BPF_MEM | size_code,
        insn.dst_reg,
        insn.src_reg,
        new_off as i16,
        insn.imm,
    );

    Ok(vec![Patch::new(idx, PatchType::Replace(new_insn))])
}

/// Convert access with additional offset
fn convert_offset_access(
    insn: &BpfInsn,
    idx: usize,
    access: &CtxAccessInfo,
    mapping: &CtxFieldMapping,
    extra_off: i32,
) -> Result<Vec<Patch>> {
    let delta = access.off as i32 - mapping.ctx_off as i32;
    let new_off = mapping.target_off + delta + extra_off;

    let new_insn = BpfInsn::new(
        insn.code,
        insn.dst_reg,
        insn.src_reg,
        new_off as i16,
        insn.imm,
    );

    Ok(vec![Patch::new(idx, PatchType::Replace(new_insn))])
}

/// Convert access with byte swap (endianness conversion)
fn convert_swap_access(
    insn: &BpfInsn,
    idx: usize,
    access: &CtxAccessInfo,
    mapping: &CtxFieldMapping,
) -> Result<Vec<Patch>> {
    let delta = access.off as i32 - mapping.ctx_off as i32;
    let new_off = mapping.target_off + delta;

    // Generate: load, then byte swap
    let size_code = match access.size {
        2 => BPF_H,
        4 => BPF_W,
        8 => BPF_DW,
        _ => {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "byte swap not supported for size {}",
                access.size
            )))
        }
    };

    let load_insn = BpfInsn::new(
        BPF_LDX | BPF_MEM | size_code,
        insn.dst_reg,
        insn.src_reg,
        new_off as i16,
        0,
    );

    // Byte swap instruction (endianness conversion)
    let swap_size: i32 = match access.size {
        2 => 16,
        4 => 32,
        8 => 64,
        _ => {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "byte swap not supported for size {}",
                access.size
            )))
        }
    };

    let swap_insn = BpfInsn::new(BPF_ALU64 | BPF_END | BPF_X, insn.dst_reg, 0, 0, swap_size);

    Ok(vec![
        Patch::new(idx, PatchType::Replace(load_insn)),
        Patch::new(idx, PatchType::InsertAfter(vec![swap_insn])),
    ])
}

/// Convert access via helper function call
fn convert_helper_access(
    _insn: &BpfInsn,
    idx: usize,
    access: &CtxAccessInfo,
    helper_id: u32,
) -> Result<Vec<Patch>> {
    // Generate helper call sequence:
    // r1 = ctx
    // r2 = offset
    // call helper_id
    // (result in r0, may need to move to dst_reg)

    let mut insns = Vec::new();

    // r1 = ctx_reg (if not already r1)
    if access.ctx_reg != 1 {
        insns.push(BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_X,
            1,
            access.ctx_reg,
            0,
            0,
        ));
    }

    // r2 = offset
    insns.push(BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_K,
        2,
        0,
        0,
        access.off as i32,
    ));

    // call helper
    insns.push(BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id as i32));

    Ok(vec![
        Patch::new(idx, PatchType::Replace(insns[0])),
        Patch::new(idx, PatchType::InsertAfter(insns[1..].to_vec())),
    ])
}

/// Convert computed access (requires runtime calculation)
fn convert_computed_access(
    insn: &BpfInsn,
    idx: usize,
    access: &CtxAccessInfo,
    mapping: &CtxFieldMapping,
) -> Result<Vec<Patch>> {
    // Computed accesses are for fields that require dereferencing
    // intermediate pointers (e.g., skb->data comes from skb->head + offset)

    // This is a simplified version - actual implementation depends on field
    let delta = access.off as i32 - mapping.ctx_off as i32;
    let new_off = mapping.target_off + delta;

    // For now, just adjust offset (proper implementation would add
    // intermediate load and add instructions)
    let new_insn = BpfInsn::new(
        insn.code,
        insn.dst_reg,
        insn.src_reg,
        new_off as i16,
        insn.imm,
    );

    Ok(vec![Patch::new(idx, PatchType::Replace(new_insn))])
}

/// Collect context accesses from verification results
pub fn collect_ctx_accesses(
    insns: &[BpfInsn],
    ctx_reg_at_insn: &[Option<u8>],
) -> Vec<CtxAccessInfo> {
    let mut accesses = Vec::new();

    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();

        // Check for memory access
        if class != BPF_LDX && class != BPF_STX && class != BPF_ST {
            continue;
        }

        // Check if src register (for LDX) or dst register (for STX/ST) is context
        let ctx_reg = match class {
            BPF_LDX => insn.src_reg,
            BPF_STX | BPF_ST => insn.dst_reg,
            _ => continue,
        };

        // Check if this register holds context pointer
        if let Some(Some(expected_ctx_reg)) = ctx_reg_at_insn.get(idx) {
            if ctx_reg != *expected_ctx_reg {
                continue;
            }
        } else {
            // No context info available for this instruction
            continue;
        }

        let size = match insn.code & 0x18 {
            BPF_B => 1,
            BPF_H => 2,
            BPF_W => 4,
            BPF_DW => 8,
            _ => continue,
        };

        accesses.push(CtxAccessInfo {
            insn_idx: idx,
            off: insn.off as u32,
            size,
            is_write: class == BPF_STX || class == BPF_ST,
            ctx_reg,
        });
    }

    accesses
}

// ============================================================================
// Heuristic Optimization for Context Access
// ============================================================================

/// Access pattern detected in the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPattern {
    /// Single isolated access.
    Single,
    /// Sequential accesses to adjacent fields.
    Sequential,
    /// Strided accesses with regular interval.
    Strided(u32),
    /// Random/irregular access pattern.
    Random,
    /// Loop-based repeated access.
    LoopBased,
}

/// Heuristic hint for optimization decisions.
#[derive(Debug, Clone)]
pub struct AccessHeuristics {
    /// Detected access pattern.
    pub pattern: AccessPattern,
    /// Fields likely to be accessed together.
    pub field_affinity: Vec<(u32, u32)>,
    /// Estimated access frequency per field.
    pub access_frequency: HashMap<u32, u32>,
    /// Whether field coalescing is beneficial.
    pub coalesce_benefit: bool,
    /// Whether prefetch would help.
    pub prefetch_benefit: bool,
    /// Estimated cache line usage.
    pub cache_lines_touched: usize,
    /// Hot fields (frequently accessed).
    pub hot_fields: Vec<u32>,
    /// Cold fields (rarely accessed).
    pub cold_fields: Vec<u32>,
}

impl Default for AccessHeuristics {
    fn default() -> Self {
        Self {
            pattern: AccessPattern::Single,
            field_affinity: Vec::new(),
            access_frequency: HashMap::new(),
            coalesce_benefit: false,
            prefetch_benefit: false,
            cache_lines_touched: 0,
            hot_fields: Vec::new(),
            cold_fields: Vec::new(),
        }
    }
}

impl AccessHeuristics {
    /// Analyze accesses and compute heuristics.
    pub fn analyze(accesses: &[CtxAccessInfo]) -> Self {
        let mut heuristics = Self::default();

        if accesses.is_empty() {
            return heuristics;
        }

        // Compute access frequency
        for access in accesses {
            *heuristics.access_frequency.entry(access.off).or_insert(0) += 1;
        }

        // Detect pattern
        heuristics.pattern = Self::detect_pattern(accesses);

        // Find field affinity (fields accessed together)
        heuristics.field_affinity = Self::find_affinity(accesses);

        // Compute cache line usage
        heuristics.cache_lines_touched = Self::compute_cache_lines(accesses);

        // Determine hot/cold fields
        Self::classify_fields(&mut heuristics);

        // Determine optimization benefits
        heuristics.coalesce_benefit = Self::should_coalesce(accesses);
        heuristics.prefetch_benefit = heuristics.cache_lines_touched > 2;

        heuristics
    }

    /// Detect the access pattern.
    fn detect_pattern(accesses: &[CtxAccessInfo]) -> AccessPattern {
        if accesses.len() == 1 {
            return AccessPattern::Single;
        }

        // Sort by offset
        let mut sorted: Vec<_> = accesses.iter().collect();
        sorted.sort_by_key(|a| a.off);

        // Check for sequential pattern
        let mut is_sequential = true;
        let mut strides = Vec::new();

        for window in sorted.windows(2) {
            let off1 = window[0].off + window[0].size;
            let off2 = window[1].off;

            if off1 != off2 {
                is_sequential = false;
            }

            if window[1].off > window[0].off {
                strides.push(window[1].off - window[0].off);
            }
        }

        if is_sequential {
            return AccessPattern::Sequential;
        }

        // Check for strided pattern
        if !strides.is_empty() {
            let first_stride = strides[0];
            if strides.iter().all(|&s| s == first_stride) {
                return AccessPattern::Strided(first_stride);
            }
        }

        // Check for loop-based pattern (same offsets repeated)
        let unique_offsets: HashSet<_> = accesses.iter().map(|a| a.off).collect();
        if unique_offsets.len() < accesses.len() / 2 {
            return AccessPattern::LoopBased;
        }

        AccessPattern::Random
    }

    /// Find fields that are often accessed together.
    fn find_affinity(accesses: &[CtxAccessInfo]) -> Vec<(u32, u32)> {
        let mut affinity = Vec::new();

        // Look for accesses within a small window of instructions
        const WINDOW_SIZE: usize = 5;

        for i in 0..accesses.len() {
            for j in (i + 1)..accesses.len().min(i + WINDOW_SIZE) {
                if accesses[i].off != accesses[j].off {
                    let pair = if accesses[i].off < accesses[j].off {
                        (accesses[i].off, accesses[j].off)
                    } else {
                        (accesses[j].off, accesses[i].off)
                    };
                    if !affinity.contains(&pair) {
                        affinity.push(pair);
                    }
                }
            }
        }

        affinity
    }

    /// Compute number of cache lines touched.
    fn compute_cache_lines(accesses: &[CtxAccessInfo]) -> usize {
        const CACHE_LINE_SIZE: u32 = 64;

        let mut lines: HashSet<u32> = HashSet::new();

        for access in accesses {
            let start_line = access.off / CACHE_LINE_SIZE;
            let end_line = (access.off + access.size - 1) / CACHE_LINE_SIZE;
            for line in start_line..=end_line {
                lines.insert(line);
            }
        }

        lines.len()
    }

    /// Classify fields as hot or cold based on frequency.
    fn classify_fields(heuristics: &mut AccessHeuristics) {
        if heuristics.access_frequency.is_empty() {
            return;
        }

        let total: u32 = heuristics.access_frequency.values().sum();
        let threshold_hot = total / heuristics.access_frequency.len() as u32;

        for (&off, &count) in &heuristics.access_frequency {
            if count >= threshold_hot * 2 {
                heuristics.hot_fields.push(off);
            } else if count == 1 {
                heuristics.cold_fields.push(off);
            }
        }

        heuristics.hot_fields.sort();
        heuristics.cold_fields.sort();
    }

    /// Determine if field coalescing would be beneficial.
    fn should_coalesce(accesses: &[CtxAccessInfo]) -> bool {
        // Coalescing is beneficial when:
        // 1. Multiple adjacent small accesses exist
        // 2. Accesses are reads (writes can't always be coalesced)

        let reads: Vec<_> = accesses.iter().filter(|a| !a.is_write).collect();

        if reads.len() < 2 {
            return false;
        }

        // Check for adjacent accesses
        let mut sorted = reads;
        sorted.sort_by_key(|a| a.off);

        for window in sorted.windows(2) {
            let end1 = window[0].off + window[0].size;
            let start2 = window[1].off;

            // Adjacent or overlapping
            if end1 >= start2 && window[0].size < 8 && window[1].size < 8 {
                return true;
            }
        }

        false
    }
}

/// Configuration for context access optimization.
#[derive(Debug, Clone)]
pub struct CtxOptConfig {
    /// Enable field coalescing.
    pub enable_coalescing: bool,
    /// Enable dead access elimination.
    pub enable_dce: bool,
    /// Enable access reordering for cache.
    pub enable_reordering: bool,
    /// Enable speculative field conversion.
    pub enable_speculation: bool,
    /// Maximum coalesced access size.
    pub max_coalesce_size: u32,
    /// Minimum benefit threshold for coalescing.
    pub coalesce_threshold: u32,
}

impl Default for CtxOptConfig {
    fn default() -> Self {
        Self {
            enable_coalescing: true,
            enable_dce: true,
            enable_reordering: false, // Conservative by default
            enable_speculation: false,
            max_coalesce_size: 8,
            coalesce_threshold: 2,
        }
    }
}

impl CtxOptConfig {
    /// Aggressive optimization configuration.
    pub fn aggressive() -> Self {
        Self {
            enable_coalescing: true,
            enable_dce: true,
            enable_reordering: true,
            enable_speculation: true,
            max_coalesce_size: 8,
            coalesce_threshold: 1,
        }
    }

    /// Conservative configuration (minimal changes).
    pub fn conservative() -> Self {
        Self {
            enable_coalescing: false,
            enable_dce: false,
            enable_reordering: false,
            enable_speculation: false,
            max_coalesce_size: 4,
            coalesce_threshold: 4,
        }
    }
}

/// Coalesced field access.
#[derive(Debug, Clone)]
pub struct CoalescedAccess {
    /// Starting offset.
    pub start_off: u32,
    /// Total size of coalesced access.
    pub total_size: u32,
    /// Original accesses that were coalesced.
    pub original_accesses: Vec<usize>,
    /// Extraction masks for each original value.
    pub extract_masks: Vec<(u32, u32)>, // (shift, mask)
}

/// Result of context optimization.
#[derive(Debug, Clone, Default)]
pub struct CtxOptResult {
    /// Accesses coalesced.
    pub accesses_coalesced: usize,
    /// Dead accesses eliminated.
    pub dead_accesses_removed: usize,
    /// Accesses reordered.
    pub accesses_reordered: usize,
    /// Instructions saved.
    pub insns_saved: i32,
    /// Detected pattern.
    pub pattern: Option<AccessPattern>,
    /// Optimization heuristics used.
    pub heuristics: Option<AccessHeuristics>,
}

/// Optimize context accesses using heuristics.
pub fn optimize_ctx_accesses(accesses: &[CtxAccessInfo], config: &CtxOptConfig) -> CtxOptResult {
    let mut result = CtxOptResult::default();

    if accesses.is_empty() {
        return result;
    }

    // Analyze access patterns
    let heuristics = AccessHeuristics::analyze(accesses);
    result.pattern = Some(heuristics.pattern);
    result.heuristics = Some(heuristics.clone());

    // Apply coalescing if beneficial
    if config.enable_coalescing && heuristics.coalesce_benefit {
        let coalesced = find_coalesce_opportunities(accesses, config);
        result.accesses_coalesced = coalesced.len();
        result.insns_saved += coalesced.len() as i32;
    }

    result
}

/// Find opportunities for field coalescing.
pub fn find_coalesce_opportunities(
    accesses: &[CtxAccessInfo],
    config: &CtxOptConfig,
) -> Vec<CoalescedAccess> {
    let mut coalesced = Vec::new();

    // Only coalesce reads
    let reads: Vec<_> = accesses
        .iter()
        .enumerate()
        .filter(|(_, a)| !a.is_write)
        .collect();

    if reads.len() < 2 {
        return coalesced;
    }

    // Sort by offset
    let mut sorted = reads;
    sorted.sort_by_key(|(_, a)| a.off);

    let mut i = 0;
    while i < sorted.len() {
        let mut group = vec![sorted[i]];
        let start_off = sorted[i].1.off;
        let mut end_off = start_off + sorted[i].1.size;

        // Find adjacent accesses
        let mut j = i + 1;
        while j < sorted.len() {
            let next_off = sorted[j].1.off;
            let next_end = next_off + sorted[j].1.size;

            // Check if adjacent and within max size
            if next_off <= end_off && next_end - start_off <= config.max_coalesce_size {
                group.push(sorted[j]);
                end_off = end_off.max(next_end);
                j += 1;
            } else {
                break;
            }
        }

        // Only coalesce if we have enough accesses
        if group.len() >= config.coalesce_threshold as usize {
            let total_size = end_off - start_off;

            // Calculate extraction masks
            let extract_masks: Vec<_> = group
                .iter()
                .map(|(_, a)| {
                    let shift = (a.off - start_off) * 8;
                    let mask = (1u64 << (a.size * 8)) - 1;
                    (shift, mask as u32)
                })
                .collect();

            coalesced.push(CoalescedAccess {
                start_off,
                total_size,
                original_accesses: group.iter().map(|(idx, _)| *idx).collect(),
                extract_masks,
            });
        }

        i = j;
    }

    coalesced
}

/// Dead access information.
#[derive(Debug, Clone)]
pub struct DeadAccessInfo {
    /// Instruction index of dead access.
    pub insn_idx: usize,
    /// Reason the access is dead.
    pub reason: DeadAccessReason,
}

/// Reason why an access is considered dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadAccessReason {
    /// Value is overwritten before use.
    OverwrittenBeforeUse,
    /// Value is never used.
    NeverUsed,
    /// Redundant load (same value already in register).
    RedundantLoad,
}

/// Find dead context accesses that can be eliminated.
pub fn find_dead_accesses(accesses: &[CtxAccessInfo], insns: &[BpfInsn]) -> Vec<DeadAccessInfo> {
    let mut dead = Vec::new();

    for (i, access) in accesses.iter().enumerate() {
        if access.is_write {
            continue; // Only analyze reads
        }

        let insn_idx = access.insn_idx;
        if insn_idx >= insns.len() {
            continue;
        }

        let dst_reg = insns[insn_idx].dst_reg;

        // Check if this register is overwritten before being used
        let mut used = false;
        let mut overwritten = false;

        let end = insns.len().min(insn_idx + 20);
        for check_insn in &insns[(insn_idx + 1)..end] {
            // Check if register is used as source
            if check_insn.src_reg == dst_reg {
                used = true;
                break;
            }

            // Check if register is used in memory access
            let class = check_insn.class();
            if (class == BPF_STX || class == BPF_ST) && check_insn.src_reg == dst_reg {
                used = true;
                break;
            }

            // Check if register is overwritten
            if check_insn.dst_reg == dst_reg {
                let check_class = check_insn.class();
                if check_class == BPF_ALU
                    || check_class == BPF_ALU64
                    || check_class == BPF_LDX
                    || check_class == BPF_LD
                {
                    overwritten = true;
                    break;
                }
            }

            // Stop at control flow
            if class == BPF_JMP || class == BPF_JMP32 {
                break;
            }
        }

        if overwritten && !used {
            dead.push(DeadAccessInfo {
                insn_idx,
                reason: DeadAccessReason::OverwrittenBeforeUse,
            });
        }

        // Check for redundant loads (same field loaded into different register
        // when previous register still valid)
        for prev_access in &accesses[..i] {
            if prev_access.off == access.off
                && prev_access.size == access.size
                && !prev_access.is_write
            {
                // Check if original register is still valid
                let orig_insn = prev_access.insn_idx;
                let orig_dst = insns[orig_insn].dst_reg;

                // Simple check: if no intervening write to that register
                let mut still_valid = true;
                for insn in &insns[(orig_insn + 1)..insn_idx] {
                    if insn.dst_reg == orig_dst {
                        still_valid = false;
                        break;
                    }
                }

                if still_valid {
                    dead.push(DeadAccessInfo {
                        insn_idx,
                        reason: DeadAccessReason::RedundantLoad,
                    });
                    break;
                }
            }
        }
    }

    dead
}

/// Context access cache for repeated conversions.
#[derive(Debug, Default)]
pub struct CtxAccessCache {
    /// Cached conversions by (offset, size).
    cache: HashMap<(u32, u32), CtxFieldAccess>,
    /// Hit count for statistics.
    pub hits: usize,
    /// Miss count for statistics.
    pub misses: usize,
}

impl CtxAccessCache {
    /// Create a new cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached conversion.
    pub fn get(&mut self, off: u32, size: u32) -> Option<&CtxFieldAccess> {
        if self.cache.contains_key(&(off, size)) {
            self.hits += 1;
            self.cache.get(&(off, size))
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a conversion into the cache.
    pub fn insert(&mut self, off: u32, size: u32, access: CtxFieldAccess) {
        self.cache.insert((off, size), access);
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Get cache hit rate as percentage (0-100).
    pub fn hit_rate_percent(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            0
        } else {
            ((self.hits as u64 * 100) / total as u64) as u32
        }
    }
}

/// Speculative field pre-conversion based on program type.
///
/// Some fields are commonly accessed together. Pre-converting them
/// can reduce conversion overhead at runtime.
pub fn speculative_preconvert(prog_type: BpfProgType, heuristics: &AccessHeuristics) -> Vec<u32> {
    let mut fields_to_preconvert = Vec::new();

    // Add hot fields
    fields_to_preconvert.extend(&heuristics.hot_fields);

    // Add commonly co-accessed fields based on program type
    match prog_type {
        BpfProgType::SocketFilter | BpfProgType::SchedCls | BpfProgType::SchedAct => {
            // Network programs often access: len, protocol, mark
            let common = [0, 16, 8]; // len, protocol, mark offsets
            for &off in &common {
                if !fields_to_preconvert.contains(&off) {
                    fields_to_preconvert.push(off);
                }
            }
        }
        BpfProgType::Xdp => {
            // XDP programs: data, data_end, data_meta
            let common = [0, 4, 8];
            for &off in &common {
                if !fields_to_preconvert.contains(&off) {
                    fields_to_preconvert.push(off);
                }
            }
        }
        BpfProgType::CgroupSkb => {
            // Cgroup: len, mark, priority
            let common = [0, 8, 32];
            for &off in &common {
                if !fields_to_preconvert.contains(&off) {
                    fields_to_preconvert.push(off);
                }
            }
        }
        _ => {}
    }

    // Add fields with high affinity
    for &(f1, f2) in &heuristics.field_affinity {
        if fields_to_preconvert.contains(&f1) && !fields_to_preconvert.contains(&f2) {
            fields_to_preconvert.push(f2);
        }
        if fields_to_preconvert.contains(&f2) && !fields_to_preconvert.contains(&f1) {
            fields_to_preconvert.push(f1);
        }
    }

    fields_to_preconvert.sort();
    fields_to_preconvert.dedup();
    fields_to_preconvert
}
