// SPDX-License-Identifier: GPL-2.0

//! Linux BPF 上下文结构定义模块
//!
//! Linux BPF Context Structure Definitions.
//!
//! 本模块包含 Linux 各种程序类型的上下文结构定义，如 XDP、Socket Filter 等。
//!
//! This module contains context structure definitions for various Linux
//! program types such as XDP, Socket Filter, etc.
//!
//! # 支持的上下文 / Supported Contexts
//!
//! - **`xdp_md`**: XDP 程序上下文，提供数据包数据访问
//!   XDP program context providing packet data access
//! - **`__sk_buff`**: Socket 程序上下文
//!   Socket program context
//! - **`pt_regs`**: Kprobe 程序上下文
//!   Kprobe program context

use bpf_verifier_core::platform::{
    ContextProvider, ContextFieldDef, FieldAccessMode, FieldResultType, ContextDef,
};

// TODO: Migrate from bpf-verifier-core/src/check/prog_type.rs and mem/context.rs

/// Linux context provider.
#[derive(Clone)]
pub struct LinuxContextProvider {
    // Runtime configuration could go here
}

impl LinuxContextProvider {
    /// Create a new Linux context provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxContextProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextProvider for LinuxContextProvider {
    fn get_context(&self, prog_type: u32) -> Option<&ContextDef> {
        LINUX_CONTEXTS.iter().find(|c| c.prog_type == prog_type)
    }

    fn iter(&self) -> impl Iterator<Item = &ContextDef> {
        LINUX_CONTEXTS.iter()
    }
}

// XDP context fields (struct xdp_md)
static XDP_FIELDS: &[ContextFieldDef] = &[
    ContextFieldDef {
        offset: 0,
        size: 4,
        access: FieldAccessMode::Read,
        name: "data",
        result_type: FieldResultType::PtrToPacket,
        special: true,
        alignment: 4,
        allow_narrow: false,
    },
    ContextFieldDef {
        offset: 4,
        size: 4,
        access: FieldAccessMode::Read,
        name: "data_end",
        result_type: FieldResultType::PtrToPacketEnd,
        special: true,
        alignment: 4,
        allow_narrow: false,
    },
    ContextFieldDef {
        offset: 8,
        size: 4,
        access: FieldAccessMode::Read,
        name: "data_meta",
        result_type: FieldResultType::PtrToPacketMeta,
        special: true,
        alignment: 4,
        allow_narrow: false,
    },
    ContextFieldDef {
        offset: 12,
        size: 4,
        access: FieldAccessMode::Read,
        name: "ingress_ifindex",
        result_type: FieldResultType::Scalar,
        special: false,
        alignment: 4,
        allow_narrow: false,
    },
    ContextFieldDef {
        offset: 16,
        size: 4,
        access: FieldAccessMode::Read,
        name: "rx_queue_index",
        result_type: FieldResultType::Scalar,
        special: false,
        alignment: 4,
        allow_narrow: false,
    },
    ContextFieldDef {
        offset: 20,
        size: 4,
        access: FieldAccessMode::Read,
        name: "egress_ifindex",
        result_type: FieldResultType::Scalar,
        special: false,
        alignment: 4,
        allow_narrow: false,
    },
];

// Minimal context database for initial compilation
// TODO: Migrate full database
static LINUX_CONTEXTS: &[ContextDef] = &[
    ContextDef {
        prog_type: 6, // XDP
        size: 24,
        fields: XDP_FIELDS,
        allow_narrow_default: false,
        default_alignment: 4,
    },
];
