// SPDX-License-Identifier: GPL-2.0

//! Linux BPF 程序类型定义模块
//!
//! Linux BPF Program Type Definitions.
//!
//! 本模块包含 Linux 支持的所有 BPF 程序类型定义，包括它们的能力、
//! 上下文大小和返回值范围。
//!
//! This module contains definitions of all BPF program types supported by
//! Linux, including their capabilities, context sizes, and return value ranges.
//!
//! # 主要程序类型 / Main Program Types
//!
//! - **XDP**: 高性能数据包处理，在驱动层运行
//!   High-performance packet processing at driver level
//! - **SOCKET_FILTER**: 套接字过滤器
//!   Socket filter
//! - **KPROBE / TRACEPOINT**: 内核跟踪和调试
//!   Kernel tracing and debugging
//! - **STRUCT_OPS**: 实现内核结构体操作
//!   Implement kernel struct operations

use bpf_verifier_core::platform::{ProgTypeProvider, ProgTypeInfo, ProgCapabilities, RetvalRange};

// TODO: Migrate from bpf-verifier-core/src/check/prog_type.rs

/// Linux program type provider.
#[derive(Clone)]
pub struct LinuxProgTypeProvider {
    // Runtime configuration could go here
}

impl LinuxProgTypeProvider {
    /// Create a new Linux program type provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxProgTypeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgTypeProvider for LinuxProgTypeProvider {
    fn get_info(&self, prog_type: u32) -> Option<&ProgTypeInfo> {
        LINUX_PROG_TYPES.iter().find(|p| p.prog_type == prog_type)
    }

    fn iter(&self) -> impl Iterator<Item = &ProgTypeInfo> {
        LINUX_PROG_TYPES.iter()
    }
}

// Minimal program type database for initial compilation
// TODO: Migrate full database from check/prog_type.rs
static LINUX_PROG_TYPES: &[ProgTypeInfo] = &[
    ProgTypeInfo {
        prog_type: 0, // UNSPEC
        name: "UNSPEC",
        ctx_size: 0,
        ret_range: RetvalRange::new(0, 0),
        capabilities: ProgCapabilities::none(),
        max_insns: 1_000_000,
        description: "Unspecified program type",
        allowed_helpers: &[],
    },
    ProgTypeInfo {
        prog_type: 1, // SOCKET_FILTER
        name: "SOCKET_FILTER",
        ctx_size: 84, // __sk_buff
        ret_range: RetvalRange::new(0, 0xFFFFFFFF_u32 as i64),
        capabilities: ProgCapabilities::none(),
        max_insns: 4096,
        description: "Socket filter program",
        allowed_helpers: &[],
    },
    ProgTypeInfo {
        prog_type: 6, // XDP
        name: "XDP",
        ctx_size: 24, // xdp_md
        ret_range: RetvalRange::new(0, 4), // XDP_ABORTED..XDP_REDIRECT
        capabilities: ProgCapabilities {
            direct_packet_access: true,
            tail_call: true,
            spinlock: true,
            sleepable: false,
            kernel_mem_access: false,
            timer: false,
            rcu: false,
            arena: true,
            exceptions: false,
            private_stack: false,
        },
        max_insns: 1_000_000,
        description: "XDP (eXpress Data Path) program",
        allowed_helpers: &[],
    },
];
