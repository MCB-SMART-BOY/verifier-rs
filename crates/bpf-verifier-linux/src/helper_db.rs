// SPDX-License-Identifier: GPL-2.0

//! Linux BPF 辅助函数数据库模块
//!
//! Linux BPF Helper Function Database.
//!
//! 本模块包含 Linux BPF 辅助函数的完整数据库，包括函数签名、
//! 返回类型和允许的程序类型。
//!
//! This module contains the complete database of Linux BPF helper functions,
//! including their signatures, return types, and allowed program types.
//!
//! # 主要辅助函数类别 / Main Helper Categories
//!
//! - **Map 操作 / Map operations**: `bpf_map_lookup_elem`、`bpf_map_update_elem` 等
//! - **数据包操作 / Packet operations**: `bpf_skb_load_bytes`、`bpf_xdp_adjust_head` 等
//! - **跟踪 / Tracing**: `bpf_probe_read`、`bpf_get_current_pid_tgid` 等
//! - **时间 / Time**: `bpf_ktime_get_ns`、`bpf_jiffies64` 等

use bpf_verifier_core::platform::{HelperProvider, HelperDef, HelperFlags};
use bpf_verifier_core::core::types::{BpfArgType, BpfRetType};

// TODO: Migrate HELPER_DB from bpf-verifier-core/src/check/helper_db.rs
// For now, provide a minimal implementation

/// Linux BPF helper provider.
#[derive(Clone)]
pub struct LinuxHelperProvider {
    // In future: could hold runtime configuration
}

impl LinuxHelperProvider {
    /// Create a new Linux helper provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxHelperProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperProvider for LinuxHelperProvider {
    fn lookup(&self, func_id: u32) -> Option<&HelperDef> {
        LINUX_HELPERS.iter().find(|h| h.func_id == func_id)
    }

    fn count(&self) -> usize {
        LINUX_HELPERS.len()
    }

    fn iter(&self) -> impl Iterator<Item = &HelperDef> {
        LINUX_HELPERS.iter()
    }
}

// Minimal helper database for initial compilation
// TODO: Migrate full database from check/helper_db.rs
static LINUX_HELPERS: &[HelperDef] = &[
    // Map operations
    HelperDef {
        func_id: 1, // bpf_map_lookup_elem
        name: "bpf_map_lookup_elem",
        ret_type: BpfRetType::PtrToMapValueOrNull,
        arg_types: [
            BpfArgType::ConstMapPtr,
            BpfArgType::PtrToMapKey,
            BpfArgType::DontCare,
            BpfArgType::DontCare,
            BpfArgType::DontCare,
        ],
        flags: HelperFlags::none(),
        allowed_prog_types: &[],
    },
    HelperDef {
        func_id: 2, // bpf_map_update_elem
        name: "bpf_map_update_elem",
        ret_type: BpfRetType::Integer,
        arg_types: [
            BpfArgType::ConstMapPtr,
            BpfArgType::PtrToMapKey,
            BpfArgType::PtrToMapValue,
            BpfArgType::Anything,
            BpfArgType::DontCare,
        ],
        flags: HelperFlags::none(),
        allowed_prog_types: &[],
    },
    HelperDef {
        func_id: 3, // bpf_map_delete_elem
        name: "bpf_map_delete_elem",
        ret_type: BpfRetType::Integer,
        arg_types: [
            BpfArgType::ConstMapPtr,
            BpfArgType::PtrToMapKey,
            BpfArgType::DontCare,
            BpfArgType::DontCare,
            BpfArgType::DontCare,
        ],
        flags: HelperFlags::none(),
        allowed_prog_types: &[],
    },
];
