// SPDX-License-Identifier: GPL-2.0

//! Linux BPF program type definitions.

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
