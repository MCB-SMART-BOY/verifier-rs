// SPDX-License-Identifier: GPL-2.0

//! Linux BPF map type definitions.

use bpf_verifier_core::platform::{MapProvider, MapTypeInfo, MapCapabilities};

// TODO: Migrate from bpf-verifier-core/src/special/map_ops.rs

/// Linux map provider.
#[derive(Clone)]
pub struct LinuxMapProvider {
    // Runtime configuration could go here
}

impl LinuxMapProvider {
    /// Create a new Linux map provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxMapProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MapProvider for LinuxMapProvider {
    fn get_info(&self, map_type: u32) -> Option<&MapTypeInfo> {
        LINUX_MAP_TYPES.iter().find(|m| m.map_type == map_type)
    }

    fn iter(&self) -> impl Iterator<Item = &MapTypeInfo> {
        LINUX_MAP_TYPES.iter()
    }
}

// Minimal map type database for initial compilation
// TODO: Migrate full database from special/map_ops.rs
static LINUX_MAP_TYPES: &[MapTypeInfo] = &[
    MapTypeInfo {
        map_type: 0, // UNSPEC
        name: "UNSPEC",
        capabilities: MapCapabilities::none(),
        description: "Unspecified map type",
        allowed_helpers: &[],
    },
    MapTypeInfo {
        map_type: 1, // HASH
        name: "HASH",
        capabilities: MapCapabilities::standard(),
        description: "Hash table map",
        allowed_helpers: &[1, 2, 3], // lookup, update, delete
    },
    MapTypeInfo {
        map_type: 2, // ARRAY
        name: "ARRAY",
        capabilities: MapCapabilities::array(),
        description: "Array map",
        allowed_helpers: &[1, 2], // lookup, update (no delete)
    },
    MapTypeInfo {
        map_type: 6, // PERCPU_HASH
        name: "PERCPU_HASH",
        capabilities: MapCapabilities::standard().with_percpu(),
        description: "Per-CPU hash table map",
        allowed_helpers: &[1, 2, 3],
    },
    MapTypeInfo {
        map_type: 7, // PERCPU_ARRAY
        name: "PERCPU_ARRAY",
        capabilities: MapCapabilities::array().with_percpu(),
        description: "Per-CPU array map",
        allowed_helpers: &[1, 2],
    },
    MapTypeInfo {
        map_type: 23, // STACK
        name: "STACK",
        capabilities: MapCapabilities::stack_queue(),
        description: "Stack map",
        allowed_helpers: &[],
    },
    MapTypeInfo {
        map_type: 22, // QUEUE
        name: "QUEUE",
        capabilities: MapCapabilities::stack_queue(),
        description: "Queue map",
        allowed_helpers: &[],
    },
];
