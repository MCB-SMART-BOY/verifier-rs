// SPDX-License-Identifier: GPL-2.0

//! Linux BPF kfunc definitions.

use bpf_verifier_core::platform::{KfuncProvider, KfuncDef, KfuncFlags};

// TODO: Migrate from bpf-verifier-core/src/check/kfunc.rs

/// Linux kfunc provider.
#[derive(Clone)]
pub struct LinuxKfuncProvider {
    // Runtime configuration could go here
}

impl LinuxKfuncProvider {
    /// Create a new Linux kfunc provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxKfuncProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KfuncProvider for LinuxKfuncProvider {
    fn lookup(&self, btf_id: u32) -> Option<&KfuncDef> {
        LINUX_KFUNCS.iter().find(|k| k.btf_id == btf_id)
    }

    fn lookup_by_name(&self, name: &str) -> Option<&KfuncDef> {
        LINUX_KFUNCS.iter().find(|k| k.name == name)
    }

    fn iter(&self) -> impl Iterator<Item = &KfuncDef> {
        LINUX_KFUNCS.iter()
    }
}

// Minimal kfunc database for initial compilation
// TODO: Migrate full database from check/kfunc.rs
static LINUX_KFUNCS: &[KfuncDef] = &[
    KfuncDef {
        btf_id: 1,
        name: "bpf_rcu_read_lock",
        flags: KfuncFlags::none(),
        allowed_prog_types: &[],
        param_types: &[],
        ret_type: None,
        ret_btf_id: None,
    },
    KfuncDef {
        btf_id: 2,
        name: "bpf_rcu_read_unlock",
        flags: KfuncFlags::none(),
        allowed_prog_types: &[],
        param_types: &[],
        ret_type: None,
        ret_btf_id: None,
    },
];
