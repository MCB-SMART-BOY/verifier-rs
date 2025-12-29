// SPDX-License-Identifier: GPL-2.0

//! Linux platform specification implementation.

use bpf_verifier_core::platform::PlatformSpec;
use crate::{
    LinuxHelperProvider, LinuxProgTypeProvider, LinuxKfuncProvider,
    LinuxMapProvider, LinuxContextProvider,
};

/// Linux platform specification.
///
/// This is the main entry point for using the Linux platform with
/// the BPF verifier. It implements [`PlatformSpec`] and provides
/// access to all Linux-specific definitions.
///
/// # Example
///
/// ```ignore
/// use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
/// use bpf_verifier_linux::LinuxSpec;
///
/// let platform = LinuxSpec::new();
/// let mut env = VerifierEnv::new(platform, BpfProgType::Xdp as u32, insns);
/// let mut verifier = MainVerifier::new(&mut env);
/// verifier.verify()?;
/// ```
#[derive(Clone)]
pub struct LinuxSpec {
    helper: LinuxHelperProvider,
    prog_type: LinuxProgTypeProvider,
    kfunc: LinuxKfuncProvider,
    map: LinuxMapProvider,
    context: LinuxContextProvider,
}

impl LinuxSpec {
    /// Create a new Linux platform specification with default settings.
    pub fn new() -> Self {
        Self {
            helper: LinuxHelperProvider::new(),
            prog_type: LinuxProgTypeProvider::new(),
            kfunc: LinuxKfuncProvider::new(),
            map: LinuxMapProvider::new(),
            context: LinuxContextProvider::new(),
        }
    }
}

impl Default for LinuxSpec {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformSpec for LinuxSpec {
    type Helper = LinuxHelperProvider;
    type ProgType = LinuxProgTypeProvider;
    type Kfunc = LinuxKfuncProvider;
    type Map = LinuxMapProvider;
    type Context = LinuxContextProvider;

    fn helper(&self) -> &Self::Helper {
        &self.helper
    }

    fn prog_type(&self) -> &Self::ProgType {
        &self.prog_type
    }

    fn kfunc(&self) -> &Self::Kfunc {
        &self.kfunc
    }

    fn map(&self) -> &Self::Map {
        &self.map
    }

    fn context(&self) -> &Self::Context {
        &self.context
    }

    fn name(&self) -> &'static str {
        "linux"
    }

    fn version(&self) -> Option<&'static str> {
        Some("6.x")
    }
}
