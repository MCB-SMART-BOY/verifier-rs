// SPDX-License-Identifier: GPL-2.0

//! Platform specification trait.
//!
//! This module defines the main [`PlatformSpec`] trait that combines all
//! platform-specific providers into a single coherent interface.

use super::{
    ContextProvider, HelperProvider, KfuncProvider, MapProvider, ProgTypeProvider,
};

/// Platform specification trait.
///
/// This is the main trait that platform implementations must implement.
/// It provides access to all platform-specific providers through a single
/// unified interface.
///
/// # Design
///
/// The trait uses associated types for each provider, allowing:
/// - Static dispatch for zero-cost abstractions
/// - Compile-time type checking
/// - Platform-specific optimizations
///
/// # Example Implementation
///
/// ```ignore
/// use bpf_verifier_core::platform::*;
///
/// #[derive(Clone)]
/// struct LinuxSpec {
///     helper: LinuxHelperProvider,
///     prog_type: LinuxProgTypeProvider,
///     kfunc: LinuxKfuncProvider,
///     map: LinuxMapProvider,
///     context: LinuxContextProvider,
/// }
///
/// impl PlatformSpec for LinuxSpec {
///     type Helper = LinuxHelperProvider;
///     type ProgType = LinuxProgTypeProvider;
///     type Kfunc = LinuxKfuncProvider;
///     type Map = LinuxMapProvider;
///     type Context = LinuxContextProvider;
///
///     fn helper(&self) -> &Self::Helper { &self.helper }
///     fn prog_type(&self) -> &Self::ProgType { &self.prog_type }
///     fn kfunc(&self) -> &Self::Kfunc { &self.kfunc }
///     fn map(&self) -> &Self::Map { &self.map }
///     fn context(&self) -> &Self::Context { &self.context }
///     fn name(&self) -> &'static str { "linux" }
/// }
/// ```
///
/// # Usage in Verifier
///
/// ```ignore
/// use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
///
/// fn verify_program<P: PlatformSpec>(
///     platform: P,
///     prog_type: u32,
///     insns: Vec<BpfInsn>,
/// ) -> Result<()> {
///     let mut env = VerifierEnv::new(platform, prog_type, insns);
///     let mut verifier = MainVerifier::new(&mut env);
///     verifier.verify()
/// }
///
/// // For Linux
/// let result = verify_program(LinuxSpec::new(), XDP, insns);
///
/// // For custom OS
/// let result = verify_program(MyOsSpec::new(), MY_PROG_TYPE, insns);
/// ```
pub trait PlatformSpec: Clone + Send + Sync + 'static {
    /// Helper function provider type
    type Helper: HelperProvider;
    /// Program type provider type
    type ProgType: ProgTypeProvider;
    /// Kfunc provider type
    type Kfunc: KfuncProvider;
    /// Map provider type
    type Map: MapProvider;
    /// Context provider type
    type Context: ContextProvider;

    /// Get the helper provider.
    fn helper(&self) -> &Self::Helper;

    /// Get the program type provider.
    fn prog_type(&self) -> &Self::ProgType;

    /// Get the kfunc provider.
    fn kfunc(&self) -> &Self::Kfunc;

    /// Get the map provider.
    fn map(&self) -> &Self::Map;

    /// Get the context provider.
    fn context(&self) -> &Self::Context;

    /// Get the platform name (for logging/debugging).
    fn name(&self) -> &'static str;

    /// Get platform version (optional).
    fn version(&self) -> Option<&'static str> {
        None
    }

    /// Check if this platform supports a specific feature.
    fn supports_feature(&self, _feature: &str) -> bool {
        false
    }

    // =========================================================================
    // Convenience methods that delegate to providers
    // =========================================================================

    /// Look up a helper by ID.
    fn lookup_helper(&self, func_id: u32) -> Option<&super::HelperDef> {
        self.helper().lookup(func_id)
    }

    /// Check if a helper is allowed for a program type.
    fn is_helper_allowed(&self, func_id: u32, prog_type: u32) -> bool {
        self.helper().is_allowed_for_prog(func_id, prog_type)
    }

    /// Get program type info.
    fn get_prog_info(&self, prog_type: u32) -> Option<&super::ProgTypeInfo> {
        self.prog_type().get_info(prog_type)
    }

    /// Check if a program type is valid.
    fn is_prog_type_valid(&self, prog_type: u32) -> bool {
        self.prog_type().is_valid(prog_type)
    }

    /// Look up a kfunc by BTF ID.
    fn lookup_kfunc(&self, btf_id: u32) -> Option<&super::KfuncDef> {
        self.kfunc().lookup(btf_id)
    }

    /// Get map type info.
    fn get_map_info(&self, map_type: u32) -> Option<&super::MapTypeInfo> {
        self.map().get_info(map_type)
    }

    /// Get context size for a program type.
    fn ctx_size(&self, prog_type: u32) -> u32 {
        self.context().ctx_size(prog_type)
    }
}

/// A no-op platform for testing.
///
/// This platform implementation provides empty/default responses
/// for all queries. Useful for testing verifier logic without
/// platform-specific data.
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullPlatform;

/// Empty helper provider
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullHelperProvider;

impl HelperProvider for NullHelperProvider {
    fn lookup(&self, _func_id: u32) -> Option<&super::HelperDef> {
        None
    }

    fn count(&self) -> usize {
        0
    }

    fn iter(&self) -> impl Iterator<Item = &super::HelperDef> {
        core::iter::empty()
    }
}

/// Empty program type provider
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullProgTypeProvider;

impl ProgTypeProvider for NullProgTypeProvider {
    fn get_info(&self, _prog_type: u32) -> Option<&super::ProgTypeInfo> {
        None
    }

    fn iter(&self) -> impl Iterator<Item = &super::ProgTypeInfo> {
        core::iter::empty()
    }
}

/// Empty kfunc provider
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullKfuncProvider;

impl KfuncProvider for NullKfuncProvider {
    fn lookup(&self, _btf_id: u32) -> Option<&super::KfuncDef> {
        None
    }

    fn lookup_by_name(&self, _name: &str) -> Option<&super::KfuncDef> {
        None
    }

    fn iter(&self) -> impl Iterator<Item = &super::KfuncDef> {
        core::iter::empty()
    }
}

/// Empty map provider
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullMapProvider;

impl MapProvider for NullMapProvider {
    fn get_info(&self, _map_type: u32) -> Option<&super::MapTypeInfo> {
        None
    }

    fn iter(&self) -> impl Iterator<Item = &super::MapTypeInfo> {
        core::iter::empty()
    }
}

/// Empty context provider
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct NullContextProvider;

impl ContextProvider for NullContextProvider {
    fn get_context(&self, _prog_type: u32) -> Option<&super::context::ContextDef> {
        None
    }

    fn iter(&self) -> impl Iterator<Item = &super::context::ContextDef> {
        core::iter::empty()
    }
}

impl PlatformSpec for NullPlatform {
    type Helper = NullHelperProvider;
    type ProgType = NullProgTypeProvider;
    type Kfunc = NullKfuncProvider;
    type Map = NullMapProvider;
    type Context = NullContextProvider;

    fn helper(&self) -> &Self::Helper {
        static INSTANCE: NullHelperProvider = NullHelperProvider;
        &INSTANCE
    }

    fn prog_type(&self) -> &Self::ProgType {
        static INSTANCE: NullProgTypeProvider = NullProgTypeProvider;
        &INSTANCE
    }

    fn kfunc(&self) -> &Self::Kfunc {
        static INSTANCE: NullKfuncProvider = NullKfuncProvider;
        &INSTANCE
    }

    fn map(&self) -> &Self::Map {
        static INSTANCE: NullMapProvider = NullMapProvider;
        &INSTANCE
    }

    fn context(&self) -> &Self::Context {
        static INSTANCE: NullContextProvider = NullContextProvider;
        &INSTANCE
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_platform() {
        let platform = NullPlatform;
        
        assert_eq!(platform.name(), "null");
        assert!(platform.lookup_helper(1).is_none());
        assert!(!platform.is_prog_type_valid(1));
        assert!(platform.lookup_kfunc(1).is_none());
        assert!(platform.get_map_info(1).is_none());
        assert_eq!(platform.ctx_size(1), 0);
    }
}
