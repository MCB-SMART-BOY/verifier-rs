// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::btf::core

use bpf_verifier::prelude::*;
use bpf_verifier::btf::core::*;


    #[test]
    fn test_core_relo_kind_conversion() {
        assert_eq!(
            BpfCoreReloKind::try_from(0),
            Ok(BpfCoreReloKind::FieldByteOffset)
        );
        assert_eq!(
            BpfCoreReloKind::try_from(8),
            Ok(BpfCoreReloKind::TypeExists)
        );
        assert!(BpfCoreReloKind::try_from(100).is_err());
    }

    #[test]
    fn test_core_relo_result_default() {
        let result = CoreReloResult::default();
        assert!(!result.success);
        assert!(!result.exists);
        assert_eq!(result.new_val, 0);
    }

    #[test]
    fn test_core_relo_stats() {
        let mut stats = CoreReloStats::default();
        assert!(stats.all_succeeded());

        stats.succeeded = 5;
        assert!(stats.all_succeeded());

        stats.failed = 1;
        assert!(!stats.all_succeeded());
    }

    #[test]
    fn test_type_exists_relo() {
        let mut local_btf = Btf::new();
        local_btf.add_kernel_types();

        let target_btf = Btf::new();

        let mut ctx = CoreReloContext::new(&local_btf, &target_btf);

        // Type that exists in local but might not in target
        let result = ctx.relo_type_exists(1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_core_access_component() {
        let field = CoreAccessComponent::Field {
            index: 0,
            name: Some("test_field".into()),
        };
        
        match field {
            CoreAccessComponent::Field { index, name } => {
                assert_eq!(index, 0);
                assert_eq!(name, Some("test_field".into()));
            }
            _ => panic!("Expected field component"),
        }

        let array = CoreAccessComponent::Array { index: 5 };
        match array {
            CoreAccessComponent::Array { index } => {
                assert_eq!(index, 5);
            }
            _ => panic!("Expected array component"),
        }
    }

    #[test]
    fn test_core_access_spec() {
        let spec = CoreAccessSpec {
            type_id: 42,
            access: vec![
                CoreAccessComponent::Field {
                    index: 0,
                    name: Some("first".into()),
                },
                CoreAccessComponent::Field {
                    index: 1,
                    name: Some("second".into()),
                },
            ],
            bit_offset: 64,
        };

        assert_eq!(spec.type_id, 42);
        assert_eq!(spec.access.len(), 2);
        assert_eq!(spec.bit_offset, 64);
    }

    #[test]
    fn test_field_exists_no_target() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let ctx = CoreReloContext::new(&local_btf, &target_btf);

        let spec = CoreAccessSpec {
            type_id: 1,
            access: vec![],
            bit_offset: 0,
        };

        // No target type - should return exists: false
        let result = ctx.relo_field_exists(&spec, None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.success);
        assert!(!result.exists);
        assert_eq!(result.new_val, 0);
    }

    #[test]
    fn test_type_size_no_target() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let mut ctx = CoreReloContext::new(&local_btf, &target_btf);

        // Non-existent type
        let result = ctx.relo_type_size(9999);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success);
        assert!(!result.exists);
    }

    #[test]
    fn test_bitfield_lshift_no_target() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let ctx = CoreReloContext::new(&local_btf, &target_btf);

        let spec = CoreAccessSpec {
            type_id: 1,
            access: vec![],
            bit_offset: 0,
        };

        // No target type - should fail
        let result = ctx.relo_field_lshift(&spec, None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_bitfield_rshift_no_target() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let ctx = CoreReloContext::new(&local_btf, &target_btf);

        let spec = CoreAccessSpec {
            type_id: 1,
            access: vec![],
            bit_offset: 0,
        };

        // No target type - should fail
        let result = ctx.relo_field_rshift(&spec, None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_enumval_exists_not_enum() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let ctx = CoreReloContext::new(&local_btf, &target_btf);

        let spec = CoreAccessSpec {
            type_id: 1,
            access: vec![],
            bit_offset: 0,
        };

        // Type ID 1 is not an enum in empty BTF
        let result = ctx.relo_enumval_exists(&spec, Some(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_type_matches_no_target() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();

        let mut ctx = CoreReloContext::new(&local_btf, &target_btf);

        let result = ctx.relo_type_matches(1, None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.success);
        assert!(!result.exists);
        assert_eq!(result.new_val, 0);
    }

    #[test]
    fn test_apply_core_relos_empty() {
        let local_btf = Btf::new();
        let target_btf = Btf::new();
        let mut insns = vec![];
        let relos = vec![];

        let result = apply_core_relos(&mut insns, &relos, &local_btf, &target_btf);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert!(stats.all_succeeded());
        assert_eq!(stats.succeeded, 0);
        assert_eq!(stats.failed, 0);
    }
