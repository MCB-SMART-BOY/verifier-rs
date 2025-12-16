// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::btf::btf

use bpf_verifier::btf::btf::*;

use super::*;

    #[test]
    fn test_btf_new() {
        let btf = Btf::new();
        assert!(btf.get_type(0).is_some()); // void type
    }

    // ========================================================================
    // DeclTag Permission Tests
    // ========================================================================

    #[test]
    fn test_decl_tag_permissions() {
        let mut store = DeclTagStore::new();
        
        // Add type-level rdonly tag
        store.add_tag(DeclTagInfo {
            target_type_id: 1,
            component_idx: -1,
            tag: decl_tags::BTF_RDONLY.to_string(),
        });
        
        // Add member-level rcu tag
        store.add_tag(DeclTagInfo {
            target_type_id: 2,
            component_idx: 0,
            tag: decl_tags::BTF_RCU.to_string(),
        });
        
        let type_perms = store.get_type_permissions(1);
        assert!(type_perms.rdonly);
        assert!(!type_perms.rcu);
        
        let member_perms = store.get_member_permissions(2, 0);
        assert!(member_perms.rcu);
        assert!(!member_perms.rdonly);
        
        assert!(store.type_has_tag(1, decl_tags::BTF_RDONLY));
        assert!(!store.type_has_tag(1, decl_tags::BTF_RCU));
        assert!(store.member_has_tag(2, 0, decl_tags::BTF_RCU));
    }

    #[test]
    fn test_permissions_merge() {
        let mut perms = BtfPermissions::default();
        assert!(!perms.rdonly);
        assert!(!perms.trusted);
        
        let rdonly_perms = BtfPermissions::from_tag(decl_tags::BTF_RDONLY);
        perms.merge(&rdonly_perms);
        assert!(perms.rdonly);
        
        let trusted_perms = BtfPermissions::from_tag(decl_tags::BTF_TRUSTED);
        perms.merge(&trusted_perms);
        assert!(perms.rdonly);
        assert!(perms.trusted);
    }

    // ========================================================================
    // Union Variant Tracking Tests
    // ========================================================================

    #[test]
    fn test_union_variant_tracking() {
        let mut tracker = UnionAccessTracker::new();
        
        // First access sets the variant
        assert!(tracker.record_access(1, 0, 0, 4, 100).is_ok());
        
        let state = tracker.get_state(1, 0).unwrap();
        assert!(state.is_known());
        assert_eq!(state.active_variant, 0);
        
        // Same variant access is ok
        assert!(tracker.record_access(1, 0, 0, 4, 100).is_ok());
        
        // Different variant access is an error
        let result = tracker.record_access(1, 0, 1, 8, 101);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("variant mismatch"));
    }

    #[test]
    fn test_union_variant_clear() {
        let mut tracker = UnionAccessTracker::new();
        
        tracker.record_access(1, 0, 0, 4, 100).unwrap();
        tracker.record_access(1, 8, 1, 4, 101).unwrap();
        tracker.record_access(2, 0, 0, 4, 200).unwrap();
        
        // Clear ptr 1
        tracker.clear_ptr(1);
        
        assert!(tracker.get_state(1, 0).is_none());
        assert!(tracker.get_state(1, 8).is_none());
        assert!(tracker.get_state(2, 0).is_some());
    }

    // ========================================================================
    // Nested Access Validation Tests
    // ========================================================================

    fn create_nested_struct_btf() -> Btf {
        let mut btf = Btf::new();
        
        // Add u32 type
        let u32_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u32".into()),
            size: 4,
            int_encoding: Some(BtfIntEncoding {
                encoding: 0,
                offset: 0,
                bits: 32,
            }),
            ..Default::default()
        });
        
        // Add u64 type
        let u64_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u64".into()),
            size: 8,
            int_encoding: Some(BtfIntEncoding {
                encoding: 0,
                offset: 0,
                bits: 64,
            }),
            ..Default::default()
        });
        
        // Add inner struct
        let inner_id = btf.add_type(BtfType {
            kind: BtfKind::Struct,
            name: Some("inner".into()),
            size: 8,
            members: vec![
                BtfMember {
                    name: Some("x".into()),
                    type_id: u32_id,
                    offset: 0,
                },
                BtfMember {
                    name: Some("y".into()),
                    type_id: u32_id,
                    offset: 32,
                },
            ],
            ..Default::default()
        });
        
        // Add outer struct with nested inner
        let _outer_id = btf.add_type(BtfType {
            kind: BtfKind::Struct,
            name: Some("outer".into()),
            size: 16,
            members: vec![
                BtfMember {
                    name: Some("a".into()),
                    type_id: u32_id,
                    offset: 0,
                },
                BtfMember {
                    name: Some("nested".into()),
                    type_id: inner_id,
                    offset: 32,
                },
                BtfMember {
                    name: Some("b".into()),
                    type_id: u32_id,
                    offset: 96,
                },
            ],
            ..Default::default()
        });
        
        // Add union type
        let _union_id = btf.add_type(BtfType {
            kind: BtfKind::Union,
            name: Some("data_union".into()),
            size: 8,
            members: vec![
                BtfMember {
                    name: Some("i".into()),
                    type_id: u32_id,
                    offset: 0,
                },
                BtfMember {
                    name: Some("l".into()),
                    type_id: u64_id,
                    offset: 0,
                },
            ],
            ..Default::default()
        });
        
        btf
    }

    #[test]
    fn test_nested_access_by_offset() {
        let btf = create_nested_struct_btf();
        let outer_id = btf.find_by_name("outer")[0];
        
        let validator = NestedAccessValidator::new(&btf);
        
        // Access outer.a at offset 0
        let result = validator.validate_access_at_offset(outer_id, 0, 4, false);
        assert!(result.valid);
        assert_eq!(result.path, vec!["a"]);
        
        // Access outer.nested.x at offset 4
        let result = validator.validate_access_at_offset(outer_id, 4, 4, false);
        assert!(result.valid);
        assert_eq!(result.path, vec!["nested", "x"]);
        
        // Access outer.nested.y at offset 8
        let result = validator.validate_access_at_offset(outer_id, 8, 4, false);
        assert!(result.valid);
        assert_eq!(result.path, vec!["nested", "y"]);
        
        // Access outer.b at offset 12
        let result = validator.validate_access_at_offset(outer_id, 12, 4, false);
        assert!(result.valid);
        assert_eq!(result.path, vec!["b"]);
        
        // Out of bounds access
        let result = validator.validate_access_at_offset(outer_id, 14, 4, false);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("exceeds"));
    }

    #[test]
    fn test_nested_access_by_path() {
        let btf = create_nested_struct_btf();
        let outer_id = btf.find_by_name("outer")[0];
        
        let validator = NestedAccessValidator::new(&btf);
        
        // Access outer.nested.x
        let result = validator.validate_access_path(outer_id, &["nested", "x"], 4, false);
        assert!(result.valid);
        assert_eq!(result.total_offset, 4);
        
        // Access outer.nested.y
        let result = validator.validate_access_path(outer_id, &["nested", "y"], 4, false);
        assert!(result.valid);
        assert_eq!(result.total_offset, 8);
        
        // Invalid field name
        let result = validator.validate_access_path(outer_id, &["nested", "z"], 4, false);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_union_access_detection() {
        let btf = create_nested_struct_btf();
        let union_id = btf.find_by_name("data_union")[0];
        
        let validator = NestedAccessValidator::new(&btf);
        
        // Access union.i
        let result = validator.validate_access_path(union_id, &["i"], 4, false);
        assert!(result.valid);
        assert!(result.contains_union);
        assert_eq!(result.union_variant, Some((0, btf.find_by_name("u32")[0])));
        
        // Access union.l
        let result = validator.validate_access_path(union_id, &["l"], 8, false);
        assert!(result.valid);
        assert!(result.contains_union);
        assert_eq!(result.union_variant.unwrap().0, 1);
    }

    #[test]
    fn test_rdonly_permission_check() {
        let btf = create_nested_struct_btf();
        let outer_id = btf.find_by_name("outer")[0];
        
        let mut tags = DeclTagStore::new();
        // Mark outer.a as rdonly
        tags.add_tag(DeclTagInfo {
            target_type_id: outer_id,
            component_idx: 0, // First member
            tag: decl_tags::BTF_RDONLY.to_string(),
        });
        
        let validator = NestedAccessValidator::new(&btf).with_decl_tags(&tags);
        
        // Read access should succeed
        let result = validator.validate_access_path(outer_id, &["a"], 4, false);
        assert!(result.valid);
        assert!(result.permissions.rdonly);
        
        // Write access should fail
        let result = validator.validate_access_path(outer_id, &["a"], 4, true);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("read-only"));
    }

    #[test]
    fn test_add_int_type() {
        let mut btf = Btf::new();
        btf.add_kernel_types();
        
        let ids = btf.find_by_name("u32");
        assert!(!ids.is_empty());
        
        let ty = btf.get_type(ids[0]).unwrap();
        assert_eq!(ty.kind, BtfKind::Int);
        assert_eq!(ty.size, 4);
    }

    #[test]
    fn test_add_struct() {
        let mut btf = Btf::new();
        
        let u32_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u32".into()),
            size: 4,
            ..Default::default()
        });
        
        let struct_id = btf.add_type(BtfType {
            kind: BtfKind::Struct,
            name: Some("my_struct".into()),
            size: 8,
            members: vec![
                BtfMember {
                    name: Some("field_a".into()),
                    type_id: u32_id,
                    offset: 0,
                },
                BtfMember {
                    name: Some("field_b".into()),
                    type_id: u32_id,
                    offset: 32, // bits
                },
            ],
            ..Default::default()
        });
        
        assert!(btf.is_struct(struct_id));
        
        let member = btf.find_member(struct_id, "field_a");
        assert!(member.is_some());
        assert_eq!(member.unwrap().offset, 0);
    }

    #[test]
    fn test_ptr_type() {
        let mut btf = Btf::new();
        
        let int_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("int".into()),
            size: 4,
            ..Default::default()
        });
        
        let ptr_id = btf.add_type(BtfType {
            kind: BtfKind::Ptr,
            type_ref: int_id,
            ..Default::default()
        });
        
        assert!(btf.is_ptr(ptr_id));
        assert_eq!(btf.ptr_target(ptr_id), Some(int_id));
        assert_eq!(btf.type_size(ptr_id), Some(8));
    }

    #[test]
    fn test_check_btf_access() {
        let mut btf = Btf::new();
        
        let u32_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u32".into()),
            size: 4,
            ..Default::default()
        });
        
        let struct_id = btf.add_type(BtfType {
            kind: BtfKind::Struct,
            name: Some("test".into()),
            size: 8,
            members: vec![
                BtfMember {
                    name: Some("a".into()),
                    type_id: u32_id,
                    offset: 0,
                },
                BtfMember {
                    name: Some("b".into()),
                    type_id: u32_id,
                    offset: 32,
                },
            ],
            ..Default::default()
        });
        
        // Valid access
        let access = check_btf_access(&btf, struct_id, 0, 4);
        assert!(access.is_some());
        
        // Out of bounds
        let access = check_btf_access(&btf, struct_id, 0, 16);
        assert!(access.is_none());
        
        // Negative offset
        let access = check_btf_access(&btf, struct_id, -1, 4);
        assert!(access.is_none());
    }

    // ========================================================================
    // BTF String Table Tests
    // ========================================================================

    #[test]
    fn test_string_table_new() {
        let table = BtfStringTable::new();
        
        // New table should have empty string at offset 0
        assert_eq!(table.get(0), Some(""));
        assert_eq!(table.len(), 1); // Just the null terminator
        assert!(table.is_empty()); // Only empty string
    }

    #[test]
    fn test_string_table_add_and_get() {
        let mut table = BtfStringTable::new();
        
        // Add first string
        let offset1 = table.add("hello");
        assert_eq!(offset1, 1); // After initial null byte
        assert_eq!(table.get(offset1), Some("hello"));
        
        // Add second string
        let offset2 = table.add("world");
        assert_eq!(offset2, 7); // 1 + 5 ("hello") + 1 (null)
        assert_eq!(table.get(offset2), Some("world"));
        
        // Verify both strings are still accessible
        assert_eq!(table.get(offset1), Some("hello"));
        assert_eq!(table.get(offset2), Some("world"));
    }

    #[test]
    fn test_string_table_deduplication() {
        let mut table = BtfStringTable::new();
        
        let offset1 = table.add("duplicate");
        let offset2 = table.add("duplicate");
        
        // Same string should return same offset
        assert_eq!(offset1, offset2);
        
        // Table should only have one copy
        let expected_len = 1 + 9 + 1; // null + "duplicate" + null
        assert_eq!(table.len(), expected_len);
    }

    #[test]
    fn test_string_table_empty_string() {
        let mut table = BtfStringTable::new();
        
        // Empty string should return offset 0 (initial empty string)
        let offset = table.add("");
        assert_eq!(offset, 0);
        assert_eq!(table.get(0), Some(""));
    }

    #[test]
    fn test_string_table_invalid_offset() {
        let table = BtfStringTable::new();
        
        // Invalid offset should return None
        assert_eq!(table.get(100), None);
        assert_eq!(table.get(u32::MAX), None);
    }

    #[test]
    fn test_string_table_as_bytes() {
        let mut table = BtfStringTable::new();
        table.add("test");
        
        let bytes = table.as_bytes();
        
        // Should be: \0 t e s t \0
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..5], b"test");
        assert_eq!(bytes[5], 0);
    }

    #[test]
    fn test_string_table_from_bytes() {
        // Create raw string table data
        let data = vec![
            0,                          // Empty string at offset 0
            b'h', b'e', b'l', b'l', b'o', 0,  // "hello" at offset 1
            b'w', b'o', b'r', b'l', b'd', 0,  // "world" at offset 7
        ];
        
        let table = BtfStringTable::from_bytes(data);
        
        assert_eq!(table.get(0), Some(""));
        assert_eq!(table.get(1), Some("hello"));
        assert_eq!(table.get(7), Some("world"));
    }

    #[test]
    fn test_string_table_roundtrip() {
        let mut original = BtfStringTable::new();
        original.add("first");
        original.add("second");
        original.add("third");
        
        // Serialize and deserialize
        let bytes = original.as_bytes().to_vec();
        let restored = BtfStringTable::from_bytes(bytes);
        
        // Verify all strings are preserved
        assert_eq!(restored.get(0), Some(""));
        assert_eq!(original.get(1), restored.get(1));
        assert_eq!(original.get(7), restored.get(7));
        assert_eq!(original.get(14), restored.get(14));
    }

    #[test]
    fn test_btf_string_table_integration() {
        let mut btf = Btf::new();
        
        // Add strings via Btf API
        let offset1 = btf.add_string("my_type");
        let offset2 = btf.add_string("my_field");
        
        // Retrieve strings
        assert_eq!(btf.get_string(offset1), Some("my_type"));
        assert_eq!(btf.get_string(offset2), Some("my_field"));
        
        // Deduplication works through Btf API
        let offset3 = btf.add_string("my_type");
        assert_eq!(offset1, offset3);
    }

    #[test]
    fn test_string_table_special_chars() {
        let mut table = BtfStringTable::new();
        
        // Test with special characters
        let offset1 = table.add("struct.name");
        let offset2 = table.add("__my_func__");
        let offset3 = table.add("field_123");
        
        assert_eq!(table.get(offset1), Some("struct.name"));
        assert_eq!(table.get(offset2), Some("__my_func__"));
        assert_eq!(table.get(offset3), Some("field_123"));
    }

    #[test]
    fn test_string_table_unicode() {
        let mut table = BtfStringTable::new();
        
        // BTF typically uses ASCII, but UTF-8 should work
        let offset = table.add("тест"); // Russian "test"
        assert_eq!(table.get(offset), Some("тест"));
    }
