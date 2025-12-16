// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::btf::validation

use bpf_verifier::btf::validation::*;

use super::*;

    #[test]
    fn test_btf_kind_from_u32() {
        assert_eq!(BtfKind::from(1), BtfKind::Int);
        assert_eq!(BtfKind::from(4), BtfKind::Struct);
        assert_eq!(BtfKind::from(13), BtfKind::FuncProto);
        assert_eq!(BtfKind::from(100), BtfKind::Unknown);
    }

    #[test]
    fn test_btf_int_encoding() {
        let enc = BtfIntEncoding::from_raw(0x20000001);
        assert!(enc.is_signed);
        assert!(!enc.is_char);
        assert!(!enc.is_bool);
        assert_eq!(enc.offset, 0);
        assert_eq!(enc.bits, 32);
    }

    #[test]
    fn test_btf_types_basic() {
        let mut types = BtfTypes::new();
        assert_eq!(types.len(), 1); // void

        let id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });
        assert_eq!(id, 1);
        assert_eq!(types.len(), 2);

        let ty = types.get(1).unwrap();
        assert_eq!(ty.kind(), BtfKind::Int);
        assert_eq!(ty.name(), Some("int"));
    }

    #[test]
    fn test_btf_type_size() {
        let types = create_kernel_btf();
        
        // Check integer sizes
        let int_ids = types.get_by_name("int");
        assert!(!int_ids.is_empty());
        assert_eq!(types.type_size(int_ids[0]), Some(4));

        let u64_ids = types.get_by_name("u64");
        assert!(!u64_ids.is_empty());
        assert_eq!(types.type_size(u64_ids[0]), Some(8));
    }

    #[test]
    fn test_btf_struct() {
        let mut types = BtfTypes::new();
        
        // Add u32 type
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        // Add struct
        let _struct_id = types.add_type(BtfType::Struct {
            name: "test_struct".to_string(),
            size: 12,
            members: vec![
                BtfMember {
                    name: "a".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "b".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
                BtfMember {
                    name: "c".to_string(),
                    type_id: u32_id,
                    offset: 8,
                    bitfield: false,
                },
            ],
        });

        let struct_ids = types.get_by_name("test_struct");
        assert_eq!(struct_ids.len(), 1);
        assert_eq!(types.type_size(struct_ids[0]), Some(12));
    }

    #[test]
    fn test_btf_find_member() {
        let mut types = BtfTypes::new();
        
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let struct_id = types.add_type(BtfType::Struct {
            name: "point".to_string(),
            size: 8,
            members: vec![
                BtfMember {
                    name: "x".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "y".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
            ],
        });

        let (offset, type_id) = types.find_member(struct_id, "x").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(type_id, u32_id);

        let (offset, type_id) = types.find_member(struct_id, "y").unwrap();
        assert_eq!(offset, 4);
        assert_eq!(type_id, u32_id);

        assert!(types.find_member(struct_id, "z").is_none());
    }

    #[test]
    fn test_btf_resolve_type() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let typedef_id = types.add_type(BtfType::Typedef {
            name: "my_int".to_string(),
            target: int_id,
        });

        let const_id = types.add_type(BtfType::Const { target: typedef_id });

        // Resolve through const -> typedef -> int
        assert_eq!(types.resolve_type(const_id), int_id);
        assert_eq!(types.resolve_type(typedef_id), int_id);
        assert_eq!(types.resolve_type(int_id), int_id);
    }

    #[test]
    fn test_btf_validator_access() {
        let mut types = BtfTypes::new();
        
        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let struct_id = types.add_type(BtfType::Struct {
            name: "test".to_string(),
            size: 8,
            members: vec![
                BtfMember {
                    name: "a".to_string(),
                    type_id: u32_id,
                    offset: 0,
                    bitfield: false,
                },
                BtfMember {
                    name: "b".to_string(),
                    type_id: u32_id,
                    offset: 4,
                    bitfield: false,
                },
            ],
        });

        let mut validator = BtfValidator::new(types);

        // Valid access to field a
        let info = validator.validate_access(struct_id, 0, 4, false).unwrap();
        assert_eq!(info.field_type, u32_id);
        assert_eq!(info.field_offset, 0);

        // Valid access to field b
        let info = validator.validate_access(struct_id, 4, 4, false).unwrap();
        assert_eq!(info.field_type, u32_id);
        assert_eq!(info.field_offset, 0);

        // Out of bounds access
        assert!(validator.validate_access(struct_id, 8, 4, false).is_err());
    }

    #[test]
    fn test_btf_types_compatible() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let s32_id = types.add_type(BtfType::Int {
            name: "s32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let u32_id = types.add_type(BtfType::Int {
            name: "u32".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: false,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let validator = BtfValidator::new(types);

        // Same type
        assert!(validator.types_compatible(int_id, int_id));

        // Same size and signedness
        assert!(validator.types_compatible(int_id, s32_id));

        // Different signedness
        assert!(!validator.types_compatible(int_id, u32_id));
    }

    #[test]
    fn test_btf_func_proto() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let proto_id = types.add_type(BtfType::FuncProto {
            ret_type: int_id,
            params: vec![
                BtfParam {
                    name: "a".to_string(),
                    type_id: int_id,
                },
                BtfParam {
                    name: "b".to_string(),
                    type_id: int_id,
                },
            ],
        });

        let func_id = types.add_type(BtfType::Func {
            name: "add".to_string(),
            proto: proto_id,
            linkage: 0,
        });

        let validator = BtfValidator::new(types);

        let arg_types = validator.get_func_arg_types(func_id);
        assert_eq!(arg_types.len(), 2);
        assert_eq!(arg_types[0], int_id);
        assert_eq!(arg_types[1], int_id);

        let ret_type = validator.get_func_return_type(func_id);
        assert_eq!(ret_type, Some(int_id));
    }

    #[test]
    fn test_btf_pointer_types() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let ptr_id = types.add_type(BtfType::Ptr { target: int_id });
        let void_ptr_id = types.add_type(BtfType::Ptr { target: 0 }); // void*

        assert!(types.is_pointer(ptr_id));
        assert!(types.is_integer(int_id));
        assert!(!types.is_pointer(int_id));

        assert_eq!(types.ptr_target(ptr_id), Some(int_id));
        assert_eq!(types.ptr_target(void_ptr_id), Some(0));

        // Pointer size is 8 bytes (64-bit)
        assert_eq!(types.type_size(ptr_id), Some(8));
    }

    #[test]
    fn test_btf_array_access() {
        let mut types = BtfTypes::new();
        
        let int_id = types.add_type(BtfType::Int {
            name: "int".to_string(),
            size: 4,
            encoding: BtfIntEncoding {
                is_signed: true,
                is_char: false,
                is_bool: false,
                offset: 0,
                bits: 32,
            },
        });

        let arr_id = types.add_type(BtfType::Array(BtfArray {
            elem_type: int_id,
            index_type: int_id,
            nelems: 10,
        }));

        assert_eq!(types.type_size(arr_id), Some(40)); // 10 * 4 bytes

        let mut validator = BtfValidator::new(types);

        // Valid access
        let info = validator.validate_access(arr_id, 0, 4, false).unwrap();
        assert_eq!(info.field_type, int_id);

        // Access at element 5
        let info = validator.validate_access(arr_id, 20, 4, false).unwrap();
        assert_eq!(info.field_type, int_id);

        // Out of bounds
        assert!(validator.validate_access(arr_id, 40, 4, false).is_err());
    }

    #[test]
    fn test_create_kernel_btf() {
        let types = create_kernel_btf();
        
        // Should have common types
        assert!(!types.get_by_name("int").is_empty());
        assert!(!types.get_by_name("u32").is_empty());
        assert!(!types.get_by_name("u64").is_empty());
        assert!(!types.get_by_name("s32").is_empty());
        assert!(!types.get_by_name("char").is_empty());
        assert!(!types.get_by_name("_Bool").is_empty());
    }

    #[test]
    fn test_btf_validator_empty() {
        let mut validator = BtfValidator::empty();

        // Empty validator should allow all accesses
        let info = validator.validate_access(999, 100, 8, true).unwrap();
        assert_eq!(info.field_offset, 100);
    }

    // ========================================================================
    // Enum64 Tests
    // ========================================================================

    #[test]
    fn test_btf_enum64_basic() {
        let mut types = BtfTypes::new();

        // Add a 64-bit enum with large values
        let enum_id = types.add_type(BtfType::Enum64 {
            name: "large_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "VAL_MIN".to_string(),
                    val: i64::MIN,
                },
                BtfEnum64Value {
                    name: "VAL_NEG".to_string(),
                    val: -0x100000000i64,
                },
                BtfEnum64Value {
                    name: "VAL_ZERO".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "VAL_LARGE".to_string(),
                    val: 0x123456789ABCDEFi64,
                },
                BtfEnum64Value {
                    name: "VAL_MAX".to_string(),
                    val: i64::MAX,
                },
            ],
            is_signed: true,
        });

        let ty = types.get(enum_id).unwrap();
        assert_eq!(ty.kind(), BtfKind::Enum64);
        assert_eq!(ty.name(), Some("large_enum"));
        assert_eq!(types.type_size(enum_id), Some(8));
    }

    #[test]
    fn test_btf_enum64_unsigned() {
        let mut types = BtfTypes::new();

        // Unsigned 64-bit enum
        let enum_id = types.add_type(BtfType::Enum64 {
            name: "flags64".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "FLAG_NONE".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "FLAG_HIGH".to_string(),
                    val: 0x8000000000000000u64 as i64, // High bit set
                },
                BtfEnum64Value {
                    name: "FLAG_ALL".to_string(),
                    val: -1i64, // All bits set (0xFFFFFFFFFFFFFFFF)
                },
            ],
            is_signed: false,
        });

        let ty = types.get(enum_id).unwrap();
        assert_eq!(ty.kind(), BtfKind::Enum64);
        
        if let BtfType::Enum64 { is_signed, .. } = ty {
            assert!(!is_signed);
        } else {
            panic!("Expected Enum64 type");
        }
    }

    #[test]
    fn test_btf_enum64_kind_conversion() {
        // Test that kind 19 maps to Enum64
        assert_eq!(BtfKind::from(19), BtfKind::Enum64);
    }

    #[test]
    fn test_btf_enum_vs_enum64_size() {
        let mut types = BtfTypes::new();

        // 32-bit enum
        let enum32_id = types.add_type(BtfType::Enum {
            name: "small_enum".to_string(),
            size: 4,
            values: vec![
                BtfEnumValue {
                    name: "A".to_string(),
                    val: 0,
                },
                BtfEnumValue {
                    name: "B".to_string(),
                    val: i32::MAX,
                },
            ],
            is_signed: true,
        });

        // 64-bit enum
        let enum64_id = types.add_type(BtfType::Enum64 {
            name: "big_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "X".to_string(),
                    val: 0,
                },
                BtfEnum64Value {
                    name: "Y".to_string(),
                    val: i64::MAX,
                },
            ],
            is_signed: true,
        });

        // Verify sizes
        assert_eq!(types.type_size(enum32_id), Some(4));
        assert_eq!(types.type_size(enum64_id), Some(8));

        // Verify kinds
        assert_eq!(types.get(enum32_id).unwrap().kind(), BtfKind::Enum);
        assert_eq!(types.get(enum64_id).unwrap().kind(), BtfKind::Enum64);
    }

    #[test]
    fn test_btf_enum64_compatibility() {
        let mut types = BtfTypes::new();

        // Two Enum64 types with same size should be compatible
        let enum1_id = types.add_type(BtfType::Enum64 {
            name: "enum_a".to_string(),
            size: 8,
            values: vec![BtfEnum64Value {
                name: "VAL".to_string(),
                val: 1,
            }],
            is_signed: true,
        });

        let enum2_id = types.add_type(BtfType::Enum64 {
            name: "enum_b".to_string(),
            size: 8,
            values: vec![BtfEnum64Value {
                name: "OTHER".to_string(),
                val: 2,
            }],
            is_signed: true,
        });

        // Both should have same size
        assert_eq!(types.type_size(enum1_id), types.type_size(enum2_id));
    }

    #[test]
    fn test_btf_enum64_value_lookup() {
        let mut types = BtfTypes::new();

        let enum_id = types.add_type(BtfType::Enum64 {
            name: "test_enum".to_string(),
            size: 8,
            values: vec![
                BtfEnum64Value {
                    name: "FIRST".to_string(),
                    val: 100,
                },
                BtfEnum64Value {
                    name: "SECOND".to_string(),
                    val: 0x100000000i64,
                },
                BtfEnum64Value {
                    name: "THIRD".to_string(),
                    val: -500,
                },
            ],
            is_signed: true,
        });

        let ty = types.get(enum_id).unwrap();
        if let BtfType::Enum64 { values, .. } = ty {
            assert_eq!(values.len(), 3);
            assert_eq!(values[0].name, "FIRST");
            assert_eq!(values[0].val, 100);
            assert_eq!(values[1].name, "SECOND");
            assert_eq!(values[1].val, 0x100000000i64);
            assert_eq!(values[2].name, "THIRD");
            assert_eq!(values[2].val, -500);
        } else {
            panic!("Expected Enum64 type");
        }
    }
