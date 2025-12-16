// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::kfunc

use bpf_verifier::prelude::*;
use bpf_verifier::check::kfunc::*;

    use bpf_verifier::state::reg_state::BpfRegState;
    use bpf_verifier::btf::database::{Btf, BtfType, BtfKind};

    #[test]
    fn test_kfunc_registry() {
        let mut registry = KfuncRegistry::new();
        
        registry.register(KfuncDesc {
            btf_id: 100,
            name: "test_kfunc".into(),
            ..Default::default()
        }).unwrap();

        assert!(registry.contains(100));
        assert!(!registry.contains(101));
        
        let desc = registry.find_by_id(100).unwrap();
        assert_eq!(desc.name, "test_kfunc");
        
        let desc2 = registry.find_by_name("test_kfunc").unwrap();
        assert_eq!(desc2.btf_id, 100);
    }

    #[test]
    fn test_register_common() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        assert!(registry.find_by_name("bpf_rcu_read_lock").is_some());
        assert!(registry.find_by_name("bpf_obj_new_impl").is_some());
    }

    #[test]
    fn test_kfunc_flags() {
        let flags = KfuncFlags {
            is_acquire: true,
            ret_null: true,
            ..Default::default()
        };
        
        assert!(flags.is_acquire);
        assert!(flags.ret_null);
        assert!(!flags.is_release);
    }

    #[test]
    fn test_is_kfunc_call() {
        let kfunc_call = BpfInsn::new(
            BPF_JMP | BPF_CALL,
            0,
            BPF_PSEUDO_KFUNC_CALL,
            0,
            100,
        );
        assert!(is_kfunc_call(&kfunc_call));

        let helper_call = BpfInsn::new(
            BPF_JMP | BPF_CALL,
            0,
            0,
            0,
            1,
        );
        assert!(!is_kfunc_call(&helper_call));
    }

    #[test]
    fn test_special_kfuncs() {
        assert!(is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_LOCK));
        assert!(!is_kfunc_bpf_rcu_read_lock(special_kfuncs::BPF_RCU_READ_UNLOCK));
        
        assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_PUSH_FRONT));
        assert!(is_bpf_list_api_kfunc(special_kfuncs::BPF_LIST_POP_BACK));
        assert!(!is_bpf_list_api_kfunc(special_kfuncs::BPF_OBJ_NEW));
    }

    #[test]
    fn test_kfunc_arg_desc() {
        let desc = KfuncArgDesc {
            arg_type: KfuncArgType::PtrToBtfId,
            btf_id: Some(42),
            nullable: true,
            ..Default::default()
        };
        
        assert_eq!(desc.arg_type, KfuncArgType::PtrToBtfId);
        assert_eq!(desc.btf_id, Some(42));
        assert!(desc.nullable);
        assert!(!desc.is_release);
    }

    #[test]
    fn test_check_kfunc_arg_btf_type_scalar() {
        let btf = Btf::new();
        
        // Scalar register
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        
        let expected = KfuncArgDesc {
            arg_type: KfuncArgType::Scalar,
            ..Default::default()
        };
        
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_ok());
        
        // Wrong type
        reg.reg_type = BpfRegType::PtrToStack;
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_err());
    }

    #[test]
    fn test_check_kfunc_arg_btf_type_ptr() {
        let btf = Btf::new();
        
        // Pointer register
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMem;
        
        let expected = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            ..Default::default()
        };
        
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_ok());
        
        // Scalar is not a pointer
        reg.reg_type = BpfRegType::ScalarValue;
        assert!(check_kfunc_arg_btf_type(&reg, &expected, &btf).is_err());
    }

    #[test]
    fn test_check_kfunc_arg_nullable() {
        let btf = Btf::new();
        
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMem;
        reg.type_flags = BpfTypeFlag::PTR_MAYBE_NULL;
        
        // Non-nullable expected
        let non_nullable = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            nullable: false,
            ..Default::default()
        };
        assert!(check_kfunc_arg_btf_type(&reg, &non_nullable, &btf).is_err());
        
        // Nullable expected
        let nullable = KfuncArgDesc {
            arg_type: KfuncArgType::AnyPtr,
            nullable: true,
            ..Default::default()
        };
        assert!(check_kfunc_arg_btf_type(&reg, &nullable, &btf).is_ok());
    }

    #[test]
    fn test_btf_types_compatible() {
        let mut btf = Btf::new();
        
        let u32_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u32".into()),
            size: 4,
            ..Default::default()
        });
        
        let int_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("int".into()),
            size: 4,
            ..Default::default()
        });
        
        let u64_id = btf.add_type(BtfType {
            kind: BtfKind::Int,
            name: Some("u64".into()),
            size: 8,
            ..Default::default()
        });
        
        // Same type
        assert!(btf_types_compatible(&btf, u32_id, u32_id));
        
        // Compatible (same kind, same size)
        assert!(btf_types_compatible(&btf, u32_id, int_id));
        
        // Incompatible (different size)
        assert!(!btf_types_compatible(&btf, u32_id, u64_id));
    }

    #[test]
    fn test_is_release_arg() {
        let release_desc = KfuncDesc {
            btf_id: 100,
            name: "test_release".into(),
            flags: KfuncFlags {
                is_release: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(is_release_arg(&release_desc, 0)); // First arg
        assert!(!is_release_arg(&release_desc, 1)); // Second arg
        
        let acquire_desc = KfuncDesc {
            btf_id: 101,
            name: "test_acquire".into(),
            flags: KfuncFlags {
                is_acquire: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(!is_release_arg(&acquire_desc, 0));
    }

    #[test]
    fn test_percpu_obj_new_registered() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        // Check percpu_obj_new_impl is registered
        let desc = registry.find_by_name("bpf_percpu_obj_new_impl");
        assert!(desc.is_some());
        let desc = desc.unwrap();
        assert!(desc.flags.is_acquire);
        assert!(desc.flags.ret_null);
        assert_eq!(desc.params.len(), 2);
        
        // Check percpu_obj_drop_impl is registered
        let drop_desc = registry.find_by_name("bpf_percpu_obj_drop_impl");
        assert!(drop_desc.is_some());
        let drop_desc = drop_desc.unwrap();
        assert!(drop_desc.flags.is_release);
    }

    #[test]
    fn test_validate_percpu_obj_size() {
        // Valid size (within limit)
        assert!(validate_percpu_obj_size(256, "small_struct").is_ok());
        assert!(validate_percpu_obj_size(512, "max_struct").is_ok());
        
        // Invalid size (exceeds limit)
        let result = validate_percpu_obj_size(513, "too_large_struct");
        assert!(result.is_err());
        
        let result = validate_percpu_obj_size(1024, "very_large_struct");
        assert!(result.is_err());
    }

    #[test]
    fn test_percpu_obj_new_params() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        let desc = registry.find_by_name("bpf_percpu_obj_new_impl").unwrap();
        
        // Verify parameter types
        assert_eq!(desc.params[0].arg_type, KfuncArgType::Scalar); // local_type_id
        assert_eq!(desc.params[1].arg_type, KfuncArgType::Scalar); // meta (must be NULL)
        
        // Return type should be acquired pointer
        assert_eq!(desc.ret_type, KfuncRetType::AcquiredPtr);
    }

    #[test]
    fn test_percpu_obj_drop_params() {
        let mut registry = KfuncRegistry::new();
        registry.register_common();
        
        let desc = registry.find_by_name("bpf_percpu_obj_drop_impl").unwrap();
        
        // Verify parameter types
        assert_eq!(desc.params[0].arg_type, KfuncArgType::PtrToAlloc); // p
        assert!(desc.params[0].is_release); // First arg is released
        assert_eq!(desc.params[1].arg_type, KfuncArgType::Scalar); // meta
        
        // Return type should be void
        assert_eq!(desc.ret_type, KfuncRetType::Void);
    }
