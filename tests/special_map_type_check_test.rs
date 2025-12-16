// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::map_type_check

use bpf_verifier::special::map_type_check::*;

use super::*;

    fn make_map_info(map_type: BpfMapType, key_size: u32, value_size: u32) -> MapInfo {
        MapInfo {
            map_type,
            key_size,
            value_size,
            max_entries: 100,
        }
    }

    #[test]
    fn test_map_op_signature_lookup() {
        let sig = MapOpSignature::lookup(64, 4);
        assert_eq!(sig.name, "map_lookup_elem");
        assert!(!sig.modifies_map);
        assert!(sig.can_return_null);
        assert!(matches!(sig.key_req, KeyTypeReq::PtrToKey(4)));
        assert!(matches!(sig.value_req, ValueTypeReq::PtrToValue(64)));
    }

    #[test]
    fn test_map_op_signature_update() {
        let sig = MapOpSignature::update(32, 8);
        assert_eq!(sig.name, "map_update_elem");
        assert!(sig.modifies_map);
        assert!(!sig.can_return_null);
    }

    #[test]
    fn test_map_type_checker_hash() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapLookupElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapUpdateElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapDeleteElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPushElem).is_err());
    }

    #[test]
    fn test_map_type_checker_array() {
        let info = make_map_info(BpfMapType::Array, 4, 64);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapLookupElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapUpdateElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapDeleteElem).is_err());
    }

    #[test]
    fn test_map_type_checker_stack() {
        let info = make_map_info(BpfMapType::Stack, 0, 16);
        let checker = MapTypeChecker::new(info);

        assert!(checker.check_operation(BpfFuncId::MapPushElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPopElem).is_ok());
        assert!(checker.check_operation(BpfFuncId::MapPeekElem).is_ok());
    }

    #[test]
    fn test_validate_key_ptr_to_stack() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);
        let sig = MapOpSignature::lookup(32, 4);

        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToStack;

        assert!(checker.validate_key(&reg, &sig).is_ok());
    }

    #[test]
    fn test_validate_key_wrong_type() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);
        let checker = MapTypeChecker::new(info);
        let sig = MapOpSignature::lookup(32, 4);

        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::NotInit;

        assert!(checker.validate_key(&reg, &sig).is_err());
    }

    #[test]
    fn test_map_types_compatible() {
        assert!(map_types_compatible(BpfMapType::Hash, BpfMapType::Hash));
        assert!(map_types_compatible(BpfMapType::Hash, BpfMapType::LruHash));
        assert!(map_types_compatible(BpfMapType::Array, BpfMapType::PercpuArray));
        assert!(!map_types_compatible(BpfMapType::Hash, BpfMapType::Array));
    }

    #[test]
    fn test_get_map_op_return_type() {
        let info = make_map_info(BpfMapType::Hash, 4, 32);

        let (ret_type, can_null) = get_map_op_return_type(BpfFuncId::MapLookupElem, &info);
        assert_eq!(ret_type, BpfRegType::PtrToMapValue);
        assert!(can_null);

        let (ret_type, can_null) = get_map_op_return_type(BpfFuncId::MapUpdateElem, &info);
        assert_eq!(ret_type, BpfRegType::ScalarValue);
        assert!(!can_null);
    }

    #[test]
    fn test_map_value_constraints() {
        let info = make_map_info(BpfMapType::Hash, 4, 64);
        let constraints = MapValueConstraints::for_map(&info);

        assert!(constraints.check_access(0, 4).is_ok());
        assert!(constraints.check_access(56, 8).is_ok()); // Aligned access
        assert!(constraints.check_access(64, 4).is_err()); // Out of bounds
        assert!(constraints.check_access(-4, 4).is_err()); // Negative offset
    }

    #[test]
    fn test_map_value_constraints_special_fields() {
        let info = make_map_info(BpfMapType::Hash, 4, 64);
        let mut constraints = MapValueConstraints::for_map(&info);
        constraints.timer_offset = Some(16);
        constraints.spin_lock_offset = Some(32);

        // Access to timer field should fail
        assert!(constraints.check_access(16, 8).is_err());
        assert!(constraints.check_access(20, 4).is_err()); // Overlaps timer

        // Access to spin lock field should fail
        assert!(constraints.check_access(32, 4).is_err());

        // Other accesses should be ok
        assert!(constraints.check_access(0, 8).is_ok());
        assert!(constraints.check_access(40, 8).is_ok());
    }

    #[test]
    fn test_validate_map_operation_success() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::Hash, 4, 32));

        let mut key_reg = BpfRegState::new_not_init();
        key_reg.reg_type = BpfRegType::PtrToStack;

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            Some(&key_reg),
            None,
            None,
        );

        assert!(validation.valid);
        assert!(validation.signature.is_some());
        assert!(validation.errors.is_empty());
    }

    #[test]
    fn test_validate_map_operation_no_map_info() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        // No map_ptr set

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            None,
            None,
            None,
        );

        assert!(!validation.valid);
        assert!(!validation.errors.is_empty());
    }

    #[test]
    fn test_validate_map_operation_missing_key() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::Hash, 4, 32));

        let validation = validate_map_operation(
            BpfFuncId::MapLookupElem,
            &map_reg,
            None, // Missing key
            None,
            None,
        );

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|e| e.contains("key")));
    }

    #[test]
    fn test_validation_with_warning() {
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_ptr = Some(make_map_info(BpfMapType::ProgArray, 4, 4));

        let mut key_reg = BpfRegState::new_not_init();
        key_reg.reg_type = BpfRegType::PtrToStack;

        let mut value_reg = BpfRegState::new_not_init();
        value_reg.reg_type = BpfRegType::PtrToStack;

        let validation = validate_map_operation(
            BpfFuncId::MapUpdateElem,
            &map_reg,
            Some(&key_reg),
            Some(&value_reg),
            None,
        );

        assert!(validation.valid);
        assert!(!validation.warnings.is_empty());
        assert!(validation.warnings[0].contains("prog_array"));
    }

    // ========================================================================
    // Tests for check_map_func_compatibility
    // ========================================================================

    #[test]
    fn test_prog_array_tail_call_compat() {
        let ctx = MapFuncCompatContext::default();

        // prog_array only works with tail_call
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::MapLookupElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::MapUpdateElem).is_err());

        // tail_call only works with prog_array
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::TailCall).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::TailCall).is_err());
    }

    #[test]
    fn test_perf_event_array_compat() {
        let ctx = MapFuncCompatContext::default();

        // perf_event_array works with perf event functions
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::PerfEventOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::PerfEventRead).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::SkbOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::XdpOutput).is_ok());

        // but not with generic map functions
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PerfEventArray, BpfFuncId::MapLookupElem).is_err());
    }

    #[test]
    fn test_ringbuf_compat() {
        let ctx = MapFuncCompatContext::default();

        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufOutput).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufReserve).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::RingbufQuery).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Ringbuf, BpfFuncId::MapLookupElem).is_err());

        // ringbuf functions require ringbuf map
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::RingbufOutput).is_err());
    }

    #[test]
    fn test_stack_queue_compat() {
        let ctx = MapFuncCompatContext::default();

        // Stack/queue maps work with push/pop/peek
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPushElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPopElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapPeekElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapPushElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapPopElem).is_ok());

        // but not with lookup/update/delete
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Stack, BpfFuncId::MapLookupElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Queue, BpfFuncId::MapUpdateElem).is_err());
    }

    #[test]
    fn test_storage_maps_compat() {
        let ctx = MapFuncCompatContext::default();

        // SK storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::SkStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::SkStorageDelete).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::SkStorage, BpfFuncId::MapLookupElem).is_err());

        // Task storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::TaskStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::TaskStorageDelete).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::TaskStorage, BpfFuncId::SkStorageGet).is_err());

        // Inode storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::InodeStorage, BpfFuncId::InodeStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::InodeStorage, BpfFuncId::InodeStorageDelete).is_ok());

        // Cgroup storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgrpStorage, BpfFuncId::CgrpStorageGet).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgrpStorage, BpfFuncId::CgrpStorageDelete).is_ok());
    }

    #[test]
    fn test_redirect_map_compat() {
        let ctx = MapFuncCompatContext::default();

        // redirect_map works with devmap, cpumap, xskmap
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Devmap, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::DevmapHash, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Cpumap, BpfFuncId::RedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Xskmap, BpfFuncId::RedirectMap).is_ok());

        // but not with regular maps
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::RedirectMap).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::RedirectMap).is_err());
    }

    #[test]
    fn test_sockmap_compat() {
        let ctx = MapFuncCompatContext::new(BpfProgType::SkSkb);

        // sockmap operations
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SkRedirectMap).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SockMapUpdate).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::MapLookupElem).is_ok());

        // sockhash operations
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SkRedirectHash).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SockHashUpdate).is_ok());

        // wrong function for wrong map type
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockmap, BpfFuncId::SkRedirectHash).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Sockhash, BpfFuncId::SkRedirectMap).is_err());
    }

    #[test]
    fn test_cgroup_storage_compat() {
        let ctx = MapFuncCompatContext::default();

        assert!(check_map_func_compatibility(&ctx, BpfMapType::CgroupStorage, BpfFuncId::GetLocalStorage).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::PercpuCgroupStorage, BpfFuncId::GetLocalStorage).is_ok());

        // get_local_storage requires cgroup storage
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::GetLocalStorage).is_err());
    }

    #[test]
    fn test_array_of_maps_compat() {
        let ctx = MapFuncCompatContext::default();

        // Only lookup is allowed for map-of-maps
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ArrayOfMaps, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::HashOfMaps, BpfFuncId::MapLookupElem).is_ok());

        assert!(check_map_func_compatibility(&ctx, BpfMapType::ArrayOfMaps, BpfFuncId::MapUpdateElem).is_err());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::HashOfMaps, BpfFuncId::MapDeleteElem).is_err());
    }

    #[test]
    fn test_bloom_filter_compat() {
        let ctx = MapFuncCompatContext::default();

        // Bloom filter supports peek (check) and push (add)
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPeekElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPushElem).is_ok());

        // But not pop (no removal from bloom filter)
        assert!(check_map_func_compatibility(&ctx, BpfMapType::BloomFilter, BpfFuncId::MapPopElem).is_err());
    }

    #[test]
    fn test_tail_call_subprog_restriction() {
        let mut ctx = MapFuncCompatContext::new(BpfProgType::Xdp);
        ctx.subprog_cnt = 2; // Has subprograms
        ctx.jit_supports_subprog_tailcalls = false;

        // Tail call with subprograms and no JIT support should fail
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_err());

        // With JIT support it should work
        ctx.jit_supports_subprog_tailcalls = true;
        assert!(check_map_func_compatibility(&ctx, BpfMapType::ProgArray, BpfFuncId::TailCall).is_ok());
    }

    #[test]
    fn test_generic_hash_array_compat() {
        let ctx = MapFuncCompatContext::default();

        // Generic hash map works with standard helpers
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapUpdateElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Hash, BpfFuncId::MapDeleteElem).is_ok());

        // Array map works with standard helpers
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::MapLookupElem).is_ok());
        assert!(check_map_func_compatibility(&ctx, BpfMapType::Array, BpfFuncId::MapUpdateElem).is_ok());
    }

    #[test]
    fn test_is_special_map_type() {
        assert!(is_special_map_type(BpfMapType::ProgArray));
        assert!(is_special_map_type(BpfMapType::Ringbuf));
        assert!(is_special_map_type(BpfMapType::SkStorage));
        assert!(!is_special_map_type(BpfMapType::Hash));
        assert!(!is_special_map_type(BpfMapType::Array));
    }

    #[test]
    fn test_get_allowed_funcs_for_map() {
        let funcs = get_allowed_funcs_for_map(BpfMapType::ProgArray);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0], BpfFuncId::TailCall);

        let funcs = get_allowed_funcs_for_map(BpfMapType::Stack);
        assert_eq!(funcs.len(), 3);
        assert!(funcs.contains(&BpfFuncId::MapPushElem));
        assert!(funcs.contains(&BpfFuncId::MapPopElem));
        assert!(funcs.contains(&BpfFuncId::MapPeekElem));

        let funcs = get_allowed_funcs_for_map(BpfMapType::Hash);
        assert!(funcs.contains(&BpfFuncId::MapLookupElem));
        assert!(funcs.contains(&BpfFuncId::MapUpdateElem));
        assert!(funcs.contains(&BpfFuncId::MapDeleteElem));
    }
