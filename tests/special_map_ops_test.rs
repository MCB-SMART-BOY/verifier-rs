// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::map_ops

use bpf_verifier::special::map_ops::*;

use super::*;

    #[test]
    fn test_map_capabilities() {
        let hash_caps = MapCapabilities::for_map_type(BpfMapType::Hash);
        assert!(hash_caps.can_lookup);
        assert!(hash_caps.can_update);
        assert!(hash_caps.can_delete);

        let array_caps = MapCapabilities::for_map_type(BpfMapType::Array);
        assert!(array_caps.can_lookup);
        assert!(array_caps.can_update);
        assert!(!array_caps.can_delete);

        let percpu_caps = MapCapabilities::for_map_type(BpfMapType::PercpuHash);
        assert!(percpu_caps.is_percpu);
    }

    #[test]
    fn test_map_op_allowed() {
        // Hash map supports all ops
        assert!(check_map_op_allowed(BpfMapType::Hash, MapOpType::Lookup).is_ok());
        assert!(check_map_op_allowed(BpfMapType::Hash, MapOpType::Update).is_ok());
        assert!(check_map_op_allowed(BpfMapType::Hash, MapOpType::Delete).is_ok());

        // Array doesn't support delete
        assert!(check_map_op_allowed(BpfMapType::Array, MapOpType::Delete).is_err());

        // Peek only for stack/queue
        assert!(check_map_op_allowed(BpfMapType::Stack, MapOpType::Peek).is_ok());
        assert!(check_map_op_allowed(BpfMapType::Hash, MapOpType::Peek).is_err());
    }

    #[test]
    fn test_map_value_desc() {
        let desc = MapValueDesc {
            size: 64,
            fields: vec![
                MapValueField {
                    offset: 0,
                    size: 4,
                    field_type: MapValueFieldType::SpinLock,
                    btf_id: None,
                },
                MapValueField {
                    offset: 8,
                    size: 16,
                    field_type: MapValueFieldType::Timer,
                    btf_id: None,
                },
            ],
        };

        // Regular access is OK
        assert!(desc.check_access(24, 8, true).is_ok());

        // Writing to spin_lock is not OK
        assert!(desc.check_access(0, 4, true).is_err());

        // Any timer access is not OK
        assert!(desc.check_access(8, 8, false).is_err());
    }

    #[test]
    fn test_field_at() {
        let desc = MapValueDesc {
            size: 32,
            fields: vec![
                MapValueField {
                    offset: 8,
                    size: 8,
                    field_type: MapValueFieldType::Kptr,
                    btf_id: Some(100),
                },
            ],
        };

        assert!(desc.get_field_at(0, 4).is_none());
        assert!(desc.get_field_at(8, 8).is_some());
        assert!(desc.get_field_at(12, 4).is_some()); // Partial overlap
    }

    #[test]
    fn test_map_value_range() {
        let range = MapValueRange::full(64);
        assert!(range.check_access(0, 8));
        assert!(range.check_access(56, 8));
        assert!(!range.check_access(60, 8)); // Would overflow

        let narrowed = range.narrow(8, 32);
        assert!(!narrowed.check_access(0, 8)); // Before narrow start
        assert!(narrowed.check_access(8, 8));
        assert!(narrowed.check_access(24, 8));
        assert!(!narrowed.check_access(28, 8)); // Would exceed narrow end
    }

    #[test]
    fn test_adjust_map_value_ptr() {
        use crate::state::reg_state::MapInfo;
        
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.off = 0;
        reg.map_ptr = Some(MapInfo {
            map_type: BpfMapType::Hash,
            key_size: 4,
            value_size: 64,
            max_entries: 100,
        });

        // Valid adjustment
        assert!(adjust_map_value_ptr(&mut reg, 8, 64).is_ok());
        assert_eq!(reg.off, 8);

        // Another valid adjustment
        assert!(adjust_map_value_ptr(&mut reg, 16, 64).is_ok());
        assert_eq!(reg.off, 24);

        // Invalid - would go out of bounds
        assert!(adjust_map_value_ptr(&mut reg, 64, 64).is_err());

        // Invalid - would go negative
        assert!(adjust_map_value_ptr(&mut reg, -100, 64).is_err());
    }

    #[test]
    fn test_map_ptrs_may_alias() {
        let mut reg1 = BpfRegState::new_not_init();
        reg1.reg_type = BpfRegType::PtrToMapValue;
        reg1.map_uid = 1;
        reg1.off = 0;

        let mut reg2 = BpfRegState::new_not_init();
        reg2.reg_type = BpfRegType::PtrToMapValue;
        reg2.map_uid = 1;
        reg2.off = 0;

        // Same map_uid, same offset - may alias
        assert!(map_ptrs_may_alias(&reg1, &reg2));

        // Different map_uid - no alias
        reg2.map_uid = 2;
        assert!(!map_ptrs_may_alias(&reg1, &reg2));

        // Different types - no alias
        reg2.reg_type = BpfRegType::PtrToStack;
        assert!(!map_ptrs_may_alias(&reg1, &reg2));
    }

    #[test]
    fn test_track_map_value_var_off() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.off = 8;

        // Valid variable offset range
        let range = track_map_value_var_off(&mut reg, 0, 16, 64).unwrap();
        assert_eq!(range.min_off, 8);
        assert_eq!(range.max_off, 25); // 8 + 16 + 1
        assert!(range.is_variable);

        // Fixed offset (min == max)
        let range = track_map_value_var_off(&mut reg, 0, 0, 64).unwrap();
        assert!(!range.is_variable);

        // Out of bounds
        assert!(track_map_value_var_off(&mut reg, 0, 100, 64).is_err());
    }

    #[test]
    fn test_propagate_map_ptr_info() {
        use crate::state::reg_state::MapInfo;
        
        let mut src = BpfRegState::new_not_init();
        src.reg_type = BpfRegType::PtrToMapValue;
        src.map_ptr = Some(MapInfo {
            map_type: BpfMapType::Array,
            key_size: 4,
            value_size: 32,
            max_entries: 50,
        });

        let mut dst = BpfRegState::new_not_init();
        propagate_map_ptr_info(&mut dst, &src);

        assert!(dst.map_ptr.is_some());
        assert_eq!(dst.map_ptr.as_ref().unwrap().map_type, BpfMapType::Array);
        assert_eq!(dst.map_ptr.as_ref().unwrap().value_size, 32);
    }
