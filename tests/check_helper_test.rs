// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::helper

use bpf_verifier::check::helper::*;

use super::*;

    #[test]
    fn test_get_helper_proto() {
        let proto = get_helper_proto(BpfFuncId::MapLookupElem);
        assert!(proto.is_some());
        
        let proto = proto.unwrap();
        assert_eq!(proto.arg_types[0], BpfArgType::ConstMapPtr);
        assert_eq!(proto.arg_types[1], BpfArgType::PtrToMapKey);
    }

    #[test]
    fn test_helper_proto_construction() {
        let proto = HelperProto::new(
            BpfFuncId::KtimeGetNs,
            BpfRetType::Integer,
            &[],
        );
        
        assert_eq!(proto.arg_types[0], BpfArgType::DontCare);
    }

    #[test]
    fn test_check_mem_arg() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        
        assert!(check_mem_arg(&reg, "memory").is_ok());
        
        reg.reg_type = BpfRegType::PtrToCtx;
        assert!(check_mem_arg(&reg, "memory").is_err());
    }
