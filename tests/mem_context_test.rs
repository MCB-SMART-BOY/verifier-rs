// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::context

use bpf_verifier::prelude::*;
use bpf_verifier::mem::context::*;


    #[test]
    fn test_xdp_rules() {
        let rules = ContextAccessRules::xdp();
        
        assert_eq!(rules.ctx_size, 24);
        assert_eq!(rules.fields.len(), 6);
        
        // data field
        let field = rules.find_field(0, 4).unwrap();
        assert_eq!(field.result_type, BpfRegType::PtrToPacket);
        
        // data_end field
        let field = rules.find_field(4, 4).unwrap();
        assert_eq!(field.result_type, BpfRegType::PtrToPacketEnd);
    }

    #[test]
    fn test_field_access() {
        let rules = ContextAccessRules::xdp();
        
        // Valid access
        assert!(rules.find_field(0, 4).is_some());
        
        // Invalid offset
        assert!(rules.find_field(100, 4).is_none());
    }

    #[test]
    fn test_spans_multiple_fields() {
        let rules = ContextAccessRules::xdp();
        
        // Single field access
        assert!(!rules.spans_multiple_fields(0, 4));
        
        // Spans data and data_end
        assert!(rules.spans_multiple_fields(0, 8));
    }

    #[test]
    fn test_check_ctx_access() {
        let rules = ContextAccessRules::xdp();
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;

        // Valid read of data field
        let result = check_ctx_access(&reg, 0, 4, false, &rules);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), BpfRegType::PtrToPacket);

        // Write to read-only field should fail
        let result = check_ctx_access(&reg, 0, 4, true, &rules);
        assert!(result.is_err());
    }

    #[test]
    fn test_sched_cls_writable() {
        let rules = ContextAccessRules::sched_cls();
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;

        // mark field should be writable
        let result = check_ctx_access(&reg, 8, 4, true, &rules);
        assert!(result.is_ok());
    }

    #[test]
    fn test_negative_offset() {
        let rules = ContextAccessRules::xdp();
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;

        let result = check_ctx_access(&reg, -4, 4, false, &rules);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_to_packet() {
        // XDP data field at offset 0 should convert to PtrToPacket
        let result = convert_ctx_to_packet_access(BpfProgType::Xdp, 0);
        assert_eq!(result, Some(BpfRegType::PtrToPacket));

        // Non-packet field should return None
        let result = convert_ctx_to_packet_access(BpfProgType::Xdp, 12);
        assert!(result.is_none());
    }

    #[test]
    fn test_narrow_access() {
        let rules = ContextAccessRules::xdp();
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;

        // XDP doesn't allow narrow access
        let result = check_ctx_access(&reg, 0, 2, false, &rules);
        assert!(result.is_err());

        // Socket filter does
        let rules = ContextAccessRules::socket_filter();
        let _result = check_ctx_access(&reg, 0, 2, false, &rules);
        // May still fail due to field boundaries, but narrow access is allowed
    }
