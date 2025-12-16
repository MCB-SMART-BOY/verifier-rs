// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::packet

use bpf_verifier::mem::packet::*;

use super::*;

    #[test]
    fn test_packet_range() {
        let range = PacketRange::new(0, 100);
        
        assert!(range.contains(0, 10));
        assert!(range.contains(90, 10));
        assert!(!range.contains(95, 10)); // Would exceed end
        assert!(!range.contains(-1, 1)); // Negative offset
    }

    #[test]
    fn test_packet_range_intersect() {
        let a = PacketRange::new(0, 100);
        let b = PacketRange::new(50, 150);
        
        let c = a.intersect(&b).unwrap();
        assert_eq!(c.start, 50);
        assert_eq!(c.end, 100);
    }

    #[test]
    fn test_packet_range_no_intersect() {
        let a = PacketRange::new(0, 50);
        let b = PacketRange::new(60, 100);
        
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn test_packet_state() {
        let mut state = PacketState::new();
        
        assert!(!state.is_access_safe(0, 10));
        
        state.mark_bounds_checked(PacketRange::new(0, 100));
        
        assert!(state.is_access_safe(0, 10));
        assert!(state.is_access_safe(50, 50));
        assert!(!state.is_access_safe(95, 10));
    }

    #[test]
    fn test_check_packet_access() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.off = 0;

        assert!(check_packet_access(&reg, 0, 4, false).is_ok());
        assert!(check_packet_access(&reg, 100, 4, false).is_ok());
    }

    #[test]
    fn test_check_packet_access_negative() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.off = 0;

        assert!(check_packet_access(&reg, -1, 4, false).is_err());
    }

    #[test]
    fn test_packet_write_allowed() {
        assert!(check_packet_write_allowed(BpfProgType::Xdp));
        assert!(check_packet_write_allowed(BpfProgType::SchedCls));
        assert!(!check_packet_write_allowed(BpfProgType::SocketFilter));
    }

    #[test]
    fn test_direct_packet_access() {
        let access = DirectPacketAccess {
            offset: 14, // After Ethernet header
            size: 4,
            is_write: false,
            insn_idx: 5,
        };

        let ranges = vec![PacketRange::new(0, 100)];
        let accesses = vec![access];

        assert!(validate_packet_accesses(&accesses, &ranges).is_ok());
    }

    #[test]
    fn test_unverified_access() {
        let access = DirectPacketAccess {
            offset: 200,
            size: 4,
            is_write: false,
            insn_idx: 5,
        };

        let ranges = vec![PacketRange::new(0, 100)];
        let accesses = vec![access];

        assert!(validate_packet_accesses(&accesses, &ranges).is_err());
    }

    #[test]
    fn test_variable_packet_bounds() {
        let mut bounds = VariablePacketBounds::new(10, 50);
        
        // Not verified yet
        assert!(!bounds.is_access_safe(4, 100));
        
        bounds.verified = true;
        
        // max_off (50) + size (4) = 54 <= 100
        assert!(bounds.is_access_safe(4, 100));
        
        // max_off (50) + size (60) = 110 > 100
        assert!(!bounds.is_access_safe(60, 100));
    }

    #[test]
    fn test_variable_bounds_narrow() {
        let mut bounds = VariablePacketBounds::new(0, 100);
        
        // After: if (var < 50) - taken branch
        bounds.narrow(BPF_JLT, 50, true);
        assert_eq!(bounds.max_off, 49);
        
        let mut bounds2 = VariablePacketBounds::new(0, 100);
        // After: if (var >= 30) - taken branch
        bounds2.narrow(BPF_JGE, 30, true);
        assert_eq!(bounds2.min_off, 30);
    }

    #[test]
    fn test_packet_bounds_context() {
        let mut ctx = PacketBoundsContext::new();
        
        // Initially no access is verified
        assert!(!ctx.is_access_verified(0, 4));
        
        // Record a bounds check
        ctx.record_bounds_check(PacketRange::new(0, 100));
        
        // Now accesses within range are verified
        assert!(ctx.is_access_verified(0, 4));
        assert!(ctx.is_access_verified(96, 4));
        assert!(!ctx.is_access_verified(97, 4)); // Would exceed end
    }

    #[test]
    fn test_packet_bounds_context_init() {
        let mut ctx = PacketBoundsContext::new();
        
        // XDP context field loads
        ctx.init_from_ctx_load(1, 0);  // data
        ctx.init_from_ctx_load(2, 8);  // data_end
        
        assert_eq!(ctx.data_reg, Some(1));
        assert_eq!(ctx.data_end_reg, Some(2));
    }

    #[test]
    fn test_is_packet_ptr() {
        let mut reg = BpfRegState::new_not_init();
        
        reg.reg_type = BpfRegType::ScalarValue;
        assert!(!is_packet_ptr(&reg));
        
        reg.reg_type = BpfRegType::PtrToPacket;
        assert!(is_packet_ptr(&reg));
        
        reg.reg_type = BpfRegType::PtrToPacketEnd;
        assert!(is_packet_ptr(&reg));
        
        reg.reg_type = BpfRegType::PtrToPacketMeta;
        assert!(is_packet_ptr(&reg));
    }

    #[test]
    fn test_validate_packet_access_full() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.off = 0;
        
        let mut ctx = PacketBoundsContext::new();
        ctx.record_bounds_check(PacketRange::new(0, 100));
        
        // Valid access
        assert!(validate_packet_access_full(
            &reg, 0, 4, false, &ctx, BpfProgType::Xdp
        ).is_ok());
        
        // Access beyond verified bounds
        assert!(validate_packet_access_full(
            &reg, 100, 4, false, &ctx, BpfProgType::Xdp
        ).is_err());
    }

    #[test]
    fn test_validate_packet_access_write_permission() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.off = 0;
        
        let mut ctx = PacketBoundsContext::new();
        ctx.record_bounds_check(PacketRange::new(0, 100));
        
        // XDP allows writes
        assert!(validate_packet_access_full(
            &reg, 0, 4, true, &ctx, BpfProgType::Xdp
        ).is_ok());
        
        // Socket filter doesn't allow writes
        assert!(validate_packet_access_full(
            &reg, 0, 4, true, &ctx, BpfProgType::SocketFilter
        ).is_err());
    }

    #[test]
    fn test_find_packet_pointers() {
        let mut regs: [BpfRegState; MAX_BPF_REG] = core::array::from_fn(|_| BpfRegState::new_not_init());
        
        regs[1].reg_type = BpfRegType::PtrToPacket;
        regs[1].off = 0;
        regs[2].reg_type = BpfRegType::PtrToPacketEnd;
        
        let ptrs = find_packet_pointers(&regs);
        
        assert_eq!(ptrs.data, Some(1));
        assert_eq!(ptrs.data_end, Some(2));
        assert!(ptrs.can_check_bounds());
    }

    #[test]
    fn test_track_packet_ptr_derivation() {
        let mut dst = BpfRegState::new_not_init();
        let mut src = BpfRegState::new_not_init();
        src.reg_type = BpfRegType::PtrToPacket;
        src.off = 10;
        src.id = 1;
        
        // Add 4 to packet pointer
        assert!(track_packet_ptr_derivation(&mut dst, &src, 4).is_ok());
        
        assert_eq!(dst.reg_type, BpfRegType::PtrToPacket);
        assert_eq!(dst.off, 14);
        assert_eq!(dst.id, 1);
    }

    #[test]
    fn test_track_packet_ptr_derivation_negative() {
        let mut dst = BpfRegState::new_not_init();
        let mut src = BpfRegState::new_not_init();
        src.reg_type = BpfRegType::PtrToPacket;
        src.off = 5;
        
        // Subtracting more than current offset would go negative
        assert!(track_packet_ptr_derivation(&mut dst, &src, -10).is_err());
    }

    #[test]
    fn test_invalidate_packet_bounds_after_helper() {
        let mut ctx = PacketBoundsContext::new();
        ctx.record_bounds_check(PacketRange::new(0, 100));
        ctx.in_checked_region = true;
        
        // xdp_adjust_head invalidates bounds
        invalidate_packet_bounds_after_helper(&mut ctx, 44);
        
        assert!(!ctx.in_checked_region);
        assert!(ctx.verified_ranges.is_empty());
    }

    #[test]
    fn test_compute_safe_range_from_reg() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToPacket;
        reg.off = 14; // After Ethernet header
        
        let range = compute_safe_range_from_reg(&reg, 20);
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.start, 14);
        assert_eq!(range.end, 34);
    }

    #[test]
    fn test_invert_jmp_op() {
        assert_eq!(invert_jmp_op(BPF_JGT), BPF_JLT);
        assert_eq!(invert_jmp_op(BPF_JLT), BPF_JGT);
        assert_eq!(invert_jmp_op(BPF_JGE), BPF_JLE);
        assert_eq!(invert_jmp_op(BPF_JLE), BPF_JGE);
    }

    #[test]
    fn test_analyze_packet_bounds_jmp() {
        let mut regs: [BpfRegState; MAX_BPF_REG] = core::array::from_fn(|_| BpfRegState::new_not_init());
        
        // data + 42 in r1
        regs[1].reg_type = BpfRegType::PtrToPacket;
        regs[1].off = 42;
        
        // data_end in r2
        regs[2].reg_type = BpfRegType::PtrToPacketEnd;
        
        // Pattern: if (data + 42 > data_end) goto drop;
        // Fall-through means data + 42 <= data_end
        let result = analyze_packet_bounds_jmp(&regs, 1, 2, BPF_JGT, false);
        
        assert!(result.is_some());
        let (_, range) = result.unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, 42);
    }
