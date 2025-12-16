// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::atomic

use bpf_verifier::prelude::*;
use bpf_verifier::check::atomic::*;


    #[test]
    fn test_atomic_size() {
        let insn32 = BpfInsn::new(BPF_STX | BPF_ATOMIC | BPF_W, 1, 2, 0, BPF_ADD as i32);
        assert_eq!(atomic_size(&insn32), 4);

        let insn64 = BpfInsn::new(BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_ADD as i32);
        assert_eq!(atomic_size(&insn64), 8);
    }

    #[test]
    fn test_is_atomic_rmw() {
        let insn = BpfInsn::new(BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_ADD as i32);
        assert!(is_atomic_rmw(&insn));
        
        let not_atomic = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 1, 2, 0, 0);
        assert!(!is_atomic_rmw(&not_atomic));
    }

    #[test]
    fn test_is_cmpxchg() {
        let insn = BpfInsn::new(
            BPF_STX | BPF_ATOMIC | BPF_DW, 
            1, 2, 0, 
            BPF_ATOMIC_CMPXCHG as i32
        );
        assert!(is_cmpxchg(&insn));
    }

    #[test]
    fn test_is_xchg() {
        let insn = BpfInsn::new(
            BPF_STX | BPF_ATOMIC | BPF_DW, 
            1, 2, 0, 
            BPF_ATOMIC_XCHG as i32
        );
        assert!(is_xchg(&insn));
    }

    #[test]
    fn test_has_fetch() {
        let fetch = BpfInsn::new(
            BPF_STX | BPF_ATOMIC | BPF_DW, 
            1, 2, 0, 
            (BPF_ADD as i32) | (BPF_FETCH as i32)
        );
        assert!(has_fetch(&fetch));

        let no_fetch = BpfInsn::new(
            BPF_STX | BPF_ATOMIC | BPF_DW, 
            1, 2, 0, 
            BPF_ADD as i32
        );
        assert!(!has_fetch(&no_fetch));
    }

    #[test]
    fn test_atomic_ptr_type_ok() {
        assert!(atomic_ptr_type_ok(BpfRegType::PtrToMapValue, 8));
        assert!(atomic_ptr_type_ok(BpfRegType::PtrToStack, 8));
        assert!(!atomic_ptr_type_ok(BpfRegType::PtrToPacket, 8));
        assert!(!atomic_ptr_type_ok(BpfRegType::PtrToCtx, 8));
    }

    #[test]
    fn test_atomic_op_name() {
        assert_eq!(atomic_op_name(BPF_ADD as u32), "atomic_add");
        assert_eq!(atomic_op_name(BPF_ADD as u32 | BPF_FETCH), "atomic_fetch_add");
        assert_eq!(atomic_op_name(0xe0 | BPF_FETCH), "atomic_xchg");
        assert_eq!(atomic_op_name(0xf0 | BPF_FETCH), "atomic_cmpxchg");
    }
