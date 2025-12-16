// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::btf::func_info

use bpf_verifier::prelude::*;
use bpf_verifier::btf::func_info::*;


    #[test]
    fn test_func_info_basic() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let subprogs = vec![SubprogInfo {
            start: 0,
            end: 2,
            stack_depth: 0,
            is_global: false,
            is_async_cb: false,
            is_exception_cb: false,
        }];

        let mut verifier = BtfInfoVerifier::new(None, &insns, &subprogs);
        
        // Empty func_info should pass
        let result = verifier.check_btf_func_early(&[], MIN_BPF_FUNCINFO_SIZE);
        assert!(result.is_ok());
    }

    #[test]
    fn test_line_info_alignment() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let subprogs = vec![SubprogInfo {
            start: 0,
            end: 2,
            stack_depth: 0,
            is_global: false,
            is_async_cb: false,
            is_exception_cb: false,
        }];

        let mut verifier = BtfInfoVerifier::new(None, &insns, &subprogs);
        
        // Misaligned offset should fail
        let bad_line_info = vec![BpfLineInfo {
            insn_off: 3, // Not 8-byte aligned
            file_name_off: 0,
            line_off: 0,
            line_col: 0,
        }];
        
        let result = verifier.check_btf_line(&bad_line_info, MIN_BPF_LINEINFO_SIZE);
        assert!(result.is_err());
    }

    #[test]
    fn test_core_relo_kind() {
        assert_eq!(
            BpfCoreReloKind::try_from(0),
            Ok(BpfCoreReloKind::FieldByteOffset)
        );
        assert_eq!(
            BpfCoreReloKind::try_from(9),
            Ok(BpfCoreReloKind::TypeSize)
        );
        assert!(BpfCoreReloKind::try_from(100).is_err());
    }
