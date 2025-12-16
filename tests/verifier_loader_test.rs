// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::verifier::loader

use bpf_verifier::verifier::loader::*;

use super::*;

    #[test]
    fn test_fd_array() {
        let mut fd_array = FdArray::new();
        
        let map_info = BpfMapInfo::new(5, 1, 0x1234);
        fd_array.add_map(map_info);
        
        assert_eq!(fd_array.map_count(), 1);
        assert!(fd_array.get_map(5).is_some());
        assert!(fd_array.get_map(6).is_none());
    }

    #[test]
    fn test_load_options() {
        let opts = LoadOptions::privileged(BpfProgType::SocketFilter);
        assert!(opts.is_privileged);
        assert!(opts.caps.bounded_loops);

        let opts = LoadOptions::unprivileged(BpfProgType::SocketFilter);
        assert!(!opts.is_privileged);
    }

    #[test]
    fn test_simple_program_verification() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // r0 = 0
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // exit
        ];

        let result = load_and_verify(insns, BpfProgType::SocketFilter, true);
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.insns.len(), 2);
        assert!(result.stats.insn_processed > 0);
    }

    #[test]
    fn test_check_program() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let stats = check_program(&insns, BpfProgType::SocketFilter, true);
        assert!(stats.is_ok());
    }

    #[test]
    fn test_map_info_conversion() {
        let mut map_info = BpfMapInfo::new(1, 2, 0x5678);
        map_info.key_size = 4;
        map_info.value_size = 8;
        map_info.max_entries = 100;

        let internal = map_info.to_map_info();
        assert_eq!(internal.map_type, BpfMapType::Array); // map_type 2 = Array
        assert_eq!(internal.key_size, 4);
        assert_eq!(internal.value_size, 8);
        assert_eq!(internal.max_entries, 100);
    }

    #[test]
    fn test_verify_stats_default() {
        let stats = VerifyStats::default();
        assert_eq!(stats.insn_processed, 0);
        assert_eq!(stats.peak_states, 0);
        assert_eq!(stats.subprog_count, 0);
    }

    #[test]
    fn test_bpf_check_empty_program() {
        let insns = vec![];
        let fd_array = FdArray::new();
        let options = LoadOptions::privileged(BpfProgType::SocketFilter);

        let result = bpf_check(insns, &fd_array, &options);
        assert!(matches!(result, Err(VerifierError::EmptyProgram)));
    }
