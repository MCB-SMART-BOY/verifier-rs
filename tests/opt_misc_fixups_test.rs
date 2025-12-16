// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::misc_fixups

use bpf_verifier::opt::misc_fixups::*;

use super::*;

    #[test]
    fn test_is_helper_call() {
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        assert!(is_helper_call(&call));

        let pseudo_call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL as u8, 0, 1);
        assert!(!is_helper_call(&pseudo_call));

        let exit = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        assert!(!is_helper_call(&exit));
    }

    #[test]
    fn test_is_atomic_op() {
        let atomic = BpfInsn::new(BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_ADD as i32);
        assert!(is_atomic_op(&atomic));

        let regular_store = BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, 1, 2, 0, 0);
        assert!(!is_atomic_op(&regular_store));
    }

    #[test]
    fn test_bpf_func_from_u32() {
        assert_eq!(BpfFunc::from_u32(1), Some(BpfFunc::MapLookupElem));
        assert_eq!(BpfFunc::from_u32(12), Some(BpfFunc::TailCall));
        assert_eq!(BpfFunc::from_u32(181), Some(BpfFunc::LoopCall));
        assert_eq!(BpfFunc::from_u32(9999), None);
    }

    #[test]
    fn test_fixup_context_default() {
        let ctx = FixupContext::default();
        assert_eq!(ctx.prog_type, BpfProgType::Unspec);
        assert!(ctx.inline_map_lookups);
        assert!(ctx.inline_bpf_loop);
    }

    #[test]
    fn test_do_misc_fixups_empty() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let ctx = FixupContext::default();
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.insns_added, 0);
    }

    #[test]
    fn test_do_misc_fixups_tail_call() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12), // tail_call
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let ctx = FixupContext::default();
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.helpers_transformed, 1);
        // Tail call instrumentation adds 4 instructions
        assert!(insns.len() > 3);
    }

    #[test]
    fn test_find_const_before() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        assert_eq!(find_const_before(&insns, 2, 1), Some(0));
        assert_eq!(find_const_before(&insns, 2, 2), Some(1));
        assert_eq!(find_const_before(&insns, 2, 3), None);
    }

    #[test]
    fn test_fixup_result_default() {
        let result = FixupResult::default();
        assert_eq!(result.map_lookups_inlined, 0);
        assert_eq!(result.loops_inlined, 0);
        assert_eq!(result.helpers_transformed, 0);
        assert_eq!(result.insns_added, 0);
    }

    #[test]
    fn test_compute_jhash() {
        // Test jhash with known values
        let key1 = vec![1u8, 2, 3, 4];
        let hash1 = compute_jhash(&key1, 0);
        assert_ne!(hash1, 0);
        
        // Same key should produce same hash
        let hash1_again = compute_jhash(&key1, 0);
        assert_eq!(hash1, hash1_again);
        
        // Different key should produce different hash
        let key2 = vec![5u8, 6, 7, 8];
        let hash2 = compute_jhash(&key2, 0);
        assert_ne!(hash1, hash2);
        
        // Different initval should produce different hash
        let hash1_init = compute_jhash(&key1, 42);
        assert_ne!(hash1, hash1_init);
        
        // Empty key with zero initval produces zero
        let empty = vec![];
        assert_eq!(compute_jhash(&empty, 0), 0);
    }

    #[test]
    fn test_round_up_value_size() {
        assert_eq!(round_up_value_size(1), 8);
        assert_eq!(round_up_value_size(4), 8);
        assert_eq!(round_up_value_size(8), 8);
        assert_eq!(round_up_value_size(9), 16);
        assert_eq!(round_up_value_size(16), 16);
        assert_eq!(round_up_value_size(100), 104);
    }

    #[test]
    fn test_try_inline_array_lookup() {
        // Setup: LD_IMM64 r1, map_fd; MOV r2, index; CALL map_lookup
        let insns = vec![
            // LD_IMM64 r1, fd=5 (map pointer)
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 5),
            BpfInsn::new(0, 0, 0, 0, 0), // second part of LD_IMM64
            // MOV r2, 3 (index)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 3),
            // CALL map_lookup_elem
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        let map_info = FixupMapInfo {
            fd: 5,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 10,
        };
        
        let result = try_inline_array_lookup(&insns, 3, &map_info);
        assert!(result.is_some());
        
        let patches = result.unwrap();
        assert!(!patches.is_empty());
    }

    #[test]
    fn test_try_inline_array_lookup_out_of_bounds() {
        let insns = vec![
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 5),
            BpfInsn::new(0, 0, 0, 0, 0),
            // Index 100 is out of bounds for max_entries=10
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
        ];
        
        let map_info = FixupMapInfo {
            fd: 5,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 10,
        };
        
        // Should return None because index is out of bounds
        let result = try_inline_array_lookup(&insns, 3, &map_info);
        assert!(result.is_none());
    }

    #[test]
    fn test_map_lookup_with_context() {
        let mut insns = vec![
            // LD_IMM64 r1, fd=1 (map pointer)
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            // MOV r2, 0 (index)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            // CALL map_lookup_elem
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
            // EXIT
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut ctx = FixupContext::default();
        ctx.inline_map_lookups = true;
        ctx.maps.push(FixupMapInfo {
            fd: 1,
            map_ptr: 0xffff_8800_0000_0000,
            map_type: map_types::ARRAY,
            key_size: 4,
            value_size: 16,
            max_entries: 100,
        });
        
        let result = do_misc_fixups(&mut insns, &ctx).unwrap();
        assert_eq!(result.map_lookups_inlined, 1);
    }

    #[test]
    fn test_bpf_loop_inline_small() {
        // Test small loop unrolling
        let insns = vec![
            // MOV r1, 4 (nr_loops)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 4),
            // MOV r2, callback (placeholder)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            // CALL bpf_loop (181)
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            // EXIT
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_some());
    }

    #[test]
    fn test_bpf_loop_inline_large() {
        // Test larger loop with counter
        let insns = vec![
            // MOV r1, 32 (nr_loops)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 32),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_some());
    }

    #[test]
    fn test_bpf_loop_too_large() {
        // Loops > 64 should not be inlined
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 181),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let result = try_inline_bpf_loop(&insns, 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_fastcall_spills_fills_empty() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let insn_aux = HashMap::new();
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 0);
        assert_eq!(result.fills_removed, 0);
        assert!(!result.stack_depths_modified);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_single() {
        // Simulate: spill, call, fill pattern
        // insn[0] = spill (r6 to stack)
        // insn[1] = call (marked with fastcall_spills_num=1)
        // insn[2] = fill (stack to r6)
        // insn[3] = exit
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0), // spill r6
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0), // fill r6
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(1, InsnAuxData {
            fastcall_spills_num: 1,
            ..Default::default()
        });
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 1);
        assert_eq!(result.fills_removed, 1);
        
        // Check that spill (insn[0]) and fill (insn[2]) are now NOPs
        assert_eq!(insns[0].code, NOP_INSN.code);
        assert_eq!(insns[2].code, NOP_INSN.code);
        // Call and exit should be unchanged
        assert_eq!(insns[1].code, BPF_JMP | BPF_CALL);
        assert_eq!(insns[3].code, BPF_JMP | BPF_EXIT);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_multiple() {
        // Simulate: spill, spill, call, fill, fill pattern (2 register spills)
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0),  // spill r6
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 7, -16, 0), // spill r7
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 7, BPF_REG_FP as u8, -16, 0), // fill r7
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0),  // fill r6
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(2, InsnAuxData {
            fastcall_spills_num: 2,
            ..Default::default()
        });
        let mut subprogs = vec![];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 2);
        assert_eq!(result.fills_removed, 2);
        
        // Check that all spills and fills are NOPs
        assert_eq!(insns[0].code, NOP_INSN.code);
        assert_eq!(insns[1].code, NOP_INSN.code);
        assert_eq!(insns[3].code, NOP_INSN.code);
        assert_eq!(insns[4].code, NOP_INSN.code);
    }

    #[test]
    fn test_remove_fastcall_spills_fills_with_subprog() {
        let mut insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 6, -8, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1),
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 6, BPF_REG_FP as u8, -8, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            // Subprogram 1 starts at index 4
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        insn_aux.insert(1, InsnAuxData {
            fastcall_spills_num: 1,
            ..Default::default()
        });
        
        let mut subprogs = vec![
            SubprogFastcallInfo {
                start: 0,
                end: 4,
                stack_depth: 64,
                fastcall_stack_off: -16,
                keep_fastcall_stack: false,
            },
            SubprogFastcallInfo {
                start: 4,
                end: 6,
                stack_depth: 32,
                fastcall_stack_off: 0,
                keep_fastcall_stack: false,
            },
        ];
        
        let result = remove_fastcall_spills_fills(&mut insns, &insn_aux, &mut subprogs);
        assert_eq!(result.spills_removed, 1);
        assert_eq!(result.fills_removed, 1);
        assert!(result.stack_depths_modified);
        
        // Subprog 0 should have adjusted stack depth
        assert_eq!(subprogs[0].stack_depth, 16); // -(-16) = 16
    }

    #[test]
    fn test_subprog_fastcall_info_default() {
        let info = SubprogFastcallInfo::default();
        assert_eq!(info.start, 0);
        assert_eq!(info.end, 0);
        assert_eq!(info.stack_depth, 0);
        assert_eq!(info.fastcall_stack_off, 0);
        assert!(!info.keep_fastcall_stack);
    }

    #[test]
    fn test_fastcall_removal_result_default() {
        let result = FastcallRemovalResult::default();
        assert_eq!(result.spills_removed, 0);
        assert_eq!(result.fills_removed, 0);
        assert!(!result.stack_depths_modified);
    }

    #[test]
    fn test_get_call_summary_helper() {
        // Test map_lookup_elem - 2 params, non-void, fastcall
        let call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        let kfuncs = vec![];
        let summary = get_call_summary(&call, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 2);
        assert!(!summary.is_void);
        assert!(summary.fastcall);
        
        // Test tail_call - 3 params, void, not fastcall
        let tail_call = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12);
        let summary = get_call_summary(&tail_call, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 3);
        assert!(summary.is_void);
        assert!(!summary.fastcall);
        
        // Test ktime_get_ns - 0 params, non-void, fastcall
        let ktime = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 5);
        let summary = get_call_summary(&ktime, &kfuncs).unwrap();
        assert_eq!(summary.num_params, 0);
        assert!(!summary.is_void);
        assert!(summary.fastcall);
    }

    #[test]
    fn test_get_call_summary_not_call() {
        // Non-call instruction should return None
        let mov = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0);
        let kfuncs = vec![];
        assert!(get_call_summary(&mov, &kfuncs).is_none());
        
        // Subprogram call (BPF_PSEUDO_CALL) should return None
        let subcall = BpfInsn::new(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 10);
        assert!(get_call_summary(&subcall, &kfuncs).is_none());
    }

    #[test]
    fn test_mark_fastcall_patterns_single_spill() {
        // Pattern: spill r3, call map_lookup (clobbers r0,r1,r2), fill r3
        // map_lookup_elem has 2 params, so it clobbers R0 (return), R1, R2 (params)
        // Only R3, R4, R5 are expected in the fastcall pattern
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 3, -8, 0), // spill r3
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0), // fill r3
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // Spill and fill should be marked as fastcall pattern
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        
        // Call instruction should have fastcall_spills_num set
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 1);
    }

    #[test]
    fn test_mark_fastcall_patterns_multiple_spills() {
        // Pattern: spill r3, spill r4, call map_lookup (clobbers r0,r1,r2), fill r4, fill r3
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 3, -8, 0),  // spill r3
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 4, -16, 0), // spill r4
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 4, BPF_REG_FP as u8, -16, 0), // fill r4
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0),  // fill r3
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 6,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // All spills and fills should be marked
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&1).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&3).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&4).map_or(false, |a| a.fastcall_pattern));
        
        // Call instruction should have fastcall_spills_num = 2
        assert_eq!(insn_aux.get(&2).map_or(0, |a| a.fastcall_spills_num), 2);
    }

    #[test]
    fn test_mark_fastcall_patterns_no_match_wrong_register() {
        // Pattern breaks because spill uses r1 which is clobbered by map_lookup
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 1, -8, 0), // spill r1 (clobbered!)
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 1, BPF_REG_FP as u8, -8, 0), // fill r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // No patterns should be marked (r1 is clobbered by map_lookup)
        assert!(!insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(!insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
    }

    #[test]
    fn test_mark_fastcall_patterns_no_match_different_regs() {
        // Pattern breaks because spill and fill use different registers
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 2, -8, 0), // spill r2
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1), // call map_lookup_elem
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 3, BPF_REG_FP as u8, -8, 0), // fill r3 (wrong!)
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // No patterns should be marked
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
    }

    #[test]
    fn test_mark_fastcall_patterns_non_fastcall_helper() {
        // tail_call is not a fastcall helper, so keep_fastcall_stack should be set
        let insns = vec![
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_FP as u8, 4, -8, 0), // spill r4
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 12), // call tail_call (uses r0,r1,r2,r3)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 4, BPF_REG_FP as u8, -8, 0), // fill r4
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut insn_aux = HashMap::new();
        let mut subprogs = vec![SubprogFastcallInfo {
            start: 0,
            end: 4,
            ..Default::default()
        }];
        let kfuncs = vec![];
        
        mark_fastcall_patterns(&insns, &mut insn_aux, &mut subprogs, &kfuncs).unwrap();
        
        // Pattern should still be marked
        assert!(insn_aux.get(&0).map_or(false, |a| a.fastcall_pattern));
        assert!(insn_aux.get(&2).map_or(false, |a| a.fastcall_pattern));
        
        // But fastcall_spills_num should NOT be set (not a fastcall helper)
        assert_eq!(insn_aux.get(&1).map_or(0, |a| a.fastcall_spills_num), 0);
        
        // And keep_fastcall_stack should be true
        assert!(subprogs[0].keep_fastcall_stack);
    }

    #[test]
    fn test_call_summary_default() {
        let cs = CallSummary::default();
        assert_eq!(cs.num_params, 0);
        assert!(!cs.is_void);
        assert!(!cs.fastcall);
    }
