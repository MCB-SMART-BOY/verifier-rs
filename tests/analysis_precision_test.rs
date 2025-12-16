// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::precision

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::precision::*;


    #[test]
    fn test_backtrack_state() {
        let mut bt = BacktrackState::new();
        
        bt.set_reg(0, 1);
        assert!(bt.is_reg_set(0, 1));
        assert!(!bt.is_reg_set(0, 2));
        
        bt.clear_reg(0, 1);
        assert!(!bt.is_reg_set(0, 1));
    }

    #[test]
    fn test_backtrack_stack_slots() {
        let mut bt = BacktrackState::new();
        
        bt.set_slot(0, 5);
        assert!(bt.is_slot_set(0, 5));
        assert!(!bt.is_slot_set(0, 6));
        
        bt.clear_slot(0, 5);
        assert!(!bt.is_slot_set(0, 5));
    }

    #[test]
    fn test_backtrack_mov() {
        let mut bt = BacktrackState::new();
        bt.set_reg(0, 0); // R0 needs precision
        
        // MOV R0, R1 - precision should transfer to R1
        let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0);
        backtrack_alu(&mut bt, &insn, 0, 1).unwrap();
        
        assert!(!bt.is_reg_set(0, 0)); // R0 cleared
        assert!(bt.is_reg_set(0, 1));  // R1 now needs precision
    }

    #[test]
    fn test_backtrack_mov_imm() {
        let mut bt = BacktrackState::new();
        bt.set_reg(0, 0); // R0 needs precision
        
        // MOV R0, 42 - precision satisfied (immediate)
        let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42);
        backtrack_alu(&mut bt, &insn, 0, 0).unwrap();
        
        assert!(!bt.is_reg_set(0, 0)); // R0 cleared
    }

    #[test]
    fn test_backtrack_add() {
        let mut bt = BacktrackState::new();
        bt.set_reg(0, 0); // R0 needs precision
        
        // ADD R0, R1 - both contribute
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0);
        backtrack_alu(&mut bt, &insn, 0, 1).unwrap();
        
        assert!(bt.is_reg_set(0, 0)); // R0 still needed (input)
        assert!(bt.is_reg_set(0, 1)); // R1 now needs precision
    }

    #[test]
    fn test_backtrack_add_imm() {
        let mut bt = BacktrackState::new();
        bt.set_reg(0, 0); // R0 needs precision
        
        // ADD R0, 10 - only R0 matters
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 10);
        backtrack_alu(&mut bt, &insn, 0, 0).unwrap();
        
        assert!(bt.is_reg_set(0, 0)); // R0 still needed (input)
    }

    #[test]
    fn test_backtrack_insn_ldx() {
        let mut bt = BacktrackState::new();
        bt.set_reg(0, 0); // R0 needs precision
        
        // LDX R0, [R10-8] - load from stack
        let insn = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, BPF_REG_FP as u8, -8, 0);
        backtrack_insn(&mut bt, &insn, 0, 0).unwrap();
        
        assert!(!bt.is_reg_set(0, 0)); // R0 cleared
        assert!(bt.is_slot_set(0, 0)); // Stack slot 0 needs precision
    }

    #[test]
    fn test_backtracker() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10), // r1 = 10
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5),  // r1 += 5
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),  // r0 = r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let mut state = BpfVerifierState::new();
        // Add jump history
        state.push_jmp_history(0, 0, 0);
        state.push_jmp_history(1, 0, 0);
        state.push_jmp_history(2, 1, 0);
        
        let mut backtracker = PrecisionBacktracker::new(&insns);
        backtracker.mark_reg_precise(0, 0); // Mark R0 as needing precision
        
        backtracker.backtrack(&mut state).unwrap();
    }

    #[test]
    fn test_collect_linked() {
        let mut state = BpfVerifierState::new();
        
        // Set up two registers with same ID
        if let Some(func) = state.cur_func_mut() {
            func.regs[1].id = 100;
            func.regs[1].reg_type = BpfRegType::ScalarValue;
            func.regs[2].id = 100;
            func.regs[2].reg_type = BpfRegType::ScalarValue;
            func.regs[3].id = 200; // Different ID
        }
        
        let linked = collect_linked_regs(&state, 0, 1);
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0], (0, 2));
    }

    #[test]
    fn test_reg_needs_precision() {
        let mut state = BpfVerifierState::new();
        
        if let Some(func) = state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].precise = true;
            func.regs[1].reg_type = BpfRegType::ScalarValue;
            func.regs[1].precise = false;
        }
        
        assert!(reg_needs_precision(&state, 0));
        assert!(!reg_needs_precision(&state, 1));
    }

    #[test]
    fn test_mark_all_scalars_precise() {
        let mut state = BpfVerifierState::new();
        
        if let Some(func) = state.cur_func_mut() {
            func.regs[0].reg_type = BpfRegType::ScalarValue;
            func.regs[0].precise = false;
            func.regs[1].reg_type = BpfRegType::ScalarValue;
            func.regs[1].precise = false;
            func.regs[2].reg_type = BpfRegType::PtrToCtx; // Not scalar
        }
        
        mark_all_scalars_precise(&mut state);
        
        if let Some(func) = state.cur_func() {
            assert!(func.regs[0].precise);
            assert!(func.regs[1].precise);
            assert!(!func.regs[2].precise); // Pointers don't get marked
        }
    }
