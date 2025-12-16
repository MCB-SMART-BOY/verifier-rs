// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::iter

use bpf_verifier::prelude::*;
use bpf_verifier::special::iter::*;
use bpf_verifier::state::StackManager;
use bpf_verifier::bounds::tnum::Tnum;

    fn make_stack_ptr_reg(off: i32) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.var_off = Tnum::const_value(0);
        reg.off = off;
        reg
    }

    #[test]
    fn test_iter_valid_uninit() {
        let reg = make_stack_ptr_reg(-24);
        let stack = StackManager::new();

        // Should be valid for uninit (stack not allocated yet)
        assert!(is_iter_reg_valid_uninit(&reg, &stack, 3));
    }

    #[test]
    fn test_iter_lifecycle() {
        let mut stack = StackManager::new();
        let mut refs = ReferenceManager::new();

        stack.grow(32).unwrap();

        let reg = make_stack_ptr_reg(-24);

        // Mark slots for iterator
        let ref_id = mark_stack_slots_iter(&mut stack, &mut refs, &reg, 100, 3, 0, false).unwrap();
        assert!(refs.has_ref(ref_id));

        // Check it's valid
        assert!(is_iter_reg_valid_init(&reg, &stack, 100, 3).is_ok());

        // Unmark (destroy)
        assert!(unmark_stack_slots_iter(&mut stack, &mut refs, &reg, 3).is_ok());
        assert!(!refs.has_ref(ref_id));
    }
