// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::user

use bpf_verifier::prelude::*;
use bpf_verifier::mem::user::*;


    fn make_user_ptr_reg() -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMem;
        reg.type_flags = BpfTypeFlag::MEM_USER;
        reg.mem_size = 4096;
        reg
    }

    fn make_kernel_ptr_reg() -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMem;
        reg.mem_size = 4096;
        reg
    }

    fn make_arena_user_ptr_reg() -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToArena;
        reg.type_flags = BpfTypeFlag::MEM_USER;
        reg
    }

    #[test]
    fn test_is_user_mem_pointer() {
        let user_reg = make_user_ptr_reg();
        let kernel_reg = make_kernel_ptr_reg();

        assert!(is_user_mem_pointer(&user_reg));
        assert!(!is_user_mem_pointer(&kernel_reg));
    }

    #[test]
    fn test_direct_access_denied_for_normal_user_ptr() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::default();

        let result = check_user_mem_direct_access(&reg, &ctx, false);
        assert!(!result.allowed);
        assert!(result.safe_alternative.is_some());
    }

    #[test]
    fn test_direct_access_allowed_for_arena_with_nospec() {
        let reg = make_arena_user_ptr_reg();
        let ctx = UserMemContext::default()
            .with_direct_access()
            .with_nospec();

        let result = check_user_mem_direct_access(&reg, &ctx, false);
        assert!(result.allowed);
        assert!(!result.needs_nospec);
    }

    #[test]
    fn test_direct_access_needs_nospec_for_arena() {
        let reg = make_arena_user_ptr_reg();
        let ctx = UserMemContext::default().with_direct_access();

        let result = check_user_mem_direct_access(&reg, &ctx, false);
        assert!(result.allowed);
        assert!(result.needs_nospec);
    }

    #[test]
    fn test_probe_read_user_always_allowed() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::default();

        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::ProbeRead,
            100,
        )
        .unwrap();

        assert!(result.allowed);
    }

    #[test]
    fn test_copy_from_user_requires_sleepable() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::default();

        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::CopyFromUser,
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_copy_from_user_allowed_in_sleepable() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::sleepable(BpfProgType::Tracing);

        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::CopyFromUser,
            100,
        )
        .unwrap();

        assert!(result.allowed);
    }

    #[test]
    fn test_probe_write_requires_privilege() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::default();

        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::ProbeWrite,
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_probe_write_allowed_privileged_kprobe() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::privileged(BpfProgType::Kprobe);

        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::ProbeWrite,
            100,
        )
        .unwrap();

        assert!(result.allowed);
    }

    #[test]
    fn test_speculation_barrier_for_user_mem() {
        let user_reg = make_user_ptr_reg();
        let kernel_reg = make_kernel_ptr_reg();

        assert!(needs_speculation_barrier(&user_reg, true));
        assert!(!needs_speculation_barrier(&kernel_reg, true));
        assert!(!needs_speculation_barrier(&user_reg, false)); // Not for stores
    }

    #[test]
    fn test_user_mem_helper_detection() {
        assert!(is_user_mem_helper(BpfFuncId::ProbeReadUser));
        assert!(is_user_mem_helper(BpfFuncId::CopyFromUser));
        assert!(!is_user_mem_helper(BpfFuncId::MapLookupElem));
    }

    #[test]
    fn test_validate_probe_read_dst_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;

        let result = validate_probe_read_user_dst(&reg, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_probe_read_dst_readonly() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMem;
        reg.type_flags = BpfTypeFlag::MEM_RDONLY;
        reg.mem_size = 1024;

        let result = validate_probe_read_user_dst(&reg, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_arena_user_access_read() {
        let reg = make_arena_user_ptr_reg();

        let result = check_arena_user_access(&reg, 0, 8, false, true).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_arena_user_access_write_denied() {
        let reg = make_arena_user_ptr_reg();

        let result = check_arena_user_access(&reg, 0, 8, true, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_mem_copy_tracker() {
        let mut tracker = UserMemCopyTracker::new();

        tracker.record_probe_read(100);
        tracker.record_probe_read(200);
        tracker.record_copy_from_user(150);

        assert_eq!(tracker.probe_read_count, 2);
        assert_eq!(tracker.copy_from_user_count, 1);
        assert_eq!(tracker.bytes_read, 450);
        assert_eq!(tracker.total_reads(), 3);
    }

    #[test]
    fn test_mark_clear_user_mem() {
        let mut reg = make_kernel_ptr_reg();

        assert!(!is_user_mem_pointer(&reg));

        mark_reg_user_mem(&mut reg);
        assert!(is_user_mem_pointer(&reg));

        clear_reg_user_mem(&mut reg);
        assert!(!is_user_mem_pointer(&reg));
    }

    #[test]
    fn test_get_user_read_helper() {
        let ctx = UserMemContext::default();
        assert_eq!(get_user_read_helper(&ctx, false), BpfFuncId::ProbeReadUser);
        assert_eq!(get_user_read_helper(&ctx, true), BpfFuncId::ProbeReadUserStr);

        let sleepable_ctx = UserMemContext::sleepable(BpfProgType::Tracing);
        assert_eq!(get_user_read_helper(&sleepable_ctx, false), BpfFuncId::CopyFromUser);
    }

    #[test]
    fn test_size_validation() {
        let reg = make_user_ptr_reg();
        let ctx = UserMemContext::default();

        // Zero size should fail
        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::ProbeRead,
            0,
        );
        assert!(result.is_err());

        // Excessive size should fail
        let result = check_user_mem_helper_access(
            &reg,
            &ctx,
            UserMemAccessType::ProbeRead,
            300 * 1024, // > 256KB
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // Tests for User Pointer Propagation
    // ========================================================================

    #[test]
    fn test_user_ptr_propagation_preserve() {
        // ADD/SUB with user dst preserves user pointer (BPF_ADD = 0x00, BPF_SUB = 0x10)
        let result = propagate_user_ptr_alu(0x00, true, false); // BPF_ADD
        assert_eq!(result, UserPtrPropagation::Preserve);

        let result = propagate_user_ptr_alu(0x10, true, false); // BPF_SUB
        assert_eq!(result, UserPtrPropagation::Preserve);
    }

    #[test]
    fn test_user_ptr_propagation_invalidate() {
        // Unknown operations should invalidate
        let result = propagate_user_ptr_alu(0x20, true, false); // LSH
        assert_eq!(result, UserPtrPropagation::Invalidate);

        let result = propagate_user_ptr_alu(0x30, true, false); // RSH
        assert_eq!(result, UserPtrPropagation::Invalidate);
    }

    #[test]
    fn test_user_ptr_propagation_mov() {
        // MOV from user src preserves, MOV from non-user converts to kernel
        let result = propagate_user_ptr_alu(0xb0, false, true); // BPF_MOV with user src
        assert_eq!(result, UserPtrPropagation::Preserve);

        let result = propagate_user_ptr_alu(0xb0, true, false); // BPF_MOV with non-user src
        assert_eq!(result, UserPtrPropagation::ToKernel);
    }

    #[test]
    fn test_apply_user_ptr_propagation() {
        let mut reg = make_user_ptr_reg();

        apply_user_ptr_propagation(&mut reg, UserPtrPropagation::Preserve);
        assert!(is_user_mem_pointer(&reg));

        apply_user_ptr_propagation(&mut reg, UserPtrPropagation::Invalidate);
        assert!(!is_user_mem_pointer(&reg));
        // Invalidate adds PTR_UNTRUSTED but doesn't change reg_type
        assert!(reg.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED));
    }

    // ========================================================================
    // Tests for User Memory Bounds Validation
    // ========================================================================

    #[test]
    fn test_user_mem_bounds_check_access() {
        // Test UserMemBounds::check_access directly
        let bounds = UserMemBounds::from_range(0, 4096);

        // Valid access within bounds
        let result = bounds.check_access(0, 100);
        assert!(result.is_ok());

        // Access at end of bounds
        let result = bounds.check_access(4000, 96);
        assert!(result.is_ok());
    }

    #[test]
    fn test_user_mem_bounds_oob_access() {
        let bounds = UserMemBounds::from_range(0, 100);

        // Access past bounds
        let result = bounds.check_access(50, 100);
        assert!(result.is_err());

        // Access exceeds max_off
        let result = bounds.check_access(0, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_mem_bounds_negative_offset() {
        let bounds = UserMemBounds::from_range(0, 4096);

        // Negative offset below min
        let result = bounds.check_access(-10, 8);
        assert!(result.is_err());
    }

    // ========================================================================
    // Tests for Memory Isolation
    // ========================================================================

    #[test]
    fn test_memory_isolation_user_to_kernel_denied() {
        let user_reg = make_user_ptr_reg();
        let kernel_reg = make_kernel_ptr_reg();

        // Mixing user and kernel pointers in Full isolation is denied
        let result = check_memory_isolation(&user_reg, &kernel_reg, MemoryIsolation::Full);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_isolation_kernel_to_kernel_allowed() {
        let kernel_reg1 = make_kernel_ptr_reg();
        let kernel_reg2 = make_kernel_ptr_reg();

        let result = check_memory_isolation(&kernel_reg1, &kernel_reg2, MemoryIsolation::Full);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_isolation_none_allows_mixing() {
        let user_reg = make_user_ptr_reg();
        let kernel_reg = make_kernel_ptr_reg();

        // None isolation allows any mixing
        let result = check_memory_isolation(&user_reg, &kernel_reg, MemoryIsolation::None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_user_ptr_store_to_map_denied() {
        let user_ptr = make_user_ptr_reg();
        let mut map_dst = BpfRegState::default();
        map_dst.reg_type = BpfRegType::PtrToMapValue;

        // Cannot store user pointer to map value without allow_ptr_leaks
        let result = check_user_ptr_store(&user_ptr, &map_dst, false);
        assert!(result.is_err());

        // Allowed with allow_ptr_leaks
        let result = check_user_ptr_store(&user_ptr, &map_dst, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_user_ptr_store_to_stack_allowed() {
        let user_ptr = make_user_ptr_reg();
        let mut stack_dst = BpfRegState::default();
        stack_dst.reg_type = BpfRegType::PtrToStack;

        // Storing user pointer to stack is always allowed
        let result = check_user_ptr_store(&user_ptr, &stack_dst, false);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Tests for Taint Analysis
    // ========================================================================

    #[test]
    fn test_taint_tracker_initial_state() {
        let tracker = UserMemTaintTracker::new();
        
        for i in 0..11 {
            assert_eq!(tracker.get_taint(i), UserMemTaint::Clean);
        }
    }

    #[test]
    fn test_taint_tracker_set_and_propagate() {
        let mut tracker = UserMemTaintTracker::new();
        
        // Mark R1 as tainted from user load
        tracker.taint_from_user_load(1);
        assert_eq!(tracker.get_taint(1), UserMemTaint::DirectUser);
        assert!(tracker.is_tainted(1));
        
        // Propagate taint from R1 to R2 via ALU
        tracker.propagate_alu(2, 1);
        assert_eq!(tracker.get_taint(2), UserMemTaint::DerivedUser);
    }

    #[test]
    fn test_taint_tracker_sanitize() {
        let mut tracker = UserMemTaintTracker::new();
        
        tracker.taint_from_user_load(1);
        tracker.mark_validated(1);
        
        assert_eq!(tracker.get_taint(1), UserMemTaint::Validated);
        assert!(!tracker.is_tainted(1));
        assert_eq!(tracker.sanitize_count, 1);
    }

    #[test]
    fn test_taint_propagation_rules() {
        let clean = UserMemTaint::Clean;
        let direct = UserMemTaint::DirectUser;
        let derived = UserMemTaint::DerivedUser;
        let validated = UserMemTaint::Validated;

        // Clean + Clean = Clean
        assert_eq!(clean.propagate(&clean), UserMemTaint::Clean);
        
        // Any + DirectUser = DerivedUser
        assert_eq!(clean.propagate(&direct), UserMemTaint::DerivedUser);
        assert_eq!(direct.propagate(&clean), UserMemTaint::DerivedUser);
        
        // Validated + Validated = Validated
        assert_eq!(validated.propagate(&validated), UserMemTaint::Validated);
        
        // Derived + anything non-clean = Derived
        assert_eq!(derived.propagate(&derived), UserMemTaint::DerivedUser);
    }

    // ========================================================================
    // Tests for Alignment Validation
    // ========================================================================

    fn make_aligned_user_ptr_reg() -> BpfRegState {
        use bpf_verifier::bounds::Tnum;
        let mut reg = make_user_ptr_reg();
        reg.off = 0;
        reg.var_off = Tnum::const_value(0); // Const var_off = aligned
        reg
    }

    #[test]
    fn test_alignment_valid() {
        let reg = make_aligned_user_ptr_reg();

        // 4-byte access at aligned offset 0
        let result = check_user_mem_alignment(&reg, 0, 4, true);
        assert!(result.is_ok());

        // 8-byte access at aligned offset 8
        let result = check_user_mem_alignment(&reg, 8, 8, true);
        assert!(result.is_ok());

        // 4-byte access at aligned offset 4
        let result = check_user_mem_alignment(&reg, 4, 4, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_alignment_invalid_strict() {
        let reg = make_aligned_user_ptr_reg();

        // 4-byte access at offset 1 (misaligned)
        let result = check_user_mem_alignment(&reg, 1, 4, true);
        assert!(result.is_err());

        // 4-byte access at offset 2 (misaligned)
        let result = check_user_mem_alignment(&reg, 2, 4, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_alignment_relaxed_allows_misaligned() {
        let reg = make_aligned_user_ptr_reg();

        // Misaligned access allowed in relaxed mode
        let result = check_user_mem_alignment(&reg, 1, 4, false);
        assert!(result.is_ok());

        let result = check_user_mem_alignment(&reg, 3, 8, false);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Tests for Fault Behavior
    // ========================================================================

    #[test]
    fn test_fault_behavior_mapping() {
        // ProbeRead returns error on fault
        assert_eq!(get_fault_behavior(UserMemAccessType::ProbeRead), UserMemFaultBehavior::ReturnError);
        // CopyFromUser fills with zeros on fault
        assert_eq!(get_fault_behavior(UserMemAccessType::CopyFromUser), UserMemFaultBehavior::FillZero);
        // DirectLoad aborts on fault
        assert_eq!(get_fault_behavior(UserMemAccessType::DirectLoad), UserMemFaultBehavior::Abort);
    }

    #[test]
    fn test_validate_fault_behavior() {
        let ctx = UserMemContext::default();

        // ReturnError should always be safe
        let result = validate_fault_behavior(UserMemFaultBehavior::ReturnError, &ctx);
        assert!(result.is_ok());

        // ReturnZero should always be safe
        let result = validate_fault_behavior(UserMemFaultBehavior::ReturnZero, &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fault_behavior_abort_requires_direct_access() {
        let ctx = UserMemContext::default();
        
        // Abort requires allow_direct_access
        let result = validate_fault_behavior(UserMemFaultBehavior::Abort, &ctx);
        assert!(result.is_err());

        // With direct access allowed, Abort is OK
        let ctx_with_direct = UserMemContext::default().with_direct_access();
        let result = validate_fault_behavior(UserMemFaultBehavior::Abort, &ctx_with_direct);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Tests for Access Pattern Validation
    // ========================================================================

    #[test]
    fn test_access_pattern_sequential() {
        // Sequential access within 4KB is OK
        let result = validate_access_pattern(
            UserMemAccessPattern::Sequential,
            UserMemAccessType::ProbeRead,
            64,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_pattern_string_requires_str_helper() {
        // String pattern with ProbeRead should suggest probe_read_str
        let result = validate_access_pattern(
            UserMemAccessPattern::String,
            UserMemAccessType::ProbeRead,
            100,
        );
        assert!(result.is_err());

        // String pattern with ProbeReadStr is OK
        let result = validate_access_pattern(
            UserMemAccessPattern::String,
            UserMemAccessType::ProbeReadStr,
            100,
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // Tests for copy_from_user_task Validation
    // ========================================================================

    #[test]
    fn test_copy_from_user_task_valid() {
        let mut task_reg = BpfRegState::default();
        task_reg.reg_type = BpfRegType::PtrToBtfId;

        let user_addr_reg = make_user_ptr_reg();

        let mut dst_reg = BpfRegState::default();
        dst_reg.reg_type = BpfRegType::PtrToStack;

        let ctx_inner = CopyFromUserTaskContext {
            task_reg: Some(task_reg),
            user_addr_reg: Some(user_addr_reg),
            dst_reg: Some(dst_reg),
            size: 100,
            flags: 0,
        };

        let verifier_ctx = UserMemContext::sleepable(BpfProgType::Tracing);

        let result = validate_copy_from_user_task(&ctx_inner, &verifier_ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_copy_from_user_task_requires_sleepable() {
        let mut task_reg = BpfRegState::default();
        task_reg.reg_type = BpfRegType::PtrToBtfId;

        let user_addr_reg = make_user_ptr_reg();

        let mut dst_reg = BpfRegState::default();
        dst_reg.reg_type = BpfRegType::PtrToStack;

        let ctx_inner = CopyFromUserTaskContext {
            task_reg: Some(task_reg),
            user_addr_reg: Some(user_addr_reg),
            dst_reg: Some(dst_reg),
            size: 100,
            flags: 0,
        };

        // Non-sleepable context should fail
        let verifier_ctx = UserMemContext::default();

        let result = validate_copy_from_user_task(&ctx_inner, &verifier_ctx);
        assert!(result.is_err());
    }

    // ========================================================================
    // Tests for Comprehensive Validation
    // ========================================================================

    #[test]
    fn test_validate_user_mem_access_complete_basic() {
        let mut src_reg = make_user_ptr_reg();
        src_reg.off = 0;
        let ctx = UserMemContext::default();

        // ProbeRead is always allowed for user memory
        let result = validate_user_mem_access_complete(
            &src_reg,
            None,
            0,
            8,
            UserMemAccessType::ProbeRead,
            &ctx,
            None, // No bounds - skip bounds check
            None,
        );
        
        assert!(result.is_ok());
        let validation = result.unwrap();
        assert!(validation.allowed);
    }

    #[test]
    fn test_validate_user_mem_access_complete_with_bounds() {
        use bpf_verifier::bounds::Tnum;
        let mut src_reg = make_user_ptr_reg();
        src_reg.off = 0;
        src_reg.var_off = Tnum::const_value(0); // Const var_off for bounds check
        let ctx = UserMemContext::default();
        let bounds = UserMemBounds::from_range(0, 4096);

        let result = validate_user_mem_access_complete(
            &src_reg,
            None,
            0,
            100,
            UserMemAccessType::ProbeRead,
            &ctx,
            Some(&bounds),
            None,
        );
        
        assert!(result.is_ok());
    }
