// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::mem::arena

use bpf_verifier::prelude::*;
use bpf_verifier::mem::arena::*;


#[test]
fn test_arena_state() {
    let mut state = ArenaState::new();

    let info = ArenaInfo {
        id: 0,
        map_fd: 3,
        size: 4096,
        user_base: 0x7f0000000000,
        readonly: false,
        btf_id: 0,
    };

    let id = state.register(info).unwrap();
    assert!(state.exists(id));
    assert!(state.get(id).is_some());
}

#[test]
fn test_mem_region_contains() {
    let region = MemRegion::new(MemRegionType::Stack, -512, 0, true);

    assert!(region.contains(-100, 8));
    assert!(region.contains(-512, 512));
    assert!(!region.contains(-600, 8)); // Before start
    assert!(!region.contains(-8, 16)); // Crosses end
}

#[test]
fn test_mem_region_access() {
    let region = MemRegion::new(MemRegionType::MapValue, 0, 256, true);

    assert!(region.check_access(0, 8, false).is_ok());
    assert!(region.check_access(0, 8, true).is_ok());
    assert!(region.check_access(248, 8, true).is_ok());
    assert!(region.check_access(256, 8, true).is_err()); // Out of bounds
}

#[test]
fn test_readonly_region() {
    let region = MemRegion::new(MemRegionType::Context, 0, 128, false);

    assert!(region.check_access(0, 8, false).is_ok());
    assert!(region.check_access(0, 8, true).is_err()); // Write to readonly
}

#[test]
fn test_arena_region() {
    let region = MemRegion::arena(1, 4096);

    assert_eq!(region.region_type, MemRegionType::Arena);
    assert_eq!(region.arena_id, Some(1));
    assert!(region.contains(0, 4096));
    assert!(!region.contains(0, 4097));
}

#[test]
fn test_resolve_stack_access() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToStack;

    let region = resolve_mem_access(&reg, -8, 8, true).unwrap();
    assert_eq!(region.region_type, MemRegionType::Stack);
    assert!(region.writable);
}

#[test]
fn test_addr_space_cast() {
    let mut reg = BpfRegState::new_not_init();
    reg.reg_type = BpfRegType::PtrToArena;

    // Arena can be cast
    let result = check_addr_space_cast(&reg, AddressSpace::Kernel, AddressSpace::User);
    assert!(result.is_ok());

    // Non-arena cannot be cast
    reg.reg_type = BpfRegType::PtrToStack;
    let result = check_addr_space_cast(&reg, AddressSpace::Kernel, AddressSpace::User);
    assert!(result.is_err());
}

#[test]
fn test_arena_alloc_tracker() {
    let mut tracker = ArenaAllocTracker::new();

    // Allocate
    let id1 = tracker.alloc(1, 0, 4096, 0, 100);
    let id2 = tracker.alloc(1, 4096, 4096, 1, 101);

    assert!(tracker.get(id1).is_some());
    assert!(tracker.get(id2).is_some());
    assert_eq!(tracker.stats.current_allocs, 2);

    // Find allocation
    let found = tracker.find_allocation_at(1, 100, 100);
    assert!(found.is_some());
    assert_eq!(found.unwrap().alloc_id, id1);

    // Free
    assert!(tracker.free(id1).is_ok());
    assert_eq!(tracker.stats.current_allocs, 1);

    // Double free should fail
    assert!(tracker.free(id1).is_err());

    // Check leaks - should find id2 still active
    assert!(tracker.check_leaks().is_err());

    // Free remaining
    assert!(tracker.free(id2).is_ok());
    assert!(tracker.check_leaks().is_ok());
}

#[test]
fn test_arena_addr_context() {
    let ctx = ArenaAddrContext {
        arena_id: 1,
        kern_base: 0xffff_8880_0000_0000,
        user_base: 0x7f00_0000_0000,
        size: 0x1000_0000, // 256 MB
    };

    // Kernel to user translation
    let user = ctx.kern_to_user(0xffff_8880_0000_1000).unwrap();
    assert_eq!(user, 0x7f00_0000_1000);

    // User to kernel translation
    let kern = ctx.user_to_kern(0x7f00_0000_1000).unwrap();
    assert_eq!(kern, 0xffff_8880_0000_1000);

    // Out of bounds
    assert!(ctx.kern_to_user(0xffff_8880_0000_0000 + 0x1000_0000).is_err());
    assert!(ctx.user_to_kern(0x7f00_0000_0000 + 0x1000_0000).is_err());

    // Contains check
    assert!(ctx.contains_kern(0xffff_8880_0000_0000));
    assert!(!ctx.contains_kern(0xffff_8880_0000_0000 + 0x1000_0000));
    assert!(ctx.contains_user(0x7f00_0000_0000));
}

#[test]
fn test_arena_helper_detection() {
    assert!(is_arena_helper(arena_helpers::ARENA_ALLOC_PAGES));
    assert!(is_arena_helper(arena_helpers::ARENA_FREE_PAGES));
    assert!(!is_arena_helper(0));
}

#[test]
fn test_page_crossing() {
    // 4KB pages
    let page_size = 4096;

    // Within same page
    assert!(!check_arena_page_crossing(0, 100, page_size));
    assert!(!check_arena_page_crossing(4000, 96, page_size));

    // Crosses page boundary
    assert!(check_arena_page_crossing(4000, 100, page_size));
    assert!(check_arena_page_crossing(4095, 2, page_size));
}
