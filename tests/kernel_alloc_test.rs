// SPDX-License-Identifier: GPL-2.0

//! Tests for kernel allocation utilities.

#![cfg(feature = "kernel")]

use bpf_verifier::kernel::alloc::{AllocStats, GfpFlags, next_power_of_two};

#[test]
fn test_alloc_stats() {
    let mut stats = AllocStats::new();

    stats.record_alloc(100);
    assert_eq!(stats.allocs, 1);
    assert_eq!(stats.current_bytes, 100);
    assert_eq!(stats.peak_bytes, 100);

    stats.record_alloc(200);
    assert_eq!(stats.allocs, 2);
    assert_eq!(stats.current_bytes, 300);
    assert_eq!(stats.peak_bytes, 300);

    stats.record_free(100);
    assert_eq!(stats.frees, 1);
    assert_eq!(stats.current_bytes, 200);
    assert_eq!(stats.peak_bytes, 300);

    assert!(stats.has_potential_leak());
    assert_eq!(stats.outstanding(), 1);
}

#[test]
fn test_gfp_flags() {
    let flags = GfpFlags::GFP_KERNEL.or(GfpFlags::__GFP_ZERO);
    assert_ne!(flags.raw(), 0);
}

#[test]
fn test_next_power_of_two() {
    assert_eq!(next_power_of_two(0), 1);
    assert_eq!(next_power_of_two(1), 1);
    assert_eq!(next_power_of_two(2), 2);
    assert_eq!(next_power_of_two(3), 4);
    assert_eq!(next_power_of_two(5), 8);
    assert_eq!(next_power_of_two(17), 32);
}
