// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::ctx_access

use bpf_verifier::prelude::*;
use bpf_verifier::opt::ctx_access::*;


#[test]
fn test_ctx_conv_config_socket_filter() {
    let config = CtxConvConfig::for_socket_filter();
    assert_eq!(config.prog_type, BpfProgType::SocketFilter);
    assert!(!config.write_ok);
    assert!(config.narrow_load_ok);
    assert!(!config.field_map.is_empty());
}

#[test]
fn test_ctx_conv_config_xdp() {
    let config = CtxConvConfig::for_xdp();
    assert_eq!(config.prog_type, BpfProgType::Xdp);
    assert!(!config.field_map.is_empty());
}

#[test]
fn test_find_mapping() {
    let config = CtxConvConfig::for_socket_filter();
    
    // len field at offset 0
    let mapping = config.find_mapping(0, 4);
    assert!(mapping.is_some());
    let m = mapping.unwrap();
    assert_eq!(m.ctx_off, 0);
    assert_eq!(m.ctx_size, 4);
    
    // protocol field at offset 16
    let mapping = config.find_mapping(16, 4);
    assert!(mapping.is_some());
    
    // Non-existent field
    let mapping = config.find_mapping(1000, 4);
    assert!(mapping.is_none());
}

#[test]
fn test_ctx_access_info() {
    let access = CtxAccessInfo {
        insn_idx: 5,
        off: 16,
        size: 4,
        is_write: false,
        ctx_reg: 1,
    };
    
    assert_eq!(access.insn_idx, 5);
    assert_eq!(access.off, 16);
    assert!(!access.is_write);
}

#[test]
fn test_ctx_conv_result_default() {
    let result = CtxConvResult::default();
    assert_eq!(result.accesses_converted, 0);
    assert_eq!(result.helper_calls_added, 0);
    assert_eq!(result.swaps_added, 0);
    assert_eq!(result.insns_added, 0);
}

#[test]
fn test_convert_ctx_accesses_empty() {
    let mut insns = vec![
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    let config = CtxConvConfig::for_socket_filter();
    let accesses = Vec::new();
    
    let result = convert_ctx_accesses(&mut insns, &config, &accesses).unwrap();
    assert_eq!(result.accesses_converted, 0);
}

#[test]
fn test_collect_ctx_accesses() {
    let insns = vec![
        BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, 0, 1, 0, 0),  // load from ctx
        BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    
    // Mark R1 as context at instruction 0
    let ctx_reg_at_insn = vec![Some(1), None, None];
    
    let accesses = collect_ctx_accesses(&insns, &ctx_reg_at_insn);
    assert_eq!(accesses.len(), 1);
    assert_eq!(accesses[0].insn_idx, 0);
    assert_eq!(accesses[0].ctx_reg, 1);
    assert_eq!(accesses[0].size, 4);
}

#[test]
fn test_convert_direct_access() {
    let insn = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, 0, 1, 0, 0);
    let access = CtxAccessInfo {
        insn_idx: 0,
        off: 0,
        size: 4,
        is_write: false,
        ctx_reg: 1,
    };
    let mapping = CtxFieldMapping {
        ctx_off: 0,
        ctx_size: 4,
        target_off: 104,
        target_size: 4,
        read_only: true,
        conv: CtxConvType::Direct,
    };
    
    let patches = convert_direct_access(&insn, 0, &access, &mapping).unwrap();
    assert_eq!(patches.len(), 1);
}

#[test]
fn test_ctx_conv_type() {
    assert_eq!(CtxConvType::Direct, CtxConvType::Direct);
    assert_ne!(CtxConvType::Direct, CtxConvType::LoadSwap);
    assert_ne!(CtxConvType::Direct, CtxConvType::Denied);
}

#[test]
fn test_field_mapping_read_only() {
    let config = CtxConvConfig::for_socket_filter();
    
    // len field should be read-only
    let mapping = config.find_mapping(0, 4).unwrap();
    assert!(mapping.read_only);
    
    // mark field should be writable
    let mapping = config.find_mapping(8, 4).unwrap();
    assert!(!mapping.read_only);
}

#[test]
fn test_skb_offsets_default() {
    let offsets = SkbOffsets::default();
    assert_eq!(offsets.len, 104);
    assert_eq!(offsets.data, 192);
    assert_eq!(offsets.tail, 200);
}

#[test]
fn test_skb_offsets_versions() {
    let v6 = SkbOffsets::linux_6_x_x86_64();
    let v5 = SkbOffsets::linux_5_x_x86_64();
    let v4 = SkbOffsets::linux_4_x_x86_64();
    
    // Offsets differ between versions
    assert_ne!(v6.data, v5.data);
    assert_ne!(v5.data, v4.data);
    
    // Each version should have sensible values
    assert!(v6.len > 0);
    assert!(v5.len > 0);
    assert!(v4.len > 0);
}

#[test]
fn test_skb_offsets_custom() {
    let custom = SkbOffsets::custom(
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150
    );
    assert_eq!(custom.len, 10);
    assert_eq!(custom.pkt_type, 20);
    assert_eq!(custom.mark, 30);
    assert_eq!(custom.data, 100);
    assert_eq!(custom.tail, 110);
    assert_eq!(custom.tc_index, 120);
    assert_eq!(custom.hash, 130);
    assert_eq!(custom.cb, 140);
    assert_eq!(custom.tc_classid, 150);
}

#[test]
fn test_xdp_offsets() {
    let v6 = XdpOffsets::linux_6_x();
    let v5 = XdpOffsets::linux_5_x();
    
    // XDP buffer layout is stable
    assert_eq!(v6.data, 0);
    assert_eq!(v6.data_end, 8);
    assert_eq!(v5.data, 0);
    assert_eq!(v5.data_end, 8);
}

#[test]
fn test_kernel_offsets_for_version() {
    let k6 = KernelOffsets::for_kernel(6, 1, "x86_64");
    let k5 = KernelOffsets::for_kernel(5, 15, "x86_64");
    let k4 = KernelOffsets::for_kernel(4, 19, "x86_64");
    
    // Verify each version uses appropriate offsets
    assert_eq!(k6.skb.len, SkbOffsets::linux_6_x_x86_64().len);
    assert_eq!(k5.skb.len, SkbOffsets::linux_5_x_x86_64().len);
    assert_eq!(k4.skb.len, SkbOffsets::linux_4_x_x86_64().len);
}

#[test]
fn test_kernel_offsets_detect() {
    let detected = KernelOffsets::detect();
    // Should return valid offsets
    assert!(detected.skb.len > 0);
    assert!(detected.xdp.data_end > detected.xdp.data);
}

#[test]
fn test_kernel_offsets_arch() {
    let x86 = KernelOffsets::for_kernel(6, 0, "x86_64");
    let arm = KernelOffsets::for_kernel(6, 0, "aarch64");
    
    // Both should have valid offsets
    assert!(x86.skb.len > 0);
    assert!(arm.skb.len > 0);
}

// ========== Heuristic Optimization Tests ==========

#[test]
fn test_access_pattern_single() {
    let accesses = vec![
        CtxAccessInfo {
            insn_idx: 0,
            off: 0,
            size: 4,
            is_write: false,
            ctx_reg: 1,
        },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert_eq!(heuristics.pattern, AccessPattern::Single);
}

#[test]
fn test_access_pattern_sequential() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 4, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 8, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert_eq!(heuristics.pattern, AccessPattern::Sequential);
}

#[test]
fn test_access_pattern_strided() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 16, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert_eq!(heuristics.pattern, AccessPattern::Strided(8));
}

#[test]
fn test_access_pattern_loop_based() {
    // Loop-based pattern: same offsets repeated many times with irregular strides
    // After sorting by offset, the strides should be non-uniform to avoid Strided detection
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 3, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 4, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 5, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 6, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 7, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 8, off: 20, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 9, off: 20, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    // 3 unique offsets (0, 8, 20), 10 accesses -> 3 < 10/2 = 5, so LoopBased
    // Sorted: 0,0,0,0,8,8,8,8,20,20 -> strides: 0,0,0,8,0,0,0,12,0 (non-uniform)
    assert_eq!(heuristics.pattern, AccessPattern::LoopBased);
}

#[test]
fn test_access_heuristics_empty() {
    let accesses: Vec<CtxAccessInfo> = vec![];
    let heuristics = AccessHeuristics::analyze(&accesses);
    
    assert_eq!(heuristics.pattern, AccessPattern::Single);
    assert!(heuristics.access_frequency.is_empty());
    assert!(!heuristics.coalesce_benefit);
}

#[test]
fn test_access_frequency() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 3, off: 4, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert_eq!(*heuristics.access_frequency.get(&0).unwrap(), 3);
    assert_eq!(*heuristics.access_frequency.get(&4).unwrap(), 1);
}

#[test]
fn test_cache_lines_touched() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 64, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 128, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert_eq!(heuristics.cache_lines_touched, 3);
}

#[test]
fn test_field_affinity() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 8, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 16, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert!(!heuristics.field_affinity.is_empty());
    // 0 and 8 should have affinity (within window)
    assert!(heuristics.field_affinity.contains(&(0, 8)));
}

#[test]
fn test_coalesce_benefit_detection() {
    // Adjacent small accesses - should benefit
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 2, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 2, size: 2, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert!(heuristics.coalesce_benefit);
}

#[test]
fn test_no_coalesce_benefit_for_writes() {
    // Writes shouldn't trigger coalesce
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 2, is_write: true, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 2, size: 2, is_write: true, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    assert!(!heuristics.coalesce_benefit);
}

#[test]
fn test_ctx_opt_config_default() {
    let config = CtxOptConfig::default();
    assert!(config.enable_coalescing);
    assert!(config.enable_dce);
    assert!(!config.enable_reordering);
    assert!(!config.enable_speculation);
    assert_eq!(config.max_coalesce_size, 8);
}

#[test]
fn test_ctx_opt_config_aggressive() {
    let config = CtxOptConfig::aggressive();
    assert!(config.enable_coalescing);
    assert!(config.enable_dce);
    assert!(config.enable_reordering);
    assert!(config.enable_speculation);
}

#[test]
fn test_ctx_opt_config_conservative() {
    let config = CtxOptConfig::conservative();
    assert!(!config.enable_coalescing);
    assert!(!config.enable_dce);
    assert!(!config.enable_reordering);
    assert!(!config.enable_speculation);
}

#[test]
fn test_optimize_ctx_accesses_empty() {
    let accesses: Vec<CtxAccessInfo> = vec![];
    let config = CtxOptConfig::default();
    
    let result = optimize_ctx_accesses(&accesses, &config);
    assert_eq!(result.accesses_coalesced, 0);
}

#[test]
fn test_optimize_ctx_accesses_with_coalescing() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 2, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 2, size: 2, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 4, size: 2, is_write: false, ctx_reg: 1 },
    ];
    let config = CtxOptConfig::default();
    
    let result = optimize_ctx_accesses(&accesses, &config);
    // Pattern should be detected
    assert!(result.pattern.is_some());
    assert!(result.heuristics.is_some());
}

#[test]
fn test_find_coalesce_opportunities() {
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 2, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 2, size: 2, is_write: false, ctx_reg: 1 },
    ];
    let config = CtxOptConfig::default();
    
    let coalesced = find_coalesce_opportunities(&accesses, &config);
    assert_eq!(coalesced.len(), 1);
    assert_eq!(coalesced[0].start_off, 0);
    assert_eq!(coalesced[0].total_size, 4);
}

#[test]
fn test_find_coalesce_no_opportunity() {
    // Far apart accesses - no coalesce
    let accesses = vec![
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 100, size: 4, is_write: false, ctx_reg: 1 },
    ];
    let config = CtxOptConfig::default();
    
    let coalesced = find_coalesce_opportunities(&accesses, &config);
    assert!(coalesced.is_empty());
}

#[test]
fn test_dead_access_reason() {
    assert_eq!(DeadAccessReason::OverwrittenBeforeUse, DeadAccessReason::OverwrittenBeforeUse);
    assert_ne!(DeadAccessReason::OverwrittenBeforeUse, DeadAccessReason::NeverUsed);
    assert_ne!(DeadAccessReason::NeverUsed, DeadAccessReason::RedundantLoad);
}

#[test]
fn test_find_dead_accesses_empty() {
    let accesses: Vec<CtxAccessInfo> = vec![];
    let insns = vec![
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ];
    
    let dead = find_dead_accesses(&accesses, &insns);
    assert!(dead.is_empty());
}

#[test]
fn test_ctx_access_cache_new() {
    let cache = CtxAccessCache::new();
    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 0);
}

#[test]
fn test_ctx_access_cache_insert_get() {
    let mut cache = CtxAccessCache::new();
    
    let access = CtxFieldAccess {
        ctx_off: 0,
        size: 4,
        is_write: false,
        converted_off: 104,
        conv_type: CtxConvType::Direct,
    };
    
    cache.insert(0, 4, access);
    
    // First lookup - should hit
    let result = cache.get(0, 4);
    assert!(result.is_some());
    assert_eq!(cache.hits, 1);
    
    // Lookup non-existent - should miss
    let result = cache.get(8, 4);
    assert!(result.is_none());
    assert_eq!(cache.misses, 1);
}

#[test]
fn test_ctx_access_cache_clear() {
    let mut cache = CtxAccessCache::new();
    
    let access = CtxFieldAccess {
        ctx_off: 0,
        size: 4,
        is_write: false,
        converted_off: 104,
        conv_type: CtxConvType::Direct,
    };
    
    cache.insert(0, 4, access);
    let _ = cache.get(0, 4);
    
    cache.clear();
    
    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 0);
    assert!(cache.get(0, 4).is_none());
}

#[test]
fn test_ctx_access_cache_hit_rate() {
    let mut cache = CtxAccessCache::new();
    
    // Empty cache - 0 hit rate
    assert_eq!(cache.hit_rate(), 0.0);
    
    let access = CtxFieldAccess {
        ctx_off: 0,
        size: 4,
        is_write: false,
        converted_off: 104,
        conv_type: CtxConvType::Direct,
    };
    
    cache.insert(0, 4, access);
    
    // 1 hit, 1 miss = 50%
    let _ = cache.get(0, 4);
    let _ = cache.get(8, 4);
    assert_eq!(cache.hit_rate(), 0.5);
}

#[test]
fn test_speculative_preconvert_socket_filter() {
    let heuristics = AccessHeuristics::default();
    
    let fields = speculative_preconvert(BpfProgType::SocketFilter, &heuristics);
    
    // Should include common network fields
    assert!(fields.contains(&0));  // len
    assert!(fields.contains(&16)); // protocol
    assert!(fields.contains(&8));  // mark
}

#[test]
fn test_speculative_preconvert_xdp() {
    let heuristics = AccessHeuristics::default();
    
    let fields = speculative_preconvert(BpfProgType::Xdp, &heuristics);
    
    // Should include XDP common fields
    assert!(fields.contains(&0)); // data
    assert!(fields.contains(&4)); // data_end
    assert!(fields.contains(&8)); // data_meta
}

#[test]
fn test_speculative_preconvert_with_hot_fields() {
    let mut heuristics = AccessHeuristics::default();
    heuristics.hot_fields = vec![100, 200];
    
    let fields = speculative_preconvert(BpfProgType::SocketFilter, &heuristics);
    
    // Should include hot fields
    assert!(fields.contains(&100));
    assert!(fields.contains(&200));
}

#[test]
fn test_speculative_preconvert_with_affinity() {
    let mut heuristics = AccessHeuristics::default();
    heuristics.hot_fields = vec![0];
    heuristics.field_affinity = vec![(0, 50)];
    
    let fields = speculative_preconvert(BpfProgType::SocketFilter, &heuristics);
    
    // Should include field 50 due to affinity with hot field 0
    assert!(fields.contains(&0));
    assert!(fields.contains(&50));
}

#[test]
fn test_coalesced_access_structure() {
    let coalesced = CoalescedAccess {
        start_off: 0,
        total_size: 8,
        original_accesses: vec![0, 1, 2],
        extract_masks: vec![(0, 0xFFFF), (16, 0xFFFF), (32, 0xFFFFFFFF)],
    };
    
    assert_eq!(coalesced.start_off, 0);
    assert_eq!(coalesced.total_size, 8);
    assert_eq!(coalesced.original_accesses.len(), 3);
    assert_eq!(coalesced.extract_masks.len(), 3);
}

#[test]
fn test_ctx_opt_result_default() {
    let result = CtxOptResult::default();
    assert_eq!(result.accesses_coalesced, 0);
    assert_eq!(result.dead_accesses_removed, 0);
    assert_eq!(result.accesses_reordered, 0);
    assert_eq!(result.insns_saved, 0);
    assert!(result.pattern.is_none());
    assert!(result.heuristics.is_none());
}

#[test]
fn test_hot_cold_field_classification() {
    let accesses = vec![
        // Access offset 0 many times (hot)
        CtxAccessInfo { insn_idx: 0, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 1, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 2, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        CtxAccessInfo { insn_idx: 3, off: 0, size: 4, is_write: false, ctx_reg: 1 },
        // Access offset 100 once (cold)
        CtxAccessInfo { insn_idx: 4, off: 100, size: 4, is_write: false, ctx_reg: 1 },
    ];
    
    let heuristics = AccessHeuristics::analyze(&accesses);
    
    // Offset 0 should be hot
    assert!(heuristics.hot_fields.contains(&0));
    // Offset 100 should be cold
    assert!(heuristics.cold_fields.contains(&100));
}
