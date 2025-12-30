// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::states_equal

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::states_equal::*;

use bpf_verifier::bounds::tnum::Tnum;

#[test]
fn test_idmap_basic() {
    let mut idmap = IdMap::new();
    
    // ID 0 always matches
    assert!(idmap.check_ids(0, 0));
    assert!(idmap.check_ids(5, 0));
    
    // First mapping
    assert!(idmap.check_ids(1, 10));
    
    // Same mapping again
    assert!(idmap.check_ids(1, 10));
    
    // Different cur_id for same old_id - fails
    assert!(!idmap.check_ids(2, 10));
}

#[test]
fn test_regsafe_not_init() {
    let config = CompareConfig::for_pruning();
    let mut idmap = IdMap::new();
    
    let cur = BpfRegState::default();
    let old = BpfRegState::default();
    
    // Both NOT_INIT
    assert!(regsafe(&cur, &old, &config, &mut idmap));
}

#[test]
fn test_regsafe_scalar_subsumption() {
    let config = CompareConfig::for_pruning();
    let mut idmap = IdMap::new();
    
    let mut cur = BpfRegState::default();
    cur.reg_type = BpfRegType::ScalarValue;
    cur.umin_value = 10;
    cur.umax_value = 20;
    cur.smin_value = 10;
    cur.smax_value = 20;
    cur.u32_min_value = 10;
    cur.u32_max_value = 20;
    cur.s32_min_value = 10;
    cur.s32_max_value = 20;
    cur.var_off = Tnum::range(10, 20);
    
    let mut old = BpfRegState::default();
    old.reg_type = BpfRegType::ScalarValue;
    old.umin_value = 0;
    old.umax_value = 100;
    old.smin_value = 0;
    old.smax_value = 100;
    old.u32_min_value = 0;
    old.u32_max_value = 100;
    old.s32_min_value = 0;
    old.s32_max_value = 100;
    old.var_off = Tnum::unknown();
    
    // cur is within old's range - safe
    assert!(regsafe(&cur, &old, &config, &mut idmap));
    
    // Swap - old is NOT within cur's range
    assert!(!regsafe(&old, &cur, &config, &mut idmap));
}

#[test]
fn test_regsafe_scalar_exact() {
    let config = CompareConfig::for_loop_detection();
    let mut idmap = IdMap::new();
    
    let mut reg1 = BpfRegState::default();
    reg1.reg_type = BpfRegType::ScalarValue;
    reg1.umin_value = 10;
    reg1.umax_value = 20;
    reg1.smin_value = 10;
    reg1.smax_value = 20;
    reg1.var_off = Tnum::range(10, 20);
    
    let reg2 = reg1.clone();
    
    // Exact match
    assert!(regsafe(&reg1, &reg2, &config, &mut idmap));
    
    // Modify one - no longer matches
    reg1.umax_value = 21;
    assert!(!regsafe(&reg1, &reg2, &config, &mut idmap));
}

#[test]
fn test_states_equal_basic() {
    let config = CompareConfig::for_pruning();
    
    let state1 = BpfVerifierState::new();
    let state2 = BpfVerifierState::new();
    
    assert!(states_equal_with_config(&state1, &state2, &config));
}

#[test]
fn test_states_equal_different_frames() {
    let config = CompareConfig::for_pruning();
    
    let mut state1 = BpfVerifierState::new();
    let state2 = BpfVerifierState::new();
    
    state1.curframe = 1;
    
    assert!(!states_equal_with_config(&state1, &state2, &config));
}

#[test]
fn test_stackslot_safe_spill() {
    let config = CompareConfig::for_pruning();
    let mut idmap = IdMap::new();
    
    let mut cur = BpfStackState::default();
    cur.slot_type[BPF_REG_SIZE - 1] = BpfStackSlotType::Spill;
    cur.spilled_ptr.reg_type = BpfRegType::ScalarValue;
    cur.spilled_ptr.umin_value = 10;
    cur.spilled_ptr.umax_value = 20;
    
    let mut old = BpfStackState::default();
    old.slot_type[BPF_REG_SIZE - 1] = BpfStackSlotType::Spill;
    old.spilled_ptr.reg_type = BpfRegType::ScalarValue;
    old.spilled_ptr.umin_value = 0;
    old.spilled_ptr.umax_value = 100;
    
    assert!(stackslot_safe(&cur, &old, &config, &mut idmap));
}

#[test]
fn test_compare_config_modes() {
    let pruning = CompareConfig::for_pruning();
    assert!(!pruning.exact());
    assert!(pruning.check_precision);
    
    let loop_detect = CompareConfig::for_loop_detection();
    assert!(loop_detect.exact());
    assert!(!loop_detect.check_precision);

    let range_within = CompareConfig::for_range_within();
    assert!(range_within.range_within());
    assert!(!range_within.exact());
    assert!(!range_within.check_precision);
}
