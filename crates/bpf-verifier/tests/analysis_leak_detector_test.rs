// TODO: Export internal functions for testing
#![cfg(feature = "__disabled_test__")]
#![allow(unexpected_cfgs)]
// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::analysis::leak_detector

use bpf_verifier::prelude::*;
use bpf_verifier::analysis::leak_detector::*;


#[test]
fn test_leak_detector_no_leaks() {
    let detector = LeakDetector::new();
    let result = detector.analyze();
    assert!(!result.has_leaks());
}

#[test]
fn test_reference_tracker_acquire() {
    let mut tracker = ReferenceTracker::new();
    tracker.record_acquire(0, 1, RefStateType::Ptr, "bpf_sk_lookup_tcp");
    
    assert_eq!(tracker.acquire_points.len(), 1);
    assert!(tracker.acquire_points.contains_key(&1));
}

#[test]
fn test_reference_tracker_release() {
    let mut tracker = ReferenceTracker::new();
    tracker.record_acquire(0, 1, RefStateType::Ptr, "bpf_sk_lookup_tcp");
    tracker.record_release(5, 1);
    
    assert_eq!(tracker.release_points.get(&1).unwrap().len(), 1);
}

#[test]
fn test_leak_detection_with_leak() {
    let mut detector = LeakDetector::new();
    
    // Acquire reference at insn 0
    detector.tracker_mut().record_acquire(0, 1, RefStateType::Ptr, "bpf_sk_lookup_tcp");
    
    // Record exit at insn 10 with reference still held
    detector.tracker_mut().record_exit(10);
    detector.tracker_mut().record_held_refs(10, &[1]);
    
    let result = detector.analyze();
    assert!(result.has_leaks());
    assert_eq!(result.leaks.len(), 1);
    assert_eq!(result.leaks[0].ref_id, 1);
}

#[test]
fn test_leak_detection_no_leak() {
    let mut detector = LeakDetector::new();
    
    // Acquire reference at insn 0
    detector.tracker_mut().record_acquire(0, 1, RefStateType::Ptr, "bpf_sk_lookup_tcp");
    
    // Release at insn 5
    detector.tracker_mut().record_release(5, 1);
    
    // Exit at insn 10 with no references held
    detector.tracker_mut().record_exit(10);
    // Don't record ref 1 as held at exit
    
    let result = detector.analyze();
    assert!(!result.has_leaks());
    assert_eq!(result.released_refs.len(), 1);
}

#[test]
fn test_check_at_exit_with_ptr_leak() {
    let detector = LeakDetector::new();
    let refs = vec![BpfReferenceState::new_ptr(1, 5)];
    
    let result = detector.check_at_exit(&refs, 10);
    assert!(result.is_err());
    
    if let Err(VerifierError::UnreleasedReference(id)) = result {
        assert_eq!(id, 1);
    } else {
        panic!("Expected UnreleasedReference error");
    }
}

#[test]
fn test_check_at_exit_with_lock_leak() {
    let detector = LeakDetector::new();
    let refs = vec![BpfReferenceState::new_lock(1, 5, 0x1000)];
    
    let result = detector.check_at_exit(&refs, 10);
    assert!(result.is_err());
    
    if let Err(VerifierError::InvalidLock(_)) = result {
        // Expected
    } else {
        panic!("Expected InvalidLock error");
    }
}

#[test]
fn test_check_at_exit_no_leaks() {
    let detector = LeakDetector::new();
    let refs: Vec<BpfReferenceState> = vec![];
    
    let result = detector.check_at_exit(&refs, 10);
    assert!(result.is_ok());
}

#[test]
fn test_has_unreleased_refs() {
    let refs_with_leak = vec![BpfReferenceState::new_ptr(1, 0)];
    assert!(LeakDetector::has_unreleased_refs(&refs_with_leak));
    
    let no_refs: Vec<BpfReferenceState> = vec![];
    assert!(!LeakDetector::has_unreleased_refs(&no_refs));
}

#[test]
fn test_get_leaked_ids() {
    let refs = vec![
        BpfReferenceState::new_ptr(1, 0),
        BpfReferenceState::new_lock(2, 5, 0x1000),
    ];
    
    let leaked = LeakDetector::get_leaked_ids(&refs);
    assert_eq!(leaked.len(), 2);
    assert!(leaked.contains(&1));
    assert!(leaked.contains(&2));
}

#[test]
fn test_leak_info_report() {
    let mut result = LeakDetectionResult::default();
    result.leaks.push(LeakInfo {
        ref_id: 1,
        ref_type: RefStateType::Ptr,
        acquire_insn: 5,
        leak_paths: vec![LeakPath {
            path: vec![5, 20],
            exit_insn: 20,
            is_callback_return: false,
        }],
        acquire_source: "bpf_sk_lookup_tcp".to_string(),
    });
    result.total_acquired = 1;
    result.total_released = 0;
    result.paths_analyzed = 1;

    let report = result.report();
    assert!(report.contains("1 leak(s)"));
    assert!(report.contains("ref_id=1"));
    assert!(report.contains("bpf_sk_lookup_tcp"));
}

#[test]
fn test_callback_return_leak() {
    let mut detector = LeakDetector::new();
    
    detector.tracker_mut().record_acquire(0, 1, RefStateType::Ptr, "bpf_ringbuf_reserve");
    detector.tracker_mut().record_callback_return(8);
    detector.tracker_mut().record_held_refs(8, &[1]);
    
    let result = detector.analyze();
    assert!(result.has_leaks());
    assert!(result.leaks[0].leak_paths[0].is_callback_return);
}

#[test]
fn test_is_ref_acquiring_helper() {
    // sk_lookup_tcp = 84
    assert!(is_ref_acquiring_helper(84));
    // Some non-ref helper
    assert!(!is_ref_acquiring_helper(1)); // map_lookup_elem
}

#[test]
fn test_is_ref_releasing_helper() {
    // sk_release = 86
    assert!(is_ref_releasing_helper(86));
    // Some non-release helper
    assert!(!is_ref_releasing_helper(1)); // map_lookup_elem
}
