// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::helper_db

use bpf_verifier::prelude::*;
use bpf_verifier::check::helper_db::*;


#[test]
fn test_lookup_helper() {
    let helper = lookup_helper(BpfFuncId::MapLookupElem);
    assert!(helper.is_some());
    let helper = helper.unwrap();
    assert_eq!(helper.name, "map_lookup_elem");
    assert_eq!(helper.arg_types[0], BpfArgType::ConstMapPtr);
    assert_eq!(helper.arg_types[1], BpfArgType::PtrToMapKey);
}

#[test]
fn test_lookup_by_name() {
    let helper = lookup_helper_by_name("ktime_get_ns");
    assert!(helper.is_some());
    assert_eq!(helper.unwrap().func_id, BpfFuncId::KtimeGetNs);
}

#[test]
fn test_acquire_release_flags() {
    let reserve = lookup_helper(BpfFuncId::RingbufReserve).unwrap();
    assert!(reserve.flags.acquires_ref);
    
    let submit = lookup_helper(BpfFuncId::RingbufSubmit).unwrap();
    assert!(submit.flags.releases_ref);
}

#[test]
fn test_privileged_helpers() {
    let probe_read = lookup_helper(BpfFuncId::ProbeRead).unwrap();
    assert!(probe_read.flags.privileged);
    
    let ktime = lookup_helper(BpfFuncId::KtimeGetNs).unwrap();
    assert!(!ktime.flags.privileged);
}

#[test]
fn test_sleepable_helpers() {
    let copy_user = lookup_helper(BpfFuncId::CopyFromUser).unwrap();
    assert!(copy_user.flags.may_sleep);
}

#[test]
fn test_helper_count() {
    // Ensure we have a substantial number of helpers
    assert!(HELPER_DB.len() >= 150);
}

#[test]
fn test_to_proto() {
    let helper = lookup_helper(BpfFuncId::MapUpdateElem).unwrap();
    let proto = helper.to_proto();
    
    assert_eq!(proto.func_id, BpfFuncId::MapUpdateElem);
    assert_eq!(proto.ret_type, BpfRetType::Integer);
    assert_eq!(proto.arg_types[0], BpfArgType::ConstMapPtr);
}

#[test]
fn test_no_duplicate_helpers() {
    // Check for duplicates by comparing func_id values as u32
    let mut seen: Vec<u32> = Vec::new();
    for helper in HELPER_DB.iter() {
        let id = helper.func_id as u32;
        assert!(
            !seen.contains(&id),
            "Duplicate helper: {:?}",
            helper.func_id
        );
        seen.push(id);
    }
}
