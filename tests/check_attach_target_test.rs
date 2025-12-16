// SPDX-License-Identifier: GPL-2.0

//! Tests for attach target validation.

use bpf_verifier::check::attach_target::{
    check_extension_compatibility, is_sleepable_lsm_hook,
};

#[test]
fn test_sleepable_lsm_hook() {
    assert!(is_sleepable_lsm_hook("bpf_lsm_file_open"));
    assert!(is_sleepable_lsm_hook("bpf_lsm_socket_create"));
    assert!(!is_sleepable_lsm_hook("some_random_hook"));
}

#[test]
fn test_extension_compatibility_ok() {
    // Extension without pkt data on target without pkt data - OK
    assert!(check_extension_compatibility(false, false, false, false).is_ok());

    // Extension with pkt data on target with pkt data - OK
    assert!(check_extension_compatibility(true, false, true, false).is_ok());

    // Extension non-sleepable on sleepable target - OK
    assert!(check_extension_compatibility(false, false, false, true).is_ok());
}

#[test]
fn test_extension_compatibility_pkt_data_mismatch() {
    // Extension with pkt data on target without pkt data - ERROR
    assert!(check_extension_compatibility(true, false, false, false).is_err());
}

#[test]
fn test_extension_compatibility_sleep_mismatch() {
    // Extension sleepable on non-sleepable target - ERROR
    assert!(check_extension_compatibility(false, true, false, false).is_err());
}
