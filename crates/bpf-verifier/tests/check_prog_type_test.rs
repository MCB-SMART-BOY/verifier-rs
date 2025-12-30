// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::check::prog_type

use bpf_verifier::prelude::*;
use bpf_verifier::check::prog_type::*;


#[test]
fn test_xdp_info() {
    let info = get_prog_type_info(BpfProgType::Xdp);
    assert_eq!(info.prog_type, BpfProgType::Xdp);
    assert!(info.has_direct_packet_access);
    assert!(info.can_tail_call);
    assert_eq!(info.ret_range.minval, xdp_action::XDP_ABORTED);
    assert_eq!(info.ret_range.maxval, xdp_action::XDP_REDIRECT);
}

#[test]
fn test_socket_filter_info() {
    let info = get_prog_type_info(BpfProgType::SocketFilter);
    assert_eq!(info.prog_type, BpfProgType::SocketFilter);
    assert!(info.has_direct_packet_access);
    assert!(info.can_tail_call);
    assert!(!info.ctx_fields.is_empty());
}

#[test]
fn test_kprobe_info() {
    let info = get_prog_type_info(BpfProgType::Kprobe);
    assert!(!info.has_direct_packet_access);
    assert!(info.can_access_kernel_mem);
    assert!(info.allowed_helpers.contains(&BpfFuncId::ProbeRead));
}

#[test]
fn test_tracing_info() {
    let info = get_prog_type_info(BpfProgType::Tracing);
    assert!(info.can_access_kernel_mem);
    assert!(info.is_sleepable);
    assert!(info.allowed_helpers.contains(&BpfFuncId::RingbufReserve));
}

#[test]
fn test_validator_helper_allowed() {
    let validator = ProgTypeValidator::new(BpfProgType::Xdp);
    assert!(validator.is_helper_allowed(BpfFuncId::MapLookupElem));
    assert!(validator.is_helper_allowed(BpfFuncId::XdpAdjustHead));
    assert!(!validator.is_helper_allowed(BpfFuncId::ProbeRead));
}

#[test]
fn test_validator_return_value() {
    let validator = ProgTypeValidator::new(BpfProgType::Xdp);
    assert!(validator.validate_return_value(xdp_action::XDP_PASS).is_ok());
    assert!(validator.validate_return_value(xdp_action::XDP_DROP).is_ok());
    assert!(validator.validate_return_value(100).is_err());
    assert!(validator.validate_return_value(-1).is_err());
}

#[test]
fn test_validator_ctx_access() {
    let validator = ProgTypeValidator::new(BpfProgType::Xdp);
    
    // data field at offset 0
    let result = validator.validate_ctx_access(xdp_md::DATA, 4, false);
    assert!(result.is_ok());
    
    // Write to read-only field should fail
    let result = validator.validate_ctx_access(xdp_md::DATA, 4, true);
    assert!(result.is_err());
}

#[test]
fn test_validator_program_size() {
    let validator = ProgTypeValidator::new(BpfProgType::SocketFilter);
    assert!(validator.validate_program_size(1000).is_ok());
    assert!(validator.validate_program_size(5000).is_err()); // > 4096
}

#[test]
fn test_tc_program_helpers() {
    let validator = ProgTypeValidator::new(BpfProgType::SchedCls);
    assert!(validator.is_helper_allowed(BpfFuncId::SkbStoreBytes));
    assert!(validator.is_helper_allowed(BpfFuncId::Redirect));
    assert!(validator.is_helper_allowed(BpfFuncId::FibLookup));
}

#[test]
fn test_lsm_capabilities() {
    let validator = ProgTypeValidator::new(BpfProgType::Lsm);
    assert!(validator.is_sleepable());
    assert!(validator.can_access_kernel_mem());
    assert!(validator.can_use_spinlock());
    assert!(!validator.can_tail_call());
}

#[test]
fn test_sock_ops_capabilities() {
    let validator = ProgTypeValidator::new(BpfProgType::SockOps);
    assert!(validator.can_use_spinlock());
    assert!(!validator.can_tail_call());
    assert!(validator.is_helper_allowed(BpfFuncId::SockHashUpdate));
}

#[test]
fn test_return_range_validation() {
    let validator = ProgTypeValidator::new(BpfProgType::Xdp);
    
    // Valid range overlapping with allowed
    assert!(validator.validate_return_range(0, 2).is_ok());
    
    // Invalid range outside allowed
    assert!(validator.validate_return_range(10, 20).is_err());
    assert!(validator.validate_return_range(-10, -5).is_err());
}

#[test]
fn test_netfilter_info() {
    let info = get_prog_type_info(BpfProgType::Netfilter);
    assert!(info.has_direct_packet_access);
    assert!(info.can_use_spinlock);
    assert!(!info.can_tail_call);
}

#[test]
fn test_struct_ops_info() {
    let info = get_prog_type_info(BpfProgType::StructOps);
    assert!(info.can_access_kernel_mem);
    assert!(info.can_use_spinlock);
    assert!(!info.is_sleepable);
}

#[test]
fn test_flow_dissector_limited_helpers() {
    let validator = ProgTypeValidator::new(BpfProgType::FlowDissector);
    assert!(validator.is_helper_allowed(BpfFuncId::SkbLoadBytes));
    // Map ops are always allowed
    assert!(validator.is_helper_allowed(BpfFuncId::MapLookupElem));
    // But most other helpers are not
    assert!(!validator.is_helper_allowed(BpfFuncId::GetCurrentPidTgid));
}
