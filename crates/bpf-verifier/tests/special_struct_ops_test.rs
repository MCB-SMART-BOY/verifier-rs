// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::special::struct_ops

use bpf_verifier::prelude::*;
use bpf_verifier::special::struct_ops::*;


#[test]
fn test_struct_ops_type_sleepable() {
    assert!(!StructOpsType::TcpCongestionOps.supports_sleepable());
    assert!(StructOpsType::SchedExtOps.supports_sleepable());
    assert!(StructOpsType::HidBpfOps.supports_sleepable());
}

#[test]
fn test_struct_ops_context() {
    let ctx = tcp_congestion_ops::init_context(100, 1);

    assert_eq!(ctx.ops_type, StructOpsType::TcpCongestionOps);
    assert!(!ctx.members.is_empty());

    // ssthresh is required
    let ssthresh = ctx.get_member("ssthresh");
    assert!(ssthresh.is_some());
    assert!(!ssthresh.unwrap().optional);

    // init is optional
    let init = ctx.get_member("init");
    assert!(init.is_some());
    assert!(init.unwrap().optional);
}

#[test]
fn test_struct_ops_return_type_range() {
    let void_range = StructOpsRetType::Void.get_range();
    assert_eq!(void_range.minval, 0);
    assert_eq!(void_range.maxval, 0);

    let bool_range = StructOpsRetType::Bool.get_range();
    assert_eq!(bool_range.minval, 0);
    assert_eq!(bool_range.maxval, 1);

    let u32_range = StructOpsRetType::U32.get_range();
    assert_eq!(u32_range.minval, 0);
}

#[test]
fn test_struct_ops_state_machine() {
    let mut state = StructOpsState::Init;

    assert!(state.transition(StructOpsEvent::AttachPrograms).is_ok());
    assert_eq!(state, StructOpsState::Ready);

    assert!(state.can_register());
    assert!(state.transition(StructOpsEvent::Register).is_ok());
    assert_eq!(state, StructOpsState::Registered);

    assert!(state.can_unregister());
    assert!(state.transition(StructOpsEvent::Unregister).is_ok());
    assert_eq!(state, StructOpsState::Unregistering);

    assert!(state.transition(StructOpsEvent::Complete).is_ok());
    assert_eq!(state, StructOpsState::Destroyed);
}

#[test]
fn test_invalid_state_transition() {
    let mut state = StructOpsState::Init;

    // Cannot register from Init state
    assert!(state.transition(StructOpsEvent::Register).is_err());
}

#[test]
fn test_helper_allowed_in_struct_ops() {
    // Common helpers should be allowed
    assert!(is_helper_allowed_in_struct_ops(
        BpfFuncId::MapLookupElem,
        StructOpsType::TcpCongestionOps
    ));
    assert!(is_helper_allowed_in_struct_ops(
        BpfFuncId::KtimeGetNs,
        StructOpsType::TcpCongestionOps
    ));

    // TCP-specific helpers allowed for TCP congestion ops
    assert!(is_helper_allowed_in_struct_ops(
        BpfFuncId::TcpSendAck,
        StructOpsType::TcpCongestionOps
    ));

    // But not for other types
    assert!(!is_helper_allowed_in_struct_ops(
        BpfFuncId::TcpSendAck,
        StructOpsType::HidBpfOps
    ));
}

#[test]
fn test_tcp_congestion_return_validation() {
    // ssthresh must return non-negative
    assert!(tcp_congestion_ops::validate_return("ssthresh", 100).is_ok());
    assert!(tcp_congestion_ops::validate_return("ssthresh", 0).is_ok());
    assert!(tcp_congestion_ops::validate_return("ssthresh", -1).is_err());

    // Void functions accept any return
    assert!(tcp_congestion_ops::validate_return("init", 0).is_ok());
    assert!(tcp_congestion_ops::validate_return("cong_avoid", 0).is_ok());
}

#[test]
fn test_validate_struct_ops_map() {
    // Valid configuration
    assert!(validate_struct_ops_map(100, 200).is_ok());

    // Missing vmlinux type
    assert!(validate_struct_ops_map(0, 200).is_err());

    // Missing map BTF ID
    assert!(validate_struct_ops_map(100, 0).is_err());
}

#[test]
fn test_context_member_lookup() {
    let mut ctx = tcp_congestion_ops::init_context(100, 1);

    // Set current member
    assert!(ctx.set_current_member(0).is_ok());
    assert!(ctx.current_member_info().is_some());
    assert_eq!(ctx.current_member_info().unwrap().name, "init");

    // Out of range
    assert!(ctx.set_current_member(100).is_err());
}

#[test]
fn test_current_supports_sleepable() {
    let mut ctx = tcp_congestion_ops::init_context(100, 1);

    // TCP congestion ops don't support sleepable
    ctx.set_current_member(0).unwrap();
    assert!(!ctx.current_supports_sleepable());
}
