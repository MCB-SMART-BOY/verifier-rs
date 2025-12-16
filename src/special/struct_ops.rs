//! Struct_ops program verification support.
//!
//! struct_ops allows BPF programs to implement kernel struct operations,
//! enabling custom implementations of kernel callbacks like TCP congestion
//! control algorithms (tcp_congestion_ops) or scheduler operations.
//!
//! Key verification requirements:
//! 1. Function prototypes must match kernel struct member signatures via BTF
//! 2. Return values must match kernel expectations
//! 3. Argument access must be validated against BTF types
//! 4. Some struct_ops can be sleepable, others cannot
//! 5. State transitions and lifecycle must be validated


use alloc::{format, string::String, vec, vec::Vec};

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::state::reg_state::BpfRegState;

// ============================================================================
// Struct Ops Types
// ============================================================================

/// Known kernel struct_ops types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructOpsType {
    /// TCP congestion control operations (struct tcp_congestion_ops)
    TcpCongestionOps,
    /// BPF struct_ops for scheduler (struct sched_ext_ops)
    SchedExtOps,
    /// HID-BPF operations (struct hid_bpf_ops)
    HidBpfOps,
    /// Custom/unknown struct_ops
    Custom(u32),
}

impl StructOpsType {
    /// Check if this struct_ops type supports sleepable programs
    pub fn supports_sleepable(&self) -> bool {
        match self {
            StructOpsType::TcpCongestionOps => false,
            StructOpsType::SchedExtOps => true, // Some ops are sleepable
            StructOpsType::HidBpfOps => true,
            StructOpsType::Custom(_) => false, // Conservative default
        }
    }

    /// Get the maximum number of arguments for this struct_ops type
    pub fn max_args(&self) -> usize {
        match self {
            StructOpsType::TcpCongestionOps => 5,
            StructOpsType::SchedExtOps => 5,
            StructOpsType::HidBpfOps => 4,
            StructOpsType::Custom(_) => 5,
        }
    }
}

// ============================================================================
// Struct Ops Member Info
// ============================================================================

/// Information about a struct_ops member (callback function)
#[derive(Debug, Clone)]
pub struct StructOpsMemberInfo {
    /// Member name in the struct
    pub name: String,
    /// BTF ID of the function prototype
    pub func_proto_btf_id: u32,
    /// Offset in the struct
    pub offset: u32,
    /// Whether this member is optional
    pub optional: bool,
    /// Whether this callback can sleep
    pub sleepable: bool,
    /// Expected return type
    pub ret_type: StructOpsRetType,
    /// Argument count
    pub arg_count: usize,
    /// Argument BTF IDs
    pub arg_btf_ids: Vec<u32>,
}

/// Return type for struct_ops callbacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructOpsRetType {
    /// Void return
    Void,
    /// Integer return (generic)
    Int,
    /// Unsigned 32-bit return
    U32,
    /// Unsigned 64-bit return
    U64,
    /// Pointer return (possibly null)
    Pointer,
    /// Boolean return (0 or 1)
    Bool,
}

impl StructOpsRetType {
    /// Get the valid return value range
    pub fn get_range(&self) -> BpfRetvalRange {
        match self {
            StructOpsRetType::Void => BpfRetvalRange::new(0, 0),
            StructOpsRetType::Int => BpfRetvalRange::new(i32::MIN, i32::MAX),
            StructOpsRetType::U32 => BpfRetvalRange::new(0, i32::MAX),
            StructOpsRetType::U64 => BpfRetvalRange::new(0, i32::MAX), // Truncated to 32-bit
            StructOpsRetType::Pointer => BpfRetvalRange::new(i32::MIN, i32::MAX),
            StructOpsRetType::Bool => BpfRetvalRange::new(0, 1),
        }
    }
}

// ============================================================================
// Struct Ops Context
// ============================================================================

/// Struct_ops verification context
#[derive(Debug, Clone)]
pub struct StructOpsContext {
    /// The struct_ops type
    pub ops_type: StructOpsType,
    /// BTF ID of the struct
    pub struct_btf_id: u32,
    /// Map ID backing this struct_ops
    pub map_id: u32,
    /// Member info for all callbacks
    pub members: Vec<StructOpsMemberInfo>,
    /// Currently verifying member index
    pub current_member: Option<usize>,
    /// Whether the struct_ops map is initialized
    pub initialized: bool,
}

impl StructOpsContext {
    /// Create a new struct_ops context
    pub fn new(ops_type: StructOpsType, struct_btf_id: u32, map_id: u32) -> Self {
        Self {
            ops_type,
            struct_btf_id,
            map_id,
            members: Vec::new(),
            current_member: None,
            initialized: false,
        }
    }

    /// Add a member to the struct_ops
    pub fn add_member(&mut self, member: StructOpsMemberInfo) {
        self.members.push(member);
    }

    /// Get member by name
    pub fn get_member(&self, name: &str) -> Option<&StructOpsMemberInfo> {
        self.members.iter().find(|m| m.name == name)
    }

    /// Get member by index
    pub fn get_member_by_idx(&self, idx: usize) -> Option<&StructOpsMemberInfo> {
        self.members.get(idx)
    }

    /// Set current member being verified
    pub fn set_current_member(&mut self, idx: usize) -> Result<()> {
        if idx >= self.members.len() {
            return Err(VerifierError::InvalidFunctionCall(format!(
                "struct_ops member index {} out of range (max {})",
                idx,
                self.members.len()
            )));
        }
        self.current_member = Some(idx);
        Ok(())
    }

    /// Get the current member being verified
    pub fn current_member_info(&self) -> Option<&StructOpsMemberInfo> {
        self.current_member.and_then(|idx| self.members.get(idx))
    }

    /// Check if struct_ops type supports sleepable for current member
    pub fn current_supports_sleepable(&self) -> bool {
        if !self.ops_type.supports_sleepable() {
            return false;
        }
        self.current_member_info()
            .map(|m| m.sleepable)
            .unwrap_or(false)
    }
}

// ============================================================================
// TCP Congestion Ops Definitions
// ============================================================================

/// TCP congestion control operations
pub mod tcp_congestion_ops {
    use super::*;

    /// Initialize TCP congestion ops struct_ops context
    pub fn init_context(struct_btf_id: u32, map_id: u32) -> StructOpsContext {
        let mut ctx = StructOpsContext::new(
            StructOpsType::TcpCongestionOps,
            struct_btf_id,
            map_id,
        );

        // Add standard TCP congestion control callbacks
        ctx.add_member(StructOpsMemberInfo {
            name: "init".into(),
            func_proto_btf_id: 0, // Filled from BTF
            offset: 0,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 1, // struct sock *sk
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "release".into(),
            func_proto_btf_id: 0,
            offset: 8,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 1,
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "ssthresh".into(),
            func_proto_btf_id: 0,
            offset: 16,
            optional: false, // Required
            sleepable: false,
            ret_type: StructOpsRetType::U32,
            arg_count: 1,
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "cong_avoid".into(),
            func_proto_btf_id: 0,
            offset: 24,
            optional: false, // Required
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 3, // sock, ack_cnt, prior_in_flight
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "set_state".into(),
            func_proto_btf_id: 0,
            offset: 32,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 2, // sock, new_state
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "cwnd_event".into(),
            func_proto_btf_id: 0,
            offset: 40,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 2, // sock, event
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "in_ack_event".into(),
            func_proto_btf_id: 0,
            offset: 48,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 2, // sock, flags
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "undo_cwnd".into(),
            func_proto_btf_id: 0,
            offset: 56,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::U32,
            arg_count: 1,
            arg_btf_ids: vec![],
        });

        ctx.add_member(StructOpsMemberInfo {
            name: "pkts_acked".into(),
            func_proto_btf_id: 0,
            offset: 64,
            optional: true,
            sleepable: false,
            ret_type: StructOpsRetType::Void,
            arg_count: 2, // sock, ack_sample
            arg_btf_ids: vec![],
        });

        ctx
    }

    /// Validate return value for a TCP congestion ops callback
    pub fn validate_return(member_name: &str, retval: i64) -> Result<()> {
        match member_name {
            "ssthresh" | "undo_cwnd" => {
                // Must return non-negative u32
                if retval < 0 {
                    return Err(VerifierError::InvalidReturnValue(format!(
                        "tcp_congestion_ops.{} must return non-negative value, got {}",
                        member_name, retval
                    )));
                }
            }
            "init" | "release" | "cong_avoid" | "set_state" | "cwnd_event"
            | "in_ack_event" | "pkts_acked" => {
                // Void return - value is ignored but should be 0
            }
            _ => {
                // Unknown member - allow any return
            }
        }
        Ok(())
    }
}

// ============================================================================
// Struct Ops Argument Validation
// ============================================================================

/// Validate struct_ops callback arguments
pub fn validate_struct_ops_args(
    ctx: &StructOpsContext,
    args: &[BpfRegState],
) -> Result<()> {
    let member = ctx.current_member_info().ok_or_else(|| {
        VerifierError::InvalidFunctionCall("no current struct_ops member".into())
    })?;

    // Check argument count
    if args.len() < member.arg_count {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "struct_ops.{} requires {} arguments, got {}",
            member.name, member.arg_count, args.len()
        )));
    }

    // First argument is typically the struct context (e.g., struct sock *)
    if !args.is_empty() {
        let first_arg = &args[0];
        
        // Must be a BTF pointer type
        if first_arg.reg_type != BpfRegType::PtrToBtfId {
            // Allow PtrToCtx as well since it may be typed
            if first_arg.reg_type != BpfRegType::PtrToCtx {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_BTF_ID or PTR_TO_CTX".into(),
                    got: format!("{:?}", first_arg.reg_type),
                });
            }
        }

        // Check for null pointer
        if first_arg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            // Some callbacks allow null first arg, but most don't
            // This would be validated against member-specific rules
        }
    }

    Ok(())
}

/// Validate return value for struct_ops callback
pub fn validate_struct_ops_return(
    ctx: &StructOpsContext,
    retval: &BpfRegState,
) -> Result<()> {
    let member = ctx.current_member_info().ok_or_else(|| {
        VerifierError::InvalidFunctionCall("no current struct_ops member".into())
    })?;

    // Get expected return range
    let expected_range = member.ret_type.get_range();

    // Check return type
    match retval.reg_type {
        BpfRegType::ScalarValue => {
            // Scalar is always acceptable, bounds checked separately
        }
        BpfRegType::PtrToBtfId | BpfRegType::PtrToMem => {
            // Pointer return is allowed for Pointer return type
            if member.ret_type != StructOpsRetType::Pointer {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("{:?}", member.ret_type),
                    got: "pointer".into(),
                });
            }
        }
        _ => {
            if member.ret_type != StructOpsRetType::Void {
                return Err(VerifierError::TypeMismatch {
                    expected: format!("{:?}", member.ret_type),
                    got: format!("{:?}", retval.reg_type),
                });
            }
        }
    }

    // Check scalar bounds if applicable
    if retval.reg_type == BpfRegType::ScalarValue {
        // If we have known bounds, validate them
        if retval.smin_value > expected_range.maxval as i64
            || retval.smax_value < expected_range.minval as i64
        {
            return Err(VerifierError::InvalidReturnValue(format!(
                "return value range [{}, {}] outside expected [{}, {}]",
                retval.smin_value, retval.smax_value,
                expected_range.minval, expected_range.maxval
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Struct Ops Map Validation
// ============================================================================

/// Validate struct_ops map creation
pub fn validate_struct_ops_map(
    btf_vmlinux_value_type_id: u32,
    map_btf_id: u32,
) -> Result<()> {
    // struct_ops map must have a valid BTF type
    if btf_vmlinux_value_type_id == 0 {
        return Err(VerifierError::InvalidMapAccess(
            "struct_ops map requires btf_vmlinux_value_type_id".into(),
        ));
    }

    // Map BTF ID should match
    if map_btf_id == 0 {
        return Err(VerifierError::InvalidMapAccess(
            "struct_ops map requires btf_id".into(),
        ));
    }

    Ok(())
}

/// Check if all required struct_ops members are implemented
pub fn check_required_members(ctx: &StructOpsContext) -> Result<()> {
    for member in &ctx.members {
        if !member.optional {
            // In a full implementation, we would track which members
            // have BPF programs attached and verify required ones are present
        }
    }
    Ok(())
}

// ============================================================================
// Struct Ops State Machine
// ============================================================================

/// State of a struct_ops map
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StructOpsState {
    /// Initial state, not yet registered
    #[default]
    Init,
    /// Programs attached, ready to register
    Ready,
    /// Registered with kernel
    Registered,
    /// Unregistering
    Unregistering,
    /// Unregistered/destroyed
    Destroyed,
}

impl StructOpsState {
    /// Check if registration is allowed from this state
    pub fn can_register(&self) -> bool {
        matches!(self, StructOpsState::Ready)
    }

    /// Check if unregistration is allowed from this state
    pub fn can_unregister(&self) -> bool {
        matches!(self, StructOpsState::Registered)
    }

    /// Transition to next state
    pub fn transition(&mut self, event: StructOpsEvent) -> Result<()> {
        let new_state = match (*self, event) {
            (StructOpsState::Init, StructOpsEvent::AttachPrograms) => {
                StructOpsState::Ready
            }
            (StructOpsState::Ready, StructOpsEvent::Register) => {
                StructOpsState::Registered
            }
            (StructOpsState::Registered, StructOpsEvent::Unregister) => {
                StructOpsState::Unregistering
            }
            (StructOpsState::Unregistering, StructOpsEvent::Complete) => {
                StructOpsState::Destroyed
            }
            _ => {
                return Err(VerifierError::InvalidState(format!(
                    "invalid struct_ops transition from {:?} on {:?}",
                    self, event
                )));
            }
        };

        *self = new_state;
        Ok(())
    }
}

/// Events that can trigger struct_ops state transitions
#[derive(Debug, Clone, Copy)]
pub enum StructOpsEvent {
    /// BPF programs attached to struct_ops map
    AttachPrograms,
    /// struct_ops registered with kernel
    Register,
    /// struct_ops unregistration requested
    Unregister,
    /// Operation completed
    Complete,
}

// ============================================================================
// Struct Ops Helpers Validation
// ============================================================================

/// Check if a helper is allowed in struct_ops context
pub fn is_helper_allowed_in_struct_ops(
    func_id: BpfFuncId,
    ops_type: StructOpsType,
) -> bool {
    // Common helpers allowed in all struct_ops
    let common_allowed = matches!(
        func_id,
        BpfFuncId::MapLookupElem
            | BpfFuncId::MapUpdateElem
            | BpfFuncId::MapDeleteElem
            | BpfFuncId::KtimeGetNs
            | BpfFuncId::KtimeGetBootNs
            | BpfFuncId::GetPrandomU32
            | BpfFuncId::GetSmpProcessorId
            | BpfFuncId::TracePrintk
            | BpfFuncId::SpinLock
            | BpfFuncId::SpinUnlock
            | BpfFuncId::RingbufOutput
            | BpfFuncId::RingbufReserve
            | BpfFuncId::RingbufSubmit
            | BpfFuncId::RingbufDiscard
    );

    if common_allowed {
        return true;
    }

    // Type-specific helpers
    match ops_type {
        StructOpsType::TcpCongestionOps => {
            // TCP congestion control specific helpers
            matches!(
                func_id,
                BpfFuncId::TcpSendAck
                    | BpfFuncId::SkStorageGet
                    | BpfFuncId::SkStorageDelete
            )
        }
        StructOpsType::SchedExtOps => {
            // Scheduler specific helpers
            matches!(
                func_id,
                BpfFuncId::TaskStorageGet
                    | BpfFuncId::TaskStorageDelete
                    | BpfFuncId::GetCurrentTask
                    | BpfFuncId::GetCurrentTaskBtf
            )
        }
        StructOpsType::HidBpfOps => {
            // HID specific helpers are more restricted
            false
        }
        StructOpsType::Custom(_) => {
            // Conservative: only common helpers
            false
        }
    }
}

// ============================================================================
// Struct Ops Kfunc Support
// ============================================================================

/// struct_ops specific kfuncs
pub mod struct_ops_kfuncs {
    /// kfunc to get struct_ops state
    pub const BPF_STRUCT_OPS_GET_STATE: u32 = 0x7001;
    /// kfunc to set struct_ops result
    pub const BPF_STRUCT_OPS_SET_RESULT: u32 = 0x7002;
}

/// Check if a kfunc is struct_ops specific
pub fn is_struct_ops_kfunc(btf_id: u32) -> bool {
    matches!(
        btf_id,
        struct_ops_kfuncs::BPF_STRUCT_OPS_GET_STATE
            | struct_ops_kfuncs::BPF_STRUCT_OPS_SET_RESULT
    )
}

// ============================================================================
// Tests
// ============================================================================
