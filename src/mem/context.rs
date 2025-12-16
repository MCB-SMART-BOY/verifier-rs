// SPDX-License-Identifier: GPL-2.0

//!

//! This module implements context structure access verification for BPF programs.

//! Different program types have different context structures with specific access rules.

use alloc::{format, vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;

/// Context field access descriptor
#[derive(Debug, Clone)]
pub struct CtxFieldAccess {
    /// Offset in context structure
    pub offset: u32,
    /// Size of field
    pub size: u32,
    /// Whether field is readable
    pub readable: bool,
    /// Whether field is writable
    pub writable: bool,
    /// Result type after reading this field
    pub result_type: BpfRegType,
    /// BTF ID for pointer fields
    pub btf_id: Option<u32>,
}

impl CtxFieldAccess {
    /// Create readable field
    pub fn readable(offset: u32, size: u32, result_type: BpfRegType) -> Self {
        Self {
            offset,
            size,
            readable: true,
            writable: false,
            result_type,
            btf_id: None,
        }
    }

    /// Create read-write field
    pub fn read_write(offset: u32, size: u32, result_type: BpfRegType) -> Self {
        Self {
            offset,
            size,
            readable: true,
            writable: true,
            result_type,
            btf_id: None,
        }
    }

    /// Create pointer field
    pub fn pointer(offset: u32, size: u32, ptr_type: BpfRegType, btf_id: Option<u32>) -> Self {
        Self {
            offset,
            size,
            readable: true,
            writable: false,
            result_type: ptr_type,
            btf_id,
        }
    }
}

/// Context access rules for a program type
#[derive(Debug, Clone)]
pub struct ContextAccessRules {
    /// Program type
    pub prog_type: BpfProgType,
    /// Context structure size
    pub ctx_size: u32,
    /// Field access descriptors
    pub fields: Vec<CtxFieldAccess>,
    /// Whether narrow access is allowed
    pub allow_narrow_access: bool,
    /// Whether unaligned access is allowed
    pub allow_unaligned: bool,
}

impl Default for ContextAccessRules {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Unspec,
            ctx_size: 0,
            fields: Vec::new(),
            allow_narrow_access: false,
            allow_unaligned: false,
        }
    }
}

impl ContextAccessRules {
    /// Create rules for XDP program
    pub fn xdp() -> Self {
        Self {
            prog_type: BpfProgType::Xdp,
            ctx_size: 24, // sizeof(struct xdp_md)
            fields: vec![
                CtxFieldAccess::readable(0, 4, BpfRegType::PtrToPacket), // data
                CtxFieldAccess::readable(4, 4, BpfRegType::PtrToPacketEnd), // data_end
                CtxFieldAccess::readable(8, 4, BpfRegType::PtrToPacketMeta), // data_meta
                CtxFieldAccess::readable(12, 4, BpfRegType::ScalarValue), // ingress_ifindex
                CtxFieldAccess::readable(16, 4, BpfRegType::ScalarValue), // rx_queue_index
                CtxFieldAccess::readable(20, 4, BpfRegType::ScalarValue), // egress_ifindex
            ],
            allow_narrow_access: false,
            allow_unaligned: false,
        }
    }

    /// Create rules for socket filter program
    pub fn socket_filter() -> Self {
        Self {
            prog_type: BpfProgType::SocketFilter,
            ctx_size: 0, // Uses __sk_buff which is rewritten
            fields: vec![
                CtxFieldAccess::readable(0, 4, BpfRegType::ScalarValue), // len
                CtxFieldAccess::readable(4, 4, BpfRegType::ScalarValue), // pkt_type
                CtxFieldAccess::readable(8, 4, BpfRegType::ScalarValue), // mark
                CtxFieldAccess::readable(12, 4, BpfRegType::ScalarValue), // queue_mapping
                CtxFieldAccess::readable(16, 4, BpfRegType::ScalarValue), // protocol
                CtxFieldAccess::readable(20, 4, BpfRegType::ScalarValue), // vlan_present
                CtxFieldAccess::readable(24, 4, BpfRegType::ScalarValue), // vlan_tci
                CtxFieldAccess::readable(28, 4, BpfRegType::ScalarValue), // vlan_proto
                CtxFieldAccess::readable(32, 4, BpfRegType::ScalarValue), // priority
                CtxFieldAccess::readable(36, 4, BpfRegType::ScalarValue), // ingress_ifindex
                CtxFieldAccess::readable(40, 4, BpfRegType::ScalarValue), // ifindex
                CtxFieldAccess::readable(44, 4, BpfRegType::ScalarValue), // tc_index
                CtxFieldAccess::readable(48, 4, BpfRegType::ScalarValue), // cb[0]
                CtxFieldAccess::readable(52, 4, BpfRegType::ScalarValue), // cb[1]
                CtxFieldAccess::readable(56, 4, BpfRegType::ScalarValue), // cb[2]
                CtxFieldAccess::readable(60, 4, BpfRegType::ScalarValue), // cb[3]
                CtxFieldAccess::readable(64, 4, BpfRegType::ScalarValue), // cb[4]
                CtxFieldAccess::readable(68, 4, BpfRegType::ScalarValue), // hash
                CtxFieldAccess::readable(72, 4, BpfRegType::ScalarValue), // tc_classid
                CtxFieldAccess::readable(76, 4, BpfRegType::PtrToPacket), // data
                CtxFieldAccess::readable(80, 4, BpfRegType::PtrToPacketEnd), // data_end
                CtxFieldAccess::readable(84, 4, BpfRegType::ScalarValue), // napi_id
                CtxFieldAccess::readable(88, 4, BpfRegType::ScalarValue), // family
                CtxFieldAccess::readable(92, 4, BpfRegType::ScalarValue), // remote_ip4
                CtxFieldAccess::readable(96, 16, BpfRegType::ScalarValue), // remote_ip6
                CtxFieldAccess::readable(112, 4, BpfRegType::ScalarValue), // local_ip4
                CtxFieldAccess::readable(116, 16, BpfRegType::ScalarValue), // local_ip6
                CtxFieldAccess::readable(132, 4, BpfRegType::ScalarValue), // remote_port
                CtxFieldAccess::readable(136, 4, BpfRegType::ScalarValue), // local_port
            ],
            allow_narrow_access: true,
            allow_unaligned: false,
        }
    }

    /// Create rules for TC classifier program
    pub fn sched_cls() -> Self {
        let mut rules = Self::socket_filter();
        rules.prog_type = BpfProgType::SchedCls;
        // TC can write to some fields
        rules.fields[2] = CtxFieldAccess::read_write(8, 4, BpfRegType::ScalarValue); // mark
        rules.fields[8] = CtxFieldAccess::read_write(32, 4, BpfRegType::ScalarValue); // priority
        rules.fields[17] = CtxFieldAccess::read_write(72, 4, BpfRegType::ScalarValue); // tc_classid
        rules
    }

    /// Create rules for tracepoint program
    pub fn tracepoint() -> Self {
        Self {
            prog_type: BpfProgType::Tracepoint,
            ctx_size: 0,        // Variable based on tracepoint
            fields: Vec::new(), // Fields determined by BTF
            allow_narrow_access: true,
            allow_unaligned: true,
        }
    }

    /// Create rules for kprobe program
    pub fn kprobe() -> Self {
        Self {
            prog_type: BpfProgType::Kprobe,
            ctx_size: 0,        // Uses pt_regs
            fields: Vec::new(), // Architecture-dependent
            allow_narrow_access: true,
            allow_unaligned: false,
        }
    }

    /// Create rules for cgroup/sock program
    pub fn cgroup_sock() -> Self {
        Self {
            prog_type: BpfProgType::CgroupSock,
            ctx_size: 64,
            fields: vec![
                CtxFieldAccess::read_write(0, 4, BpfRegType::ScalarValue), // bound_dev_if
                CtxFieldAccess::readable(4, 4, BpfRegType::ScalarValue),   // family
                CtxFieldAccess::readable(8, 4, BpfRegType::ScalarValue),   // type
                CtxFieldAccess::readable(12, 4, BpfRegType::ScalarValue),  // protocol
                CtxFieldAccess::read_write(16, 4, BpfRegType::ScalarValue), // mark
                CtxFieldAccess::read_write(20, 4, BpfRegType::ScalarValue), // priority
                CtxFieldAccess::readable(24, 4, BpfRegType::ScalarValue),  // src_ip4
                CtxFieldAccess::readable(28, 16, BpfRegType::ScalarValue), // src_ip6
            ],
            allow_narrow_access: false,
            allow_unaligned: false,
        }
    }

    /// Create permissive default rules for when program type is unknown
    ///
    /// This allows reading any offset as a scalar value. This is less safe
    /// than program-specific rules but enables verification to proceed
    /// when the exact context type is not known.
    pub fn default_permissive() -> Self {
        // Create a large context with readable scalar fields at common offsets
        let mut fields = Vec::new();

        // Add common field sizes at 4-byte aligned offsets up to 256 bytes
        for offset in (0..256).step_by(4) {
            fields.push(CtxFieldAccess::readable(offset, 4, BpfRegType::ScalarValue));
        }
        // Also add 8-byte fields for pointer-sized reads
        for offset in (0..256).step_by(8) {
            fields.push(CtxFieldAccess::readable(offset, 8, BpfRegType::ScalarValue));
        }

        Self {
            prog_type: BpfProgType::Unspec,
            ctx_size: 256,
            fields,
            allow_narrow_access: true,
            allow_unaligned: false,
        }
    }

    /// Get rules for a program type
    pub fn for_prog_type(prog_type: BpfProgType) -> Self {
        match prog_type {
            BpfProgType::Xdp => Self::xdp(),
            BpfProgType::SocketFilter => Self::socket_filter(),
            BpfProgType::SchedCls | BpfProgType::SchedAct => Self::sched_cls(),
            BpfProgType::Tracepoint | BpfProgType::RawTracepoint => Self::tracepoint(),
            BpfProgType::Kprobe => Self::kprobe(),
            BpfProgType::CgroupSock => Self::cgroup_sock(),
            _ => Self::default(),
        }
    }

    /// Find field at offset
    pub fn find_field(&self, offset: u32, size: u32) -> Option<&CtxFieldAccess> {
        self.fields
            .iter()
            .find(|&field| offset >= field.offset && offset + size <= field.offset + field.size)
            .map(|v| v as _)
    }

    /// Check if access spans multiple fields (not allowed)
    pub fn spans_multiple_fields(&self, offset: u32, size: u32) -> bool {
        let mut found_field = false;
        for field in &self.fields {
            let field_end = field.offset + field.size;
            let access_end = offset + size;

            // Check for overlap
            if offset < field_end && access_end > field.offset {
                if found_field {
                    return true; // Already found one field, this spans multiple
                }
                // Check if access is fully within this field
                if offset >= field.offset && access_end <= field_end {
                    found_field = true;
                } else {
                    return true; // Partial overlap means spanning
                }
            }
        }
        false
    }
}

/// Check context access
pub fn check_ctx_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    rules: &ContextAccessRules,
) -> Result<BpfRegType> {
    // Must be context pointer
    if reg.reg_type != BpfRegType::PtrToCtx {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_CTX".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    let access_off = reg.off + off;

    // Check for negative offset
    if access_off < 0 {
        return Err(VerifierError::InvalidContextAccess(
            "negative context offset".into(),
        ));
    }

    let access_off = access_off as u32;

    // Check alignment
    if !rules.allow_unaligned && !access_off.is_multiple_of(size) {
        return Err(VerifierError::InvalidContextAccess(format!(
            "unaligned context access at offset {}",
            access_off
        )));
    }

    // Check if access spans multiple fields
    if rules.spans_multiple_fields(access_off, size) {
        return Err(VerifierError::InvalidContextAccess(
            "access spans multiple context fields".into(),
        ));
    }

    // Find the field being accessed
    let field = rules.find_field(access_off, size).ok_or_else(|| {
        VerifierError::InvalidContextAccess(format!(
            "no field at offset {} size {}",
            access_off, size
        ))
    })?;

    // Check narrow access
    if !rules.allow_narrow_access && size < field.size {
        return Err(VerifierError::InvalidContextAccess(
            "narrow context access not allowed".into(),
        ));
    }

    // Check read/write permission
    if is_write && !field.writable {
        return Err(VerifierError::InvalidContextAccess(format!(
            "field at offset {} is not writable",
            access_off
        )));
    }
    if !is_write && !field.readable {
        return Err(VerifierError::InvalidContextAccess(format!(
            "field at offset {} is not readable",
            access_off
        )));
    }

    Ok(field.result_type)
}

/// Convert context access to direct packet access (for networking programs)
pub fn convert_ctx_to_packet_access(prog_type: BpfProgType, offset: u32) -> Option<BpfRegType> {
    let rules = ContextAccessRules::for_prog_type(prog_type);

    for field in &rules.fields {
        if offset == field.offset {
            match field.result_type {
                BpfRegType::PtrToPacket
                | BpfRegType::PtrToPacketEnd
                | BpfRegType::PtrToPacketMeta => {
                    return Some(field.result_type);
                }
                _ => {}
            }
        }
    }
    None
}

/// Context field rewrite for JIT
#[derive(Debug, Clone)]
pub struct CtxRewrite {
    /// Original offset in context
    pub orig_offset: u32,
    /// Rewritten offset in actual structure
    pub new_offset: u32,
    /// Size of access
    pub size: u32,
    /// Whether this needs helper call
    pub needs_helper: bool,
}

/// Get context rewrite for socket buffer access
pub fn get_skb_rewrite(offset: u32, size: u32) -> Option<CtxRewrite> {
    // __sk_buff to sk_buff field mapping
    // This is simplified - real kernel has complex mapping
    match offset {
        0 => Some(CtxRewrite {
            orig_offset: 0,
            new_offset: 104,
            size,
            needs_helper: false,
        }), // len
        76 => Some(CtxRewrite {
            orig_offset: 76,
            new_offset: 200,
            size,
            needs_helper: false,
        }), // data
        80 => Some(CtxRewrite {
            orig_offset: 80,
            new_offset: 208,
            size,
            needs_helper: false,
        }), // data_end
        _ => None,
    }
}
