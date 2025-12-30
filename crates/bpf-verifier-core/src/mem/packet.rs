// SPDX-License-Identifier: GPL-2.0

//! XDP 和 TC 程序的数据包访问验证模块
//!
//! Packet data access verification for XDP and TC programs.
//!
//! 本模块实现了 XDP 和 TC 程序的数据包数据访问验证。它跟踪数据包指针
//! （data、data_end、data_meta）并确保安全访问。
//!
//! This module implements packet data access verification for XDP and TC programs.
//! It tracks packet pointers (data, data_end, data_meta) and ensures safe access.
//!
//! # 边界检查模式 / Bounds Check Patterns
//!
//! BPF 验证器必须确保所有数据包访问都在边界内。这通过跟踪边界检查并将该信息
//! 传播到后续指令来实现。
//!
//! The BPF verifier must ensure that all packet accesses are within bounds.
//! This is done by tracking bounds checks and propagating that information
//! to subsequent instructions.
//!
//! ## 典型的边界检查模式 / Typical Bounds Check Pattern
//!
//! ```text
//! // C 代码 / C code:
//! if (data + sizeof(struct ethhdr) > data_end)
//!     return XDP_DROP;
//! // 此后可以安全访问以太网头 / After this, ethernet header access is safe
//! ```
//!
//! # 可变偏移访问 / Variable Offset Access
//!
//! 对于非常量偏移的数据包访问，验证器使用 min/max 边界来验证安全性。

use alloc::{format, vec::Vec};

use crate::bounds::tnum::Tnum;
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;

use crate::core::error::{Result, VerifierError};

/// Maximum packet offset for direct access
pub const MAX_PACKET_OFF: i32 = 0xFFFF;

/// Minimum Ethernet header size
pub const ETH_HLEN: i32 = 14;

/// IPv4 header minimum size
pub const IPV4_HLEN_MIN: i32 = 20;

/// IPv6 header size
pub const IPV6_HLEN: i32 = 40;

/// TCP header minimum size
pub const TCP_HLEN_MIN: i32 = 20;

/// UDP header size
pub const UDP_HLEN: i32 = 8;

/// Packet pointer state
#[derive(Debug, Clone, Default)]
pub struct PacketState {
    /// Register holding packet data pointer
    pub data_reg: Option<u8>,
    /// Register holding packet data_end pointer
    pub data_end_reg: Option<u8>,
    /// Register holding packet data_meta pointer
    pub data_meta_reg: Option<u8>,
    /// Whether packet bounds have been checked
    pub bounds_checked: bool,
    /// Verified safe access range
    pub safe_range: Option<PacketRange>,
}

/// Verified packet access range
#[derive(Debug, Clone, Copy)]
pub struct PacketRange {
    /// Start offset from packet data
    pub start: i32,
    /// End offset from packet data (exclusive)
    pub end: i32,
}

impl PacketRange {
    /// Create new packet range
    pub fn new(start: i32, end: i32) -> Self {
        Self { start, end }
    }

    /// Check if offset is within range
    pub fn contains(&self, off: i32, size: u32) -> bool {
        off >= self.start && (off + size as i32) <= self.end
    }

    /// Intersect with another range
    pub fn intersect(&self, other: &PacketRange) -> Option<PacketRange> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start < end {
            Some(PacketRange::new(start, end))
        } else {
            None
        }
    }

    /// Extend range
    pub fn extend(&mut self, off: i32, size: u32) {
        self.start = self.start.min(off);
        self.end = self.end.max(off + size as i32);
    }
}

/// Variable-offset packet access bounds
/// Used when the offset is not a constant but has known bounds
#[derive(Debug, Clone, Copy)]
pub struct VariablePacketBounds {
    /// Minimum offset
    pub min_off: i32,
    /// Maximum offset
    pub max_off: i32,
    /// Tracked number for known/unknown bits
    pub var_off: Tnum,
    /// Whether bounds have been verified
    pub verified: bool,
}

impl VariablePacketBounds {
    /// Create new variable bounds
    pub fn new(min_off: i32, max_off: i32) -> Self {
        Self {
            min_off,
            max_off,
            var_off: Tnum::unknown(),
            verified: false,
        }
    }

    /// Create from tnum
    pub fn from_tnum(tnum: Tnum, base_off: i32) -> Self {
        let min = tnum.min();
        let max = tnum.max();
        Self {
            min_off: base_off.saturating_add(min as i32),
            max_off: base_off.saturating_add(max as i32),
            var_off: tnum,
            verified: false,
        }
    }

    /// Check if access is within verified bounds
    pub fn is_access_safe(&self, size: u32, verified_end: i32) -> bool {
        if !self.verified {
            return false;
        }
        // Worst case: max_off + size must be <= verified_end
        self.max_off.saturating_add(size as i32) <= verified_end
    }

    /// Narrow bounds after a comparison
    pub fn narrow(&mut self, op: u8, bound: i32, is_taken: bool) {
        match op {
            BPF_JLT => {
                if is_taken {
                    // var < bound, so max is bound - 1
                    self.max_off = self.max_off.min(bound - 1);
                } else {
                    // var >= bound
                    self.min_off = self.min_off.max(bound);
                }
            }
            BPF_JLE => {
                if is_taken {
                    // var <= bound
                    self.max_off = self.max_off.min(bound);
                } else {
                    // var > bound
                    self.min_off = self.min_off.max(bound + 1);
                }
            }
            BPF_JGT => {
                if is_taken {
                    // var > bound
                    self.min_off = self.min_off.max(bound + 1);
                } else {
                    // var <= bound
                    self.max_off = self.max_off.min(bound);
                }
            }
            BPF_JGE => {
                if is_taken {
                    // var >= bound
                    self.min_off = self.min_off.max(bound);
                } else {
                    // var < bound
                    self.max_off = self.max_off.min(bound - 1);
                }
            }
            _ => {}
        }
    }
}

/// Packet bounds context for tracking across instructions
#[derive(Debug, Clone, Default)]
pub struct PacketBoundsContext {
    /// Data pointer register
    pub data_reg: Option<usize>,
    /// Data end pointer register  
    pub data_end_reg: Option<usize>,
    /// Data meta pointer register
    pub data_meta_reg: Option<usize>,
    /// Verified safe ranges (stack of ranges from nested checks)
    pub verified_ranges: Vec<PacketRange>,
    /// Variable offset tracking per register
    pub var_bounds: [Option<VariablePacketBounds>; MAX_BPF_REG],
    /// Whether we're in a bounds-checked region
    pub in_checked_region: bool,
}

impl PacketBoundsContext {
    /// Create new packet bounds context
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize context from context register loads
    pub fn init_from_ctx_load(&mut self, dst_reg: usize, field_off: i32) {
        // XDP context: data at 0, data_end at 8, data_meta at 16
        // SKB context: data at 76, data_end at 80
        match field_off {
            0 => self.data_reg = Some(dst_reg),
            8 => self.data_end_reg = Some(dst_reg),
            16 => self.data_meta_reg = Some(dst_reg),
            76 => self.data_reg = Some(dst_reg),     // SKB data
            80 => self.data_end_reg = Some(dst_reg), // SKB data_end
            _ => {}
        }
    }

    /// Record a bounds check result
    pub fn record_bounds_check(&mut self, range: PacketRange) {
        self.verified_ranges.push(range);
        self.in_checked_region = true;
    }

    /// Check if an access at given offset and size is safe
    pub fn is_access_verified(&self, off: i32, size: u32) -> bool {
        for range in &self.verified_ranges {
            if range.contains(off, size) {
                return true;
            }
        }
        false
    }

    /// Check variable-offset access
    pub fn check_var_access(&self, regno: usize, size: u32) -> bool {
        if let Some(bounds) = &self.var_bounds[regno] {
            // Check against all verified ranges
            for range in &self.verified_ranges {
                if bounds.is_access_safe(size, range.end) {
                    return true;
                }
            }
        }
        false
    }

    /// Update variable bounds for a register
    pub fn update_var_bounds(&mut self, regno: usize, bounds: VariablePacketBounds) {
        if regno < MAX_BPF_REG {
            self.var_bounds[regno] = Some(bounds);
        }
    }

    /// Clear variable bounds for a register (when it's overwritten)
    pub fn clear_var_bounds(&mut self, regno: usize) {
        if regno < MAX_BPF_REG {
            self.var_bounds[regno] = None;
        }
    }

    /// Propagate bounds info after a register move
    pub fn propagate_bounds(&mut self, dst: usize, src: usize) {
        if src < MAX_BPF_REG && dst < MAX_BPF_REG {
            self.var_bounds[dst] = self.var_bounds[src];
        }
    }

    /// Get the maximum verified safe offset
    pub fn max_verified_offset(&self) -> i32 {
        self.verified_ranges
            .iter()
            .map(|r| r.end)
            .max()
            .unwrap_or(0)
    }
}

impl PacketState {
    /// Create new packet state
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize for XDP program
    pub fn init_xdp(&mut self, _ctx_reg: u8) {
        // XDP context has data, data_end, data_meta fields
        // After loading from context, registers will track these
        self.bounds_checked = false;
        self.safe_range = None;
    }

    /// Initialize for TC/socket program
    pub fn init_skb(&mut self, _ctx_reg: u8) {
        // SKB has data, data_end
        self.bounds_checked = false;
        self.safe_range = None;
    }

    /// Mark bounds as checked after successful comparison
    pub fn mark_bounds_checked(&mut self, range: PacketRange) {
        self.bounds_checked = true;
        self.safe_range = Some(range);
    }

    /// Check if access is safe
    pub fn is_access_safe(&self, off: i32, size: u32) -> bool {
        if !self.bounds_checked {
            return false;
        }
        if let Some(range) = &self.safe_range {
            range.contains(off, size)
        } else {
            false
        }
    }
}

/// Check packet pointer access
pub fn check_packet_access(reg: &BpfRegState, off: i32, _size: u32, is_write: bool) -> Result<()> {
    // Must be packet pointer type
    match reg.reg_type {
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {}
        _ => {
            return Err(VerifierError::TypeMismatch {
                expected: "PTR_TO_PACKET or PTR_TO_PACKET_META".into(),
                got: format!("{:?}", reg.reg_type),
            });
        }
    }

    // Check offset bounds
    let access_off = reg.off + off;
    if access_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "negative packet offset".into(),
        ));
    }
    if access_off > MAX_PACKET_OFF {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet offset {} exceeds maximum {}",
            access_off, MAX_PACKET_OFF
        )));
    }

    // Writes to packet data require special handling
    if is_write {
        // Check if write is allowed (depends on program type and helpers called)
    }

    Ok(())
}

/// Analyze packet bounds check pattern
/// Returns the verified safe range if pattern is recognized
pub fn analyze_bounds_check(
    data_reg: &BpfRegState,
    end_reg: &BpfRegState,
    check_reg: &BpfRegState,
    jmp_op: u8,
    is_taken: bool,
) -> Option<PacketRange> {
    // Common pattern: if (data + N > data_end) goto error;
    // After this check (not taken), we know data + N <= data_end

    // data_reg should be PTR_TO_PACKET
    if data_reg.reg_type != BpfRegType::PtrToPacket {
        return None;
    }

    // end_reg should be PTR_TO_PACKET_END
    if end_reg.reg_type != BpfRegType::PtrToPacketEnd {
        return None;
    }

    // check_reg is data + offset
    let offset = check_reg.off;

    match jmp_op {
        BPF_JGT => {
            if !is_taken {
                // data + offset <= data_end, so offset bytes are safe
                return Some(PacketRange::new(0, offset));
            }
        }
        BPF_JGE => {
            if !is_taken {
                // data + offset < data_end, so offset-1 bytes are safe
                return Some(PacketRange::new(0, offset - 1));
            }
        }
        BPF_JLT => {
            if is_taken {
                // data + offset < data_end
                return Some(PacketRange::new(0, offset));
            }
        }
        BPF_JLE => {
            if is_taken {
                // data + offset <= data_end
                return Some(PacketRange::new(0, offset + 1));
            }
        }
        _ => {}
    }

    None
}

/// Track packet pointer through ALU operation
pub fn track_packet_alu(dst: &mut BpfRegState, src: &BpfRegState, op: u8, imm: i32) -> Result<()> {
    if dst.reg_type != BpfRegType::PtrToPacket && dst.reg_type != BpfRegType::PtrToPacketMeta {
        return Ok(());
    }

    match op {
        BPF_ADD => {
            if src.reg_type == BpfRegType::ScalarValue && src.is_const() {
                // Adding constant to packet pointer
                let new_off = dst.off + src.const_value() as i32;
                if !(0..=MAX_PACKET_OFF).contains(&new_off) {
                    return Err(VerifierError::InvalidPointerArithmetic(format!(
                        "packet offset {} out of range",
                        new_off
                    )));
                }
                dst.off = new_off;
            } else if imm != 0 {
                // Adding immediate
                let new_off = dst.off + imm;
                if !(0..=MAX_PACKET_OFF).contains(&new_off) {
                    return Err(VerifierError::InvalidPointerArithmetic(format!(
                        "packet offset {} out of range",
                        new_off
                    )));
                }
                dst.off = new_off;
            } else {
                // Adding unknown value - result is scalar, not packet ptr
                dst.reg_type = BpfRegType::ScalarValue;
            }
        }
        BPF_SUB => {
            if src.reg_type == BpfRegType::ScalarValue && src.is_const() {
                let new_off = dst.off - src.const_value() as i32;
                if new_off < 0 {
                    return Err(VerifierError::InvalidPointerArithmetic(
                        "negative packet offset".into(),
                    ));
                }
                dst.off = new_off;
            } else if src.reg_type == BpfRegType::PtrToPacket
                || src.reg_type == BpfRegType::PtrToPacketEnd
            {
                // ptr - ptr = scalar (difference)
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
            } else {
                return Err(VerifierError::InvalidPointerArithmetic(
                    "invalid packet pointer subtraction".into(),
                ));
            }
        }
        _ => {
            // Other operations on packet pointers not allowed
            return Err(VerifierError::InvalidPointerArithmetic(format!(
                "operation {:02x} not allowed on packet pointer",
                op
            )));
        }
    }

    Ok(())
}

/// Direct packet access info
#[derive(Debug, Clone)]
pub struct DirectPacketAccess {
    /// Offset from packet start
    pub offset: i32,
    /// Access size
    pub size: u32,
    /// Whether this is a write
    pub is_write: bool,
    /// Instruction index
    pub insn_idx: usize,
}

/// Collect all direct packet accesses in a program
pub fn collect_packet_accesses(
    insns: &[BpfInsn],
    packet_regs: &[bool; MAX_BPF_REG],
) -> Vec<DirectPacketAccess> {
    let mut accesses = Vec::new();

    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();

        match class {
            BPF_LDX => {
                let src = insn.src_reg as usize;
                if src < MAX_BPF_REG && packet_regs[src] {
                    accesses.push(DirectPacketAccess {
                        offset: insn.off as i32,
                        size: insn.size() as u32,
                        is_write: false,
                        insn_idx: idx,
                    });
                }
            }
            BPF_STX => {
                let dst = insn.dst_reg as usize;
                if dst < MAX_BPF_REG && packet_regs[dst] {
                    accesses.push(DirectPacketAccess {
                        offset: insn.off as i32,
                        size: insn.size() as u32,
                        is_write: true,
                        insn_idx: idx,
                    });
                }
            }
            _ => {}
        }
    }

    accesses
}

/// Validate all packet accesses have bounds checks
pub fn validate_packet_accesses(
    accesses: &[DirectPacketAccess],
    verified_ranges: &[PacketRange],
) -> Result<()> {
    for access in accesses {
        let mut is_safe = false;

        for range in verified_ranges {
            if range.contains(access.offset, access.size) {
                is_safe = true;
                break;
            }
        }

        if !is_safe {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "packet access at offset {} size {} at insn {} not bounds checked",
                access.offset, access.size, access.insn_idx
            )));
        }
    }

    Ok(())
}

/// Check packet write permission for program type
pub fn check_packet_write_allowed(prog_type: BpfProgType) -> bool {
    matches!(
        prog_type,
        BpfProgType::Xdp
            | BpfProgType::SchedCls
            | BpfProgType::SchedAct
            | BpfProgType::LwtXmit
            | BpfProgType::SkSkb
    )
}

/// Check if a register contains a packet-related pointer
pub fn is_packet_ptr(reg: &BpfRegState) -> bool {
    matches!(
        reg.reg_type,
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta | BpfRegType::PtrToPacketEnd
    )
}

/// Validate packet access with full context
pub fn validate_packet_access_full(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    ctx: &PacketBoundsContext,
    prog_type: BpfProgType,
) -> Result<()> {
    // Must be packet pointer type
    if !is_packet_ptr(reg) {
        return Err(VerifierError::TypeMismatch {
            expected: "packet pointer".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }

    // Cannot read/write through packet_end
    if reg.reg_type == BpfRegType::PtrToPacketEnd {
        return Err(VerifierError::InvalidMemoryAccess(
            "cannot access memory through PTR_TO_PACKET_END".into(),
        ));
    }

    // Check write permission
    if is_write && !check_packet_write_allowed(prog_type) {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet write not allowed for program type {:?}",
            prog_type
        )));
    }

    // Calculate actual offset
    let access_off = reg.off + off;

    // Check for negative offset
    if access_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative packet offset {}",
            access_off
        )));
    }

    // Check maximum offset
    if access_off > MAX_PACKET_OFF {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet offset {} exceeds maximum {}",
            access_off, MAX_PACKET_OFF
        )));
    }

    // Check if access is within verified bounds
    if !ctx.is_access_verified(access_off, size) {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet access at offset {} size {} not within verified bounds",
            access_off, size
        )));
    }

    Ok(())
}

/// Analyze a conditional jump for packet bounds check patterns
/// Returns (data_reg_idx, verified_range) if a bounds check pattern is recognized
pub fn analyze_packet_bounds_jmp(
    regs: &[BpfRegState; MAX_BPF_REG],
    dst_reg: usize,
    src_reg: usize,
    jmp_op: u8,
    is_taken: bool,
) -> Option<(usize, PacketRange)> {
    let dst = &regs[dst_reg];
    let src = &regs[src_reg];

    // Pattern 1: data + N compared to data_end
    // if (data + N > data_end) goto drop;
    if dst.reg_type == BpfRegType::PtrToPacket && src.reg_type == BpfRegType::PtrToPacketEnd {
        return analyze_data_vs_end_check(dst, jmp_op, is_taken);
    }

    // Pattern 2: data_end compared to data + N
    // if (data_end < data + N) goto drop;
    if dst.reg_type == BpfRegType::PtrToPacketEnd && src.reg_type == BpfRegType::PtrToPacket {
        // Swap and invert the comparison
        let inverted_op = invert_jmp_op(jmp_op);
        return analyze_data_vs_end_check(src, inverted_op, is_taken);
    }

    None
}

/// Analyze data vs data_end comparison
fn analyze_data_vs_end_check(
    data_reg: &BpfRegState,
    jmp_op: u8,
    is_taken: bool,
) -> Option<(usize, PacketRange)> {
    let offset = data_reg.off;

    match jmp_op {
        BPF_JGT => {
            // data + offset > data_end
            if !is_taken {
                // Fall through: data + offset <= data_end
                // Safe to access bytes [0, offset]
                return Some((0, PacketRange::new(0, offset)));
            }
        }
        BPF_JGE => {
            // data + offset >= data_end
            if !is_taken {
                // Fall through: data + offset < data_end
                // Safe to access bytes [0, offset - 1]
                if offset > 0 {
                    return Some((0, PacketRange::new(0, offset - 1)));
                }
            }
        }
        BPF_JLT => {
            // data + offset < data_end
            if is_taken {
                // Taken: safe to access bytes [0, offset - 1]
                if offset > 0 {
                    return Some((0, PacketRange::new(0, offset - 1)));
                }
            }
        }
        BPF_JLE => {
            // data + offset <= data_end
            if is_taken {
                // Taken: safe to access bytes [0, offset]
                return Some((0, PacketRange::new(0, offset)));
            }
        }
        _ => {}
    }

    None
}

/// Invert a jump operation (for swapped operands)
pub fn invert_jmp_op(op: u8) -> u8 {
    match op {
        BPF_JGT => BPF_JLT,
        BPF_JGE => BPF_JLE,
        BPF_JLT => BPF_JGT,
        BPF_JLE => BPF_JGE,
        BPF_JSGT => BPF_JSLT,
        BPF_JSGE => BPF_JSLE,
        BPF_JSLT => BPF_JSGT,
        BPF_JSLE => BPF_JSGE,
        other => other,
    }
}

/// Track packet pointer derivation
/// When data + N is computed, track the relationship
pub fn track_packet_ptr_derivation(
    dst: &mut BpfRegState,
    src: &BpfRegState,
    offset_delta: i32,
) -> Result<()> {
    if src.reg_type != BpfRegType::PtrToPacket && src.reg_type != BpfRegType::PtrToPacketMeta {
        return Ok(());
    }

    let new_off = src.off + offset_delta;

    if new_off < 0 {
        return Err(VerifierError::InvalidPointerArithmetic(
            "packet pointer would have negative offset".into(),
        ));
    }

    if new_off > MAX_PACKET_OFF {
        return Err(VerifierError::InvalidPointerArithmetic(format!(
            "packet offset {} exceeds maximum",
            new_off
        )));
    }

    dst.reg_type = src.reg_type;
    dst.off = new_off;
    dst.id = src.id;

    Ok(())
}

/// Find packet pointers in registers
pub fn find_packet_pointers(regs: &[BpfRegState; MAX_BPF_REG]) -> PacketPointers {
    let mut result = PacketPointers::default();

    for (i, reg) in regs.iter().enumerate() {
        match reg.reg_type {
            BpfRegType::PtrToPacket => {
                if result.data.is_none() || reg.off == 0 {
                    result.data = Some(i);
                }
            }
            BpfRegType::PtrToPacketEnd => {
                result.data_end = Some(i);
            }
            BpfRegType::PtrToPacketMeta => {
                result.data_meta = Some(i);
            }
            _ => {}
        }
    }

    result
}

/// Found packet pointers in registers
#[derive(Debug, Default)]
pub struct PacketPointers {
    /// Register with PTR_TO_PACKET (preferring offset 0)
    pub data: Option<usize>,
    /// Register with PTR_TO_PACKET_END
    pub data_end: Option<usize>,
    /// Register with PTR_TO_PACKET_META
    pub data_meta: Option<usize>,
}

impl PacketPointers {
    /// Check if we have both data and data_end for bounds checking
    pub fn can_check_bounds(&self) -> bool {
        self.data.is_some() && self.data_end.is_some()
    }
}

/// Compute safe packet range from register bounds
pub fn compute_safe_range_from_reg(reg: &BpfRegState, verified_length: i32) -> Option<PacketRange> {
    if reg.reg_type != BpfRegType::PtrToPacket {
        return None;
    }

    let start = reg.off;
    let end = start + verified_length;

    if start >= 0 && end <= MAX_PACKET_OFF {
        Some(PacketRange::new(start, end))
    } else {
        None
    }
}

/// Update packet bounds after helper call that may modify packet
pub fn invalidate_packet_bounds_after_helper(ctx: &mut PacketBoundsContext, helper_id: u32) {
    // Helpers that can change packet size/contents
    let invalidates = matches!(
        helper_id,
        9 | // skb_store_bytes
        31 | // skb_change_proto
        38 | // skb_change_tail
        39 | // skb_pull_data
        43 | // skb_change_head
        44 | // xdp_adjust_head
        50 | // skb_adjust_room
        54 | // xdp_adjust_meta
        65 // xdp_adjust_tail
    );

    if invalidates {
        ctx.verified_ranges.clear();
        ctx.in_checked_region = false;
        for bounds in ctx.var_bounds.iter_mut() {
            *bounds = None;
        }
    }
}
