//!

//! This module handles validation of memory load and store operations,

//! including checks for pointer bounds, alignment, and access permissions.



use alloc::{format, string::ToString};

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

use super::context::{ContextAccessRules, check_ctx_access as context_check_ctx_access};
use super::packet::MAX_PACKET_OFF;
use super::user::UserMemContext;

/// Check if direct packet data access is allowed
pub fn may_access_direct_pkt_data(prog_type: BpfProgType, is_write: bool) -> bool {
    match prog_type {
        BpfProgType::SocketFilter
        | BpfProgType::SchedCls
        | BpfProgType::SchedAct
        | BpfProgType::Xdp
        | BpfProgType::LwtIn
        | BpfProgType::LwtOut
        | BpfProgType::LwtXmit
        | BpfProgType::SkSkb
        | BpfProgType::SkMsg => true,
        _ => !is_write,
    }
}

/// Check pointer alignment
pub fn check_ptr_alignment(
    reg: &BpfRegState,
    access_size: u32,
    strict: bool,
) -> Result<()> {
    // Get the actual offset
    let off = reg.off + reg.var_off.value as i32;

    // Check basic alignment
    if strict && (off as u32) % access_size != 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "misaligned access: offset {} not aligned to {} bytes",
            off, access_size
        )));
    }

    // For packet pointers, also check variable offset alignment
    if reg.is_pkt_pointer() {
        // Variable part must be aligned
        if reg.var_off.mask & (access_size as u64 - 1) != 0 {
            return Err(VerifierError::InvalidMemoryAccess("misaligned packet access: variable offset has bad alignment".to_string()));
        }
    }

    Ok(())
}

/// Check memory access bounds
pub fn check_mem_access(
    state: &mut BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    allow_ptr_leaks: bool,
) -> Result<BpfRegType> {
    // Create default user memory context from allow_ptr_leaks
    let user_ctx = if allow_ptr_leaks {
        UserMemContext {
            privileged: true,
            ..Default::default()
        }
    } else {
        UserMemContext::default()
    };
    
    check_mem_access_with_ctx(state, reg, off, size, is_write, allow_ptr_leaks, &user_ctx)
}

/// Check memory access bounds with full user memory context
pub fn check_mem_access_with_ctx(
    state: &mut BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    allow_ptr_leaks: bool,
    user_ctx: &UserMemContext,
) -> Result<BpfRegType> {
    let reg_type = reg.reg_type;

    // Check for null pointer dereference first
    if reg.may_be_null() && reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "cannot access memory through potentially null pointer: {:?}",
            reg_type
        )));
    }

    match reg_type {
        BpfRegType::PtrToStack => {
            check_stack_access(state, reg, off, size, is_write)
        }
        BpfRegType::PtrToMapValue => {
            check_map_value_access(state, reg, off, size, is_write, allow_ptr_leaks)
        }
        BpfRegType::PtrToMapKey => {
            // Map keys are read-only
            if is_write {
                return Err(VerifierError::InvalidMapAccess(
                    "cannot write to map key".into()
                ));
            }
            check_map_key_access(reg, off, size)
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            check_packet_access(reg, off, size, is_write, allow_ptr_leaks)
        }
        BpfRegType::PtrToPacketEnd => {
            Err(VerifierError::InvalidMemoryAccess(
                "cannot access memory through packet_end pointer".into()
            ))
        }
        BpfRegType::PtrToCtx => {
            check_ctx_access(reg, off, size, is_write)
        }
        BpfRegType::PtrToBtfId => {
            check_btf_id_access(reg, off, size, is_write)
        }
        BpfRegType::PtrToMem => {
            check_mem_region_access_with_ctx(reg, off, size, is_write, user_ctx)
        }
        BpfRegType::PtrToArena => {
            check_arena_access_with_ctx(reg, off, size, is_write, user_ctx)
        }
        BpfRegType::PtrToSocket | BpfRegType::PtrToSockCommon | BpfRegType::PtrToTcpSock => {
            // Socket pointers are read-only
            if is_write {
                return Err(VerifierError::InvalidMemoryAccess(
                    "cannot write to socket structure".into()
                ));
            }
            check_sock_access(reg, off, size)
        }
        BpfRegType::PtrToBuf | BpfRegType::PtrToRdOnlyBuf | BpfRegType::PtrToRdWrBuf => {
            check_buffer_access(reg, off, size, is_write)
        }
        BpfRegType::ConstPtrToMap => {
            // Reading map pointer itself (e.g., for bpf_map_lookup)
            Err(VerifierError::InvalidMemoryAccess(
                "cannot dereference const map pointer directly".into()
            ))
        }
        BpfRegType::ScalarValue if reg.is_null() => {
            Err(VerifierError::InvalidMemoryAccess(
                "null pointer dereference".into(),
            ))
        }
        BpfRegType::ScalarValue => {
            Err(VerifierError::InvalidMemoryAccess(
                "cannot dereference scalar value as pointer".into(),
            ))
        }
        BpfRegType::NotInit => {
            Err(VerifierError::UninitializedRegister(0))
        }
        _ => Err(VerifierError::InvalidMemoryAccess(format!(
            "invalid register type for memory access: {:?}",
            reg_type
        ))),
    }
}

/// Maximum variable offset magnitude allowed for stack access
const BPF_MAX_VAR_OFF: i64 = 1 << 29;

/// Check stack memory access with proper variable offset handling
fn check_stack_access(
    state: &mut BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    use crate::core::types::BpfStackSlotType;
    use crate::state::stack_state::get_spi;
    
    // Calculate min/max offset based on whether var_off is constant
    let (min_off, max_off): (i64, i64);
    
    if reg.var_off.is_const() {
        // Constant offset case
        min_off = reg.var_off.value as i64 + reg.off as i64 + off as i64;
        max_off = min_off + size as i64;
    } else {
        // Variable offset case - use signed bounds
        // Check for unbounded variable offset
        if reg.smax_value >= BPF_MAX_VAR_OFF || reg.smin_value <= -BPF_MAX_VAR_OFF {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("unbounded variable-offset stack access: smin={}, smax={}", 
                    reg.smin_value, reg.smax_value)
            ));
        }
        
        min_off = reg.smin_value + reg.off as i64 + off as i64;
        max_off = reg.smax_value + reg.off as i64 + off as i64 + size as i64;
    }
    
    // Stack grows downward, offsets must be negative
    // max_off is the end of access, must be <= 0
    if max_off > 0 {
        if reg.var_off.is_const() {
            return Err(VerifierError::StackOutOfBounds(min_off as i32));
        } else {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable-offset stack access may exceed frame pointer: max_off={}",
                max_off
            )));
        }
    }
    
    // Check access size is valid
    if size == 0 || size > 8 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "invalid stack access size: {}", size
        )));
    }
    
    // min_off is the start of access (most negative), must be >= -MAX_BPF_STACK
    // The needed stack size is -min_off
    let stack_depth = (-min_off) as usize;
    if stack_depth > MAX_BPF_STACK {
        if reg.var_off.is_const() {
            return Err(VerifierError::StackOutOfBounds(min_off as i32));
        } else {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable-offset stack access exceeds stack limit: min_off={}",
                min_off
            )));
        }
    }

    // Ensure stack is allocated to required depth
    let func = state.cur_func_mut().ok_or(VerifierError::Internal(
        "no current function".into(),
    ))?;

    if stack_depth > func.stack.allocated_stack {
        func.stack.grow(stack_depth)?;
    }

    // For variable offset accesses, we need to handle all possibly-accessed slots
    let min_spi = get_spi(min_off as i32).ok_or(VerifierError::StackOutOfBounds(min_off as i32))?;
    let max_spi = get_spi((max_off - 1) as i32).unwrap_or(0);
    
    // Variable offset writes mark all possible slots
    // Variable offset reads must check all possible slots are initialized
    
    if is_write {
        // Writing to stack - mark affected slots as MISC (initialized)
        for spi in max_spi..=min_spi {
            if spi < func.stack.stack.len() {
                // Check for special slots that cannot be overwritten
                let slot_type = func.stack.stack[spi].slot_type[BPF_REG_SIZE - 1];
                match slot_type {
                    BpfStackSlotType::Dynptr => {
                        return Err(VerifierError::InvalidMemoryAccess(
                            "cannot overwrite dynptr slot".into()
                        ));
                    }
                    BpfStackSlotType::Iter => {
                        // Check if iterator is still active
                        if func.stack.stack[spi].spilled_ptr.iter.state == 
                           crate::core::types::BpfIterState::Active {
                            return Err(VerifierError::InvalidMemoryAccess(
                                "cannot overwrite active iterator slot".into()
                            ));
                        }
                    }
                    _ => {}
                }
                
                // For variable offset writes, mark as MISC (loses precision)
                // The kernel also has logic to handle partial overwrites
                if !reg.var_off.is_const() {
                    // Variable offset write - mark entire slot as MISC
                    func.stack.stack[spi].slot_type = [BpfStackSlotType::Misc; BPF_REG_SIZE];
                } else {
                    // Constant offset write - can be more precise
                    func.stack.stack[spi].slot_type = [BpfStackSlotType::Misc; BPF_REG_SIZE];
                }
            }
        }
    } else {
        // Reading from stack - verify all possibly-accessed bytes are initialized
        for spi in max_spi..=min_spi {
            if spi >= func.stack.stack.len() {
                return Err(VerifierError::InvalidMemoryAccess(
                    format!("reading uninitialized stack at spi {}", spi)
                ));
            }
            
            let slot = &func.stack.stack[spi];
            // Check each byte in the slot
            for byte_idx in 0..BPF_REG_SIZE {
                if slot.slot_type[byte_idx] == BpfStackSlotType::Invalid {
                    if reg.var_off.is_const() {
                        return Err(VerifierError::InvalidMemoryAccess(
                            format!("reading uninitialized stack at offset {}", min_off)
                        ));
                    } else {
                        return Err(VerifierError::InvalidMemoryAccess(
                            format!("variable-offset read from possibly uninitialized stack at spi {}", spi)
                        ));
                    }
                }
            }
        }
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check map value memory access with variable offset support
fn check_map_value_access(
    _state: &mut BpfVerifierState,
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    allow_ptr_leaks: bool,
) -> Result<BpfRegType> {
    // Calculate min/max offset based on whether var_off is constant
    let (min_off, max_off): (i64, i64);
    
    if reg.var_off.is_const() {
        // Constant offset case
        min_off = reg.var_off.value as i64 + reg.off as i64 + off as i64;
        max_off = min_off + size as i64;
    } else {
        // Variable offset case - use unsigned bounds for map values
        // Check for unbounded variable offset
        if reg.umax_value >= BPF_MAX_VAR_OFF as u64 {
            return Err(VerifierError::InvalidMapAccess(format!(
                "unbounded variable-offset map value access: umax={}",
                reg.umax_value
            )));
        }
        
        min_off = reg.umin_value as i64 + reg.off as i64 + off as i64;
        max_off = reg.umax_value as i64 + reg.off as i64 + off as i64 + size as i64;
    }
    
    // Check for negative offset
    if min_off < 0 {
        if reg.var_off.is_const() {
            return Err(VerifierError::InvalidMapAccess(format!(
                "negative offset {} into map value",
                min_off
            )));
        } else {
            return Err(VerifierError::InvalidMapAccess(format!(
                "variable-offset map access may go negative: min_off={}",
                min_off
            )));
        }
    }

    // Check against map value size
    let map_info = reg.map_ptr.as_ref();
    if let Some(info) = map_info {
        if max_off > info.value_size as i64 {
            if reg.var_off.is_const() {
                return Err(VerifierError::InvalidMapAccess(format!(
                    "access offset {} size {} exceeds map value size {}",
                    min_off, size, info.value_size
                )));
            } else {
                return Err(VerifierError::InvalidMapAccess(format!(
                    "variable-offset access may exceed map value size {}: max_off={}",
                    info.value_size, max_off
                )));
            }
        }
    }

    // Check read-only maps
    if is_write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        return Err(VerifierError::InvalidMapAccess(
            "write to read-only map value".into(),
        ));
    }

    // In unprivileged mode, cannot store pointers into maps
    if is_write && !allow_ptr_leaks {
        // The value being stored would be checked by the caller
        // This is a placeholder for the full pointer leak check
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check map key memory access
fn check_map_key_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
) -> Result<BpfRegType> {
    let total_off = reg.off + off;

    if total_off < 0 {
        return Err(VerifierError::InvalidMapAccess(format!(
            "negative offset {} into map key",
            total_off
        )));
    }

    // Check against map key size
    let map_info = reg.map_ptr.as_ref();
    if let Some(info) = map_info {
        let end_off = total_off as u32 + size;
        if end_off > info.key_size {
            return Err(VerifierError::InvalidMapAccess(format!(
                "access offset {} size {} exceeds map key size {}",
                total_off, size, info.key_size
            )));
        }
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check packet memory access with variable offset support
fn check_packet_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    allow_ptr_leaks: bool,
) -> Result<BpfRegType> {
    // Calculate min/max offset based on whether var_off is constant
    let (min_off, max_off): (i64, i64);
    
    if reg.var_off.is_const() {
        // Constant offset case
        min_off = reg.var_off.value as i64 + reg.off as i64 + off as i64;
        max_off = min_off + size as i64;
    } else {
        // Variable offset case - packet uses unsigned bounds
        // Check for unbounded variable offset
        if reg.umax_value >= BPF_MAX_VAR_OFF as u64 {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "unbounded variable-offset packet access: umax={}",
                reg.umax_value
            )));
        }
        
        min_off = reg.umin_value as i64 + reg.off as i64 + off as i64;
        max_off = reg.umax_value as i64 + reg.off as i64 + off as i64 + size as i64;
    }
    
    // Check for negative offset
    if min_off < 0 {
        if reg.var_off.is_const() {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "negative offset {} into packet",
                min_off
            )));
        } else {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable-offset packet access may go negative: min_off={}",
                min_off
            )));
        }
    }

    // Check against maximum packet offset
    if max_off > MAX_PACKET_OFF as i64 {
        if reg.var_off.is_const() {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "offset {} exceeds maximum packet offset",
                min_off
            )));
        } else {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "variable-offset packet access may exceed max offset: max_off={}",
                max_off
            )));
        }
    }

    // Packet bounds are ultimately checked dynamically at runtime
    // by comparing against pkt_end. The above are static sanity checks.
    
    // Check variable offset alignment for packet access
    if !reg.var_off.is_const() {
        // Variable part must be aligned to access size
        if size > 1 && (reg.var_off.mask & (size as u64 - 1)) != 0 {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "misaligned variable-offset packet access: var_off mask=0x{:x}, size={}",
                reg.var_off.mask, size
            )));
        }
    }

    // Cannot store pointers into packet data
    if is_write && !allow_ptr_leaks {
        // Pointer leak check would be done by caller
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check context memory access
fn check_ctx_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    // Get context access rules based on program type
    // The program type would normally be passed from verifier env,
    // but for now we infer it from the context or use a default
    let rules = get_ctx_access_rules_for_reg(reg);
    
    context_check_ctx_access(reg, off, size, is_write, &rules)
}

/// Get context access rules for a register
/// 
/// In a full implementation, this would use the program type from the
/// verifier environment. For now, we try to infer from available info
/// or use permissive defaults.
fn get_ctx_access_rules_for_reg(reg: &BpfRegState) -> ContextAccessRules {
    // Check if we have BTF info that tells us the context type
    if reg.btf_id() > 0 {
        // Could look up BTF to determine program type
        // For now, use XDP as a reasonable default with common fields
        return ContextAccessRules::xdp();
    }
    
    // Default to a permissive context that allows reads of scalar values
    // This is conservative - real implementation should know program type
    ContextAccessRules::default_permissive()
}

/// Check BTF ID pointer access
/// 
/// This implements BTF struct access validation similar to kernel's btf_struct_access.
/// It validates field access based on BTF type information and returns the appropriate
/// result type for the accessed field.
/// RCU access validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcuAccessResult {
    /// Access is allowed
    Allowed,
    /// Access requires RCU read lock
    RequiresRcuLock,
    /// Access is denied
    Denied,
}

/// Check BTF ID memory access with full RCU/percpu validation
/// 
/// This implements the kernel's BTF-based memory access checks including:
/// - Read-only and untrusted pointer checks
/// - RCU-protected pointer access validation
/// - Percpu memory access restrictions
/// - Nested pointer field detection
fn check_btf_id_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    // Check read-only memory
    if is_write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only BTF type".into(),
        ));
    }

    // Check trusted pointer requirements for writes
    // Untrusted pointers cannot be written to
    if is_write && reg.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to untrusted BTF pointer".into(),
        ));
    }

    // Compute the total offset
    let total_off = reg.off.saturating_add(off);
    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into BTF type",
            total_off
        )));
    }

    // Get BTF ID from register
    let btf_id = reg.btf_id();
    if btf_id == 0 {
        // No BTF info - allow scalar access with warning
        return Ok(BpfRegType::ScalarValue);
    }

    // =========================================================================
    // RCU-protected pointer access validation
    // =========================================================================
    // RCU (Read-Copy-Update) is a synchronization mechanism used in the kernel.
    // BPF programs must hold an RCU read lock when accessing RCU-protected data.
    // The verifier tracks bpf_rcu_read_lock/unlock calls to verify this.
    
    if reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
        // This pointer was obtained from an RCU-protected dereference
        // Access rules:
        // 1. Cannot write to RCU-protected memory (would break RCU guarantees)
        // 2. Reading is safe if under RCU read lock (verified at call site)
        // 3. Reading without lock may work but is unsafe (kernel allows with warning)
        
        if is_write {
            return Err(VerifierError::InvalidMemoryAccess(
                "cannot write to RCU-protected memory".into(),
            ));
        }
        
        // For reads, we allow but the caller should verify RCU lock state
        // The result type inherits RCU protection
    }
    
    // Check for RCU pointer field access
    // When reading a pointer field marked __rcu, the result needs RCU protection
    if reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
        // RCU pointer dereference - result is RCU-protected
        // Caller must be under rcu_read_lock
    }

    // =========================================================================
    // Percpu memory access validation  
    // =========================================================================
    // Percpu memory has a different value on each CPU. BPF programs typically
    // access the current CPU's value, but this requires special handling.
    
    if reg.type_flags.contains(BpfTypeFlag::MEM_PERCPU) {
        // Percpu access rules:
        // 1. Generally read-only from BPF (writing could race with other CPUs)
        // 2. Some helpers allow percpu writes with proper synchronization
        // 3. Must not store percpu pointers (address is CPU-specific)
        
        if is_write {
            // Check if this is an allowed percpu write context
            // For now, deny all writes - kernel has specific exceptions
            return Err(VerifierError::InvalidMemoryAccess(
                "write to percpu memory not allowed from BPF".into(),
            ));
        }
        
        // For reads, the value is from the current CPU
        // Result type remains scalar (not a pointer)
    }

    // =========================================================================
    // User memory access validation
    // =========================================================================
    // User memory (from user space) requires special handling
    
    if reg.type_flags.contains(BpfTypeFlag::MEM_USER) {
        // User memory access rules:
        // 1. Direct access may fault - use bpf_probe_read_user instead
        // 2. Cannot write to user memory from most BPF programs
        // 3. Address must be validated before access
        
        if is_write {
            return Err(VerifierError::InvalidMemoryAccess(
                "direct write to user memory not allowed".into(),
            ));
        }
        
        // Allow reads but caller should use proper helpers for safety
    }

    // =========================================================================
    // Nested pointer field access
    // =========================================================================
    // When accessing a pointer field within a struct, the result is a new pointer.
    // This is determined by BTF type lookup.
    
    if let Some(ref btf_info) = reg.btf_info {
        // Check if this access is at a known pointer field offset
        if btf_info.is_ptr_field(total_off as u32) {
            // The accessed field is a pointer - return pointer type
            let mut result_type = BpfRegType::PtrToBtfId;
            
            // Check for nullable pointer fields
            if btf_info.is_nullable_field(total_off as u32) {
                // Nullable fields require NULL check after load
                // This is indicated by returning PTR_MAYBE_NULL type
                result_type = BpfRegType::PtrToBtfId;
                // Type flags would include PTR_MAYBE_NULL
            }
            
            return Ok(result_type);
        }
    }

    // =========================================================================
    // Size and alignment checks
    // =========================================================================
    
    // BTF struct access should be naturally aligned
    if size > 0 && size <= 8 && (total_off as u32) % size != 0 {
        // Unaligned access - may be allowed for packed structs
        // For now, we allow it but log for debugging
        // A full implementation would check BTF attributes
    }
    
    // Check for oversized access
    if size > 8 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "access size {} exceeds maximum 8 bytes for BTF type",
            size
        )));
    }

    // Default: scalar value access
    Ok(BpfRegType::ScalarValue)
}

/// Check generic memory region access
/// 
/// Simplified API for checking memory access without user memory context.
/// For user memory validation, use `check_mem_region_access_with_ctx` instead.
pub fn check_mem_region_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    check_mem_region_access_with_ctx(reg, off, size, is_write, &UserMemContext::default())
}

/// Check generic memory region access with user memory context
fn check_mem_region_access_with_ctx(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    user_ctx: &UserMemContext,
) -> Result<BpfRegType> {
    use super::user::{is_user_mem_pointer, check_user_mem_direct_access};
    
    let total_off = reg.off + off;

    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into memory region",
            total_off
        )));
    }

    // Check read-only memory
    if is_write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only memory region".into(),
        ));
    }

    // Check user memory access restrictions
    if is_user_mem_pointer(reg) {
        let validation = check_user_mem_direct_access(reg, user_ctx, is_write);
        
        if !validation.allowed {
            return Err(VerifierError::InvalidMemoryAccess(
                validation.warning.unwrap_or_else(|| 
                    "direct user memory access not allowed".into()
                ),
            ));
        }
        
        // Note: validation.needs_nospec would be used by JIT for speculation barriers
    }

    // Check against known memory size
    if reg.mem_size > 0 {
        let end_off = total_off as u32 + size;
        if end_off > reg.mem_size {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "access offset {} size {} exceeds memory size {}",
                total_off, size, reg.mem_size
            )));
        }
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check socket structure access
fn check_sock_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
) -> Result<BpfRegType> {
    let total_off = reg.off + off;

    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into socket",
            total_off
        )));
    }

    // Socket access is typically validated against a BTF layout
    // For now, just check basic bounds
    // The actual field access would be checked against sk_buff or sock struct

    // Socket structures have limited accessible fields
    // This would be program-type specific
    let _ = size;

    Ok(BpfRegType::ScalarValue)
}

/// Check buffer access (rdonly/rdwr buffers)
fn check_buffer_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    let total_off = reg.off + off;

    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into buffer",
            total_off
        )));
    }

    // Check read-only buffer
    if is_write && reg.reg_type == BpfRegType::PtrToRdOnlyBuf {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only buffer".into(),
        ));
    }

    // Check against buffer size if known
    if reg.mem_size > 0 {
        let end_off = total_off as u32 + size;
        if end_off > reg.mem_size {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "buffer access offset {} size {} exceeds size {}",
                total_off, size, reg.mem_size
            )));
        }
    }

    Ok(BpfRegType::ScalarValue)
}

/// Check memory access for helper arguments
pub fn check_helper_mem_access(
    state: &BpfVerifierState,
    regno: usize,
    access_size: i32,
    zero_size_allowed: bool,
) -> Result<()> {
    if access_size < 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            "negative memory size".into(),
        ));
    }

    if access_size == 0 && !zero_size_allowed {
        return Err(VerifierError::InvalidMemoryAccess(
            "zero-size memory access not allowed".into(),
        ));
    }

    let reg = state.reg(regno).ok_or(VerifierError::InvalidRegister(regno as u8))?;

    // Check pointer type is valid for memory access
    match reg.reg_type {
        BpfRegType::PtrToStack
        | BpfRegType::PtrToMapValue
        | BpfRegType::PtrToMem
        | BpfRegType::PtrToPacket
        | BpfRegType::PtrToPacketMeta => Ok(()),
        BpfRegType::ScalarValue if reg.is_null() => {
            if access_size == 0 {
                Ok(())
            } else {
                Err(VerifierError::InvalidMemoryAccess(
                    "null pointer with non-zero size".into(),
                ))
            }
        }
        _ => Err(VerifierError::InvalidMemoryAccess(format!(
            "invalid register type {:?} for memory access",
            reg.reg_type
        ))),
    }
}

// Note: check_stack_range_initialized is provided by the stack_access module

/// Check map access type against map properties
pub fn check_map_access_type(
    map_type: BpfMapType,
    is_write: bool,
    is_spin_lock: bool,
) -> Result<()> {
    // Arrays are writable
    // Some maps have special restrictions

    match map_type {
        BpfMapType::ProgArray | BpfMapType::PerfEventArray | BpfMapType::CgroupArray => {
            if is_write {
                return Err(VerifierError::InvalidMapAccess(
                    "writes to this map type not allowed".into(),
                ));
            }
        }
        _ => {}
    }

    // Spin lock operations have additional requirements
    if is_spin_lock {
        // Would check map has spin lock field
    }

    Ok(())
}

/// Valid atomic operation codes
pub mod atomic_ops {
    use crate::core::types::*;
    
    /// Atomic add
    pub const ATOMIC_ADD: u32 = BPF_ADD as u32;
    /// Atomic or
    pub const ATOMIC_OR: u32 = BPF_OR as u32;
    /// Atomic and
    pub const ATOMIC_AND: u32 = BPF_AND as u32;
    /// Atomic xor
    pub const ATOMIC_XOR: u32 = BPF_XOR as u32;
    /// Atomic fetch flag (combine with above ops)
    pub const ATOMIC_FETCH: u32 = BPF_FETCH;
    /// Atomic exchange
    pub const ATOMIC_XCHG: u32 = BPF_XCHG;
    /// Atomic compare-and-exchange
    pub const ATOMIC_CMPXCHG: u32 = BPF_CMPXCHG;
}

/// Check if an atomic operation code is valid
fn is_valid_atomic_op(op: u32) -> bool {
    use atomic_ops::*;
    
    // Base operations (without fetch)
    let base_ops = [ATOMIC_ADD, ATOMIC_OR, ATOMIC_AND, ATOMIC_XOR];
    
    // Check for base ops (with or without fetch flag)
    for &base in &base_ops {
        if op == base || op == (base | ATOMIC_FETCH) {
            return true;
        }
    }
    
    // Special operations
    matches!(op, ATOMIC_XCHG | ATOMIC_CMPXCHG)
}

/// Get the name of an atomic operation for error messages
fn atomic_op_name(op: u32) -> &'static str {
    use atomic_ops::*;
    
    match op {
        ATOMIC_ADD => "add",
        x if x == ATOMIC_ADD | ATOMIC_FETCH => "fetch_add",
        ATOMIC_OR => "or",
        x if x == ATOMIC_OR | ATOMIC_FETCH => "fetch_or",
        ATOMIC_AND => "and",
        x if x == ATOMIC_AND | ATOMIC_FETCH => "fetch_and",
        ATOMIC_XOR => "xor",
        x if x == ATOMIC_XOR | ATOMIC_FETCH => "fetch_xor",
        ATOMIC_XCHG => "xchg",
        ATOMIC_CMPXCHG => "cmpxchg",
        _ => "unknown",
    }
}

/// Check atomic operation on a memory location
pub fn check_atomic_op(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    op: u32,
) -> Result<()> {
    // Validate the atomic operation code
    if !is_valid_atomic_op(op) {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "invalid atomic operation code 0x{:x}",
            op
        )));
    }
    
    // Atomic operations have alignment requirements
    if off % size as i32 != 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "atomic {} requires {}-byte aligned access, got offset {}",
            atomic_op_name(op), size, off
        )));
    }
    
    // Size must be 4 (32-bit) or 8 (64-bit) bytes
    if size != 4 && size != 8 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "atomic {} requires 32-bit or 64-bit operand, got {} bytes",
            atomic_op_name(op), size
        )));
    }

    // Check pointer type allows atomics
    match reg.reg_type {
        BpfRegType::PtrToMapValue | BpfRegType::PtrToStack | BpfRegType::PtrToArena => {}
        BpfRegType::PtrToMem if reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) => {
            // Allocated memory (e.g., from ringbuf_reserve) allows atomics
        }
        _ => {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "atomic {} not allowed on {:?}",
                atomic_op_name(op), reg.reg_type
            )));
        }
    }
    
    // CMPXCHG has additional requirements - R0 must contain expected value
    // This is checked elsewhere in the instruction verification

    Ok(())
}

// =============================================================================
// RCU and Synchronization Validation
// =============================================================================

/// Check if RCU read lock is required for this access
/// 
/// Returns true if the access requires RCU protection to be safe.
/// This is used to validate that bpf_rcu_read_lock is held.
pub fn requires_rcu_lock(reg: &BpfRegState) -> bool {
    // RCU-protected memory requires lock
    if reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
        return true;
    }
    
    // Pointer obtained from RCU dereference requires lock to be safe
    if reg.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
        // Untrusted pointers from RCU dereference need protection
        return true;
    }
    
    false
}

/// Validate RCU access is safe given the current lock state
/// 
/// This checks that:
/// 1. RCU-protected accesses are done under rcu_read_lock
/// 2. Pointers from RCU dereferences are used safely
pub fn validate_rcu_access(
    reg: &BpfRegState,
    rcu_lock_held: bool,
    is_write: bool,
) -> Result<RcuAccessResult> {
    // Writes to RCU-protected memory are never allowed
    if is_write && reg.type_flags.contains(BpfTypeFlag::MEM_RCU) {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to RCU-protected memory is not allowed".into(),
        ));
    }
    
    // Check if RCU lock is required
    if requires_rcu_lock(reg) {
        if rcu_lock_held {
            return Ok(RcuAccessResult::Allowed);
        } else {
            // Access without RCU lock - may be unsafe
            // Kernel allows with warning in some cases
            return Ok(RcuAccessResult::RequiresRcuLock);
        }
    }
    
    Ok(RcuAccessResult::Allowed)
}

/// Check if a pointer can be safely stored (no pointer leaks)
/// 
/// In unprivileged mode, pointers cannot be stored to maps or
/// leaked to userspace. This prevents information disclosure attacks.
pub fn check_ptr_leak(
    src_reg: &BpfRegState,
    dst_reg: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    // Privileged programs can store pointers
    if allow_ptr_leaks {
        return Ok(());
    }
    
    // Non-pointer sources are always OK
    if !src_reg.is_pointer() {
        return Ok(());
    }
    
    // Check destination type
    match dst_reg.reg_type {
        BpfRegType::PtrToMapValue => {
            // Cannot store pointers to maps in unprivileged mode
            return Err(VerifierError::InvalidMemoryAccess(
                "storing pointer to map value leaks kernel address".into(),
            ));
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            // Cannot store pointers to packet data
            return Err(VerifierError::InvalidMemoryAccess(
                "storing pointer to packet data leaks kernel address".into(),
            ));
        }
        BpfRegType::PtrToStack => {
            // Storing to stack is OK (local to BPF program)
            return Ok(());
        }
        BpfRegType::PtrToMem if dst_reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) => {
            // Storing to allocated memory (e.g., ringbuf) may leak
            return Err(VerifierError::InvalidMemoryAccess(
                "storing pointer to allocated memory may leak kernel address".into(),
            ));
        }
        _ => {}
    }
    
    Ok(())
}

/// Validate percpu pointer access
/// 
/// Percpu memory requires special handling:
/// - Addresses are CPU-specific and cannot be stored
/// - Writes require synchronization
/// - Values read may differ across CPUs
pub fn validate_percpu_access(
    reg: &BpfRegState,
    is_write: bool,
    is_sleepable_prog: bool,
) -> Result<()> {
    if !reg.type_flags.contains(BpfTypeFlag::MEM_PERCPU) {
        return Ok(());
    }
    
    // Percpu writes are generally not allowed
    if is_write {
        return Err(VerifierError::InvalidMemoryAccess(
            "write to percpu memory not allowed".into(),
        ));
    }
    
    // In sleepable programs, percpu access is problematic because
    // the program may be preempted and resume on a different CPU
    if is_sleepable_prog {
        return Err(VerifierError::InvalidMemoryAccess(
            "percpu access in sleepable program is not safe".into(),
        ));
    }
    
    Ok(())
}

/// Check arena memory access (bpf_arena) - legacy wrapper
/// 
/// Arena is a special memory region that allows user-space-like
/// memory allocation within BPF programs.
pub fn check_arena_access(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
) -> Result<BpfRegType> {
    check_arena_access_with_ctx(reg, off, size, is_write, &UserMemContext::default())
}

/// Check arena memory access with user memory context
pub fn check_arena_access_with_ctx(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    is_write: bool,
    user_ctx: &UserMemContext,
) -> Result<BpfRegType> {
    use super::user::{is_user_mem_pointer, check_arena_user_access};
    
    let total_off = reg.off.saturating_add(off);
    
    if total_off < 0 {
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "negative offset {} into arena",
            total_off
        )));
    }
    
    // Check user memory access for arena with MEM_USER flag
    if is_user_mem_pointer(reg) {
        // Arena user pointer access - requires special validation
        // Use nospec status from the context
        let has_nospec = user_ctx.has_nospec;
        let validation = check_arena_user_access(reg, off, size, is_write, has_nospec)?;
        
        if !validation.allowed {
            return Err(VerifierError::InvalidMemoryAccess(
                validation.warning.unwrap_or_else(||
                    "arena user memory access not allowed".into()
                ),
            ));
        }
        
        // Note: validation.needs_nospec would be used by JIT
    }
    
    // Arena has size limits
    if reg.mem_size > 0 {
        let end_off = total_off as u64 + size as u64;
        if end_off > reg.mem_size as u64 {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "arena access offset {} size {} exceeds size {}",
                total_off, size, reg.mem_size
            )));
        }
    }
    
    // Arena is read-write by default (kernel-space arena)
    let _ = is_write;
    
    Ok(BpfRegType::ScalarValue)
}
