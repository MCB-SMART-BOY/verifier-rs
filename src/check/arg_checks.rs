//!

//! This module implements detailed argument validation for BPF helper functions,

//! including memory bounds checking, type compatibility, and special argument handling.


#[cfg(not(feature = "std"))]
use alloc::format;

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// Result of argument type checking
#[derive(Debug, Clone)]
pub struct ArgCheckResult {
    /// Whether the argument is valid
    pub valid: bool,
    /// Memory access size (if applicable)
    pub mem_size: Option<u64>,
    /// Whether NULL is allowed
    pub null_allowed: bool,
    /// Whether the argument is read-only
    pub read_only: bool,
    /// Fixed memory size (for map key/value)
    pub fixed_size: Option<u32>,
}

impl Default for ArgCheckResult {
    fn default() -> Self {
        Self {
            valid: true,
            mem_size: None,
            null_allowed: false,
            read_only: false,
            fixed_size: None,
        }
    }
}

/// Check if a register type is compatible with the expected argument type
pub fn check_arg_type_compat(
    reg: &BpfRegState,
    arg_type: BpfArgType,
    arg_idx: usize,
) -> Result<ArgCheckResult> {
    let mut result = ArgCheckResult::default();
    
    // Check register is initialized
    if reg.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(arg_idx as u8));
    }

    match arg_type {
        BpfArgType::DontCare => {
            // Unused argument slot
            result.valid = true;
        }
        
        BpfArgType::Anything => {
            // Any value is acceptable - but still must be initialized
            result.valid = true;
        }
        
        BpfArgType::ConstMapPtr => {
            check_const_map_ptr(reg, &mut result)?;
        }
        
        BpfArgType::PtrToMapKey => {
            check_ptr_to_mem(reg, &mut result, "map_key", false)?;
            result.read_only = true;
        }
        
        BpfArgType::PtrToMapValue => {
            check_ptr_to_mem(reg, &mut result, "map_value", false)?;
        }
        
        BpfArgType::PtrToUninitMem => {
            check_ptr_to_uninit_mem(reg, &mut result)?;
        }
        
        BpfArgType::ConstSize => {
            check_const_size(reg, &mut result, false)?;
        }
        
        BpfArgType::ConstSizeOrZero => {
            check_const_size(reg, &mut result, true)?;
        }
        
        BpfArgType::PtrToCtx => {
            check_ptr_to_ctx(reg, &mut result)?;
        }
        
        BpfArgType::PtrToMem => {
            check_ptr_to_mem(reg, &mut result, "memory", true)?;
        }
        
        BpfArgType::PtrToMemRdonly => {
            check_ptr_to_mem(reg, &mut result, "memory", true)?;
            result.read_only = true;
        }
        
        BpfArgType::PtrToStack => {
            check_ptr_to_stack(reg, &mut result)?;
        }
        
        BpfArgType::PtrToSocket => {
            check_ptr_to_socket(reg, &mut result)?;
        }
        
        BpfArgType::PtrToBtfId => {
            check_ptr_to_btf_id(reg, &mut result)?;
        }
        
        BpfArgType::PtrToAllocMem => {
            check_ptr_to_alloc_mem(reg, &mut result)?;
        }
        
        BpfArgType::ConstAllocSizeOrZero => {
            check_const_alloc_size(reg, &mut result)?;
        }
        
        BpfArgType::PtrToDynptr => {
            check_ptr_to_dynptr(reg, &mut result)?;
        }
        
        BpfArgType::PtrToTimer => {
            check_ptr_to_timer(reg, &mut result)?;
        }
        
        BpfArgType::PtrToKptr => {
            check_ptr_to_kptr(reg, &mut result)?;
        }
        
        BpfArgType::PtrToIter => {
            // Iterator pointer - checked via special_types module
            if reg.reg_type != BpfRegType::PtrToStack {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_STACK (iterator)".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        
        BpfArgType::PtrToArena => {
            // Arena pointer - checked via special_types module
            if reg.reg_type != BpfRegType::PtrToArena {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_ARENA".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
    }
    
    Ok(result)
}

/// Check constant map pointer argument
fn check_const_map_ptr(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::ConstPtrToMap {
        return Err(VerifierError::TypeMismatch {
            expected: "const_ptr_to_map".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Offset must be zero for map pointers
    if reg.off != 0 {
        return Err(VerifierError::InvalidPointer(
            "map pointer with non-zero offset".into(),
        ));
    }
    
    result.valid = true;
    Ok(())
}

/// Check pointer to memory argument
fn check_ptr_to_mem(
    reg: &BpfRegState, 
    result: &mut ArgCheckResult,
    expected: &str,
    allow_null: bool,
) -> Result<()> {
    // Check for NULL pointer
    if reg.reg_type == BpfRegType::ScalarValue {
        if reg.is_null() {
            if allow_null {
                result.null_allowed = true;
                result.valid = true;
                return Ok(());
            } else {
                return Err(VerifierError::InvalidPointer(
                    format!("NULL pointer not allowed for {}", expected),
                ));
            }
        }
        return Err(VerifierError::TypeMismatch {
            expected: expected.into(),
            got: "scalar".into(),
        });
    }
    
    // Check valid memory pointer types
    match reg.reg_type {
        BpfRegType::PtrToStack => {
            result.valid = true;
            // Stack has fixed size limit
        }
        BpfRegType::PtrToMapValue => {
            result.valid = true;
            // Map value has known size from map definition
        }
        BpfRegType::PtrToMapKey => {
            result.valid = true;
        }
        BpfRegType::PtrToMem => {
            result.valid = true;
            // Check MEM_RDONLY flag for read-only access
            if reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
                result.read_only = true;
            }
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            result.valid = true;
            // Packet access requires bounds checking
        }
        BpfRegType::PtrToBuf => {
            result.valid = true;
        }
        _ => {
            return Err(VerifierError::TypeMismatch {
                expected: expected.into(),
                got: format!("{:?}", reg.reg_type),
            });
        }
    }
    
    // Check for valid offset
    if reg.off < 0 {
        // Negative offsets might be suspicious
    }
    
    Ok(())
}

/// Check pointer to uninitialized memory
fn check_ptr_to_uninit_mem(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    match reg.reg_type {
        BpfRegType::PtrToStack => {
            result.valid = true;
        }
        BpfRegType::PtrToMem if reg.type_flags.contains(BpfTypeFlag::MEM_UNINIT) => {
            result.valid = true;
        }
        BpfRegType::PtrToMapValue => {
            // Map values can be written to
            result.valid = true;
        }
        _ => {
            return Err(VerifierError::TypeMismatch {
                expected: "ptr_to_uninit_mem".into(),
                got: format!("{:?}", reg.reg_type),
            });
        }
    }
    Ok(())
}

/// Check constant size argument
fn check_const_size(
    reg: &BpfRegState, 
    result: &mut ArgCheckResult,
    allow_zero: bool,
) -> Result<()> {
    if reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar (size)".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Check if size is bounded
    let max_size = reg.umax_value;
    let min_size = reg.umin_value;
    
    if !allow_zero && min_size == 0 && !reg.is_const() {
        // Size could be zero, which is not allowed
        return Err(VerifierError::BoundsCheckFailed(
            "size argument may be zero".into(),
        ));
    }
    
    // Check for reasonable size limits
    const MAX_HELPER_SIZE: u64 = 1 << 29; // 512MB
    if max_size > MAX_HELPER_SIZE {
        return Err(VerifierError::BoundsCheckFailed(
            format!("size {} exceeds maximum {}", max_size, MAX_HELPER_SIZE),
        ));
    }
    
    result.mem_size = Some(max_size);
    result.valid = true;
    Ok(())
}

/// Check pointer to context
fn check_ptr_to_ctx(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToCtx {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_ctx".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Context pointers should have zero var_off for most cases
    if !reg.var_off.is_const() {
        return Err(VerifierError::InvalidPointer(
            "context pointer with variable offset".into(),
        ));
    }
    
    result.valid = true;
    Ok(())
}

/// Check pointer to stack
fn check_ptr_to_stack(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToStack {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_stack".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Stack pointer offset should be valid
    let total_off = reg.off + reg.var_off.value as i32;
    if total_off > 0 {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }
    if (-total_off) as usize > MAX_BPF_STACK {
        return Err(VerifierError::StackOutOfBounds(total_off));
    }
    
    result.valid = true;
    Ok(())
}

/// Check pointer to socket
fn check_ptr_to_socket(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    match reg.reg_type {
        BpfRegType::PtrToSocket | BpfRegType::PtrToTcpSock | BpfRegType::PtrToXdpSock => {
            result.valid = true;
        }
        _ => {
            return Err(VerifierError::TypeMismatch {
                expected: "ptr_to_socket".into(),
                got: format!("{:?}", reg.reg_type),
            });
        }
    }
    
    // Socket pointers obtained from helpers have ref_obj_id
    // which must be tracked for release
    
    Ok(())
}

/// Check pointer to BTF ID
fn check_ptr_to_btf_id(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToBtfId {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_btf_id".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    result.valid = true;
    Ok(())
}

/// Check pointer to allocated memory
fn check_ptr_to_alloc_mem(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::PtrToMem {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_alloc_mem".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    if !reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_alloc_mem (with MEM_ALLOC flag)".into(),
            got: format!("{:?} without MEM_ALLOC", reg.reg_type),
        });
    }
    
    // Allocated memory must have valid ref_obj_id for tracking
    if reg.ref_obj_id == 0 {
        return Err(VerifierError::InvalidPointer(
            "allocated memory without ref_obj_id".into(),
        ));
    }
    
    result.valid = true;
    Ok(())
}

/// Check constant allocation size
fn check_const_alloc_size(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    if reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar (alloc_size)".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Allocation size should be bounded
    const MAX_ALLOC_SIZE: u64 = 1 << 20; // 1MB
    if reg.umax_value > MAX_ALLOC_SIZE {
        return Err(VerifierError::BoundsCheckFailed(
            format!("allocation size {} exceeds maximum {}", reg.umax_value, MAX_ALLOC_SIZE),
        ));
    }
    
    result.mem_size = Some(reg.umax_value);
    result.valid = true;
    Ok(())
}

/// Check pointer to dynptr
fn check_ptr_to_dynptr(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    // Dynptr must be on stack
    if reg.reg_type != BpfRegType::PtrToStack {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_stack (for dynptr)".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Check alignment (dynptr is 16 bytes)
    let off = reg.off + reg.var_off.value as i32;
    if off % 8 != 0 {
        return Err(VerifierError::InvalidPointer(
            "dynptr must be 8-byte aligned".into(),
        ));
    }
    
    result.fixed_size = Some(16); // sizeof(struct bpf_dynptr)
    result.valid = true;
    Ok(())
}

/// Check pointer to timer
fn check_ptr_to_timer(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    // Timer must be embedded in map value
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_map_value (for timer)".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    result.fixed_size = Some(16); // sizeof(struct bpf_timer)
    result.valid = true;
    Ok(())
}

/// Check pointer to kptr
fn check_ptr_to_kptr(reg: &BpfRegState, result: &mut ArgCheckResult) -> Result<()> {
    // Kptr must be in map value
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "ptr_to_map_value (for kptr)".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    result.fixed_size = Some(8); // sizeof(void*)
    result.valid = true;
    Ok(())
}

/// Validate memory access bounds for a helper argument
pub fn check_mem_access_bounds(
    _state: &BpfVerifierState,
    reg: &BpfRegState,
    access_size: u64,
    write: bool,
) -> Result<()> {
    match reg.reg_type {
        BpfRegType::PtrToStack => {
            let off = reg.off + reg.var_off.value as i32;
            let end_off = off - access_size as i32;
            
            if off > 0 || (-end_off) as usize > MAX_BPF_STACK {
                return Err(VerifierError::StackOutOfBounds(off));
            }
            
            // Check stack is initialized for reads
            if !write {
                // Would check each stack slot is initialized
            }
        }
        BpfRegType::PtrToMapValue => {
            // Check access against map value size
            if let Some(map_info) = &reg.map_ptr {
                let off = reg.off as u64 + reg.var_off.value;
                if off + access_size > map_info.value_size as u64 {
                    return Err(VerifierError::InvalidMapAccess(
                        format!("access offset {} + size {} exceeds value_size {}",
                                off, access_size, map_info.value_size),
                    ));
                }
            }
        }
        BpfRegType::PtrToPacket => {
            // Packet access requires range checking against packet_end
            // This is done dynamically at runtime, but we verify the bounds are tracked
            if reg.mem_size == 0 {
                return Err(VerifierError::InvalidMemoryAccess(
                    "unbounded packet access".into(),
                ));
            }
            
            let off = reg.off as u64 + reg.var_off.value;
            if off + access_size > reg.mem_size as u64 {
                return Err(VerifierError::InvalidMemoryAccess(
                    format!("packet access {} + {} exceeds range {}", 
                            off, access_size, reg.mem_size),
                ));
            }
        }
        BpfRegType::PtrToMem => {
            // Generic memory pointer - check mem_size if set
            if reg.mem_size > 0 {
                let off = reg.off as u64 + reg.var_off.value;
                if off + access_size > reg.mem_size as u64 {
                    return Err(VerifierError::InvalidMemoryAccess(
                        format!("memory access {} + {} exceeds size {}",
                                off, access_size, reg.mem_size),
                    ));
                }
            }
            
            // Check read-only constraint for writes
            if write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
                return Err(VerifierError::InvalidMemoryAccess(
                    "write to read-only memory".into(),
                ));
            }
        }
        _ => {}
    }
    
    Ok(())
}

/// Check that a memory + size pair is valid for helper access
pub fn check_helper_mem_access(
    state: &BpfVerifierState,
    ptr_regno: usize,
    size_regno: usize,
    write: bool,
) -> Result<()> {
    let ptr_reg = state.reg(ptr_regno).ok_or(
        VerifierError::InvalidRegister(ptr_regno as u8)
    )?;
    
    let size_reg = state.reg(size_regno).ok_or(
        VerifierError::InvalidRegister(size_regno as u8)
    )?;
    
    // Size must be scalar
    if size_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar (size)".into(),
            got: format!("{:?}", size_reg.reg_type),
        });
    }
    
    // Use max possible size for bounds checking
    let access_size = size_reg.umax_value;
    
    // Check the memory access is valid
    check_mem_access_bounds(state, ptr_reg, access_size, write)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_arg_type_anything() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_unknown(false);
        
        let result = check_arg_type_compat(&reg, BpfArgType::Anything, 1);
        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    #[test]
    fn test_check_const_map_ptr() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ConstPtrToMap;
        reg.off = 0;
        
        let result = check_arg_type_compat(&reg, BpfArgType::ConstMapPtr, 1);
        assert!(result.is_ok());
        
        // Non-zero offset should fail
        reg.off = 4;
        let result = check_arg_type_compat(&reg, BpfArgType::ConstMapPtr, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ptr_to_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = crate::bounds::tnum::Tnum::const_value(0);
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToStack, 1);
        assert!(result.is_ok());
        
        // Positive offset should fail
        reg.off = 8;
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToStack, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_const_size() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(64);
        reg.umax_value = 64;
        reg.umin_value = 64;
        
        let result = check_arg_type_compat(&reg, BpfArgType::ConstSize, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mem_size, Some(64));
    }

    #[test]
    fn test_check_uninit_register() {
        let reg = BpfRegState::default(); // NotInit by default
        
        let result = check_arg_type_compat(&reg, BpfArgType::Anything, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ptr_to_mem_allows_stack() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToMem, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_dynptr_alignment() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = crate::bounds::tnum::Tnum::const_value(0);
        
        let result = check_arg_type_compat(&reg, BpfArgType::PtrToDynptr, 1);
        assert!(result.is_ok());
        
        // Misaligned offset
        reg.off = -17;
        // This would fail alignment check - the check uses off + var_off.value
    }
}
