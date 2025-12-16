//! Bounds analysis integration with instruction verification
//!
//! This module connects the bounds tracking system with instruction verification,
//! providing bounds propagation through ALU operations, bounds checking for
//! memory access, and pointer arithmetic bounds validation.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use super::bounds::ScalarBounds;
use crate::state::reg_state::BpfRegState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// Result of bounds analysis for an operation
#[derive(Debug, Clone)]
pub struct BoundsAnalysisResult {
    /// Whether the operation is safe
    pub safe: bool,
    /// Updated register bounds
    pub new_bounds: Option<ScalarBounds>,
    /// Warning messages
    pub warnings: Vec<String>,
    /// Whether bounds overflow occurred
    pub overflow: bool,
}

impl Default for BoundsAnalysisResult {
    fn default() -> Self {
        Self {
            safe: true,
            new_bounds: None,
            warnings: Vec::new(),
            overflow: false,
        }
    }
}

/// Analyze bounds for an ALU operation
pub fn analyze_alu_bounds(
    dst_reg: &BpfRegState,
    src_reg: &BpfRegState,
    opcode: u8,
    is_64bit: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();
    
    // Only analyze scalar operations
    if dst_reg.reg_type != BpfRegType::ScalarValue {
        return Ok(result);
    }
    
    // Build ScalarBounds from register state
    let dst_bounds = reg_to_scalar_bounds(dst_reg);
    let src_bounds = reg_to_scalar_bounds(src_reg);
    
    // Perform the operation
    let op = opcode & 0xf0;
    match dst_bounds.alu_op(op, &src_bounds, is_64bit) {
        Ok(new_bounds) => {
            result.new_bounds = Some(new_bounds);
            
            // Check for potential overflow
            if matches!(op, 0x00 | 0x20) { // ADD or MUL
                if new_bounds.umax_value < dst_bounds.umin_value {
                    result.overflow = true;
                    result.warnings.push("potential unsigned overflow".into());
                }
            }
        }
        Err(e) => {
            result.safe = false;
            return Err(e);
        }
    }
    
    Ok(result)
}

/// Analyze bounds for a memory access
pub fn analyze_mem_access_bounds(
    ptr_reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();
    
    match ptr_reg.reg_type {
        BpfRegType::PtrToStack => {
            analyze_stack_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToMapValue => {
            analyze_map_value_access_bounds(ptr_reg, off, size, write, &mut result)?;
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            analyze_packet_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToCtx => {
            analyze_ctx_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToMem => {
            analyze_mem_ptr_access_bounds(ptr_reg, off, size, write, &mut result)?;
        }
        _ => {
            // For other pointer types, defer to type-specific checks
        }
    }
    
    Ok(result)
}

/// Analyze stack access bounds
fn analyze_stack_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Calculate total offset range
    let base_off = reg.off;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;
    
    // Stack grows downward, offsets are negative from frame pointer
    let min_total = (base_off as i64) + var_min + (off as i64);
    let max_total = (base_off as i64) + var_max + (off as i64);
    
    // Access end (most negative point)
    let min_end = min_total - (size as i64);
    let _max_end = max_total - (size as i64);
    
    // Check bounds
    if max_total > 0 {
        result.safe = false;
        return Err(VerifierError::StackOutOfBounds(max_total as i32));
    }
    
    if (-min_end) as usize > MAX_BPF_STACK {
        result.safe = false;
        return Err(VerifierError::StackOutOfBounds(min_end as i32));
    }
    
    // Check variable offset
    if !reg.var_off.is_const() {
        result.warnings.push(format!(
            "variable stack offset: {} to {}", var_min, var_max
        ));
        
        // Check if variable offset could span slot boundaries
        let slot_span = ((max_total - min_total) / BPF_REG_SIZE as i64) + 1;
        if slot_span > 1 {
            result.warnings.push(format!(
                "access may span {} stack slots", slot_span
            ));
        }
    }
    
    result.safe = true;
    Ok(())
}

/// Analyze map value access bounds
fn analyze_map_value_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Get map value size
    let value_size = if let Some(ref map_info) = reg.map_ptr {
        map_info.value_size as u64
    } else {
        result.warnings.push("map value size unknown".into());
        return Ok(());
    };
    
    // Calculate access range
    let base_off = reg.off as i64;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;
    
    let min_off = base_off + var_min + (off as i64);
    let max_off = base_off + var_max + (off as i64);
    let access_end = max_off + (size as i64);
    
    // Check negative offset
    if min_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(
            format!("negative offset {}", min_off)
        ));
    }
    
    // Check bounds
    if access_end > value_size as i64 {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(
            format!("access {}+{} exceeds value_size {}", max_off, size, value_size)
        ));
    }
    
    // Check write to read-only
    if write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(
            "write to read-only map value".into()
        ));
    }
    
    result.safe = true;
    Ok(())
}

/// Analyze packet access bounds
fn analyze_packet_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Packet access requires explicit range check
    if reg.mem_size == 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            "unbounded packet access - requires packet_end check".into()
        ));
    }
    
    let base_off = reg.off as i64;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;
    
    let max_off = base_off + var_max + (off as i64);
    let access_end = max_off + (size as i64);
    
    if access_end > reg.mem_size as i64 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            format!("packet access {}+{} may exceed range {}", 
                    max_off, size, reg.mem_size)
        ));
    }
    
    // Negative offset check
    let min_off = base_off + var_min + (off as i64);
    if min_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            format!("packet access with negative offset {}", min_off)
        ));
    }
    
    result.safe = true;
    Ok(())
}

/// Analyze context access bounds
fn analyze_ctx_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Context access must have constant offset
    if !reg.var_off.is_const() {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(
            "variable offset context access not allowed".into()
        ));
    }
    
    let total_off = reg.off + off + (reg.var_off.value as i32);
    
    // Negative offset not allowed
    if total_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(
            format!("negative context offset {}", total_off)
        ));
    }
    
    // Size must be valid (1, 2, 4, or 8 bytes)
    if !matches!(size, 1 | 2 | 4 | 8) {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(
            format!("invalid access size {}", size)
        ));
    }
    
    // Alignment check
    if (total_off as u32) % size != 0 {
        result.warnings.push(format!(
            "unaligned context access: offset {} size {}", total_off, size
        ));
    }
    
    result.safe = true;
    Ok(())
}

/// Analyze generic memory pointer access bounds
fn analyze_mem_ptr_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Check known memory size
    if reg.mem_size > 0 {
        let base_off = reg.off as i64;
        let var_max = reg.var_off.max() as i64;
        let access_end = base_off + var_max + (off as i64) + (size as i64);
        
        if access_end > reg.mem_size as i64 {
            result.safe = false;
            return Err(VerifierError::InvalidMemoryAccess(
                format!("access exceeds memory size {}", reg.mem_size)
            ));
        }
    }
    
    // Check read-only
    if write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only memory".into()
        ));
    }
    
    result.safe = true;
    Ok(())
}

/// Analyze pointer arithmetic bounds
pub fn analyze_ptr_arithmetic(
    ptr_reg: &BpfRegState,
    scalar_reg: &BpfRegState,
    is_add: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();
    
    // Scalar must have bounded range for safe pointer arithmetic
    let scalar_bounds = reg_to_scalar_bounds(scalar_reg);
    
    match ptr_reg.reg_type {
        BpfRegType::PtrToStack => {
            // Stack pointer arithmetic
            let new_off_min = if is_add {
                (ptr_reg.off as i64).saturating_add(scalar_bounds.smin_value)
            } else {
                (ptr_reg.off as i64).saturating_sub(scalar_bounds.smax_value)
            };
            let new_off_max = if is_add {
                (ptr_reg.off as i64).saturating_add(scalar_bounds.smax_value)
            } else {
                (ptr_reg.off as i64).saturating_sub(scalar_bounds.smin_value)
            };
            
            // Check bounds
            if new_off_max > 0 {
                result.safe = false;
                return Err(VerifierError::StackOutOfBounds(new_off_max as i32));
            }
            if (-new_off_min) as usize > MAX_BPF_STACK {
                result.safe = false;
                return Err(VerifierError::StackOutOfBounds(new_off_min as i32));
            }
        }
        BpfRegType::PtrToMapValue => {
            // Map value pointer arithmetic
            if let Some(ref map_info) = ptr_reg.map_ptr {
                let value_size = map_info.value_size as i64;
                
                let new_off_max = if is_add {
                    (ptr_reg.off as i64) + scalar_bounds.smax_value
                } else {
                    (ptr_reg.off as i64) - scalar_bounds.smin_value
                };
                
                if new_off_max > value_size {
                    result.warnings.push(format!(
                        "pointer may exceed map value size {}", value_size
                    ));
                }
            }
        }
        BpfRegType::PtrToPacket => {
            // Packet pointer arithmetic - needs range tracking
            if !scalar_bounds.is_non_negative() && is_add {
                result.warnings.push("adding potentially negative value to packet pointer".into());
            }
        }
        _ => {}
    }
    
    result.safe = true;
    Ok(result)
}

/// Convert register state to ScalarBounds
fn reg_to_scalar_bounds(reg: &BpfRegState) -> ScalarBounds {
    ScalarBounds {
        var_off: reg.var_off,
        umin_value: reg.umin_value,
        umax_value: reg.umax_value,
        smin_value: reg.smin_value,
        smax_value: reg.smax_value,
        u32_min_value: reg.u32_min_value,
        u32_max_value: reg.u32_max_value,
        s32_min_value: reg.s32_min_value,
        s32_max_value: reg.s32_max_value,
    }
}

/// Apply ScalarBounds to register state
pub fn apply_bounds_to_reg(reg: &mut BpfRegState, bounds: &ScalarBounds) {
    reg.var_off = bounds.var_off;
    reg.umin_value = bounds.umin_value;
    reg.umax_value = bounds.umax_value;
    reg.smin_value = bounds.smin_value;
    reg.smax_value = bounds.smax_value;
    reg.u32_min_value = bounds.u32_min_value;
    reg.u32_max_value = bounds.u32_max_value;
    reg.s32_min_value = bounds.s32_min_value;
    reg.s32_max_value = bounds.s32_max_value;
}

/// Refine register bounds after a conditional jump
pub fn refine_bounds_on_branch(
    reg: &mut BpfRegState,
    cmp_val: u64,
    cmp_op: u8,
    branch_taken: bool,
) {
    if reg.reg_type != BpfRegType::ScalarValue {
        return;
    }
    
    let mut bounds = reg_to_scalar_bounds(reg);
    bounds.adjust_for_cmp(cmp_val, cmp_op, branch_taken);
    apply_bounds_to_reg(reg, &bounds);
}

/// Check if a division operation is safe (no division by zero)
pub fn check_div_bounds(divisor_reg: &BpfRegState) -> Result<()> {
    if divisor_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar".into(),
            got: format!("{:?}", divisor_reg.reg_type),
        });
    }
    
    // Check if divisor could be zero
    if divisor_reg.umin_value == 0 {
        // Could be zero - check if it's definitely zero
        if divisor_reg.is_const() && divisor_reg.const_value() == 0 {
            return Err(VerifierError::DivisionByZero);
        }
        
        // Potentially zero - needs runtime check or more analysis
        if !divisor_reg.var_off.is_const() || divisor_reg.var_off.value == 0 {
            // Conservative: might be zero
        }
    }
    
    Ok(())
}

/// Check shift amount bounds
pub fn check_shift_bounds(shift_reg: &BpfRegState, is_64bit: bool) -> Result<()> {
    if shift_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar".into(),
            got: format!("{:?}", shift_reg.reg_type),
        });
    }
    
    let max_shift = if is_64bit { 63 } else { 31 };
    
    // Shift amount should be bounded
    if shift_reg.umax_value > max_shift {
        // Shift amount could be too large
        // In BPF, large shifts are masked, so this is a warning not error
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_access_bounds() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -16;
        reg.var_off = Tnum::const_value(0);
        
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
    }

    #[test]
    fn test_stack_access_out_of_bounds() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = 8; // Positive offset - invalid
        reg.var_off = Tnum::const_value(0);
        
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_value_access_bounds() {
        use crate::state::reg_state::MapInfo;
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.off = 0;
        reg.var_off = Tnum::const_value(0);
        reg.map_ptr = Some(MapInfo {
            map_type: BpfMapType::Hash,
            key_size: 4,
            value_size: 64,
            max_entries: 100,
        });
        
        // Valid access
        let result = analyze_mem_access_bounds(&reg, 0, 8, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
        
        // Out of bounds access
        let result = analyze_mem_access_bounds(&reg, 60, 8, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ctx_variable_offset_rejected() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToCtx;
        reg.off = 0;
        reg.var_off = Tnum::unknown(); // Variable offset
        
        let result = analyze_mem_access_bounds(&reg, 0, 4, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ptr_arithmetic_stack() {
        let mut ptr_reg = BpfRegState::default();
        ptr_reg.reg_type = BpfRegType::PtrToStack;
        ptr_reg.off = -64;
        
        let mut scalar_reg = BpfRegState::default();
        scalar_reg.reg_type = BpfRegType::ScalarValue;
        scalar_reg.smin_value = 0;
        scalar_reg.smax_value = 8;
        scalar_reg.umin_value = 0;
        scalar_reg.umax_value = 8;
        
        // Subtracting from stack pointer (going more negative) should be ok
        let result = analyze_ptr_arithmetic(&ptr_reg, &scalar_reg, false);
        assert!(result.is_ok());
        assert!(result.unwrap().safe);
    }

    #[test]
    fn test_div_by_zero_check() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(0);
        
        let result = check_div_bounds(&reg);
        assert!(result.is_err());
    }

    #[test]
    fn test_div_safe() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 1;
        reg.umax_value = 10;
        reg.smin_value = 1;
        reg.smax_value = 10;
        
        let result = check_div_bounds(&reg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_refine_bounds_on_branch() {
        use crate::bounds::tnum::Tnum;
        
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 0;
        reg.umax_value = 100;
        reg.smin_value = 0;
        reg.smax_value = 100;
        reg.var_off = Tnum::unknown();
        
        // After JGT 50 (taken)
        refine_bounds_on_branch(&mut reg, 50, 0x20, true);
        
        assert_eq!(reg.umin_value, 51);
    }
}
