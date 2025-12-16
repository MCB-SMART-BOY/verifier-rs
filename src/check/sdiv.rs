//!

//! This module implements safety checks for signed division operations in BPF.

//! Signed division has special cases that need careful handling to prevent

//! undefined behavior.



use alloc::vec::Vec;

use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::bounds::bounds::ScalarBounds;
use crate::core::error::{Result, VerifierError};

/// Signed division safety result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdivSafety {
    /// Division is provably safe
    Safe,
    /// Division might overflow (INT_MIN / -1)
    MightOverflow,
    /// Division might divide by zero
    MightDivByZero,
    /// Both overflow and div-by-zero possible
    Unsafe,
}

/// Check signed division safety for 64-bit
pub fn check_sdiv64_safety(
    dividend: &BpfRegState,
    divisor: &BpfRegState,
) -> SdivSafety {
    let mut result = SdivSafety::Safe;

    // Check for division by zero
    if divisor_might_be_zero(divisor) {
        result = SdivSafety::MightDivByZero;
    }

    // Check for overflow: INT64_MIN / -1
    if might_overflow_sdiv64(dividend, divisor) {
        result = match result {
            SdivSafety::MightDivByZero => SdivSafety::Unsafe,
            _ => SdivSafety::MightOverflow,
        };
    }

    result
}

/// Check signed division safety for 32-bit
pub fn check_sdiv32_safety(
    dividend: &BpfRegState,
    divisor: &BpfRegState,
) -> SdivSafety {
    let mut result = SdivSafety::Safe;

    // Check for division by zero
    if divisor_might_be_zero_32(divisor) {
        result = SdivSafety::MightDivByZero;
    }

    // Check for overflow: INT32_MIN / -1
    if might_overflow_sdiv32(dividend, divisor) {
        result = match result {
            SdivSafety::MightDivByZero => SdivSafety::Unsafe,
            _ => SdivSafety::MightOverflow,
        };
    }

    result
}

/// Check if divisor might be zero
fn divisor_might_be_zero(divisor: &BpfRegState) -> bool {
    if divisor.reg_type != BpfRegType::ScalarValue {
        return true; // Non-scalar, unknown
    }

    // Check if 0 is in the possible range
    if divisor.is_const() {
        return divisor.const_value() == 0;
    }

    // Check unsigned range
    if divisor.umin_value > 0 {
        return false; // Definitely not zero
    }

    // Check signed range
    if divisor.smin_value > 0 || divisor.smax_value < 0 {
        return false; // Definitely not zero
    }

    true // Might be zero
}

/// Check if 32-bit divisor might be zero
fn divisor_might_be_zero_32(divisor: &BpfRegState) -> bool {
    if divisor.reg_type != BpfRegType::ScalarValue {
        return true;
    }

    if divisor.u32_min_value > 0 {
        return false;
    }

    if divisor.s32_min_value > 0 || divisor.s32_max_value < 0 {
        return false;
    }

    true
}

/// Check if 64-bit signed division might overflow (INT64_MIN / -1)
fn might_overflow_sdiv64(dividend: &BpfRegState, divisor: &BpfRegState) -> bool {
    if dividend.reg_type != BpfRegType::ScalarValue ||
       divisor.reg_type != BpfRegType::ScalarValue {
        return true;
    }

    // Overflow happens when dividend == INT64_MIN and divisor == -1
    // Check if dividend range includes INT64_MIN (smin_value == i64::MIN means it could be MIN)
    let dividend_might_be_min = dividend.smin_value == i64::MIN;
    // Check if divisor range includes -1
    let divisor_might_be_neg1 = divisor.smin_value <= -1 && divisor.smax_value >= -1;

    // If dividend is known not to be INT64_MIN, safe
    if dividend.is_const() && dividend.smin_value != i64::MIN {
        return false;
    }

    // If divisor is known not to be -1, safe
    if divisor.is_const() && divisor.smin_value != -1 {
        return false;
    }

    // If dividend can't be INT64_MIN (min is greater than MIN)
    if dividend.smin_value > i64::MIN {
        return false;
    }

    // If divisor can't be -1
    if divisor.smin_value > -1 || divisor.smax_value < -1 {
        return false;
    }

    // Both conditions might occur
    dividend_might_be_min && divisor_might_be_neg1
}

/// Check if 32-bit signed division might overflow (INT32_MIN / -1)
fn might_overflow_sdiv32(dividend: &BpfRegState, divisor: &BpfRegState) -> bool {
    if dividend.reg_type != BpfRegType::ScalarValue ||
       divisor.reg_type != BpfRegType::ScalarValue {
        return true;
    }

    // If dividend can't be INT32_MIN (min is greater than MIN)
    if dividend.s32_min_value > i32::MIN {
        return false;
    }

    // If divisor can't be -1
    if divisor.s32_min_value > -1 || divisor.s32_max_value < -1 {
        return false;
    }

    true
}

/// Compute safe bounds after signed division
pub fn compute_sdiv_bounds(
    dividend: &ScalarBounds,
    divisor: &ScalarBounds,
    is_64: bool,
) -> Result<ScalarBounds> {
    // Check for division by zero first
    if is_64 {
        if divisor.umin_value == 0 && divisor.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }
    } else if divisor.u32_min_value == 0 && divisor.u32_max_value == 0 {
        return Err(VerifierError::DivisionByZero);
    }

    let mut result = ScalarBounds::unknown();

    if is_64 {
        // For signed division, result depends on signs of both operands
        if divisor.is_const() && divisor.const_value().unwrap_or(0) != 0 {
            let d = divisor.smin_value;
            
            if dividend.is_const() {
                // Both constant - compute directly
                let n = dividend.smin_value;
                if d == -1 && n == i64::MIN {
                    // Overflow case - result wraps to INT64_MIN
                    return Ok(ScalarBounds::known(i64::MIN as u64));
                }
                return Ok(ScalarBounds::known((n / d) as u64));
            }

            // Divisor is constant, dividend is range
            if d > 0 {
                // Positive divisor
                result.smin_value = dividend.smin_value / d;
                result.smax_value = dividend.smax_value / d;
            } else if d < 0 {
                // Negative divisor - reverses inequalities
                result.smin_value = dividend.smax_value / d;
                result.smax_value = dividend.smin_value / d;
            }
        } else {
            // Divisor is range - harder to bound precisely
            // Conservative: result is unknown
        }
    } else {
        // 32-bit version
        if divisor.u32_min_value == divisor.u32_max_value && divisor.u32_min_value != 0 {
            let d = divisor.s32_min_value;
            
            if dividend.u32_min_value == dividend.u32_max_value {
                let n = dividend.s32_min_value;
                if d == -1 && n == i32::MIN {
                    return Ok(ScalarBounds::known(i32::MIN as i64 as u64));
                }
                return Ok(ScalarBounds::known((n / d) as i64 as u64));
            }
        }
    }

    result.deduce_bounds();
    Ok(result)
}

/// Compute safe bounds after signed modulo
pub fn compute_smod_bounds(
    dividend: &ScalarBounds,
    divisor: &ScalarBounds,
    is_64: bool,
) -> Result<ScalarBounds> {
    // Check for mod by zero
    if is_64 {
        if divisor.umin_value == 0 && divisor.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }
    } else if divisor.u32_min_value == 0 && divisor.u32_max_value == 0 {
        return Err(VerifierError::DivisionByZero);
    }

    let mut result = ScalarBounds::unknown();

    // Signed modulo result has same sign as dividend
    // and |result| < |divisor|
    
    if is_64 {
        if divisor.is_const() && divisor.const_value().unwrap_or(0) != 0 {
            let d_abs = divisor.smin_value.abs();
            
            // Result is in range (-(|d|-1), |d|-1)
            result.smin_value = -(d_abs - 1);
            result.smax_value = d_abs - 1;

            // If dividend is non-negative, result is non-negative
            if dividend.smin_value >= 0 {
                result.smin_value = 0;
            }
            
            // If dividend is non-positive, result is non-positive
            if dividend.smax_value <= 0 {
                result.smax_value = 0;
            }
        }
    } else if divisor.s32_min_value == divisor.s32_max_value && divisor.s32_min_value != 0 {
        let d_abs = divisor.s32_min_value.abs();
        
        result.s32_min_value = -(d_abs - 1);
        result.s32_max_value = d_abs - 1;

        if dividend.s32_min_value >= 0 {
            result.s32_min_value = 0;
        }
        
        if dividend.s32_max_value <= 0 {
            result.s32_max_value = 0;
        }
    }

    result.deduce_bounds();
    Ok(result)
}

/// Check and fix signed division instruction
pub fn check_sdiv_insn(
    dst: &BpfRegState,
    src: &BpfRegState,
    is_64: bool,
) -> Result<SdivSafety> {
    let safety = if is_64 {
        check_sdiv64_safety(dst, src)
    } else {
        check_sdiv32_safety(dst, src)
    };

    match safety {
        SdivSafety::Safe => Ok(safety),
        SdivSafety::MightDivByZero => {
            // Verifier should ensure divisor != 0
            Err(VerifierError::DivisionByZero)
        }
        SdivSafety::MightOverflow => {
            // Overflow is defined behavior in BPF (wraps)
            // but we should warn
            Ok(safety)
        }
        SdivSafety::Unsafe => {
            Err(VerifierError::DivisionByZero)
        }
    }
}

/// Patch division to handle edge cases
#[derive(Debug, Clone)]
pub struct DivPatch {
    /// Insert zero check before division
    pub needs_zero_check: bool,
    /// Insert overflow check (INT_MIN / -1)
    pub needs_overflow_check: bool,
    /// Instruction index
    pub insn_idx: usize,
}

/// Analyze division instructions and return needed patches
pub fn analyze_divisions(insns: &[BpfInsn]) -> Vec<DivPatch> {
    let mut patches = Vec::new();

    for (idx, insn) in insns.iter().enumerate() {
        let class = insn.class();
        
        if class != BPF_ALU && class != BPF_ALU64 {
            continue;
        }

        let op = insn.code & 0xf0;
        
        // Check for DIV or MOD
        if op != BPF_DIV && op != BPF_MOD {
            continue;
        }

        // Check if signed (SDIV/SMOD opcodes would be different)
        // For now, assume all divisions need checks
        patches.push(DivPatch {
            needs_zero_check: true,
            needs_overflow_check: op == BPF_DIV, // Only DIV can overflow, MOD is safe
            insn_idx: idx,
        });
    }

    patches
}
