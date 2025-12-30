// SPDX-License-Identifier: GPL-2.0

//! 返回值验证模块
//!
//! Return value verification module.
//!
//! 本模块实现了 BPF 程序返回值的验证。不同的程序类型对返回值有不同的要求。
//!
//! This module implements verification of BPF program return values.
//! Different program types have different requirements for their return values.
//!
//! # 返回值要求示例 / Return Value Requirements Examples
//!
//! - **XDP 程序 / XDP Programs**: 返回 XDP_PASS, XDP_DROP, XDP_TX 等
//! - **Socket Filter**: 返回要保留的字节数
//! - **Tracing 程序 / Tracing Programs**: 通常返回 0 表示成功

use alloc::format;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::verifier_state::BpfVerifierState;

/// Return value range
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfRetvalRange {
    /// Minimum allowed return value
    pub minval: i64,
    /// Maximum allowed return value
    pub maxval: i64,
}

impl BpfRetvalRange {
    /// Create a new return value range
    pub fn new(minval: i64, maxval: i64) -> Self {
        Self { minval, maxval }
    }

    /// Unbounded range
    pub fn unbounded() -> Self {
        Self {
            minval: i64::MIN,
            maxval: i64::MAX,
        }
    }

    /// Check if value is within range
    pub fn contains(&self, val: i64) -> bool {
        val >= self.minval && val <= self.maxval
    }

    /// Check if this range is within another
    pub fn within(&self, other: &Self) -> bool {
        self.minval >= other.minval && self.maxval <= other.maxval
    }
}

/// Get the expected return value range for a program type
pub fn get_prog_retval_range(prog_type: BpfProgType) -> BpfRetvalRange {
    match prog_type {
        // XDP programs return XDP actions
        BpfProgType::Xdp => BpfRetvalRange::new(0, 5), // XDP_PASS, XDP_DROP, etc.

        // Socket filters return packet length or 0
        BpfProgType::SocketFilter => BpfRetvalRange::new(0, i64::MAX),

        // TC classifiers return TC actions
        BpfProgType::SchedCls | BpfProgType::SchedAct => BpfRetvalRange::new(-1, 7),

        // Tracing programs usually return 0
        BpfProgType::Tracepoint | BpfProgType::RawTracepoint | BpfProgType::PerfEvent => {
            BpfRetvalRange::new(0, 0)
        }

        // Kprobes can return 0 or 1
        BpfProgType::Kprobe => BpfRetvalRange::new(0, 1),

        // cGroup programs have specific ranges
        BpfProgType::CgroupSkb | BpfProgType::CgroupSock | BpfProgType::CgroupDevice => {
            BpfRetvalRange::new(0, 1)
        }

        // LSM programs return 0 for allow, negative for deny
        BpfProgType::Lsm => BpfRetvalRange::new(i32::MIN as i64, 0),

        // Struct ops - depends on the callback
        BpfProgType::StructOps => BpfRetvalRange::unbounded(),

        // Default: any return value
        _ => BpfRetvalRange::unbounded(),
    }
}

/// Check return code for a program exit
pub fn check_return_code(
    state: &BpfVerifierState,
    prog_type: BpfProgType,
    is_subprog: bool,
    is_exception_exit: bool,
) -> Result<()> {
    // Get R0 (return value register)
    let r0 = state
        .reg(BPF_REG_0)
        .ok_or(VerifierError::InvalidRegister(0))?;

    // Subprograms can return any value
    if is_subprog {
        // Just check R0 is initialized
        if r0.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(0));
        }
        return Ok(());
    }

    // Exception exits don't check return value
    if is_exception_exit {
        return Ok(());
    }

    // Get expected range
    let expected = get_prog_retval_range(prog_type);

    // Check return value type
    match r0.reg_type {
        BpfRegType::NotInit => {
            return Err(VerifierError::UninitializedRegister(0));
        }
        BpfRegType::ScalarValue => {
            // Check if known value is within range
            if r0.is_const() {
                let val = r0.const_value() as i64;
                if !expected.contains(val) {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!(
                            "return value in range [{}, {}]",
                            expected.minval, expected.maxval
                        ),
                        got: format!("{}", val),
                    });
                }
            } else {
                // Check if bounds are within expected range
                let ret_range = BpfRetvalRange::new(r0.smin_value, r0.smax_value);
                if !ret_range.within(&expected) {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!(
                            "return value in range [{}, {}]",
                            expected.minval, expected.maxval
                        ),
                        got: format!("range [{}, {}]", r0.smin_value, r0.smax_value),
                    });
                }
            }
        }
        _ => {
            // Pointer return values are generally not allowed for main program
            // Exception: some program types allow specific pointer returns
            if !allows_ptr_return(prog_type) {
                return Err(VerifierError::TypeMismatch {
                    expected: "scalar return value".into(),
                    got: format!("{:?}", r0.reg_type),
                });
            }
        }
    }

    Ok(())
}

/// Check if a program type allows pointer return values
fn allows_ptr_return(prog_type: BpfProgType) -> bool {
    match prog_type {
        // Struct ops callbacks may return pointers
        BpfProgType::StructOps => true,
        // Most programs should return scalars
        _ => false,
    }
}

/// Refine return value based on conditional check
pub fn do_refine_retval_range(
    state: &mut BpfVerifierState,
    _insn_idx: usize,
    expected: &BpfRetvalRange,
) -> Result<()> {
    // Get R0
    let r0 = state
        .reg_mut(BPF_REG_0)
        .ok_or(VerifierError::InvalidRegister(0))?;

    if r0.reg_type != BpfRegType::ScalarValue {
        return Ok(());
    }

    // Intersect with expected range
    if r0.smin_value < expected.minval {
        r0.smin_value = expected.minval;
    }
    if r0.smax_value > expected.maxval {
        r0.smax_value = expected.maxval;
    }
    if r0.umax_value > expected.maxval as u64 {
        r0.umax_value = expected.maxval as u64;
    }

    r0.sync_bounds();

    Ok(())
}

/// Check callback return value
pub fn check_callback_return(state: &BpfVerifierState, expected: &BpfRetvalRange) -> Result<()> {
    let r0 = state
        .reg(BPF_REG_0)
        .ok_or(VerifierError::InvalidRegister(0))?;

    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(0));
    }

    if r0.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar callback return".into(),
            got: format!("{:?}", r0.reg_type),
        });
    }

    // Check bounds
    let ret_range = BpfRetvalRange::new(r0.smin_value, r0.smax_value);
    if !ret_range.within(expected) {
        return Err(VerifierError::TypeMismatch {
            expected: format!(
                "callback return in [{}, {}]",
                expected.minval, expected.maxval
            ),
            got: format!("range [{}, {}]", r0.smin_value, r0.smax_value),
        });
    }

    Ok(())
}

/// Get function return value range based on helper/kfunc prototype
pub fn get_func_retval_range(func_id: u32) -> Option<BpfRetvalRange> {
    // Some helpers have known return ranges
    match func_id {
        1 => Some(BpfRetvalRange::new(0, i64::MAX)), // map_lookup - pointer or NULL
        _ => None,
    }
}
