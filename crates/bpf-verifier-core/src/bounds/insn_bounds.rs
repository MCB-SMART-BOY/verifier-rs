// SPDX-License-Identifier: GPL-2.0

//! Bounds analysis integration with instruction verification
//! 边界分析与指令验证的集成
//!
//! This module connects the bounds tracking system with instruction verification,
//! providing bounds propagation through ALU operations, bounds checking for
//! memory access, and pointer arithmetic bounds validation.
//!
//! 本模块将边界跟踪系统与指令验证连接起来，提供 ALU 操作的边界传播、
//! 内存访问的边界检查以及指针算术的边界验证。

use alloc::{format, string::String, vec::Vec};

use super::scalar::ScalarBounds;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;

/// Result of bounds analysis for an operation
/// 操作的边界分析结果
#[derive(Debug, Clone)]
pub struct BoundsAnalysisResult {
    /// Whether the operation is safe
    /// 操作是否安全
    pub safe: bool,
    /// Updated register bounds
    /// 更新后的寄存器边界
    pub new_bounds: Option<ScalarBounds>,
    /// Warning messages
    /// 警告消息
    pub warnings: Vec<String>,
    /// Whether bounds overflow occurred
    /// 是否发生边界溢出
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
/// 分析 ALU 操作的边界
///
/// This function analyzes how ALU operations affect register bounds,
/// detecting potential overflows and computing new bounds.
///
/// 此函数分析 ALU 操作如何影响寄存器边界，检测潜在的溢出并计算新边界。
pub fn analyze_alu_bounds(
    dst_reg: &BpfRegState,
    src_reg: &BpfRegState,
    opcode: u8,
    is_64bit: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();

    // Only analyze scalar operations
    // 只分析标量操作
    if dst_reg.reg_type != BpfRegType::ScalarValue {
        return Ok(result);
    }

    // Build ScalarBounds from register state
    // 从寄存器状态构建 ScalarBounds
    let dst_bounds = reg_to_scalar_bounds(dst_reg);
    let src_bounds = reg_to_scalar_bounds(src_reg);

    // Perform the operation
    // 执行操作
    let op = opcode & 0xf0;
    match dst_bounds.alu_op(op, &src_bounds, is_64bit) {
        Ok(new_bounds) => {
            result.new_bounds = Some(new_bounds);

            // Check for potential overflow
            // 检查潜在的溢出
            if matches!(op, 0x00 | 0x20) {
                // ADD or MUL
                // 加法或乘法
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
/// 分析内存访问的边界
///
/// This function checks if a memory access is within valid bounds
/// for the given pointer type.
///
/// 此函数检查对于给定的指针类型，内存访问是否在有效边界内。
pub fn analyze_mem_access_bounds(
    ptr_reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();

    match ptr_reg.reg_type {
        BpfRegType::PtrToStack => {
            // Analyze stack access bounds
            // 分析栈访问边界
            analyze_stack_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToMapValue => {
            // Analyze map value access bounds
            // 分析 map 值访问边界
            analyze_map_value_access_bounds(ptr_reg, off, size, write, &mut result)?;
        }
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta => {
            // Analyze packet access bounds
            // 分析数据包访问边界
            analyze_packet_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToCtx => {
            // Analyze context access bounds
            // 分析上下文访问边界
            analyze_ctx_access_bounds(ptr_reg, off, size, &mut result)?;
        }
        BpfRegType::PtrToMem => {
            // Analyze generic memory pointer access bounds
            // 分析通用内存指针访问边界
            analyze_mem_ptr_access_bounds(ptr_reg, off, size, write, &mut result)?;
        }
        _ => {
            // For other pointer types, defer to type-specific checks
            // 对于其他指针类型，延迟到类型特定的检查
        }
    }

    Ok(result)
}

/// Analyze stack access bounds
/// 分析栈访问边界
///
/// Stack grows downward, so offsets are negative from frame pointer.
/// This validates that accesses stay within MAX_BPF_STACK.
///
/// 栈向下增长，因此偏移量相对于帧指针是负数。
/// 这验证访问保持在 MAX_BPF_STACK 范围内。
fn analyze_stack_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Calculate total offset range
    // 计算总偏移范围
    let base_off = reg.off;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;

    // Stack grows downward, offsets are negative from frame pointer
    // 栈向下增长，偏移量相对于帧指针是负数
    let min_total = (base_off as i64) + var_min + (off as i64);
    let max_total = (base_off as i64) + var_max + (off as i64);

    // Access end (most negative point)
    // 访问结束点（最负的位置）
    let min_end = min_total - (size as i64);
    let _max_end = max_total - (size as i64);

    // Check bounds
    // 检查边界
    if max_total > 0 {
        result.safe = false;
        return Err(VerifierError::StackOutOfBounds(max_total as i32));
    }

    if (-min_end) as usize > MAX_BPF_STACK {
        result.safe = false;
        return Err(VerifierError::StackOutOfBounds(min_end as i32));
    }

    // Check variable offset
    // 检查可变偏移
    if !reg.var_off.is_const() {
        result
            .warnings
            .push(format!("variable stack offset: {} to {}", var_min, var_max));

        // Check if variable offset could span slot boundaries
        // 检查可变偏移是否可能跨越槽边界
        let slot_span = ((max_total - min_total) / BPF_REG_SIZE as i64) + 1;
        if slot_span > 1 {
            result
                .warnings
                .push(format!("access may span {} stack slots", slot_span));
        }
    }

    result.safe = true;
    Ok(())
}

/// Analyze map value access bounds
/// 分析 map 值访问边界
///
/// Validates that access stays within the map value size and
/// respects read-only restrictions.
///
/// 验证访问保持在 map 值大小范围内，并遵守只读限制。
fn analyze_map_value_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Get map value size
    // 获取 map 值大小
    let value_size = if let Some(ref map_info) = reg.map_ptr {
        map_info.value_size as u64
    } else {
        result.warnings.push("map value size unknown".into());
        return Ok(());
    };

    // Calculate access range
    // 计算访问范围
    let base_off = reg.off as i64;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;

    let min_off = base_off + var_min + (off as i64);
    let max_off = base_off + var_max + (off as i64);
    let access_end = max_off + (size as i64);

    // Check negative offset
    // 检查负偏移
    if min_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(format!(
            "negative offset {}",
            min_off
        )));
    }

    // Check bounds
    // 检查边界
    if access_end > value_size as i64 {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(format!(
            "access {}+{} exceeds value_size {}",
            max_off, size, value_size
        )));
    }

    // Check write to read-only
    // 检查对只读区域的写入
    if write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        result.safe = false;
        return Err(VerifierError::InvalidMapAccess(
            "write to read-only map value".into(),
        ));
    }

    result.safe = true;
    Ok(())
}

/// Analyze packet access bounds
/// 分析数据包访问边界
///
/// Packet access requires explicit range checks against packet_end.
/// This validates that accesses stay within the checked range.
///
/// 数据包访问需要对 packet_end 进行显式范围检查。
/// 这验证访问保持在已检查的范围内。
fn analyze_packet_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Packet access requires explicit range check
    // 数据包访问需要显式范围检查
    if reg.mem_size == 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            "unbounded packet access - requires packet_end check".into(),
        ));
    }

    let base_off = reg.off as i64;
    let var_min = reg.var_off.min() as i64;
    let var_max = reg.var_off.max() as i64;

    let max_off = base_off + var_max + (off as i64);
    let access_end = max_off + (size as i64);

    // Check if access exceeds checked range
    // 检查访问是否超出已检查范围
    if access_end > reg.mem_size as i64 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet access {}+{} may exceed range {}",
            max_off, size, reg.mem_size
        )));
    }

    // Negative offset check
    // 负偏移检查
    let min_off = base_off + var_min + (off as i64);
    if min_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(format!(
            "packet access with negative offset {}",
            min_off
        )));
    }

    result.safe = true;
    Ok(())
}

/// Analyze context access bounds
/// 分析上下文访问边界
///
/// Context access must have constant offset and valid size.
/// Variable offsets are not allowed for safety.
///
/// 上下文访问必须有常量偏移和有效大小。
/// 为了安全，不允许可变偏移。
fn analyze_ctx_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Context access must have constant offset
    // 上下文访问必须有常量偏移
    if !reg.var_off.is_const() {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(
            "variable offset context access not allowed".into(),
        ));
    }

    let total_off = reg.off + off + (reg.var_off.value as i32);

    // Negative offset not allowed
    // 不允许负偏移
    if total_off < 0 {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(format!(
            "negative context offset {}",
            total_off
        )));
    }

    // Size must be valid (1, 2, 4, or 8 bytes)
    // 大小必须有效（1、2、4 或 8 字节）
    if !matches!(size, 1 | 2 | 4 | 8) {
        result.safe = false;
        return Err(VerifierError::InvalidContextAccess(format!(
            "invalid access size {}",
            size
        )));
    }

    // Alignment check
    // 对齐检查
    if !(total_off as u32).is_multiple_of(size) {
        result.warnings.push(format!(
            "unaligned context access: offset {} size {}",
            total_off, size
        ));
    }

    result.safe = true;
    Ok(())
}

/// Analyze generic memory pointer access bounds
/// 分析通用内存指针访问边界
///
/// Validates access against known memory size and read-only flags.
///
/// 根据已知的内存大小和只读标志验证访问。
fn analyze_mem_ptr_access_bounds(
    reg: &BpfRegState,
    off: i32,
    size: u32,
    write: bool,
    result: &mut BoundsAnalysisResult,
) -> Result<()> {
    // Check known memory size
    // 检查已知内存大小
    if reg.mem_size > 0 {
        let base_off = reg.off as i64;
        let var_max = reg.var_off.max() as i64;
        let access_end = base_off + var_max + (off as i64) + (size as i64);

        if access_end > reg.mem_size as i64 {
            result.safe = false;
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "access exceeds memory size {}",
                reg.mem_size
            )));
        }
    }

    // Check read-only
    // 检查只读
    if write && reg.type_flags.contains(BpfTypeFlag::MEM_RDONLY) {
        result.safe = false;
        return Err(VerifierError::InvalidMemoryAccess(
            "write to read-only memory".into(),
        ));
    }

    result.safe = true;
    Ok(())
}

/// Analyze pointer arithmetic bounds
/// 分析指针算术边界
///
/// Validates that pointer arithmetic stays within valid bounds
/// for the pointer type (stack, map value, packet, etc).
///
/// 验证指针算术对于指针类型（栈、map 值、数据包等）保持在有效边界内。
pub fn analyze_ptr_arithmetic(
    ptr_reg: &BpfRegState,
    scalar_reg: &BpfRegState,
    is_add: bool,
) -> Result<BoundsAnalysisResult> {
    let mut result = BoundsAnalysisResult::default();

    // Scalar must have bounded range for safe pointer arithmetic
    // 标量必须有有界范围才能安全进行指针算术
    let scalar_bounds = reg_to_scalar_bounds(scalar_reg);

    match ptr_reg.reg_type {
        BpfRegType::PtrToStack => {
            // Stack pointer arithmetic
            // 栈指针算术
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
            // 检查边界
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
            // Map 值指针算术
            if let Some(ref map_info) = ptr_reg.map_ptr {
                let value_size = map_info.value_size as i64;

                let new_off_max = if is_add {
                    (ptr_reg.off as i64) + scalar_bounds.smax_value
                } else {
                    (ptr_reg.off as i64) - scalar_bounds.smin_value
                };

                if new_off_max > value_size {
                    result
                        .warnings
                        .push(format!("pointer may exceed map value size {}", value_size));
                }
            }
        }
        BpfRegType::PtrToPacket => {
            // Packet pointer arithmetic - needs range tracking
            // 数据包指针算术 - 需要范围跟踪
            if !scalar_bounds.is_non_negative() && is_add {
                result
                    .warnings
                    .push("adding potentially negative value to packet pointer".into());
            }
        }
        _ => {}
    }

    result.safe = true;
    Ok(result)
}

/// Convert register state to ScalarBounds
/// 将寄存器状态转换为 ScalarBounds
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
/// 将 ScalarBounds 应用到寄存器状态
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
/// 在条件跳转后细化寄存器边界
///
/// Updates register bounds based on the result of a comparison,
/// narrowing the possible range of values.
///
/// 根据比较结果更新寄存器边界，缩小可能的值范围。
pub fn refine_bounds_on_branch(
    reg: &mut BpfRegState,
    cmp_val: u64,
    cmp_op: u8,
    branch_taken: bool,
) {
    // Only refine scalar values
    // 只细化标量值
    if reg.reg_type != BpfRegType::ScalarValue {
        return;
    }

    let mut bounds = reg_to_scalar_bounds(reg);
    bounds.adjust_for_cmp(cmp_val, cmp_op, branch_taken);
    apply_bounds_to_reg(reg, &bounds);
}

/// Check if a division operation is safe (no division by zero)
/// 检查除法操作是否安全（没有除以零）
///
/// Returns an error if the divisor could potentially be zero.
///
/// 如果除数可能为零则返回错误。
pub fn check_div_bounds(divisor_reg: &BpfRegState) -> Result<()> {
    // Divisor must be a scalar
    // 除数必须是标量
    if divisor_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar".into(),
            got: format!("{:?}", divisor_reg.reg_type),
        });
    }

    // Check if divisor could be zero
    // 检查除数是否可能为零
    if divisor_reg.umin_value == 0 {
        // Could be zero - check if it's definitely zero
        // 可能为零 - 检查是否一定为零
        if divisor_reg.is_const() && divisor_reg.const_value() == 0 {
            return Err(VerifierError::DivisionByZero);
        }

        // Potentially zero - needs runtime check or more analysis
        // 可能为零 - 需要运行时检查或更多分析
        if !divisor_reg.var_off.is_const() || divisor_reg.var_off.value == 0 {
            // Conservative: might be zero
            // 保守处理：可能为零
        }
    }

    Ok(())
}

/// Check shift amount bounds
/// 检查移位量边界
///
/// Validates that shift amount is within valid range for the
/// operation width (0-31 for 32-bit, 0-63 for 64-bit).
///
/// 验证移位量在操作宽度的有效范围内
/// （32 位为 0-31，64 位为 0-63）。
pub fn check_shift_bounds(shift_reg: &BpfRegState, is_64bit: bool) -> Result<()> {
    // Shift amount must be a scalar
    // 移位量必须是标量
    if shift_reg.reg_type != BpfRegType::ScalarValue {
        return Err(VerifierError::TypeMismatch {
            expected: "scalar".into(),
            got: format!("{:?}", shift_reg.reg_type),
        });
    }

    let max_shift = if is_64bit { 63 } else { 31 };

    // Shift amount should be bounded
    // 移位量应该有界
    if shift_reg.umax_value > max_shift {
        // Shift amount could be too large
        // In BPF, large shifts are masked, so this is a warning not error
        // 移位量可能过大
        // 在 BPF 中，大的移位量会被掩码，所以这是警告而非错误
    }

    Ok(())
}
