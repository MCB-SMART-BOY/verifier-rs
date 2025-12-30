// SPDX-License-Identifier: GPL-2.0

//! Register spill and fill tracking for stack operations.
//! 栈操作的寄存器溢出和填充跟踪
//!
//! This module implements precise tracking of register values when they are
//! spilled to the stack and restored (filled) back to registers. This is
//! critical for maintaining precision through function calls and around
//! complex control flow.
//! 本模块实现寄存器值溢出到栈以及恢复（填充）回寄存器的精确跟踪。
//! 这对于在函数调用和复杂控制流中保持精度至关重要。

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::{get_spi, BpfStackState};
use crate::state::verifier_state::BpfVerifierState;

/// Result of a stack read operation.
/// 栈读取操作的结果
#[derive(Debug, Clone)]
pub enum StackReadResult {
    /// Successfully read a spilled register with full precision.
    /// 成功读取具有完整精度的溢出寄存器
    SpilledReg(BpfRegState),
    /// Read initialized but imprecise data (scalar unknown).
    /// 读取已初始化但不精确的数据（未知标量）
    Initialized,
    /// Read zeroed data.
    /// 读取零数据
    Zero,
    /// Read uninitialized data (error).
    /// 读取未初始化的数据（错误）
    Uninitialized,
    /// Read a dynptr slot.
    /// 读取 dynptr 槽
    Dynptr(BpfRegState),
    /// Read an iterator slot.
    /// 读取迭代器槽
    Iterator(BpfRegState),
}

/// Spill/fill tracking context.
/// 溢出/填充跟踪上下文
pub struct SpillFillTracker;

impl SpillFillTracker {
    /// Spill a register to the stack.
    /// 将寄存器溢出到栈
    ///
    /// This preserves the full register state including bounds and tnum
    /// so it can be precisely restored later.
    /// 这保留完整的寄存器状态，包括边界和 tnum，
    /// 以便稍后可以精确恢复。
    pub fn spill_reg(
        state: &mut BpfVerifierState,
        stack_off: i32,
        reg: &BpfRegState,
        size: usize,
    ) -> Result<()> {
        // Stack offset must be negative and aligned
        // 栈偏移必须为负且对齐
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        // Grow stack if needed
        // 如需要则扩展栈
        if abs_off > func.stack.allocated_stack {
            func.stack.grow(abs_off)?;
        }

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let slot = &mut func.stack.stack[spi];

        // Check for overlapping special slots
        // 检查是否与特殊槽重叠
        if slot.is_special() {
            let slot_type = slot.get_type();
            match slot_type {
                BpfStackSlotType::Dynptr => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite dynptr slot".into(),
                    ));
                }
                BpfStackSlotType::Iter => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite iterator slot".into(),
                    ));
                }
                BpfStackSlotType::IrqFlag => {
                    return Err(VerifierError::InvalidMemoryAccess(
                        "cannot overwrite IRQ flag slot".into(),
                    ));
                }
                _ => {}
            }
        }

        if size == BPF_REG_SIZE {
            // Full 64-bit spill - preserve full precision
            // 完整 64 位溢出 - 保留完整精度
            slot.mark_spill(reg);
        } else {
            // Partial write - mark affected bytes as misc
            // 部分写入 - 将受影响的字节标记为杂项
            Self::mark_partial_write(slot, stack_off, size);
        }

        Ok(())
    }

    /// Fill (restore) a register from the stack.
    /// 从栈填充（恢复）寄存器
    ///
    /// Returns the register state if a full spill was found,
    /// otherwise returns appropriate result for partial/unknown data.
    /// 如果找到完整溢出则返回寄存器状态，
    /// 否则对于部分/未知数据返回适当的结果。
    pub fn fill_reg(
        state: &BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<StackReadResult> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state
            .cur_func()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            // Reading from unallocated stack
            // 从未分配的栈读取
            return Ok(StackReadResult::Uninitialized);
        }

        let slot = &func.stack.stack[spi];
        let slot_type = slot.get_type();

        // Check slot types
        // 检查槽类型
        match slot_type {
            BpfStackSlotType::Spill => {
                if size == BPF_REG_SIZE && slot.is_spilled_scalar_reg64() {
                    // Full 64-bit read of a spilled register - restore with precision
                    // 完整 64 位读取溢出的寄存器 - 精确恢复
                    Ok(StackReadResult::SpilledReg(slot.spilled_ptr.clone()))
                } else if size == BPF_REG_SIZE {
                    // Full read but not a scalar - still restore
                    // 完整读取但不是标量 - 仍然恢复
                    Ok(StackReadResult::SpilledReg(slot.spilled_ptr.clone()))
                } else {
                    // Partial read of a spill - loses precision
                    // 部分读取溢出 - 丢失精度
                    Ok(StackReadResult::Initialized)
                }
            }
            BpfStackSlotType::Zero => Ok(StackReadResult::Zero),
            BpfStackSlotType::Misc => {
                // Initialized but unknown value
                // 已初始化但值未知
                Ok(StackReadResult::Initialized)
            }
            BpfStackSlotType::Invalid => {
                // Reading uninitialized data
                // 读取未初始化的数据
                Ok(StackReadResult::Uninitialized)
            }
            BpfStackSlotType::Dynptr => Ok(StackReadResult::Dynptr(slot.spilled_ptr.clone())),
            BpfStackSlotType::Iter => Ok(StackReadResult::Iterator(slot.spilled_ptr.clone())),
            BpfStackSlotType::IrqFlag => Err(VerifierError::InvalidMemoryAccess(
                "cannot read IRQ flag directly".into(),
            )),
        }
    }

    /// Check if a stack range is readable.
    /// 检查栈范围是否可读
    pub fn check_stack_read(state: &BpfVerifierState, stack_off: i32, size: usize) -> Result<bool> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state
            .cur_func()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        // For stack access at offset -8 with size 8, we check the slot at SPI 0
        // The slot covers bytes at offsets -8 through -1
        // 对于偏移 -8 大小为 8 的栈访问，我们检查 SPI 0 处的槽
        // 该槽覆盖偏移 -8 到 -1 的字节
        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Ok(false); // Unallocated 未分配
        }

        let slot = &func.stack.stack[spi];

        // Check that all bytes in the range are initialized
        // 检查范围内的所有字节是否已初始化
        // For a full 8-byte read at the slot boundary, check all slot bytes
        // 对于在槽边界的完整 8 字节读取，检查所有槽字节
        if size == BPF_REG_SIZE {
            for i in 0..BPF_REG_SIZE {
                if slot.slot_type[i] == BpfStackSlotType::Invalid {
                    return Ok(false);
                }
            }
        } else {
            // Partial read - check specific bytes
            // 部分读取 - 检查特定字节
            let start_byte = ((-stack_off - 1) as usize) % BPF_REG_SIZE;
            for i in 0..size {
                let byte_idx = (start_byte + BPF_REG_SIZE - i) % BPF_REG_SIZE;
                if byte_idx < BPF_REG_SIZE && slot.slot_type[byte_idx] == BpfStackSlotType::Invalid
                {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check if a stack range is writable (no special slots).
    /// 检查栈范围是否可写（无特殊槽）
    pub fn check_stack_write(
        state: &BpfVerifierState,
        stack_off: i32,
        size: usize,
    ) -> Result<bool> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state
            .cur_func()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        // Check for special slots that cannot be overwritten
        // 检查不能被覆盖的特殊槽
        for i in 0..size {
            let byte_off = stack_off - i as i32;
            let Some(spi) = get_spi(byte_off) else {
                continue;
            };

            if spi < func.stack.stack.len() {
                let slot = &func.stack.stack[spi];
                let slot_type = slot.get_type();

                match slot_type {
                    BpfStackSlotType::Dynptr
                    | BpfStackSlotType::Iter
                    | BpfStackSlotType::IrqFlag => {
                        return Ok(false);
                    }
                    _ => {}
                }
            }
        }

        Ok(true)
    }

    /// Mark a partial write (destroys existing spill precision).
    /// 标记部分写入（破坏现有溢出精度）
    fn mark_partial_write(slot: &mut BpfStackState, off: i32, size: usize) {
        let start_byte = ((-off - 1) as usize) % BPF_REG_SIZE;

        for i in 0..size {
            let byte_idx = (start_byte + i) % BPF_REG_SIZE;
            if byte_idx < BPF_REG_SIZE {
                slot.slot_type[byte_idx] = BpfStackSlotType::Misc;
            }
        }

        // If we've partially overwritten a spill, it's no longer a valid spill
        // 如果我们部分覆盖了溢出，它就不再是有效的溢出
        let mut has_spill = false;
        let mut has_other = false;
        for i in 0..BPF_REG_SIZE {
            if slot.slot_type[i] == BpfStackSlotType::Spill {
                has_spill = true;
            } else if slot.slot_type[i] != BpfStackSlotType::Invalid {
                has_other = true;
            }
        }

        if has_spill && has_other {
            // Partially destroyed spill - convert all spill bytes to misc
            // 部分破坏的溢出 - 将所有溢出字节转换为杂项
            for i in 0..BPF_REG_SIZE {
                if slot.slot_type[i] == BpfStackSlotType::Spill {
                    slot.slot_type[i] = BpfStackSlotType::Misc;
                }
            }
        }
    }

    /// Store a zero value to the stack.
    /// 将零值存储到栈
    pub fn store_zero(state: &mut BpfVerifierState, stack_off: i32, size: usize) -> Result<()> {
        if stack_off >= 0 {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let abs_off = (-stack_off) as usize;
        if abs_off > MAX_BPF_STACK {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let func = state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        // Grow stack if needed
        // 如需要则扩展栈
        if abs_off > func.stack.allocated_stack {
            func.stack.grow(abs_off)?;
        }

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi >= func.stack.stack.len() {
            return Err(VerifierError::StackOutOfBounds(stack_off));
        }

        let _slot = &mut func.stack.stack[spi];

        // Check for special slots
        // 检查特殊槽
        if !Self::check_stack_write(state, stack_off, size)? {
            // Re-borrow for the actual write
            // 重新借用以进行实际写入
            let func = state
                .cur_func_mut()
                .ok_or(VerifierError::Internal("no current function".into()))?;
            let slot = &mut func.stack.stack[spi];

            if slot.get_type() == BpfStackSlotType::Dynptr
                || slot.get_type() == BpfStackSlotType::Iter
                || slot.get_type() == BpfStackSlotType::IrqFlag
            {
                return Err(VerifierError::InvalidMemoryAccess(
                    "cannot overwrite special stack slot with zero".into(),
                ));
            }
        }

        // Re-borrow for the actual write
        // 重新借用以进行实际写入
        let func = state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;
        let slot = &mut func.stack.stack[spi];

        if size == BPF_REG_SIZE {
            slot.mark_zero_full();
        } else {
            let start_byte = ((-stack_off - 1) as usize) % BPF_REG_SIZE;
            for i in 0..size {
                let byte_idx = (start_byte + i) % BPF_REG_SIZE;
                if byte_idx < BPF_REG_SIZE {
                    slot.slot_type[byte_idx] = BpfStackSlotType::Zero;
                }
            }
        }

        Ok(())
    }

    /// Scrub a spilled register (convert to misc when callee-saved).
    /// 擦除溢出的寄存器（在被调用者保存时转换为杂项）
    pub fn scrub_spill(state: &mut BpfVerifierState, stack_off: i32) -> Result<()> {
        if stack_off >= 0 {
            return Ok(());
        }

        let func = state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        let spi = get_spi(stack_off).ok_or(VerifierError::StackOutOfBounds(stack_off))?;
        if spi < func.stack.stack.len() {
            let slot = &mut func.stack.stack[spi];
            if slot.is_spilled_reg() {
                slot.mark_misc_full();
            }
        }

        Ok(())
    }
}

/// Apply a fill operation result to a destination register.
/// 将填充操作结果应用到目标寄存器
pub fn apply_fill_result(dst: &mut BpfRegState, result: StackReadResult, size: usize) {
    match result {
        StackReadResult::SpilledReg(spilled) => {
            *dst = spilled;
        }
        StackReadResult::Zero => {
            dst.mark_known_zero();
            if size < BPF_REG_SIZE {
                // Partial read of zero - still zero but limited range
                // 部分读取零 - 仍然是零但范围有限
                dst.umax_value = (1u64 << (size * 8)) - 1;
            }
        }
        StackReadResult::Initialized => {
            dst.mark_unknown(false);
            if size < BPF_REG_SIZE {
                // Limit range based on size
                // 根据大小限制范围
                dst.umax_value = (1u64 << (size * 8)) - 1;
                dst.smax_value = dst.umax_value as i64;
            }
        }
        StackReadResult::Uninitialized => {
            // Should have been caught earlier as an error
            // 应该早已作为错误捕获
            dst.mark_unknown(false);
        }
        StackReadResult::Dynptr(spilled) => {
            *dst = spilled;
        }
        StackReadResult::Iterator(spilled) => {
            *dst = spilled;
        }
    }
}
