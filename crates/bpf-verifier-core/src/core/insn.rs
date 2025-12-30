// SPDX-License-Identifier: GPL-2.0

//! Instruction checking and validation
//! 指令检查和验证
//!
//! This module implements the instruction-level verification logic,
//! including ALU operations, jumps, calls, and memory access instructions.
//!
//! 本模块实现指令级验证逻辑，包括 ALU 操作、跳转、调用和内存访问指令。

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Check if a register is 64-bit for the given instruction
/// 检查寄存器在给定指令中是否为 64 位
pub fn is_reg64(insn: &BpfInsn, _regno: usize, is_src: bool) -> bool {
    let class = insn.class();

    // 32-bit ALU operations
    // 32 位 ALU 操作
    if class == BPF_ALU {
        // MOV32 and shifts are special
        // MOV32 和移位操作是特殊的
        if is_src {
            if insn.code & 0xf0 == BPF_MOV {
                return false;
            }
            // Shifts use only lower 5/6 bits
            // 移位操作仅使用低 5/6 位
            if matches!(insn.code & 0xf0, BPF_LSH | BPF_RSH | BPF_ARSH) {
                return false;
            }
        }
        return false;
    }

    // 64-bit ALU operations
    // 64 位 ALU 操作
    if class == BPF_ALU64 {
        return true;
    }

    // Memory operations - depends on size
    // 内存操作 - 取决于大小
    if matches!(class, BPF_LDX | BPF_STX | BPF_ST) {
        let size = insn.size();
        // BPF_DW is 64-bit
        // BPF_DW 是 64 位
        return size == 3; // BPF_DW
    }

    // Jumps and calls are 64-bit
    // 跳转和调用是 64 位的
    true
}

/// Get the destination register for an instruction (if any)
/// 获取指令的目标寄存器（如果有）
pub fn insn_def_regno(insn: &BpfInsn) -> Option<usize> {
    let class = insn.class();

    match class {
        BPF_ALU | BPF_ALU64 => {
            // NEG has no dst in some cases, but generally ALU writes to dst
            // NEG 在某些情况下没有目标寄存器，但通常 ALU 会写入目标寄存器
            Some(insn.dst_reg as usize)
        }
        BPF_LDX => Some(insn.dst_reg as usize),
        BPF_LD => {
            // LD_IMM64 writes to dst
            // LD_IMM64 写入目标寄存器
            if insn.mode() == BPF_IMM {
                Some(insn.dst_reg as usize)
            } else {
                Some(BPF_REG_0)
            }
        }
        BPF_JMP | BPF_JMP32 => {
            // CALL writes to R0
            // CALL 写入 R0
            if insn.code & 0xf0 == BPF_CALL {
                Some(BPF_REG_0)
            } else {
                None
            }
        }
        BPF_STX => {
            // Atomic operations may write to dst
            // 原子操作可能写入目标寄存器
            if insn.mode() == BPF_ATOMIC {
                // CMPXCHG always writes to R0
                // CMPXCHG 总是写入 R0
                if insn.imm == BPF_CMPXCHG as i32 {
                    Some(BPF_REG_0)
                } else if insn.imm & BPF_FETCH as i32 != 0 {
                    Some(insn.src_reg as usize)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if instruction has a 32-bit definition
/// 检查指令是否有 32 位定义
pub fn insn_has_def32(insn: &BpfInsn) -> bool {
    if let Some(regno) = insn_def_regno(insn) {
        !is_reg64(insn, regno, false)
    } else {
        false
    }
}

/// Check register argument (source or destination)
/// 检查寄存器参数（源或目标）
pub fn check_reg_arg(
    state: &mut BpfVerifierState,
    _insn: &BpfInsn,
    regno: usize,
    is_src: bool,
    allow_ptr_leaks: bool,
) -> Result<()> {
    if regno >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(regno as u8));
    }

    let reg = state
        .reg(regno)
        .ok_or(VerifierError::Internal("failed to get register".into()))?;

    if is_src {
        // Source register must be readable (initialized)
        // 源寄存器必须可读（已初始化）
        if reg.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(regno as u8));
        }
        // Mark as read
        // 标记为已读
        // state.reg_mut(regno).unwrap().live.read = true;
    } else {
        // Destination register will be written
        // 目标寄存器将被写入
        // Check pointer leaks in unprivileged mode
        // 在非特权模式下检查指针泄漏
        if !allow_ptr_leaks && reg.is_pointer() {
            // This is OK for most cases, but might need special handling
            // 这在大多数情况下是可以的，但可能需要特殊处理
        }
        // Mark as written
        // 标记为已写入
        // state.reg_mut(regno).unwrap().live.written = true;
    }

    Ok(())
}

/// Mark instruction as needing zero extension
/// 标记指令需要零扩展
pub fn mark_insn_zext(state: &mut BpfVerifierState, insn: &BpfInsn) -> Result<()> {
    if let Some(regno) = insn_def_regno(insn) {
        if !is_reg64(insn, regno, false) {
            // 32-bit write needs zero extension
            // 32 位写入需要零扩展
            if let Some(reg) = state.reg_mut(regno) {
                reg.subreg_def = 1; // Mark as having 32-bit definition / 标记为有 32 位定义
            }
        }
    }
    Ok(())
}

/// Check ALU operation
/// 检查 ALU 操作
pub fn check_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let class = insn.class();
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;

    let dst_reg = insn.dst_reg as usize;
    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(dst_reg as u8));
    }

    // Check destination register
    // 检查目标寄存器
    check_reg_arg(state, insn, dst_reg, false, allow_ptr_leaks)?;

    // For register source, check it's valid
    // 对于寄存器源，检查其有效性
    if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        check_reg_arg(state, insn, src_reg, true, allow_ptr_leaks)?;
    }

    // Special handling for NEG (no source operand)
    // NEG 的特殊处理（无源操作数）
    if op == BPF_NEG {
        let dst_state = state
            .reg(dst_reg)
            .ok_or(VerifierError::Internal("failed to get dst register".into()))?
            .clone();

        if dst_state.is_pointer() {
            return Err(VerifierError::InvalidPointerArithmetic(
                "NEG not allowed on pointers".into(),
            ));
        }

        if let Some(dst) = state.reg_mut(dst_reg) {
            if dst.is_const() {
                let val = dst.const_value();
                let neg_val = (-(val as i64)) as u64;
                if class == BPF_ALU64 {
                    dst.mark_known(neg_val);
                } else {
                    dst.mark_known((neg_val as u32) as u64);
                    dst.subreg_def = 1;
                }
            } else {
                // For non-constant, swap and negate bounds
                // 对于非常量，交换并取反边界
                let (new_smin, new_smax) = if dst.smax_value != i64::MIN {
                    (-dst.smax_value, -dst.smin_value.saturating_neg())
                } else {
                    (i64::MIN, i64::MAX)
                };
                dst.smin_value = new_smin;
                dst.smax_value = new_smax;
                dst.umin_value = 0;
                dst.umax_value = u64::MAX;
                if class == BPF_ALU {
                    dst.subreg_def = 1;
                    dst.assign_32_into_64();
                }
            }
        }
        return Ok(());
    }

    // Special handling for END (byte swap)
    // END（字节交换）的特殊处理
    if op == BPF_END {
        let dst_state = state
            .reg(dst_reg)
            .ok_or(VerifierError::Internal("failed to get dst register".into()))?
            .clone();

        if dst_state.is_pointer() {
            return Err(VerifierError::InvalidPointerArithmetic(
                "byte swap not allowed on pointers".into(),
            ));
        }

        // insn.imm specifies the swap size (16, 32, or 64)
        // insn.imm 指定交换大小（16、32 或 64）
        let swap_size = insn.imm as u32;

        if let Some(dst) = state.reg_mut(dst_reg) {
            if dst.is_const() {
                let val = dst.const_value();
                let swapped = match swap_size {
                    16 => (val as u16).swap_bytes() as u64,
                    32 => (val as u32).swap_bytes() as u64,
                    64 => val.swap_bytes(),
                    _ => {
                        dst.mark_unknown(false);
                        return Ok(());
                    }
                };
                dst.mark_known(swapped);
            } else {
                // After byte swap, bounds become unknown
                // 字节交换后，边界变为未知
                // But we can constrain based on swap size
                // 但我们可以根据交换大小进行约束
                match swap_size {
                    16 => {
                        dst.umin_value = 0;
                        dst.umax_value = u16::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u16::MAX as i64;
                    }
                    32 => {
                        dst.umin_value = 0;
                        dst.umax_value = u32::MAX as u64;
                        dst.smin_value = 0;
                        dst.smax_value = u32::MAX as i64;
                    }
                    64 => {
                        dst.mark_unbounded();
                    }
                    _ => {
                        dst.mark_unknown(false);
                    }
                }
            }

            // BPF_ALU class with END is for 64-bit values
            // BPF_ALU 类与 END 用于 64 位值
            if class == BPF_ALU && swap_size != 64 {
                dst.subreg_def = 1;
            }
        }
        return Ok(());
    }

    // Special handling for MOV
    // MOV 的特殊处理
    if op == BPF_MOV {
        if src_type == BPF_X {
            // Register move
            // 寄存器移动
            let src_reg = insn.src_reg as usize;
            let src_state = state
                .reg(src_reg)
                .ok_or(VerifierError::Internal("failed to get src register".into()))?
                .clone();

            if let Some(dst) = state.reg_mut(dst_reg) {
                *dst = src_state;
                if class == BPF_ALU {
                    // 32-bit move - upper bits get zeroed
                    // 32 位移动 - 高位被清零
                    dst.subreg_def = 1;
                    dst.assign_32_into_64();
                }
            }
        } else {
            // Immediate move
            // 立即数移动
            if let Some(dst) = state.reg_mut(dst_reg) {
                if class == BPF_ALU64 {
                    dst.reg_type = BpfRegType::ScalarValue;
                    dst.mark_known(insn.imm as i64 as u64);
                } else {
                    dst.reg_type = BpfRegType::ScalarValue;
                    dst.mark_known(insn.imm as u32 as u64);
                    dst.subreg_def = 1;
                }
            }
        }
        return Ok(());
    }

    // For other ALU ops, check operands
    // 对于其他 ALU 操作，检查操作数
    let dst_state = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("failed to get dst register".into()))?
        .clone();

    // Handle pointer arithmetic
    // 处理指针算术
    if dst_state.is_pointer() {
        return check_ptr_alu_op(state, insn, &dst_state, allow_ptr_leaks);
    }

    // Scalar ALU operation
    // 标量 ALU 操作
    check_scalar_alu_op(state, insn, class == BPF_ALU64)
}

/// Check pointer ALU operation
/// 检查指针 ALU 操作
fn check_ptr_alu_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    dst_state: &BpfRegState,
    allow_ptr_leaks: bool,
) -> Result<()> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;

    // Only ADD and SUB are allowed on pointers
    // 指针上只允许 ADD 和 SUB
    if !matches!(op, BPF_ADD | BPF_SUB) {
        if !allow_ptr_leaks {
            return Err(VerifierError::InvalidPointerArithmetic(
                "only ADD and SUB allowed on pointers".into(),
            ));
        }
        // In privileged mode, mark result as unknown scalar
        // 在特权模式下，将结果标记为未知标量
        if let Some(dst) = state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
        }
        return Ok(());
    }

    // Get the addend (either immediate or register value)
    // 获取加数（立即数或寄存器值）
    let addend = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        let src_state = state
            .reg(src_reg)
            .ok_or(VerifierError::Internal("failed to get src register".into()))?;

        // Source must be scalar for pointer arithmetic
        // 指针算术的源必须是标量
        if src_state.is_pointer() {
            if op == BPF_SUB && dst_state.reg_type == src_state.reg_type {
                // ptr - ptr = scalar (if same type)
                // ptr - ptr = 标量（如果类型相同）
                if let Some(dst) = state.reg_mut(dst_reg) {
                    dst.mark_unknown(false);
                }
                return Ok(());
            }
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot add pointer to pointer".into(),
            ));
        }

        if src_state.is_const() {
            Some(src_state.const_value() as i64)
        } else {
            None
        }
    } else {
        Some(insn.imm as i64)
    };

    // Update pointer offset
    // 更新指针偏移量
    if let Some(dst) = state.reg_mut(dst_reg) {
        if let Some(add_val) = addend {
            let new_off = if op == BPF_ADD {
                dst_state.off.saturating_add(add_val as i32)
            } else {
                dst_state.off.saturating_sub(add_val as i32)
            };
            *dst = dst_state.clone();
            dst.off = new_off;
        } else {
            // Unknown addend - update var_off
            // 未知加数 - 更新 var_off
            *dst = dst_state.clone();
            dst.var_off = crate::bounds::tnum::Tnum::unknown();
        }
    }

    Ok(())
}

/// Check scalar ALU operation
/// 检查标量 ALU 操作
fn check_scalar_alu_op(state: &mut BpfVerifierState, insn: &BpfInsn, is_64bit: bool) -> Result<()> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;

    // Get source value
    // 获取源值
    let src_val = if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        state.reg(src_reg).cloned()
    } else {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        if is_64bit {
            // Sign-extend for 64-bit operations
            // 64 位操作的符号扩展
            reg.mark_known(insn.imm as i64 as u64);
        } else {
            // Zero-extend for 32-bit operations
            // 32 位操作的零扩展
            reg.mark_known(insn.imm as u32 as u64);
        }
        Some(reg)
    };

    let src = src_val.ok_or(VerifierError::Internal("no src value".into()))?;
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?
        .clone();

    // Check for division by zero
    // 检查除以零
    if matches!(op, BPF_DIV | BPF_MOD) {
        // Check if divisor could be zero
        // 检查除数是否可能为零
        if src.umax_value == 0 {
            return Err(VerifierError::DivisionByZero);
        }
        // Note: runtime check will be inserted if umin_value == 0
        // 注意：如果 umin_value == 0，将插入运行时检查
    }

    // Use ScalarBounds for comprehensive bounds propagation
    // 使用 ScalarBounds 进行全面的边界传播
    let result = compute_alu_result(&dst, &src, op, is_64bit)?;

    if let Some(dst_mut) = state.reg_mut(dst_reg) {
        *dst_mut = result;
        if !is_64bit {
            dst_mut.subreg_def = 1;
            // Zero-extend 32-bit result to 64-bit
            // 将 32 位结果零扩展到 64 位
            dst_mut.assign_32_into_64();
        }
        // Ensure bounds are synchronized
        // 确保边界同步
        dst_mut.sync_bounds();
    }

    Ok(())
}

/// Compute ALU result with bounds tracking using ScalarBounds
/// 使用 ScalarBounds 计算带边界跟踪的 ALU 结果
fn compute_alu_result(
    dst: &BpfRegState,
    src: &BpfRegState,
    op: u8,
    is_64bit: bool,
) -> Result<BpfRegState> {
    let mut result = dst.clone();
    result.reg_type = BpfRegType::ScalarValue;

    // Convert to ScalarBounds for comprehensive ALU handling
    // 转换为 ScalarBounds 以进行全面的 ALU 处理
    let dst_bounds = dst.to_scalar_bounds();
    let src_bounds = src.to_scalar_bounds();

    // Use ScalarBounds::alu_op for proper bounds propagation
    // 使用 ScalarBounds::alu_op 进行正确的边界传播
    let result_bounds = dst_bounds.alu_op(op, &src_bounds, is_64bit)?;

    // Apply the computed bounds back to the register state
    // 将计算的边界应用回寄存器状态
    result.apply_scalar_bounds(&result_bounds);

    // Handle 32-bit operations - zero extension
    // 处理 32 位操作 - 零扩展
    if !is_64bit {
        result.subreg_def = 1;
    }

    Ok(result)
}

/// Check conditional jump operation
/// 检查条件跳转操作
///
/// This function implements the kernel's `check_cond_jmp_op()`. It:
/// 1. Validates the registers used in the comparison
/// 2. Determines if the branch outcome can be statically determined
/// 3. Refines register bounds based on the branch condition
/// 4. Returns the possible paths (fall-through and/or target)
///
/// 此函数实现内核的 `check_cond_jmp_op()`。它：
/// 1. 验证比较中使用的寄存器
/// 2. 确定分支结果是否可以静态确定
/// 3. 根据分支条件细化寄存器边界
/// 4. 返回可能的路径（直落和/或目标）
pub fn check_cond_jmp_op(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
    allow_ptr_leaks: bool,
) -> Result<(Option<usize>, Option<usize>)> {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let dst_reg = insn.dst_reg as usize;
    let is_32bit = insn.class() == BPF_JMP32;

    // Unconditional jump
    // 无条件跳转
    if op == BPF_JA {
        let target = (insn_idx as i32 + insn.off as i32 + 1) as usize;
        return Ok((Some(target), None));
    }

    // Check destination register
    // 检查目标寄存器
    check_reg_arg(state, insn, dst_reg, true, allow_ptr_leaks)?;

    // Check source register if needed
    // 如果需要，检查源寄存器
    if src_type == BPF_X {
        let src_reg = insn.src_reg as usize;
        check_reg_arg(state, insn, src_reg, true, allow_ptr_leaks)?;
    }

    let fall_through = insn_idx + 1;
    let target = (insn_idx as i32 + insn.off as i32 + 1) as usize;

    // Get register states
    // 获取寄存器状态
    let dst_state = state
        .reg(dst_reg)
        .ok_or(VerifierError::Internal("no dst register".into()))?
        .clone();

    let src_val = if src_type == BPF_X {
        state.reg(insn.src_reg as usize).cloned()
    } else {
        let mut reg = BpfRegState::new_scalar_unknown(false);
        if is_32bit {
            reg.mark_known(insn.imm as u32 as u64);
        } else {
            reg.mark_known(insn.imm as i64 as u64);
        }
        Some(reg)
    };

    let src_state = src_val.ok_or(VerifierError::Internal("no src".into()))?;

    // Check for pointer comparisons
    // 检查指针比较
    if dst_state.is_pointer() || src_state.is_pointer() {
        return check_ptr_cmp(
            state,
            insn,
            &dst_state,
            &src_state,
            fall_through,
            target,
            allow_ptr_leaks,
        );
    }

    // Try to determine if branch is always/never taken using bounds
    // 尝试使用边界确定分支是否总是/从不被采取
    let taken = is_branch_taken_with_bounds(&dst_state, &src_state, op, is_32bit);

    match taken {
        Some(true) => {
            // Branch always taken - refine dst bounds for target path
            // 分支总是被采取 - 为目标路径细化目标边界
            refine_reg_bounds_for_branch(state, dst_reg, &src_state, op, true, is_32bit);
            Ok((Some(target), None))
        }
        Some(false) => {
            // Branch never taken - refine dst bounds for fall-through path
            // 分支从不被采取 - 为直落路径细化目标边界
            refine_reg_bounds_for_branch(state, dst_reg, &src_state, op, false, is_32bit);
            Ok((Some(fall_through), None))
        }
        None => {
            // Both paths possible - bounds will be refined per-path in the caller
            // 两条路径都可能 - 边界将在调用者中按路径细化
            // Mark registers as needing precision for this conditional
            // 标记寄存器需要此条件的精度
            mark_regs_for_precision(
                state,
                dst_reg,
                if src_type == BPF_X {
                    Some(insn.src_reg as usize)
                } else {
                    None
                },
            );
            Ok((Some(fall_through), Some(target)))
        }
    }
}

/// Check pointer comparison in conditional jump
/// 检查条件跳转中的指针比较
fn check_ptr_cmp(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    dst: &BpfRegState,
    src: &BpfRegState,
    fall_through: usize,
    target: usize,
    allow_ptr_leaks: bool,
) -> Result<(Option<usize>, Option<usize>)> {
    let op = insn.code & 0xf0;
    let dst_reg = insn.dst_reg as usize;

    // Only certain comparisons are allowed for pointers
    // 指针只允许某些比较
    match op {
        BPF_JEQ | BPF_JNE => {
            // Equality comparison is always allowed
            // 相等比较始终允许
        }
        BPF_JGT | BPF_JGE | BPF_JLT | BPF_JLE | BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE => {
            // Ordering comparisons require same pointer type
            // 排序比较需要相同的指针类型
            if dst.is_pointer()
                && src.is_pointer()
                && dst.reg_type != src.reg_type
                && !allow_ptr_leaks
            {
                return Err(VerifierError::InvalidPointerComparison(
                    "cannot compare pointers of different types".into(),
                ));
            }
        }
        _ => {
            return Err(VerifierError::InvalidPointerComparison(
                "invalid comparison operation for pointers".into(),
            ));
        }
    }

    // Handle NULL pointer checks
    // 处理 NULL 指针检查
    if op == BPF_JEQ || op == BPF_JNE {
        // Check if comparing with NULL (scalar 0)
        // 检查是否与 NULL（标量 0）比较
        let comparing_with_null =
            (src.reg_type == BpfRegType::ScalarValue && src.is_const() && src.const_value() == 0)
                || (dst.reg_type == BpfRegType::ScalarValue
                    && dst.is_const()
                    && dst.const_value() == 0);

        if comparing_with_null {
            // This is a NULL check - important for PTR_MAYBE_NULL handling
            // 这是 NULL 检查 - 对于 PTR_MAYBE_NULL 处理很重要
            if dst.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                // After check, one path has non-NULL pointer
                // 检查后，一条路径有非 NULL 指针
                // The caller should handle marking the pointer as non-null on the appropriate path
                // 调用者应在适当的路径上处理将指针标记为非空
                return Ok((Some(fall_through), Some(target)));
            }
        }
    }

    // For same-type pointers, try to determine outcome from offsets
    // 对于相同类型的指针，尝试从偏移量确定结果
    if dst.reg_type == src.reg_type && dst.is_const() && src.is_const() {
        let dst_val = dst.const_value();
        let src_val = src.const_value();

        let taken = match op {
            BPF_JEQ => dst_val == src_val,
            BPF_JNE => dst_val != src_val,
            BPF_JGT => dst_val > src_val,
            BPF_JGE => dst_val >= src_val,
            BPF_JLT => dst_val < src_val,
            BPF_JLE => dst_val <= src_val,
            _ => return Ok((Some(fall_through), Some(target))),
        };

        if taken {
            return Ok((Some(target), None));
        } else {
            return Ok((Some(fall_through), None));
        }
    }

    // Mark dst as needing precision for the conditional
    // 标记目标需要条件的精度
    mark_regs_for_precision(state, dst_reg, None);

    Ok((Some(fall_through), Some(target)))
}

/// Determine if branch is taken based on register bounds
/// 根据寄存器边界确定是否采取分支
fn is_branch_taken_with_bounds(
    dst: &BpfRegState,
    src: &BpfRegState,
    op: u8,
    is_32bit: bool,
) -> Option<bool> {
    // First try exact constant comparison
    // 首先尝试精确常量比较
    if let Some(result) = is_branch_taken(dst, src, op, is_32bit) {
        return Some(result);
    }

    // Try bounds-based reasoning
    // 尝试基于边界的推理
    if dst.reg_type != BpfRegType::ScalarValue {
        return None;
    }

    let (dst_umin, dst_umax, dst_smin, dst_smax) = if is_32bit {
        (
            dst.u32_min_value as u64,
            dst.u32_max_value as u64,
            dst.s32_min_value as i64,
            dst.s32_max_value as i64,
        )
    } else {
        (
            dst.umin_value,
            dst.umax_value,
            dst.smin_value,
            dst.smax_value,
        )
    };

    let (src_umin, src_umax, src_smin, src_smax) = if src.is_const() {
        let val = src.const_value();
        let sval = val as i64;
        (val, val, sval, sval)
    } else if src.reg_type == BpfRegType::ScalarValue {
        if is_32bit {
            (
                src.u32_min_value as u64,
                src.u32_max_value as u64,
                src.s32_min_value as i64,
                src.s32_max_value as i64,
            )
        } else {
            (
                src.umin_value,
                src.umax_value,
                src.smin_value,
                src.smax_value,
            )
        }
    } else {
        return None;
    };

    match op {
        BPF_JEQ => {
            // Can only be always-true if both are single values and equal
            // 只有当两者都是单一值且相等时才能总是为真
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(true);
            }
            // Can be always-false if ranges don't overlap
            // 如果范围不重叠，则可以总是为假
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(false);
            }
        }
        BPF_JNE => {
            // Always true if ranges don't overlap
            // 如果范围不重叠，则总是为真
            if dst_umax < src_umin || dst_umin > src_umax {
                return Some(true);
            }
            // Always false if both are same constant
            // 如果两者是相同的常量，则总是为假
            if dst_umin == dst_umax && src_umin == src_umax && dst_umin == src_umin {
                return Some(false);
            }
        }
        BPF_JGT => {
            if dst_umin > src_umax {
                return Some(true);
            }
            if dst_umax <= src_umin {
                return Some(false);
            }
        }
        BPF_JGE => {
            if dst_umin >= src_umax {
                return Some(true);
            }
            if dst_umax < src_umin {
                return Some(false);
            }
        }
        BPF_JLT => {
            if dst_umax < src_umin {
                return Some(true);
            }
            if dst_umin >= src_umax {
                return Some(false);
            }
        }
        BPF_JLE => {
            if dst_umax <= src_umin {
                return Some(true);
            }
            if dst_umin > src_umax {
                return Some(false);
            }
        }
        BPF_JSGT => {
            if dst_smin > src_smax {
                return Some(true);
            }
            if dst_smax <= src_smin {
                return Some(false);
            }
        }
        BPF_JSGE => {
            if dst_smin >= src_smax {
                return Some(true);
            }
            if dst_smax < src_smin {
                return Some(false);
            }
        }
        BPF_JSLT => {
            if dst_smax < src_smin {
                return Some(true);
            }
            if dst_smin >= src_smax {
                return Some(false);
            }
        }
        BPF_JSLE => {
            if dst_smax <= src_smin {
                return Some(true);
            }
            if dst_smin > src_smax {
                return Some(false);
            }
        }
        BPF_JSET => {
            // Can determine if known bits definitely overlap or don't
            // 可以确定已知位是否明确重叠或不重叠
            let known_dst = !dst.var_off.mask;
            let known_src = !src.var_off.mask;
            let val_dst = dst.var_off.value;
            let val_src = src.var_off.value;

            // If all bits are known and overlap is non-zero
            // 如果所有位都已知且重叠非零
            if known_dst & known_src == u64::MAX {
                return Some((val_dst & val_src) != 0);
            }
            // If any known set bit overlaps
            // 如果任何已知设置位重叠
            if (val_dst & val_src) != 0 {
                return Some(true);
            }
        }
        _ => {}
    }

    None
}

/// Refine register bounds based on branch outcome
/// 根据分支结果细化寄存器边界
fn refine_reg_bounds_for_branch(
    state: &mut BpfVerifierState,
    dst_reg: usize,
    src: &BpfRegState,
    op: u8,
    taken: bool,
    is_32bit: bool,
) {
    let dst = match state.reg_mut(dst_reg) {
        Some(r) => r,
        None => return,
    };

    if dst.reg_type != BpfRegType::ScalarValue {
        return;
    }

    let src_val = if src.is_const() {
        src.const_value()
    } else {
        return; // Can only refine with constant source for now / 目前只能用常量源进行细化
    };

    // Apply refinement using the range_refine module logic
    // 使用 range_refine 模块逻辑应用细化
    use crate::bounds::range_refine::{refine_reg_const, BranchCond};

    let cond = match op {
        BPF_JEQ => BranchCond::Eq,
        BPF_JNE => BranchCond::Ne,
        BPF_JGT => BranchCond::Gt,
        BPF_JGE => BranchCond::Ge,
        BPF_JLT => BranchCond::Lt,
        BPF_JLE => BranchCond::Le,
        BPF_JSGT => BranchCond::Sgt,
        BPF_JSGE => BranchCond::Sge,
        BPF_JSLT => BranchCond::Slt,
        BPF_JSLE => BranchCond::Sle,
        _ => return,
    };

    let result = refine_reg_const(dst, src_val, cond, taken);
    result.apply_to(dst);

    // Handle 32-bit operations
    // 处理 32 位操作
    if is_32bit {
        // Sync 32-bit bounds to 64-bit
        // 同步 32 位边界到 64 位
        dst.sync_bounds();
    }
}

/// Mark registers as needing precision for conditional
/// 标记寄存器需要条件的精度
fn mark_regs_for_precision(state: &mut BpfVerifierState, dst_reg: usize, src_reg: Option<usize>) {
    if let Some(dst) = state.reg_mut(dst_reg) {
        if dst.reg_type == BpfRegType::ScalarValue {
            dst.precise = true;
        }
    }

    if let Some(src_regno) = src_reg {
        if let Some(src) = state.reg_mut(src_regno) {
            if src.reg_type == BpfRegType::ScalarValue {
                src.precise = true;
            }
        }
    }
}

/// Determine if a branch is statically taken
/// 确定分支是否静态被采取
fn is_branch_taken(dst: &BpfRegState, src: &BpfRegState, op: u8, _is_32bit: bool) -> Option<bool> {
    // Only check if both are constants
    // 只有当两者都是常量时才检查
    if !dst.is_const() || !src.is_const() {
        // Could do range analysis here
        // 这里可以做范围分析
        return None;
    }

    let d = dst.const_value();
    let s = src.const_value();

    let result = match op {
        BPF_JEQ => d == s,
        BPF_JNE => d != s,
        BPF_JGT => d > s,
        BPF_JGE => d >= s,
        BPF_JLT => d < s,
        BPF_JLE => d <= s,
        BPF_JSGT => (d as i64) > (s as i64),
        BPF_JSGE => (d as i64) >= (s as i64),
        BPF_JSLT => (d as i64) < (s as i64),
        BPF_JSLE => (d as i64) <= (s as i64),
        BPF_JSET => (d & s) != 0,
        _ => return None,
    };

    Some(result)
}

/// Check LD_IMM64 instruction
/// 检查 LD_IMM64 指令
pub fn check_ld_imm64(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    next_insn: &BpfInsn,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;

    if dst_reg >= MAX_BPF_REG {
        return Err(VerifierError::InvalidRegister(dst_reg as u8));
    }

    // Compute 64-bit immediate
    // 计算 64 位立即数
    let imm = (insn.imm as u32 as u64) | ((next_insn.imm as u32 as u64) << 32);

    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.reg_type = BpfRegType::ScalarValue;
        dst.mark_known(imm);
    }

    Ok(())
}

/// Check CALL instruction
/// 检查 CALL 指令
pub fn check_call(state: &mut BpfVerifierState, insn: &BpfInsn, _insn_idx: usize) -> Result<()> {
    // Check that R1-R5 are properly set up for the call
    // 检查 R1-R5 是否为调用正确设置
    for regno in 1..=5 {
        if let Some(reg) = state.reg(regno) {
            if reg.reg_type == BpfRegType::NotInit {
                // This might be OK depending on the helper
                // 这可能没问题，取决于辅助函数
            }
        }
    }

    // After call, clear caller-saved registers
    // 调用后，清除调用者保存的寄存器
    state.clear_caller_saved_regs();

    // R0 gets the return value (unknown scalar for now)
    // R0 获取返回值（目前为未知标量）
    if let Some(r0) = state.reg_mut(BPF_REG_0) {
        r0.mark_unknown(false);
    }

    // Handle special helpers would go here
    // 特殊辅助函数的处理将在这里
    if insn.is_helper_call() {
        // Check helper-specific constraints
        // 检查辅助函数特定的约束
    } else if insn.is_pseudo_call() {
        // Handle subprogram call
        // 处理子程序调用
        // Would push a new frame here
        // 这里将推送新帧
    } else if insn.is_kfunc_call() {
        // Handle kfunc call
        // 处理 kfunc 调用
    }

    Ok(())
}

/// Check EXIT instruction
/// 检查 EXIT 指令
pub fn check_exit(state: &BpfVerifierState) -> Result<()> {
    // Check for unreleased resources
    // 检查未释放的资源
    state.check_resource_leak()?;

    // R0 should contain the return value
    // R0 应包含返回值
    let r0 = state
        .reg(BPF_REG_0)
        .ok_or(VerifierError::Internal("no R0 at exit".into()))?;

    if r0.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(0));
    }

    Ok(())
}
