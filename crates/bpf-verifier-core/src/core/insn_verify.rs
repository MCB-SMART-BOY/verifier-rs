// SPDX-License-Identifier: GPL-2.0

//! Comprehensive instruction verification
//! 全面的指令验证
//!
//! This module provides complete instruction decoding and verification,
//! dispatching to appropriate handlers for each instruction class.
//!
//! 本模块提供完整的指令解码和验证，为每个指令类别分派到适当的处理程序。

use alloc::format;

use crate::core::error::{Result, VerifierError};
use crate::core::insn::{check_alu_op, check_call, check_cond_jmp_op, check_exit, check_ld_imm64};
use crate::core::types::*;
use crate::mem::memory::check_mem_access;
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;

/// Result of verifying a single instruction
/// 验证单条指令的结果
#[derive(Debug, Clone)]
pub struct InsnVerifyResult {
    /// Next instruction index (fall-through)
    /// 下一条指令索引（直落）
    pub next_insn: Option<usize>,
    /// Branch target (if conditional/unconditional jump)
    /// 分支目标（如果是条件/无条件跳转）
    pub branch_target: Option<usize>,
    /// Whether this instruction terminates (exit/tail_call)
    /// 此指令是否终止（exit/tail_call）
    pub terminates: bool,
    /// Whether to skip the next instruction (for LD_IMM64)
    /// 是否跳过下一条指令（用于 LD_IMM64）
    pub skip_next: bool,
    /// Modified register (if any)
    /// 被修改的寄存器（如果有）
    pub modified_reg: Option<usize>,
}

impl InsnVerifyResult {
    /// Normal sequential execution
    /// 正常顺序执行
    pub fn sequential(insn_idx: usize) -> Self {
        Self {
            next_insn: Some(insn_idx + 1),
            branch_target: None,
            terminates: false,
            skip_next: false,
            modified_reg: None,
        }
    }

    /// Unconditional jump
    /// 无条件跳转
    pub fn jump(target: usize) -> Self {
        Self {
            next_insn: None,
            branch_target: Some(target),
            terminates: false,
            skip_next: false,
            modified_reg: None,
        }
    }

    /// Conditional jump (both paths possible)
    /// 条件跳转（两条路径都可能）
    pub fn conditional(fall_through: usize, target: usize) -> Self {
        Self {
            next_insn: Some(fall_through),
            branch_target: Some(target),
            terminates: false,
            skip_next: false,
            modified_reg: None,
        }
    }

    /// Terminating instruction (exit/tail_call)
    /// 终止指令（exit/tail_call）
    pub fn terminate() -> Self {
        Self {
            next_insn: None,
            branch_target: None,
            terminates: true,
            skip_next: false,
            modified_reg: None,
        }
    }

    /// LD_IMM64 (skip next instruction)
    /// LD_IMM64（跳过下一条指令）
    pub fn skip_one(insn_idx: usize) -> Self {
        Self {
            next_insn: Some(insn_idx + 2),
            branch_target: None,
            terminates: false,
            skip_next: true,
            modified_reg: None,
        }
    }
}

/// Instruction verifier context
/// 指令验证器上下文
pub struct InsnVerifier<'a> {
    /// Current verifier state
    /// 当前验证器状态
    pub state: &'a mut BpfVerifierState,
    /// Program type
    /// 程序类型
    pub prog_type: BpfProgType,
    /// Allow pointer leaks (privileged mode)
    /// 允许指针泄漏（特权模式）
    pub allow_ptr_leaks: bool,
    /// Strict alignment checking
    /// 严格对齐检查
    pub strict_alignment: bool,
}

impl<'a> InsnVerifier<'a> {
    /// Create a new instruction verifier
    /// 创建新的指令验证器
    pub fn new(
        state: &'a mut BpfVerifierState,
        prog_type: BpfProgType,
        allow_ptr_leaks: bool,
    ) -> Self {
        Self {
            state,
            prog_type,
            allow_ptr_leaks,
            strict_alignment: false,
        }
    }

    /// Verify a single instruction
    /// 验证单条指令
    pub fn verify_insn(
        &mut self,
        insn: &BpfInsn,
        next_insn: Option<&BpfInsn>,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => self.verify_alu(insn, insn_idx),
            BPF_LDX => self.verify_ldx(insn, insn_idx),
            BPF_STX => self.verify_stx(insn, insn_idx),
            BPF_ST => self.verify_st(insn, insn_idx),
            BPF_LD => self.verify_ld(insn, next_insn, insn_idx),
            BPF_JMP | BPF_JMP32 => self.verify_jmp(insn, insn_idx),
            _ => Err(VerifierError::InvalidInstruction(insn_idx)),
        }
    }

    /// Verify ALU instruction
    /// 验证 ALU 指令
    fn verify_alu(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        check_alu_op(self.state, insn, self.allow_ptr_leaks)?;
        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify LDX (load from memory) instruction
    /// 验证 LDX（从内存加载）指令
    fn verify_ldx(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let src_reg = insn.src_reg as usize;
        let dst_reg = insn.dst_reg as usize;
        let size = insn_access_size(insn);

        // Check source register is valid pointer
        // 检查源寄存器是否为有效指针
        let src = self
            .state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
            .clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check memory access
        // 检查内存访问
        let result_type = check_mem_access(
            self.state,
            &src,
            insn.off as i32,
            size,
            false, // read / 读取
            self.allow_ptr_leaks,
        )?;

        // Set destination register based on loaded value
        // 根据加载的值设置目标寄存器
        self.set_load_result(dst_reg, &src, insn.off as i32, size, result_type)?;

        Ok(InsnVerifyResult {
            modified_reg: Some(dst_reg),
            ..InsnVerifyResult::sequential(insn_idx)
        })
    }

    /// Verify STX (store register to memory) instruction
    /// 验证 STX（存储寄存器到内存）指令
    fn verify_stx(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let mode = insn.mode();

        if mode == BPF_ATOMIC {
            return self.verify_atomic(insn, insn_idx);
        }

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let size = insn_access_size(insn);

        // Check destination register is valid pointer
        // 检查目标寄存器是否为有效指针
        let dst = self
            .state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check source register is initialized
        // 检查源寄存器是否已初始化
        let src = self
            .state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
            .clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check for pointer leaks
        // 检查指针泄漏
        if !self.allow_ptr_leaks && src.is_pointer() {
            // Storing pointers to certain memory types is restricted
            // 存储指针到某些内存类型是受限的
            self.check_pointer_store(&dst, &src)?;
        }

        // Check memory access
        // 检查内存访问
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true, // write / 写入
            self.allow_ptr_leaks,
        )?;

        // Update stack slots if writing to stack
        // 如果写入栈，则更新栈槽
        if dst.reg_type == BpfRegType::PtrToStack {
            self.update_stack_on_store(&dst, insn.off as i32, size, &src)?;
        }

        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify ST (store immediate to memory) instruction
    /// 验证 ST（存储立即数到内存）指令
    fn verify_st(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let dst_reg = insn.dst_reg as usize;
        let size = insn_access_size(insn);

        // Check destination register is valid pointer
        // 检查目标寄存器是否为有效指针
        let dst = self
            .state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check memory access
        // 检查内存访问
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true, // write / 写入
            self.allow_ptr_leaks,
        )?;

        // Update stack slots if writing to stack
        // 如果写入栈，则更新栈槽
        if dst.reg_type == BpfRegType::PtrToStack {
            let mut imm_reg = BpfRegState::new_scalar_unknown(false);
            imm_reg.mark_known(insn.imm as u64);
            self.update_stack_on_store(&dst, insn.off as i32, size, &imm_reg)?;
        }

        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify LD instruction (mostly LD_IMM64)
    /// 验证 LD 指令（主要是 LD_IMM64）
    fn verify_ld(
        &mut self,
        insn: &BpfInsn,
        next_insn: Option<&BpfInsn>,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        let mode = insn.mode();

        if mode == BPF_IMM {
            // LD_IMM64 - two instruction encoding
            // LD_IMM64 - 两条指令编码
            let next = next_insn.ok_or(VerifierError::InvalidInstruction(insn_idx))?;

            // Verify the second instruction is properly formed
            // 验证第二条指令格式正确
            if next.code != 0 || next.dst_reg != 0 || next.src_reg != 0 || next.off != 0 {
                // Check for special pseudo instructions
                // 检查特殊伪指令
                if insn.src_reg != 0 {
                    // This is a map/btf load, handle specially
                    // 这是映射表/btf 加载，特殊处理
                    return self.verify_ld_imm64_special(insn, next, insn_idx);
                }
            }

            check_ld_imm64(self.state, insn, next)?;
            Ok(InsnVerifyResult::skip_one(insn_idx))
        } else if mode == BPF_ABS || mode == BPF_IND {
            // Legacy packet access (deprecated but still used)
            // 传统数据包访问（已弃用但仍在使用）
            self.verify_ld_abs_ind(insn, mode, insn_idx)
        } else {
            Err(VerifierError::InvalidInstruction(insn_idx))
        }
    }

    /// Verify LD_IMM64 with special src_reg values (map, BTF, etc.)
    /// 验证带有特殊 src_reg 值的 LD_IMM64（映射表、BTF 等）
    fn verify_ld_imm64_special(
        &mut self,
        insn: &BpfInsn,
        next: &BpfInsn,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg;

        match src_reg {
            BPF_PSEUDO_MAP_FD => {
                // Load map pointer
                // 加载映射表指针
                if let Some(dst) = self.state.reg_mut(dst_reg) {
                    dst.reg_type = BpfRegType::ConstPtrToMap;
                    dst.mark_known_zero();
                    // map_ptr would be set from actual map info lookup
                    // map_ptr 将从实际的映射表信息查找中设置
                }
            }
            BPF_PSEUDO_MAP_VALUE => {
                // Load map value pointer
                // 加载映射表值指针
                let _off = (next.imm as u32 as u64) | ((insn.imm as u32 as u64) << 32);
                if let Some(dst) = self.state.reg_mut(dst_reg) {
                    dst.reg_type = BpfRegType::PtrToMapValue;
                    dst.mark_known_zero();
                }
            }
            _ => {
                // Unknown pseudo type - treat as scalar
                // 未知伪类型 - 视为标量
                let imm = (insn.imm as u32 as u64) | ((next.imm as u32 as u64) << 32);
                if let Some(dst) = self.state.reg_mut(dst_reg) {
                    dst.reg_type = BpfRegType::ScalarValue;
                    dst.mark_known(imm);
                }
            }
        }

        Ok(InsnVerifyResult::skip_one(insn_idx))
    }

    /// Verify legacy LD_ABS/LD_IND packet access
    /// 验证传统 LD_ABS/LD_IND 数据包访问
    fn verify_ld_abs_ind(
        &mut self,
        insn: &BpfInsn,
        mode: u8,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        // These are only valid in certain program types
        // 这些仅在某些程序类型中有效
        if !matches!(
            self.prog_type,
            BpfProgType::SocketFilter | BpfProgType::SchedCls | BpfProgType::SchedAct
        ) {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }

        if mode == BPF_IND {
            // Check source register for indirect access
            // 检查间接访问的源寄存器
            let src_reg = insn.src_reg as usize;
            let src = self
                .state
                .reg(src_reg)
                .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

            if src.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }
        }

        // Result goes to R0
        // 结果放入 R0
        if let Some(r0) = self.state.reg_mut(BPF_REG_0) {
            r0.reg_type = BpfRegType::ScalarValue;
            r0.mark_unknown(false);
        }

        // Clobbers R1-R5
        // 破坏 R1-R5
        for regno in 1..=5 {
            if let Some(reg) = self.state.reg_mut(regno) {
                reg.mark_not_init(false);
            }
        }

        Ok(InsnVerifyResult {
            modified_reg: Some(BPF_REG_0),
            ..InsnVerifyResult::sequential(insn_idx)
        })
    }

    /// Verify JMP instruction
    /// 验证 JMP 指令
    fn verify_jmp(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let op = insn.code & 0xf0;

        match op {
            BPF_CALL => self.verify_call(insn, insn_idx),
            BPF_EXIT => {
                check_exit(self.state)?;
                Ok(InsnVerifyResult::terminate())
            }
            BPF_JA => {
                // Unconditional jump
                // 无条件跳转
                let target = (insn_idx as i64 + insn.off as i64 + 1) as usize;
                Ok(InsnVerifyResult::jump(target))
            }
            _ => {
                // Conditional jump
                // 条件跳转
                let (next, branch) =
                    check_cond_jmp_op(self.state, insn, insn_idx, self.allow_ptr_leaks)?;

                match (next, branch) {
                    (Some(n), Some(b)) => Ok(InsnVerifyResult::conditional(n, b)),
                    (Some(n), None) => Ok(InsnVerifyResult::sequential(n.saturating_sub(1))),
                    (None, Some(b)) => Ok(InsnVerifyResult::jump(b)),
                    (None, None) => Err(VerifierError::Internal(
                        "conditional jump with no targets".into(),
                    )),
                }
            }
        }
    }

    /// Verify CALL instruction
    /// 验证 CALL 指令
    fn verify_call(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        check_call(self.state, insn, insn_idx)?;

        // Check for tail call
        // 检查尾调用
        if insn.is_helper_call() && insn.imm == BpfFuncId::TailCall as i32 {
            // Tail call may not return
            // 尾调用可能不返回
            return Ok(InsnVerifyResult {
                next_insn: Some(insn_idx + 1),
                branch_target: None,
                terminates: false, // May fall through if tail call fails / 如果尾调用失败可能直落
                skip_next: false,
                modified_reg: Some(BPF_REG_0),
            });
        }

        Ok(InsnVerifyResult {
            modified_reg: Some(BPF_REG_0),
            ..InsnVerifyResult::sequential(insn_idx)
        })
    }

    /// Verify atomic instruction
    /// 验证原子指令
    fn verify_atomic(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let size = insn_access_size(insn);
        let atomic_op = insn.imm as u32;

        // Check destination register is valid pointer
        // 检查目标寄存器是否为有效指针
        let dst = self
            .state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
            .clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Atomics only work on certain memory types
        // 原子操作仅适用于某些内存类型
        if !matches!(
            dst.reg_type,
            BpfRegType::PtrToStack | BpfRegType::PtrToMapValue | BpfRegType::PtrToMem
        ) {
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "atomic operation on invalid memory type: {:?}",
                dst.reg_type
            )));
        }

        // Check source register
        // 检查源寄存器
        let src = self
            .state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Source must be scalar
        // 源必须是标量
        if src.reg_type != BpfRegType::ScalarValue {
            return Err(VerifierError::TypeMismatch {
                expected: "scalar".into(),
                got: format!("{:?}", src.reg_type),
            });
        }

        // Check memory access
        // 检查内存访问
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true,
            self.allow_ptr_leaks,
        )?;

        // Handle result for fetch operations
        // 处理获取操作的结果
        let mut result = InsnVerifyResult::sequential(insn_idx);

        if atomic_op == BPF_CMPXCHG {
            // CMPXCHG writes old value to R0
            // CMPXCHG 将旧值写入 R0
            if let Some(r0) = self.state.reg_mut(BPF_REG_0) {
                r0.reg_type = BpfRegType::ScalarValue;
                r0.mark_unknown(false);
            }
            result.modified_reg = Some(BPF_REG_0);
        } else if atomic_op & BPF_FETCH != 0 {
            // Fetch operations write old value to src_reg
            // 获取操作将旧值写入 src_reg
            if let Some(reg) = self.state.reg_mut(src_reg) {
                reg.reg_type = BpfRegType::ScalarValue;
                reg.mark_unknown(false);
            }
            result.modified_reg = Some(src_reg);
        }

        Ok(result)
    }

    /// Set load result based on memory type
    /// 根据内存类型设置加载结果
    fn set_load_result(
        &mut self,
        dst_reg: usize,
        _src: &BpfRegState,
        _off: i32,
        size: u32,
        result_type: BpfRegType,
    ) -> Result<()> {
        let dst = self
            .state
            .reg_mut(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

        match result_type {
            BpfRegType::ScalarValue => {
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
                // 32-bit loads zero-extend
                // 32 位加载零扩展
                if size < 8 {
                    dst.umax_value = (1u64 << (size * 8)) - 1;
                    dst.smax_value = dst.umax_value as i64;
                    dst.smin_value = 0;
                }
            }
            BpfRegType::PtrToMapValue => {
                // Loading from map value could be a pointer
                // 从映射表值加载可能是指针
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
            }
            _ => {
                // For other types, result is scalar
                // 对于其他类型，结果是标量
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
            }
        }

        Ok(())
    }

    /// Check if storing a pointer to memory is allowed
    /// 检查是否允许将指针存储到内存
    fn check_pointer_store(&self, dst: &BpfRegState, _src: &BpfRegState) -> Result<()> {
        // Stack is always OK for pointer stores
        // 栈始终允许指针存储
        if dst.reg_type == BpfRegType::PtrToStack {
            return Ok(());
        }

        // Map values can store pointers if they have kptr fields
        // 如果映射表值有 kptr 字段，则可以存储指针
        if dst.reg_type == BpfRegType::PtrToMapValue {
            // Would check map BTF here for kptr fields
            // 这里将检查映射表 BTF 的 kptr 字段
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot store pointer to map value without kptr".into(),
            ));
        }

        Err(VerifierError::InvalidPointerArithmetic(
            "pointer stores not allowed to this memory type".into(),
        ))
    }

    /// Update stack slots after a store
    /// 存储后更新栈槽
    fn update_stack_on_store(
        &mut self,
        dst: &BpfRegState,
        off: i32,
        _size: u32,
        _src: &BpfRegState,
    ) -> Result<()> {
        let stack_off = -(dst.off + off);

        if stack_off <= 0 {
            return Err(VerifierError::StackOutOfBounds(dst.off + off));
        }

        // Ensure stack is allocated to this depth
        // 确保栈已分配到此深度
        let func = self
            .state
            .cur_func_mut()
            .ok_or(VerifierError::Internal("no current function".into()))?;

        if stack_off as usize > func.stack.allocated_stack {
            func.stack.grow(stack_off as usize)?;
        }

        // Stack slot updates would happen here via the StackManager API
        // 栈槽更新将通过 StackManager API 在这里进行
        // For now, we just ensure the stack is allocated
        // 目前，我们只确保栈已分配

        Ok(())
    }
}

/// Get access size from instruction
/// 从指令获取访问大小
pub fn insn_access_size(insn: &BpfInsn) -> u32 {
    match insn.size() {
        0 => 4, // BPF_W (32-bit) / BPF_W（32 位）
        1 => 2, // BPF_H (16-bit) / BPF_H（16 位）
        2 => 1, // BPF_B (8-bit) / BPF_B（8 位）
        3 => 8, // BPF_DW (64-bit) / BPF_DW（64 位）
        _ => 0,
    }
}

/// Verify a full program
/// 验证完整程序
pub fn verify_program(
    insns: &[BpfInsn],
    prog_type: BpfProgType,
    allow_ptr_leaks: bool,
) -> Result<()> {
    if insns.is_empty() {
        return Err(VerifierError::InvalidInstruction(0));
    }

    let mut state = BpfVerifierState::new();

    // Initialize R1 as context pointer
    // 将 R1 初始化为上下文指针
    if let Some(r1) = state.reg_mut(1) {
        r1.reg_type = BpfRegType::PtrToCtx;
        r1.mark_known_zero();
    }

    // Initialize R10 as frame pointer (stack base)
    // 将 R10 初始化为帧指针（栈基址）
    if let Some(r10) = state.reg_mut(10) {
        r10.reg_type = BpfRegType::PtrToStack;
        r10.off = 0;
        r10.mark_known_zero();
    }

    let mut verifier = InsnVerifier::new(&mut state, prog_type, allow_ptr_leaks);
    let mut insn_idx = 0;

    while insn_idx < insns.len() {
        let insn = &insns[insn_idx];
        let next_insn = insns.get(insn_idx + 1);

        let result = verifier.verify_insn(insn, next_insn, insn_idx)?;

        if result.terminates {
            // Check if we've verified all reachable code
            // 检查是否已验证所有可达代码
            break;
        }

        if result.skip_next {
            insn_idx += 2;
        } else if let Some(next) = result.next_insn {
            insn_idx = next;
        } else if let Some(target) = result.branch_target {
            insn_idx = target;
        } else {
            break;
        }
    }

    Ok(())
}
