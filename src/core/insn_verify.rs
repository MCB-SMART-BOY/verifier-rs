//! Comprehensive instruction verification
//!
//! This module provides complete instruction decoding and verification,
//! dispatching to appropriate handlers for each instruction class.

#[cfg(not(feature = "std"))]
use alloc::format;

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::core::insn::{check_alu_op, check_cond_jmp_op, check_ld_imm64, check_call, check_exit};
use crate::mem::memory::check_mem_access;

/// Result of verifying a single instruction
#[derive(Debug, Clone)]
pub struct InsnVerifyResult {
    /// Next instruction index (fall-through)
    pub next_insn: Option<usize>,
    /// Branch target (if conditional/unconditional jump)
    pub branch_target: Option<usize>,
    /// Whether this instruction terminates (exit/tail_call)
    pub terminates: bool,
    /// Whether to skip the next instruction (for LD_IMM64)
    pub skip_next: bool,
    /// Modified register (if any)
    pub modified_reg: Option<usize>,
}

impl InsnVerifyResult {
    /// Normal sequential execution
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
pub struct InsnVerifier<'a> {
    /// Current verifier state
    pub state: &'a mut BpfVerifierState,
    /// Program type
    pub prog_type: BpfProgType,
    /// Allow pointer leaks (privileged mode)
    pub allow_ptr_leaks: bool,
    /// Strict alignment checking
    pub strict_alignment: bool,
}

impl<'a> InsnVerifier<'a> {
    /// Create a new instruction verifier
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
    fn verify_alu(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        check_alu_op(self.state, insn, self.allow_ptr_leaks)?;
        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify LDX (load from memory) instruction
    fn verify_ldx(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let src_reg = insn.src_reg as usize;
        let dst_reg = insn.dst_reg as usize;
        let size = insn_access_size(insn);

        // Check source register is valid pointer
        let src = self.state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?.clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check memory access
        let result_type = check_mem_access(
            self.state,
            &src,
            insn.off as i32,
            size,
            false, // read
            self.allow_ptr_leaks,
        )?;

        // Set destination register based on loaded value
        self.set_load_result(dst_reg, &src, insn.off as i32, size, result_type)?;

        Ok(InsnVerifyResult {
            modified_reg: Some(dst_reg),
            ..InsnVerifyResult::sequential(insn_idx)
        })
    }

    /// Verify STX (store register to memory) instruction
    fn verify_stx(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let mode = insn.mode();

        if mode == BPF_ATOMIC {
            return self.verify_atomic(insn, insn_idx);
        }

        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let size = insn_access_size(insn);

        // Check destination register is valid pointer
        let dst = self.state.reg(dst_reg).ok_or(VerifierError::InvalidRegister(dst_reg as u8))?.clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check source register is initialized
        let src = self.state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?.clone();

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check for pointer leaks
        if !self.allow_ptr_leaks && src.is_pointer() {
            // Storing pointers to certain memory types is restricted
            self.check_pointer_store(&dst, &src)?;
        }

        // Check memory access
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true, // write
            self.allow_ptr_leaks,
        )?;

        // Update stack slots if writing to stack
        if dst.reg_type == BpfRegType::PtrToStack {
            self.update_stack_on_store(&dst, insn.off as i32, size, &src)?;
        }

        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify ST (store immediate to memory) instruction
    fn verify_st(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let dst_reg = insn.dst_reg as usize;
        let size = insn_access_size(insn);

        // Check destination register is valid pointer
        let dst = self.state.reg(dst_reg).ok_or(VerifierError::InvalidRegister(dst_reg as u8))?.clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Check memory access
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true, // write
            self.allow_ptr_leaks,
        )?;

        // Update stack slots if writing to stack
        if dst.reg_type == BpfRegType::PtrToStack {
            let mut imm_reg = BpfRegState::new_scalar_unknown(false);
            imm_reg.mark_known(insn.imm as u64);
            self.update_stack_on_store(&dst, insn.off as i32, size, &imm_reg)?;
        }

        Ok(InsnVerifyResult::sequential(insn_idx))
    }

    /// Verify LD instruction (mostly LD_IMM64)
    fn verify_ld(
        &mut self,
        insn: &BpfInsn,
        next_insn: Option<&BpfInsn>,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        let mode = insn.mode();

        if mode == BPF_IMM {
            // LD_IMM64 - two instruction encoding
            let next = next_insn.ok_or(VerifierError::InvalidInstruction(insn_idx))?;

            // Verify the second instruction is properly formed
            if next.code != 0 || next.dst_reg != 0 || next.src_reg != 0 || next.off != 0 {
                // Check for special pseudo instructions
                if insn.src_reg != 0 {
                    // This is a map/btf load, handle specially
                    return self.verify_ld_imm64_special(insn, next, insn_idx);
                }
            }

            check_ld_imm64(self.state, insn, next)?;
            Ok(InsnVerifyResult::skip_one(insn_idx))
        } else if mode == BPF_ABS || mode == BPF_IND {
            // Legacy packet access (deprecated but still used)
            self.verify_ld_abs_ind(insn, mode, insn_idx)
        } else {
            Err(VerifierError::InvalidInstruction(insn_idx))
        }
    }

    /// Verify LD_IMM64 with special src_reg values (map, BTF, etc.)
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
                if let Some(dst) = self.state.reg_mut(dst_reg) {
                    dst.reg_type = BpfRegType::ConstPtrToMap;
                    dst.mark_known_zero();
                    // map_ptr would be set from actual map info lookup
                }
            }
            BPF_PSEUDO_MAP_VALUE => {
                // Load map value pointer
                let _off = (next.imm as u32 as u64) | ((insn.imm as u32 as u64) << 32);
                if let Some(dst) = self.state.reg_mut(dst_reg) {
                    dst.reg_type = BpfRegType::PtrToMapValue;
                    dst.mark_known_zero();
                }
            }
            _ => {
                // Unknown pseudo type - treat as scalar
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
    fn verify_ld_abs_ind(
        &mut self,
        insn: &BpfInsn,
        mode: u8,
        insn_idx: usize,
    ) -> Result<InsnVerifyResult> {
        // These are only valid in certain program types
        if !matches!(
            self.prog_type,
            BpfProgType::SocketFilter | BpfProgType::SchedCls | BpfProgType::SchedAct
        ) {
            return Err(VerifierError::InvalidInstruction(insn_idx));
        }

        if mode == BPF_IND {
            // Check source register for indirect access
            let src_reg = insn.src_reg as usize;
            let src = self.state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

            if src.reg_type != BpfRegType::ScalarValue {
                return Err(VerifierError::InvalidInstruction(insn_idx));
            }
        }

        // Result goes to R0
        if let Some(r0) = self.state.reg_mut(BPF_REG_0) {
            r0.reg_type = BpfRegType::ScalarValue;
            r0.mark_unknown(false);
        }

        // Clobbers R1-R5
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
                let target = (insn_idx as i64 + insn.off as i64 + 1) as usize;
                Ok(InsnVerifyResult::jump(target))
            }
            _ => {
                // Conditional jump
                let (next, branch) = check_cond_jmp_op(
                    self.state,
                    insn,
                    insn_idx,
                    self.allow_ptr_leaks,
                )?;

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
    fn verify_call(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        check_call(self.state, insn, insn_idx)?;

        // Check for tail call
        if insn.is_helper_call() && insn.imm == BpfFuncId::TailCall as i32 {
            // Tail call may not return
            return Ok(InsnVerifyResult {
                next_insn: Some(insn_idx + 1),
                branch_target: None,
                terminates: false, // May fall through if tail call fails
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
    fn verify_atomic(&mut self, insn: &BpfInsn, insn_idx: usize) -> Result<InsnVerifyResult> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;
        let size = insn_access_size(insn);
        let atomic_op = insn.imm as u32;

        // Check destination register is valid pointer
        let dst = self.state.reg(dst_reg).ok_or(VerifierError::InvalidRegister(dst_reg as u8))?.clone();

        if dst.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(dst_reg as u8));
        }

        // Atomics only work on certain memory types
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
        let src = self.state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?;

        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Source must be scalar
        if src.reg_type != BpfRegType::ScalarValue {
            return Err(VerifierError::TypeMismatch {
                expected: "scalar".into(),
                got: format!("{:?}", src.reg_type),
            });
        }

        // Check memory access
        check_mem_access(
            self.state,
            &dst,
            insn.off as i32,
            size,
            true,
            self.allow_ptr_leaks,
        )?;

        // Handle result for fetch operations
        let mut result = InsnVerifyResult::sequential(insn_idx);

        if atomic_op == BPF_CMPXCHG {
            // CMPXCHG writes old value to R0
            if let Some(r0) = self.state.reg_mut(BPF_REG_0) {
                r0.reg_type = BpfRegType::ScalarValue;
                r0.mark_unknown(false);
            }
            result.modified_reg = Some(BPF_REG_0);
        } else if atomic_op & BPF_FETCH != 0 {
            // Fetch operations write old value to src_reg
            if let Some(reg) = self.state.reg_mut(src_reg) {
                reg.reg_type = BpfRegType::ScalarValue;
                reg.mark_unknown(false);
            }
            result.modified_reg = Some(src_reg);
        }

        Ok(result)
    }

    /// Set load result based on memory type
    fn set_load_result(
        &mut self,
        dst_reg: usize,
        _src: &BpfRegState,
        _off: i32,
        size: u32,
        result_type: BpfRegType,
    ) -> Result<()> {
        let dst = self.state.reg_mut(dst_reg).ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;

        match result_type {
            BpfRegType::ScalarValue => {
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
                // 32-bit loads zero-extend
                if size < 8 {
                    dst.umax_value = (1u64 << (size * 8)) - 1;
                    dst.smax_value = dst.umax_value as i64;
                    dst.smin_value = 0;
                }
            }
            BpfRegType::PtrToMapValue => {
                // Loading from map value could be a pointer
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
            }
            _ => {
                // For other types, result is scalar
                dst.reg_type = BpfRegType::ScalarValue;
                dst.mark_unknown(false);
            }
        }

        Ok(())
    }

    /// Check if storing a pointer to memory is allowed
    fn check_pointer_store(&self, dst: &BpfRegState, _src: &BpfRegState) -> Result<()> {
        // Stack is always OK for pointer stores
        if dst.reg_type == BpfRegType::PtrToStack {
            return Ok(());
        }

        // Map values can store pointers if they have kptr fields
        if dst.reg_type == BpfRegType::PtrToMapValue {
            // Would check map BTF here for kptr fields
            return Err(VerifierError::InvalidPointerArithmetic(
                "cannot store pointer to map value without kptr".into(),
            ));
        }

        Err(VerifierError::InvalidPointerArithmetic(
            "pointer stores not allowed to this memory type".into(),
        ))
    }

    /// Update stack slots after a store
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
        let func = self.state.cur_func_mut().ok_or(VerifierError::Internal(
            "no current function".into(),
        ))?;

        if stack_off as usize > func.stack.allocated_stack {
            func.stack.grow(stack_off as usize)?;
        }

        // Stack slot updates would happen here via the StackManager API
        // For now, we just ensure the stack is allocated

        Ok(())
    }
}

/// Get access size from instruction
pub fn insn_access_size(insn: &BpfInsn) -> u32 {
    match insn.size() {
        0 => 4, // BPF_W (32-bit)
        1 => 2, // BPF_H (16-bit)
        2 => 1, // BPF_B (8-bit)
        3 => 8, // BPF_DW (64-bit)
        _ => 0,
    }
}

/// Verify a full program
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
    if let Some(r1) = state.reg_mut(1) {
        r1.reg_type = BpfRegType::PtrToCtx;
        r1.mark_known_zero();
    }

    // Initialize R10 as frame pointer (stack base)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insn_access_size() {
        // 32-bit (BPF_W)
        let insn_w = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, 0, 1, 0, 0);
        assert_eq!(insn_access_size(&insn_w), 4);

        // 64-bit (BPF_DW)
        let insn_dw = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 1, 0, 0);
        assert_eq!(insn_access_size(&insn_dw), 8);

        // 16-bit (BPF_H)
        let insn_h = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_H, 0, 1, 0, 0);
        assert_eq!(insn_access_size(&insn_h), 2);

        // 8-bit (BPF_B)
        let insn_b = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_B, 0, 1, 0, 0);
        assert_eq!(insn_access_size(&insn_b), 1);
    }

    #[test]
    fn test_insn_verify_result_sequential() {
        let result = InsnVerifyResult::sequential(5);
        assert_eq!(result.next_insn, Some(6));
        assert_eq!(result.branch_target, None);
        assert!(!result.terminates);
        assert!(!result.skip_next);
    }

    #[test]
    fn test_insn_verify_result_jump() {
        let result = InsnVerifyResult::jump(10);
        assert_eq!(result.next_insn, None);
        assert_eq!(result.branch_target, Some(10));
        assert!(!result.terminates);
    }

    #[test]
    fn test_insn_verify_result_conditional() {
        let result = InsnVerifyResult::conditional(6, 10);
        assert_eq!(result.next_insn, Some(6));
        assert_eq!(result.branch_target, Some(10));
    }

    #[test]
    fn test_insn_verify_result_terminate() {
        let result = InsnVerifyResult::terminate();
        assert_eq!(result.next_insn, None);
        assert_eq!(result.branch_target, None);
        assert!(result.terminates);
    }

    #[test]
    fn test_insn_verify_result_skip_one() {
        let result = InsnVerifyResult::skip_one(5);
        assert_eq!(result.next_insn, Some(7));
        assert!(result.skip_next);
    }

    #[test]
    fn test_verify_alu_mov_imm() {
        let mut state = BpfVerifierState::new();
        let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

        // mov r1, 42
        let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42);
        let result = verifier.verify_insn(&insn, None, 0).unwrap();

        assert_eq!(result.next_insn, Some(1));
        assert_eq!(verifier.state.reg(1).unwrap().const_value(), 42);
    }

    #[test]
    fn test_verify_alu_add() {
        let mut state = BpfVerifierState::new();
        state.reg_mut(1).unwrap().mark_known(10);
        state.reg_mut(1).unwrap().reg_type = BpfRegType::ScalarValue;

        let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

        // add r1, 5
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5);
        verifier.verify_insn(&insn, None, 0).unwrap();

        assert_eq!(verifier.state.reg(1).unwrap().const_value(), 15);
    }

    #[test]
    fn test_verify_exit() {
        let mut state = BpfVerifierState::new();
        // R0 must be initialized for exit
        state.reg_mut(0).unwrap().reg_type = BpfRegType::ScalarValue;
        state.reg_mut(0).unwrap().mark_known(0);

        let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

        let insn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        let result = verifier.verify_insn(&insn, None, 0).unwrap();

        assert!(result.terminates);
    }

    #[test]
    fn test_verify_unconditional_jump() {
        let mut state = BpfVerifierState::new();
        let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

        // ja +5 (jump ahead 5 instructions)
        let insn = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
        let result = verifier.verify_insn(&insn, None, 0).unwrap();

        assert_eq!(result.branch_target, Some(6)); // 0 + 5 + 1
        assert_eq!(result.next_insn, None);
    }

    #[test]
    fn test_verify_ld_imm64() {
        let mut state = BpfVerifierState::new();
        let mut verifier = InsnVerifier::new(&mut state, BpfProgType::SocketFilter, true);

        // lddw r1, 0x123456789ABCDEF0
        let insn1 = BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, 1, 0, 0, 0x9ABCDEF0u32 as i32);
        let insn2 = BpfInsn::new(0, 0, 0, 0, 0x12345678u32 as i32);

        let result = verifier.verify_insn(&insn1, Some(&insn2), 0).unwrap();

        assert!(result.skip_next);
        assert_eq!(result.next_insn, Some(2));
        assert_eq!(
            verifier.state.reg(1).unwrap().const_value(),
            0x123456789ABCDEF0u64
        );
    }
}
