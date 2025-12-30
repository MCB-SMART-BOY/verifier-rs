// SPDX-License-Identifier: GPL-2.0

//! 原子指令处理模块
//!
//! Atomic instruction handling module.
//!
//! 本模块实现了 BPF 原子操作的验证，包括原子加法、交换、比较交换和获取操作。
//!
//! This module implements verification for BPF atomic operations,
//! including atomic add, exchange, compare-exchange, and fetch operations.
//!
//! # 原子操作类型 / Atomic Operation Types
//!
//! - `ATOMIC_ADD`: 原子加法 / Atomic add
//! - `ATOMIC_OR/AND/XOR`: 原子位运算 / Atomic bitwise operations
//! - `ATOMIC_XCHG`: 原子交换 / Atomic exchange
//! - `ATOMIC_CMPXCHG`: 原子比较交换 / Atomic compare-exchange
//! - `LOAD_ACQ`: 带获取语义的加载 / Load with acquire semantics
//! - `STORE_REL`: 带释放语义的存储 / Store with release semantics

#![allow(missing_docs)] // Atomic operation constants

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::mem::memory::check_mem_access;
use crate::state::verifier_state::BpfVerifierState;

/// Atomic operation codes (encoded in imm field)
pub const BPF_ATOMIC_ADD: u32 = BPF_ADD as u32;
pub const BPF_ATOMIC_OR: u32 = BPF_OR as u32;
pub const BPF_ATOMIC_AND: u32 = BPF_AND as u32;
pub const BPF_ATOMIC_XOR: u32 = BPF_XOR as u32;
pub const BPF_ATOMIC_XCHG: u32 = 0xe0 | BPF_FETCH;
pub const BPF_ATOMIC_CMPXCHG: u32 = 0xf0 | BPF_FETCH;

/// Check if instruction is an atomic RMW operation
pub fn is_atomic_rmw(insn: &BpfInsn) -> bool {
    let class = insn.class();
    if class != BPF_STX {
        return false;
    }
    (insn.code & 0xe0) == BPF_ATOMIC
}

/// Check if instruction is atomic load
pub fn is_atomic_load(insn: &BpfInsn) -> bool {
    let class = insn.class();
    if class != BPF_LDX {
        return false;
    }
    // Atomic load has special encoding
    (insn.code & 0xe0) == BPF_ATOMIC && (insn.imm as u32 & BPF_FETCH) != 0
}

/// Check if instruction is load-acquire (BPF_LOAD_ACQ)
pub fn is_load_acquire(insn: &BpfInsn) -> bool {
    insn.code == (BPF_LDX | BPF_ATOMIC) && insn.imm == BPF_LOAD_ACQ as i32
}

/// Check if instruction is atomic store
pub fn is_atomic_store(insn: &BpfInsn) -> bool {
    let class = insn.class();
    if class != BPF_STX {
        return false;
    }
    // Atomic store has ATOMIC mode but no FETCH flag
    (insn.code & 0xe0) == BPF_ATOMIC && (insn.imm as u32 & BPF_FETCH) == 0
}

/// Check if instruction is store-release (BPF_STORE_REL)
pub fn is_store_release(insn: &BpfInsn) -> bool {
    insn.code == (BPF_STX | BPF_ATOMIC) && insn.imm == BPF_STORE_REL as i32
}

/// Check if this is a compare-and-exchange instruction
pub fn is_cmpxchg(insn: &BpfInsn) -> bool {
    is_atomic_rmw(insn) && (insn.imm as u32) == BPF_ATOMIC_CMPXCHG
}

/// Check if this is an exchange instruction
pub fn is_xchg(insn: &BpfInsn) -> bool {
    is_atomic_rmw(insn) && (insn.imm as u32) == BPF_ATOMIC_XCHG
}

/// Check if atomic operation has fetch semantics
pub fn has_fetch(insn: &BpfInsn) -> bool {
    (insn.imm as u32 & BPF_FETCH) != 0
}

/// Get the size of an atomic operation in bytes
pub fn atomic_size(insn: &BpfInsn) -> u32 {
    match insn.code & 0x18 {
        x if x == BPF_W => 4,
        x if x == BPF_DW => 8,
        _ => 0, // Invalid
    }
}

/// Check an atomic RMW instruction
pub fn check_atomic_rmw(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let size = atomic_size(insn);

    if size == 0 {
        return Err(VerifierError::InvalidInsnSize(insn_idx));
    }

    // Validate atomic operation code
    let atomic_op = insn.imm as u32 & !BPF_FETCH;
    match atomic_op {
        x if x == BPF_ADD as u32 => {}
        x if x == BPF_OR as u32 => {}
        x if x == BPF_AND as u32 => {}
        x if x == BPF_XOR as u32 => {}
        0xe0 => {} // XCHG
        0xf0 => {} // CMPXCHG
        _ => {
            return Err(VerifierError::InvalidAtomicOp(atomic_op));
        }
    }

    // Check source register is initialized
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
    if src.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(src_reg as u8));
    }

    // Check destination register (pointer)
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
        .clone();

    // Destination must be a pointer
    if !dst.is_pointer() {
        return Err(VerifierError::ExpectedPointer(dst_reg as u8));
    }

    // Check memory access
    check_mem_access(state, &dst, insn.off as i32, size, true, false)?;

    // For CMPXCHG, R0 is also used (compare value)
    if is_cmpxchg(insn) {
        let r0 = state
            .reg(BPF_REG_0)
            .ok_or(VerifierError::InvalidRegister(0))?;
        if r0.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(0));
        }
    }

    // Handle fetch semantics - result goes to src_reg
    if has_fetch(insn) {
        if let Some(reg) = state.reg_mut(src_reg) {
            // The fetched value is unknown scalar
            reg.mark_unknown(size == 4);
        }
    }

    // For CMPXCHG, the old value goes to R0
    if is_cmpxchg(insn) {
        if let Some(r0) = state.reg_mut(BPF_REG_0) {
            r0.mark_unknown(size == 4);
        }
    }

    Ok(())
}

/// Check an atomic load instruction
pub fn check_atomic_load(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let size = atomic_size(insn);

    if size == 0 {
        return Err(VerifierError::InvalidInsnSize(insn_idx));
    }

    // Check source register (pointer)
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
        .clone();

    if !src.is_pointer() {
        return Err(VerifierError::ExpectedPointer(src_reg as u8));
    }

    // Check memory access (read)
    check_mem_access(state, &src, insn.off as i32, size, false, false)?;

    // Set destination to unknown scalar
    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.mark_unknown(size == 4);
    }

    Ok(())
}

/// Check an atomic store instruction
pub fn check_atomic_store(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;
    let size = atomic_size(insn);

    if size == 0 {
        return Err(VerifierError::InvalidInsnSize(insn_idx));
    }

    // Check source register is initialized
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
    if src.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(src_reg as u8));
    }

    // Check destination register (pointer)
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
        .clone();

    if !dst.is_pointer() {
        return Err(VerifierError::ExpectedPointer(dst_reg as u8));
    }

    // Check memory access (write)
    check_mem_access(state, &dst, insn.off as i32, size, true, false)?;

    Ok(())
}

/// Check a load-acquire instruction
pub fn check_load_acquire(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Get size from instruction code
    let size = match insn.code & 0x18 {
        x if x == BPF_W => 4,
        x if x == BPF_DW => 8,
        _ => return Err(VerifierError::InvalidInsnSize(insn_idx)),
    };

    // Check source register (pointer to memory)
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?
        .clone();

    if !src.is_pointer() {
        return Err(VerifierError::ExpectedPointer(src_reg as u8));
    }

    // Verify pointer type supports atomic operations
    if !atomic_ptr_type_ok(src.reg_type, size) {
        return Err(VerifierError::InvalidMemoryAccess(
            "load-acquire not supported for this pointer type".into(),
        ));
    }

    // Check memory access (read with acquire semantics)
    check_mem_access(state, &src, insn.off as i32, size, false, false)?;

    // Set destination register to unknown scalar (loaded value)
    if let Some(dst) = state.reg_mut(dst_reg) {
        dst.mark_unknown(size == 4);
    }

    Ok(())
}

/// Check a store-release instruction
pub fn check_store_release(
    state: &mut BpfVerifierState,
    insn: &BpfInsn,
    insn_idx: usize,
) -> Result<()> {
    let dst_reg = insn.dst_reg as usize;
    let src_reg = insn.src_reg as usize;

    // Get size from instruction code
    let size = match insn.code & 0x18 {
        x if x == BPF_W => 4,
        x if x == BPF_DW => 8,
        _ => return Err(VerifierError::InvalidInsnSize(insn_idx)),
    };

    // Check source register is initialized (value to store)
    let src = state
        .reg(src_reg)
        .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
    if src.reg_type == BpfRegType::NotInit {
        return Err(VerifierError::UninitializedRegister(src_reg as u8));
    }

    // Check destination register (pointer to memory)
    let dst = state
        .reg(dst_reg)
        .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?
        .clone();

    if !dst.is_pointer() {
        return Err(VerifierError::ExpectedPointer(dst_reg as u8));
    }

    // Verify pointer type supports atomic operations
    if !atomic_ptr_type_ok(dst.reg_type, size) {
        return Err(VerifierError::InvalidMemoryAccess(
            "store-release not supported for this pointer type".into(),
        ));
    }

    // Check memory access (write with release semantics)
    check_mem_access(state, &dst, insn.off as i32, size, true, false)?;

    Ok(())
}

/// Check any atomic instruction
pub fn check_atomic(state: &mut BpfVerifierState, insn: &BpfInsn, insn_idx: usize) -> Result<()> {
    if is_load_acquire(insn) {
        check_load_acquire(state, insn, insn_idx)
    } else if is_store_release(insn) {
        check_store_release(state, insn, insn_idx)
    } else if is_atomic_load(insn) {
        check_atomic_load(state, insn, insn_idx)
    } else if is_atomic_store(insn) {
        check_atomic_store(state, insn, insn_idx)
    } else if is_atomic_rmw(insn) {
        check_atomic_rmw(state, insn, insn_idx)
    } else {
        Err(VerifierError::InvalidInstruction(insn_idx))
    }
}

/// Pointer types that support atomic operations
pub fn atomic_ptr_type_ok(reg_type: BpfRegType, _size: u32) -> bool {
    match reg_type {
        // Map values support atomics
        BpfRegType::PtrToMapValue => true,
        // Stack supports atomics
        BpfRegType::PtrToStack => true,
        // Arena supports atomics
        BpfRegType::PtrToArena => true,
        // Memory allocations support atomics
        BpfRegType::PtrToMem => true,
        // Packet data does not support atomics
        BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta | BpfRegType::PtrToPacketEnd => false,
        // Context access may be restricted
        BpfRegType::PtrToCtx => false,
        _ => false,
    }
}

/// Get the name of an atomic operation
pub fn atomic_op_name(imm: u32) -> &'static str {
    // Check for special acquire/release operations
    if imm == BPF_LOAD_ACQ {
        return "load_acquire";
    }
    if imm == BPF_STORE_REL {
        return "store_release";
    }

    let op = imm & !BPF_FETCH;
    let fetch = imm & BPF_FETCH != 0;

    match op {
        x if x == BPF_ADD as u32 => {
            if fetch {
                "atomic_fetch_add"
            } else {
                "atomic_add"
            }
        }
        x if x == BPF_OR as u32 => {
            if fetch {
                "atomic_fetch_or"
            } else {
                "atomic_or"
            }
        }
        x if x == BPF_AND as u32 => {
            if fetch {
                "atomic_fetch_and"
            } else {
                "atomic_and"
            }
        }
        x if x == BPF_XOR as u32 => {
            if fetch {
                "atomic_fetch_xor"
            } else {
                "atomic_xor"
            }
        }
        0xe0 => "atomic_xchg",
        0xf0 => "atomic_cmpxchg",
        _ => "atomic_unknown",
    }
}
