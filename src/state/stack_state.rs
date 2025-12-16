//! Stack state management
//!
//! This module handles BPF stack slot tracking, including spilled registers,
//! dynptrs, iterators, and IRQ flags.


use alloc::{format, vec::Vec};

use crate::state::reg_state::BpfRegState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};

/// State of a single stack slot (8 bytes)
#[derive(Debug, Clone)]
pub struct BpfStackState {
    /// Spilled register state (if this slot contains a spilled reg)
    pub spilled_ptr: BpfRegState,
    /// Type of each byte in the slot
    pub slot_type: [BpfStackSlotType; BPF_REG_SIZE],
}

impl Default for BpfStackState {
    fn default() -> Self {
        Self {
            spilled_ptr: BpfRegState::default(),
            slot_type: [BpfStackSlotType::Invalid; BPF_REG_SIZE],
        }
    }
}

impl BpfStackState {
    /// Create a new invalid stack slot
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this slot is valid (has been written)
    pub fn is_valid(&self) -> bool {
        self.slot_type.iter().any(|t| *t != BpfStackSlotType::Invalid)
    }

    /// Check if entire slot is zero
    pub fn is_zero(&self) -> bool {
        self.slot_type.iter().all(|t| *t == BpfStackSlotType::Zero)
    }

    /// Check if this slot contains a spilled register
    pub fn is_spill(&self) -> bool {
        self.slot_type[0] == BpfStackSlotType::Spill
    }

    /// Check if this slot contains a dynptr
    pub fn is_dynptr(&self) -> bool {
        self.slot_type[0] == BpfStackSlotType::Dynptr
    }

    /// Check if this slot contains an iterator
    pub fn is_iter(&self) -> bool {
        self.slot_type[0] == BpfStackSlotType::Iter
    }

    /// Check if this slot contains a special type (spill, dynptr, iter, irq)
    pub fn is_special(&self) -> bool {
        self.slot_type[0].is_special()
    }

    /// Get the type of the first byte in this slot
    pub fn get_type(&self) -> BpfStackSlotType {
        self.slot_type[0]
    }

    /// Mark slot as containing spilled register
    pub fn mark_spill(&mut self, reg: &BpfRegState) {
        self.spilled_ptr = reg.clone();
        self.slot_type[0] = BpfStackSlotType::Spill;
        for i in 1..BPF_REG_SIZE {
            self.slot_type[i] = BpfStackSlotType::Misc;
        }
    }

    /// Mark slot as containing misc data (full slot)
    pub fn mark_misc_full(&mut self) {
        for i in 0..BPF_REG_SIZE {
            self.slot_type[i] = BpfStackSlotType::Misc;
        }
    }

    /// Mark slot as containing misc data (partial)
    pub fn mark_misc(&mut self, size: usize) {
        for i in 0..size.min(BPF_REG_SIZE) {
            self.slot_type[i] = BpfStackSlotType::Misc;
        }
    }

    /// Mark slot as containing zeros (full slot)
    pub fn mark_zero_full(&mut self) {
        for i in 0..BPF_REG_SIZE {
            self.slot_type[i] = BpfStackSlotType::Zero;
        }
    }

    /// Mark slot as containing zeros (partial)
    pub fn mark_zero(&mut self, size: usize) {
        for i in 0..size.min(BPF_REG_SIZE) {
            self.slot_type[i] = BpfStackSlotType::Zero;
        }
    }

    /// Check if this slot contains a spilled register (any type)
    pub fn is_spilled_reg(&self) -> bool {
        self.is_spill()
    }

    /// Check if this is a spilled 64-bit scalar register
    pub fn is_spilled_scalar_reg64(&self) -> bool {
        self.is_spill() && self.spilled_ptr.is_scalar()
    }

    /// Check if this is a spilled scalar register
    pub fn is_spilled_scalar_reg(&self) -> bool {
        self.is_spill() && self.spilled_ptr.is_scalar()
    }

    /// Mark slot as invalid
    pub fn mark_invalid(&mut self) {
        self.spilled_ptr = BpfRegState::default();
        for i in 0..BPF_REG_SIZE {
            self.slot_type[i] = BpfStackSlotType::Invalid;
        }
    }

    /// Get the spilled register if this is a spill slot
    pub fn get_spilled_reg(&self) -> Option<&BpfRegState> {
        if self.is_spill() {
            Some(&self.spilled_ptr)
        } else {
            None
        }
    }
}

/// Type alias for stack manager (for compatibility)
pub type StackManager = StackState;

/// Get stack slot index and byte offset from stack offset
/// Returns (slot_index, byte_offset_within_slot)
pub fn get_spi(off: i32) -> Option<usize> {
    if off >= 0 || off < -(MAX_BPF_STACK as i32) {
        return None;
    }
    // off is negative: -8..-1 -> slot 0, -16..-9 -> slot 1, etc.
    Some(((-off - 1) as usize) / BPF_REG_SIZE)
}

/// Get stack slot index for a dynptr at the given register offset
pub fn dynptr_get_spi(reg: &BpfRegState, _allocated_stack: usize) -> Result<usize> {
    let off = reg.off;
    if off < -(MAX_BPF_STACK as i32) || off >= 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            format!("invalid dynptr stack offset {}", off)
        ));
    }
    let spi = ((-off - 1) as usize) / BPF_REG_SIZE;
    // Dynptr takes 2 slots
    if spi < 1 {
        return Err(VerifierError::InvalidMemoryAccess(
            "dynptr needs 2 stack slots".into()
        ));
    }
    Ok(spi)
}

/// Get stack slot index for an iterator at the given register offset
pub fn iter_get_spi(reg: &BpfRegState, nr_slots: usize, _allocated_stack: usize) -> Result<usize> {
    let off = reg.off;
    if off < -(MAX_BPF_STACK as i32) || off >= 0 {
        return Err(VerifierError::InvalidMemoryAccess(
            format!("invalid iterator stack offset {}", off)
        ));
    }
    let spi = ((-off - 1) as usize) / BPF_REG_SIZE;
    if spi + 1 < nr_slots {
        return Err(VerifierError::InvalidMemoryAccess(
            format!("iterator needs {} stack slots", nr_slots)
        ));
    }
    Ok(spi)
}

/// Full stack state for a function frame
#[derive(Debug, Clone)]
pub struct StackState {
    /// Stack slots, indexed by slot number (offset / 8)
    /// Slot 0 is at fp-8, slot 1 is at fp-16, etc.
    pub stack: Vec<BpfStackState>,
    /// Maximum allocated stack offset (positive value, in bytes)
    pub allocated_stack: usize,
}

impl Default for StackState {
    fn default() -> Self {
        Self::new()
    }
}

impl StackState {
    /// Create a new empty stack state
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            allocated_stack: 0,
        }
    }

    /// Create stack state with given size
    pub fn with_size(size: usize) -> Self {
        let num_slots = (size + BPF_REG_SIZE - 1) / BPF_REG_SIZE;
        Self {
            stack: (0..num_slots).map(|_| BpfStackState::new()).collect(),
            allocated_stack: size,
        }
    }

    /// Grow the stack to accommodate the given offset (positive value)
    pub fn grow(&mut self, size: usize) -> Result<()> {
        if size > MAX_BPF_STACK {
            return Err(VerifierError::StackOverflow(size as i32));
        }
        let num_slots = (size + BPF_REG_SIZE - 1) / BPF_REG_SIZE;
        while self.stack.len() < num_slots {
            self.stack.push(BpfStackState::new());
        }
        if size > self.allocated_stack {
            self.allocated_stack = size;
        }
        Ok(())
    }

    /// Get slot index for a stack offset (offset is negative, relative to fp)
    pub fn offset_to_slot(&self, offset: i32) -> Option<usize> {
        if offset >= 0 || offset < -(MAX_BPF_STACK as i32) {
            return None;
        }
        // offset is negative: -8 -> slot 0, -16 -> slot 1, etc.
        Some((((-offset) as usize) - 1) / BPF_REG_SIZE)
    }

    /// Get stack offset for a slot index
    pub fn slot_to_offset(&self, slot: usize) -> i32 {
        -(((slot + 1) * BPF_REG_SIZE) as i32)
    }

    /// Ensure slot exists, growing stack vector if needed
    fn ensure_slot(&mut self, slot: usize) {
        while self.stack.len() <= slot {
            self.stack.push(BpfStackState::new());
        }
    }

    /// Get a stack slot by offset
    pub fn get_slot(&self, offset: i32) -> Option<&BpfStackState> {
        let slot = self.offset_to_slot(offset)?;
        self.stack.get(slot)
    }

    /// Get a mutable stack slot by offset
    pub fn get_slot_mut(&mut self, offset: i32) -> Option<&mut BpfStackState> {
        let slot = self.offset_to_slot(offset)?;
        self.ensure_slot(slot);
        self.stack.get_mut(slot)
    }

    /// Spill a register to the stack
    pub fn spill_reg(&mut self, offset: i32, reg: &BpfRegState) -> Result<()> {
        // Must be 8-byte aligned
        if offset % BPF_REG_SIZE as i32 != 0 {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("unaligned spill at offset {}", offset)
            ));
        }

        let slot = self.offset_to_slot(offset)
            .ok_or_else(|| VerifierError::InvalidMemoryAccess(
                format!("invalid stack offset {}", offset)
            ))?;

        self.ensure_slot(slot);
        self.stack[slot].mark_spill(reg);

        // Update allocated stack
        let stack_used = (slot + 1) * BPF_REG_SIZE;
        if stack_used > self.allocated_stack {
            self.allocated_stack = stack_used;
        }

        Ok(())
    }

    /// Fill (restore) a register from the stack
    pub fn fill_reg(&self, offset: i32) -> Result<BpfRegState> {
        // Must be 8-byte aligned
        if offset % BPF_REG_SIZE as i32 != 0 {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("unaligned fill at offset {}", offset)
            ));
        }

        let slot = self.offset_to_slot(offset)
            .ok_or_else(|| VerifierError::InvalidMemoryAccess(
                format!("invalid stack offset {}", offset)
            ))?;

        if slot >= self.stack.len() {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("reading uninitialized stack at offset {}", offset)
            ));
        }

        let stack_slot = &self.stack[slot];
        if !stack_slot.is_spill() {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("fill from non-spill slot at offset {}", offset)
            ));
        }

        Ok(stack_slot.spilled_ptr.clone())
    }

    /// Write misc data to stack
    pub fn write_misc(&mut self, offset: i32, size: usize) -> Result<()> {
        let slot = self.offset_to_slot(offset)
            .ok_or_else(|| VerifierError::InvalidMemoryAccess(
                format!("invalid stack offset {}", offset)
            ))?;

        self.ensure_slot(slot);
        self.stack[slot].mark_misc(size);

        let stack_used = (slot + 1) * BPF_REG_SIZE;
        if stack_used > self.allocated_stack {
            self.allocated_stack = stack_used;
        }

        Ok(())
    }

    /// Write zeros to stack
    pub fn write_zero(&mut self, offset: i32, size: usize) -> Result<()> {
        let slot = self.offset_to_slot(offset)
            .ok_or_else(|| VerifierError::InvalidMemoryAccess(
                format!("invalid stack offset {}", offset)
            ))?;

        self.ensure_slot(slot);
        self.stack[slot].mark_zero(size);

        let stack_used = (slot + 1) * BPF_REG_SIZE;
        if stack_used > self.allocated_stack {
            self.allocated_stack = stack_used;
        }

        Ok(())
    }

    /// Check if a stack range is initialized
    pub fn is_initialized(&self, offset: i32, size: usize) -> bool {
        let Some(start_slot) = self.offset_to_slot(offset) else {
            return false;
        };
        let Some(end_slot) = self.offset_to_slot(offset - size as i32 + 1) else {
            return false;
        };

        for slot_idx in start_slot..=end_slot {
            if slot_idx >= self.stack.len() {
                return false;
            }
            if !self.stack[slot_idx].is_valid() {
                return false;
            }
        }
        true
    }

    /// Get the allocated stack size in bytes
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_stack
    }

    /// Get a stack slot by slot index (spi)
    pub fn get_slot_by_spi(&self, spi: usize) -> Option<&BpfStackState> {
        self.stack.get(spi)
    }

    /// Get a mutable stack slot by slot index (spi)
    pub fn get_slot_mut_by_spi(&mut self, spi: usize) -> Option<&mut BpfStackState> {
        if spi >= self.stack.len() {
            // Grow if needed
            while self.stack.len() <= spi {
                self.stack.push(BpfStackState::new());
            }
        }
        self.stack.get_mut(spi)
    }

    /// Mark stack slots for a dynptr
    pub fn mark_dynptr_slots(
        &mut self,
        spi: usize,
        dynptr_type: BpfDynptrType,
        dynptr_id: u32,
        ref_obj_id: u32,
    ) -> Result<()> {
        // Dynptr takes 2 slots: spi (first) and spi-1 (second)
        if spi < 1 {
            return Err(VerifierError::InvalidMemoryAccess(
                "dynptr needs 2 stack slots".into()
            ));
        }

        // Ensure slots exist
        while self.stack.len() <= spi {
            self.stack.push(BpfStackState::new());
        }

        // Mark first slot
        let slot1 = &mut self.stack[spi];
        slot1.slot_type = [BpfStackSlotType::Dynptr; BPF_REG_SIZE];
        slot1.spilled_ptr.dynptr.dynptr_type = dynptr_type;
        slot1.spilled_ptr.dynptr.first_slot = true;
        slot1.spilled_ptr.id = dynptr_id;
        slot1.spilled_ptr.ref_obj_id = ref_obj_id;

        // Mark second slot
        let slot2 = &mut self.stack[spi - 1];
        slot2.slot_type = [BpfStackSlotType::Dynptr; BPF_REG_SIZE];
        slot2.spilled_ptr.dynptr.dynptr_type = dynptr_type;
        slot2.spilled_ptr.dynptr.first_slot = false;
        slot2.spilled_ptr.id = dynptr_id;
        slot2.spilled_ptr.ref_obj_id = ref_obj_id;

        // Update allocated stack
        let stack_used = (spi + 1) * BPF_REG_SIZE;
        if stack_used > self.allocated_stack {
            self.allocated_stack = stack_used;
        }

        Ok(())
    }

    /// Invalidate a dynptr at the given slot index
    pub fn invalidate_dynptr(&mut self, spi: usize) {
        if spi >= self.stack.len() {
            return;
        }

        // Clear first slot
        self.stack[spi].mark_invalid();

        // Clear second slot if exists
        if spi > 0 && spi - 1 < self.stack.len() {
            self.stack[spi - 1].mark_invalid();
        }
    }

    /// Mark stack slots for an iterator
    pub fn mark_iter_slots(
        &mut self,
        spi: usize,
        nr_slots: usize,
        btf_id: u32,
        ref_obj_id: u32,
        is_rcu: bool,
    ) -> Result<()> {
        if spi + 1 < nr_slots {
            return Err(VerifierError::InvalidMemoryAccess(
                format!("iterator needs {} stack slots", nr_slots)
            ));
        }

        // Ensure slots exist
        while self.stack.len() <= spi {
            self.stack.push(BpfStackState::new());
        }

        // Mark all slots
        for i in 0..nr_slots {
            let slot_idx = spi - i;
            let slot = &mut self.stack[slot_idx];
            slot.slot_type = [BpfStackSlotType::Iter; BPF_REG_SIZE];
            slot.spilled_ptr.iter.btf_id = btf_id;
            slot.spilled_ptr.iter.state = BpfIterState::Active;
            slot.spilled_ptr.iter.depth = 0;
            // First slot gets the ref_obj_id
            if i == 0 {
                slot.spilled_ptr.ref_obj_id = ref_obj_id;
            } else {
                slot.spilled_ptr.ref_obj_id = 0;
            }
            if is_rcu {
                slot.spilled_ptr.type_flags.insert(BpfTypeFlag::MEM_RCU);
            }
        }

        // Update allocated stack
        let stack_used = (spi + 1) * BPF_REG_SIZE;
        if stack_used > self.allocated_stack {
            self.allocated_stack = stack_used;
        }

        Ok(())
    }

    /// Unmark stack slots for an iterator (destroy)
    pub fn unmark_iter_slots(&mut self, spi: usize, nr_slots: usize) {
        for i in 0..nr_slots {
            if spi >= i && spi - i < self.stack.len() {
                self.stack[spi - i].mark_invalid();
            }
        }
    }

    /// Check if iterator slots are valid for uninitialized use
    pub fn is_iter_valid_uninit(&self, spi: usize, nr_slots: usize) -> bool {
        // Check that we have enough slots and they're not special types
        if spi + 1 < nr_slots {
            return false;
        }

        for i in 0..nr_slots {
            let slot_idx = spi - i;
            if slot_idx < self.stack.len() {
                let slot = &self.stack[slot_idx];
                // Can't overwrite special slots
                if slot.is_special() {
                    return false;
                }
            }
        }
        true
    }
}
