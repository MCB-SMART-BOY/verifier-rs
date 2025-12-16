// SPDX-License-Identifier: GPL-2.0

//! Dynptr support for BPF programs.
//!
//! Dynptrs are BPF primitives that provide safe access to dynamically-sized memory.
//! They can point to local stack memory, ringbuf entries, SKB/XDP data, etc.

use alloc::{format, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::reference::ReferenceManager;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::{dynptr_get_spi, StackManager};
use crate::stdlib::BTreeMap;

/// Helper to convert argument type to dynptr type
pub fn arg_to_dynptr_type(arg_type: BpfArgType) -> Option<BpfDynptrType> {
    // In the real implementation, this would check the DYNPTR_TYPE_FLAG_MASK
    // For now, we'll return None (would need arg type flags)
    match arg_type {
        BpfArgType::PtrToDynptr => Some(BpfDynptrType::Local),
        _ => None,
    }
}

/// Mark stack slots for a dynptr
pub fn mark_stack_slots_dynptr(
    stack: &mut StackManager,
    refs: &mut ReferenceManager,
    reg: &BpfRegState,
    dynptr_type: BpfDynptrType,
    insn_idx: usize,
    clone_ref_obj_id: Option<u32>,
) -> Result<u32> {
    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;

    // Destroy any existing dynptrs at these slots
    destroy_if_dynptr_stack_slot(stack, spi)?;
    if spi > 0 {
        destroy_if_dynptr_stack_slot(stack, spi - 1)?;
    }

    // Generate IDs
    let dynptr_id = refs.gen_id();

    // Handle refcounted dynptrs
    let ref_obj_id = if dynptr_type.is_refcounted() {
        clone_ref_obj_id.unwrap_or_else(|| refs.acquire_ptr(insn_idx))
    } else {
        0
    };

    // Mark the slots
    stack.mark_dynptr_slots(spi, dynptr_type, dynptr_id, ref_obj_id)?;

    Ok(dynptr_id)
}

/// Unmark stack slots for a dynptr (release)
pub fn unmark_stack_slots_dynptr(
    stack: &mut StackManager,
    refs: &mut ReferenceManager,
    reg: &BpfRegState,
) -> Result<()> {
    // CONST_PTR_TO_DYNPTR cannot be released this way
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return Err(VerifierError::InvalidDynptr(
            "CONST_PTR_TO_DYNPTR cannot be released".into(),
        ));
    }

    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;
    let slot = stack
        .get_slot_by_spi(spi)
        .ok_or(VerifierError::StackOutOfBounds(
            -(spi as i32 + 1) * BPF_REG_SIZE as i32,
        ))?;

    // Check if refcounted
    if !slot.spilled_ptr.dynptr.dynptr_type.is_refcounted() {
        stack.invalidate_dynptr(spi);
        return Ok(());
    }

    let ref_obj_id = slot.spilled_ptr.ref_obj_id;

    // Release the reference
    refs.release_ptr(ref_obj_id)?;

    // Invalidate all dynptr clones with the same ref_obj_id
    let slots_to_invalidate: Vec<usize> = stack
        .stack
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.spilled_ptr.ref_obj_id == ref_obj_id && s.get_type() == BpfStackSlotType::Dynptr
        })
        .map(|(i, _)| i)
        .collect();

    for slot_spi in slots_to_invalidate {
        if stack
            .get_slot_by_spi(slot_spi)
            .map(|s| s.spilled_ptr.dynptr.first_slot)
            .unwrap_or(false)
        {
            stack.invalidate_dynptr(slot_spi);
        }
    }

    Ok(())
}

/// Destroy a dynptr at a stack slot if present
pub fn destroy_if_dynptr_stack_slot(stack: &mut StackManager, spi: usize) -> Result<()> {
    let slot = match stack.get_slot_by_spi(spi) {
        Some(s) => s,
        None => return Ok(()),
    };

    if slot.get_type() != BpfStackSlotType::Dynptr {
        return Ok(());
    }

    // Check if this is refcounted (can't overwrite)
    if slot.spilled_ptr.dynptr.dynptr_type.is_refcounted() {
        return Err(VerifierError::InvalidDynptr(
            "cannot overwrite referenced dynptr".into(),
        ));
    }

    // Find the first slot of the dynptr
    let first_spi = if slot.spilled_ptr.dynptr.first_slot {
        spi
    } else {
        spi + 1
    };

    // Invalidate both slots
    stack.invalidate_dynptr(first_spi);

    Ok(())
}

/// Check if a dynptr register is valid for uninitialized use
pub fn is_dynptr_reg_valid_uninit(reg: &BpfRegState, stack: &StackManager) -> bool {
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return false;
    }

    match dynptr_get_spi(reg, stack.allocated_stack) {
        Ok(_) => true,
        Err(_) => {
            // -ERANGE is OK (stack not allocated yet)
            true
        }
    }
}

/// Check if a dynptr register is valid for initialized use
pub fn is_dynptr_reg_valid_init(reg: &BpfRegState, stack: &StackManager) -> bool {
    // CONST_PTR_TO_DYNPTR is always valid if it exists
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return true;
    }

    let spi = match dynptr_get_spi(reg, stack.allocated_stack) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Check first slot marker
    let slot = match stack.get_slot_by_spi(spi) {
        Some(s) => s,
        None => return false,
    };

    if !slot.spilled_ptr.dynptr.first_slot {
        return false;
    }

    // Check both slots are STACK_DYNPTR
    if slot.get_type() != BpfStackSlotType::Dynptr {
        return false;
    }

    if spi == 0 {
        return false;
    }

    let slot2 = match stack.get_slot_by_spi(spi - 1) {
        Some(s) => s,
        None => return false,
    };

    slot2.get_type() == BpfStackSlotType::Dynptr
}

/// Check if dynptr type matches expected type
pub fn is_dynptr_type_expected(
    reg: &BpfRegState,
    stack: &StackManager,
    expected_type: BpfDynptrType,
) -> bool {
    // ARG_PTR_TO_DYNPTR accepts any type
    if expected_type == BpfDynptrType::Invalid {
        return true;
    }

    let actual_type = if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        reg.dynptr.dynptr_type
    } else {
        match dynptr_get_spi(reg, stack.allocated_stack) {
            Ok(spi) => match stack.get_slot_by_spi(spi) {
                Some(slot) => slot.spilled_ptr.dynptr.dynptr_type,
                None => return false,
            },
            Err(_) => return false,
        }
    };

    actual_type == expected_type
}

/// Get the dynptr ID from a register
pub fn dynptr_id(reg: &BpfRegState, stack: &StackManager) -> Result<u32> {
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return Ok(reg.id);
    }

    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;
    let slot = stack
        .get_slot_by_spi(spi)
        .ok_or(VerifierError::InvalidDynptr("dynptr slot not found".into()))?;

    Ok(slot.spilled_ptr.id)
}

/// Get the ref_obj_id from a dynptr
pub fn dynptr_ref_obj_id(reg: &BpfRegState, stack: &StackManager) -> Result<u32> {
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return Ok(reg.ref_obj_id);
    }

    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;
    let slot = stack
        .get_slot_by_spi(spi)
        .ok_or(VerifierError::InvalidDynptr("dynptr slot not found".into()))?;

    Ok(slot.spilled_ptr.ref_obj_id)
}

/// Get the dynptr type from a register
pub fn dynptr_get_type(reg: &BpfRegState, stack: &StackManager) -> Result<BpfDynptrType> {
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return Ok(reg.dynptr.dynptr_type);
    }

    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;
    let slot = stack
        .get_slot_by_spi(spi)
        .ok_or(VerifierError::InvalidDynptr("dynptr slot not found".into()))?;

    Ok(slot.spilled_ptr.dynptr.dynptr_type)
}

/// Mark a dynptr read (for tracking)
pub fn mark_dynptr_read(stack: &mut StackManager, reg: &BpfRegState) -> Result<()> {
    if reg.reg_type == BpfRegType::ConstPtrToDynptr {
        return Ok(());
    }

    let spi = dynptr_get_spi(reg, stack.allocated_stack)?;

    // Mark both slots as read
    if let Some(slot) = stack.get_slot_mut_by_spi(spi) {
        slot.spilled_ptr.live.read = true;
    }
    if spi > 0 {
        if let Some(slot) = stack.get_slot_mut_by_spi(spi - 1) {
            slot.spilled_ptr.live.read = true;
        }
    }

    Ok(())
}

/// Dynptr slice state for bpf_dynptr_slice / bpf_dynptr_slice_rdwr
#[derive(Debug, Clone)]
pub struct DynptrSlice {
    /// Parent dynptr ID this slice was derived from
    pub parent_id: u32,
    /// Offset into parent dynptr
    pub offset: u32,
    /// Length of the slice
    pub len: u32,
    /// Whether slice is read-write (vs read-only)
    pub rdwr: bool,
    /// Whether this slice is using a user-provided buffer
    pub uses_buffer: bool,
    /// Parent dynptr type
    pub parent_type: BpfDynptrType,
}

impl DynptrSlice {
    /// Create a new slice
    pub fn new(
        parent_id: u32,
        offset: u32,
        len: u32,
        rdwr: bool,
        parent_type: BpfDynptrType,
    ) -> Self {
        Self {
            parent_id,
            offset,
            len,
            rdwr,
            uses_buffer: false,
            parent_type,
        }
    }

    /// Check if access is within slice bounds
    pub fn is_valid_access(&self, off: u32, size: u32) -> bool {
        off.checked_add(size)
            .map(|end| end <= self.len)
            .unwrap_or(false)
    }
}

/// Validate bpf_dynptr_slice call
///
/// Returns (is_rdonly, may_return_null, return_size)
pub fn validate_dynptr_slice(
    reg: &BpfRegState,
    stack: &StackManager,
    _offset: u32,
    len: u32,
    buffer_provided: bool,
    rdwr: bool,
) -> Result<(bool, bool, u32)> {
    // Check dynptr is valid
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for slice".into(),
        ));
    }

    let dynptr_type = dynptr_get_type(reg, stack)?;

    // Check if slice operation is allowed for this dynptr type
    match dynptr_type {
        BpfDynptrType::Local => {
            // Local dynptrs support slice
        }
        BpfDynptrType::Ringbuf => {
            // Ringbuf supports slice
        }
        BpfDynptrType::Skb | BpfDynptrType::Xdp => {
            // SKB/XDP support slice, may need to copy to buffer
        }
        BpfDynptrType::Invalid => {
            return Err(VerifierError::InvalidDynptr("invalid dynptr type".into()));
        }
        _ => {
            // Other types may or may not support slice
        }
    }

    // rdwr slice requires read-write access
    let is_rdonly = !rdwr;

    // For SKB/XDP, may need to return pointer to user buffer (can be null if buffer not provided)
    let may_return_null =
        matches!(dynptr_type, BpfDynptrType::Skb | BpfDynptrType::Xdp) && !buffer_provided;

    // Return size is the requested length
    Ok((is_rdonly, may_return_null, len))
}

/// Create slice result register state
pub fn create_slice_result_reg(
    parent_reg: &BpfRegState,
    stack: &StackManager,
    offset: u32,
    len: u32,
    rdwr: bool,
    buffer_reg: Option<&BpfRegState>,
) -> Result<BpfRegState> {
    let parent_id = dynptr_id(parent_reg, stack)?;
    let parent_type = dynptr_get_type(parent_reg, stack)?;

    let mut result = BpfRegState::default();

    // Slice returns PTR_TO_MEM or NULL
    result.reg_type = BpfRegType::PtrToMem;
    result.mem_size = len;

    // Mark as maybe null for SKB/XDP without buffer
    if matches!(parent_type, BpfDynptrType::Skb | BpfDynptrType::Xdp) && buffer_reg.is_none() {
        result.type_flags.insert(BpfTypeFlag::PTR_MAYBE_NULL);
    }

    // Mark as rdonly if not rdwr
    if !rdwr {
        result.type_flags.insert(BpfTypeFlag::MEM_RDONLY);
    }

    // Store slice info
    result.id = parent_id; // Link to parent
    result.off = offset as i32;

    Ok(result)
}

/// Validate bpf_dynptr_clone call
pub fn validate_dynptr_clone(
    src_reg: &BpfRegState,
    dst_reg: &BpfRegState,
    stack: &StackManager,
) -> Result<()> {
    // Source must be valid initialized dynptr
    if !is_dynptr_reg_valid_init(src_reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "source dynptr not initialized".into(),
        ));
    }

    // Destination must be valid for uninitialized use
    if !is_dynptr_reg_valid_uninit(dst_reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "destination not valid for dynptr".into(),
        ));
    }

    Ok(())
}

/// Process bpf_dynptr_clone - creates a clone of the dynptr
pub fn process_dynptr_clone(
    src_reg: &BpfRegState,
    dst_reg: &BpfRegState,
    stack: &mut StackManager,
    refs: &mut ReferenceManager,
    insn_idx: usize,
) -> Result<u32> {
    // Get source dynptr info
    let src_type = dynptr_get_type(src_reg, stack)?;
    let src_ref_obj_id = dynptr_ref_obj_id(src_reg, stack)?;

    // For refcounted dynptrs, clone shares the same ref_obj_id
    let clone_ref_id = if src_type.is_refcounted() && src_ref_obj_id != 0 {
        Some(src_ref_obj_id)
    } else {
        None
    };

    // Mark destination slots as dynptr
    let new_id = mark_stack_slots_dynptr(stack, refs, dst_reg, src_type, insn_idx, clone_ref_id)?;

    Ok(new_id)
}

/// Validate bpf_dynptr_adjust call
pub fn validate_dynptr_adjust(
    reg: &BpfRegState,
    stack: &StackManager,
    start_offset: u32,
    end_offset: u32,
) -> Result<()> {
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for adjust".into(),
        ));
    }

    // Start must be <= end
    if start_offset > end_offset {
        return Err(VerifierError::InvalidDynptr(
            "adjust: start_offset > end_offset".into(),
        ));
    }

    Ok(())
}

/// Validate bpf_dynptr_is_null call
pub fn validate_dynptr_is_null(reg: &BpfRegState, stack: &StackManager) -> Result<()> {
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for is_null check".into(),
        ));
    }
    Ok(())
}

/// Validate bpf_dynptr_is_rdonly call  
pub fn validate_dynptr_is_rdonly(reg: &BpfRegState, stack: &StackManager) -> Result<()> {
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for is_rdonly check".into(),
        ));
    }
    Ok(())
}

/// Validate bpf_dynptr_size call
pub fn validate_dynptr_size(reg: &BpfRegState, stack: &StackManager) -> Result<()> {
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for size check".into(),
        ));
    }
    Ok(())
}

/// Validate bpf_dynptr_data call - gets raw pointer to data
pub fn validate_dynptr_data(
    reg: &BpfRegState,
    stack: &StackManager,
    offset: u32,
    len: u32,
    rdwr: bool,
) -> Result<BpfRegState> {
    if !is_dynptr_reg_valid_init(reg, stack) {
        return Err(VerifierError::InvalidDynptr(
            "dynptr not initialized for data access".into(),
        ));
    }

    let dynptr_type = dynptr_get_type(reg, stack)?;

    // Check if direct data access is allowed
    match dynptr_type {
        BpfDynptrType::Local | BpfDynptrType::Ringbuf => {
            // Direct access allowed
        }
        BpfDynptrType::Skb | BpfDynptrType::Xdp => {
            // Need to use slice for these
            return Err(VerifierError::InvalidDynptr(
                "use bpf_dynptr_slice for SKB/XDP".into(),
            ));
        }
        _ => {}
    }

    let mut result = BpfRegState::default();
    result.reg_type = BpfRegType::PtrToMem;
    result.mem_size = len;
    result.off = offset as i32;

    if !rdwr {
        result.type_flags.insert(BpfTypeFlag::MEM_RDONLY);
    }

    Ok(result)
}

// ============================================================================
// Nested Dynptr State Machine
// ============================================================================

/// State of a dynptr in the state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynptrState {
    /// Not initialized
    Uninit,
    /// Initialized and valid
    Valid,
    /// Sliced (a slice was taken)
    Sliced,
    /// Adjusted (bounds were adjusted)
    Adjusted,
    /// Released (no longer usable)
    Released,
    /// Invalid (error state)
    Invalid,
}

impl Default for DynptrState {
    fn default() -> Self {
        DynptrState::Uninit
    }
}

/// State transition for nested dynptr operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynptrTransition {
    /// Initialize a new dynptr
    Init,
    /// Take a slice from dynptr
    Slice,
    /// Clone the dynptr
    Clone,
    /// Adjust dynptr bounds
    Adjust,
    /// Get data pointer
    GetData,
    /// Release dynptr
    Release,
    /// Check properties (is_null, is_rdonly, size)
    Check,
    /// Pass to exception handler
    PassToException,
    /// Use in iterator
    UseInIterator,
}

/// Nested dynptr context for tracking complex operations
#[derive(Debug, Clone)]
pub struct NestedDynptrContext {
    /// Current state
    pub state: DynptrState,
    /// Nesting depth (for nested slices/clones)
    pub depth: u32,
    /// Parent dynptr ID (if this is derived)
    pub parent_id: Option<u32>,
    /// Derived dynptr IDs
    pub children: Vec<u32>,
    /// Current slice info (if sliced)
    pub slice_info: Option<DynptrSlice>,
    /// Adjustment info
    pub adjustment: Option<DynptrAdjustment>,
    /// Whether in exception context
    pub in_exception: bool,
    /// Whether in iterator context
    pub in_iterator: bool,
    /// Iteration count (for iterator context)
    pub iteration_count: u32,
}

/// Dynptr bounds adjustment tracking
#[derive(Debug, Clone)]
pub struct DynptrAdjustment {
    /// Original start offset
    pub original_start: u32,
    /// Original end offset
    pub original_end: u32,
    /// Current start offset
    pub current_start: u32,
    /// Current end offset
    pub current_end: u32,
}

impl NestedDynptrContext {
    /// Create new context
    pub fn new() -> Self {
        Self {
            state: DynptrState::Uninit,
            depth: 0,
            parent_id: None,
            children: Vec::new(),
            slice_info: None,
            adjustment: None,
            in_exception: false,
            in_iterator: false,
            iteration_count: 0,
        }
    }

    /// Create context for a derived dynptr
    pub fn derived(parent_id: u32, depth: u32) -> Self {
        Self {
            state: DynptrState::Valid,
            depth,
            parent_id: Some(parent_id),
            children: Vec::new(),
            slice_info: None,
            adjustment: None,
            in_exception: false,
            in_iterator: false,
            iteration_count: 0,
        }
    }

    /// Apply state transition
    pub fn transition(&mut self, trans: DynptrTransition) -> Result<()> {
        let new_state = match (self.state, trans) {
            // From Uninit
            (DynptrState::Uninit, DynptrTransition::Init) => DynptrState::Valid,
            (DynptrState::Uninit, _) => {
                return Err(VerifierError::InvalidDynptr(
                    "dynptr not initialized".into(),
                ));
            }

            // From Valid
            (DynptrState::Valid, DynptrTransition::Slice) => DynptrState::Sliced,
            (DynptrState::Valid, DynptrTransition::Clone) => DynptrState::Valid,
            (DynptrState::Valid, DynptrTransition::Adjust) => DynptrState::Adjusted,
            (DynptrState::Valid, DynptrTransition::GetData) => DynptrState::Valid,
            (DynptrState::Valid, DynptrTransition::Release) => DynptrState::Released,
            (DynptrState::Valid, DynptrTransition::Check) => DynptrState::Valid,
            (DynptrState::Valid, DynptrTransition::PassToException) => {
                self.in_exception = true;
                DynptrState::Valid
            }
            (DynptrState::Valid, DynptrTransition::UseInIterator) => {
                self.in_iterator = true;
                DynptrState::Valid
            }

            // From Sliced - can still do some operations
            (DynptrState::Sliced, DynptrTransition::Slice) => {
                self.depth += 1;
                if self.depth > MAX_NESTED_DYNPTR_DEPTH {
                    return Err(VerifierError::InvalidDynptr(
                        "nested dynptr slice depth exceeded".into(),
                    ));
                }
                DynptrState::Sliced
            }
            (DynptrState::Sliced, DynptrTransition::Release) => DynptrState::Released,
            (DynptrState::Sliced, DynptrTransition::Check) => DynptrState::Sliced,
            (DynptrState::Sliced, DynptrTransition::GetData) => {
                return Err(VerifierError::InvalidDynptr(
                    "cannot get data from sliced dynptr, use slice pointer".into(),
                ));
            }

            // From Adjusted - similar to Valid but with modified bounds
            (DynptrState::Adjusted, DynptrTransition::Slice) => DynptrState::Sliced,
            (DynptrState::Adjusted, DynptrTransition::Adjust) => DynptrState::Adjusted,
            (DynptrState::Adjusted, DynptrTransition::Release) => DynptrState::Released,
            (DynptrState::Adjusted, DynptrTransition::Check) => DynptrState::Adjusted,
            (DynptrState::Adjusted, DynptrTransition::GetData) => DynptrState::Adjusted,

            // From Released - nothing allowed
            (DynptrState::Released, _) => {
                return Err(VerifierError::InvalidDynptr(
                    "dynptr already released".into(),
                ));
            }

            // From Invalid
            (DynptrState::Invalid, _) => {
                return Err(VerifierError::InvalidDynptr(
                    "dynptr in invalid state".into(),
                ));
            }

            // Default: invalid transition
            (state, trans) => {
                return Err(VerifierError::InvalidDynptr(format!(
                    "invalid dynptr transition {:?} from state {:?}",
                    trans, state
                )));
            }
        };

        self.state = new_state;
        Ok(())
    }

    /// Check if dynptr can be used in current context
    pub fn can_use(&self) -> bool {
        matches!(
            self.state,
            DynptrState::Valid | DynptrState::Sliced | DynptrState::Adjusted
        )
    }

    /// Add child dynptr
    pub fn add_child(&mut self, child_id: u32) {
        self.children.push(child_id);
    }

    /// Record slice operation
    pub fn record_slice(&mut self, slice: DynptrSlice) {
        self.slice_info = Some(slice);
    }

    /// Record adjustment
    pub fn record_adjustment(&mut self, start: u32, end: u32) {
        if let Some(ref mut adj) = self.adjustment {
            adj.current_start = start;
            adj.current_end = end;
        } else {
            self.adjustment = Some(DynptrAdjustment {
                original_start: 0,
                original_end: u32::MAX,
                current_start: start,
                current_end: end,
            });
        }
    }
}

impl Default for NestedDynptrContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum nesting depth for dynptr operations
const MAX_NESTED_DYNPTR_DEPTH: u32 = 8;

// ============================================================================
// Exception Context Integration
// ============================================================================

/// Dynptr state during exception handling
#[derive(Debug, Clone)]
pub struct DynptrExceptionState {
    /// Dynptrs that need cleanup on exception
    pub cleanup_required: Vec<u32>,
    /// Dynptrs that were saved before exception
    pub saved_dynptrs: BTreeMap<u32, NestedDynptrContext>,
    /// Whether we're in a try block
    pub in_try_block: bool,
    /// Exception nesting depth
    pub exception_depth: u32,
}

impl DynptrExceptionState {
    /// Create new exception state
    pub fn new() -> Self {
        Self {
            cleanup_required: Vec::new(),
            saved_dynptrs: BTreeMap::new(),
            in_try_block: false,
            exception_depth: 0,
        }
    }

    /// Enter try block
    pub fn enter_try(&mut self) {
        self.in_try_block = true;
        self.exception_depth += 1;
    }

    /// Exit try block
    pub fn exit_try(&mut self) {
        if self.exception_depth > 0 {
            self.exception_depth -= 1;
        }
        if self.exception_depth == 0 {
            self.in_try_block = false;
        }
    }

    /// Mark dynptr for cleanup on exception
    pub fn mark_for_cleanup(&mut self, dynptr_id: u32) {
        if !self.cleanup_required.contains(&dynptr_id) {
            self.cleanup_required.push(dynptr_id);
        }
    }

    /// Save dynptr state before potential exception
    pub fn save_state(&mut self, dynptr_id: u32, ctx: NestedDynptrContext) {
        self.saved_dynptrs.insert(dynptr_id, ctx);
    }

    /// Get saved state for recovery
    pub fn get_saved_state(&self, dynptr_id: u32) -> Option<&NestedDynptrContext> {
        self.saved_dynptrs.get(&dynptr_id)
    }

    /// Clear cleanup markers after successful completion
    pub fn clear_cleanup(&mut self) {
        self.cleanup_required.clear();
    }

    /// Get all dynptrs that need cleanup
    pub fn get_cleanup_list(&self) -> &[u32] {
        &self.cleanup_required
    }
}

impl Default for DynptrExceptionState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Iterator Context Integration
// ============================================================================

/// Dynptr behavior in iterator context
#[derive(Debug, Clone)]
pub struct DynptrIteratorContext {
    /// Dynptr IDs used in current iteration
    pub iteration_dynptrs: Vec<u32>,
    /// Maximum iterations allowed with dynptr
    pub max_iterations: u32,
    /// Current iteration count
    pub current_iteration: u32,
    /// Whether iterator modifies dynptr
    pub modifies_dynptr: bool,
    /// Widening applied to dynptr bounds
    pub bounds_widened: bool,
}

impl DynptrIteratorContext {
    /// Create new iterator context
    pub fn new(max_iterations: u32) -> Self {
        Self {
            iteration_dynptrs: Vec::new(),
            max_iterations,
            current_iteration: 0,
            modifies_dynptr: false,
            bounds_widened: false,
        }
    }

    /// Register dynptr use in iteration
    pub fn register_dynptr(&mut self, dynptr_id: u32) {
        if !self.iteration_dynptrs.contains(&dynptr_id) {
            self.iteration_dynptrs.push(dynptr_id);
        }
    }

    /// Increment iteration
    pub fn next_iteration(&mut self) -> Result<()> {
        self.current_iteration += 1;
        if self.current_iteration > self.max_iterations {
            return Err(VerifierError::InvalidDynptr(
                "dynptr used in too many iterations".into(),
            ));
        }
        Ok(())
    }

    /// Mark that dynptr bounds need widening
    pub fn mark_needs_widening(&mut self) {
        self.bounds_widened = true;
    }

    /// Check if dynptr is safe for iteration
    pub fn is_safe_for_iteration(&self, dynptr_id: u32, ctx: &NestedDynptrContext) -> bool {
        // Can't use released dynptr
        if ctx.state == DynptrState::Released {
            return false;
        }
        // Limit depth in iterations
        if ctx.depth > 2 {
            return false;
        }
        // Already using too many dynptrs in iteration
        if self.iteration_dynptrs.len() >= 4 && !self.iteration_dynptrs.contains(&dynptr_id) {
            return false;
        }
        true
    }
}

impl Default for DynptrIteratorContext {
    fn default() -> Self {
        Self::new(BPF_MAX_LOOPS)
    }
}

/// Maximum loops for BPF iteration
const BPF_MAX_LOOPS: u32 = 8 * 1024 * 1024;

// ============================================================================
// Enhanced Dynptr Tracker
// ============================================================================

/// Track dynptr through function calls
#[derive(Debug, Clone, Default)]
pub struct DynptrTracker {
    /// Active dynptrs by ID
    active: BTreeMap<u32, DynptrInfo>,
    /// Nested context for each dynptr
    nested_ctx: BTreeMap<u32, NestedDynptrContext>,
    /// Exception state
    pub exception_state: DynptrExceptionState,
    /// Iterator context (if in iteration)
    pub iterator_ctx: Option<DynptrIteratorContext>,
    /// Total dynptrs created
    pub total_created: u32,
    /// Total dynptrs released  
    pub total_released: u32,
}

/// Information about an active dynptr
#[derive(Debug, Clone)]
pub struct DynptrInfo {
    /// Dynptr type
    pub dynptr_type: BpfDynptrType,
    /// Stack slot index
    pub spi: usize,
    /// Reference object ID (for refcounted)
    pub ref_obj_id: u32,
    /// Instruction where created
    pub created_at: usize,
    /// Whether this is a clone
    pub is_clone: bool,
    /// Parent ID if clone
    pub parent_id: Option<u32>,
}

impl DynptrTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new dynptr
    pub fn register(&mut self, id: u32, info: DynptrInfo) {
        // Create nested context before moving info
        let mut ctx = NestedDynptrContext::new();
        ctx.state = DynptrState::Valid;
        if info.is_clone {
            ctx.parent_id = info.parent_id;
            ctx.depth = 1;
        }
        self.nested_ctx.insert(id, ctx);

        self.active.insert(id, info);
        self.total_created += 1;
    }

    /// Register derived dynptr (clone, slice result, etc.)
    pub fn register_derived(&mut self, id: u32, parent_id: u32, info: DynptrInfo) {
        self.active.insert(id, info);

        // Get parent depth
        let parent_depth = self
            .nested_ctx
            .get(&parent_id)
            .map(|c| c.depth)
            .unwrap_or(0);

        // Create derived context
        let ctx = NestedDynptrContext::derived(parent_id, parent_depth + 1);
        self.nested_ctx.insert(id, ctx);

        // Add child to parent
        if let Some(parent_ctx) = self.nested_ctx.get_mut(&parent_id) {
            parent_ctx.add_child(id);
        }

        self.total_created += 1;
    }

    /// Get dynptr info
    pub fn get(&self, id: u32) -> Option<&DynptrInfo> {
        self.active.get(&id)
    }

    /// Get nested context
    pub fn get_context(&self, id: u32) -> Option<&NestedDynptrContext> {
        self.nested_ctx.get(&id)
    }

    /// Get mutable nested context
    pub fn get_context_mut(&mut self, id: u32) -> Option<&mut NestedDynptrContext> {
        self.nested_ctx.get_mut(&id)
    }

    /// Apply transition to dynptr
    pub fn apply_transition(&mut self, id: u32, trans: DynptrTransition) -> Result<()> {
        let ctx = self
            .nested_ctx
            .get_mut(&id)
            .ok_or_else(|| VerifierError::InvalidDynptr(format!("dynptr {} not found", id)))?;
        ctx.transition(trans)
    }

    /// Release a dynptr
    pub fn release(&mut self, id: u32) -> Result<Option<DynptrInfo>> {
        // Apply release transition
        if let Some(ctx) = self.nested_ctx.get_mut(&id) {
            ctx.transition(DynptrTransition::Release)?;
        }

        let info = self.active.remove(&id);
        if info.is_some() {
            self.total_released += 1;
        }

        // Also release any child dynptrs
        if let Some(ctx) = self.nested_ctx.get(&id) {
            let children: Vec<u32> = ctx.children.clone();
            for child_id in children {
                let _ = self.release(child_id);
            }
        }

        Ok(info)
    }

    /// Check if dynptr exists
    pub fn exists(&self, id: u32) -> bool {
        self.active.contains_key(&id)
    }

    /// Check if dynptr is usable
    pub fn is_usable(&self, id: u32) -> bool {
        self.nested_ctx
            .get(&id)
            .map(|c| c.can_use())
            .unwrap_or(false)
    }

    /// Get count of active dynptrs
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Get nesting depth
    pub fn get_depth(&self, id: u32) -> u32 {
        self.nested_ctx.get(&id).map(|c| c.depth).unwrap_or(0)
    }

    /// Check nesting depth limit
    pub fn check_depth_limit(&self, id: u32) -> Result<()> {
        let depth = self.get_depth(id);
        if depth > MAX_NESTED_DYNPTR_DEPTH {
            return Err(VerifierError::InvalidDynptr(format!(
                "dynptr nesting depth {} exceeds limit {}",
                depth, MAX_NESTED_DYNPTR_DEPTH
            )));
        }
        Ok(())
    }

    // ========================================================================
    // Exception Integration
    // ========================================================================

    /// Enter try block - save all active dynptr states
    pub fn enter_try_block(&mut self) {
        self.exception_state.enter_try();

        // Save current states of all active dynptrs
        for (id, ctx) in &self.nested_ctx {
            if ctx.can_use() {
                self.exception_state.save_state(*id, ctx.clone());
            }
        }
    }

    /// Exit try block normally
    pub fn exit_try_block_normal(&mut self) {
        self.exception_state.exit_try();
        self.exception_state.clear_cleanup();
    }

    /// Exit try block via exception
    pub fn exit_try_block_exception(&mut self) -> Result<()> {
        self.exception_state.exit_try();

        // Release all dynptrs marked for cleanup
        let cleanup_list: Vec<u32> = self.exception_state.cleanup_required.clone();
        for id in cleanup_list {
            if let Some(info) = self.active.get(&id) {
                if info.dynptr_type.is_refcounted() {
                    // Must release refcounted dynptrs
                    self.release(id)?;
                }
            }
        }

        self.exception_state.clear_cleanup();
        Ok(())
    }

    /// Mark dynptr for exception cleanup
    pub fn mark_exception_cleanup(&mut self, id: u32) {
        if self.exception_state.in_try_block {
            self.exception_state.mark_for_cleanup(id);
        }
    }

    /// Check if in exception context
    pub fn in_exception_context(&self) -> bool {
        self.exception_state.in_try_block
    }

    // ========================================================================
    // Iterator Integration
    // ========================================================================

    /// Enter iterator context
    pub fn enter_iterator(&mut self, max_iterations: u32) {
        self.iterator_ctx = Some(DynptrIteratorContext::new(max_iterations));
    }

    /// Exit iterator context
    pub fn exit_iterator(&mut self) {
        self.iterator_ctx = None;
    }

    /// Register dynptr use in iteration
    pub fn use_in_iteration(&mut self, id: u32) -> Result<()> {
        // Check if in iterator
        let iter_ctx = match &mut self.iterator_ctx {
            Some(ctx) => ctx,
            None => return Ok(()), // Not in iterator, OK
        };

        // Check if dynptr is safe for iteration
        let nested_ctx = self
            .nested_ctx
            .get(&id)
            .ok_or_else(|| VerifierError::InvalidDynptr(format!("dynptr {} not found", id)))?;

        if !iter_ctx.is_safe_for_iteration(id, nested_ctx) {
            return Err(VerifierError::InvalidDynptr(
                "dynptr not safe for use in iteration".into(),
            ));
        }

        iter_ctx.register_dynptr(id);

        // Mark in nested context
        if let Some(ctx) = self.nested_ctx.get_mut(&id) {
            ctx.in_iterator = true;
        }

        Ok(())
    }

    /// Advance iteration
    pub fn next_iteration(&mut self) -> Result<()> {
        if let Some(ref mut iter_ctx) = self.iterator_ctx {
            iter_ctx.next_iteration()?;
        }
        Ok(())
    }

    /// Check if in iterator
    pub fn in_iterator(&self) -> bool {
        self.iterator_ctx.is_some()
    }

    // ========================================================================
    // Validation
    // ========================================================================

    /// Validate all dynptrs are released
    pub fn validate_cleanup(&self) -> Result<()> {
        let unreleased: Vec<u32> = self
            .active
            .iter()
            .filter(|(_, info)| info.dynptr_type.is_refcounted())
            .map(|(id, _)| *id)
            .collect();

        if !unreleased.is_empty() {
            return Err(VerifierError::InvalidDynptr(format!(
                "unreleased refcounted dynptrs: {:?}",
                unreleased
            )));
        }
        Ok(())
    }

    /// Validate no iterator context leaks
    pub fn validate_no_iterator_leak(&self) -> Result<()> {
        if self.iterator_ctx.is_some() {
            return Err(VerifierError::InvalidDynptr(
                "iterator context not properly closed".into(),
            ));
        }
        Ok(())
    }

    /// Validate no exception context leaks
    pub fn validate_no_exception_leak(&self) -> Result<()> {
        if self.exception_state.in_try_block {
            return Err(VerifierError::InvalidDynptr(
                "exception context not properly closed".into(),
            ));
        }
        Ok(())
    }

    /// Full validation
    pub fn validate_all(&self) -> Result<()> {
        self.validate_cleanup()?;
        self.validate_no_iterator_leak()?;
        self.validate_no_exception_leak()?;
        Ok(())
    }

    /// Get all dynptrs at or above a certain depth
    pub fn get_deep_dynptrs(&self, min_depth: u32) -> Vec<u32> {
        self.nested_ctx
            .iter()
            .filter(|(_, ctx)| ctx.depth >= min_depth && ctx.can_use())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get parent chain for a dynptr
    pub fn get_parent_chain(&self, id: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = id;

        while let Some(ctx) = self.nested_ctx.get(&current) {
            if let Some(parent) = ctx.parent_id {
                chain.push(parent);
                current = parent;
            } else {
                break;
            }
        }

        chain
    }
}
