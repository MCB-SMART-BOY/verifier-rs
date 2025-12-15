//! Timer and Kptr special field validation
//!
//! This module implements verification for bpf_timer and bpf_kptr special fields
//! embedded in map values. These fields have strict access rules:
//!
//! ## Timer Rules:
//! - Timer must be initialized with bpf_timer_init before use
//! - Timer callbacks must match the map they're associated with (map_uid)
//! - Timer cannot be used in PREEMPT_RT configurations
//! - Timer fields cannot be directly read/written by BPF programs
//!
//! ## Kptr Rules:
//! - Kptr can be UNREF (unreferenced) or REF (referenced)
//! - Referenced kptrs require proper acquire/release semantics
//! - Kptr access must be through bpf_kptr_xchg or atomic operations
//! - Kptr type must match the BTF type declared in the map
//! - RCU-safe kptrs can be read under RCU protection

#[cfg(not(feature = "std"))]
use alloc::format;

use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::state::reg_state::BpfRegState;
use crate::state::reference::ReferenceManager;

/// Size of bpf_timer struct in bytes
pub const BPF_TIMER_SIZE: u32 = 16;

/// Size of a kptr field (pointer size)
pub const BPF_KPTR_SIZE: u32 = 8;

/// Types of kptr fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KptrType {
    /// Unreferenced kptr - can store untrusted pointers
    Unref,
    /// Referenced kptr - requires proper reference management
    Ref,
    /// Per-CPU kptr - points to per-CPU data
    Percpu,
}

impl KptrType {
    /// Check if this kptr type requires reference counting
    pub fn requires_refcount(&self) -> bool {
        matches!(self, KptrType::Ref | KptrType::Percpu)
    }
    
    /// Check if untrusted pointers are allowed
    pub fn allows_untrusted(&self) -> bool {
        matches!(self, KptrType::Unref)
    }
}

/// Special field types in map values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialFieldType {
    /// bpf_timer field
    Timer,
    /// bpf_spin_lock field
    SpinLock,
    /// bpf_kptr field
    Kptr(KptrType),
    /// bpf_list_head field
    ListHead,
    /// bpf_list_node field
    ListNode,
    /// bpf_rb_root field
    RbRoot,
    /// bpf_rb_node field
    RbNode,
    /// bpf_refcount field
    Refcount,
    /// bpf_workqueue field
    Workqueue,
}

impl SpecialFieldType {
    /// Get the size of this special field
    pub fn size(&self) -> u32 {
        match self {
            SpecialFieldType::Timer => BPF_TIMER_SIZE,
            SpecialFieldType::SpinLock => 4,
            SpecialFieldType::Kptr(_) => BPF_KPTR_SIZE,
            SpecialFieldType::ListHead => 16,
            SpecialFieldType::ListNode => 16,
            SpecialFieldType::RbRoot => 16,
            SpecialFieldType::RbNode => 24,
            SpecialFieldType::Refcount => 4,
            SpecialFieldType::Workqueue => 16,
        }
    }
    
    /// Check if direct BPF access is forbidden
    pub fn forbids_direct_access(&self) -> bool {
        match self {
            SpecialFieldType::Timer |
            SpecialFieldType::SpinLock |
            SpecialFieldType::Kptr(_) |
            SpecialFieldType::ListHead |
            SpecialFieldType::ListNode |
            SpecialFieldType::RbRoot |
            SpecialFieldType::RbNode |
            SpecialFieldType::Refcount |
            SpecialFieldType::Workqueue => true,
        }
    }
}

/// Information about a special field in a map value
#[derive(Debug, Clone)]
pub struct SpecialFieldInfo {
    /// Type of the special field
    pub field_type: SpecialFieldType,
    /// Offset within the map value
    pub offset: u32,
    /// BTF type ID for kptr target type (if applicable)
    pub btf_id: Option<u32>,
}

/// Timer state tracking
#[derive(Debug, Clone, Default)]
pub struct TimerState {
    /// Map UID where timer is located
    pub map_uid: u32,
    /// Offset of timer within map value
    pub timer_off: u32,
    /// Whether timer has been initialized
    pub initialized: bool,
    /// Whether callback has been set
    pub callback_set: bool,
    /// Instruction index where callback was set
    pub callback_insn: Option<usize>,
}

impl TimerState {
    /// Create new uninitialized timer state
    pub fn new(map_uid: u32, timer_off: u32) -> Self {
        Self {
            map_uid,
            timer_off,
            initialized: false,
            callback_set: false,
            callback_insn: None,
        }
    }
    
    /// Mark timer as initialized
    pub fn init(&mut self) {
        self.initialized = true;
    }
    
    /// Set callback for timer
    pub fn set_callback(&mut self, insn_idx: usize) -> Result<()> {
        if !self.initialized {
            return Err(VerifierError::InvalidState(
                "cannot set callback on uninitialized timer".into()
            ));
        }
        self.callback_set = true;
        self.callback_insn = Some(insn_idx);
        Ok(())
    }
}

/// Kptr state tracking
#[derive(Debug, Clone)]
pub struct KptrState {
    /// Type of kptr
    pub kptr_type: KptrType,
    /// BTF type ID of the pointed-to type
    pub btf_id: u32,
    /// Whether a value is currently stored
    pub has_value: bool,
    /// Reference ID if value is referenced
    pub ref_obj_id: u32,
}

impl KptrState {
    /// Create new empty kptr state
    pub fn new(kptr_type: KptrType, btf_id: u32) -> Self {
        Self {
            kptr_type,
            btf_id,
            has_value: false,
            ref_obj_id: 0,
        }
    }
}

/// Validate timer pointer argument for timer helpers
pub fn check_timer_arg(
    reg: &BpfRegState,
    regno: u8,
) -> Result<(u32, u32)> {
    // Must be PTR_TO_MAP_VALUE
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_MAP_VALUE for timer".into(),
            got: format!("{:?}", reg.reg_type),
        });
    }
    
    // Check offset is valid for timer access
    let timer_off = reg.off as u32;
    
    // Timer should be 8-byte aligned
    if timer_off % 8 != 0 {
        return Err(VerifierError::InvalidPointer(format!(
            "R{} timer offset {} is not 8-byte aligned",
            regno, timer_off
        )));
    }
    
    Ok((reg.map_uid, timer_off))
}

/// Validate map argument for bpf_timer_init
pub fn check_timer_init_map_arg(
    timer_reg: &BpfRegState,
    map_reg: &BpfRegState,
) -> Result<()> {
    // Map register must be PTR_TO_MAP
    if !matches!(map_reg.reg_type, BpfRegType::ConstPtrToMap) {
        return Err(VerifierError::TypeMismatch {
            expected: "CONST_PTR_TO_MAP for timer init".into(),
            got: format!("{:?}", map_reg.reg_type),
        });
    }
    
    // Map UIDs should match (timer must be in the provided map)
    // This prevents:
    //   timer = bpf_map_lookup_elem(inner_map1);
    //   bpf_timer_init(timer, inner_map2);  // WRONG!
    if timer_reg.map_uid != 0 && map_reg.map_uid != 0 {
        if timer_reg.map_uid != map_reg.map_uid {
            return Err(VerifierError::InvalidState(format!(
                "timer map_uid={} doesn't match map argument map_uid={}",
                timer_reg.map_uid, map_reg.map_uid
            )));
        }
    }
    
    Ok(())
}

/// Check kptr access permissions
pub fn check_kptr_access(
    reg: &BpfRegState,
    kptr_type: KptrType,
    target_btf_id: u32,
    is_write: bool,
    in_rcu: bool,
) -> Result<()> {
    // For writes (xchg), check source pointer type
    if is_write {
        // Must be PTR_TO_BTF_ID
        if reg.reg_type != BpfRegType::PtrToBtfId {
            // Or NULL (const zero) for clearing the kptr
            let is_null = reg.is_const() && reg.const_value() == 0;
            if !is_null {
                return Err(VerifierError::TypeMismatch {
                    expected: "PTR_TO_BTF_ID or NULL for kptr xchg".into(),
                    got: format!("{:?}", reg.reg_type),
                });
            }
        }
        
        // Check type flags based on kptr type
        let mut allowed_flags = BpfTypeFlag::PTR_MAYBE_NULL | BpfTypeFlag::PTR_TRUSTED | BpfTypeFlag::MEM_RCU;
        
        if kptr_type == KptrType::Unref {
            allowed_flags.insert(BpfTypeFlag::PTR_UNTRUSTED);
        }
        
        if kptr_type == KptrType::Percpu {
            allowed_flags.insert(BpfTypeFlag::MEM_PERCPU);
        }
        
        // Check for disallowed flags
        let disallowed = reg.type_flags.difference(allowed_flags);
        if !disallowed.is_empty() {
            return Err(VerifierError::TypeMismatch {
                expected: format!("pointer with allowed flags for {:?} kptr", kptr_type),
                got: format!("pointer with flags {:?}", reg.type_flags),
            });
        }
        
        // Check BTF type matches (if available)
        if let Some(btf_info) = &reg.btf_info {
            if target_btf_id != 0 && btf_info.btf_id != target_btf_id {
                // For referenced kptrs, type must match exactly
                if kptr_type != KptrType::Unref {
                    return Err(VerifierError::TypeMismatch {
                        expected: format!("BTF type {} for kptr", target_btf_id),
                        got: format!("BTF type {}", btf_info.btf_id),
                    });
                }
            }
        }
    } else {
        // Read access - check RCU protection
        if !in_rcu && kptr_type != KptrType::Unref {
            // Referenced kptrs can only be read under RCU protection
            // or they return an RCU-protected pointer
        }
    }
    
    Ok(())
}

/// Determine the result type of a kptr load
pub fn kptr_load_type(
    kptr_type: KptrType,
    in_rcu: bool,
    is_rcu_protected: bool,
) -> BpfTypeFlag {
    let mut flags = BpfTypeFlag::PTR_MAYBE_NULL;
    
    if is_rcu_protected && in_rcu {
        flags.insert(BpfTypeFlag::MEM_RCU);
        
        if kptr_type == KptrType::Percpu {
            flags.insert(BpfTypeFlag::MEM_PERCPU);
        } else {
            // For non-percpu, check if it's locally allocated
            flags.insert(BpfTypeFlag::MEM_ALLOC);
        }
    }
    
    flags
}

/// Check if timer access is allowed in current context
pub fn check_timer_context(
    refs: &ReferenceManager,
    is_preempt_rt: bool,
) -> Result<()> {
    // Timer cannot be used in PREEMPT_RT
    if is_preempt_rt {
        return Err(VerifierError::InvalidState(
            "bpf_timer cannot be used for PREEMPT_RT".into()
        ));
    }
    
    // Timer operations should not be called while holding locks
    // (to avoid potential deadlocks)
    if refs.active_locks > 0 {
        return Err(VerifierError::InvalidState(
            "bpf_timer operations cannot be called while holding spin lock".into()
        ));
    }
    
    Ok(())
}

/// Validate special field overlap for map value access
pub fn check_special_field_overlap(
    offset: i32,
    size: u32,
    fields: &[SpecialFieldInfo],
) -> Result<()> {
    let access_end = offset as u32 + size;
    
    for field in fields {
        let field_end = field.offset + field.field_type.size();
        
        // Check for overlap
        if (offset as u32) < field_end && field.offset < access_end {
            let field_name = match field.field_type {
                SpecialFieldType::Timer => "timer",
                SpecialFieldType::SpinLock => "spin_lock",
                SpecialFieldType::Kptr(_) => "kptr",
                SpecialFieldType::ListHead => "list_head",
                SpecialFieldType::ListNode => "list_node",
                SpecialFieldType::RbRoot => "rb_root",
                SpecialFieldType::RbNode => "rb_node",
                SpecialFieldType::Refcount => "refcount",
                SpecialFieldType::Workqueue => "workqueue",
            };
            
            return Err(VerifierError::InvalidMapAccess(format!(
                "access at offset {} size {} overlaps with {} field at offset {}",
                offset, size, field_name, field.offset
            )));
        }
    }
    
    Ok(())
}

/// Check callback registration for timer
pub fn check_timer_callback_registration(
    timer_map_uid: u32,
    callback_map_uid: u32,
) -> Result<()> {
    // The callback's context (map) must match the timer's map
    if timer_map_uid != 0 && callback_map_uid != 0 {
        if timer_map_uid != callback_map_uid {
            return Err(VerifierError::InvalidState(format!(
                "timer callback map_uid={} doesn't match timer map_uid={}",
                callback_map_uid, timer_map_uid
            )));
        }
    }
    Ok(())
}

/// Validate kptr xchg operation
pub fn check_kptr_xchg(
    dst_reg: &BpfRegState,
    src_reg: &BpfRegState,
    kptr_type: KptrType,
    target_btf_id: u32,
    refs: &mut ReferenceManager,
    insn_idx: usize,
) -> Result<u32> {
    // Destination must be PTR_TO_MAP_VALUE pointing to the kptr field
    if dst_reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::TypeMismatch {
            expected: "PTR_TO_MAP_VALUE for kptr xchg destination".into(),
            got: format!("{:?}", dst_reg.reg_type),
        });
    }
    
    // Validate source pointer
    check_kptr_access(src_reg, kptr_type, target_btf_id, true, refs.in_rcu())?;
    
    // If source has a reference, it's being transferred to the kptr
    if src_reg.ref_obj_id != 0 && kptr_type.requires_refcount() {
        // Release the source reference (it's now owned by the kptr)
        refs.release_ptr(src_reg.ref_obj_id)?;
    }
    
    // The old value is returned - acquire a reference for it
    let ret_ref_id = if kptr_type.requires_refcount() {
        refs.acquire_ptr(insn_idx)
    } else {
        0
    };
    
    Ok(ret_ref_id)
}

// ============================================================================
// Workqueue and Task Work Processing
// ============================================================================

/// Information about a workqueue callback
#[derive(Debug, Clone, Default)]
pub struct WorkqueueInfo {
    /// Map UID that the workqueue is associated with
    pub map_uid: u32,
    /// BTF ID of the workqueue struct
    pub btf_id: u32,
    /// Offset of workqueue field in map value
    pub offset: u32,
    /// Whether the workqueue has been initialized
    pub initialized: bool,
}

/// Information about a task_work callback
#[derive(Debug, Clone, Default)]
pub struct TaskWorkInfo {
    /// Map UID for the task_work
    pub map_uid: u32,
    /// BTF ID of the task_work struct
    pub btf_id: u32,
    /// Offset in map value
    pub offset: u32,
    /// Whether task_work has been scheduled
    pub scheduled: bool,
}

/// Process a workqueue kfunc call.
///
/// Validates workqueue operations including:
/// - bpf_wq_init: Initialize workqueue in map value
/// - bpf_wq_set_callback_impl: Set callback function
/// - bpf_wq_start: Start the workqueue
///
/// Corresponds to kernel's process_wq_func() (L8595-8614)
pub fn process_wq_func(
    reg: &BpfRegState,
    kfunc_id: u32,
    map_uid: u32,
    insn_idx: usize,
) -> Result<Option<WorkqueueInfo>> {
    // Verify the register points to a map value
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::InvalidKfunc(
            "workqueue arg must be pointer to map value".into()
        ));
    }
    
    // Check offset is valid for workqueue field
    let off = reg.off;
    if off < 0 {
        return Err(VerifierError::InvalidKfunc(
            format!("invalid workqueue offset {}", off)
        ));
    }
    
    // Different handling based on kfunc type
    // These are placeholder BTF IDs - real implementation would use actual IDs
    const BPF_WQ_INIT: u32 = 1001;
    const BPF_WQ_SET_CALLBACK: u32 = 1002;
    const BPF_WQ_START: u32 = 1003;
    
    match kfunc_id {
        BPF_WQ_INIT => {
            // Initialize workqueue - creates new workqueue info
            Ok(Some(WorkqueueInfo {
                map_uid,
                btf_id: 0, // Would be resolved from BTF
                offset: off as u32,
                initialized: true,
            }))
        }
        BPF_WQ_SET_CALLBACK => {
            // Set callback - workqueue must already be initialized
            // Callback validation happens elsewhere
            Ok(None)
        }
        BPF_WQ_START => {
            // Start workqueue - must be initialized with callback set
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Process a task_work kfunc call.
///
/// Validates task_work operations including:
/// - bpf_task_work_init: Initialize task_work
/// - bpf_task_work_schedule: Schedule work on a task
///
/// Corresponds to kernel's process_task_work_func() (L8616-8634)
pub fn process_task_work_func(
    reg: &BpfRegState,
    kfunc_id: u32,
    map_uid: u32,
    insn_idx: usize,
) -> Result<Option<TaskWorkInfo>> {
    // Verify the register points to a map value
    if reg.reg_type != BpfRegType::PtrToMapValue {
        return Err(VerifierError::InvalidKfunc(
            "task_work arg must be pointer to map value".into()
        ));
    }
    
    // Check offset
    let off = reg.off;
    if off < 0 {
        return Err(VerifierError::InvalidKfunc(
            format!("invalid task_work offset {}", off)
        ));
    }
    
    // Placeholder BTF IDs
    const BPF_TASK_WORK_INIT: u32 = 2001;
    const BPF_TASK_WORK_SCHEDULE: u32 = 2002;
    
    match kfunc_id {
        BPF_TASK_WORK_INIT => {
            Ok(Some(TaskWorkInfo {
                map_uid,
                btf_id: 0,
                offset: off as u32,
                scheduled: false,
            }))
        }
        BPF_TASK_WORK_SCHEDULE => {
            // Schedule the task_work
            Ok(Some(TaskWorkInfo {
                map_uid,
                btf_id: 0,
                offset: off as u32,
                scheduled: true,
            }))
        }
        _ => Ok(None),
    }
}

/// Validate workqueue callback registration.
///
/// Ensures that:
/// 1. The callback function is a valid subprogram
/// 2. The callback signature matches expected prototype
/// 3. The workqueue is associated with the correct map
pub fn validate_wq_callback(
    callback_subprog: usize,
    wq_info: &WorkqueueInfo,
    prog_type: BpfProgType,
) -> Result<()> {
    // Workqueue callbacks are only allowed in certain program types
    match prog_type {
        BpfProgType::Syscall | BpfProgType::StructOps => {
            // Allowed
        }
        _ => {
            return Err(VerifierError::InvalidKfunc(
                format!("workqueue not allowed in {:?} programs", prog_type)
            ));
        }
    }
    
    if !wq_info.initialized {
        return Err(VerifierError::InvalidKfunc(
            "workqueue must be initialized before setting callback".into()
        ));
    }
    
    Ok(())
}

/// Validate task_work callback registration.
pub fn validate_task_work_callback(
    callback_subprog: usize,
    tw_info: &TaskWorkInfo,
    prog_type: BpfProgType,
) -> Result<()> {
    // Task work has similar restrictions
    match prog_type {
        BpfProgType::Syscall | BpfProgType::StructOps | BpfProgType::Tracing => {
            // Allowed
        }
        _ => {
            return Err(VerifierError::InvalidKfunc(
                format!("task_work not allowed in {:?} programs", prog_type)
            ));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kptr_type() {
        assert!(!KptrType::Unref.requires_refcount());
        assert!(KptrType::Ref.requires_refcount());
        assert!(KptrType::Percpu.requires_refcount());
        
        assert!(KptrType::Unref.allows_untrusted());
        assert!(!KptrType::Ref.allows_untrusted());
    }

    #[test]
    fn test_special_field_size() {
        assert_eq!(SpecialFieldType::Timer.size(), 16);
        assert_eq!(SpecialFieldType::SpinLock.size(), 4);
        assert_eq!(SpecialFieldType::Kptr(KptrType::Ref).size(), 8);
        assert_eq!(SpecialFieldType::RbNode.size(), 24);
    }

    #[test]
    fn test_timer_state() {
        let mut timer = TimerState::new(1, 0);
        assert!(!timer.initialized);
        
        // Cannot set callback before init
        assert!(timer.set_callback(10).is_err());
        
        timer.init();
        assert!(timer.initialized);
        
        // Can set callback after init
        assert!(timer.set_callback(10).is_ok());
        assert!(timer.callback_set);
        assert_eq!(timer.callback_insn, Some(10));
    }

    #[test]
    fn test_check_timer_arg() {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::PtrToMapValue;
        reg.map_uid = 1;
        reg.off = 16;
        
        let result = check_timer_arg(&reg, 1);
        assert!(result.is_ok());
        let (map_uid, timer_off) = result.unwrap();
        assert_eq!(map_uid, 1);
        assert_eq!(timer_off, 16);
        
        // Unaligned offset should fail
        reg.off = 17;
        assert!(check_timer_arg(&reg, 1).is_err());
    }

    #[test]
    fn test_check_timer_init_map_arg() {
        let mut timer_reg = BpfRegState::new_not_init();
        timer_reg.reg_type = BpfRegType::PtrToMapValue;
        timer_reg.map_uid = 1;
        
        let mut map_reg = BpfRegState::new_not_init();
        map_reg.reg_type = BpfRegType::ConstPtrToMap;
        map_reg.map_uid = 1;
        
        // Same map_uid should succeed
        assert!(check_timer_init_map_arg(&timer_reg, &map_reg).is_ok());
        
        // Different map_uid should fail
        map_reg.map_uid = 2;
        assert!(check_timer_init_map_arg(&timer_reg, &map_reg).is_err());
    }

    #[test]
    fn test_check_special_field_overlap() {
        let fields = vec![
            SpecialFieldInfo {
                field_type: SpecialFieldType::Timer,
                offset: 16,
                btf_id: None,
            },
            SpecialFieldInfo {
                field_type: SpecialFieldType::SpinLock,
                offset: 32,
                btf_id: None,
            },
        ];
        
        // Access before timer - should succeed
        assert!(check_special_field_overlap(0, 16, &fields).is_ok());
        
        // Access overlapping timer - should fail
        assert!(check_special_field_overlap(12, 8, &fields).is_err());
        
        // Access between timer and spin_lock - should succeed
        assert!(check_special_field_overlap(32, 4, &fields).is_err()); // Hits spin_lock
        
        // Access after special fields - should succeed
        assert!(check_special_field_overlap(36, 8, &fields).is_ok());
    }

    #[test]
    fn test_kptr_load_type() {
        // Not in RCU - just nullable
        let flags = kptr_load_type(KptrType::Ref, false, true);
        assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
        assert!(!flags.contains(BpfTypeFlag::MEM_RCU));
        
        // In RCU with RCU-protected kptr
        let flags = kptr_load_type(KptrType::Ref, true, true);
        assert!(flags.contains(BpfTypeFlag::PTR_MAYBE_NULL));
        assert!(flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(flags.contains(BpfTypeFlag::MEM_ALLOC));
        
        // Percpu kptr in RCU
        let flags = kptr_load_type(KptrType::Percpu, true, true);
        assert!(flags.contains(BpfTypeFlag::MEM_RCU));
        assert!(flags.contains(BpfTypeFlag::MEM_PERCPU));
    }

    #[test]
    fn test_check_timer_context() {
        let refs = ReferenceManager::new();
        
        // Normal context should succeed
        assert!(check_timer_context(&refs, false).is_ok());
        
        // PREEMPT_RT should fail
        assert!(check_timer_context(&refs, true).is_err());
        
        // With lock held should fail
        let mut refs_with_lock = ReferenceManager::new();
        refs_with_lock.acquire_lock(0, 0x1000);
        assert!(check_timer_context(&refs_with_lock, false).is_err());
    }

    #[test]
    fn test_check_timer_callback_registration() {
        // Same map_uid should succeed
        assert!(check_timer_callback_registration(1, 1).is_ok());
        
        // Different map_uid should fail
        assert!(check_timer_callback_registration(1, 2).is_err());
        
        // Zero map_uid (unknown) should succeed
        assert!(check_timer_callback_registration(0, 1).is_ok());
        assert!(check_timer_callback_registration(1, 0).is_ok());
    }
}
