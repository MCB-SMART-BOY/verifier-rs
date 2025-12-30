// SPDX-License-Identifier: GPL-2.0

//! Lock state tracking
//! 锁状态跟踪
//!
//! This module tracks BPF spin lock state to ensure correct lock/unlock
//! pairing and detect potential deadlocks.
//! 本模块跟踪 BPF 自旋锁状态，以确保正确的加锁/解锁配对并检测潜在的死锁。

use alloc::{format, vec::Vec};

use crate::core::error::{Result, VerifierError};

/// Maximum number of nested locks
/// 最大嵌套锁数量
pub const MAX_LOCK_DEPTH: usize = 4;

/// Lock ID type
/// 锁 ID 类型
pub type LockId = u32;

/// Information about a held lock
/// 持有锁的信息
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldLock {
    /// Lock ID (unique identifier)
    /// 锁 ID（唯一标识符）
    pub id: LockId,
    /// Map pointer where lock is located
    /// 锁所在的 map 指针
    pub map_uid: u32,
    /// Offset within map value
    /// map 值内的偏移
    pub map_off: u32,
    /// Instruction index where lock was acquired
    /// 获取锁的指令索引
    pub acquired_at: usize,
}

/// Lock state for a verification path
/// 验证路径的锁状态
#[derive(Debug, Clone, Default)]
pub struct LockState {
    /// Currently held locks (stack for nested locks)
    /// 当前持有的锁（用于嵌套锁的栈）
    held_locks: Vec<HeldLock>,
    /// Next lock ID to assign
    /// 下一个要分配的锁 ID
    next_id: LockId,
    /// Whether spin locks are enabled for this program
    /// 此程序是否启用自旋锁
    pub enabled: bool,
}

impl LockState {
    /// Create a new lock state
    /// 创建新的锁状态
    pub fn new() -> Self {
        Self {
            held_locks: Vec::new(),
            next_id: 1,
            enabled: true,
        }
    }

    /// Acquire a lock
    /// 获取锁
    pub fn acquire(&mut self, map_uid: u32, map_off: u32, insn_idx: usize) -> Result<LockId> {
        // Check nesting limit
        // 检查嵌套限制
        if self.held_locks.len() >= MAX_LOCK_DEPTH {
            return Err(VerifierError::InvalidLock("too many nested locks".into()));
        }

        // Check for already held (same lock)
        // 检查是否已持有（同一个锁）
        for lock in &self.held_locks {
            if lock.map_uid == map_uid && lock.map_off == map_off {
                return Err(VerifierError::InvalidLock(format!(
                    "lock at map_uid={}, offset={} already held (acquired at insn {})",
                    map_uid, map_off, lock.acquired_at
                )));
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        self.held_locks.push(HeldLock {
            id,
            map_uid,
            map_off,
            acquired_at: insn_idx,
        });

        Ok(id)
    }

    /// Release a lock
    /// 释放锁
    pub fn release(&mut self, map_uid: u32, map_off: u32) -> Result<LockId> {
        // Find the lock
        // 查找锁
        let pos = self
            .held_locks
            .iter()
            .position(|l| l.map_uid == map_uid && l.map_off == map_off);

        match pos {
            Some(idx) => {
                // For proper nesting, should release most recent lock
                // 为了正确嵌套，应该释放最近的锁
                if idx != self.held_locks.len() - 1 {
                    return Err(VerifierError::InvalidLock(
                        "locks must be released in reverse order".into(),
                    ));
                }
                match self.held_locks.pop() {
                    Some(lock) => Ok(lock.id),
                    None => Err(VerifierError::InvalidLock(
                        "lock state inconsistency".into(),
                    )),
                }
            }
            None => Err(VerifierError::InvalidLock(format!(
                "releasing lock not held: map_uid={}, offset={}",
                map_uid, map_off
            ))),
        }
    }

    /// Check if any locks are held
    /// 检查是否持有任何锁
    pub fn has_locks(&self) -> bool {
        !self.held_locks.is_empty()
    }

    /// Get number of held locks
    /// 获取持有的锁数量
    pub fn lock_count(&self) -> usize {
        self.held_locks.len()
    }

    /// Check if a specific lock is held
    /// 检查是否持有特定锁
    pub fn is_locked(&self, map_uid: u32, map_off: u32) -> bool {
        self.held_locks
            .iter()
            .any(|l| l.map_uid == map_uid && l.map_off == map_off)
    }

    /// Get the most recently acquired lock
    /// 获取最近获取的锁
    pub fn current_lock(&self) -> Option<&HeldLock> {
        self.held_locks.last()
    }

    /// Check that all locks are released at program exit
    /// 检查程序退出时所有锁是否已释放
    pub fn check_all_released(&self) -> Result<()> {
        if let Some(lock) = self.held_locks.first() {
            return Err(VerifierError::InvalidLock(format!(
                "lock not released: map_uid={}, offset={} (acquired at insn {})",
                lock.map_uid, lock.map_off, lock.acquired_at
            )));
        }
        Ok(())
    }

    /// Copy state for branch exploration
    /// 复制状态用于分支探索
    pub fn clone_for_branch(&self) -> Self {
        Self {
            held_locks: self.held_locks.clone(),
            next_id: self.next_id,
            enabled: self.enabled,
        }
    }

    /// Check if states are equivalent for pruning
    /// 检查状态是否等效以进行剪枝
    pub fn equivalent(&self, other: &LockState) -> bool {
        if self.held_locks.len() != other.held_locks.len() {
            return false;
        }

        // Lock IDs may differ but locks should be at same locations
        // 锁 ID 可能不同，但锁应该在相同位置
        for (a, b) in self.held_locks.iter().zip(other.held_locks.iter()) {
            if a.map_uid != b.map_uid || a.map_off != b.map_off {
                return false;
            }
        }

        true
    }
}

/// Operations that are allowed while holding a lock
/// 持有锁时允许的操作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAllowedOp {
    /// Memory access to same map value
    /// 对同一 map 值的内存访问
    MapValueAccess,
    /// ALU operations
    /// ALU 操作
    Alu,
    /// Conditional jumps (within locked region)
    /// 条件跳转（在锁定区域内）
    ConditionalJump,
    /// Function calls to lock-safe helpers
    /// 调用锁安全的辅助函数
    LockSafeHelper,
}

/// Check if an operation is allowed while holding a lock
/// 检查持有锁时是否允许某操作
pub fn is_op_lock_safe(op: LockAllowedOp) -> bool {
    matches!(
        op,
        LockAllowedOp::MapValueAccess
            | LockAllowedOp::Alu
            | LockAllowedOp::ConditionalJump
            | LockAllowedOp::LockSafeHelper
    )
}

/// Operations forbidden while holding a spin lock
/// 持有自旋锁时禁止的操作
pub fn check_lock_restrictions(
    lock_state: &LockState,
    is_helper_call: bool,
    might_sleep: bool,
) -> Result<()> {
    if !lock_state.has_locks() {
        return Ok(());
    }

    // Cannot call helpers that might sleep while holding lock
    // 持有锁时不能调用可能睡眠的辅助函数
    if is_helper_call && might_sleep {
        return Err(VerifierError::InvalidLock(
            "cannot call sleeping helper while holding spin lock".into(),
        ));
    }

    Ok(())
}

/// Spin lock helper IDs
/// 自旋锁辅助函数 ID
pub mod spin_lock_helpers {
    /// bpf_spin_lock helper ID
    /// bpf_spin_lock 辅助函数 ID
    pub const BPF_SPIN_LOCK: u32 = 93;
    /// bpf_spin_unlock helper ID
    /// bpf_spin_unlock 辅助函数 ID
    pub const BPF_SPIN_UNLOCK: u32 = 94;
}

/// Check if helper is bpf_spin_lock
/// 检查辅助函数是否为 bpf_spin_lock
pub fn is_spin_lock_helper(helper_id: u32) -> bool {
    helper_id == spin_lock_helpers::BPF_SPIN_LOCK
}

/// Check if helper is bpf_spin_unlock
/// 检查辅助函数是否为 bpf_spin_unlock
pub fn is_spin_unlock_helper(helper_id: u32) -> bool {
    helper_id == spin_lock_helpers::BPF_SPIN_UNLOCK
}

/// RCU read-side critical section state
/// RCU 读侧临界区状态
#[derive(Debug, Clone, Default)]
pub struct RcuState {
    /// Whether we're in an RCU read-side critical section
    /// 是否在 RCU 读侧临界区中
    pub in_rcu_section: bool,
    /// Instruction where RCU section started
    /// RCU 区段开始的指令
    pub rcu_lock_insn: Option<usize>,
    /// Nesting depth for RCU locks
    /// RCU 锁的嵌套深度
    pub rcu_nesting: u32,
    /// RCU pointers acquired in this section
    /// 在此区段中获取的 RCU 指针
    rcu_pointers: Vec<RcuPointer>,
}

/// Information about an RCU-protected pointer
/// RCU 保护指针的信息
#[derive(Debug, Clone)]
pub struct RcuPointer {
    /// Register that holds the pointer
    /// 持有指针的寄存器
    pub reg_id: u32,
    /// BTF type ID
    /// BTF 类型 ID
    pub btf_id: u32,
    /// Whether pointer is still valid
    /// 指针是否仍然有效
    pub valid: bool,
}

impl RcuState {
    /// Create new RCU state
    /// 创建新的 RCU 状态
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter RCU read-side critical section
    /// 进入 RCU 读侧临界区
    pub fn rcu_read_lock(&mut self, insn_idx: usize) -> Result<()> {
        if self.rcu_nesting == 0 {
            self.rcu_lock_insn = Some(insn_idx);
        }
        self.rcu_nesting += 1;
        self.in_rcu_section = true;
        Ok(())
    }

    /// Exit RCU read-side critical section
    /// 退出 RCU 读侧临界区
    pub fn rcu_read_unlock(&mut self) -> Result<()> {
        if self.rcu_nesting == 0 {
            return Err(VerifierError::InvalidLock(
                "rcu_read_unlock without matching rcu_read_lock".into(),
            ));
        }
        self.rcu_nesting -= 1;
        if self.rcu_nesting == 0 {
            self.in_rcu_section = false;
            self.rcu_lock_insn = None;
            // Invalidate all RCU pointers
            // 使所有 RCU 指针失效
            for ptr in &mut self.rcu_pointers {
                ptr.valid = false;
            }
        }
        Ok(())
    }

    /// Track an RCU-protected pointer
    /// 跟踪 RCU 保护的指针
    pub fn track_rcu_pointer(&mut self, reg_id: u32, btf_id: u32) {
        if self.in_rcu_section {
            self.rcu_pointers.push(RcuPointer {
                reg_id,
                btf_id,
                valid: true,
            });
        }
    }

    /// Check if RCU pointer access is valid
    /// 检查 RCU 指针访问是否有效
    pub fn check_rcu_access(&self, reg_id: u32) -> Result<()> {
        for ptr in &self.rcu_pointers {
            if ptr.reg_id == reg_id {
                if !ptr.valid {
                    return Err(VerifierError::InvalidLock(
                        "accessing RCU pointer after rcu_read_unlock".into(),
                    ));
                }
                return Ok(());
            }
        }
        // Not an RCU pointer we're tracking
        // 不是我们正在跟踪的 RCU 指针
        Ok(())
    }

    /// Check all RCU sections are closed at exit
    /// 检查退出时所有 RCU 区段是否已关闭
    pub fn check_all_unlocked(&self) -> Result<()> {
        if self.rcu_nesting > 0 {
            return Err(VerifierError::InvalidLock(format!(
                "rcu_read_lock not unlocked (nesting={})",
                self.rcu_nesting
            )));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    /// 检查状态是否等效以进行剪枝
    pub fn equivalent(&self, other: &RcuState) -> bool {
        self.rcu_nesting == other.rcu_nesting
    }
}

/// Combined lock and RCU state
/// 组合的锁和 RCU 状态
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// Spin lock state
    /// 自旋锁状态
    pub lock: LockState,
    /// RCU state
    /// RCU 状态
    pub rcu: RcuState,
    /// Whether preemption is disabled
    /// 抢占是否被禁用
    pub preempt_disabled: bool,
    /// Preemption disable depth
    /// 抢占禁用深度
    pub preempt_disable_depth: u32,
}

impl SyncState {
    /// Create new synchronization state
    /// 创建新的同步状态
    pub fn new() -> Self {
        Self::default()
    }

    /// Check all synchronization primitives are properly released
    /// 检查所有同步原语是否正确释放
    pub fn check_all_released(&self) -> Result<()> {
        self.lock.check_all_released()?;
        self.rcu.check_all_unlocked()?;
        if self.preempt_disabled {
            return Err(VerifierError::InvalidLock(
                "preemption not re-enabled at exit".into(),
            ));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    /// 检查状态是否等效以进行剪枝
    pub fn equivalent(&self, other: &SyncState) -> bool {
        self.lock.equivalent(&other.lock)
            && self.rcu.equivalent(&other.rcu)
            && self.preempt_disable_depth == other.preempt_disable_depth
    }

    /// Disable preemption
    /// 禁用抢占
    pub fn preempt_disable(&mut self) {
        self.preempt_disable_depth += 1;
        self.preempt_disabled = true;
    }

    /// Enable preemption
    /// 启用抢占
    pub fn preempt_enable(&mut self) -> Result<()> {
        if self.preempt_disable_depth == 0 {
            return Err(VerifierError::InvalidLock(
                "preempt_enable without matching preempt_disable".into(),
            ));
        }
        self.preempt_disable_depth -= 1;
        if self.preempt_disable_depth == 0 {
            self.preempt_disabled = false;
        }
        Ok(())
    }
}

/// Helpers that might sleep (cannot be called while holding locks)
/// 可能睡眠的辅助函数（持有锁时不能调用）
pub fn helper_might_sleep(helper_id: u32) -> bool {
    // List of helpers that might sleep
    // 可能睡眠的辅助函数列表
    const SLEEPING_HELPERS: &[u32] = &[
        1, // bpf_map_lookup_elem (some map types) - bpf_map_lookup_elem（某些 map 类型）
        2, // bpf_map_update_elem (some map types) - bpf_map_update_elem（某些 map 类型）
        3, // bpf_map_delete_elem (some map types) - bpf_map_delete_elem（某些 map 类型）
        11, // bpf_get_current_comm
           // ... more helpers
           // ... 更多辅助函数
    ];
    SLEEPING_HELPERS.contains(&helper_id)
}

/// Validate synchronization state for a helper call
/// 验证辅助函数调用的同步状态
pub fn validate_sync_for_helper(sync: &SyncState, helper_id: u32) -> Result<()> {
    // Check spin lock restrictions
    // 检查自旋锁限制
    if sync.lock.has_locks() && helper_might_sleep(helper_id) {
        return Err(VerifierError::InvalidLock(format!(
            "helper {} might sleep while holding spin lock",
            helper_id
        )));
    }

    // Spin lock/unlock helpers have special handling
    // 自旋锁/解锁辅助函数有特殊处理
    if is_spin_lock_helper(helper_id) || is_spin_unlock_helper(helper_id) {
        // These are the lock operations themselves
        // 这些是锁操作本身
        return Ok(());
    }

    Ok(())
}

/// bpf_rcu_read_lock/unlock kfunc IDs
/// bpf_rcu_read_lock/unlock kfunc ID
pub mod rcu_kfuncs {
    /// bpf_rcu_read_lock kfunc
    /// bpf_rcu_read_lock kfunc
    pub const RCU_READ_LOCK: u32 = 0x1001;
    /// bpf_rcu_read_unlock kfunc
    /// bpf_rcu_read_unlock kfunc
    pub const RCU_READ_UNLOCK: u32 = 0x1002;
}

/// Check if kfunc is bpf_rcu_read_lock
/// 检查 kfunc 是否为 bpf_rcu_read_lock
pub fn is_rcu_lock_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == rcu_kfuncs::RCU_READ_LOCK
}

/// Check if kfunc is bpf_rcu_read_unlock
/// 检查 kfunc 是否为 bpf_rcu_read_unlock
pub fn is_rcu_unlock_kfunc(kfunc_id: u32) -> bool {
    kfunc_id == rcu_kfuncs::RCU_READ_UNLOCK
}

/// Validate pointer access based on synchronization state
/// 基于同步状态验证指针访问
pub fn validate_ptr_access_sync(sync: &SyncState, is_rcu_ptr: bool, _ptr_id: u32) -> Result<()> {
    if is_rcu_ptr && !sync.rcu.in_rcu_section {
        return Err(VerifierError::InvalidLock(
            "accessing RCU pointer outside RCU read-side critical section".into(),
        ));
    }
    Ok(())
}

/// Lock ordering validator to detect potential deadlocks
/// 锁顺序验证器，用于检测潜在的死锁
#[derive(Debug, Clone, Default)]
pub struct LockOrderValidator {
    /// Known lock orderings (lock_a must be acquired before lock_b)
    /// 已知的锁顺序（lock_a 必须在 lock_b 之前获取）
    orderings: Vec<(LockId, LockId)>,
}

impl LockOrderValidator {
    /// Create new validator
    /// 创建新的验证器
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a lock ordering
    /// 记录锁顺序
    pub fn record_ordering(&mut self, first: LockId, second: LockId) {
        // Check for existing conflicting ordering
        // 检查是否存在冲突的顺序
        for (a, b) in &self.orderings {
            if *a == second && *b == first {
                // Conflicting ordering detected - potential deadlock
                // In a real implementation, we'd return an error
                // 检测到冲突的顺序 - 潜在的死锁
                // 在实际实现中，我们会返回错误
            }
        }
        self.orderings.push((first, second));
    }

    /// Check if acquiring `second` after `first` is valid
    /// 检查在 `first` 之后获取 `second` 是否有效
    pub fn check_ordering(&self, first: LockId, second: LockId) -> Result<()> {
        for (a, b) in &self.orderings {
            if *a == second && *b == first {
                return Err(VerifierError::InvalidLock(format!(
                    "potential deadlock: lock {} must be acquired before lock {}",
                    first, second
                )));
            }
        }
        Ok(())
    }
}

// ============================================================================
// IRQ Flag State Tracking
// IRQ 标志状态跟踪
// ============================================================================

/// IRQ flag kfunc classes
/// IRQ 标志 kfunc 类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqKfuncClass {
    /// bpf_local_irq_save
    /// bpf_local_irq_save
    LocalIrqSave,
    /// bpf_local_irq_restore
    /// bpf_local_irq_restore
    LocalIrqRestore,
    /// bpf_spin_lock_irqsave
    /// bpf_spin_lock_irqsave
    SpinLockIrqSave,
    /// bpf_spin_unlock_irqrestore
    /// bpf_spin_unlock_irqrestore
    SpinUnlockIrqRestore,
}

/// IRQ flag information stored on stack
/// 存储在栈上的 IRQ 标志信息
#[derive(Debug, Clone)]
pub struct IrqFlagSlot {
    /// Reference ID for this IRQ state
    /// 此 IRQ 状态的引用 ID
    pub ref_obj_id: u32,
    /// Kfunc class that created this flag
    /// 创建此标志的 kfunc 类别
    pub kfunc_class: IrqKfuncClass,
    /// Instruction where IRQ was disabled
    /// 禁用 IRQ 的指令
    pub acquired_at: usize,
    /// Stack slot index
    /// 栈槽索引
    pub spi: usize,
}

/// IRQ state tracking
/// IRQ 状态跟踪
#[derive(Debug, Clone, Default)]
pub struct IrqState {
    /// Active IRQ disable ID (most recent)
    /// 活动的 IRQ 禁用 ID（最近的）
    pub active_irq_id: Option<u32>,
    /// Stack of IRQ flags (for nested IRQ disable)
    /// IRQ 标志栈（用于嵌套 IRQ 禁用）
    irq_flags: Vec<IrqFlagSlot>,
    /// Next IRQ flag ID
    /// 下一个 IRQ 标志 ID
    next_id: u32,
}

impl IrqState {
    /// Create new IRQ state
    /// 创建新的 IRQ 状态
    pub fn new() -> Self {
        Self {
            active_irq_id: None,
            irq_flags: Vec::new(),
            next_id: 1,
        }
    }

    /// Acquire IRQ state (disable interrupts)
    /// 获取 IRQ 状态（禁用中断）
    pub fn acquire_irq(
        &mut self,
        insn_idx: usize,
        spi: usize,
        kfunc_class: IrqKfuncClass,
    ) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;

        self.irq_flags.push(IrqFlagSlot {
            ref_obj_id: id,
            kfunc_class,
            acquired_at: insn_idx,
            spi,
        });

        self.active_irq_id = Some(id);
        Ok(id)
    }

    /// Release IRQ state (restore interrupts)
    /// 释放 IRQ 状态（恢复中断）
    /// Must be released in LIFO order (stack-like)
    /// 必须按 LIFO 顺序释放（类似栈）
    pub fn release_irq(&mut self, ref_obj_id: u32) -> Result<()> {
        // IRQ flags must be restored in reverse order
        // IRQ 标志必须按相反顺序恢复
        if let Some(last) = self.irq_flags.last() {
            if last.ref_obj_id != ref_obj_id {
                return Err(VerifierError::InvalidLock(format!(
                    "IRQ flags must be restored in order: expected {}, got {}",
                    last.ref_obj_id, ref_obj_id
                )));
            }
        } else {
            return Err(VerifierError::InvalidLock(
                "restoring IRQ state without matching save".into(),
            ));
        }

        self.irq_flags.pop();

        // Update active IRQ ID
        // 更新活动的 IRQ ID
        self.active_irq_id = self.irq_flags.last().map(|f| f.ref_obj_id);

        Ok(())
    }

    /// Check if IRQs are currently disabled
    /// 检查 IRQ 当前是否被禁用
    pub fn irqs_disabled(&self) -> bool {
        !self.irq_flags.is_empty()
    }

    /// Get current IRQ disable depth
    /// 获取当前 IRQ 禁用深度
    pub fn irq_depth(&self) -> usize {
        self.irq_flags.len()
    }

    /// Get IRQ flag by reference ID
    /// 通过引用 ID 获取 IRQ 标志
    pub fn get_irq_flag(&self, ref_obj_id: u32) -> Option<&IrqFlagSlot> {
        self.irq_flags.iter().find(|f| f.ref_obj_id == ref_obj_id)
    }

    /// Check all IRQ flags are restored at exit
    /// 检查退出时所有 IRQ 标志是否已恢复
    pub fn check_all_restored(&self) -> Result<()> {
        if let Some(flag) = self.irq_flags.first() {
            return Err(VerifierError::InvalidLock(format!(
                "IRQ flag not restored: id={} (saved at insn {})",
                flag.ref_obj_id, flag.acquired_at
            )));
        }
        Ok(())
    }

    /// Check if states are equivalent for pruning
    /// 检查状态是否等效以进行剪枝
    pub fn equivalent(&self, other: &IrqState) -> bool {
        self.irq_flags.len() == other.irq_flags.len()
    }
}

/// Mark stack slot as IRQ flag
/// 将栈槽标记为 IRQ 标志
pub fn mark_stack_slot_irq_flag(
    irq_state: &mut IrqState,
    insn_idx: usize,
    spi: usize,
    kfunc_class: IrqKfuncClass,
) -> Result<u32> {
    irq_state.acquire_irq(insn_idx, spi, kfunc_class)
}

/// Unmark stack slot IRQ flag (on restore)
/// 取消栈槽 IRQ 标志标记（恢复时）
pub fn unmark_stack_slot_irq_flag(irq_state: &mut IrqState, ref_obj_id: u32) -> Result<()> {
    irq_state.release_irq(ref_obj_id)
}

/// Unmark stack slot IRQ flag with kfunc class validation
/// 带 kfunc 类别验证地取消栈槽 IRQ 标志标记
///
/// This ensures that IRQ flags are restored using the matching kfunc class:
/// - native kfuncs (local_irq_save/restore) must be matched
/// - lock kfuncs (spin_lock_irqsave/unlock_irqrestore) must be matched
///
/// 这确保 IRQ 标志使用匹配的 kfunc 类别恢复：
/// - native kfuncs（local_irq_save/restore）必须匹配
/// - lock kfuncs（spin_lock_irqsave/unlock_irqrestore）必须匹配
pub fn unmark_stack_slot_irq_flag_with_class(
    irq_state: &mut IrqState,
    ref_obj_id: u32,
    restore_kfunc_class: IrqKfuncClass,
) -> Result<()> {
    // Find the IRQ flag to get its kfunc class
    // 查找 IRQ 标志以获取其 kfunc 类别
    let saved_class = irq_state
        .get_irq_flag(ref_obj_id)
        .map(|f| f.kfunc_class)
        .ok_or_else(|| VerifierError::InvalidLock("IRQ flag not found for restore".into()))?;

    // Validate kfunc class compatibility
    // 验证 kfunc 类别兼容性
    let is_native_save = matches!(saved_class, IrqKfuncClass::LocalIrqSave);
    let is_native_restore = matches!(restore_kfunc_class, IrqKfuncClass::LocalIrqRestore);
    let is_lock_save = matches!(saved_class, IrqKfuncClass::SpinLockIrqSave);
    let is_lock_restore = matches!(restore_kfunc_class, IrqKfuncClass::SpinUnlockIrqRestore);

    if (is_native_save && !is_native_restore) || (is_lock_save && !is_lock_restore) {
        let flag_type = if is_native_save { "native" } else { "lock" };
        let used_type = if is_native_restore { "native" } else { "lock" };
        return Err(VerifierError::InvalidLock(format!(
            "IRQ flag acquired by {} kfuncs cannot be restored with {} kfuncs",
            flag_type, used_type
        )));
    }

    irq_state.release_irq(ref_obj_id)
}

/// Check if IRQ flag register is valid for init
/// 检查 IRQ 标志寄存器是否对初始化有效
pub fn is_irq_flag_reg_valid_uninit(spi: usize, stack_size: usize) -> bool {
    // Check stack slot is within bounds
    // 检查栈槽是否在边界内
    spi < stack_size
}

/// Check if IRQ flag register is valid (already initialized)
/// 检查 IRQ 标志寄存器是否有效（已初始化）
pub fn is_irq_flag_reg_valid_init(irq_state: &IrqState, ref_obj_id: u32) -> Result<()> {
    if irq_state.get_irq_flag(ref_obj_id).is_none() {
        return Err(VerifierError::InvalidLock(
            "invalid IRQ flag reference".into(),
        ));
    }
    Ok(())
}

/// IRQ-related kfunc IDs
/// IRQ 相关 kfunc ID
pub mod irq_kfuncs {
    /// bpf_local_irq_save
    /// bpf_local_irq_save
    pub const LOCAL_IRQ_SAVE: u32 = 0x2001;
    /// bpf_local_irq_restore
    /// bpf_local_irq_restore
    pub const LOCAL_IRQ_RESTORE: u32 = 0x2002;
    /// bpf_spin_lock_irqsave
    /// bpf_spin_lock_irqsave
    pub const SPIN_LOCK_IRQSAVE: u32 = 0x2003;
    /// bpf_spin_unlock_irqrestore
    /// bpf_spin_unlock_irqrestore
    pub const SPIN_UNLOCK_IRQRESTORE: u32 = 0x2004;
}

/// Get IRQ kfunc class from kfunc ID
/// 从 kfunc ID 获取 IRQ kfunc 类别
pub fn get_irq_kfunc_class(kfunc_id: u32) -> Option<IrqKfuncClass> {
    match kfunc_id {
        irq_kfuncs::LOCAL_IRQ_SAVE => Some(IrqKfuncClass::LocalIrqSave),
        irq_kfuncs::LOCAL_IRQ_RESTORE => Some(IrqKfuncClass::LocalIrqRestore),
        irq_kfuncs::SPIN_LOCK_IRQSAVE => Some(IrqKfuncClass::SpinLockIrqSave),
        irq_kfuncs::SPIN_UNLOCK_IRQRESTORE => Some(IrqKfuncClass::SpinUnlockIrqRestore),
        _ => None,
    }
}

/// Check if kfunc is an IRQ save operation
/// 检查 kfunc 是否为 IRQ 保存操作
pub fn is_irq_save_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        irq_kfuncs::LOCAL_IRQ_SAVE | irq_kfuncs::SPIN_LOCK_IRQSAVE
    )
}

/// Check if kfunc is an IRQ restore operation
/// 检查 kfunc 是否为 IRQ 恢复操作
pub fn is_irq_restore_kfunc(kfunc_id: u32) -> bool {
    matches!(
        kfunc_id,
        irq_kfuncs::LOCAL_IRQ_RESTORE | irq_kfuncs::SPIN_UNLOCK_IRQRESTORE
    )
}

// ============================================================================
// Extended SyncState with IRQ
// 带 IRQ 的扩展 SyncState
// ============================================================================

/// Full synchronization state including IRQ
/// 包括 IRQ 的完整同步状态
#[derive(Debug, Clone, Default)]
pub struct FullSyncState {
    /// Basic sync state (locks, RCU, preemption)
    /// 基本同步状态（锁、RCU、抢占）
    pub sync: SyncState,
    /// IRQ state
    /// IRQ 状态
    pub irq: IrqState,
}

impl FullSyncState {
    /// Create new full sync state
    /// 创建新的完整同步状态
    pub fn new() -> Self {
        Self::default()
    }

    /// Check all synchronization primitives are properly released
    /// 检查所有同步原语是否正确释放
    pub fn check_all_released(&self) -> Result<()> {
        self.sync.check_all_released()?;
        self.irq.check_all_restored()?;
        Ok(())
    }

    /// Check if states are equivalent for pruning
    /// 检查状态是否等效以进行剪枝
    pub fn equivalent(&self, other: &FullSyncState) -> bool {
        self.sync.equivalent(&other.sync) && self.irq.equivalent(&other.irq)
    }

    /// Check if any synchronization is active
    /// 检查是否有任何同步处于活动状态
    pub fn has_active_sync(&self) -> bool {
        self.sync.lock.has_locks()
            || self.sync.rcu.in_rcu_section
            || self.sync.preempt_disabled
            || self.irq.irqs_disabled()
    }
}
