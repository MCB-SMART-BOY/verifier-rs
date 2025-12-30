// SPDX-License-Identifier: GPL-2.0

//! Data Race Detection for BPF Programs
//! BPF 程序的数据竞争检测
//!
//! This module implements static analysis to detect potential data races in BPF programs.
//! 本模块实现静态分析以检测 BPF 程序中潜在的数据竞争。
//! It focuses on:
//! 主要关注：
//! - Global variable access synchronization
//! - 全局变量访问同步
//! - Concurrent map operations
//! - 并发 map 操作
//! - RCU and lock interactions
//! - RCU 和锁的交互
//! - Per-CPU data access patterns
//! - Per-CPU 数据访问模式

use alloc::{format, string::String, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::stdlib::{BTreeMap, BTreeSet};

// ============================================================================
// Access Types and Tracking
// 访问类型和跟踪
// ============================================================================

/// Type of memory access
/// 内存访问类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessType {
    /// Read access
    /// 读访问
    Read,
    /// Write access
    /// 写访问
    Write,
    /// Atomic read
    /// 原子读
    AtomicRead,
    /// Atomic write
    /// 原子写
    AtomicWrite,
    /// Read-modify-write (e.g., atomic_add)
    /// 读-修改-写（例如 atomic_add）
    ReadModifyWrite,
}

impl AccessType {
    /// Check if this is a write access
    /// 检查是否是写访问
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            AccessType::Write | AccessType::AtomicWrite | AccessType::ReadModifyWrite
        )
    }

    /// Check if this is atomic
    /// 检查是否是原子操作
    pub fn is_atomic(&self) -> bool {
        matches!(
            self,
            AccessType::AtomicRead | AccessType::AtomicWrite | AccessType::ReadModifyWrite
        )
    }

    /// Check if two access types can race
    /// 检查两种访问类型是否可能竞争
    pub fn can_race_with(&self, other: &AccessType) -> bool {
        // At least one must be a write
        // 至少有一个必须是写操作
        if !self.is_write() && !other.is_write() {
            return false;
        }
        // Atomic operations don't race with each other
        // 原子操作之间不会竞争
        if self.is_atomic() && other.is_atomic() {
            return false;
        }
        true
    }
}

/// Memory location identifier
/// 内存位置标识符
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryLocation {
    /// Global variable by BTF ID and offset
    /// 通过 BTF ID 和偏移量标识的全局变量
    Global {
        /// BTF type ID for the global
        /// 全局变量的 BTF 类型 ID
        btf_id: u32,
        /// Offset within the global
        /// 全局变量内的偏移量
        offset: i32,
    },
    /// Map element by map ID and key hash
    /// 通过 map ID 和键哈希标识的 map 元素
    MapElement {
        /// Map identifier
        /// Map 标识符
        map_id: u32,
        /// Hash of the key (for tracking specific elements)
        /// 键的哈希值（用于跟踪特定元素）
        key_hash: u64,
    },
    /// Per-CPU variable by ID and offset
    /// 通过 ID 和偏移量标识的 Per-CPU 变量
    PerCpu {
        /// Variable identifier
        /// 变量标识符
        var_id: u32,
        /// Offset within the variable
        /// 变量内的偏移量
        offset: i32,
    },
    /// Stack location by frame and offset
    /// 通过帧和偏移量标识的栈位置
    Stack {
        /// Stack frame number
        /// 栈帧编号
        frame: u32,
        /// Offset within the frame
        /// 帧内偏移量
        offset: i32,
    },
    /// Arena memory location
    /// Arena 内存位置
    Arena {
        /// Offset within the arena
        /// arena 内的偏移量
        offset: u64,
    },
    /// Unknown/dynamic location
    /// 未知/动态位置
    Unknown,
}

/// A single memory access record
/// 单个内存访问记录
#[derive(Debug, Clone)]
pub struct MemoryAccess {
    /// Location being accessed
    /// 被访问的位置
    pub location: MemoryLocation,
    /// Type of access
    /// 访问类型
    pub access_type: AccessType,
    /// Instruction index
    /// 指令索引
    pub insn_idx: usize,
    /// Size of access in bytes
    /// 访问大小（字节）
    pub size: u32,
    /// Current lock state when access occurs
    /// 访问发生时的当前锁状态
    pub lock_state: LockState,
    /// Whether in RCU read section
    /// 是否在 RCU 读取区段内
    pub in_rcu_read: bool,
    /// Whether this is a preemptible context
    /// 是否是可抢占上下文
    pub preemptible: bool,
}

/// Lock state at a program point
/// 程序点处的锁状态
#[derive(Debug, Clone, Default)]
pub struct LockState {
    /// Held spin locks (by lock ID)
    /// 持有的自旋锁（按锁 ID）
    pub spin_locks: BTreeSet<u32>,
    /// Held RCU read locks
    /// 持有的 RCU 读锁
    pub rcu_read_depth: u32,
    /// Held mutex locks (sleepable)
    /// 持有的互斥锁（可睡眠）
    pub mutex_locks: BTreeSet<u32>,
    /// IRQ state (disabled = true)
    /// IRQ 状态（禁用 = true）
    pub irq_disabled: bool,
    /// Preemption disabled depth
    /// 抢占禁用深度
    pub preempt_disabled: u32,
}

impl LockState {
    /// Check if any synchronization is held
    /// 检查是否持有任何同步原语
    pub fn has_synchronization(&self) -> bool {
        !self.spin_locks.is_empty()
            || self.rcu_read_depth > 0
            || !self.mutex_locks.is_empty()
            || self.irq_disabled
            || self.preempt_disabled > 0
    }

    /// Check if holding a specific lock
    /// 检查是否持有特定锁
    pub fn holds_lock(&self, lock_id: u32) -> bool {
        self.spin_locks.contains(&lock_id) || self.mutex_locks.contains(&lock_id)
    }

    /// Acquire spin lock
    /// 获取自旋锁
    pub fn acquire_spin(&mut self, lock_id: u32) {
        self.spin_locks.insert(lock_id);
    }

    /// Release spin lock
    /// 释放自旋锁
    pub fn release_spin(&mut self, lock_id: u32) -> Result<()> {
        if !self.spin_locks.remove(&lock_id) {
            return Err(VerifierError::InvalidState(format!(
                "releasing unheld spin lock {}",
                lock_id
            )));
        }
        Ok(())
    }

    /// Enter RCU read section
    /// 进入 RCU 读取区段
    pub fn rcu_read_lock(&mut self) {
        self.rcu_read_depth += 1;
    }

    /// Exit RCU read section
    /// 退出 RCU 读取区段
    pub fn rcu_read_unlock(&mut self) -> Result<()> {
        if self.rcu_read_depth == 0 {
            return Err(VerifierError::InvalidState(
                "rcu_read_unlock without matching lock".into(),
            ));
        }
        self.rcu_read_depth -= 1;
        Ok(())
    }

    /// Check if states are compatible (can run concurrently safely)
    /// 检查状态是否兼容（可以安全地并发运行）
    pub fn is_compatible_with(&self, other: &LockState) -> bool {
        // If both hold the same lock, they can't run concurrently
        // 如果两者持有相同的锁，它们不能并发运行
        for lock in &self.spin_locks {
            if other.spin_locks.contains(lock) {
                return true; // Same lock = exclusive access / 相同锁 = 独占访问
            }
        }
        for lock in &self.mutex_locks {
            if other.mutex_locks.contains(lock) {
                return true;
            }
        }
        // Both in RCU read section is OK for reads
        // 两者都在 RCU 读取区段内对于读操作是可以的
        // No common lock = potentially concurrent
        // 没有共同的锁 = 可能并发
        false
    }
}

// ============================================================================
// Race Detection Engine
// 竞争检测引擎
// ============================================================================

/// Potential data race
/// 潜在的数据竞争
#[derive(Debug, Clone)]
pub struct DataRace {
    /// First access
    /// 第一个访问
    pub access1: MemoryAccess,
    /// Second access
    /// 第二个访问
    pub access2: MemoryAccess,
    /// Reason this is flagged as a race
    /// 标记为竞争的原因
    pub reason: RaceReason,
    /// Severity level
    /// 严重程度
    pub severity: RaceSeverity,
}

/// Reason for flagging a race
/// 标记竞争的原因
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceReason {
    /// No synchronization on either access
    /// 两个访问都没有同步
    NoSynchronization,
    /// Different locks held
    /// 持有不同的锁
    DifferentLocks,
    /// One access outside RCU section
    /// 一个访问在 RCU 区段外
    RcuMismatch,
    /// Non-atomic access to shared data
    /// 对共享数据的非原子访问
    NonAtomicShared,
    /// Write to per-CPU data from wrong CPU context
    /// 从错误的 CPU 上下文写入 per-CPU 数据
    PerCpuViolation,
    /// Map access without proper locking
    /// 没有正确锁定的 map 访问
    UnsyncedMapAccess,
}

/// Severity of the race
/// 竞争的严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RaceSeverity {
    /// Informational - might be intentional
    /// 信息性 - 可能是有意的
    Info,
    /// Warning - likely unintended
    /// 警告 - 可能是无意的
    Warning,
    /// Error - definite bug
    /// 错误 - 确定的 bug
    Error,
}

/// Race detector state
/// 竞争检测器状态
#[derive(Debug, Clone)]
pub struct RaceDetector {
    /// All recorded memory accesses
    /// 所有记录的内存访问
    accesses: Vec<MemoryAccess>,
    /// Current lock state
    /// 当前锁状态
    pub lock_state: LockState,
    /// Detected races
    /// 检测到的竞争
    races: Vec<DataRace>,
    /// Global variables that are known to be shared
    /// 已知共享的全局变量
    shared_globals: BTreeSet<u32>,
    /// Maps that are accessed concurrently
    /// 被并发访问的 map
    concurrent_maps: BTreeSet<u32>,
    /// Per-CPU variables
    /// Per-CPU 变量
    percpu_vars: BTreeSet<u32>,
    /// Whether we're in a preemptible context
    /// 是否在可抢占上下文中
    pub preemptible: bool,
    /// Program type (affects concurrency model)
    /// 程序类型（影响并发模型）
    prog_type: BpfProgType,
}

impl RaceDetector {
    /// Create new race detector
    /// 创建新的竞争检测器
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            accesses: Vec::new(),
            lock_state: LockState::default(),
            races: Vec::new(),
            shared_globals: BTreeSet::new(),
            concurrent_maps: BTreeSet::new(),
            percpu_vars: BTreeSet::new(),
            preemptible: Self::is_preemptible_prog_type(prog_type),
            prog_type,
        }
    }

    /// Check if program type is preemptible
    /// 检查程序类型是否可抢占
    fn is_preemptible_prog_type(prog_type: BpfProgType) -> bool {
        matches!(
            prog_type,
            BpfProgType::Tracing | BpfProgType::Lsm | BpfProgType::StructOps
        )
    }

    /// Mark a global variable as shared
    /// 将全局变量标记为共享
    pub fn mark_shared_global(&mut self, btf_id: u32) {
        self.shared_globals.insert(btf_id);
    }

    /// Mark a map as concurrently accessed
    /// 将 map 标记为被并发访问
    pub fn mark_concurrent_map(&mut self, map_id: u32) {
        self.concurrent_maps.insert(map_id);
    }

    /// Mark a variable as per-CPU
    /// 将变量标记为 per-CPU
    pub fn mark_percpu(&mut self, var_id: u32) {
        self.percpu_vars.insert(var_id);
    }

    /// Record a memory access
    /// 记录内存访问
    pub fn record_access(&mut self, access: MemoryAccess) {
        self.accesses.push(access);
    }

    /// Record a global variable access
    /// 记录全局变量访问
    pub fn record_global_access(
        &mut self,
        btf_id: u32,
        offset: i32,
        access_type: AccessType,
        insn_idx: usize,
        size: u32,
    ) {
        let access = MemoryAccess {
            location: MemoryLocation::Global { btf_id, offset },
            access_type,
            insn_idx,
            size,
            lock_state: self.lock_state.clone(),
            in_rcu_read: self.lock_state.rcu_read_depth > 0,
            preemptible: self.preemptible,
        };
        self.record_access(access);
    }

    /// Record a map access
    /// 记录 map 访问
    pub fn record_map_access(
        &mut self,
        map_id: u32,
        key_hash: u64,
        access_type: AccessType,
        insn_idx: usize,
        size: u32,
    ) {
        let access = MemoryAccess {
            location: MemoryLocation::MapElement { map_id, key_hash },
            access_type,
            insn_idx,
            size,
            lock_state: self.lock_state.clone(),
            in_rcu_read: self.lock_state.rcu_read_depth > 0,
            preemptible: self.preemptible,
        };
        self.record_access(access);
    }

    /// Record per-CPU variable access
    /// 记录 per-CPU 变量访问
    pub fn record_percpu_access(
        &mut self,
        var_id: u32,
        offset: i32,
        access_type: AccessType,
        insn_idx: usize,
        size: u32,
    ) {
        let access = MemoryAccess {
            location: MemoryLocation::PerCpu { var_id, offset },
            access_type,
            insn_idx,
            size,
            lock_state: self.lock_state.clone(),
            in_rcu_read: self.lock_state.rcu_read_depth > 0,
            preemptible: self.preemptible,
        };
        self.record_access(access);
    }

    /// Acquire a spin lock
    /// 获取自旋锁
    pub fn acquire_spin_lock(&mut self, lock_id: u32) {
        self.lock_state.acquire_spin(lock_id);
        // Acquiring a spin lock disables preemption
        // 获取自旋锁会禁用抢占
        self.lock_state.preempt_disabled += 1;
    }

    /// Release a spin lock
    /// 释放自旋锁
    pub fn release_spin_lock(&mut self, lock_id: u32) -> Result<()> {
        self.lock_state.release_spin(lock_id)?;
        if self.lock_state.preempt_disabled > 0 {
            self.lock_state.preempt_disabled -= 1;
        }
        Ok(())
    }

    /// Enter RCU read section
    /// 进入 RCU 读取区段
    pub fn rcu_read_lock(&mut self) {
        self.lock_state.rcu_read_lock();
    }

    /// Exit RCU read section
    /// 退出 RCU 读取区段
    pub fn rcu_read_unlock(&mut self) -> Result<()> {
        self.lock_state.rcu_read_unlock()
    }

    /// Disable preemption
    /// 禁用抢占
    pub fn preempt_disable(&mut self) {
        self.lock_state.preempt_disabled += 1;
    }

    /// Enable preemption
    /// 启用抢占
    pub fn preempt_enable(&mut self) -> Result<()> {
        if self.lock_state.preempt_disabled == 0 {
            return Err(VerifierError::InvalidState(
                "preempt_enable without matching disable".into(),
            ));
        }
        self.lock_state.preempt_disabled -= 1;
        Ok(())
    }

    /// Analyze all recorded accesses for races
    /// 分析所有记录的访问以检测竞争
    pub fn analyze(&mut self) -> &[DataRace] {
        self.races.clear();

        // Compare all pairs of accesses
        // 比较所有访问对
        for i in 0..self.accesses.len() {
            for j in (i + 1)..self.accesses.len() {
                if let Some(race) = self.check_race(&self.accesses[i], &self.accesses[j]) {
                    self.races.push(race);
                }
            }
        }

        &self.races
    }

    /// Check if two accesses constitute a race
    /// 检查两个访问是否构成竞争
    fn check_race(&self, access1: &MemoryAccess, access2: &MemoryAccess) -> Option<DataRace> {
        // Must access the same location
        // 必须访问相同位置
        if access1.location != access2.location {
            return None;
        }

        // At least one must be a write
        // 至少有一个必须是写操作
        if !access1.access_type.can_race_with(&access2.access_type) {
            return None;
        }

        // Check for overlapping access regions
        // 检查重叠的访问区域
        // (Simplified - in reality would check exact byte ranges)
        // （简化 - 实际上会检查精确的字节范围）

        // Determine race reason
        // 确定竞争原因
        let reason = self.determine_race_reason(access1, access2)?;
        let severity = self.determine_severity(&reason, access1, access2);

        Some(DataRace {
            access1: access1.clone(),
            access2: access2.clone(),
            reason,
            severity,
        })
    }

    /// Determine why two accesses might race
    /// 确定两个访问可能竞争的原因
    fn determine_race_reason(
        &self,
        access1: &MemoryAccess,
        access2: &MemoryAccess,
    ) -> Option<RaceReason> {
        // Check lock-based synchronization
        // 检查基于锁的同步
        if access1.lock_state.is_compatible_with(&access2.lock_state) {
            return None; // Protected by same lock / 受相同锁保护
        }

        // Check RCU synchronization
        // 检查 RCU 同步
        match (&access1.location, &access2.location) {
            (MemoryLocation::Global { btf_id, .. }, _) if self.shared_globals.contains(btf_id) => {
                // Shared global needs synchronization
                // 共享全局变量需要同步
                if !access1.lock_state.has_synchronization()
                    && !access2.lock_state.has_synchronization()
                {
                    return Some(RaceReason::NoSynchronization);
                }
                if access1.in_rcu_read != access2.in_rcu_read {
                    return Some(RaceReason::RcuMismatch);
                }
            }
            (MemoryLocation::MapElement { map_id, .. }, _)
                if self.concurrent_maps.contains(map_id) =>
            {
                // Concurrent map access
                // 并发 map 访问
                if !access1.access_type.is_atomic() && access1.access_type.is_write() {
                    return Some(RaceReason::NonAtomicShared);
                }
                if !access2.access_type.is_atomic() && access2.access_type.is_write() {
                    return Some(RaceReason::NonAtomicShared);
                }
                if !access1.lock_state.has_synchronization() {
                    return Some(RaceReason::UnsyncedMapAccess);
                }
            }
            (MemoryLocation::PerCpu { .. }, _) => {
                // Per-CPU access in preemptible context
                // 可抢占上下文中的 per-CPU 访问
                if access1.preemptible && access1.lock_state.preempt_disabled == 0 {
                    return Some(RaceReason::PerCpuViolation);
                }
                if access2.preemptible && access2.lock_state.preempt_disabled == 0 {
                    return Some(RaceReason::PerCpuViolation);
                }
            }
            _ => {}
        }

        // Check for different locks
        // 检查是否持有不同的锁
        if access1.lock_state.has_synchronization() && access2.lock_state.has_synchronization() {
            // Both have some synchronization, but different
            // 两者都有一些同步，但不同
            return Some(RaceReason::DifferentLocks);
        }

        // No synchronization at all
        // 完全没有同步
        if !access1.lock_state.has_synchronization() || !access2.lock_state.has_synchronization() {
            return Some(RaceReason::NoSynchronization);
        }

        None
    }

    /// Determine severity of a race
    /// 确定竞争的严重程度
    fn determine_severity(
        &self,
        reason: &RaceReason,
        access1: &MemoryAccess,
        access2: &MemoryAccess,
    ) -> RaceSeverity {
        let base_severity = match reason {
            RaceReason::NoSynchronization => {
                // Both writes = Error, read/write = Warning
                // 两个写操作 = 错误，读/写 = 警告
                if access1.access_type.is_write() && access2.access_type.is_write() {
                    RaceSeverity::Error
                } else {
                    RaceSeverity::Warning
                }
            }
            RaceReason::NonAtomicShared => RaceSeverity::Error,
            RaceReason::PerCpuViolation => RaceSeverity::Error,
            RaceReason::UnsyncedMapAccess => RaceSeverity::Warning,
            RaceReason::RcuMismatch => RaceSeverity::Warning,
            RaceReason::DifferentLocks => RaceSeverity::Info,
        };

        // Escalate severity for certain program types
        // 对某些程序类型升级严重程度
        // XDP and TC programs are performance-critical and races are more dangerous
        // XDP 和 TC 程序对性能要求高，竞争更危险
        match self.prog_type {
            BpfProgType::Xdp | BpfProgType::SchedCls | BpfProgType::SchedAct => {
                if base_severity == RaceSeverity::Warning {
                    return RaceSeverity::Error;
                }
            }
            _ => {}
        }

        base_severity
    }

    /// Get all detected races
    /// 获取所有检测到的竞争
    pub fn get_races(&self) -> &[DataRace] {
        &self.races
    }

    /// Get races at or above a severity level
    /// 获取达到或超过指定严重程度的竞争
    pub fn get_races_by_severity(&self, min_severity: RaceSeverity) -> Vec<&DataRace> {
        self.races
            .iter()
            .filter(|r| r.severity >= min_severity)
            .collect()
    }

    /// Check if any errors were detected
    /// 检查是否检测到任何错误
    pub fn has_errors(&self) -> bool {
        self.races.iter().any(|r| r.severity == RaceSeverity::Error)
    }

    /// Validate no races at error level
    /// 验证没有错误级别的竞争
    pub fn validate(&self) -> Result<()> {
        let errors: Vec<_> = self.get_races_by_severity(RaceSeverity::Error);
        if !errors.is_empty() {
            let first = &errors[0];
            return Err(VerifierError::InvalidMemoryAccess(format!(
                "data race detected at insn {} and {}: {:?}",
                first.access1.insn_idx, first.access2.insn_idx, first.reason
            )));
        }
        Ok(())
    }

    /// Clear all state
    /// 清除所有状态
    pub fn clear(&mut self) {
        self.accesses.clear();
        self.races.clear();
        self.lock_state = LockState::default();
    }
}

// ============================================================================
// Map Synchronization Analysis
// Map 同步分析
// ============================================================================

/// Tracks map access patterns for race detection
/// 跟踪 map 访问模式以进行竞争检测
#[derive(Debug, Clone, Default)]
pub struct MapAccessTracker {
    /// Accesses per map
    /// 每个 map 的访问
    accesses: BTreeMap<u32, Vec<MapAccessInfo>>,
    /// Maps that use per-CPU storage
    /// 使用 per-CPU 存储的 map
    percpu_maps: BTreeSet<u32>,
    /// Maps with external synchronization
    /// 具有外部同步的 map
    synced_maps: BTreeSet<u32>,
}

/// Information about a map access
/// 关于 map 访问的信息
#[derive(Debug, Clone)]
pub struct MapAccessInfo {
    /// Access type
    /// 访问类型
    pub access_type: AccessType,
    /// Whether lookup returned non-NULL
    /// lookup 是否返回非 NULL
    pub lookup_succeeded: bool,
    /// Whether value was modified in-place
    /// 值是否被就地修改
    pub in_place_update: bool,
    /// Lock held during access
    /// 访问期间持有的锁
    pub lock_id: Option<u32>,
    /// Instruction index
    /// 指令索引
    pub insn_idx: usize,
}

impl MapAccessTracker {
    /// Create new tracker
    /// 创建新的跟踪器
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a map as per-CPU
    /// 将 map 标记为 per-CPU
    pub fn mark_percpu(&mut self, map_id: u32) {
        self.percpu_maps.insert(map_id);
    }

    /// Mark a map as having external synchronization
    /// 将 map 标记为具有外部同步
    pub fn mark_synced(&mut self, map_id: u32) {
        self.synced_maps.insert(map_id);
    }

    /// Record a map access
    /// 记录 map 访问
    pub fn record_access(&mut self, map_id: u32, info: MapAccessInfo) {
        self.accesses.entry(map_id).or_default().push(info);
    }

    /// Check for potential races in a map
    /// 检查 map 中的潜在竞争
    pub fn check_map_races(&self, map_id: u32) -> Vec<MapRaceWarning> {
        let mut warnings = Vec::new();

        // Per-CPU maps don't race (within same CPU)
        // Per-CPU map 不会竞争（在同一 CPU 内）
        if self.percpu_maps.contains(&map_id) {
            return warnings;
        }

        // Externally synced maps are OK
        // 外部同步的 map 没问题
        if self.synced_maps.contains(&map_id) {
            return warnings;
        }

        let accesses = match self.accesses.get(&map_id) {
            Some(a) => a,
            None => return warnings,
        };

        // Check for in-place updates without locking
        // 检查没有锁定的就地更新
        for (i, access1) in accesses.iter().enumerate() {
            if access1.in_place_update && access1.lock_id.is_none() {
                warnings.push(MapRaceWarning {
                    map_id,
                    insn_idx: access1.insn_idx,
                    reason: "in-place map update without lock".into(),
                });
            }

            // Check for concurrent access patterns
            // 检查并发访问模式
            for access2 in accesses.iter().skip(i + 1) {
                if access1.access_type.can_race_with(&access2.access_type) {
                    // Different locks or no locks
                    // 不同的锁或没有锁
                    if access1.lock_id != access2.lock_id {
                        warnings.push(MapRaceWarning {
                            map_id,
                            insn_idx: access1.insn_idx,
                            reason: format!(
                                "map accessed with different synchronization at {} and {}",
                                access1.insn_idx, access2.insn_idx
                            ),
                        });
                    }
                }
            }
        }

        warnings
    }
}

/// Warning about potential map race
/// 关于潜在 map 竞争的警告
#[derive(Debug, Clone)]
pub struct MapRaceWarning {
    /// Map ID
    /// Map ID
    pub map_id: u32,
    /// Instruction index
    /// 指令索引
    pub insn_idx: usize,
    /// Description
    /// 描述
    pub reason: String,
}

// ============================================================================
// Global Variable Analysis
// 全局变量分析
// ============================================================================

/// Tracks global variable access patterns
/// 跟踪全局变量访问模式
#[derive(Debug, Clone, Default)]
pub struct GlobalAccessTracker {
    /// Accesses per global variable (by BTF ID)
    /// 每个全局变量的访问（按 BTF ID）
    accesses: BTreeMap<u32, Vec<GlobalAccessInfo>>,
    /// Variables that are read-only
    /// 只读变量
    readonly_vars: BTreeSet<u32>,
    /// Variables with __percpu annotation
    /// 带有 __percpu 注解的变量
    percpu_vars: BTreeSet<u32>,
}

/// Information about a global access
/// 关于全局访问的信息
#[derive(Debug, Clone)]
pub struct GlobalAccessInfo {
    /// Offset within the variable
    /// 变量内的偏移量
    pub offset: i32,
    /// Access type
    /// 访问类型
    pub access_type: AccessType,
    /// Lock state
    /// 锁状态
    pub lock_state: LockState,
    /// Instruction index
    /// 指令索引
    pub insn_idx: usize,
}

impl GlobalAccessTracker {
    /// Create new tracker
    /// 创建新的跟踪器
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a variable as read-only
    /// 将变量标记为只读
    pub fn mark_readonly(&mut self, btf_id: u32) {
        self.readonly_vars.insert(btf_id);
    }

    /// Mark a variable as per-CPU
    /// 将变量标记为 per-CPU
    pub fn mark_percpu(&mut self, btf_id: u32) {
        self.percpu_vars.insert(btf_id);
    }

    /// Record a global variable access
    /// 记录全局变量访问
    pub fn record_access(&mut self, btf_id: u32, info: GlobalAccessInfo) {
        // Check for write to read-only
        // 检查对只读变量的写入
        if self.readonly_vars.contains(&btf_id) && info.access_type.is_write() {
            // This should have been caught earlier, but track it
            // 这应该在之前就被捕获了，但还是跟踪一下
        }
        self.accesses.entry(btf_id).or_default().push(info);
    }

    /// Analyze for races
    /// 分析竞争
    pub fn analyze(&self) -> Vec<GlobalRaceWarning> {
        let mut warnings = Vec::new();

        for (btf_id, accesses) in &self.accesses {
            // Skip read-only and per-CPU
            // 跳过只读和 per-CPU
            if self.readonly_vars.contains(btf_id) {
                continue;
            }
            if self.percpu_vars.contains(btf_id) {
                continue;
            }

            // Check for unprotected writes
            // 检查未保护的写入
            for access in accesses {
                if access.access_type.is_write() && !access.lock_state.has_synchronization() {
                    warnings.push(GlobalRaceWarning {
                        btf_id: *btf_id,
                        offset: access.offset,
                        insn_idx: access.insn_idx,
                        reason: "write to global without synchronization".into(),
                    });
                }
            }
        }

        warnings
    }
}

/// Warning about potential global variable race
/// 关于潜在全局变量竞争的警告
#[derive(Debug, Clone)]
pub struct GlobalRaceWarning {
    /// BTF ID of the variable
    /// 变量的 BTF ID
    pub btf_id: u32,
    /// Offset within variable
    /// 变量内的偏移量
    pub offset: i32,
    /// Instruction index
    /// 指令索引
    pub insn_idx: usize,
    /// Description
    /// 描述
    pub reason: String,
}

// ============================================================================
// Tests
// 测试
// ============================================================================
