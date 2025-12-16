// SPDX-License-Identifier: GPL-2.0

//! Data Race Detection for BPF Programs
//!
//! This module implements static analysis to detect potential data races in BPF programs.
//! It focuses on:
//! - Global variable access synchronization
//! - Concurrent map operations
//! - RCU and lock interactions
//! - Per-CPU data access patterns

use alloc::{format, string::String, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::stdlib::{BTreeMap, BTreeSet};

// ============================================================================
// Access Types and Tracking
// ============================================================================

/// Type of memory access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessType {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Atomic read
    AtomicRead,
    /// Atomic write
    AtomicWrite,
    /// Read-modify-write (e.g., atomic_add)
    ReadModifyWrite,
}

impl AccessType {
    /// Check if this is a write access
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            AccessType::Write | AccessType::AtomicWrite | AccessType::ReadModifyWrite
        )
    }

    /// Check if this is atomic
    pub fn is_atomic(&self) -> bool {
        matches!(
            self,
            AccessType::AtomicRead | AccessType::AtomicWrite | AccessType::ReadModifyWrite
        )
    }

    /// Check if two access types can race
    pub fn can_race_with(&self, other: &AccessType) -> bool {
        // At least one must be a write
        if !self.is_write() && !other.is_write() {
            return false;
        }
        // Atomic operations don't race with each other
        if self.is_atomic() && other.is_atomic() {
            return false;
        }
        true
    }
}

/// Memory location identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryLocation {
    /// Global variable by BTF ID and offset
    Global {
        /// BTF type ID for the global
        btf_id: u32,
        /// Offset within the global
        offset: i32,
    },
    /// Map element by map ID and key hash
    MapElement {
        /// Map identifier
        map_id: u32,
        /// Hash of the key (for tracking specific elements)
        key_hash: u64,
    },
    /// Per-CPU variable by ID and offset
    PerCpu {
        /// Variable identifier
        var_id: u32,
        /// Offset within the variable
        offset: i32,
    },
    /// Stack location by frame and offset
    Stack {
        /// Stack frame number
        frame: u32,
        /// Offset within the frame
        offset: i32,
    },
    /// Arena memory location
    Arena {
        /// Offset within the arena
        offset: u64,
    },
    /// Unknown/dynamic location
    Unknown,
}

/// A single memory access record
#[derive(Debug, Clone)]
pub struct MemoryAccess {
    /// Location being accessed
    pub location: MemoryLocation,
    /// Type of access
    pub access_type: AccessType,
    /// Instruction index
    pub insn_idx: usize,
    /// Size of access in bytes
    pub size: u32,
    /// Current lock state when access occurs
    pub lock_state: LockState,
    /// Whether in RCU read section
    pub in_rcu_read: bool,
    /// Whether this is a preemptible context
    pub preemptible: bool,
}

/// Lock state at a program point
#[derive(Debug, Clone, Default)]
pub struct LockState {
    /// Held spin locks (by lock ID)
    pub spin_locks: BTreeSet<u32>,
    /// Held RCU read locks
    pub rcu_read_depth: u32,
    /// Held mutex locks (sleepable)
    pub mutex_locks: BTreeSet<u32>,
    /// IRQ state (disabled = true)
    pub irq_disabled: bool,
    /// Preemption disabled depth
    pub preempt_disabled: u32,
}

impl LockState {
    /// Check if any synchronization is held
    pub fn has_synchronization(&self) -> bool {
        !self.spin_locks.is_empty()
            || self.rcu_read_depth > 0
            || !self.mutex_locks.is_empty()
            || self.irq_disabled
            || self.preempt_disabled > 0
    }

    /// Check if holding a specific lock
    pub fn holds_lock(&self, lock_id: u32) -> bool {
        self.spin_locks.contains(&lock_id) || self.mutex_locks.contains(&lock_id)
    }

    /// Acquire spin lock
    pub fn acquire_spin(&mut self, lock_id: u32) {
        self.spin_locks.insert(lock_id);
    }

    /// Release spin lock
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
    pub fn rcu_read_lock(&mut self) {
        self.rcu_read_depth += 1;
    }

    /// Exit RCU read section
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
    pub fn is_compatible_with(&self, other: &LockState) -> bool {
        // If both hold the same lock, they can't run concurrently
        for lock in &self.spin_locks {
            if other.spin_locks.contains(lock) {
                return true; // Same lock = exclusive access
            }
        }
        for lock in &self.mutex_locks {
            if other.mutex_locks.contains(lock) {
                return true;
            }
        }
        // Both in RCU read section is OK for reads
        // No common lock = potentially concurrent
        false
    }
}

// ============================================================================
// Race Detection Engine
// ============================================================================

/// Potential data race
#[derive(Debug, Clone)]
pub struct DataRace {
    /// First access
    pub access1: MemoryAccess,
    /// Second access
    pub access2: MemoryAccess,
    /// Reason this is flagged as a race
    pub reason: RaceReason,
    /// Severity level
    pub severity: RaceSeverity,
}

/// Reason for flagging a race
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceReason {
    /// No synchronization on either access
    NoSynchronization,
    /// Different locks held
    DifferentLocks,
    /// One access outside RCU section
    RcuMismatch,
    /// Non-atomic access to shared data
    NonAtomicShared,
    /// Write to per-CPU data from wrong CPU context
    PerCpuViolation,
    /// Map access without proper locking
    UnsyncedMapAccess,
}

/// Severity of the race
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RaceSeverity {
    /// Informational - might be intentional
    Info,
    /// Warning - likely unintended
    Warning,
    /// Error - definite bug
    Error,
}

/// Race detector state
#[derive(Debug, Clone)]
pub struct RaceDetector {
    /// All recorded memory accesses
    accesses: Vec<MemoryAccess>,
    /// Current lock state
    pub lock_state: LockState,
    /// Detected races
    races: Vec<DataRace>,
    /// Global variables that are known to be shared
    shared_globals: BTreeSet<u32>,
    /// Maps that are accessed concurrently
    concurrent_maps: BTreeSet<u32>,
    /// Per-CPU variables
    percpu_vars: BTreeSet<u32>,
    /// Whether we're in a preemptible context
    pub preemptible: bool,
    /// Program type (affects concurrency model)
    prog_type: BpfProgType,
}

impl RaceDetector {
    /// Create new race detector
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
    fn is_preemptible_prog_type(prog_type: BpfProgType) -> bool {
        matches!(
            prog_type,
            BpfProgType::Tracing | BpfProgType::Lsm | BpfProgType::StructOps
        )
    }

    /// Mark a global variable as shared
    pub fn mark_shared_global(&mut self, btf_id: u32) {
        self.shared_globals.insert(btf_id);
    }

    /// Mark a map as concurrently accessed
    pub fn mark_concurrent_map(&mut self, map_id: u32) {
        self.concurrent_maps.insert(map_id);
    }

    /// Mark a variable as per-CPU
    pub fn mark_percpu(&mut self, var_id: u32) {
        self.percpu_vars.insert(var_id);
    }

    /// Record a memory access
    pub fn record_access(&mut self, access: MemoryAccess) {
        self.accesses.push(access);
    }

    /// Record a global variable access
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
    pub fn acquire_spin_lock(&mut self, lock_id: u32) {
        self.lock_state.acquire_spin(lock_id);
        // Acquiring a spin lock disables preemption
        self.lock_state.preempt_disabled += 1;
    }

    /// Release a spin lock
    pub fn release_spin_lock(&mut self, lock_id: u32) -> Result<()> {
        self.lock_state.release_spin(lock_id)?;
        if self.lock_state.preempt_disabled > 0 {
            self.lock_state.preempt_disabled -= 1;
        }
        Ok(())
    }

    /// Enter RCU read section
    pub fn rcu_read_lock(&mut self) {
        self.lock_state.rcu_read_lock();
    }

    /// Exit RCU read section
    pub fn rcu_read_unlock(&mut self) -> Result<()> {
        self.lock_state.rcu_read_unlock()
    }

    /// Disable preemption
    pub fn preempt_disable(&mut self) {
        self.lock_state.preempt_disabled += 1;
    }

    /// Enable preemption
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
    pub fn analyze(&mut self) -> &[DataRace] {
        self.races.clear();

        // Compare all pairs of accesses
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
    fn check_race(&self, access1: &MemoryAccess, access2: &MemoryAccess) -> Option<DataRace> {
        // Must access the same location
        if access1.location != access2.location {
            return None;
        }

        // At least one must be a write
        if !access1.access_type.can_race_with(&access2.access_type) {
            return None;
        }

        // Check for overlapping access regions
        // (Simplified - in reality would check exact byte ranges)

        // Determine race reason
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
    fn determine_race_reason(
        &self,
        access1: &MemoryAccess,
        access2: &MemoryAccess,
    ) -> Option<RaceReason> {
        // Check lock-based synchronization
        if access1.lock_state.is_compatible_with(&access2.lock_state) {
            return None; // Protected by same lock
        }

        // Check RCU synchronization
        match (&access1.location, &access2.location) {
            (MemoryLocation::Global { btf_id, .. }, _) if self.shared_globals.contains(btf_id) => {
                // Shared global needs synchronization
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
        if access1.lock_state.has_synchronization() && access2.lock_state.has_synchronization() {
            // Both have some synchronization, but different
            return Some(RaceReason::DifferentLocks);
        }

        // No synchronization at all
        if !access1.lock_state.has_synchronization() || !access2.lock_state.has_synchronization() {
            return Some(RaceReason::NoSynchronization);
        }

        None
    }

    /// Determine severity of a race
    fn determine_severity(
        &self,
        reason: &RaceReason,
        access1: &MemoryAccess,
        access2: &MemoryAccess,
    ) -> RaceSeverity {
        let base_severity = match reason {
            RaceReason::NoSynchronization => {
                // Both writes = Error, read/write = Warning
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
        // XDP and TC programs are performance-critical and races are more dangerous
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
    pub fn get_races(&self) -> &[DataRace] {
        &self.races
    }

    /// Get races at or above a severity level
    pub fn get_races_by_severity(&self, min_severity: RaceSeverity) -> Vec<&DataRace> {
        self.races
            .iter()
            .filter(|r| r.severity >= min_severity)
            .collect()
    }

    /// Check if any errors were detected
    pub fn has_errors(&self) -> bool {
        self.races.iter().any(|r| r.severity == RaceSeverity::Error)
    }

    /// Validate no races at error level
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
    pub fn clear(&mut self) {
        self.accesses.clear();
        self.races.clear();
        self.lock_state = LockState::default();
    }
}

// ============================================================================
// Map Synchronization Analysis
// ============================================================================

/// Tracks map access patterns for race detection
#[derive(Debug, Clone, Default)]
pub struct MapAccessTracker {
    /// Accesses per map
    accesses: BTreeMap<u32, Vec<MapAccessInfo>>,
    /// Maps that use per-CPU storage
    percpu_maps: BTreeSet<u32>,
    /// Maps with external synchronization
    synced_maps: BTreeSet<u32>,
}

/// Information about a map access
#[derive(Debug, Clone)]
pub struct MapAccessInfo {
    /// Access type
    pub access_type: AccessType,
    /// Whether lookup returned non-NULL
    pub lookup_succeeded: bool,
    /// Whether value was modified in-place
    pub in_place_update: bool,
    /// Lock held during access
    pub lock_id: Option<u32>,
    /// Instruction index
    pub insn_idx: usize,
}

impl MapAccessTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a map as per-CPU
    pub fn mark_percpu(&mut self, map_id: u32) {
        self.percpu_maps.insert(map_id);
    }

    /// Mark a map as having external synchronization
    pub fn mark_synced(&mut self, map_id: u32) {
        self.synced_maps.insert(map_id);
    }

    /// Record a map access
    pub fn record_access(&mut self, map_id: u32, info: MapAccessInfo) {
        self.accesses.entry(map_id).or_default().push(info);
    }

    /// Check for potential races in a map
    pub fn check_map_races(&self, map_id: u32) -> Vec<MapRaceWarning> {
        let mut warnings = Vec::new();

        // Per-CPU maps don't race (within same CPU)
        if self.percpu_maps.contains(&map_id) {
            return warnings;
        }

        // Externally synced maps are OK
        if self.synced_maps.contains(&map_id) {
            return warnings;
        }

        let accesses = match self.accesses.get(&map_id) {
            Some(a) => a,
            None => return warnings,
        };

        // Check for in-place updates without locking
        for (i, access1) in accesses.iter().enumerate() {
            if access1.in_place_update && access1.lock_id.is_none() {
                warnings.push(MapRaceWarning {
                    map_id,
                    insn_idx: access1.insn_idx,
                    reason: "in-place map update without lock".into(),
                });
            }

            // Check for concurrent access patterns
            for access2 in accesses.iter().skip(i + 1) {
                if access1.access_type.can_race_with(&access2.access_type) {
                    // Different locks or no locks
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
#[derive(Debug, Clone)]
pub struct MapRaceWarning {
    /// Map ID
    pub map_id: u32,
    /// Instruction index
    pub insn_idx: usize,
    /// Description
    pub reason: String,
}

// ============================================================================
// Global Variable Analysis
// ============================================================================

/// Tracks global variable access patterns
#[derive(Debug, Clone, Default)]
pub struct GlobalAccessTracker {
    /// Accesses per global variable (by BTF ID)
    accesses: BTreeMap<u32, Vec<GlobalAccessInfo>>,
    /// Variables that are read-only
    readonly_vars: BTreeSet<u32>,
    /// Variables with __percpu annotation
    percpu_vars: BTreeSet<u32>,
}

/// Information about a global access
#[derive(Debug, Clone)]
pub struct GlobalAccessInfo {
    /// Offset within the variable
    pub offset: i32,
    /// Access type
    pub access_type: AccessType,
    /// Lock state
    pub lock_state: LockState,
    /// Instruction index
    pub insn_idx: usize,
}

impl GlobalAccessTracker {
    /// Create new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a variable as read-only
    pub fn mark_readonly(&mut self, btf_id: u32) {
        self.readonly_vars.insert(btf_id);
    }

    /// Mark a variable as per-CPU
    pub fn mark_percpu(&mut self, btf_id: u32) {
        self.percpu_vars.insert(btf_id);
    }

    /// Record a global variable access
    pub fn record_access(&mut self, btf_id: u32, info: GlobalAccessInfo) {
        // Check for write to read-only
        if self.readonly_vars.contains(&btf_id) && info.access_type.is_write() {
            // This should have been caught earlier, but track it
        }
        self.accesses.entry(btf_id).or_default().push(info);
    }

    /// Analyze for races
    pub fn analyze(&self) -> Vec<GlobalRaceWarning> {
        let mut warnings = Vec::new();

        for (btf_id, accesses) in &self.accesses {
            // Skip read-only and per-CPU
            if self.readonly_vars.contains(btf_id) {
                continue;
            }
            if self.percpu_vars.contains(btf_id) {
                continue;
            }

            // Check for unprotected writes
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
#[derive(Debug, Clone)]
pub struct GlobalRaceWarning {
    /// BTF ID of the variable
    pub btf_id: u32,
    /// Offset within variable
    pub offset: i32,
    /// Instruction index
    pub insn_idx: usize,
    /// Description
    pub reason: String,
}

// ============================================================================
// Tests
// ============================================================================
