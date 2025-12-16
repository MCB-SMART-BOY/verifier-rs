//! Reference leak detection
//!
//! This module provides comprehensive reference leak detection for BPF programs.
//! It tracks reference acquisition and release across all paths and reports
//! detailed information about leaks.


use alloc::{string::{String, ToString}, vec, vec::Vec, format};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use crate::core::types::RefStateType;
use crate::core::error::{Result, VerifierError};
use crate::state::reference::BpfReferenceState;

/// Information about a potential leak
#[derive(Debug, Clone)]
pub struct LeakInfo {
    /// Reference ID
    pub ref_id: u32,
    /// Type of reference
    pub ref_type: RefStateType,
    /// Instruction where reference was acquired
    pub acquire_insn: usize,
    /// Path(s) where leak was detected
    pub leak_paths: Vec<LeakPath>,
    /// Helper or kfunc that acquired the reference
    pub acquire_source: String,
}

/// A path where a leak was detected
#[derive(Debug, Clone)]
pub struct LeakPath {
    /// Sequence of instruction indices leading to the exit
    pub path: Vec<usize>,
    /// Exit instruction index
    pub exit_insn: usize,
    /// Whether this is a callback return
    pub is_callback_return: bool,
}

/// Comprehensive leak detection result
#[derive(Debug, Clone, Default)]
pub struct LeakDetectionResult {
    /// All detected leaks
    pub leaks: Vec<LeakInfo>,
    /// References that were properly released
    pub released_refs: Vec<u32>,
    /// Total references acquired
    pub total_acquired: usize,
    /// Total references released
    pub total_released: usize,
    /// Paths analyzed
    pub paths_analyzed: usize,
    /// Exit points found
    pub exit_points: Vec<usize>,
}

impl LeakDetectionResult {
    /// Check if there are any leaks
    pub fn has_leaks(&self) -> bool {
        !self.leaks.is_empty()
    }

    /// Get the first leak error for verification
    pub fn first_leak_error(&self) -> Option<VerifierError> {
        self.leaks.first().map(|leak| {
            VerifierError::UnreleasedReference(leak.ref_id)
        })
    }

    /// Generate detailed leak report
    pub fn report(&self) -> String {
        if self.leaks.is_empty() {
            return "No reference leaks detected".to_string();
        }

        let mut report = format!(
            "Reference leak detected: {} leak(s) found\n",
            self.leaks.len()
        );

        for (i, leak) in self.leaks.iter().enumerate() {
            report.push_str(&format!(
                "\nLeak #{}: ref_id={}, type={:?}\n",
                i + 1,
                leak.ref_id,
                leak.ref_type
            ));
            report.push_str(&format!(
                "  Acquired at insn {}: {}\n",
                leak.acquire_insn, leak.acquire_source
            ));
            
            for path in &leak.leak_paths {
                report.push_str(&format!(
                    "  Unreleased at exit insn {}{}\n",
                    path.exit_insn,
                    if path.is_callback_return { " (callback return)" } else { "" }
                ));
            }
        }

        report.push_str(&format!(
            "\nSummary: {}/{} references released, {} paths analyzed\n",
            self.total_released,
            self.total_acquired,
            self.paths_analyzed
        ));

        report
    }
}

/// Tracks reference state across verification paths
#[derive(Debug, Clone, Default)]
pub struct ReferenceTracker {
    /// Currently held references at each instruction
    refs_at_insn: HashMap<usize, HashSet<u32>>,
    /// Acquisition points for each reference
    acquire_points: HashMap<u32, AcquireInfo>,
    /// Release points for each reference
    release_points: HashMap<u32, Vec<usize>>,
    /// Exit instruction indices
    exit_insns: HashSet<usize>,
    /// Callback return points (treated as potential exits)
    callback_returns: HashSet<usize>,
}

/// Information about reference acquisition
#[derive(Debug, Clone)]
struct AcquireInfo {
    insn_idx: usize,
    ref_type: RefStateType,
    source: String,
}

impl ReferenceTracker {
    /// Create a new reference tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a reference acquisition
    pub fn record_acquire(
        &mut self,
        insn_idx: usize,
        ref_id: u32,
        ref_type: RefStateType,
        source: &str,
    ) {
        self.acquire_points.insert(
            ref_id,
            AcquireInfo {
                insn_idx,
                ref_type,
                source: source.to_string(),
            },
        );

        // Add to refs_at_insn
        self.refs_at_insn
            .entry(insn_idx)
            .or_default()
            .insert(ref_id);
    }

    /// Record a reference release
    pub fn record_release(&mut self, insn_idx: usize, ref_id: u32) {
        self.release_points
            .entry(ref_id)
            .or_default()
            .push(insn_idx);
    }

    /// Record an exit point
    pub fn record_exit(&mut self, insn_idx: usize) {
        self.exit_insns.insert(insn_idx);
    }

    /// Record a callback return point
    pub fn record_callback_return(&mut self, insn_idx: usize) {
        self.callback_returns.insert(insn_idx);
    }

    /// Record held references at an instruction
    pub fn record_held_refs(&mut self, insn_idx: usize, ref_ids: &[u32]) {
        self.refs_at_insn
            .entry(insn_idx)
            .or_default()
            .extend(ref_ids.iter().copied());
    }

    /// Clear tracking state
    pub fn clear(&mut self) {
        self.refs_at_insn.clear();
        self.acquire_points.clear();
        self.release_points.clear();
        self.exit_insns.clear();
        self.callback_returns.clear();
    }
}

/// Leak detector that analyzes verification state
pub struct LeakDetector {
    tracker: ReferenceTracker,
}

impl LeakDetector {
    /// Create a new leak detector
    pub fn new() -> Self {
        Self {
            tracker: ReferenceTracker::new(),
        }
    }

    /// Get mutable access to the tracker
    pub fn tracker_mut(&mut self) -> &mut ReferenceTracker {
        &mut self.tracker
    }

    /// Analyze for leaks based on tracked information
    pub fn analyze(&self) -> LeakDetectionResult {
        let mut result = LeakDetectionResult {
            exit_points: self.tracker.exit_insns.iter().copied().collect(),
            total_acquired: self.tracker.acquire_points.len(),
            paths_analyzed: self.tracker.exit_insns.len() + self.tracker.callback_returns.len(),
            ..Default::default()
        };

        // Check each acquired reference
        for (ref_id, acquire_info) in &self.tracker.acquire_points {
            let releases = self.tracker.release_points.get(ref_id);
            let release_count = releases.map(|r| r.len()).unwrap_or(0);

            if release_count > 0 {
                result.released_refs.push(*ref_id);
                result.total_released += 1;
            }

            // Check if reference is held at any exit point
            let mut leak_paths = Vec::new();

            for &exit_insn in &self.tracker.exit_insns {
                if let Some(held) = self.tracker.refs_at_insn.get(&exit_insn) {
                    if held.contains(ref_id) {
                        leak_paths.push(LeakPath {
                            path: vec![acquire_info.insn_idx, exit_insn],
                            exit_insn,
                            is_callback_return: false,
                        });
                    }
                }
            }

            for &cb_exit in &self.tracker.callback_returns {
                if let Some(held) = self.tracker.refs_at_insn.get(&cb_exit) {
                    if held.contains(ref_id) {
                        leak_paths.push(LeakPath {
                            path: vec![acquire_info.insn_idx, cb_exit],
                            exit_insn: cb_exit,
                            is_callback_return: true,
                        });
                    }
                }
            }

            if !leak_paths.is_empty() {
                result.leaks.push(LeakInfo {
                    ref_id: *ref_id,
                    ref_type: acquire_info.ref_type,
                    acquire_insn: acquire_info.insn_idx,
                    leak_paths,
                    acquire_source: acquire_info.source.clone(),
                });
            }
        }

        result
    }

    /// Check references at exit and return error if any leaks
    pub fn check_at_exit(
        &self,
        refs: &[BpfReferenceState],
        exit_insn: usize,
    ) -> Result<()> {
        for r in refs {
            match r.ref_type {
                RefStateType::Ptr => {
                    return Err(VerifierError::UnreleasedReference(r.id));
                }
                RefStateType::Lock | RefStateType::ResLock => {
                    return Err(VerifierError::InvalidLock(format!(
                        "lock acquired at insn {} not released before exit at insn {}",
                        r.insn_idx, exit_insn
                    )));
                }
                RefStateType::Irq => {
                    return Err(VerifierError::InvalidIrq(format!(
                        "irq state saved at insn {} not restored before exit at insn {}",
                        r.insn_idx, exit_insn
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Quick check for leaks (used during verification)
    pub fn has_unreleased_refs(refs: &[BpfReferenceState]) -> bool {
        refs.iter().any(|r| matches!(
            r.ref_type,
            RefStateType::Ptr | RefStateType::Lock | RefStateType::ResLock | RefStateType::Irq
        ))
    }

    /// Get leaked reference IDs
    pub fn get_leaked_ids(refs: &[BpfReferenceState]) -> Vec<u32> {
        refs.iter()
            .filter(|r| matches!(
                r.ref_type,
                RefStateType::Ptr | RefStateType::Lock | RefStateType::ResLock | RefStateType::Irq
            ))
            .map(|r| r.id)
            .collect()
    }
}

impl Default for LeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to identify reference-acquiring helpers
pub fn is_ref_acquiring_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        84  // SkLookupTcp
        | 85  // SkLookupUdp 
        | 95  // SkFullsock
        | 96  // TcpSock
        | 27  // GetStackid
        | 67  // GetStack
        | 131 // RingbufReserve
    )
}

/// Helper to identify reference-releasing helpers
pub fn is_ref_releasing_helper(helper_id: u32) -> bool {
    matches!(
        helper_id,
        86  // SkRelease
        | 132 // RingbufSubmit
        | 133 // RingbufDiscard
    )
}

/// Get the helper name for error messages
pub fn helper_name(helper_id: u32) -> String {
    match helper_id {
        84 => "bpf_sk_lookup_tcp".to_string(),
        85 => "bpf_sk_lookup_udp".to_string(),
        86 => "bpf_sk_release".to_string(),
        95 => "bpf_sk_fullsock".to_string(),
        96 => "bpf_tcp_sock".to_string(),
        27 => "bpf_get_stackid".to_string(),
        67 => "bpf_get_stack".to_string(),
        131 => "bpf_ringbuf_reserve".to_string(),
        132 => "bpf_ringbuf_submit".to_string(),
        133 => "bpf_ringbuf_discard".to_string(),
        _ => format!("helper_{}", helper_id),
    }
}
