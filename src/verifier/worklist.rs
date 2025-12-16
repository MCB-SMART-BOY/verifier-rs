// SPDX-License-Identifier: GPL-2.0

//! Worklist-based path exploration for BPF verification.
//!
//! This module implements an advanced worklist algorithm for exploring
//! all program paths. It uses:
//! - Priority-based exploration (depth-first by default)
//! - State merging at join points to control state explosion
//! - Pruning using explored state snapshots
//! - Range refinement on branches for precise tracking

use core::cmp::Ordering;

use alloc::vec::Vec;

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet, BinaryHeap};

use crate::analysis::state_merge::{merge_states, MergeResult, MergeStats};
use crate::analysis::states_equal::states_equal;
use crate::core::types::*;
use crate::state::verifier_state::BpfVerifierState;

/// A work item in the exploration queue.
#[derive(Debug, Clone)]
pub struct WorkItem {
    /// Instruction index to explore.
    pub insn_idx: usize,
    /// Verifier state at this point.
    pub state: BpfVerifierState,
    /// Priority (higher = explore first for depth-first).
    pub priority: u64,
    /// Depth in exploration tree.
    pub depth: u32,
    /// Parent instruction index (for path reconstruction).
    pub parent_idx: Option<usize>,
}

impl WorkItem {
    /// Create a new work item.
    pub fn new(insn_idx: usize, state: BpfVerifierState, priority: u64) -> Self {
        Self {
            insn_idx,
            state,
            priority,
            depth: 0,
            parent_idx: None,
        }
    }

    /// Create a work item with depth tracking.
    pub fn with_depth(
        insn_idx: usize,
        state: BpfVerifierState,
        priority: u64,
        depth: u32,
        parent: usize,
    ) -> Self {
        Self {
            insn_idx,
            state,
            priority,
            depth,
            parent_idx: Some(parent),
        }
    }
}

impl PartialEq for WorkItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for WorkItem {}

impl PartialOrd for WorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first (for max-heap behavior)
        self.priority.cmp(&other.priority)
    }
}

/// Exploration strategy for the worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorationStrategy {
    /// Depth-first: explore deeper paths first.
    DepthFirst,
    /// Breadth-first: explore shallower paths first.
    BreadthFirst,
    /// Branch coverage: prioritize unexplored branches.
    BranchCoverage,
}

/// Worklist for managing exploration state.
pub struct Worklist {
    /// Priority queue of work items.
    queue: BinaryHeap<WorkItem>,
    /// Explored states at each instruction (for pruning).
    explored: HashMap<usize, Vec<BpfVerifierState>>,
    /// Pending states at join points (for merging).
    pending_merge: HashMap<usize, Vec<BpfVerifierState>>,
    /// Instructions that have been visited.
    visited: HashSet<usize>,
    /// Exploration strategy.
    strategy: ExplorationStrategy,
    /// Current priority counter.
    priority_counter: u64,
    /// Maximum states per instruction for merging.
    max_states_per_insn: usize,
    /// Statistics.
    stats: WorklistStats,
    /// Merge statistics.
    merge_stats: MergeStats,
}

/// Statistics for worklist exploration.
#[derive(Debug, Clone, Default)]
pub struct WorklistStats {
    /// Total work items processed.
    pub items_processed: u64,
    /// Number of items pruned.
    pub items_pruned: u64,
    /// Number of items merged.
    pub items_merged: u64,
    /// Maximum queue size observed.
    pub max_queue_size: usize,
    /// Maximum depth observed.
    pub max_depth: u32,
    /// Number of join points encountered.
    pub join_points: u64,
}

impl Worklist {
    /// Create a new worklist with default settings.
    pub fn new() -> Self {
        Self::with_strategy(ExplorationStrategy::DepthFirst)
    }

    /// Create a new worklist with a specific strategy.
    pub fn with_strategy(strategy: ExplorationStrategy) -> Self {
        Self {
            queue: BinaryHeap::new(),
            explored: HashMap::new(),
            pending_merge: HashMap::new(),
            visited: HashSet::new(),
            strategy,
            priority_counter: 0,
            max_states_per_insn: 64,
            stats: WorklistStats::default(),
            merge_stats: MergeStats::new(),
        }
    }

    /// Set maximum states per instruction before forcing merge.
    pub fn set_max_states(&mut self, max: usize) {
        self.max_states_per_insn = max;
    }

    /// Push a new work item.
    pub fn push(&mut self, insn_idx: usize, state: BpfVerifierState) {
        let priority = self.next_priority();
        let item = WorkItem::new(insn_idx, state, priority);
        self.push_item(item);
    }

    /// Push a work item with parent tracking.
    pub fn push_with_parent(
        &mut self,
        insn_idx: usize,
        state: BpfVerifierState,
        parent_idx: usize,
        depth: u32,
    ) {
        let priority = self.next_priority();
        let item = WorkItem::with_depth(insn_idx, state, priority, depth, parent_idx);
        self.push_item(item);
    }

    /// Push a work item directly.
    fn push_item(&mut self, item: WorkItem) {
        if item.depth > self.stats.max_depth {
            self.stats.max_depth = item.depth;
        }
        self.queue.push(item);
        if self.queue.len() > self.stats.max_queue_size {
            self.stats.max_queue_size = self.queue.len();
        }
    }

    /// Pop the next work item to process.
    pub fn pop(&mut self) -> Option<WorkItem> {
        self.queue.pop()
    }

    /// Check if the worklist is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get the number of pending items.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Get the next priority value based on strategy.
    fn next_priority(&mut self) -> u64 {
        // Increment counter for each item
        self.priority_counter = self.priority_counter.saturating_add(1);

        match self.strategy {
            ExplorationStrategy::DepthFirst => {
                // Higher priority for later items (LIFO) - use counter directly
                self.priority_counter
            }
            ExplorationStrategy::BreadthFirst => {
                // Lower priority for later items (FIFO) - invert
                u64::MAX - self.priority_counter
            }
            ExplorationStrategy::BranchCoverage => {
                // Base priority, will be adjusted by caller
                self.priority_counter
            }
        }
    }

    /// Try to prune a state at the given instruction.
    ///
    /// Returns true if the state can be pruned (an equivalent state was already explored).
    pub fn try_prune(&mut self, insn_idx: usize, state: &BpfVerifierState) -> bool {
        if let Some(explored) = self.explored.get(&insn_idx) {
            for explored_state in explored {
                if states_equal(explored_state, state) {
                    self.stats.items_pruned += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Save an explored state for future pruning.
    pub fn save_explored(&mut self, insn_idx: usize, state: BpfVerifierState) {
        self.explored.entry(insn_idx).or_default().push(state);
    }

    /// Try to merge a state at a join point.
    ///
    /// Returns the merged state if merging occurred, or None if the state should be explored normally.
    pub fn try_merge_at_join(
        &mut self,
        insn_idx: usize,
        state: &BpfVerifierState,
    ) -> Option<BpfVerifierState> {
        let pending = self.pending_merge.entry(insn_idx).or_default();

        // Check if we should merge with existing states
        if pending.is_empty() {
            // First state at this join point - just save it
            pending.push(state.clone());
            return None;
        }

        // Try to merge with existing states
        for existing in pending.iter_mut() {
            let result = merge_states(existing, state);
            self.merge_stats.record(&result);

            match result {
                MergeResult::Merged(merged) => {
                    self.stats.items_merged += 1;
                    *existing = merged.clone();
                    return Some(merged);
                }
                MergeResult::FirstSubsumes => {
                    self.stats.items_merged += 1;
                    return Some(existing.clone());
                }
                MergeResult::SecondSubsumes => {
                    self.stats.items_merged += 1;
                    *existing = state.clone();
                    return Some(state.clone());
                }
                MergeResult::Incompatible => {
                    // Try next state
                    continue;
                }
            }
        }

        // No merge possible - add as new pending state if under limit
        if pending.len() < self.max_states_per_insn {
            pending.push(state.clone());
        }

        None
    }

    /// Mark an instruction as visited.
    pub fn mark_visited(&mut self, insn_idx: usize) {
        self.visited.insert(insn_idx);
    }

    /// Check if an instruction has been visited.
    pub fn is_visited(&self, insn_idx: usize) -> bool {
        self.visited.contains(&insn_idx)
    }

    /// Record that a work item was processed.
    pub fn record_processed(&mut self) {
        self.stats.items_processed += 1;
    }

    /// Record a join point.
    pub fn record_join_point(&mut self) {
        self.stats.join_points += 1;
    }

    /// Get statistics.
    pub fn stats(&self) -> &WorklistStats {
        &self.stats
    }

    /// Get merge statistics.
    pub fn merge_stats(&self) -> &MergeStats {
        &self.merge_stats
    }

    /// Get explored states at an instruction.
    pub fn get_explored(&self, insn_idx: usize) -> Option<&Vec<BpfVerifierState>> {
        self.explored.get(&insn_idx)
    }

    /// Clear all state (for reuse).
    pub fn clear(&mut self) {
        self.queue.clear();
        self.explored.clear();
        self.pending_merge.clear();
        self.visited.clear();
        self.priority_counter = 0;
        self.stats = WorklistStats::default();
        self.merge_stats = MergeStats::new();
    }
}

impl Default for Worklist {
    fn default() -> Self {
        Self::new()
    }
}

/// Join point detector for CFG analysis.
pub struct JoinPointDetector {
    /// Number of predecessors for each instruction.
    predecessors: HashMap<usize, usize>,
    /// Known join points (instructions with multiple predecessors).
    join_points: HashSet<usize>,
}

impl JoinPointDetector {
    /// Create a new join point detector.
    pub fn new() -> Self {
        Self {
            predecessors: HashMap::new(),
            join_points: HashSet::new(),
        }
    }

    /// Record an edge in the CFG.
    pub fn record_edge(&mut self, _from: usize, to: usize) {
        let count = self.predecessors.entry(to).or_insert(0);
        *count += 1;
        if *count > 1 {
            self.join_points.insert(to);
        }
    }

    /// Check if an instruction is a join point.
    pub fn is_join_point(&self, insn_idx: usize) -> bool {
        self.join_points.contains(&insn_idx)
    }

    /// Get the number of predecessors for an instruction.
    pub fn predecessor_count(&self, insn_idx: usize) -> usize {
        *self.predecessors.get(&insn_idx).unwrap_or(&0)
    }

    /// Pre-analyze a program to find join points.
    pub fn analyze_program(insns: &[BpfInsn]) -> Self {
        let mut detector = Self::new();

        for (idx, insn) in insns.iter().enumerate() {
            let class = insn.class();
            let op = insn.code & 0xf0;

            match class {
                BPF_JMP | BPF_JMP32 => {
                    match op {
                        BPF_JA => {
                            // Unconditional jump
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                detector.record_edge(idx, target);
                            }
                        }
                        BPF_EXIT => {
                            // No successor
                        }
                        BPF_CALL => {
                            // Fall through after call
                            if idx + 1 < insns.len() {
                                detector.record_edge(idx, idx + 1);
                            }
                        }
                        _ => {
                            // Conditional jump - both paths
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                detector.record_edge(idx, target);
                            }
                            if idx + 1 < insns.len() {
                                detector.record_edge(idx, idx + 1);
                            }
                        }
                    }
                }
                BPF_LD => {
                    // LD_IMM64 spans two instructions
                    if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                        if idx + 2 < insns.len() {
                            detector.record_edge(idx, idx + 2);
                        }
                    } else if idx + 1 < insns.len() {
                        detector.record_edge(idx, idx + 1);
                    }
                }
                _ => {
                    // Sequential instruction
                    if idx + 1 < insns.len() {
                        detector.record_edge(idx, idx + 1);
                    }
                }
            }
        }

        detector
    }
}

impl Default for JoinPointDetector {
    fn default() -> Self {
        Self::new()
    }
}
