// SPDX-License-Identifier: GPL-2.0

//! Parallel verification exploration for the BPF verifier.
//!
//! This module provides infrastructure for parallel state exploration,
//! enabling faster verification of complex programs by exploring multiple
//! paths concurrently.
//!
//! # Design
//!
//! The parallel verifier uses a work-stealing approach:
//! 1. The main verification loop pushes unexplored branches to a work queue
//! 2. Worker threads pull work items and explore paths in parallel
//! 3. Results are merged back with proper synchronization
//!
//! # Safety Considerations
//!
//! - State cache access must be synchronized
//! - Error reporting must be thread-safe
//! - Memory limits must account for all threads

use crate::core::error::VerifierError;
use crate::state::verifier_state::BpfVerifierState;

use alloc::vec::Vec;

// ============================================================================
// Work Item for Parallel Exploration
// ============================================================================

/// A work item representing an unexplored verification path for parallel exploration
#[derive(Debug, Clone)]
pub struct ParallelWorkItem {
    /// The verifier state at this point
    pub state: BpfVerifierState,
    /// Instruction index to continue from
    pub insn_idx: usize,
    /// Previous instruction index
    pub prev_insn_idx: usize,
    /// Priority (higher = more important)
    pub priority: u32,
    /// Depth in the exploration tree
    pub depth: u32,
    /// Parent work item ID (for result merging)
    pub parent_id: Option<u64>,
    /// Unique ID for this work item
    pub id: u64,
}

impl ParallelWorkItem {
    /// Create a new work item
    pub fn new(state: BpfVerifierState, insn_idx: usize, prev_insn_idx: usize, id: u64) -> Self {
        Self {
            state,
            insn_idx,
            prev_insn_idx,
            priority: 0,
            depth: 0,
            parent_id: None,
            id,
        }
    }

    /// Create a child work item
    pub fn child(&self, state: BpfVerifierState, insn_idx: usize, child_id: u64) -> Self {
        Self {
            state,
            insn_idx,
            prev_insn_idx: self.insn_idx,
            priority: self.priority,
            depth: self.depth + 1,
            parent_id: Some(self.id),
            id: child_id,
        }
    }

    /// Set priority based on heuristics
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

// ============================================================================
// Work Queue for Parallel Exploration
// ============================================================================

/// Result of exploring a work item
#[derive(Debug)]
pub enum ExploreResult {
    /// Path completed successfully (reached exit)
    Complete,
    /// Path was pruned (matched existing state)
    Pruned,
    /// Path generated new work items
    Branched(Vec<ParallelWorkItem>),
    /// Path encountered an error
    Error(VerifierError),
}

/// Thread-safe work queue for parallel exploration
///
/// Uses a priority queue to explore more promising paths first.
/// Work stealing enables load balancing across threads.
#[derive(Debug)]
pub struct WorkQueue {
    /// Pending work items sorted by priority
    items: Vec<ParallelWorkItem>,
    /// Next work item ID
    next_id: u64,
    /// Maximum queue size
    max_size: usize,
    /// Total items enqueued
    pub total_enqueued: u64,
    /// Total items dequeued
    pub total_dequeued: u64,
    /// Items rejected due to full queue
    pub rejected: u64,
}

impl WorkQueue {
    /// Create a new work queue
    pub fn new(max_size: usize) -> Self {
        Self {
            items: Vec::with_capacity(max_size.min(1000)),
            next_id: 0,
            max_size,
            total_enqueued: 0,
            total_dequeued: 0,
            rejected: 0,
        }
    }

    /// Allocate a new work item ID
    pub fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Push a work item onto the queue
    pub fn push(&mut self, item: ParallelWorkItem) -> bool {
        if self.items.len() >= self.max_size {
            self.rejected += 1;
            return false;
        }

        // Insert in priority order (higher priority at the end for efficient pop)
        let pos = self.items.partition_point(|x| x.priority < item.priority);
        self.items.insert(pos, item);
        self.total_enqueued += 1;
        true
    }

    /// Pop the highest priority work item
    pub fn pop(&mut self) -> Option<ParallelWorkItem> {
        let item = self.items.pop();
        if item.is_some() {
            self.total_dequeued += 1;
        }
        item
    }

    /// Peek at the highest priority item without removing it
    pub fn peek(&self) -> Option<&ParallelWorkItem> {
        self.items.last()
    }

    /// Get the current queue size
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear the queue
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Steal work items for another thread
    ///
    /// Returns up to `count` items from the low-priority end of the queue.
    pub fn steal(&mut self, count: usize) -> Vec<ParallelWorkItem> {
        let steal_count = count.min(self.items.len() / 2);
        self.items.drain(..steal_count).collect()
    }

    /// Get queue utilization as percentage (0-100)
    pub fn utilization_percent(&self) -> u32 {
        if self.max_size == 0 {
            return 0;
        }
        ((self.items.len() * 100) / self.max_size) as u32
    }
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new(10000)
    }
}

// ============================================================================
// Parallel Exploration Strategy
// ============================================================================

/// Strategy for parallel exploration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParallelStrategy {
    /// Breadth-first: explore all branches at same depth before going deeper
    BreadthFirst,
    /// Depth-first: explore one path to completion before backtracking
    DepthFirst,
    /// Priority-based: use heuristics to prioritize promising paths
    Priority,
    /// Hybrid: combine depth and breadth approaches
    #[default]
    Hybrid,
}

impl ParallelStrategy {
    /// Compute priority for a work item based on strategy
    pub fn compute_priority(&self, item: &ParallelWorkItem, max_depth: u32) -> u32 {
        match self {
            ParallelStrategy::BreadthFirst => {
                // Lower depth = higher priority
                max_depth.saturating_sub(item.depth)
            }
            ParallelStrategy::DepthFirst => {
                // Higher depth = higher priority
                item.depth
            }
            ParallelStrategy::Priority => {
                // Use existing priority (set by heuristics)
                item.priority
            }
            ParallelStrategy::Hybrid => {
                // Balance depth and existing priority
                item.priority.saturating_add(item.depth / 2)
            }
        }
    }
}



// ============================================================================
// Parallel Verification Context
// ============================================================================

/// Configuration for parallel verification
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Maximum number of worker threads
    pub max_threads: usize,
    /// Maximum work queue size per thread
    pub queue_size: usize,
    /// Exploration strategy
    pub strategy: ParallelStrategy,
    /// Maximum exploration depth before forcing sequential
    pub max_depth: u32,
    /// Minimum work items before spawning new thread
    pub spawn_threshold: usize,
    /// Enable work stealing
    pub work_stealing: bool,
}

impl ParallelConfig {
    /// Create a new configuration with sensible defaults
    pub fn new() -> Self {
        Self {
            max_threads: 4,
            queue_size: 1000,
            strategy: ParallelStrategy::Hybrid,
            max_depth: 100,
            spawn_threshold: 10,
            work_stealing: true,
        }
    }

    /// Create configuration for single-threaded mode
    pub fn single_threaded() -> Self {
        Self {
            max_threads: 1,
            queue_size: 10000,
            strategy: ParallelStrategy::DepthFirst,
            max_depth: 1000,
            spawn_threshold: usize::MAX,
            work_stealing: false,
        }
    }

    /// Set maximum threads
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.max_threads = threads.max(1);
        self
    }

    /// Set exploration strategy
    pub fn with_strategy(mut self, strategy: ParallelStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for parallel verification
#[derive(Debug, Clone, Default)]
pub struct ParallelStats {
    /// Total work items processed
    pub items_processed: u64,
    /// Work items completed (reached exit)
    pub items_completed: u64,
    /// Work items pruned
    pub items_pruned: u64,
    /// Work items that branched
    pub items_branched: u64,
    /// Work items with errors
    pub items_errored: u64,
    /// Maximum queue depth reached
    pub max_queue_depth: usize,
    /// Total branches created
    pub total_branches: u64,
    /// Work items stolen (if work stealing enabled)
    pub items_stolen: u64,
    /// Thread spawns
    pub thread_spawns: u64,
}

impl ParallelStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record processing a work item
    pub fn record_processed(&mut self) {
        self.items_processed += 1;
    }

    /// Record completing a path
    pub fn record_completed(&mut self) {
        self.items_completed += 1;
    }

    /// Record pruning a path
    pub fn record_pruned(&mut self) {
        self.items_pruned += 1;
    }

    /// Record branching
    pub fn record_branched(&mut self, branch_count: usize) {
        self.items_branched += 1;
        self.total_branches += branch_count as u64;
    }

    /// Record an error
    pub fn record_error(&mut self) {
        self.items_errored += 1;
    }

    /// Update max queue depth
    pub fn update_queue_depth(&mut self, depth: usize) {
        if depth > self.max_queue_depth {
            self.max_queue_depth = depth;
        }
    }

    /// Record work stealing
    pub fn record_steal(&mut self, count: usize) {
        self.items_stolen += count as u64;
    }

    /// Get branching factor scaled by 100 (average branches per branch point * 100)
    pub fn branching_factor_scaled(&self) -> u64 {
        if self.items_branched == 0 {
            0
        } else {
            (self.total_branches * 100) / self.items_branched
        }
    }

    /// Get prune rate as percentage (0-100)
    pub fn prune_rate_percent(&self) -> u32 {
        if self.items_processed == 0 {
            0
        } else {
            ((self.items_pruned * 100) / self.items_processed) as u32
        }
    }

    /// Get completion rate as percentage (0-100)
    pub fn completion_rate_percent(&self) -> u32 {
        if self.items_processed == 0 {
            0
        } else {
            ((self.items_completed * 100) / self.items_processed) as u32
        }
    }
}

// ============================================================================
// Parallel Exploration Controller
// ============================================================================

/// Controller for parallel verification exploration
///
/// Manages work distribution and result aggregation for parallel verification.
/// This is the main entry point for parallel exploration.
#[derive(Debug)]
pub struct ParallelExplorer {
    /// Configuration
    pub config: ParallelConfig,
    /// Work queue
    pub queue: WorkQueue,
    /// Statistics
    pub stats: ParallelStats,
    /// First error encountered (if any)
    first_error: Option<VerifierError>,
    /// Whether exploration is complete
    complete: bool,
}

impl ParallelExplorer {
    /// Create a new parallel explorer
    pub fn new(config: ParallelConfig) -> Self {
        let queue_size = config.queue_size;
        Self {
            config,
            queue: WorkQueue::new(queue_size),
            stats: ParallelStats::new(),
            first_error: None,
            complete: false,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ParallelConfig::new())
    }

    /// Add initial work item
    pub fn add_initial(&mut self, state: BpfVerifierState, insn_idx: usize) {
        let id = self.queue.alloc_id();
        let item = ParallelWorkItem::new(state, insn_idx, 0, id);
        self.queue.push(item);
    }

    /// Get next work item to process
    pub fn next_work(&mut self) -> Option<ParallelWorkItem> {
        self.queue.pop()
    }

    /// Submit result of exploring a work item
    pub fn submit_result(&mut self, _item: &ParallelWorkItem, result: ExploreResult) {
        self.stats.record_processed();
        self.stats.update_queue_depth(self.queue.len());

        match result {
            ExploreResult::Complete => {
                self.stats.record_completed();
            }
            ExploreResult::Pruned => {
                self.stats.record_pruned();
            }
            ExploreResult::Branched(new_items) => {
                self.stats.record_branched(new_items.len());
                for mut new_item in new_items {
                    // Compute priority based on strategy
                    let priority = self
                        .config
                        .strategy
                        .compute_priority(&new_item, self.config.max_depth);
                    new_item.priority = priority;
                    self.queue.push(new_item);
                }
            }
            ExploreResult::Error(err) => {
                self.stats.record_error();
                if self.first_error.is_none() {
                    self.first_error = Some(err);
                }
            }
        }
    }

    /// Check if exploration is complete
    pub fn is_complete(&self) -> bool {
        self.complete || (self.queue.is_empty() && self.first_error.is_none())
    }

    /// Check if there was an error
    pub fn has_error(&self) -> bool {
        self.first_error.is_some()
    }

    /// Get the first error (if any)
    pub fn take_error(&mut self) -> Option<VerifierError> {
        self.first_error.take()
    }

    /// Mark exploration as complete
    pub fn mark_complete(&mut self) {
        self.complete = true;
    }

    /// Get current queue size
    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    /// Steal work for another thread
    pub fn steal_work(&mut self, count: usize) -> Vec<ParallelWorkItem> {
        if self.config.work_stealing {
            let stolen = self.queue.steal(count);
            self.stats.record_steal(stolen.len());
            stolen
        } else {
            Vec::new()
        }
    }

    /// Should spawn new thread for parallel work?
    pub fn should_spawn_thread(&self) -> bool {
        self.queue.len() >= self.config.spawn_threshold
    }

    /// Get statistics
    pub fn statistics(&self) -> &ParallelStats {
        &self.stats
    }
}

impl Default for ParallelExplorer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// Path Merging for Parallel Results
// ============================================================================

/// Result of merging parallel exploration paths
#[derive(Debug)]
pub struct MergeResult {
    /// Number of paths merged
    pub paths_merged: usize,
    /// Number of conflicts detected
    pub conflicts: usize,
    /// Whether all paths succeeded
    pub all_succeeded: bool,
    /// First error from any path
    pub error: Option<VerifierError>,
}

/// Merge results from parallel exploration
///
/// Combines the results of exploring multiple paths in parallel,
/// detecting any conflicts or errors.
pub fn merge_parallel_results(results: Vec<ExploreResult>) -> MergeResult {
    let mut paths_merged = 0;
    let mut conflicts = 0;
    let mut all_succeeded = true;
    let mut error = None;

    for result in results {
        paths_merged += 1;
        match result {
            ExploreResult::Complete | ExploreResult::Pruned => {}
            ExploreResult::Branched(_) => {
                // Branches should have been processed, not returned
                conflicts += 1;
            }
            ExploreResult::Error(err) => {
                all_succeeded = false;
                if error.is_none() {
                    error = Some(err);
                }
            }
        }
    }

    MergeResult {
        paths_merged,
        conflicts,
        all_succeeded,
        error,
    }
}

// ============================================================================
// Tests
// ============================================================================
