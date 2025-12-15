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

use crate::state::verifier_state::BpfVerifierState;
use crate::core::error::VerifierError;

#[cfg(not(feature = "std"))]
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
    pub fn new(
        state: BpfVerifierState,
        insn_idx: usize,
        prev_insn_idx: usize,
        id: u64,
    ) -> Self {
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

    /// Get queue utilization ratio
    pub fn utilization(&self) -> f64 {
        self.items.len() as f64 / self.max_size as f64
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelStrategy {
    /// Breadth-first: explore all branches at same depth before going deeper
    BreadthFirst,
    /// Depth-first: explore one path to completion before backtracking
    DepthFirst,
    /// Priority-based: use heuristics to prioritize promising paths
    Priority,
    /// Hybrid: combine depth and breadth approaches
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

impl Default for ParallelStrategy {
    fn default() -> Self {
        ParallelStrategy::Hybrid
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

    /// Get branching factor (average branches per branch point)
    pub fn branching_factor(&self) -> f64 {
        if self.items_branched == 0 {
            0.0
        } else {
            self.total_branches as f64 / self.items_branched as f64
        }
    }

    /// Get prune rate
    pub fn prune_rate(&self) -> f64 {
        if self.items_processed == 0 {
            0.0
        } else {
            self.items_pruned as f64 / self.items_processed as f64
        }
    }

    /// Get completion rate
    pub fn completion_rate(&self) -> f64 {
        if self.items_processed == 0 {
            0.0
        } else {
            self.items_completed as f64 / self.items_processed as f64
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
                    let priority = self.config.strategy.compute_priority(
                        &new_item,
                        self.config.max_depth,
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_item_creation() {
        let state = BpfVerifierState::new();
        let item = ParallelWorkItem::new(state, 0, 0, 1);
        
        assert_eq!(item.insn_idx, 0);
        assert_eq!(item.id, 1);
        assert_eq!(item.depth, 0);
        assert!(item.parent_id.is_none());
    }

    #[test]
    fn test_work_item_child() {
        let state = BpfVerifierState::new();
        let parent = ParallelWorkItem::new(state.clone(), 0, 0, 1);
        let child = parent.child(state, 5, 2);
        
        assert_eq!(child.insn_idx, 5);
        assert_eq!(child.prev_insn_idx, 0);
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id, Some(1));
    }

    #[test]
    fn test_work_queue_priority() {
        let mut queue = WorkQueue::new(100);
        let state = BpfVerifierState::new();
        
        // Add items with different priorities
        let id1 = queue.alloc_id();
        let id2 = queue.alloc_id();
        let id3 = queue.alloc_id();
        
        queue.push(ParallelWorkItem::new(state.clone(), 0, 0, id1).with_priority(1));
        queue.push(ParallelWorkItem::new(state.clone(), 1, 0, id2).with_priority(3));
        queue.push(ParallelWorkItem::new(state.clone(), 2, 0, id3).with_priority(2));
        
        // Should pop in priority order (highest first)
        assert_eq!(queue.pop().unwrap().priority, 3);
        assert_eq!(queue.pop().unwrap().priority, 2);
        assert_eq!(queue.pop().unwrap().priority, 1);
    }

    #[test]
    fn test_work_queue_steal() {
        let mut queue = WorkQueue::new(100);
        let state = BpfVerifierState::new();
        
        for i in 0..10 {
            let id = queue.alloc_id();
            queue.push(ParallelWorkItem::new(state.clone(), i, 0, id));
        }
        
        let stolen = queue.steal(3);
        assert_eq!(stolen.len(), 3);
        assert_eq!(queue.len(), 7);
    }

    #[test]
    fn test_parallel_config() {
        let config = ParallelConfig::new()
            .with_threads(8)
            .with_strategy(ParallelStrategy::BreadthFirst);
        
        assert_eq!(config.max_threads, 8);
        assert_eq!(config.strategy, ParallelStrategy::BreadthFirst);
    }

    #[test]
    fn test_parallel_explorer() {
        let config = ParallelConfig::single_threaded();
        let mut explorer = ParallelExplorer::new(config);
        
        let state = BpfVerifierState::new();
        explorer.add_initial(state, 0);
        
        assert!(!explorer.is_complete());
        assert_eq!(explorer.queue_size(), 1);
        
        let item = explorer.next_work().unwrap();
        explorer.submit_result(&item, ExploreResult::Complete);
        
        assert!(explorer.is_complete());
        assert_eq!(explorer.stats.items_completed, 1);
    }

    #[test]
    fn test_parallel_explorer_branching() {
        let mut explorer = ParallelExplorer::with_defaults();
        
        let state = BpfVerifierState::new();
        explorer.add_initial(state.clone(), 0);
        
        let item = explorer.next_work().unwrap();
        
        // Simulate branching
        let child1 = item.child(state.clone(), 5, explorer.queue.alloc_id());
        let child2 = item.child(state.clone(), 10, explorer.queue.alloc_id());
        
        explorer.submit_result(&item, ExploreResult::Branched(vec![child1, child2]));
        
        assert_eq!(explorer.queue_size(), 2);
        assert_eq!(explorer.stats.items_branched, 1);
        assert_eq!(explorer.stats.total_branches, 2);
    }

    #[test]
    fn test_parallel_stats() {
        let mut stats = ParallelStats::new();
        
        stats.record_processed();
        stats.record_processed();
        stats.record_completed();
        stats.record_pruned();
        stats.record_branched(3);
        
        assert_eq!(stats.items_processed, 2);
        assert_eq!(stats.items_completed, 1);
        assert_eq!(stats.items_pruned, 1);
        assert_eq!(stats.branching_factor(), 3.0);
        assert_eq!(stats.prune_rate(), 0.5);
    }

    #[test]
    fn test_merge_parallel_results() {
        let results = vec![
            ExploreResult::Complete,
            ExploreResult::Pruned,
            ExploreResult::Complete,
        ];
        
        let merged = merge_parallel_results(results);
        
        assert_eq!(merged.paths_merged, 3);
        assert_eq!(merged.conflicts, 0);
        assert!(merged.all_succeeded);
        assert!(merged.error.is_none());
    }

    #[test]
    fn test_merge_parallel_results_with_error() {
        let results = vec![
            ExploreResult::Complete,
            ExploreResult::Error(VerifierError::InfiniteLoop(0)),
            ExploreResult::Pruned,
        ];
        
        let merged = merge_parallel_results(results);
        
        assert!(!merged.all_succeeded);
        assert!(merged.error.is_some());
    }

    #[test]
    fn test_parallel_strategy_priority() {
        let state = BpfVerifierState::new();
        let mut item = ParallelWorkItem::new(state, 0, 0, 1);
        item.depth = 5;
        item.priority = 10;
        
        let bf_priority = ParallelStrategy::BreadthFirst.compute_priority(&item, 100);
        let df_priority = ParallelStrategy::DepthFirst.compute_priority(&item, 100);
        
        assert_eq!(bf_priority, 95); // 100 - 5
        assert_eq!(df_priority, 5);  // depth
    }
}
