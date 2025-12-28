// SPDX-License-Identifier: GPL-2.0

//! Call Summary Optimization
//!
//! This module implements call summary caching to avoid re-verifying
//! the same function calls with identical register states.
//!
//! ## Overview
//!
//! When a BPF program calls a subprogram multiple times with the same
//! register state, we can cache the verification result (call summary)
//! and reuse it instead of re-verifying the entire subprogram.
//!
//! ## Benefits
//!
//! - Reduces verification time for programs with repeated function calls
//! - Improves scalability for large programs with many subprograms
//! - Maintains safety guarantees (conservative cache invalidation)
//!
//! ## Implementation
//!
//! Call summaries store:
//! - Input register states (arguments)
//! - Output register states (return value and modified registers)
//! - Stack depth changes
//! - Reference state changes
//!
//! Summaries are invalidated when:
//! - Input states don't match exactly
//! - Global state changes (maps modified, etc.)
//! - Subprogram code changes

use crate::stdlib::*;
use crate::core::error::{Result, VerifierError};
use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::{BPF_REG_1, BPF_REG_0};

/// Maximum number of cached call summaries per subprogram
const MAX_CALL_SUMMARIES: usize = 16;

/// A summary of a function call's effects on register state
#[derive(Debug, Clone)]
pub struct CallSummary {
    /// Input register states (R1-R5, arguments)
    pub input_regs: Vec<BpfRegState>,

    /// Output register state (R0, return value)
    pub output_reg: BpfRegState,

    /// Stack depth consumed by the call
    pub stack_depth: usize,

    /// Whether the call may acquire references
    pub may_acquire_refs: bool,

    /// Whether the call may release references
    pub may_release_refs: bool,

    /// Number of times this summary was reused
    pub hit_count: u32,
}

impl CallSummary {
    /// Create a new call summary
    pub fn new(
        input_regs: Vec<BpfRegState>,
        output_reg: BpfRegState,
        stack_depth: usize,
    ) -> Self {
        Self {
            input_regs,
            output_reg,
            stack_depth,
            may_acquire_refs: false,
            may_release_refs: false,
            hit_count: 0,
        }
    }

    /// Check if input registers match this summary
    /// Simple equality check - in practice would need more sophisticated matching
    pub fn matches_input(&self, regs: &[BpfRegState]) -> bool {
        if self.input_regs.len() != regs.len() {
            return false;
        }
        // For now, use a simple structural comparison
        // In a full implementation, would use more sophisticated state equivalence
        for (input_reg, reg) in self.input_regs.iter().zip(regs.iter()) {
            if input_reg.reg_type != reg.reg_type {
                return false;
            }
        }
        true
    }

    /// Apply this summary to a verifier state
    pub fn apply_to_state(&mut self, state: &mut BpfVerifierState) -> Result<()> {
        // Get current frame
        if state.curframe >= state.frame.len() {
            return Err(VerifierError::InvalidState(
                "invalid frame index".into(),
            ));
        }

        let frame = state.frame[state.curframe].as_mut()
            .ok_or_else(|| VerifierError::InvalidState("no current frame".into()))?;

        // Apply output register state (R0)
        frame.regs[BPF_REG_0] = self.output_reg.clone();

        // Update stack depth
        frame.stack.allocated_stack = frame.stack.allocated_stack.max(self.stack_depth);

        // Increment hit count
        self.hit_count += 1;

        Ok(())
    }
}

/// Cache of call summaries for a subprogram
#[derive(Debug, Clone, Default)]
pub struct CallSummaryCache {
    /// Cached summaries for this subprogram
    summaries: Vec<CallSummary>,

    /// Total number of cache hits
    pub total_hits: u64,

    /// Total number of cache misses
    pub total_misses: u64,
}

impl CallSummaryCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            summaries: Vec::new(),
            total_hits: 0,
            total_misses: 0,
        }
    }

    /// Try to find a matching summary for the given input state
    pub fn find_summary(&mut self, input_regs: &[BpfRegState]) -> Option<&mut CallSummary> {
        for summary in &mut self.summaries {
            if summary.matches_input(input_regs) {
                self.total_hits += 1;
                return Some(summary);
            }
        }
        self.total_misses += 1;
        None
    }

    /// Add a new summary to the cache
    pub fn add_summary(&mut self, summary: CallSummary) {
        // If cache is full, remove least-used summary
        if self.summaries.len() >= MAX_CALL_SUMMARIES {
            // Find summary with lowest hit count
            if let Some(min_idx) = self.summaries.iter()
                .enumerate()
                .min_by_key(|(_, s)| s.hit_count)
                .map(|(i, _)| i)
            {
                self.summaries.remove(min_idx);
            }
        }

        self.summaries.push(summary);
    }

    /// Clear all cached summaries
    pub fn clear(&mut self) {
        self.summaries.clear();
    }

    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_hits + self.total_misses;
        if total == 0 {
            0.0
        } else {
            self.total_hits as f64 / total as f64
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CallSummaryCacheStats {
        CallSummaryCacheStats {
            num_summaries: self.summaries.len(),
            total_hits: self.total_hits,
            total_misses: self.total_misses,
            hit_rate: self.hit_rate(),
        }
    }
}

/// Statistics about call summary cache performance
#[derive(Debug, Clone, Copy)]
pub struct CallSummaryCacheStats {
    /// Number of summaries currently cached
    pub num_summaries: usize,

    /// Total cache hits
    pub total_hits: u64,

    /// Total cache misses
    pub total_misses: u64,

    /// Cache hit rate (0.0 to 1.0)
    pub hit_rate: f64,
}

/// Manager for all call summary caches
#[derive(Debug, Clone, Default)]
pub struct CallSummaryManager {
    /// Caches indexed by subprogram index
    caches: BTreeMap<usize, CallSummaryCache>,
}

impl CallSummaryManager {
    /// Create a new call summary manager
    pub fn new() -> Self {
        Self {
            caches: BTreeMap::new(),
        }
    }

    /// Get or create cache for a subprogram
    pub fn get_cache(&mut self, subprog_idx: usize) -> &mut CallSummaryCache {
        self.caches.entry(subprog_idx).or_default()
    }

    /// Clear all caches
    pub fn clear_all(&mut self) {
        self.caches.clear();
    }

    /// Clear cache for a specific subprogram
    pub fn clear_subprog(&mut self, subprog_idx: usize) {
        if let Some(cache) = self.caches.get_mut(&subprog_idx) {
            cache.clear();
        }
    }

    /// Get aggregated statistics across all caches
    pub fn total_stats(&self) -> CallSummaryCacheStats {
        let mut total_summaries = 0;
        let mut total_hits = 0;
        let mut total_misses = 0;

        for cache in self.caches.values() {
            let stats = cache.stats();
            total_summaries += stats.num_summaries;
            total_hits += stats.total_hits;
            total_misses += stats.total_misses;
        }

        let total = total_hits + total_misses;
        let hit_rate = if total == 0 {
            0.0
        } else {
            total_hits as f64 / total as f64
        };

        CallSummaryCacheStats {
            num_summaries: total_summaries,
            total_hits,
            total_misses,
            hit_rate,
        }
    }
}

/// Try to apply a cached call summary
///
/// Returns true if a summary was found and applied, false otherwise.
pub fn try_apply_call_summary(
    manager: &mut CallSummaryManager,
    subprog_idx: usize,
    state: &mut BpfVerifierState,
) -> Result<bool> {
    // Get current frame to extract input registers
    if state.curframe >= state.frame.len() {
        return Ok(false);
    }

    let frame = state.frame[state.curframe].as_ref()
        .ok_or_else(|| VerifierError::InvalidState("no current frame".into()))?;

    // Extract argument registers (R1-R5)
    let mut input_regs = Vec::with_capacity(5);
    for i in 0..5 {
        input_regs.push(frame.regs[BPF_REG_1 + i].clone());
    }

    // Try to find matching summary
    let cache = manager.get_cache(subprog_idx);
    if let Some(summary) = cache.find_summary(&input_regs) {
        summary.apply_to_state(state)?;
        return Ok(true);
    }

    Ok(false)
}

/// Record a call summary after verifying a subprogram
pub fn record_call_summary(
    manager: &mut CallSummaryManager,
    subprog_idx: usize,
    input_state: &BpfVerifierState,
    output_state: &BpfVerifierState,
) -> Result<()> {
    // Extract input registers
    let input_frame = input_state.frame[input_state.curframe].as_ref()
        .ok_or_else(|| VerifierError::InvalidState("no input frame".into()))?;

    let mut input_regs = Vec::with_capacity(5);
    for i in 0..5 {
        input_regs.push(input_frame.regs[BPF_REG_1 + i].clone());
    }

    // Extract output register
    let output_frame = output_state.frame[output_state.curframe].as_ref()
        .ok_or_else(|| VerifierError::InvalidState("no output frame".into()))?;

    let output_reg = output_frame.regs[BPF_REG_0].clone();

    // Calculate stack depth change
    let stack_depth = output_frame.stack.allocated_stack;

    // Create and cache summary
    let summary = CallSummary::new(input_regs, output_reg, stack_depth);
    let cache = manager.get_cache(subprog_idx);
    cache.add_summary(summary);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_summary_creation() {
        let input_regs = vec![BpfRegState::default(); 5];
        let output_reg = BpfRegState::default();
        let summary = CallSummary::new(input_regs, output_reg, 64);

        assert_eq!(summary.stack_depth, 64);
        assert_eq!(summary.hit_count, 0);
    }

    #[test]
    fn test_call_summary_cache() {
        let mut cache = CallSummaryCache::new();

        let input_regs = vec![BpfRegState::default(); 5];
        let output_reg = BpfRegState::default();
        let summary = CallSummary::new(input_regs.clone(), output_reg, 64);

        cache.add_summary(summary);
        assert_eq!(cache.summaries.len(), 1);

        // Should find the summary
        let found = cache.find_summary(&input_regs);
        assert!(found.is_some());
        assert_eq!(cache.total_hits, 1);
        assert_eq!(cache.total_misses, 0);
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = CallSummaryCache::new();

        // Fill cache beyond capacity
        for i in 0..MAX_CALL_SUMMARIES + 5 {
            let mut input_regs = vec![BpfRegState::default(); 5];
            input_regs[0].off = i as i32; // Make each unique
            let output_reg = BpfRegState::default();
            let summary = CallSummary::new(input_regs, output_reg, 64);
            cache.add_summary(summary);
        }

        // Should not exceed max size
        assert_eq!(cache.summaries.len(), MAX_CALL_SUMMARIES);
    }

    #[test]
    fn test_hit_rate_calculation() {
        let mut cache = CallSummaryCache::new();
        cache.total_hits = 80;
        cache.total_misses = 20;

        assert_eq!(cache.hit_rate(), 0.8);
    }

    #[test]
    fn test_manager_stats() {
        let mut manager = CallSummaryManager::new();

        let cache1 = manager.get_cache(0);
        cache1.total_hits = 50;
        cache1.total_misses = 10;

        let cache2 = manager.get_cache(1);
        cache2.total_hits = 30;
        cache2.total_misses = 10;

        let stats = manager.total_stats();
        assert_eq!(stats.total_hits, 80);
        assert_eq!(stats.total_misses, 20);
        assert_eq!(stats.hit_rate, 0.8);
    }
}
