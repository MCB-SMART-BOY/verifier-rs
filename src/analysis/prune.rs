//! State pruning for BPF verifier
//!
//! This module implements state pruning optimization. When exploring
//! different paths through a BPF program, if we reach a program point
//! with a state that is "equivalent to or more restrictive than" a
//! previously seen state, we can skip further exploration.
//!
//! The key insight is that if state A is more restrictive than state B,
//! and we've already verified that B leads to a safe exit, then A
//! must also lead to a safe exit.
//!
//! This implements the `is_state_visited()` and related functions from
//! the kernel verifier.

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};
use crate::analysis::states_equal::{
    states_equal_with_config,
    CompareConfig,
    CompareMode,
};
use crate::analysis::precision::mark_all_scalars_precise;


use alloc::vec::Vec;

use alloc::collections::BTreeMap as HashMap;

/// Range comparison mode for state comparison
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeMode {
    /// Exact match required
    Exact,
    /// Current state must be within old state's ranges
    RangeWithin,
    /// Not exact - allow subsumption
    NotExact,
}

/// State cache entry for pruning
#[derive(Debug, Clone)]
pub struct StateListHead {
    /// List of states seen at this instruction
    pub states: Vec<CachedState>,
}

impl Default for StateListHead {
    fn default() -> Self {
        Self::new()
    }
}

impl StateListHead {
    /// Create a new empty state list
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }
}

/// Unique identifier for a cached state
pub type StateId = u64;

/// A cached verifier state for pruning comparisons
#[derive(Debug, Clone)]
pub struct CachedState {
    /// Unique identifier for this cached state
    pub id: StateId,
    /// The verifier state at this point
    pub state: BpfVerifierState,
    /// Instruction index where this state was saved
    pub insn_idx: usize,
    /// Whether this state has been verified to be safe (all branches completed)
    pub verified: bool,
    /// Number of branches from this state that haven't completed
    pub branches: u32,
    /// Hit count for statistics
    pub hit_cnt: u32,
    /// Miss count for eviction heuristics
    pub miss_cnt: u32,
    /// Whether all registers have been read from this state
    pub all_regs_read: bool,
    /// Parent state ID (if this state was derived from another cached state)
    pub parent_id: Option<StateId>,
    /// Whether this state is in the free list (pending removal)
    pub in_free_list: bool,
}

impl CachedState {
    /// Create a new cached state with a unique ID
    pub fn new(id: StateId, state: BpfVerifierState, insn_idx: usize) -> Self {
        Self {
            id,
            state,
            insn_idx,
            verified: false,
            branches: 1, // Start with one branch (the current exploration)
            hit_cnt: 0,
            miss_cnt: 0,
            all_regs_read: false,
            parent_id: None,
            in_free_list: false,
        }
    }

    /// Create a new cached state with a parent reference
    pub fn new_with_parent(
        id: StateId,
        state: BpfVerifierState,
        insn_idx: usize,
        parent_id: StateId,
    ) -> Self {
        let mut cached = Self::new(id, state, insn_idx);
        cached.parent_id = Some(parent_id);
        cached
    }

    /// Mark this state as having completed exploration (no more branches)
    pub fn mark_verified(&mut self) {
        self.verified = true;
        self.branches = 0;
    }

    /// Add a branch from this state
    pub fn add_branch(&mut self) {
        self.branches += 1;
    }

    /// Complete a branch from this state
    /// Returns true if this was the last branch (state is now verified)
    pub fn complete_branch(&mut self) -> bool {
        if self.branches > 0 {
            self.branches -= 1;
        }
        if self.branches == 0 {
            self.verified = true;
            true
        } else {
            false
        }
    }
}

/// State cache for all instructions
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct StateCache {
    /// Map from instruction index to list of states
    pub cache: HashMap<usize, StateListHead>,
    /// Hash-based index for faster state lookup
    /// Maps (insn_idx, state_hash) -> indices into states vector
    pub hash_index: HashMap<(usize, u64), Vec<usize>>,
    /// Map from state ID to (insn_idx, index in states vector)
    /// Used for fast parent lookup during update_branch_counts
    pub id_to_location: HashMap<StateId, (usize, usize)>,
    /// Next state ID to assign
    pub next_state_id: StateId,
    /// Total number of states cached
    pub total_states: usize,
    /// Peak number of states (for statistics)
    pub peak_states: usize,
    /// Number of pruning hits
    pub prune_hits: usize,
    /// Number of hash hits (subset of prune_hits)
    pub hash_hits: usize,
    /// Number of loop detections
    pub loop_detections: usize,
    /// Number of states freed
    pub states_freed: usize,
}

/// Compute a hash of a verifier state for fast comparison
/// 
/// This hash is used to quickly filter out obviously different states
/// before doing the expensive full comparison. The hash captures:
/// - Frame count and current frame index
/// - Register types and key scalar bounds
/// - Stack allocation state
pub fn hash_verifier_state(state: &BpfVerifierState) -> u64 {
    // Use a simple FNV-1a like hash
    const FNV_PRIME: u64 = 0x100000001b3;
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    
    let mut hash = FNV_OFFSET;
    
    // Hash frame structure
    hash ^= state.curframe as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    
    // Hash current function's registers (most important for pruning)
    if let Some(func) = state.cur_func() {
        // Hash R0-R10 types and key properties
        for (i, reg) in func.regs.iter().enumerate() {
            // Combine register index with type
            hash ^= ((i as u64) << 8) | (reg.reg_type as u64);
            hash = hash.wrapping_mul(FNV_PRIME);
            
            // For scalars, include bounds info in hash
            if reg.reg_type == BpfRegType::ScalarValue {
                // Use a mix of min/max bounds
                hash ^= (reg.umin_value >> 32) ^ (reg.umax_value & 0xFFFFFFFF);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
            
            // For pointers, include offset
            if reg.is_pointer() {
                hash ^= reg.off as u64;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
        
        // Hash stack allocation size
        hash ^= func.stack.allocated_stack as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    
    hash
}

/// Compute a lightweight hash for quick filtering
/// This is faster but less precise than full hash
pub fn hash_verifier_state_quick(state: &BpfVerifierState) -> u64 {
    let mut hash: u64 = state.curframe as u64;
    
    if let Some(func) = state.cur_func() {
        // Just hash register types
        for reg in &func.regs {
            hash = hash.rotate_left(5) ^ (reg.reg_type as u64);
        }
        hash ^= func.stack.allocated_stack as u64;
    }
    
    hash
}

impl StateCache {
    /// Create a new empty state cache
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new unique state ID
    fn alloc_state_id(&mut self) -> StateId {
        let id = self.next_state_id;
        self.next_state_id += 1;
        id
    }

    /// Get states at an instruction
    pub fn get(&self, insn_idx: usize) -> Option<&StateListHead> {
        self.cache.get(&insn_idx)
    }

    /// Get mutable states at an instruction
    pub fn get_mut(&mut self, insn_idx: usize) -> Option<&mut StateListHead> {
        self.cache.get_mut(&insn_idx)
    }

    /// Get a cached state by its ID
    pub fn get_by_id(&self, id: StateId) -> Option<&CachedState> {
        let (insn_idx, state_idx) = self.id_to_location.get(&id)?;
        self.cache.get(insn_idx)?.states.get(*state_idx)
    }

    /// Get a mutable cached state by its ID
    pub fn get_by_id_mut(&mut self, id: StateId) -> Option<&mut CachedState> {
        let (insn_idx, state_idx) = self.id_to_location.get(&id)?.clone();
        self.cache.get_mut(&insn_idx)?.states.get_mut(state_idx)
    }

    /// Add a state at an instruction, returns the assigned state ID
    pub fn push_state(&mut self, insn_idx: usize, state: BpfVerifierState) -> StateId {
        self.push_state_with_parent(insn_idx, state, None)
    }

    /// Add a state at an instruction with a parent reference
    pub fn push_state_with_parent(
        &mut self,
        insn_idx: usize,
        state: BpfVerifierState,
        parent_id: Option<StateId>,
    ) -> StateId {
        // Allocate a unique ID
        let state_id = self.alloc_state_id();
        
        // Compute hash for indexing
        let state_hash = hash_verifier_state(&state);
        
        let entry = self.cache.entry(insn_idx).or_default();
        let state_idx = entry.states.len();
        
        // Create cached state with or without parent
        let cached = if let Some(pid) = parent_id {
            CachedState::new_with_parent(state_id, state, insn_idx, pid)
        } else {
            CachedState::new(state_id, state, insn_idx)
        };
        entry.states.push(cached);
        
        // Add to hash index
        self.hash_index
            .entry((insn_idx, state_hash))
            .or_default()
            .push(state_idx);
        
        // Add to ID lookup
        self.id_to_location.insert(state_id, (insn_idx, state_idx));
        
        self.total_states += 1;
        self.peak_states = self.peak_states.max(self.total_states);
        
        state_id
    }

    /// Update branch counts starting from a state, walking up the parent chain
    ///
    /// This implements the kernel's `update_branch_counts()` function.
    /// When a path completes (exit or prune), we decrement branch counts
    /// up the parent chain. When a state's branch count reaches 0, it's
    /// fully verified and can be used for pruning.
    ///
    /// Returns Ok(()) on success, or an error if an inconsistency is detected.
    pub fn update_branch_counts(&mut self, start_id: StateId) -> Result<()> {
        let mut current_id = Some(start_id);
        
        while let Some(id) = current_id {
            // Get the state's location
            let location = match self.id_to_location.get(&id) {
                Some(loc) => loc.clone(),
                None => break, // State not found (might have been freed)
            };
            
            // Get the cached state
            let cached = match self.cache.get_mut(&location.0)
                .and_then(|head| head.states.get_mut(location.1))
            {
                Some(c) => c,
                None => break,
            };
            
            // Skip if already in free list
            if cached.in_free_list {
                current_id = cached.parent_id;
                continue;
            }
            
            // Decrement branch count
            let all_branches_done = cached.complete_branch();
            let parent_id = cached.parent_id;
            
            // If there are still branches remaining, stop propagating
            if !all_branches_done {
                break;
            }
            
            // All branches from this state are done - it's now fully verified
            // Continue to parent
            current_id = parent_id;
        }
        
        Ok(())
    }

    /// Mark a state as being in the free list (pending removal)
    pub fn mark_for_removal(&mut self, id: StateId) {
        if let Some(cached) = self.get_by_id_mut(id) {
            if !cached.in_free_list {
                cached.in_free_list = true;
                self.states_freed += 1;
                if self.total_states > 0 {
                    self.total_states -= 1;
                }
            }
        }
    }

    /// Evict a state based on miss/hit heuristics
    /// 
    /// States with high miss count relative to hit count are unlikely
    /// to be useful for pruning and can be evicted.
    pub fn maybe_evict_state(&mut self, id: StateId, is_force_checkpoint: bool) {
        if let Some(cached) = self.get_by_id_mut(id) {
            // Use bigger threshold for checkpoints to help iterator convergence
            let n = if is_force_checkpoint && cached.branches > 0 { 64 } else { 3 };
            
            if cached.miss_cnt > cached.hit_cnt * n + n {
                self.mark_for_removal(id);
            }
        }
    }

    /// Check if the current state can be pruned against cached states
    /// 
    /// Uses hash-based lookup for faster matching when many states exist
    pub fn check_prune(&mut self, insn_idx: usize, cur: &BpfVerifierState) -> bool {
        let cur_hash = hash_verifier_state(cur);
        
        // First try hash-based lookup (fast path)
        if let Some(indices) = self.hash_index.get(&(insn_idx, cur_hash)) {
            if let Some(head) = self.cache.get(&insn_idx) {
                for &idx in indices {
                    if let Some(cached) = head.states.get(idx) {
                        if cached.verified && states_equal_for_pruning(cur, &cached.state) {
                            self.prune_hits += 1;
                            self.hash_hits += 1;
                            return true;
                        }
                    }
                }
            }
        }
        
        // Fall back to full scan (handles hash collisions and different-hash equivalent states)
        if let Some(head) = self.cache.get(&insn_idx) {
            for cached in &head.states {
                if cached.verified && states_equal_for_pruning(cur, &cached.state) {
                    self.prune_hits += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Check prune using only hash-based lookup (faster but may miss some matches)
    pub fn check_prune_fast(&mut self, insn_idx: usize, cur: &BpfVerifierState) -> bool {
        let cur_hash = hash_verifier_state(cur);
        
        if let Some(indices) = self.hash_index.get(&(insn_idx, cur_hash)) {
            if let Some(head) = self.cache.get(&insn_idx) {
                for &idx in indices {
                    if let Some(cached) = head.states.get(idx) {
                        if cached.verified && states_equal_for_pruning(cur, &cached.state) {
                            self.prune_hits += 1;
                            self.hash_hits += 1;
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Mark all states at an instruction as verified
    pub fn mark_verified(&mut self, insn_idx: usize) {
        if let Some(head) = self.cache.get_mut(&insn_idx) {
            for cached in &mut head.states {
                cached.verified = true;
            }
        }
    }

    /// Get hash efficiency statistics
    pub fn hash_efficiency(&self) -> f64 {
        if self.prune_hits == 0 {
            0.0
        } else {
            self.hash_hits as f64 / self.prune_hits as f64
        }
    }

    /// Clear all cached states
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hash_index.clear();
        self.id_to_location.clear();
        // Don't reset next_state_id to avoid ID reuse
        self.total_states = 0;
        self.prune_hits = 0;
        self.hash_hits = 0;
        self.loop_detections = 0;
        self.states_freed = 0;
    }

    /// Increment miss count for a state
    pub fn increment_miss(&mut self, id: StateId) {
        if let Some(cached) = self.get_by_id_mut(id) {
            cached.miss_cnt += 1;
        }
    }

    /// Increment hit count for a state
    pub fn increment_hit(&mut self, id: StateId) {
        if let Some(cached) = self.get_by_id_mut(id) {
            cached.hit_cnt += 1;
        }
    }
}

/// Result of checking if a state was visited
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum StateVisitResult {
    /// State can be pruned - equivalent state already verified
    /// Contains the ID of the matching cached state for precision propagation
    Prune(StateId),
    /// Infinite loop detected
    InfiniteLoop,
    /// State should be explored (new state added to cache)
    /// Contains the ID of the newly cached state
    Explore(StateId),
    /// State should be explored but don't add to cache
    ExploreNoCache,
}

/// Context for state visit checking
#[allow(missing_docs)]
#[derive(Default)]
pub struct StateVisitContext {
    /// Whether to force adding a new state
    pub force_new_state: bool,
    /// Whether to add a new state based on heuristics
    pub add_new_state: bool,
    /// Number of jumps processed since last prune point
    pub jmps_since_prune: u32,
    /// Number of instructions processed since last prune point
    pub insns_since_prune: u32,
    /// Jump history length for current state
    pub jmp_history_cnt: u32,
    /// Whether this is an iterator next instruction
    pub is_iter_next: bool,
    /// Whether this is a may_goto instruction
    pub is_may_goto: bool,
    /// Whether this is a callback call
    pub is_callback_call: bool,
    /// Whether this is a force checkpoint (e.g., back edge)
    pub is_force_checkpoint: bool,
    /// Parent state ID for new states
    pub parent_state_id: Option<StateId>,
}


impl StateVisitContext {
    /// Create a new empty visit context
    pub fn new() -> Self {
        Self::default()
    }

    /// Update heuristics for whether to add a new state
    pub fn update_heuristics(&mut self) {
        // Avoid accumulating infinitely long jmp history
        if self.jmp_history_cnt > 40 {
            self.force_new_state = true;
        }

        // Heuristic: add new state if we've seen enough jumps and instructions
        // This helps with pruning efficiency
        if self.jmps_since_prune >= 2 && self.insns_since_prune >= 8 {
            self.add_new_state = true;
        }
    }

    /// Check if we should skip adding state due to loop heuristics
    pub fn should_skip_add_in_loop(&self) -> bool {
        // In a loop, avoid adding states too frequently
        !self.force_new_state
            && self.jmps_since_prune < 20
            && self.insns_since_prune < 100
    }
}

/// Check if state was visited and handle accordingly
///
/// This is the main entry point for state pruning, implementing
/// the kernel's `is_state_visited()` function.
///
/// Returns:
/// - `Ok(StateVisitResult::Prune(id))` if state can be pruned (id = matching cached state)
/// - `Ok(StateVisitResult::InfiniteLoop)` if infinite loop detected
/// - `Ok(StateVisitResult::Explore(id))` if state should be explored (id = new cached state)
/// - `Ok(StateVisitResult::ExploreNoCache)` if should explore without caching
/// - `Err(_)` on error
pub fn is_state_visited(
    cache: &mut StateCache,
    insn_idx: usize,
    cur: &BpfVerifierState,
    ctx: &mut StateVisitContext,
) -> Result<StateVisitResult> {
    ctx.update_heuristics();

    let mut loop_detected = false;
    let mut should_add_state = ctx.force_new_state || ctx.add_new_state;
    let mut prune_state_id: Option<StateId> = None;

    // Get cached states at this instruction
    if let Some(head) = cache.get_mut(insn_idx) {
        for cached in &mut head.states {
            // Skip states in free list
            if cached.in_free_list {
                continue;
            }
            
            // Only compare states at the same instruction
            if cached.insn_idx != insn_idx {
                continue;
            }

            // Check for states with pending branches (potential loop)
            if cached.branches > 0 {
                // Handle special cases for iterators
                if ctx.is_iter_next {
                    // Iterator next - check for convergence using RANGE_WITHIN mode
                    // This is a key optimization: if the iterator state has converged
                    // (current ranges within old ranges), we can prune safely
                    let config = CompareConfig::for_range_within();
                    if states_equal_with_config(cur, &cached.state, &config) {
                        cached.hit_cnt += 1;
                        // Mark the cached state as having converged
                        cached.verified = true;
                        prune_state_id = Some(cached.id);
                        break;
                    }
                    // Check if we're making progress (depth increasing)
                    if iter_active_depths_differ(&cached.state, cur) {
                        // Making progress, continue exploring
                        continue;
                    }
                }

                // Handle may_goto special case
                if ctx.is_may_goto {
                    // May_goto depth check - different depths mean different iterations
                    if cur.may_goto_depth != cached.state.may_goto_depth {
                        // Check if states are otherwise equivalent using RANGE_WITHIN
                        // This allows convergence detection for bounded loops
                        let config = CompareConfig::for_range_within();
                        if states_equal_with_config(cur, &cached.state, &config) {
                            // Same state at different may_goto depth - could be infinite
                            if cur.may_goto_depth > cached.state.may_goto_depth + 8 {
                                // Exceeded reasonable depth
                                cache.loop_detections += 1;
                                return Err(VerifierError::InfiniteLoop(insn_idx));
                            }
                            // States are converging - can prune
                            cached.hit_cnt += 1;
                            cached.verified = true;
                            prune_state_id = Some(cached.id);
                            break;
                        }
                        continue;
                    }
                }

                // Handle callback call special case
                if ctx.is_callback_call {
                    // Callback - check for equivalence using RANGE_WITHIN mode
                    // This allows detecting callback convergence
                    if cur.callback_unroll_depth == cached.state.callback_unroll_depth {
                        let config = CompareConfig::for_range_within();
                        if states_equal_with_config(cur, &cached.state, &config) {
                            cached.hit_cnt += 1;
                            prune_state_id = Some(cached.id);
                            break;
                        }
                    } else if cur.callback_unroll_depth > cached.state.callback_unroll_depth + 4 {
                        // Too many callback unrolls
                        return Err(VerifierError::TooComplex(
                            "callback unroll depth exceeded".into()
                        ));
                    }
                    continue;
                }

                // Check for infinite loop - this is a critical safety check
                if states_maybe_looping(&cached.state, cur) {
                    let config = CompareConfig::for_loop_detection();
                    if states_equal_with_config(cur, &cached.state, &config)
                        && !iter_active_depths_differ(&cached.state, cur)
                        && cached.state.may_goto_depth == cur.may_goto_depth
                        && cached.state.callback_unroll_depth == cur.callback_unroll_depth
                    {
                        // States are equivalent - this is an infinite loop
                        cache.loop_detections += 1;
                        return Err(VerifierError::InfiniteLoop(insn_idx));
                    }
                    
                    // Check for widening opportunity - if we've seen similar states
                    // multiple times, we might need to widen bounds
                    if cached.hit_cnt > 3 {
                        // Consider widening - this helps bounded loops converge
                        loop_detected = true;
                    }
                }

                // In a loop - be conservative about adding states
                if ctx.should_skip_add_in_loop() {
                    should_add_state = false;
                }
                
                // Increment miss count for states we didn't match
                cached.miss_cnt += 1;
                continue;
            }

            // State has no pending branches (verified) - check for pruning
            let use_exact = incomplete_read_marks(&cached.state);
            let config = if use_exact {
                CompareConfig::for_pruning()
            } else {
                CompareConfig {
                    mode: CompareMode::NotExact,
                    check_precision: false,
                    check_refs: true,
                    check_locks: true,
                }
            };

            if states_equal_with_config(cur, &cached.state, &config) {
                cached.hit_cnt += 1;
                prune_state_id = Some(cached.id);
                break;
            } else {
                // Increment miss count
                cached.miss_cnt += 1;
                
                // Maybe evict this state based on miss/hit ratio
                let n = if ctx.is_force_checkpoint && cached.branches > 0 { 64 } else { 3 };
                if cached.miss_cnt > cached.hit_cnt * n + n {
                    cached.in_free_list = true;
                }
            }
        }
    }

    // Return prune result if we found a matching state
    if let Some(state_id) = prune_state_id {
        cache.prune_hits += 1;
        return Ok(StateVisitResult::Prune(state_id));
    }
    
    if loop_detected && !ctx.force_new_state {
        // We detected a potential loop but didn't prove it's infinite
        // Force adding a new state to track progress
        should_add_state = true;
    }

    // Add current state to cache if appropriate
    if should_add_state {
        let new_state_id = cache.push_state_with_parent(
            insn_idx,
            cur.clone(),
            ctx.parent_state_id,
        );
        Ok(StateVisitResult::Explore(new_state_id))
    } else {
        Ok(StateVisitResult::ExploreNoCache)
    }
}

/// Check if two states are equivalent for pruning purposes
///
/// State `cur` can be pruned if it's "at least as restrictive" as `old`.
/// This means any property that holds for `old` also holds for `cur`.
pub fn states_equal_for_pruning(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    let config = CompareConfig::for_pruning();
    states_equal_with_config(cur, old, &config)
}

/// Check if states might be in a loop (quick heuristic check)
///
/// This is a fast check to see if two states *might* represent
/// iterations of the same loop. If this returns false, they
/// definitely aren't looping. If true, further checks are needed.
pub fn states_maybe_looping(old: &BpfVerifierState, cur: &BpfVerifierState) -> bool {
    // Quick check: frame depth must match
    if cur.curframe != old.curframe {
        return false;
    }

    // Check current frame's registers for suspicious similarity
    let cur_func = match cur.frame.get(cur.curframe).and_then(|f| f.as_ref()) {
        Some(f) => f,
        None => return false,
    };
    let old_func = match old.frame.get(old.curframe).and_then(|f| f.as_ref()) {
        Some(f) => f,
        None => return false,
    };

    // Count how many registers have the same type
    let mut same_type_count = 0;
    for (cur_reg, old_reg) in cur_func.regs.iter().zip(old_func.regs.iter()) {
        if cur_reg.reg_type == old_reg.reg_type {
            same_type_count += 1;
        }
    }

    // If most registers have the same type, might be looping
    same_type_count >= 8
}

/// Check if iterator active depths differ between states
///
/// If iterator depths differ, the states represent different
/// loop iterations and aren't truly equivalent.
pub fn iter_active_depths_differ(old: &BpfVerifierState, cur: &BpfVerifierState) -> bool {
    for i in 0..=cur.curframe.min(old.curframe) {
        let cur_func = match cur.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let old_func = match old.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };

        // Check stack slots for iterator state differences
        for (cur_slot, old_slot) in cur_func.stack.stack.iter().zip(old_func.stack.stack.iter()) {
            let cur_type = cur_slot.slot_type[BPF_REG_SIZE - 1];
            let old_type = old_slot.slot_type[BPF_REG_SIZE - 1];

            if cur_type == BpfStackSlotType::Iter && old_type == BpfStackSlotType::Iter {
                if cur_slot.spilled_ptr.iter.depth != old_slot.spilled_ptr.iter.depth {
                    return true;
                }
                if cur_slot.spilled_ptr.iter.state != old_slot.spilled_ptr.iter.state {
                    return true;
                }
            }
        }
    }

    false
}

/// Check for iterator convergence
///
/// For open-coded iterators, we need to detect when the loop
/// has converged to a fixpoint. Returns true if the states are
/// equivalent and contain an active iterator, indicating the
/// loop can be safely terminated.
pub fn check_iter_convergence(cur: &BpfVerifierState, old: &BpfVerifierState) -> bool {
    let config = CompareConfig::for_pruning();
    if !states_equal_with_config(cur, old, &config) {
        return false;
    }

    // Check that iterator is in active state
    let cur_func = match cur.frame.get(cur.curframe).and_then(|f| f.as_ref()) {
        Some(f) => f,
        None => return false,
    };

    // Look for active iterator on stack
    for slot in &cur_func.stack.stack {
        let slot_type = slot.slot_type[BPF_REG_SIZE - 1];
        if slot_type == BpfStackSlotType::Iter
            && slot.spilled_ptr.iter.state == BpfIterState::Active {
                return true;
            }
    }

    false
}

/// Check if a state has incomplete read marks
///
/// If read marks are incomplete, we need exact matching
/// to avoid missing required precision propagation.
fn incomplete_read_marks(state: &BpfVerifierState) -> bool {
    // Check if any register or stack slot hasn't had its
    // liveness fully determined
    for i in 0..=state.curframe {
        let func = match state.frame.get(i).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };

        // Check registers - if any are live but not precise,
        // read marks are still propagating
        for reg in &func.regs {
            // A register that's been read from but isn't marked precise
            // indicates incomplete precision propagation
            if reg.reg_type != BpfRegType::NotInit && !reg.precise {
                // This is a simplification - full implementation would
                // check actual liveness bits
                return true;
            }
        }
    }

    false
}

/// Clean up old states to manage memory
pub fn clean_old_states(cache: &mut StateCache, cur_insn: usize, window: usize) {
    // Remove states from instructions far behind current position
    let threshold = cur_insn.saturating_sub(window);
    cache.cache.retain(|&idx, _| idx >= threshold);
}

/// Clean live states - remove stale cached states
///
/// This removes cached states that are no longer useful for pruning
/// because they reference liveness information that has been superseded.
pub fn clean_live_states(cache: &mut StateCache, insn_idx: usize, cur: &BpfVerifierState) {
    if let Some(head) = cache.get_mut(insn_idx) {
        head.states.retain(|cached| {
            // Keep states that are still useful for pruning
            // Remove states with stale liveness info
            !has_stale_liveness(&cached.state, cur)
        });
    }
}

/// Check if a cached state has stale liveness information
///
/// A cached state becomes stale when:
/// 1. A register was marked as not-live in cached state but is now live
/// 2. The cached state's liveness info is from a different execution path
///    that doesn't apply to the current path
fn has_stale_liveness(cached: &BpfVerifierState, cur: &BpfVerifierState) -> bool {
    // Compare frames to detect stale liveness
    for frame_idx in 0..=cached.curframe.min(cur.curframe) {
        let cached_func = match cached.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let cur_func = match cur.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        
        // Check registers for stale liveness
        for (i, (cached_reg, cur_reg)) in cached_func.regs.iter()
            .zip(cur_func.regs.iter()).enumerate() 
        {
            // If register types don't match, liveness info may be stale
            if cached_reg.reg_type != cur_reg.reg_type {
                // Type changed - check if this affects liveness
                // A pointer becoming scalar (or vice versa) invalidates
                // the cached liveness assumptions
                if cached_reg.is_pointer() != cur_reg.is_pointer() {
                    return true;
                }
            }
            
            // If cached marked as not needing precision but current does,
            // the cached state may lead to incorrect pruning
            if !cached_reg.precise && cur_reg.precise 
                && cur_reg.reg_type == BpfRegType::ScalarValue {
                // Current path requires precision that cached doesn't have
                // This could cause incorrect pruning
                return true;
            }
            
            // Check for ID mismatches in pointer tracking
            // If IDs don't match, the liveness relationships are stale
            if cached_reg.id != 0 && cur_reg.id != 0 
                && cached_reg.id != cur_reg.id 
                && cached_reg.reg_type == cur_reg.reg_type {
                // Same type but different ID - relationships may be stale
                // This is conservative; some cases might still be valid
                let _ = i; // suppress warning
            }
        }
        
        // Check stack slots for stale liveness
        for (cached_slot, cur_slot) in cached_func.stack.stack.iter()
            .zip(cur_func.stack.stack.iter()) 
        {
            if cached_slot.slot_type != cur_slot.slot_type {
                // Stack slot type changed - could affect liveness
                if cached_slot.slot_type[0] != BpfStackSlotType::Invalid
                    && cur_slot.slot_type[0] != BpfStackSlotType::Invalid {
                    // Both have data but different types
                    return true;
                }
            }
        }
    }
    
    // Check for frame count mismatch
    if cached.curframe != cur.curframe {
        // Different call depth - liveness info may not apply
        // This is handled separately in state comparison
    }
    
    false
}

/// Mark state as having a branch
pub fn mark_branching(cache: &mut StateCache, insn_idx: usize) {
    if let Some(head) = cache.get_mut(insn_idx) {
        for cached in &mut head.states {
            cached.branches += 1;
        }
    }
}

/// Mark that a branch from a cached state has completed
pub fn complete_branch(cache: &mut StateCache, insn_idx: usize) {
    if let Some(head) = cache.get_mut(insn_idx) {
        for cached in &mut head.states {
            cached.complete_branch();
        }
    }
}

/// Propagate liveness backwards through cached states
///
/// When we discover that certain registers are live (read) at a later point,
/// we need to propagate this information back to earlier cached states.
/// This ensures that pruning doesn't incorrectly assume a register is dead
/// when it will be read later.
///
/// # Arguments
/// * `cache` - The state cache containing cached verification states
/// * `from_idx` - The instruction index where liveness was discovered
/// * `to_idx` - The instruction index to propagate liveness to
/// * `live_regs` - Bitmask of registers that are live (bit i = register i)
pub fn propagate_liveness(
    cache: &mut StateCache,
    from_idx: usize,
    to_idx: usize,
    live_regs: u16,
) {
    // Skip if no registers are live or indices are invalid
    if live_regs == 0 || from_idx <= to_idx {
        return;
    }
    
    // Get the cached states at the target instruction
    let head = match cache.get_mut(to_idx) {
        Some(h) => h,
        None => return,
    };
    
    // Propagate liveness to all cached states at this instruction
    for cached in &mut head.states {
        // Get the current frame
        let func = match cached.state.frame.get_mut(cached.state.curframe)
            .and_then(|f| f.as_mut()) 
        {
            Some(f) => f,
            None => continue,
        };
        
        // Mark each live register
        for i in 0..MAX_BPF_REG {
            if (live_regs & (1 << i)) != 0 {
                if let Some(reg) = func.regs.get_mut(i) {
                    // Mark register as having been read (live)
                    // This prevents incorrect pruning when the register
                    // will be used later in the program
                    if reg.reg_type != BpfRegType::NotInit {
                        // For scalar registers, this may require precision tracking
                        if reg.reg_type == BpfRegType::ScalarValue && !reg.precise {
                            // The register value matters - mark as needing precision
                            reg.precise = true;
                        }
                    }
                }
            }
        }
    }
}

/// Propagate precision from pruned state to current state
///
/// When we prune a path because it matches a cached state,
/// we need to propagate any precision requirements from the
/// cached state's subsequent execution.
pub fn propagate_precision(
    cur: &mut BpfVerifierState,
    cached: &BpfVerifierState,
) -> Result<()> {
    // Propagate precision requirements from cached to current state
    // This ensures that registers marked as needing precision in the
    // cached path are also marked in the current path
    
    for frame_idx in 0..=cur.curframe.min(cached.curframe) {
        let cur_func = match cur.frame.get_mut(frame_idx).and_then(|f| f.as_mut()) {
            Some(f) => f,
            None => continue,
        };
        let cached_func = match cached.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        
        // Propagate register precision
        for (i, (cur_reg, cached_reg)) in cur_func.regs.iter_mut()
            .zip(cached_func.regs.iter()).enumerate()
        {
            // If cached register needs precision and cur doesn't have it marked
            if cached_reg.precise && !cur_reg.precise
                && cur_reg.reg_type == BpfRegType::ScalarValue {
                    cur_reg.precise = true;
                }
            
            // Check if cached register was read (liveness propagation)
            if cached_reg.live.read && !cur_reg.live.read {
                cur_reg.live.read = true;
            }
            
            let _ = i; // Suppress unused warning
        }
        
        // Propagate stack slot precision
        let cur_slots = cur_func.stack.stack.len();
        let cached_slots = cached_func.stack.stack.len();
        
        for spi in 0..cur_slots.min(cached_slots) {
            if let (Some(cur_slot), Some(cached_slot)) = (
                cur_func.stack.stack.get_mut(spi),
                cached_func.stack.stack.get(spi),
            ) {
                // If both are spilled scalars, propagate precision
                if cur_slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
                    && cached_slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
                    && cached_slot.spilled_ptr.precise && !cur_slot.spilled_ptr.precise
                        && cur_slot.spilled_ptr.reg_type == BpfRegType::ScalarValue {
                            cur_slot.spilled_ptr.precise = true;
                        }
            }
        }
    }
    
    Ok(())
}

/// Propagate precision backwards to parent states
///
/// When a register is marked as precise, we need to walk back through
/// the parent chain to mark all contributing values as precise.
pub fn propagate_precision_to_parent(
    cur: &mut BpfVerifierState,
    parent: &mut BpfVerifierState,
    regno: usize,
) -> Result<()> {
    // Get the register that needs precision
    let needs_precision = if let Some(func) = cur.frame.get(cur.curframe).and_then(|f| f.as_ref()) {
        func.regs.get(regno).map(|r| r.precise).unwrap_or(false)
    } else {
        false
    };
    
    if !needs_precision {
        return Ok(());
    }
    
    // Mark the corresponding register in parent as precise
    if let Some(func) = parent.frame.get_mut(parent.curframe).and_then(|f| f.as_mut()) {
        if let Some(reg) = func.regs.get_mut(regno) {
            if reg.reg_type == BpfRegType::ScalarValue {
                reg.precise = true;
            }
        }
    }
    
    Ok(())
}

/// Jump history entry for tracking branch paths
#[derive(Debug, Clone)]
pub struct JmpHistoryEntry {
    /// Instruction index of the jump
    pub insn_idx: usize,
    /// Previous instruction index
    pub prev_idx: usize,
    /// Jump flags (e.g., whether branch was taken)
    pub flags: u32,
    /// Linked registers bitmap (for precision tracking)
    pub linked_regs: u64,
}

/// Jump history manager
#[derive(Debug, Clone, Default)]
pub struct JmpHistory {
    /// History entries
    pub entries: Vec<JmpHistoryEntry>,
    /// Maximum history length
    pub max_len: usize,
}

impl JmpHistory {
    /// Create a new jump history with the specified maximum length
    pub fn new(max_len: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_len,
        }
    }

    /// Push a new jump history entry
    pub fn push(&mut self, insn_idx: usize, prev_idx: usize, flags: u32, linked_regs: u64) -> bool {
        if self.entries.len() >= self.max_len {
            return false;
        }
        self.entries.push(JmpHistoryEntry {
            insn_idx,
            prev_idx,
            flags,
            linked_regs,
        });
        true
    }

    /// Get the current history length
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear the history
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Checkpoint for state rollback during verification
/// 
/// Checkpoints allow the verifier to save its state at a particular point
/// and roll back if a path proves invalid or too complex.
#[derive(Debug, Clone)]
pub struct StateCheckpoint {
    /// Instruction index where checkpoint was taken
    pub insn_idx: usize,
    /// Saved verifier state
    pub state: BpfVerifierState,
    /// Number of states in cache when checkpoint was taken
    pub cache_size: usize,
    /// Instructions processed at checkpoint time
    pub insns_processed: u64,
    /// States created at checkpoint time
    pub states_created: u64,
    /// Branch depth when checkpoint was taken
    pub branch_depth: u32,
}

impl StateCheckpoint {
    /// Create a new checkpoint
    pub fn new(
        insn_idx: usize,
        state: BpfVerifierState,
        cache_size: usize,
        insns_processed: u64,
        states_created: u64,
        branch_depth: u32,
    ) -> Self {
        Self {
            insn_idx,
            state,
            cache_size,
            insns_processed,
            states_created,
            branch_depth,
        }
    }
}

/// Checkpoint manager for state rollback
#[derive(Debug, Default)]
pub struct CheckpointManager {
    /// Stack of checkpoints
    checkpoints: Vec<StateCheckpoint>,
    /// Maximum number of checkpoints to keep
    max_checkpoints: usize,
    /// Total checkpoints created
    pub total_created: u64,
    /// Total rollbacks performed
    pub total_rollbacks: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            checkpoints: Vec::new(),
            max_checkpoints,
            total_created: 0,
            total_rollbacks: 0,
        }
    }

    /// Save a checkpoint
    pub fn save(&mut self, checkpoint: StateCheckpoint) -> bool {
        if self.checkpoints.len() >= self.max_checkpoints {
            // Remove oldest checkpoint
            self.checkpoints.remove(0);
        }
        self.checkpoints.push(checkpoint);
        self.total_created += 1;
        true
    }

    /// Rollback to last checkpoint, returns the checkpoint if available
    pub fn rollback(&mut self) -> Option<StateCheckpoint> {
        let cp = self.checkpoints.pop();
        if cp.is_some() {
            self.total_rollbacks += 1;
        }
        cp
    }

    /// Rollback to checkpoint at specific instruction
    pub fn rollback_to(&mut self, insn_idx: usize) -> Option<StateCheckpoint> {
        // Find and remove all checkpoints after the target
        while let Some(cp) = self.checkpoints.last() {
            if cp.insn_idx <= insn_idx {
                break;
            }
            self.checkpoints.pop();
        }
        // Return the checkpoint at or before target
        self.rollback()
    }

    /// Get number of active checkpoints
    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    /// Check if there are no checkpoints
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }

    /// Clear all checkpoints
    pub fn clear(&mut self) {
        self.checkpoints.clear();
    }

    /// Peek at the last checkpoint without removing it
    pub fn peek(&self) -> Option<&StateCheckpoint> {
        self.checkpoints.last()
    }
}

/// Complexity metrics for state exploration
#[derive(Debug, Clone, Default)]
pub struct ExplorationMetrics {
    /// Total paths explored
    pub paths_explored: u64,
    /// Paths pruned by state equivalence
    pub paths_pruned: u64,
    /// Paths terminated by exit instruction
    pub paths_completed: u64,
    /// Paths terminated by error
    pub paths_errored: u64,
    /// Maximum path length seen
    pub max_path_length: u32,
    /// Current path length
    pub current_path_length: u32,
    /// Maximum branch depth seen
    pub max_branch_depth: u32,
    /// Current branch depth
    pub current_branch_depth: u32,
    /// States at peak memory
    pub peak_states_in_memory: usize,
    /// Current states in memory
    pub current_states_in_memory: usize,
    /// Back edges detected (potential loops)
    pub back_edges_detected: u32,
    /// Widening operations performed
    pub widenings_performed: u32,
}

impl ExplorationMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record starting a new path
    pub fn start_path(&mut self) {
        self.paths_explored += 1;
        self.current_path_length = 0;
    }

    /// Record an instruction in current path
    pub fn record_insn(&mut self) {
        self.current_path_length += 1;
        if self.current_path_length > self.max_path_length {
            self.max_path_length = self.current_path_length;
        }
    }

    /// Record entering a branch
    pub fn enter_branch(&mut self) {
        self.current_branch_depth += 1;
        if self.current_branch_depth > self.max_branch_depth {
            self.max_branch_depth = self.current_branch_depth;
        }
    }

    /// Record exiting a branch
    pub fn exit_branch(&mut self) {
        self.current_branch_depth = self.current_branch_depth.saturating_sub(1);
    }

    /// Record a pruned path
    pub fn record_prune(&mut self) {
        self.paths_pruned += 1;
    }

    /// Record a completed path (reached exit)
    pub fn record_complete(&mut self) {
        self.paths_completed += 1;
    }

    /// Record an error path
    pub fn record_error(&mut self) {
        self.paths_errored += 1;
    }

    /// Update state memory tracking
    pub fn update_states(&mut self, current: usize) {
        self.current_states_in_memory = current;
        if current > self.peak_states_in_memory {
            self.peak_states_in_memory = current;
        }
    }

    /// Record a back edge (potential loop)
    pub fn record_back_edge(&mut self) {
        self.back_edges_detected += 1;
    }

    /// Record a widening operation
    pub fn record_widening(&mut self) {
        self.widenings_performed += 1;
    }

    /// Get pruning efficiency ratio
    pub fn pruning_efficiency(&self) -> f64 {
        if self.paths_explored == 0 {
            0.0
        } else {
            self.paths_pruned as f64 / self.paths_explored as f64
        }
    }

    /// Get completion rate
    pub fn completion_rate(&self) -> f64 {
        let total = self.paths_completed + self.paths_errored + self.paths_pruned;
        if total == 0 {
            0.0
        } else {
            self.paths_completed as f64 / total as f64
        }
    }
}

impl core::fmt::Display for ExplorationMetrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Exploration Metrics:")?;
        writeln!(f, "  Paths: {} explored, {} pruned, {} completed, {} errored",
            self.paths_explored, self.paths_pruned, 
            self.paths_completed, self.paths_errored)?;
        writeln!(f, "  Max path length: {}, Max branch depth: {}",
            self.max_path_length, self.max_branch_depth)?;
        writeln!(f, "  Peak states in memory: {}", self.peak_states_in_memory)?;
        writeln!(f, "  Back edges: {}, Widenings: {}",
            self.back_edges_detected, self.widenings_performed)?;
        writeln!(f, "  Pruning efficiency: {:.1}%", self.pruning_efficiency() * 100.0)?;
        Ok(())
    }
}

/// Widening operation for loop convergence
/// 
/// When a loop iterates many times without converging, we can widen
/// the bounds to force convergence at the cost of precision.
pub fn widen_scalar_bounds(reg: &mut BpfRegState) {
    if reg.reg_type != BpfRegType::ScalarValue {
        return;
    }

    // Widen unsigned bounds
    if reg.umin_value > 0 {
        reg.umin_value = 0;
    }
    if reg.umax_value < u64::MAX {
        reg.umax_value = u64::MAX;
    }

    // Widen signed bounds
    if reg.smin_value > i64::MIN {
        reg.smin_value = i64::MIN;
    }
    if reg.smax_value < i64::MAX {
        reg.smax_value = i64::MAX;
    }

    // Widen 32-bit bounds
    reg.u32_min_value = 0;
    reg.u32_max_value = u32::MAX;
    reg.s32_min_value = i32::MIN;
    reg.s32_max_value = i32::MAX;

    // Reset tnum to unknown
    reg.var_off = crate::bounds::tnum::Tnum::unknown();
}

/// Selective widening - only widen registers that are changing in a loop
pub fn widen_loop_registers(
    cur: &mut BpfVerifierState,
    old: &BpfVerifierState,
    metrics: &mut ExplorationMetrics,
) {
    let cur_frame = cur.curframe;
    
    // Get current and old function states
    let (cur_func, old_func) = match (
        cur.frame.get_mut(cur_frame).and_then(|f| f.as_mut()),
        old.frame.get(cur_frame).and_then(|f| f.as_ref()),
    ) {
        (Some(c), Some(o)) => (c, o),
        _ => return,
    };

    // Find registers that changed between iterations
    for (i, (cur_reg, old_reg)) in cur_func.regs.iter_mut()
        .zip(old_func.regs.iter()).enumerate() 
    {
        if cur_reg.reg_type != BpfRegType::ScalarValue 
            || old_reg.reg_type != BpfRegType::ScalarValue {
            continue;
        }

        // Check if bounds changed
        let bounds_changed = cur_reg.umin_value != old_reg.umin_value
            || cur_reg.umax_value != old_reg.umax_value
            || cur_reg.smin_value != old_reg.smin_value
            || cur_reg.smax_value != old_reg.smax_value;

        if bounds_changed {
            widen_scalar_bounds(cur_reg);
            metrics.record_widening();
            let _ = i; // Suppress warning
        }
    }
}

// ============================================================================
// Kernel-style Loop Widening for Iterator Convergence
// ============================================================================
//
// This implements the kernel's `maybe_widen_reg()` and `widen_imprecise_scalars()`
// functions which are critical for detecting loop convergence with open-coded
// iterators.
//
// The key insight is: when exploring an iterator loop, we need to detect when
// the loop state has converged. However, if a scalar value changes on each
// iteration (like a loop counter `i++`), naive state comparison would never
// converge.
//
// The solution is "speculative widening": before comparing states at a loop
// backedge (iter_next call), we widen imprecise scalars to unknown. This
// allows convergence detection while maintaining soundness:
//
// - If a value is "precise" (explicitly tracked), we don't widen it
// - If a value matches exactly, we don't need to widen
// - Otherwise, we widen to unknown, accepting some imprecision
//
// This is a conservative heuristic that works for most programs but may
// reject some safe programs that use imprecise values precisely on later
// iterations.

/// Check if two registers are "exact" matches for loop detection
/// 
/// Two registers are exact if they have the same type, bounds, and var_off.
/// This is used to determine if widening is necessary.
pub fn regs_exact(
    rold: &BpfRegState,
    rcur: &BpfRegState,
    idmap: &mut crate::analysis::states_equal::IdMap,
) -> bool {
    // Types must match exactly
    if rold.reg_type != rcur.reg_type {
        return false;
    }

    // Type flags must match
    if rold.type_flags != rcur.type_flags {
        return false;
    }

    // For scalars, check all bounds
    if rold.reg_type == BpfRegType::ScalarValue {
        if rold.umin_value != rcur.umin_value
            || rold.umax_value != rcur.umax_value
            || rold.smin_value != rcur.smin_value
            || rold.smax_value != rcur.smax_value
            || rold.u32_min_value != rcur.u32_min_value
            || rold.u32_max_value != rcur.u32_max_value
            || rold.s32_min_value != rcur.s32_min_value
            || rold.s32_max_value != rcur.s32_max_value
            || rold.var_off != rcur.var_off
        {
            return false;
        }
    }

    // For pointers, check offset and ID
    if rold.is_pointer() {
        if rold.off != rcur.off {
            return false;
        }
        // Check ID mapping for nullable pointers
        if rold.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            if !idmap.check_ids(rcur.id, rold.id) {
                return false;
            }
        }
    }

    true
}

/// Maybe widen a single register for loop convergence
/// 
/// This implements the kernel's `maybe_widen_reg()` function.
/// 
/// The register is widened (marked unknown) if:
/// - It's a scalar value
/// - Types match between old and current
/// - Neither is marked as precise
/// - They don't match exactly
/// 
/// This is the key operation that allows iterator loops to converge.
pub fn maybe_widen_reg(
    rold: &BpfRegState,
    rcur: &mut BpfRegState,
    idmap: &mut crate::analysis::states_equal::IdMap,
) -> bool {
    // Only widen scalars
    if rold.reg_type != BpfRegType::ScalarValue {
        return false;
    }
    
    // Types must match
    if rold.reg_type != rcur.reg_type {
        return false;
    }
    
    // Don't widen if either is precise - precision means we need exact tracking
    if rold.precise || rcur.precise {
        return false;
    }
    
    // Don't widen if they already match exactly
    if regs_exact(rold, rcur, idmap) {
        return false;
    }
    
    // Widen the current register to unknown
    rcur.mark_unknown(false);
    true
}

/// Widen imprecise scalars across all frames for loop convergence (prune version)
/// 
/// This implements the kernel's `widen_imprecise_scalars()` function for pruning.
/// 
/// Called before state comparison at iterator next calls. Widens any imprecise
/// scalar that doesn't match exactly between the old (cached) state and current
/// state. This allows loops with changing counters to converge.
/// 
/// Returns the number of registers widened.
pub fn widen_imprecise_scalars_for_prune(
    old: &BpfVerifierState,
    cur: &mut BpfVerifierState,
) -> u32 {
    let mut widened_count = 0u32;
    let mut idmap = crate::analysis::states_equal::IdMap::new();
    
    // Process frames from current (innermost) to outermost
    let max_frame = old.curframe.min(cur.curframe);
    
    for fr in (0..=max_frame).rev() {
        let old_func = match old.frame.get(fr).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let cur_func = match cur.frame.get_mut(fr).and_then(|f| f.as_mut()) {
            Some(f) => f,
            None => continue,
        };
        
        // Widen registers
        for i in 0..MAX_BPF_REG {
            if maybe_widen_reg(&old_func.regs[i], &mut cur_func.regs[i], &mut idmap) {
                widened_count += 1;
            }
        }
        
        // Widen spilled scalars on stack
        let old_slots = old_func.stack.stack.len();
        let cur_slots = cur_func.stack.stack.len();
        let min_slots = old_slots.min(cur_slots);
        
        for spi in 0..min_slots {
            // Check if both slots contain spilled scalars
            let old_is_spill = old_func.stack.stack[spi].slot_type[BPF_REG_SIZE - 1] 
                == BpfStackSlotType::Spill;
            let cur_is_spill = cur_func.stack.stack[spi].slot_type[BPF_REG_SIZE - 1] 
                == BpfStackSlotType::Spill;
            
            if !old_is_spill || !cur_is_spill {
                continue;
            }
            
            if maybe_widen_reg(
                &old_func.stack.stack[spi].spilled_ptr,
                &mut cur_func.stack.stack[spi].spilled_ptr,
                &mut idmap,
            ) {
                widened_count += 1;
            }
        }
    }
    
    widened_count
}

/// Process iterator next call - apply widening and check for convergence
/// 
/// This is called when verifier reaches an iterator next call (e.g., bpf_iter_num_next).
/// It implements the key loop convergence logic:
/// 
/// 1. Find a cached state at this instruction with pending branches (active loop)
/// 2. Widen imprecise scalars in current state
/// 3. Check if widened current state is within cached state's ranges (RANGE_WITHIN)
/// 4. If so, the loop has converged - we can stop exploring this path
/// 
/// Returns:
/// - `Some(state_id)` if loop converged (can prune)
/// - `None` if should continue exploration
pub fn process_iter_next_call(
    cache: &mut StateCache,
    insn_idx: usize,
    cur: &mut BpfVerifierState,
) -> Option<StateId> {
    // Get cached states at this instruction
    let head = cache.get_mut(insn_idx)?;
    
    for cached in &mut head.states {
        // Skip states not at this instruction
        if cached.insn_idx != insn_idx {
            continue;
        }
        
        // Skip states without pending branches (not an active loop)
        if cached.branches == 0 {
            continue;
        }
        
        // Skip states in free list
        if cached.in_free_list {
            continue;
        }
        
        // Check if iterator is in active state in the cached state
        let iter_active = check_iter_active(&cached.state);
        if !iter_active {
            continue;
        }
        
        // Apply widening to current state
        let widened = widen_imprecise_scalars_for_prune(&cached.state, cur);
        
        // Check for convergence using RANGE_WITHIN comparison
        let config = crate::analysis::states_equal::CompareConfig::for_range_within();
        if crate::analysis::states_equal::states_equal_with_config(cur, &cached.state, &config) {
            // Loop has converged!
            cached.hit_cnt += 1;
            cached.verified = true;
            
            // Log widening info if verbose
            if widened > 0 {
                // In a real implementation, we'd log this
            }
            
            return Some(cached.id);
        }
    }
    
    None
}

/// Check if any iterator in the state is in ACTIVE state
fn check_iter_active(state: &BpfVerifierState) -> bool {
    for frame_idx in 0..=state.curframe {
        let func = match state.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        
        for slot in &func.stack.stack {
            if slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Iter {
                if slot.spilled_ptr.iter.state == BpfIterState::Active {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Process may_goto instruction for bounded loop convergence
/// 
/// Similar to iterator handling, but for may_goto bounded loops.
/// May_goto uses a depth counter to track loop iterations.
pub fn process_may_goto(
    cache: &mut StateCache,
    insn_idx: usize,
    cur: &BpfVerifierState,
) -> Option<StateId> {
    let head = cache.get_mut(insn_idx)?;
    
    for cached in &mut head.states {
        if cached.insn_idx != insn_idx {
            continue;
        }
        
        if cached.branches == 0 || cached.in_free_list {
            continue;
        }
        
        // Different may_goto depths indicate different loop iterations
        if cached.state.may_goto_depth == cur.may_goto_depth {
            continue;
        }
        
        // Check for convergence using RANGE_WITHIN
        let config = crate::analysis::states_equal::CompareConfig::for_range_within();
        if crate::analysis::states_equal::states_equal_with_config(cur, &cached.state, &config) {
            cached.hit_cnt += 1;
            return Some(cached.id);
        }
    }
    
    None
}

/// Detect potential infinite loop
/// 
/// This is called when we suspect a loop might be infinite. Returns true if
/// the states are equivalent enough to indicate an infinite loop.
/// 
/// Key checks:
/// - States match exactly (not just subsumption)
/// - Iterator depths don't differ (no progress being made)
/// - May_goto and callback depths match
pub fn detect_infinite_loop(
    old: &BpfVerifierState,
    cur: &BpfVerifierState,
) -> bool {
    // First, quick check if states could be looping
    if !states_maybe_looping(old, cur) {
        return false;
    }
    
    // Check for exact state match
    let config = crate::analysis::states_equal::CompareConfig::for_loop_detection();
    if !crate::analysis::states_equal::states_equal_with_config(cur, old, &config) {
        return false;
    }
    
    // Check iterator depths - if different, we're making progress
    if iter_active_depths_differ(old, cur) {
        return false;
    }
    
    // Check may_goto depth
    if old.may_goto_depth != cur.may_goto_depth {
        return false;
    }
    
    // Check callback unroll depth
    if old.callback_unroll_depth != cur.callback_unroll_depth {
        return false;
    }
    
    // All checks passed - this is likely an infinite loop
    true
}

// ============================================================================
// SCC (Strongly Connected Component) Backedge Propagation
// ============================================================================
//
// This implements the kernel's SCC-based precision propagation for loops.
// When a loop is detected (via backedge), we need to track the states at
// the backedge and propagate precision requirements until a fixpoint is reached.
//
// Key concepts:
// - SCC: A strongly connected component in the CFG (a loop or set of loops)
// - Callchain: The call stack leading to an SCC (different call paths = different visits)
// - Backedge: A state that loops back to a previously seen state
// - Visit: Tracks entry state and accumulated backedges for an SCC callchain

/// Maximum frames in a call chain (matches kernel's MAX_CALL_FRAMES)
pub const MAX_CALL_FRAMES: usize = 8;

/// Maximum iterations for backedge propagation before falling back to mark_all_precise
pub const MAX_BACKEDGE_ITERS: usize = 64;

/// Call chain identifier for SCC tracking
/// 
/// A callchain identifies a unique path through the call graph to an SCC.
/// Different call paths to the same SCC are tracked separately because
/// parent state relationships differ.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SccCallchain {
    /// Call sites leading to the SCC (instruction indices)
    pub callsites: [usize; MAX_CALL_FRAMES],
    /// The SCC identifier (0 = not in an SCC)
    pub scc: u32,
}

impl SccCallchain {
    /// Create a new empty callchain
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this callchain represents being in an SCC
    pub fn in_scc(&self) -> bool {
        self.scc != 0
    }
}

/// A backedge state for SCC precision propagation
/// 
/// When we detect a loop (state matches a cached state with pending branches),
/// we save the current state as a backedge. Later, we propagate precision
/// requirements from the matched cached state back through the backedge states.
#[derive(Debug, Clone)]
pub struct SccBackedge {
    /// The state at the backedge point
    pub state: BpfVerifierState,
    /// The ID of the cached state this backedge matched (equal_state in kernel)
    pub equal_state_id: StateId,
}

impl SccBackedge {
    /// Create a new backedge
    pub fn new(state: BpfVerifierState, equal_state_id: StateId) -> Self {
        Self { state, equal_state_id }
    }
}

/// SCC visit tracking for a specific callchain
/// 
/// Each unique callchain through an SCC gets its own visit instance.
/// This tracks the entry state and accumulated backedges for precision
/// propagation when the SCC exploration completes.
#[derive(Debug, Clone)]
pub struct SccVisit {
    /// The callchain this visit corresponds to
    pub callchain: SccCallchain,
    /// The state that entered this SCC (first checkpoint in the SCC)
    pub entry_state_id: Option<StateId>,
    /// Accumulated backedge states
    pub backedges: Vec<SccBackedge>,
}

impl SccVisit {
    /// Create a new SCC visit
    pub fn new(callchain: SccCallchain) -> Self {
        Self {
            callchain,
            entry_state_id: None,
            backedges: Vec::new(),
        }
    }

    /// Add a backedge to this visit
    pub fn add_backedge(&mut self, backedge: SccBackedge) {
        self.backedges.push(backedge);
    }

    /// Check if this visit has any backedges
    pub fn has_backedges(&self) -> bool {
        !self.backedges.is_empty()
    }

    /// Clear backedges after propagation
    pub fn clear_backedges(&mut self) {
        self.backedges.clear();
    }
}

/// Runtime SCC visit info for a single SCC
/// 
/// Contains all visit instances for different callchains to this SCC.
/// This is different from `analysis::scc::SccInfo` which is for CFG analysis.
#[derive(Debug, Clone, Default)]
pub struct SccVisitInfo {
    /// Visit instances for this SCC (one per unique callchain)
    pub visits: Vec<SccVisit>,
}

impl SccVisitInfo {
    /// Create new SCC visit info
    pub fn new() -> Self {
        Self::default()
    }

    /// Find a visit for the given callchain
    pub fn find_visit(&self, callchain: &SccCallchain) -> Option<&SccVisit> {
        self.visits.iter().find(|v| &v.callchain == callchain)
    }

    /// Find a mutable visit for the given callchain
    pub fn find_visit_mut(&mut self, callchain: &SccCallchain) -> Option<&mut SccVisit> {
        self.visits.iter_mut().find(|v| &v.callchain == callchain)
    }

    /// Get or create a visit for the given callchain
    /// 
    /// Returns None only in the unlikely case of internal inconsistency
    pub fn get_or_create_visit(&mut self, callchain: SccCallchain) -> Option<&mut SccVisit> {
        if self.find_visit(&callchain).is_none() {
            self.visits.push(SccVisit::new(callchain.clone()));
        }
        self.find_visit_mut(&callchain)
    }
}

/// SCC tracking for the entire verification session
#[derive(Debug, Clone, Default)]
pub struct SccTracker {
    /// SCC visit info indexed by SCC id
    pub scc_info: HashMap<u32, SccVisitInfo>,
    /// Temporary callchain buffer (avoid allocations)
    callchain_buf: SccCallchain,
    /// Statistics: total backedges recorded
    pub total_backedges: u64,
    /// Statistics: total propagation rounds
    pub total_propagation_rounds: u64,
    /// Statistics: times fell back to mark_all_precise
    pub fallback_count: u64,
}

impl SccTracker {
    /// Create a new SCC tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the callchain for a verifier state
    /// 
    /// Looks for the topmost frame with an instruction in an SCC and forms
    /// the callchain as the call sites leading to that frame.
    /// 
    /// Returns true if state is in an SCC, false otherwise.
    pub fn compute_callchain(
        &mut self,
        state: &BpfVerifierState,
        insn_aux: &[crate::verifier::env::InsnAuxData],
    ) -> bool {
        self.callchain_buf = SccCallchain::default();
        
        for frame in 0..=state.curframe {
            let insn_idx = if frame == state.curframe {
                state.insn_idx
            } else {
                // Get callsite from next frame
                match state.frame.get(frame + 1).and_then(|f| f.as_ref()) {
                    Some(f) => f.callsite as usize,
                    None => continue,
                }
            };
            
            if insn_idx >= insn_aux.len() {
                continue;
            }
            
            let scc = insn_aux[insn_idx].scc;
            if scc != 0 {
                self.callchain_buf.scc = scc;
                return true;
            } else if frame < state.curframe && frame < MAX_CALL_FRAMES {
                self.callchain_buf.callsites[frame] = insn_idx;
            }
        }
        
        false
    }

    /// Get the current callchain (after compute_callchain)
    pub fn current_callchain(&self) -> &SccCallchain {
        &self.callchain_buf
    }

    /// Enter an SCC - ensure visit exists and set entry state if empty
    /// 
    /// Called from is_state_visited when we add a new state to the cache.
    pub fn maybe_enter_scc(
        &mut self,
        state: &BpfVerifierState,
        state_id: StateId,
        insn_aux: &[crate::verifier::env::InsnAuxData],
    ) -> bool {
        if !self.compute_callchain(state, insn_aux) {
            return false;
        }
        
        let callchain = self.callchain_buf.clone();
        let info = self.scc_info.entry(callchain.scc).or_default();
        if let Some(visit) = info.get_or_create_visit(callchain) {
            if visit.entry_state_id.is_none() {
                visit.entry_state_id = Some(state_id);
            }
            true
        } else {
            false
        }
    }

    /// Exit an SCC - propagate backedges and reset visit
    /// 
    /// Called from update_branch_counts when a state's branches reach 0.
    /// Returns Ok(()) on success, Err on propagation failure.
    pub fn maybe_exit_scc(
        &mut self,
        state: &BpfVerifierState,
        state_id: StateId,
        insn_aux: &[crate::verifier::env::InsnAuxData],
        cache: &mut StateCache,
    ) -> Result<()> {
        if !self.compute_callchain(state, insn_aux) {
            return Ok(());
        }
        
        let callchain = self.callchain_buf.clone();
        let scc_id = callchain.scc;
        
        // Check if we should process this exit
        let should_process = {
            let info = match self.scc_info.get(&scc_id) {
                Some(i) => i,
                None => return Ok(()),
            };
            
            let visit = match info.find_visit(&callchain) {
                Some(v) => v,
                None => return Ok(()),
            };
            
            visit.entry_state_id == Some(state_id)
        };
        
        if !should_process {
            return Ok(());
        }
        
        // Extract backedges for processing
        let backedges = {
            let info = match self.scc_info.get_mut(&scc_id) {
                Some(i) => i,
                None => return Ok(()),
            };
            
            let visit = match info.find_visit_mut(&callchain) {
                Some(v) => v,
                None => return Ok(()),
            };
            
            core::mem::take(&mut visit.backedges)
        };
        
        // Propagate backedges (no longer borrowing self.scc_info)
        let (propagation_rounds, fallback) = Self::propagate_backedges_standalone(backedges, cache)?;
        self.total_propagation_rounds += propagation_rounds;
        if fallback {
            self.fallback_count += 1;
        }
        
        // Reset the visit entry state
        if let Some(info) = self.scc_info.get_mut(&scc_id) {
            if let Some(visit) = info.find_visit_mut(&callchain) {
                visit.entry_state_id = None;
            }
        }
        
        Ok(())
    }

    /// Add a backedge state
    /// 
    /// Called when is_state_visited finds a loop (RANGE_WITHIN match).
    pub fn add_backedge(
        &mut self,
        state: &BpfVerifierState,
        equal_state_id: StateId,
        insn_aux: &[crate::verifier::env::InsnAuxData],
    ) -> Result<()> {
        if !self.compute_callchain(state, insn_aux) {
            return Err(VerifierError::Internal(
                "add_backedge: no SCC in verification path".into()
            ));
        }
        
        let callchain = self.callchain_buf.clone();
        let info = match self.scc_info.get_mut(&callchain.scc) {
            Some(i) => i,
            None => {
                return Err(VerifierError::Internal(
                    "add_backedge: no visit info for callchain".into()
                ));
            }
        };
        
        let visit = match info.find_visit_mut(&callchain) {
            Some(v) => v,
            None => {
                return Err(VerifierError::Internal(
                    "add_backedge: no visit for callchain".into()
                ));
            }
        };
        
        let backedge = SccBackedge::new(state.clone(), equal_state_id);
        visit.add_backedge(backedge);
        self.total_backedges += 1;
        
        Ok(())
    }

    /// Check if a state has incomplete read marks (is in SCC with pending backedges)
    pub fn incomplete_read_marks(
        &mut self,
        state: &BpfVerifierState,
        insn_aux: &[crate::verifier::env::InsnAuxData],
    ) -> bool {
        if !self.compute_callchain(state, insn_aux) {
            return false;
        }
        
        let callchain = &self.callchain_buf;
        let info = match self.scc_info.get(&callchain.scc) {
            Some(i) => i,
            None => return false,
        };
        
        match info.find_visit(callchain) {
            Some(v) => v.has_backedges(),
            None => false,
        }
    }

    /// Propagate precision from backedge states (standalone version)
    /// 
    /// Iteratively propagates precision marks from the equal_state (cached state
    /// that the backedge matched) to the backedge state and its parents,
    /// until a fixpoint is reached.
    /// 
    /// Returns (propagation_rounds, did_fallback) on success.
    fn propagate_backedges_standalone(
        mut backedges: Vec<SccBackedge>,
        cache: &mut StateCache,
    ) -> Result<(u64, bool)> {
        let mut iteration = 0;
        let mut total_rounds = 0u64;
        let mut did_fallback = false;
        
        loop {
            if iteration >= MAX_BACKEDGE_ITERS {
                // Too many iterations - fall back to marking all scalars precise
                for backedge in &mut backedges {
                    mark_all_scalars_precise(&mut backedge.state);
                }
                did_fallback = true;
                break;
            }
            
            let mut changed = false;
            
            for backedge in &mut backedges {
                // Get the equal state from cache
                let equal_state = match cache.get_by_id(backedge.equal_state_id) {
                    Some(cached) => &cached.state,
                    None => continue,
                };
                
                // Propagate precision from equal_state to backedge.state
                if propagate_precision_internal(equal_state, &mut backedge.state)? {
                    changed = true;
                }
            }
            
            total_rounds += 1;
            iteration += 1;
            
            if !changed {
                break;
            }
        }
        
        Ok((total_rounds, did_fallback))
    }

    /// Clear all SCC tracking data
    pub fn clear(&mut self) {
        self.scc_info.clear();
        self.callchain_buf = SccCallchain::default();
    }
}

/// Internal precision propagation from one state to another
/// 
/// Propagates precision marks from `from` state to `to` state.
/// Returns true if any changes were made.
fn propagate_precision_internal(
    from: &BpfVerifierState,
    to: &mut BpfVerifierState,
) -> Result<bool> {
    let mut changed = false;
    
    for frame_idx in 0..=from.curframe.min(to.curframe) {
        let from_func = match from.frame.get(frame_idx).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => continue,
        };
        let to_func = match to.frame.get_mut(frame_idx).and_then(|f| f.as_mut()) {
            Some(f) => f,
            None => continue,
        };
        
        // Propagate register precision
        for (from_reg, to_reg) in from_func.regs.iter().zip(to_func.regs.iter_mut()) {
            if from_reg.reg_type == BpfRegType::ScalarValue
                && from_reg.precise
                && to_reg.reg_type == BpfRegType::ScalarValue
                && !to_reg.precise
            {
                to_reg.precise = true;
                changed = true;
            }
        }
        
        // Propagate stack slot precision
        let from_slots = from_func.stack.stack.len();
        let to_slots = to_func.stack.stack.len();
        
        for spi in 0..from_slots.min(to_slots) {
            let from_slot = &from_func.stack.stack[spi];
            let to_slot = &mut to_func.stack.stack[spi];
            
            if from_slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
                && to_slot.slot_type[BPF_REG_SIZE - 1] == BpfStackSlotType::Spill
                && from_slot.spilled_ptr.reg_type == BpfRegType::ScalarValue
                && from_slot.spilled_ptr.precise
                && to_slot.spilled_ptr.reg_type == BpfRegType::ScalarValue
                && !to_slot.spilled_ptr.precise
            {
                to_slot.spilled_ptr.precise = true;
                changed = true;
            }
        }
    }
    
    Ok(changed)
}
// ============================================================================
// Memory Pressure Management
// ============================================================================

/// Pressure levels for memory management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// Normal operation - no memory pressure
    Normal,
    /// Elevated pressure - start being more aggressive with eviction
    Elevated,
    /// High pressure - aggressively evict states
    High,
    /// Critical pressure - emergency eviction mode
    Critical,
}

/// Memory pressure manager for state cache
/// 
/// Monitors the number of cached states and triggers eviction
/// when memory pressure increases. This prevents the verifier
/// from consuming too much memory on complex programs.
#[derive(Debug, Clone)]
pub struct MemoryPressureManager {
    /// Maximum number of states before critical pressure
    max_states: usize,
    /// Current number of states
    current_states: usize,
    /// Threshold for elevated pressure (percentage of max)
    elevated_threshold: f64,
    /// Threshold for high pressure (percentage of max)
    high_threshold: f64,
    /// Threshold for critical pressure (percentage of max)
    critical_threshold: f64,
    /// Number of evictions performed
    pub evictions_performed: u64,
    /// Number of times pressure level changed
    pub pressure_changes: u64,
}

impl MemoryPressureManager {
    /// Create a new memory pressure manager
    pub fn new(max_states: usize) -> Self {
        Self {
            max_states,
            current_states: 0,
            elevated_threshold: 0.7,
            high_threshold: 0.85,
            critical_threshold: 0.95,
            evictions_performed: 0,
            pressure_changes: 0,
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(
        max_states: usize,
        elevated: f64,
        high: f64,
        critical: f64,
    ) -> Self {
        Self {
            max_states,
            current_states: 0,
            elevated_threshold: elevated,
            high_threshold: high,
            critical_threshold: critical,
            evictions_performed: 0,
            pressure_changes: 0,
        }
    }

    /// Update the current state count
    pub fn update_state_count(&mut self, count: usize) {
        let old_level = self.pressure_level();
        self.current_states = count;
        let new_level = self.pressure_level();
        
        if old_level != new_level {
            self.pressure_changes += 1;
        }
    }

    /// Get the current pressure level
    pub fn pressure_level(&self) -> PressureLevel {
        if self.max_states == 0 {
            return PressureLevel::Normal;
        }
        
        let ratio = self.current_states as f64 / self.max_states as f64;
        
        if ratio >= self.critical_threshold {
            PressureLevel::Critical
        } else if ratio >= self.high_threshold {
            PressureLevel::High
        } else if ratio >= self.elevated_threshold {
            PressureLevel::Elevated
        } else {
            PressureLevel::Normal
        }
    }

    /// Get the number of states to evict based on pressure level
    pub fn eviction_target(&self) -> usize {
        match self.pressure_level() {
            PressureLevel::Normal => 0,
            PressureLevel::Elevated => self.current_states / 20, // 5%
            PressureLevel::High => self.current_states / 10,     // 10%
            PressureLevel::Critical => self.current_states / 5,   // 20%
        }
    }

    /// Record that evictions were performed
    pub fn record_evictions(&mut self, count: usize) {
        self.evictions_performed += count as u64;
    }

    /// Check if eviction is needed
    pub fn needs_eviction(&self) -> bool {
        self.pressure_level() != PressureLevel::Normal
    }

    /// Get remaining capacity before critical
    pub fn remaining_capacity(&self) -> usize {
        let critical_count = (self.max_states as f64 * self.critical_threshold) as usize;
        critical_count.saturating_sub(self.current_states)
    }
}

impl Default for MemoryPressureManager {
    fn default() -> Self {
        // Default to 10000 max states (reasonable for most programs)
        Self::new(10000)
    }
}

// ============================================================================
// Eviction Policies
// ============================================================================

/// Eviction policy for state cache
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used - evict states that haven't been hit recently
    LRU,
    /// Least Frequently Used - evict states with lowest hit count
    LFU,
    /// Miss/Hit Ratio - evict states with high miss ratio
    MissRatio,
    /// Age-based - evict oldest states first
    Age,
    /// Combined heuristic - uses multiple factors
    Combined,
}

impl EvictionPolicy {
    /// Select states for eviction from a specific instruction
    pub fn select_for_eviction(
        &self,
        cache: &StateCache,
        insn_idx: usize,
        count: usize,
    ) -> Vec<StateId> {
        let head = match cache.get(insn_idx) {
            Some(h) => h,
            None => return Vec::new(),
        };

        let mut candidates: Vec<(StateId, u64)> = head.states.iter()
            .filter(|c| !c.in_free_list && c.verified)
            .map(|c| (c.id, self.compute_score(c)))
            .collect();

        // Sort by score (lower is better candidate for eviction)
        candidates.sort_by_key(|(_, score)| *score);

        candidates.into_iter()
            .take(count)
            .map(|(id, _)| id)
            .collect()
    }

    /// Compute eviction score for a cached state (lower = more evictable)
    fn compute_score(&self, cached: &CachedState) -> u64 {
        match self {
            EvictionPolicy::LRU => {
                // Lower hit count = more evictable
                cached.hit_cnt as u64
            }
            EvictionPolicy::LFU => {
                // Same as LRU for now
                cached.hit_cnt as u64
            }
            EvictionPolicy::MissRatio => {
                // Higher miss ratio = more evictable
                // Invert so lower score = more evictable
                if cached.miss_cnt == 0 {
                    u64::MAX
                } else {
                    (cached.hit_cnt as u64 * 1000) / (cached.miss_cnt as u64 + 1)
                }
            }
            EvictionPolicy::Age => {
                // Older states (lower ID) = more evictable
                // State IDs are monotonically increasing
                cached.id
            }
            EvictionPolicy::Combined => {
                // Combine multiple factors
                let hit_score = cached.hit_cnt as u64 * 10;
                let miss_penalty = if cached.miss_cnt > cached.hit_cnt * 3 {
                    0
                } else {
                    50
                };
                let age_factor = (u64::MAX - cached.id) / 1000000;
                
                hit_score + miss_penalty + age_factor
            }
        }
    }

    /// Select states for global eviction across all instructions
    pub fn select_global_eviction(
        &self,
        cache: &StateCache,
        count: usize,
    ) -> Vec<StateId> {
        let mut all_candidates: Vec<(StateId, u64)> = Vec::new();

        for head in cache.cache.values() {
            for cached in &head.states {
                if !cached.in_free_list && cached.verified {
                    all_candidates.push((cached.id, self.compute_score(cached)));
                }
            }
        }

        all_candidates.sort_by_key(|(_, score)| *score);

        all_candidates.into_iter()
            .take(count)
            .map(|(id, _)| id)
            .collect()
    }
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        EvictionPolicy::Combined
    }
}

// ============================================================================
// Adaptive Pruning
// ============================================================================

/// Pruning mode based on verification complexity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruningMode {
    /// Normal pruning - standard comparison
    Normal,
    /// Relaxed pruning - allow more subsumption
    Relaxed,
    /// Aggressive pruning - evict more states
    Aggressive,
    /// Emergency pruning - maximum eviction
    Emergency,
}

/// Adaptive pruning configuration
/// 
/// Adjusts pruning behavior based on program complexity and memory pressure.
/// This helps balance verification precision with resource usage.
#[derive(Debug, Clone)]
pub struct AdaptivePruning {
    /// Current pruning mode
    pub current_mode: PruningMode,
    /// States added since last adjustment
    states_added: u64,
    /// States pruned since last adjustment
    states_pruned: u64,
    /// Adjustment interval (number of states before reconsidering mode)
    adjustment_interval: u64,
    /// Prune ratio target (pruned/added)
    target_prune_ratio: f64,
    /// Mode changes performed
    pub mode_changes: u64,
}

impl AdaptivePruning {
    /// Create new adaptive pruning with defaults
    pub fn new() -> Self {
        Self {
            current_mode: PruningMode::Normal,
            states_added: 0,
            states_pruned: 0,
            adjustment_interval: 100,
            target_prune_ratio: 0.3,
            mode_changes: 0,
        }
    }

    /// Create with custom parameters
    pub fn with_params(interval: u64, target_ratio: f64) -> Self {
        Self {
            current_mode: PruningMode::Normal,
            states_added: 0,
            states_pruned: 0,
            adjustment_interval: interval,
            target_prune_ratio: target_ratio,
            mode_changes: 0,
        }
    }

    /// Record a state being added
    pub fn record_state_added(&mut self) {
        self.states_added += 1;
    }

    /// Record a state being pruned
    pub fn record_state_pruned(&mut self) {
        self.states_pruned += 1;
    }

    /// Check if adjustment is needed
    pub fn should_adjust(&self) -> bool {
        self.states_added >= self.adjustment_interval
    }

    /// Adjust pruning mode based on pressure level
    pub fn adjust_mode(&mut self, pressure: PressureLevel) {
        let old_mode = self.current_mode;
        
        self.current_mode = match pressure {
            PressureLevel::Normal => {
                // Check prune ratio
                let ratio = if self.states_added > 0 {
                    self.states_pruned as f64 / self.states_added as f64
                } else {
                    0.0
                };
                
                if ratio < self.target_prune_ratio * 0.5 {
                    // Low pruning - might need more aggressive mode
                    PruningMode::Relaxed
                } else {
                    PruningMode::Normal
                }
            }
            PressureLevel::Elevated => PruningMode::Relaxed,
            PressureLevel::High => PruningMode::Aggressive,
            PressureLevel::Critical => PruningMode::Emergency,
        };

        if old_mode != self.current_mode {
            self.mode_changes += 1;
        }

        // Reset counters after adjustment
        self.states_added = 0;
        self.states_pruned = 0;
    }

    /// Get comparison config for current mode
    pub fn get_compare_config(&self) -> CompareConfig {
        match self.current_mode {
            PruningMode::Normal => CompareConfig::for_pruning(),
            PruningMode::Relaxed => CompareConfig {
                mode: CompareMode::NotExact,
                check_precision: false,
                check_refs: true,
                check_locks: true,
            },
            PruningMode::Aggressive => CompareConfig {
                mode: CompareMode::NotExact,
                check_precision: false,
                check_refs: false,
                check_locks: true,
            },
            PruningMode::Emergency => CompareConfig {
                mode: CompareMode::NotExact,
                check_precision: false,
                check_refs: false,
                check_locks: false,
            },
        }
    }

    /// Check if we should skip adding state to cache
    pub fn should_skip_cache(&self) -> bool {
        matches!(self.current_mode, PruningMode::Emergency)
    }
}

impl Default for AdaptivePruning {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Integrated Pruning Controller
// ============================================================================

/// Integrated pruning controller combining all pruning strategies
/// 
/// This controller coordinates memory pressure management, eviction,
/// and adaptive pruning to maintain efficient verification.
#[derive(Debug)]
pub struct PruningController {
    /// Memory pressure manager
    pub pressure: MemoryPressureManager,
    /// Eviction policy
    pub eviction_policy: EvictionPolicy,
    /// Adaptive pruning
    pub adaptive: AdaptivePruning,
    /// Statistics
    pub stats: PruningStats,
}

/// Pruning statistics
#[derive(Debug, Clone, Default)]
pub struct PruningStats {
    /// Total states added
    pub states_added: u64,
    /// Total states pruned
    pub states_pruned: u64,
    /// Total states evicted
    pub states_evicted: u64,
    /// Times eviction was triggered
    pub eviction_rounds: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
}

impl PruningController {
    /// Create a new pruning controller
    pub fn new(max_states: usize) -> Self {
        Self {
            pressure: MemoryPressureManager::new(max_states),
            eviction_policy: EvictionPolicy::default(),
            adaptive: AdaptivePruning::default(),
            stats: PruningStats::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        max_states: usize,
        policy: EvictionPolicy,
        target_prune_ratio: f64,
    ) -> Self {
        Self {
            pressure: MemoryPressureManager::new(max_states),
            eviction_policy: policy,
            adaptive: AdaptivePruning::with_params(100, target_prune_ratio),
            stats: PruningStats::default(),
        }
    }

    /// Update controller with current cache state
    pub fn update(&mut self, cache: &StateCache) {
        self.pressure.update_state_count(cache.total_states);
        
        if self.adaptive.should_adjust() {
            self.adaptive.adjust_mode(self.pressure.pressure_level());
        }
    }

    /// Perform eviction if needed
    pub fn maybe_evict(&mut self, cache: &mut StateCache) {
        if !self.pressure.needs_eviction() {
            return;
        }

        let target = self.pressure.eviction_target();
        if target == 0 {
            return;
        }

        let to_evict = self.eviction_policy.select_global_eviction(cache, target);
        
        for id in &to_evict {
            cache.mark_for_removal(*id);
        }

        self.stats.states_evicted += to_evict.len() as u64;
        self.stats.eviction_rounds += 1;
        self.pressure.record_evictions(to_evict.len());
    }

    /// Record state added
    pub fn record_added(&mut self) {
        self.stats.states_added += 1;
        self.adaptive.record_state_added();
    }

    /// Record state pruned
    pub fn record_pruned(&mut self) {
        self.stats.states_pruned += 1;
        self.adaptive.record_state_pruned();
    }

    /// Record cache hit
    pub fn record_hit(&mut self) {
        self.stats.cache_hits += 1;
    }

    /// Record cache miss
    pub fn record_miss(&mut self) {
        self.stats.cache_misses += 1;
    }

    /// Get current pressure level
    pub fn pressure_level(&self) -> PressureLevel {
        self.pressure.pressure_level()
    }

    /// Get current pruning mode
    pub fn pruning_mode(&self) -> PruningMode {
        self.adaptive.current_mode
    }

    /// Get comparison config for current state
    pub fn get_compare_config(&self) -> CompareConfig {
        self.adaptive.get_compare_config()
    }

    /// Check if state caching should be skipped
    pub fn should_skip_cache(&self) -> bool {
        self.adaptive.should_skip_cache()
    }

    /// Get cache efficiency ratio
    pub fn cache_efficiency(&self) -> f64 {
        let total = self.stats.cache_hits + self.stats.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.stats.cache_hits as f64 / total as f64
        }
    }

    /// Get pruning efficiency ratio
    pub fn pruning_efficiency(&self) -> f64 {
        if self.stats.states_added == 0 {
            0.0
        } else {
            self.stats.states_pruned as f64 / self.stats.states_added as f64
        }
    }
}

impl Default for PruningController {
    fn default() -> Self {
        Self::new(10000)
    }
}
