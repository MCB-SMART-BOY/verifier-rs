//! Cache optimization for the BPF verifier.
//!
//! This module provides optimized caching structures and algorithms
//! for improving verification performance:
//! - Bloom filters for fast negative lookups
//! - State compression for memory efficiency
//! - Parallel-friendly data structures

#![allow(missing_docs)] // Performance optimization internals

use crate::state::verifier_state::BpfVerifierState;
use crate::state::reg_state::BpfRegState;
use crate::core::types::*;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

// ============================================================================
// Bloom Filter for Fast State Lookup
// ============================================================================

/// A simple bloom filter for fast negative lookups
/// 
/// Used to quickly determine if a state definitely doesn't exist in the cache,
/// avoiding expensive full comparisons. False positives are possible but
/// false negatives are not.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    /// Bit array for the filter
    bits: Vec<u64>,
    /// Number of bits in the filter
    num_bits: usize,
    /// Number of hash functions to use
    num_hashes: usize,
    /// Number of items inserted
    count: usize,
}

impl BloomFilter {
    /// Create a new bloom filter with the given capacity and error rate
    /// 
    /// # Arguments
    /// * `expected_items` - Expected number of items to insert
    /// * `false_positive_rate` - Desired false positive rate (0.0 to 1.0)
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        // Calculate optimal number of bits and hash functions
        // m = -n * ln(p) / (ln(2)^2)
        // k = (m/n) * ln(2)
        let ln2 = core::f64::consts::LN_2;
        let ln2_sq = ln2 * ln2;
        
        let n = expected_items.max(1) as f64;
        let p = false_positive_rate.max(0.0001).min(0.5);
        
        let m = (-n * p.ln() / ln2_sq).ceil() as usize;
        let k = ((m as f64 / n) * ln2).ceil() as usize;
        
        let num_bits = m.max(64);
        let num_words = (num_bits + 63) / 64;
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes: k.max(1).min(16),
            count: 0,
        }
    }

    /// Create a bloom filter with explicit size
    pub fn with_size(num_bits: usize, num_hashes: usize) -> Self {
        let num_words = (num_bits + 63) / 64;
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes: num_hashes.max(1).min(16),
            count: 0,
        }
    }

    /// Insert a hash value into the filter
    pub fn insert(&mut self, hash: u64) {
        for i in 0..self.num_hashes {
            let bit_idx = self.get_bit_index(hash, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            
            if word_idx < self.bits.len() {
                self.bits[word_idx] |= 1u64 << bit_pos;
            }
        }
        self.count += 1;
    }

    /// Check if a hash value might be in the filter
    /// 
    /// Returns:
    /// - `false` if the value is definitely not in the filter
    /// - `true` if the value might be in the filter (possible false positive)
    pub fn might_contain(&self, hash: u64) -> bool {
        for i in 0..self.num_hashes {
            let bit_idx = self.get_bit_index(hash, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            
            if word_idx >= self.bits.len() {
                return false;
            }
            
            if (self.bits[word_idx] & (1u64 << bit_pos)) == 0 {
                return false;
            }
        }
        true
    }

    /// Get bit index for a hash and hash function number
    fn get_bit_index(&self, hash: u64, hash_num: usize) -> usize {
        // Use double hashing: h(i) = h1 + i * h2
        let h1 = hash;
        let h2 = hash.rotate_left(17) ^ hash.rotate_right(31);
        let combined = h1.wrapping_add((hash_num as u64).wrapping_mul(h2));
        (combined as usize) % self.num_bits
    }

    /// Clear the filter
    pub fn clear(&mut self) {
        for word in &mut self.bits {
            *word = 0;
        }
        self.count = 0;
    }

    /// Get the number of items inserted
    pub fn count(&self) -> usize {
        self.count
    }

    /// Estimate the current false positive rate
    pub fn estimated_fpr(&self) -> f64 {
        let bits_set: usize = self.bits.iter()
            .map(|w| w.count_ones() as usize)
            .sum();
        
        let fill_ratio = bits_set as f64 / self.num_bits as f64;
        fill_ratio.powi(self.num_hashes as i32)
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        // Default: 10000 items, 1% false positive rate
        Self::new(10000, 0.01)
    }
}

// ============================================================================
// State Fingerprint for Fast Comparison
// ============================================================================

/// A compact fingerprint of a verifier state for fast comparison
/// 
/// The fingerprint captures the essential characteristics of a state
/// in a fixed-size structure, enabling fast equality checks before
/// performing full state comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateFingerprint {
    /// Hash of register types
    pub reg_types_hash: u32,
    /// Hash of register bounds
    pub bounds_hash: u32,
    /// Stack allocation size
    pub stack_size: u16,
    /// Current frame number
    pub frame: u8,
    /// Flags (has refs, has locks, etc.)
    pub flags: u8,
}

impl StateFingerprint {
    /// Create a fingerprint from a verifier state
    pub fn from_state(state: &BpfVerifierState) -> Self {
        let mut reg_types_hash = 0u32;
        let mut bounds_hash = 0u32;
        let mut stack_size = 0u16;
        let mut flags = 0u8;

        if let Some(func) = state.cur_func() {
            // Hash register types
            for (i, reg) in func.regs.iter().enumerate() {
                reg_types_hash = reg_types_hash.rotate_left(3) 
                    ^ ((reg.reg_type as u32) << (i % 8));
            }

            // Hash bounds (sample key registers)
            for reg in &func.regs[..5] {
                if reg.reg_type == BpfRegType::ScalarValue {
                    bounds_hash = bounds_hash.wrapping_add(
                        (reg.umin_value as u32) ^ (reg.umax_value as u32)
                    );
                }
            }

            stack_size = func.stack.allocated_stack as u16;
        }

        // Set flags
        if state.lock_state.has_locks() {
            flags |= 0x01;
        }
        if state.in_rcu_cs() {
            flags |= 0x02;
        }
        if state.speculative {
            flags |= 0x04;
        }

        Self {
            reg_types_hash,
            bounds_hash,
            stack_size,
            frame: state.curframe as u8,
            flags,
        }
    }

    /// Check if two fingerprints are compatible (could represent equal states)
    pub fn compatible(&self, other: &Self) -> bool {
        // Quick checks - if these differ, states definitely differ
        self.frame == other.frame
            && self.flags == other.flags
            && self.stack_size == other.stack_size
            && self.reg_types_hash == other.reg_types_hash
    }

    /// Compute a combined hash for bloom filter insertion
    pub fn combined_hash(&self) -> u64 {
        let mut hash = self.reg_types_hash as u64;
        hash = hash.rotate_left(16) ^ (self.bounds_hash as u64);
        hash = hash.rotate_left(8) ^ (self.stack_size as u64);
        hash = hash.rotate_left(4) ^ (self.frame as u64);
        hash = hash.rotate_left(4) ^ (self.flags as u64);
        hash
    }
}

// ============================================================================
// Compressed State Representation
// ============================================================================

/// Compression level for state storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression - store full state
    None,
    /// Light compression - delta encoding for similar states
    Light,
    /// Heavy compression - aggressive size reduction
    Heavy,
}

/// Compressed register state (reduced from full BpfRegState)
#[derive(Debug, Clone)]
pub struct CompressedRegState {
    /// Register type
    pub reg_type: BpfRegType,
    /// Type flags (compressed to u8 for common cases)
    pub type_flags: u8,
    /// Offset for pointers
    pub off: i16,
    /// Bounds stored as deltas from common values
    pub bounds: CompressedBounds,
}

/// Compressed bounds representation
#[derive(Debug, Clone, Copy)]
pub enum CompressedBounds {
    /// Unknown bounds
    Unknown,
    /// Known constant value
    Const(u64),
    /// Small range (fits in 32 bits)
    SmallRange { min: u32, max: u32 },
    /// Full range (needs full 64-bit bounds)
    FullRange { umin: u64, umax: u64, smin: i64, smax: i64 },
}

impl CompressedRegState {
    /// Compress a full register state
    pub fn compress(reg: &BpfRegState) -> Self {
        let type_flags = (reg.type_flags.bits() & 0xFF) as u8;
        let off = reg.off.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        
        let bounds = if reg.reg_type != BpfRegType::ScalarValue {
            CompressedBounds::Unknown
        } else if reg.umin_value == reg.umax_value {
            CompressedBounds::Const(reg.umin_value)
        } else if reg.umax_value <= u32::MAX as u64 {
            CompressedBounds::SmallRange {
                min: reg.umin_value as u32,
                max: reg.umax_value as u32,
            }
        } else {
            CompressedBounds::FullRange {
                umin: reg.umin_value,
                umax: reg.umax_value,
                smin: reg.smin_value,
                smax: reg.smax_value,
            }
        };

        Self {
            reg_type: reg.reg_type,
            type_flags,
            off,
            bounds,
        }
    }

    /// Decompress to a full register state
    pub fn decompress(&self) -> BpfRegState {
        let mut reg = BpfRegState::default();
        reg.reg_type = self.reg_type;
        reg.type_flags = BpfTypeFlag::from_bits_truncate(self.type_flags as u32);
        reg.off = self.off as i32;

        match self.bounds {
            CompressedBounds::Unknown => {
                reg.mark_unknown(false);
            }
            CompressedBounds::Const(val) => {
                reg.mark_known(val);
            }
            CompressedBounds::SmallRange { min, max } => {
                reg.umin_value = min as u64;
                reg.umax_value = max as u64;
                reg.smin_value = min as i64;
                reg.smax_value = max as i64;
            }
            CompressedBounds::FullRange { umin, umax, smin, smax } => {
                reg.umin_value = umin;
                reg.umax_value = umax;
                reg.smin_value = smin;
                reg.smax_value = smax;
            }
        }

        reg
    }

    /// Estimate memory size of this compressed state
    pub fn size_bytes(&self) -> usize {
        let bounds_size = match self.bounds {
            CompressedBounds::Unknown => 1,
            CompressedBounds::Const(_) => 9,
            CompressedBounds::SmallRange { .. } => 9,
            CompressedBounds::FullRange { .. } => 33,
        };
        4 + bounds_size // reg_type(1) + type_flags(1) + off(2) + bounds
    }
}

// ============================================================================
// State Cache Statistics
// ============================================================================

/// Detailed cache statistics for performance analysis
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total lookups performed
    pub lookups: u64,
    /// Bloom filter rejections (definite misses)
    pub bloom_rejections: u64,
    /// Fingerprint rejections (quick misses)
    pub fingerprint_rejections: u64,
    /// Full comparison attempts
    pub full_comparisons: u64,
    /// Successful matches (hits)
    pub hits: u64,
    /// Hash collisions (different states, same hash)
    pub hash_collisions: u64,
    /// Average comparison time (microseconds)
    pub avg_comparison_time_us: f64,
    /// Peak memory usage (bytes)
    pub peak_memory_bytes: usize,
    /// Current memory usage (bytes)
    pub current_memory_bytes: usize,
    /// Compression ratio (original/compressed)
    pub compression_ratio: f64,
}

impl CacheStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a lookup
    pub fn record_lookup(&mut self) {
        self.lookups += 1;
    }

    /// Record a bloom filter rejection
    pub fn record_bloom_rejection(&mut self) {
        self.bloom_rejections += 1;
    }

    /// Record a fingerprint rejection
    pub fn record_fingerprint_rejection(&mut self) {
        self.fingerprint_rejections += 1;
    }

    /// Record a full comparison
    pub fn record_full_comparison(&mut self) {
        self.full_comparisons += 1;
    }

    /// Record a cache hit
    pub fn record_hit(&mut self) {
        self.hits += 1;
    }

    /// Record a hash collision
    pub fn record_collision(&mut self) {
        self.hash_collisions += 1;
    }

    /// Update memory usage
    pub fn update_memory(&mut self, bytes: usize) {
        self.current_memory_bytes = bytes;
        if bytes > self.peak_memory_bytes {
            self.peak_memory_bytes = bytes;
        }
    }

    /// Get bloom filter efficiency (rejections / lookups)
    pub fn bloom_efficiency(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            self.bloom_rejections as f64 / self.lookups as f64
        }
    }

    /// Get hit rate (hits / lookups)
    pub fn hit_rate(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            self.hits as f64 / self.lookups as f64
        }
    }

    /// Get collision rate (collisions / full_comparisons)
    pub fn collision_rate(&self) -> f64 {
        if self.full_comparisons == 0 {
            0.0
        } else {
            self.hash_collisions as f64 / self.full_comparisons as f64
        }
    }

    /// Reset all statistics
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ============================================================================
// Optimized State Cache
// ============================================================================

/// Optimized state cache with bloom filter and fingerprinting
/// 
/// Combines multiple optimization techniques:
/// 1. Bloom filter for fast negative lookups
/// 2. Fingerprinting for quick compatibility checks
/// 3. Hash-based indexing for O(1) average lookup
#[derive(Debug)]
pub struct OptimizedStateCache {
    /// Bloom filter for fast miss detection
    bloom: BloomFilter,
    /// Cache statistics
    pub stats: CacheStats,
    /// Whether to use bloom filter
    use_bloom: bool,
    /// Whether to use fingerprinting
    use_fingerprint: bool,
}

impl OptimizedStateCache {
    /// Create a new optimized cache
    pub fn new(expected_states: usize) -> Self {
        Self {
            bloom: BloomFilter::new(expected_states, 0.01),
            stats: CacheStats::new(),
            use_bloom: true,
            use_fingerprint: true,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        expected_states: usize,
        use_bloom: bool,
        use_fingerprint: bool,
    ) -> Self {
        Self {
            bloom: BloomFilter::new(expected_states, 0.01),
            stats: CacheStats::new(),
            use_bloom,
            use_fingerprint,
        }
    }

    /// Check if a state might be in the cache (bloom filter check)
    pub fn might_contain(&self, state: &BpfVerifierState) -> bool {
        if !self.use_bloom {
            return true; // Assume yes if bloom filter disabled
        }

        let fingerprint = StateFingerprint::from_state(state);
        let hash = fingerprint.combined_hash();
        self.bloom.might_contain(hash)
    }

    /// Add a state to the bloom filter
    pub fn add_to_bloom(&mut self, state: &BpfVerifierState) {
        if self.use_bloom {
            let fingerprint = StateFingerprint::from_state(state);
            let hash = fingerprint.combined_hash();
            self.bloom.insert(hash);
        }
    }

    /// Check fingerprint compatibility
    pub fn fingerprints_compatible(
        &self,
        state1: &BpfVerifierState,
        state2: &BpfVerifierState,
    ) -> bool {
        if !self.use_fingerprint {
            return true;
        }

        let fp1 = StateFingerprint::from_state(state1);
        let fp2 = StateFingerprint::from_state(state2);
        fp1.compatible(&fp2)
    }

    /// Record a cache lookup attempt
    pub fn record_lookup(&mut self, bloom_passed: bool, fingerprint_passed: bool, hit: bool) {
        self.stats.record_lookup();
        
        if !bloom_passed {
            self.stats.record_bloom_rejection();
        } else if !fingerprint_passed {
            self.stats.record_fingerprint_rejection();
        } else {
            self.stats.record_full_comparison();
            if hit {
                self.stats.record_hit();
            }
        }
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.bloom.clear();
        self.stats.reset();
    }

    /// Get the estimated bloom filter false positive rate
    pub fn bloom_fpr(&self) -> f64 {
        self.bloom.estimated_fpr()
    }

    /// Enable/disable bloom filter
    pub fn set_use_bloom(&mut self, use_bloom: bool) {
        self.use_bloom = use_bloom;
    }

    /// Enable/disable fingerprinting
    pub fn set_use_fingerprint(&mut self, use_fingerprint: bool) {
        self.use_fingerprint = use_fingerprint;
    }
}

impl Default for OptimizedStateCache {
    fn default() -> Self {
        Self::new(10000)
    }
}

// ============================================================================
// Cache-Friendly State Pool
// ============================================================================

/// A pool for reusing state allocations
/// 
/// Reduces allocation overhead by reusing state objects instead of
/// creating new ones. This is particularly beneficial for verification
/// of complex programs that create many states.
#[derive(Debug)]
pub struct StatePool {
    /// Pool of available states
    available: Vec<Box<BpfVerifierState>>,
    /// Maximum pool size
    max_size: usize,
    /// Statistics
    pub allocations: u64,
    pub reuses: u64,
    pub returns: u64,
}

impl StatePool {
    /// Create a new state pool
    pub fn new(max_size: usize) -> Self {
        Self {
            available: Vec::with_capacity(max_size),
            max_size,
            allocations: 0,
            reuses: 0,
            returns: 0,
        }
    }

    /// Get a state from the pool or allocate a new one
    pub fn get(&mut self) -> Box<BpfVerifierState> {
        if let Some(mut state) = self.available.pop() {
            // Reset the state before reuse
            *state = BpfVerifierState::new();
            self.reuses += 1;
            state
        } else {
            self.allocations += 1;
            Box::new(BpfVerifierState::new())
        }
    }

    /// Return a state to the pool
    pub fn put(&mut self, state: Box<BpfVerifierState>) {
        self.returns += 1;
        if self.available.len() < self.max_size {
            self.available.push(state);
        }
        // Otherwise, state is dropped
    }

    /// Get the current pool size
    pub fn size(&self) -> usize {
        self.available.len()
    }

    /// Get reuse ratio
    pub fn reuse_ratio(&self) -> f64 {
        let total = self.allocations + self.reuses;
        if total == 0 {
            0.0
        } else {
            self.reuses as f64 / total as f64
        }
    }

    /// Clear the pool
    pub fn clear(&mut self) {
        self.available.clear();
    }
}

impl Default for StatePool {
    fn default() -> Self {
        Self::new(1000)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = BloomFilter::new(100, 0.01);
        
        bloom.insert(12345);
        bloom.insert(67890);
        
        assert!(bloom.might_contain(12345));
        assert!(bloom.might_contain(67890));
        
        // Items not inserted might return false
        // (or true due to false positives, but unlikely with few items)
        let mut false_positives = 0;
        for i in 0..1000 {
            if i != 12345 && i != 67890 && bloom.might_contain(i) {
                false_positives += 1;
            }
        }
        // Should have very few false positives
        assert!(false_positives < 50);
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut bloom = BloomFilter::new(100, 0.01);
        
        bloom.insert(12345);
        assert!(bloom.might_contain(12345));
        
        bloom.clear();
        assert!(!bloom.might_contain(12345));
        assert_eq!(bloom.count(), 0);
    }

    #[test]
    fn test_state_fingerprint() {
        let state1 = BpfVerifierState::new();
        let state2 = BpfVerifierState::new();
        
        let fp1 = StateFingerprint::from_state(&state1);
        let fp2 = StateFingerprint::from_state(&state2);
        
        assert!(fp1.compatible(&fp2));
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compressed_bounds() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.mark_known(42);
        
        let compressed = CompressedRegState::compress(&reg);
        let decompressed = compressed.decompress();
        
        assert_eq!(decompressed.reg_type, BpfRegType::ScalarValue);
        assert_eq!(decompressed.umin_value, 42);
        assert_eq!(decompressed.umax_value, 42);
    }

    #[test]
    fn test_cache_stats() {
        let mut stats = CacheStats::new();
        
        stats.record_lookup();
        stats.record_bloom_rejection();
        stats.record_lookup();
        stats.record_full_comparison();
        stats.record_hit();
        
        assert_eq!(stats.lookups, 2);
        assert_eq!(stats.bloom_rejections, 1);
        assert_eq!(stats.full_comparisons, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.bloom_efficiency(), 0.5);
        assert_eq!(stats.hit_rate(), 0.5);
    }

    #[test]
    fn test_optimized_cache() {
        let mut cache = OptimizedStateCache::new(1000);
        let state = BpfVerifierState::new();
        
        // Initially bloom filter is empty
        assert!(!cache.might_contain(&state));
        
        // After adding, should pass bloom check
        cache.add_to_bloom(&state);
        assert!(cache.might_contain(&state));
    }

    #[test]
    fn test_state_pool() {
        let mut pool = StatePool::new(10);
        
        // Get some states
        let s1 = pool.get();
        let s2 = pool.get();
        
        assert_eq!(pool.allocations, 2);
        assert_eq!(pool.reuses, 0);
        
        // Return them
        pool.put(s1);
        pool.put(s2);
        
        assert_eq!(pool.size(), 2);
        
        // Get again - should reuse
        let _s3 = pool.get();
        assert_eq!(pool.reuses, 1);
    }

    #[test]
    fn test_state_pool_overflow() {
        let mut pool = StatePool::new(2);
        
        // Get and return 5 states
        let states: Vec<_> = (0..5).map(|_| pool.get()).collect();
        for s in states {
            pool.put(s);
        }
        
        // Pool should only keep max_size states
        assert_eq!(pool.size(), 2);
    }
}
