// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::opt::cache

use bpf_verifier::opt::cache::*;

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
