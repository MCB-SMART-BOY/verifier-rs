// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::state::idmap

use bpf_verifier::prelude::*;
use bpf_verifier::state::idmap::*;


    #[test]
    fn test_id_map_basic() {
        let mut map = IdMap::new();
        
        // Same mapping should work
        assert!(map.check_ids(1, 100));
        assert!(map.check_ids(1, 100)); // Same mapping
        
        // Different cur_id for same old_id should fail
        assert!(!map.check_ids(1, 200));
    }

    #[test]
    fn test_id_map_zero() {
        let mut map = IdMap::new();
        
        // Zero always matches zero
        assert!(map.check_ids(0, 0));
        
        // Zero doesn't match non-zero
        assert!(!map.check_ids(0, 1));
        assert!(!map.check_ids(1, 0));
    }

    #[test]
    fn test_id_map_multiple() {
        let mut map = IdMap::new();
        
        assert!(map.check_ids(1, 10));
        assert!(map.check_ids(2, 20));
        assert!(map.check_ids(3, 30));
        
        // Verify mappings
        assert_eq!(map.get_cur_id(1), Some(10));
        assert_eq!(map.get_cur_id(2), Some(20));
        assert_eq!(map.get_cur_id(3), Some(30));
    }

    #[test]
    fn test_scalar_ids() {
        let mut map = IdMap::new();
        
        // If old has no ID, any cur ID is fine
        assert!(map.check_scalar_ids(0, 0));
        assert!(map.check_scalar_ids(0, 100));
        
        // If old has ID but cur doesn't, fail
        assert!(!map.check_scalar_ids(1, 0));
        
        // Both have IDs - must match
        assert!(map.check_scalar_ids(1, 100));
        assert!(map.check_scalar_ids(1, 100));
        assert!(!map.check_scalar_ids(1, 200));
    }

    #[test]
    fn test_retval_range() {
        let r1 = RetvalRange::new(0, 100);
        let r2 = RetvalRange::new(10, 50);
        
        assert!(r2.within(&r1));
        assert!(!r1.within(&r2));
    }

    #[test]
    fn test_live_regs() {
        let mut live = LiveRegs::new();
        
        assert!(!live.any_live());
        
        live.set(0);
        live.set(5);
        
        assert!(live.is_live(0));
        assert!(live.is_live(5));
        assert!(!live.is_live(1));
        assert!(live.any_live());
        
        live.clear(0);
        assert!(!live.is_live(0));
        assert!(live.is_live(5));
    }

    #[test]
    fn test_live_regs_merge() {
        let mut a = LiveRegs::new();
        a.set(0);
        a.set(2);
        
        let mut b = LiveRegs::new();
        b.set(1);
        b.set(2);
        
        a.merge(&b);
        
        assert!(a.is_live(0));
        assert!(a.is_live(1));
        assert!(a.is_live(2));
    }

    #[test]
    fn test_id_map_reset() {
        let mut map = IdMap::new();
        
        map.check_ids(1, 100);
        assert_eq!(map.len(), 1);
        
        map.reset();
        assert_eq!(map.len(), 0);
        
        // Can now map 1 to a different value
        assert!(map.check_ids(1, 200));
    }
