//! ID mapping for state comparison
//!
//! This module handles ID mapping during state comparison. When comparing
//! two verifier states, we need to track which IDs in one state correspond
//! to which IDs in the other state.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

/// Maximum number of ID mappings to track
pub const BPF_ID_MAP_SIZE: usize = 64;

/// ID mapping entry
#[derive(Debug, Clone, Copy, Default)]
pub struct IdMapEntry {
    /// ID from the old (cached) state
    pub old_id: u32,
    /// ID from the current state
    pub cur_id: u32,
}

/// ID map for state comparison
#[derive(Debug, Clone)]
pub struct IdMap {
    /// Mapping entries
    entries: Vec<IdMapEntry>,
    /// Fast lookup: old_id -> index
    old_to_idx: HashMap<u32, usize>,
}

impl Default for IdMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdMap {
    /// Create a new empty ID map
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(BPF_ID_MAP_SIZE),
            old_to_idx: HashMap::new(),
        }
    }

    /// Reset the ID map for a new comparison
    pub fn reset(&mut self) {
        self.entries.clear();
        self.old_to_idx.clear();
    }

    /// Check if two IDs match according to the current mapping
    /// If old_id hasn't been seen, add it to the mapping
    pub fn check_ids(&mut self, old_id: u32, cur_id: u32) -> bool {
        // ID 0 is special - always matches 0
        if old_id == 0 && cur_id == 0 {
            return true;
        }
        if old_id == 0 || cur_id == 0 {
            return false;
        }

        // Check if we've seen this old_id before
        if let Some(&idx) = self.old_to_idx.get(&old_id) {
            // Must map to the same cur_id
            return self.entries[idx].cur_id == cur_id;
        }

        // New ID - add to mapping if space available
        if self.entries.len() >= BPF_ID_MAP_SIZE {
            return false; // Too many IDs
        }

        let idx = self.entries.len();
        self.entries.push(IdMapEntry { old_id, cur_id });
        self.old_to_idx.insert(old_id, idx);
        true
    }

    /// Check scalar IDs - used for precision tracking
    /// Scalar IDs are only compared when both are non-zero
    pub fn check_scalar_ids(&mut self, old_id: u32, cur_id: u32) -> bool {
        // If old doesn't have ID, cur can have any ID
        if old_id == 0 {
            return true;
        }
        // If old has ID but cur doesn't, not equal
        if cur_id == 0 {
            return false;
        }
        // Both have IDs - they must map
        self.check_ids(old_id, cur_id)
    }

    /// Get the current ID for an old ID
    pub fn get_cur_id(&self, old_id: u32) -> Option<u32> {
        self.old_to_idx.get(&old_id)
            .map(|&idx| self.entries[idx].cur_id)
    }

    /// Get number of mappings
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Range comparison for return values
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RetvalRange {
    pub minval: i64,
    pub maxval: i64,
}

impl RetvalRange {
    /// Create a new return value range
    pub fn new(minval: i64, maxval: i64) -> Self {
        Self { minval, maxval }
    }

    /// Check if this range is within another range
    pub fn within(&self, other: &RetvalRange) -> bool {
        self.minval >= other.minval && self.maxval <= other.maxval
    }

    /// Check if ranges are equal
    pub fn equal(&self, other: &RetvalRange) -> bool {
        self.minval == other.minval && self.maxval == other.maxval
    }
}

/// Live register bitmap for tracking which registers are live
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveRegs {
    /// Bitmask of live registers (bit i = register i is live)
    pub mask: u16,
}

impl LiveRegs {
    /// Create a new empty live register set
    pub fn new() -> Self {
        Self { mask: 0 }
    }

    /// Set a register as live
    pub fn set(&mut self, regno: usize) {
        if regno < 16 {
            self.mask |= 1 << regno;
        }
    }

    /// Clear a register
    pub fn clear(&mut self, regno: usize) {
        if regno < 16 {
            self.mask &= !(1 << regno);
        }
    }

    /// Check if a register is live
    pub fn is_live(&self, regno: usize) -> bool {
        if regno < 16 {
            (self.mask & (1 << regno)) != 0
        } else {
            false
        }
    }

    /// Check if any register is live
    pub fn any_live(&self) -> bool {
        self.mask != 0
    }

    /// Merge with another live set (union)
    pub fn merge(&mut self, other: &LiveRegs) {
        self.mask |= other.mask;
    }

    /// Intersect with another live set
    pub fn intersect(&mut self, other: &LiveRegs) {
        self.mask &= other.mask;
    }
}

/// Read marks for tracking which registers/slots have been read
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ReadMark {
    #[default]
    None = 0,
    /// Read in current state
    Read = 1,
    /// Read in parent state (inherited)
    ReadParent = 2,
}

impl ReadMark {
    /// Check if this mark indicates the register was read
    pub fn is_read(&self) -> bool {
        *self != ReadMark::None
    }
}

/// Parent link for state hierarchy
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum ParentLink {
    /// No parent
    #[default]
    None,
    /// Parent is an explored state at given index
    Explored(usize),
    /// Parent is on the exploration stack at given depth
    Stack(usize),
}


#[cfg(test)]
mod tests {
    use super::*;

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
}
