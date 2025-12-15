//! Program analysis for the BPF verifier.
//!
//! This module contains control flow graph analysis, precision tracking,
//! liveness analysis, loop detection, state pruning, state merging,
//! reference leak detection, and state equivalence checking.

pub mod cfg;
pub mod precision;
pub mod liveness;
pub mod loop_check;
pub mod prune;
pub mod scc;
pub mod state_merge;
pub mod leak_detector;
pub mod states_equal;
pub mod race_detector;

// Re-export from cfg (without states_equal which is in its own module)
pub use cfg::{
    BasicBlock, ControlFlowGraph, ExploredStates, Verifier,
};
pub use precision::*;
pub use liveness::*;
pub use loop_check::*;
pub use prune::*;
pub use scc::*;
pub use state_merge::*;
pub use leak_detector::*;
// states_equal module provides the canonical states_equal function
pub use states_equal::{
    states_equal, states_equal_with_config, states_equal_with_idmap,
    CompareConfig, IdMap,
};
pub use race_detector::{
    RaceDetector, DataRace, RaceSeverity, AccessType, MemoryLocation,
    MemoryAccess, LockState, MapAccessTracker, GlobalAccessTracker,
};
