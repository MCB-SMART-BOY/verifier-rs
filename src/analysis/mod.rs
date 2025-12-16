// SPDX-License-Identifier: GPL-2.0

//! Program analysis for the BPF verifier.
//!
//! This module contains control flow graph analysis, precision tracking,
//! liveness analysis, loop detection, state pruning, state merging,
//! reference leak detection, and state equivalence checking.

pub mod cfg;
pub mod leak_detector;
pub mod liveness;
pub mod loop_check;
pub mod precision;
pub mod prune;
pub mod race_detector;
pub mod scc;
pub mod state_merge;
pub mod states_equal;

// Re-export from cfg (without states_equal which is in its own module)
pub use cfg::{BasicBlock, ControlFlowGraph, ExploredStates, Verifier};
pub use leak_detector::*;
pub use liveness::*;
pub use loop_check::*;
pub use precision::*;
pub use prune::*;
pub use scc::*;
pub use state_merge::*;
// states_equal module provides the canonical states_equal function
pub use race_detector::{
    AccessType, DataRace, GlobalAccessTracker, LockState, MapAccessTracker, MemoryAccess,
    MemoryLocation, RaceDetector, RaceSeverity,
};
pub use states_equal::{
    states_equal, states_equal_with_config, states_equal_with_idmap, CompareConfig, IdMap,
};
