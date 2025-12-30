// SPDX-License-Identifier: GPL-2.0

//! Program analysis for the BPF verifier.
//! BPF 验证器的程序分析。
//!
//! This module contains control flow graph analysis, precision tracking,
//! 本模块包含控制流图分析、精度跟踪、
//! liveness analysis, loop detection, state pruning, state merging,
//! 活性分析、循环检测、状态剪枝、状态合并、
//! reference leak detection, and state equivalence checking.
//! 引用泄漏检测和状态等价性检查。

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
// 从 cfg 重新导出（states_equal 在其自己的模块中）
pub use cfg::{BasicBlock, ControlFlowGraph, ExploredStates, Verifier};
pub use leak_detector::*;
pub use liveness::*;
pub use loop_check::*;
pub use precision::*;
pub use prune::*;
pub use scc::*;
pub use state_merge::*;
// states_equal module provides the canonical states_equal function
// states_equal 模块提供规范的 states_equal 函数
pub use race_detector::{
    AccessType, DataRace, GlobalAccessTracker, LockState, MapAccessTracker, MemoryAccess,
    MemoryLocation, RaceDetector, RaceSeverity,
};
pub use states_equal::{
    states_equal, states_equal_with_config, states_equal_with_idmap, stackslot_safe,
    CompareConfig, IdMap,
};
