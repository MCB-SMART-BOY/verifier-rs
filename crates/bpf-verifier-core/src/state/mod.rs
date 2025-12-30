// SPDX-License-Identifier: GPL-2.0

//! State representation for the BPF verifier.
//! BPF 验证器的状态表示。
//!
//! This module contains register states, stack states, verifier states,
//! reference tracking, ID mapping, lock state tracking, and state snapshots.
//!
//! 本模块包含寄存器状态、栈状态、验证器状态、引用跟踪、ID 映射、
//! 锁状态跟踪和状态快照。

pub mod idmap;
pub mod lock_state;
pub mod reference;
pub mod reg_state;
pub mod snapshot;
pub mod spill_fill;
pub mod stack_state;
pub mod verifier_state;

pub use idmap::*;
pub use lock_state::*;
pub use reference::*;
pub use reg_state::*;
pub use snapshot::*;
pub use spill_fill::*;
pub use stack_state::*;
pub use verifier_state::*;
