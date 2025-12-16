// SPDX-License-Identifier: GPL-2.0

//! State representation for the BPF verifier.
//!
//! This module contains register states, stack states, verifier states,
//! reference tracking, ID mapping, lock state tracking, and state snapshots.

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
