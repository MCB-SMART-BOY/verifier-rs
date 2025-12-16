// SPDX-License-Identifier: GPL-2.0

//! Instruction verification for the BPF verifier.
//!
//! This module contains helper function verification, kfunc verification,
//! atomic operations, subprogram handling, jump analysis, signed division,
//! return value checking, callback verification, program type validation,
//! and special types (dynptr, iterator, arena) integration.

pub mod alu;
pub mod arg_checks;
pub mod atomic;
pub mod callback;
pub mod helper;
pub mod helper_db;
pub mod jump;
pub mod kfunc;
pub mod kfunc_args;
pub mod load_store;
pub mod prog_type;
pub mod retval;
pub mod sdiv;
pub mod sleepable;
pub mod special_types;
pub mod subprog;

pub use alu::*;
pub use helper::*;
pub use helper_db::*;
pub use load_store::*;
// kfunc provides the canonical is_kfunc_call
pub use atomic::*;
pub use kfunc::*;
pub use kfunc_args::*;
// subprog re-exports except is_kfunc_call (provided by kfunc)
pub use arg_checks::*;
pub use callback::*;
pub use jump::*;
pub use prog_type::*;
pub use retval::*;
pub use sdiv::*;
pub use subprog::{
    check_max_stack_depth, get_call_target, is_call_insn, is_helper_call, is_subprog_call,
    prepare_func_exit, setup_func_entry, CallSite, CallState, SubprogInfo, SubprogManager,
    MAX_CALL_FRAMES,
};
