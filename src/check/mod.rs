//! Instruction verification for the BPF verifier.
//!
//! This module contains helper function verification, kfunc verification,
//! atomic operations, subprogram handling, jump analysis, signed division,
//! return value checking, callback verification, program type validation,
//! and special types (dynptr, iterator, arena) integration.

pub mod alu;
pub mod load_store;
pub mod helper;
pub mod helper_db;
pub mod kfunc;
pub mod kfunc_args;
pub mod atomic;
pub mod subprog;
pub mod jump;
pub mod sdiv;
pub mod retval;
pub mod callback;
pub mod prog_type;
pub mod arg_checks;
pub mod sleepable;
pub mod special_types;

pub use alu::*;
pub use load_store::*;
pub use helper::*;
pub use helper_db::*;
// kfunc provides the canonical is_kfunc_call
pub use kfunc::*;
pub use kfunc_args::*;
pub use atomic::*;
// subprog re-exports except is_kfunc_call (provided by kfunc)
pub use subprog::{
    SubprogInfo, SubprogManager, CallSite, CallState,
    check_max_stack_depth, setup_func_entry, prepare_func_exit,
    is_call_insn, is_subprog_call, is_helper_call, get_call_target,
    MAX_CALL_FRAMES,
};
pub use jump::*;
pub use sdiv::*;
pub use retval::*;
pub use callback::*;
pub use prog_type::*;
pub use arg_checks::*;
