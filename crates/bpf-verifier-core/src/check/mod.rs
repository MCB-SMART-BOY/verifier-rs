// SPDX-License-Identifier: GPL-2.0

//! BPF 指令验证模块
//!
//! Instruction verification for the BPF verifier.
//!
//! 本模块包含 BPF 验证器的指令级验证逻辑，负责验证每条 BPF 指令的安全性和正确性。
//!
//! This module contains helper function verification, kfunc verification,
//! atomic operations, subprogram handling, jump analysis, signed division,
//! return value checking, callback verification, program type validation,
//! and special types (dynptr, iterator, arena) integration.
//!
//! ## 主要功能模块
//!
//! ### 函数调用验证
//! - `helper`: 辅助函数调用验证 - 验证 BPF 辅助函数的参数和返回值
//! - `helper_db`: 辅助函数数据库 - 存储辅助函数的签名和约束信息
//! - `kfunc`: 内核函数验证 - 验证 kfunc 调用的类型安全性
//! - `kfunc_args`: 内核函数参数验证 - 检查 kfunc 参数的有效性
//! - `callback`: 回调函数验证 - 验证回调函数的正确性
//!
//! ### 指令验证
//! - `alu`: ALU（算术逻辑单元）操作验证 - 验证算术和逻辑指令
//! - `atomic`: 原子操作验证 - 验证原子指令的内存安全性
//! - `jump`: 跳转指令验证 - 验证条件和无条件跳转
//! - `load_store`: 加载/存储指令验证 - 验证内存访问指令
//! - `sdiv`: 有符号除法验证 - 确保除法操作安全
//!
//! ### 程序结构验证
//! - `subprog`: 子程序管理 - 处理函数调用和返回
//! - `prog_type`: 程序类型验证 - 验证程序类型相关的约束
//! - `attach_target`: 附加目标验证 - 验证程序附加点
//! - `retval`: 返回值验证 - 验证程序返回值的有效性
//!
//! ### 特殊功能
//! - `arg_checks`: 参数检查 - 通用参数验证逻辑
//! - `sleepable`: 可睡眠上下文验证 - 验证睡眠相关约束
//! - `special_types`: 特殊类型集成 - dynptr、迭代器、arena 等

pub mod alu;
pub mod arg_checks;
pub mod atomic;
pub mod attach_target;
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
pub use attach_target::*;
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
