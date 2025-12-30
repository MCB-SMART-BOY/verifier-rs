// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的优化传递模块
//!
//! Optimization passes for the BPF verifier.
//!
//! 本模块包含各种优化和转换传递，用于提高 BPF 程序的性能和安全性。
//!
//! This module contains optimization and transformation passes:
//!
//! ## 优化传递 / Optimization Passes
//!
//! - **死代码消除 / Dead code elimination**: 移除不可达指令
//! - **指令修补 / Instruction patching**: 程序转换基础设施
//! - **杂项修复 / Miscellaneous fixups**: 对应内核的 do_misc_fixups
//! - **上下文访问转换 / Context access conversion**: 对应内核的 convert_ctx_accesses
//! - **缓存优化 / Cache optimization**: 布隆过滤器、压缩、池化
//! - **调用摘要优化 / Call summary optimization**: Linux 6.13+ 新特性
//! - **统一传递框架 / Unified pass framework**: 传递管理器

/// 缓存优化模块 - 布隆过滤器和状态压缩
/// Cache optimization module - bloom filters and state compression
pub mod cache;
/// 调用摘要模块 - 避免重复验证相同函数调用
/// Call summary module - avoid re-verifying identical function calls
pub mod call_summary;
/// 上下文访问模块 - 上下文字段访问转换
/// Context access module - context field access conversion
pub mod ctx_access;
/// 死代码消除模块 - 移除不可达指令
/// Dead code elimination module - remove unreachable instructions
pub mod dead_code;
/// JIT 子程序模块 - 为 JIT 编译准备子程序
/// JIT subprogs module - prepare subprograms for JIT compilation
pub mod jit_subprogs;
/// 杂项修复模块 - 各种指令转换和修复
/// Misc fixups module - various instruction transformations and fixes
pub mod misc_fixups;
/// 传递框架模块 - 统一的优化传递框架
/// Pass framework module - unified optimization pass framework
pub mod pass;
/// 指令修补模块 - 程序转换基础设施
/// Patching module - program transformation infrastructure
pub mod patching;

pub use cache::*;
pub use call_summary::*;
pub use ctx_access::*;
pub use dead_code::*;
pub use jit_subprogs::*;
pub use misc_fixups::*;
pub use pass::*;
pub use patching::*;
