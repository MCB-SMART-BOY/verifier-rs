// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的净化模块
//!
//! Sanitization for the BPF verifier.
//!
//! 本模块包含指针算术净化和 Spectre 推测执行攻击缓解支持。
//! 净化是验证器中的关键安全机制，用于确保即使在推测执行的情况下，
//! 内存访问也是安全的。
//!
//! This module contains pointer arithmetic sanitization and
//! Spectre mitigation support.
//!
//! ## 主要组件 (Key components)
//!
//! - `spectre`: Spectre 缓解和指针净化 - 检测并缓解推测执行攻击
//!   (Core Spectre mitigation and pointer sanitization)
//! - `overflow`: 指针溢出检查补丁 - 为 JIT 生成溢出检查代码
//!   (Pointer overflow check patches for JIT)
//!
//! ## Spectre 攻击缓解
//!
//! - Spectre v1 (边界检查绕过): 通过索引掩码和推测屏障缓解
//! - Spectre v4 (推测性存储绕过): 通过 LFENCE 指令缓解
//!
//! ## 溢出检查
//!
//! - 检测指针算术运算中的潜在溢出
//! - 为不同指针类型生成安全边界检查

/// 溢出检查模块 - 指针溢出检测和 JIT 补丁生成
/// Overflow checking - pointer overflow detection and JIT patch generation
pub mod overflow;
/// Spectre 缓解模块 - 推测执行攻击防护
/// Spectre mitigation - speculative execution attack protection
pub mod spectre;

pub use overflow::*;
pub use spectre::*;
