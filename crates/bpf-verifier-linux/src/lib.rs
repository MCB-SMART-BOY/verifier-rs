// SPDX-License-Identifier: GPL-2.0

//! # BPF 验证器 Linux 平台实现
//! # BPF Verifier Linux Platform
//!
//! BPF 验证器的 Linux 平台实现。
//! Linux platform implementation for the BPF verifier.
//!
//! ## 功能特性 / Features
//!
//! 本 crate 提供：
//! This crate provides:
//! - Linux BPF 辅助函数定义 / Linux BPF helper function definitions
//! - Linux 程序类型定义 / Linux program type definitions
//! - Linux 内核函数定义 / Linux kfunc definitions
//! - Linux 映射类型定义 / Linux map type definitions
//! - Linux 上下文结构定义 / Linux context structure definitions
//! - 内核集成层（可选，使用 `kernel` 特性）/ Kernel integration layer (optional, with `kernel` feature)
//!
//! ## 使用示例 / Usage
//!
//! ```ignore
//! use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
//! use bpf_verifier_linux::LinuxSpec;
//!
//! // 创建 Linux 平台规范 / Create Linux platform specification
//! let platform = LinuxSpec::new();
//! // 创建验证器环境 / Create verifier environment
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! // 执行验证 / Perform verification
//! let result = MainVerifier::new(&mut env).verify();
//! ```
//!
//! ## 架构 / Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │            bpf-verifier-linux (本 crate / this crate)   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │              LinuxSpec                           │   │
//! │  │  ├─ LinuxHelperProvider   (辅助函数提供者)      │   │
//! │  │  ├─ LinuxProgTypeProvider (程序类型提供者)      │   │
//! │  │  ├─ LinuxKfuncProvider    (内核函数提供者)      │   │
//! │  │  ├─ LinuxMapProvider      (映射提供者)          │   │
//! │  │  └─ LinuxContextProvider  (上下文提供者)        │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// 为方便使用重新导出核心 crate
// Re-export core crate for convenience
pub use bpf_verifier_core as core;

/// Linux 平台规范实现
/// Linux platform specification implementation
mod spec;

pub use spec::LinuxSpec;

// 平台提供者实现
// Platform provider implementations

/// 辅助函数数据库 - Linux BPF 辅助函数定义
/// Helper database - Linux BPF helper function definitions
mod helper_db;
/// 程序类型 - Linux BPF 程序类型定义
/// Program types - Linux BPF program type definitions
mod prog_types;
/// 内核函数 - Linux kfunc 定义
/// Kfuncs - Linux kfunc definitions
mod kfuncs;
/// 映射类型 - Linux BPF 映射类型定义
/// Map types - Linux BPF map type definitions
mod map_types;
/// 上下文 - Linux 上下文结构定义
/// Context - Linux context structure definitions
mod context;

/// Linux 辅助函数提供者
/// Linux helper function provider
pub use helper_db::LinuxHelperProvider;
/// Linux 程序类型提供者
/// Linux program type provider
pub use prog_types::LinuxProgTypeProvider;
/// Linux 内核函数提供者
/// Linux kfunc provider
pub use kfuncs::LinuxKfuncProvider;
/// Linux 映射提供者
/// Linux map provider
pub use map_types::LinuxMapProvider;
/// Linux 上下文提供者
/// Linux context provider
pub use context::LinuxContextProvider;

/// 内核集成层（需要 `kernel` 特性）
/// Kernel integration layer (requires `kernel` feature)
#[cfg(feature = "kernel")]
pub mod kernel;
