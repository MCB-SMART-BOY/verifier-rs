// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的内核集成层模块
//!
//! Kernel Integration Layer for the BPF Verifier.
//!
//! 本模块提供 Rust BPF 验证器和 Linux 内核之间的接口。处理以下内容：
//!
//! This module provides the interface between the Rust BPF verifier
//! and the Linux kernel. It handles:
//!
//! - **FFI 绑定 / FFI bindings**: 内核数据结构的绑定
//!   Bindings to kernel data structures
//! - **内存分配 / Memory allocation**: 使用内核分配器
//!   Using kernel allocators
//! - **错误码转换 / Error code translation**: 验证器错误到 errno 的转换
//!   Verifier errors to errno translation
//! - **日志 / Logging**: 通过内核设施进行日志记录
//!   Logging through kernel facilities
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Kernel (C code)                       │
//! │  bpf_check() -> rust_bpf_verify() -> bpf_verifier_ops   │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                 kernel::bindings (FFI)                   │
//! │  - struct bpf_verifier_env                              │
//! │  - struct bpf_prog                                      │
//! │  - struct bpf_map                                       │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                 kernel::bridge                           │
//! │  - KernelVerifierEnv (safe wrapper)                     │
//! │  - Convert C types to Rust types                        │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Rust Verifier (pure Rust)                   │
//! │  - MainVerifier                                         │
//! │  - State tracking, bounds analysis, etc.                │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod bindings;
pub mod bridge;
pub mod error;
pub mod alloc;
pub mod log;

// Re-exports for convenience
pub use bindings::*;
pub use bridge::KernelVerifierEnv;
pub use error::KernelError;
