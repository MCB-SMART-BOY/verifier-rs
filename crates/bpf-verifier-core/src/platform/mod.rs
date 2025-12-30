// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的平台抽象层
//!
//! Platform abstraction layer for BPF verifier.
//!
//! 本模块定义了平台无关的 trait，使验证器能够支持不同的 BPF 实现
//! （Linux、自定义操作系统等）。
//!
//! This module defines platform-agnostic traits that allow the verifier
//! to support different BPF implementations (Linux, custom OS, etc.).
//!
//! # 设计理念 / Design Philosophy
//!
//! 借鉴 Nix crate 的设计模式，我们分离了：
//! Following the Nix crate's design pattern, we separate:
//! - **核心逻辑 / Core logic**: 平台无关的验证算法
//! - **平台规范 / Platform specification**: 操作系统特定的定义（辅助函数、程序类型等）
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │              bpf-verifier-core (this crate)             │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │              PlatformSpec trait                  │   │
//! │  │  ├─ HelperProvider                              │   │
//! │  │  ├─ ProgTypeProvider                            │   │
//! │  │  ├─ KfuncProvider                               │   │
//! │  │  ├─ MapProvider                                 │   │
//! │  │  └─ ContextProvider                             │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//!                            ▲
//!                            │ implements
//!          ┌─────────────────┼─────────────────┐
//!          │                 │                 │
//! ┌────────┴───────┐ ┌───────┴────────┐ ┌──────┴───────┐
//! │  LinuxSpec     │ │   MyOsSpec     │ │  MockSpec    │
//! │  (Linux impl)  │ │  (Custom OS)   │ │  (Testing)   │
//! └────────────────┘ └────────────────┘ └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use bpf_verifier_core::platform::PlatformSpec;
//! use bpf_verifier_core::verifier::{VerifierEnv, MainVerifier};
//!
//! // For Linux
//! let platform = LinuxSpec::new();
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! let result = MainVerifier::new(&mut env).verify();
//!
//! // For custom OS
//! let platform = MyOsSpec::new();
//! let mut env = VerifierEnv::new(platform, prog_type, insns);
//! let result = MainVerifier::new(&mut env).verify();
//! ```

/// 平台规范 trait / Platform specification trait
pub mod spec;
/// 辅助函数提供者 / Helper function provider
mod helper;
/// 程序类型提供者 / Program type provider
mod prog_type;
/// 内核函数提供者 / Kernel function provider
mod kfunc;
/// 映射提供者 / Map provider
mod map;
/// 上下文提供者定义 / Context provider definitions
pub mod context;
/// 平台无关的类型 / Platform-agnostic types
pub mod types;

// 重新导出所有 trait 和类型
// Re-export all traits and types
pub use spec::{PlatformSpec, NullPlatform};
pub use helper::{HelperProvider, HelperDef, HelperFlags};
pub use prog_type::{ProgTypeProvider, ProgTypeInfo, ProgCapabilities};
pub use kfunc::{KfuncProvider, KfuncDef, KfuncFlags};
pub use map::{MapProvider, MapTypeInfo, MapCapabilities, MapOp};
pub use context::{ContextProvider, ContextFieldDef, FieldAccessMode, FieldResultType, ContextDef};
pub use types::*;
