// SPDX-License-Identifier: GPL-2.0

//! # BPF Verifier
//! # BPF 验证器
//!
//! Convenience crate that re-exports the BPF verifier core and Linux platform.
//! 便捷库，重新导出 BPF 验证器核心和 Linux 平台。
//!
//! This crate provides a single dependency for using the BPF verifier with
//! Linux support. For custom platforms, depend on `bpf-verifier-core` directly.
//! 此库为使用带 Linux 支持的 BPF 验证器提供了单一依赖。
//! 对于自定义平台，请直接依赖 `bpf-verifier-core`。
//!
//! ## Usage
//! ## 使用方法
//!
//! ```ignore
//! use bpf_verifier::{LinuxSpec, VerifierEnv, MainVerifier};
//! use bpf_verifier::core::types::BpfProgType;
//!
//! let platform = LinuxSpec::new();
//! let insns = vec![/* BPF instructions */];
//! let mut env = VerifierEnv::new(platform, BpfProgType::Xdp as u32, insns);
//! let mut verifier = MainVerifier::new(&mut env);
//!
//! match verifier.verify() {
//!     Ok(()) => println!("Program verified successfully"),
//!     Err(e) => println!("Verification failed: {:?}", e),
//! }
//! ```

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Re-export core crate modules for testing
// 为测试重新导出核心库模块
pub use bpf_verifier_core::analysis;
pub use bpf_verifier_core::bounds;
pub use bpf_verifier_core::btf;
pub use bpf_verifier_core::check;
pub use bpf_verifier_core::mem;
pub use bpf_verifier_core::opt;
pub use bpf_verifier_core::platform;
pub use bpf_verifier_core::sanitize;
pub use bpf_verifier_core::special;
pub use bpf_verifier_core::state;
pub use bpf_verifier_core::verifier;
pub use bpf_verifier_core::core as bpf_core;

// Re-export core crate
// 重新导出核心库
pub use bpf_verifier_core as core;

// Re-export Linux platform
// 重新导出 Linux 平台
#[cfg(feature = "linux")]
pub use bpf_verifier_linux as linux;

// Convenient re-exports (prelude)
// 便捷的重新导出 (预导入)
pub use bpf_verifier_core::prelude;
pub use bpf_verifier_core::prelude::*;

#[cfg(feature = "linux")]
pub use bpf_verifier_linux::LinuxSpec;
