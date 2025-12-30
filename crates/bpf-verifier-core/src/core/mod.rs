// SPDX-License-Identifier: GPL-2.0

//! Core types and constants for the BPF verifier.
//! BPF 验证器的核心类型和常量。
//!
//! This module contains fundamental types, error definitions, logging,
//! instruction representations, and disassembly used throughout the verifier.
//!
//! 本模块包含验证器中使用的基础类型、错误定义、日志记录、
//! 指令表示和反汇编功能。

pub mod disasm;
pub mod error;
pub mod insn;
pub mod insn_verify;
pub mod log;
pub mod types;

pub use disasm::*;
pub use error::*;
pub use insn::*;
pub use insn_verify::*;
pub use log::*;
pub use types::*;
