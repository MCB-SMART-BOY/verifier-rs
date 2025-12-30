// SPDX-License-Identifier: GPL-2.0

//! Numeric bounds tracking for the BPF verifier.
//! BPF 验证器的数值边界跟踪
//!
//! This module contains tracked numbers (Tnum), scalar bounds analysis,
//! range refinement for conditional branches, and instruction bounds integration.
//! 本模块包含跟踪数（Tnum）、标量边界分析、条件分支的范围细化以及指令边界集成。

pub mod insn_bounds;
pub mod range_refine;
pub mod scalar;
pub mod tnum;

pub use insn_bounds::*;
pub use range_refine::*;
pub use scalar::*;
pub use tnum::*;
