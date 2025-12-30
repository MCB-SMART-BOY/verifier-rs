// SPDX-License-Identifier: GPL-2.0

//! # BPF Verifier Core
//! # BPF 验证器核心库
//!
//! Platform-agnostic BPF verifier implementation.
//! 平台无关的 BPF 验证器实现。
//!
//! This crate provides static code analysis for eBPF programs to ensure safety
//! before they are loaded into the kernel.
//! 本 crate 提供对 eBPF 程序的静态代码分析，确保程序在加载到内核之前是安全的。
//!
//! ## Features
//! ## 功能特性
//!
//! - **Register State Tracking**: Tracks the type and bounds of all registers
//!   **寄存器状态追踪**：追踪所有寄存器的类型和边界
//! - **Memory Safety**: Validates all memory accesses (stack, maps, packets, context)
//!   **内存安全**：验证所有内存访问（栈、映射、数据包、上下文）
//! - **Control Flow Analysis**: Explores all possible execution paths
//!   **控制流分析**：探索所有可能的执行路径
//! - **Reference Tracking**: Ensures acquired resources are properly released
//!   **引用追踪**：确保获取的资源被正确释放
//! - **Bounds Analysis**: Tracks numeric bounds to prevent buffer overflows
//!   **边界分析**：追踪数值边界以防止缓冲区溢出
//!
//! ## Module Structure
//! ## 模块结构
//!
//! - [`core`]: Core types, error definitions, logging, and instruction representations
//!   核心类型、错误定义、日志和指令表示
//! - [`state`]: Register states, stack states, verifier states, and reference tracking
//!   寄存器状态、栈状态、验证器状态和引用追踪
//! - [`bounds`]: Numeric bounds tracking (Tnum and scalar bounds)
//!   数值边界追踪（Tnum 和标量边界）
//! - [`analysis`]: Program analysis (CFG, precision, liveness, loops, pruning)
//!   程序分析（控制流图、精度、活跃性、循环、剪枝）
//! - [`check`]: Instruction verification (helpers, kfuncs, atomics, jumps)
//!   指令验证（辅助函数、内核函数、原子操作、跳转）
//! - [`mem`]: Memory access verification (stack, packet, context, arena)
//!   内存访问验证（栈、数据包、上下文、竞技场）
//! - [`special`]: Special object handling (dynptr, iterators, exceptions, maps)
//!   特殊对象处理（动态指针、迭代器、异常、映射）
//! - [`btf`]: BTF (BPF Type Format) support
//!   BTF（BPF 类型格式）支持
//! - [`sanitize`]: Pointer arithmetic sanitization for Spectre mitigation
//!   指针算术净化，用于 Spectre 漏洞缓解
//! - [`opt`]: Optimization passes (dead code elimination, instruction patching)
//!   优化传递（死代码消除、指令修补）
//! - [`verifier`]: Main verification loop and environment
//!   主验证循环和环境
//! - [`platform`]: Platform abstraction layer for cross-OS support
//!   平台抽象层，用于跨操作系统支持
//!
//! ## Platform Abstraction
//! ## 平台抽象
//!
//! The verifier uses a trait-based platform abstraction layer that separates
//! core verification logic from OS-specific definitions. This allows:
//! 验证器使用基于 trait 的平台抽象层，将核心验证逻辑与操作系统特定定义分离。这允许：
//!
//! - Running the same verifier on different operating systems
//!   在不同操作系统上运行相同的验证器
//! - Easy testing with mock platforms
//!   使用模拟平台进行简单测试
//! - Custom BPF implementations with their own helper/map definitions
//!   自定义 BPF 实现及其自己的辅助函数/映射定义
//!
//! See the [`platform`] module for details on implementing custom platforms.
//! 有关实现自定义平台的详细信息，请参阅 [`platform`] 模块。

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Unsafe code is required for FFI with kernel and low-level memory operations
// 与内核的 FFI 和底层内存操作需要不安全代码
#![expect(unsafe_code, reason = "Required for kernel FFI and MaybeUninit usage")]

extern crate alloc;

// Re-export alloc types for internal use
// 为内部使用重新导出 alloc 类型
#[expect(unused_imports, reason = "Not all imports used in all configurations")]
pub(crate) mod stdlib {
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::vec;
    pub use alloc::format;
    pub use alloc::collections::{BTreeMap, BTreeSet, VecDeque, BinaryHeap};
}

/// Core types, error definitions, and basic utilities
/// 核心类型、错误定义和基本工具
pub mod core;

/// State tracking (registers, stack, verifier state)
/// 状态追踪（寄存器、栈、验证器状态）
pub mod state;

/// Numeric bounds tracking
/// 数值边界追踪
pub mod bounds;

/// Program analysis passes
/// 程序分析传递
pub mod analysis;

/// Instruction checking
/// 指令检查
pub mod check;

/// Memory access verification
/// 内存访问验证
pub mod mem;

/// Special object handling
/// 特殊对象处理
pub mod special;

/// BTF type support
/// BTF 类型支持
pub mod btf;

/// Sanitization passes
/// 净化传递
pub mod sanitize;

/// Optimization passes
/// 优化传递
pub mod opt;

/// Main verifier
/// 主验证器
pub mod verifier;

/// Platform abstraction layer
/// 平台抽象层
pub mod platform;

// ============================================================================
// Prelude - commonly used re-exports
// 预导入 - 常用的重新导出
// ============================================================================

/// Commonly used types and traits
/// 常用的类型和 trait
pub mod prelude {
    // Core types and errors
    // 核心类型和错误
    pub use crate::core::error::{Result, VerifierError};
    pub use crate::core::types::{
        BpfArgType, BpfFuncId, BpfInsn, BpfMapType, BpfProgType, BpfRegType,
        BpfRetType, BpfRetvalRange, BpfTypeFlag,
    };
    pub use crate::core::types::{
        BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_ATOMIC, BPF_B,
        BPF_CALL, BPF_DIV, BPF_DW, BPF_END, BPF_EXIT, BPF_H, BPF_IMM, BPF_JA,
        BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP, BPF_JMP32,
        BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_K,
        BPF_LD, BPF_LDX, BPF_LSH, BPF_MEM, BPF_MOD, BPF_MOV, BPF_MUL, BPF_NEG,
        BPF_OR, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL, BPF_PSEUDO_MAP_FD,
        BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5,
        BPF_REG_6, BPF_REG_7, BPF_REG_8, BPF_REG_9, BPF_REG_FP, BPF_REG_SIZE,
        BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_W, BPF_X, BPF_XOR,
        MAX_BPF_REG, MAX_BPF_STACK,
    };

    // State types
    // 状态类型
    pub use crate::state::reg_state::BpfRegState;
    pub use crate::state::stack_state::BpfStackState;
    pub use crate::state::verifier_state::BpfVerifierState;
    pub use crate::state::reference::{BpfReferenceState, ReferenceManager};
    pub use crate::core::types::RefStateType;
    pub use crate::core::types::BpfStackSlotType;

    // Bounds types
    // 边界类型
    pub use crate::bounds::tnum::Tnum;
    pub use crate::bounds::scalar::ScalarBounds;

    // BTF types
    // BTF 类型
    pub use crate::btf::{Btf, BpfCoreReloKind};

    // Special types
    // 特殊类型
    pub use crate::core::types::BpfDynptrType;

    // Atomic constants
    // 原子操作常量
    pub use crate::core::types::BPF_FETCH;

    // Verifier
    // 验证器
    pub use crate::verifier::{MainVerifier, VerifierEnv};

    // Platform abstraction
    // 平台抽象
    pub use crate::platform::{
        PlatformSpec, HelperProvider, ProgTypeProvider, KfuncProvider,
        MapProvider, ContextProvider,
    };
}

// Re-export error types at crate root for convenience
// 在 crate 根目录重新导出错误类型以方便使用
pub use core::error::{Result, VerifierError};
