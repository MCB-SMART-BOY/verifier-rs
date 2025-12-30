// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的 BTF（BPF 类型格式）支持模块
//!
//! BTF (BPF Type Format) support for the BPF verifier.
//!
//! 本模块包含 BTF 类型解析、验证和 CO-RE 支持。
//!
//! This module contains BTF type parsing, validation, and CO-RE support.
//!
//! ## 功能特性 / Features
//!
//! - **类型数据库 / Type Database**: 解析和存储 BTF 类型信息
//! - **类型验证 / Type Validation**: 根据 BTF 类型验证内存访问
//! - **函数信息 / Function Info**: 函数签名和行信息
//! - **CO-RE**: 一次编译到处运行的重定位支持
//! - **验证器集成 / Verifier Integration**: 带源码映射的 BTF 感知验证
//!
//! ## BTF 概述 / BTF Overview
//!
//! BTF 是一种紧凑的类型格式，用于描述 BPF 程序和映射的类型信息。
//! 它支持调试、类型安全验证和跨内核版本的程序可移植性。
//!
//! BTF is a compact type format used to describe type information for
//! BPF programs and maps. It enables debugging, type-safe verification,
//! and program portability across kernel versions.

/// 类型数据库模块 - 解析和存储 BTF 类型信息
/// Type database module - parse and store BTF type information
pub mod database;
/// CO-RE 模块 - 一次编译到处运行的重定位支持
/// CO-RE module - Compile Once Run Everywhere relocation support
pub mod core;
/// 函数信息模块 - 函数签名和行信息验证
/// Function info module - function signatures and line info validation
pub mod func_info;
/// 集成模块 - BTF 与验证器的集成
/// Integration module - BTF integration with verifier
pub mod integration;
/// 验证模块 - BTF 类型验证逻辑
/// Validation module - BTF type validation logic
pub mod validation;

// 从 database 模块重新导出（核心 BTF 数据库）
// Re-export from database module (core BTF database)
pub use database::Btf;

// 从 core 模块重新导出（CO-RE 支持）
// Re-export from core module (CO-RE support)
pub use core::{
    apply_core_relos, CoreAccessComponent, CoreAccessSpec, CoreReloContext, CoreReloResult,
    CoreReloStats,
};

// 从 func_info 模块重新导出（BTF 验证）
// Re-export from func_info module (BTF verification)
pub use func_info::{
    adjust_btf_func, BpfCoreRelo, BpfCoreReloKind, BpfFuncInfo, BpfLineInfo, BtfInfoVerifier,
    SubprogInfo, VerifiedFuncInfo, MAX_CORE_RELO_SIZE, MAX_FUNCINFO_REC_SIZE,
    MAX_LINEINFO_REC_SIZE, MIN_BPF_FUNCINFO_SIZE, MIN_BPF_LINEINFO_SIZE, MIN_CORE_RELO_SIZE,
};

// 从 validation 模块重新导出（验证类型和逻辑）
// Re-export from validation module (validation types and logic)
pub use validation::{
    create_kernel_btf, AccessInfo, BtfArray, BtfEnum64Value, BtfEnumValue, BtfIntEncoding, BtfKind,
    BtfMember, BtfParam, BtfType, BtfTypes, BtfValidator, BtfVarLinkage,
};

// 从 integration 模块重新导出（验证器集成）
// Re-export from integration module (verifier integration)
pub use integration::{
    BtfAccessResult, BtfContext, ErrorFormatter, FuncProtoInfo, KfuncValidation, LineInfoDb,
    RegBtfInfo, SourceLocation,
};
