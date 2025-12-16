// SPDX-License-Identifier: GPL-2.0

//! BTF (BPF Type Format) support for the BPF verifier.
//!
//! This module contains BTF type parsing, validation, and CO-RE support.
//!
//! ## Features
//!
//! - **Type Database**: Parse and store BTF type information
//! - **Type Validation**: Validate memory accesses against BTF types
//! - **Function Info**: Function signatures and line info
//! - **CO-RE**: Compile Once - Run Everywhere relocation support
//! - **Verifier Integration**: BTF-aware verification with source mapping

pub mod btf;
pub mod core;
pub mod func_info;
pub mod integration;
pub mod validation;

// Re-export from btf module (core BTF database)
pub use btf::Btf;

// Re-export from core module (CO-RE support)
pub use core::{
    apply_core_relos, CoreAccessComponent, CoreAccessSpec, CoreReloContext, CoreReloResult,
    CoreReloStats,
};

// Re-export from func_info module (BTF verification)
pub use func_info::{
    adjust_btf_func, BpfCoreRelo, BpfCoreReloKind, BpfFuncInfo, BpfLineInfo, BtfInfoVerifier,
    SubprogInfo, VerifiedFuncInfo, MAX_CORE_RELO_SIZE, MAX_FUNCINFO_REC_SIZE,
    MAX_LINEINFO_REC_SIZE, MIN_BPF_FUNCINFO_SIZE, MIN_BPF_LINEINFO_SIZE, MIN_CORE_RELO_SIZE,
};

// Re-export from validation module (validation types and logic)
pub use validation::{
    create_kernel_btf, AccessInfo, BtfArray, BtfEnum64Value, BtfEnumValue, BtfIntEncoding, BtfKind,
    BtfMember, BtfParam, BtfType, BtfTypes, BtfValidator, BtfVarLinkage,
};

// Re-export from integration module (verifier integration)
pub use integration::{
    BtfAccessResult, BtfContext, ErrorFormatter, FuncProtoInfo, KfuncValidation, LineInfoDb,
    RegBtfInfo, SourceLocation,
};
