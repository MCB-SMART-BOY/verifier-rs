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
    CoreAccessSpec, CoreAccessComponent, CoreReloResult, CoreReloContext,
    CoreReloStats, apply_core_relos,
};

// Re-export from func_info module (BTF verification)
pub use func_info::{
    BpfFuncInfo, BpfLineInfo, BpfCoreRelo, BpfCoreReloKind,
    BtfInfoVerifier, VerifiedFuncInfo, SubprogInfo,
    adjust_btf_func,
    MIN_BPF_FUNCINFO_SIZE, MAX_FUNCINFO_REC_SIZE,
    MIN_BPF_LINEINFO_SIZE, MAX_LINEINFO_REC_SIZE,
    MIN_CORE_RELO_SIZE, MAX_CORE_RELO_SIZE,
};

// Re-export from validation module (validation types and logic)
pub use validation::{
    BtfKind, BtfIntEncoding, BtfType, BtfMember, BtfParam, BtfArray,
    BtfEnumValue, BtfEnum64Value, BtfVarLinkage, BtfTypes, BtfValidator,
    AccessInfo, create_kernel_btf,
};

// Re-export from integration module (verifier integration)
pub use integration::{
    SourceLocation, LineInfoDb, BtfContext, BtfAccessResult,
    KfuncValidation, FuncProtoInfo, ErrorFormatter, RegBtfInfo,
};
