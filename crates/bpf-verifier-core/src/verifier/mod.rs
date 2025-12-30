// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的主验证器编排模块
//!
//! Main verifier orchestration.
//!
//! 本模块包含主验证循环、环境设置、验证统计跟踪、结果报告、
//! 资源限制、并行探索基础设施和程序加载入口点。
//!
//! This module contains the main verification loop, environment setup,
//! verification statistics tracking, result reporting, resource limits,
//! parallel exploration infrastructure, and program loading entry points.
//!
//! ## 平台通用组件 / Platform-Generic Components
//!
//! 对于平台无关的验证，请使用：
//! For platform-independent verification, use:
//! - `GenericVerifierEnv` - 平台参数化的验证器环境
//! - `GenericMainVerifier` - 平台参数化的主验证器

/// 分支状态模块 - 管理验证过程中的分支状态
/// Branch state module - manage branch states during verification
pub mod branch_state;
/// 环境模块 - 验证器环境设置
/// Environment module - verifier environment setup
pub mod env;
/// 通用环境模块 - 平台参数化的验证器环境
/// Generic environment module - platform-parameterized verifier environment
pub mod generic_env;
/// 通用验证器模块 - 平台参数化的主验证器
/// Generic verifier module - platform-parameterized main verifier
pub mod generic_verifier;
/// 限制模块 - 资源限制和复杂度控制
/// Limits module - resource limits and complexity control
pub mod limits;
/// 加载器模块 - 程序加载入口点
/// Loader module - program loading entry points
pub mod loader;
/// 主循环模块 - 主验证循环实现
/// Main loop module - main verification loop implementation
pub mod main_loop;
/// 并行模块 - 并行探索基础设施
/// Parallel module - parallel exploration infrastructure
pub mod parallel;
/// 结果模块 - 验证结果报告
/// Result module - verification result reporting
pub mod result;
/// 统计模块 - 验证统计跟踪
/// Stats module - verification statistics tracking
pub mod stats;
/// 工作清单模块 - 待验证状态管理
/// Worklist module - pending verification state management
pub mod worklist;
/// 工作清单验证器模块 - 基于工作清单的验证器
/// Worklist verifier module - worklist-based verifier
pub mod worklist_verifier;

pub use branch_state::*;
pub use env::*;
pub use generic_env::GenericVerifierEnv;
pub use generic_verifier::{GenericMainVerifier, VerificationStats};
pub use limits::*;
pub use loader::*;
pub use main_loop::*;
pub use parallel::*;
pub use result::*;
pub use stats::*;
pub use worklist::*;
pub use worklist_verifier::*;
