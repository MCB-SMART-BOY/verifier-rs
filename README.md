# BPF Verifier

Linux 内核 BPF 验证器 (`kernel/bpf/verifier.c`) 的完整 Rust 实现。

## 概述

本 crate 提供 eBPF 程序的静态代码分析，确保程序在加载到内核之前是安全的。它实现了与 Linux 内核 BPF 验证器相同的验证逻辑，但使用安全的 Rust 编写。

**项目状态**: 约 95% 功能完成

| 指标 | 数值 |
|------|------|
| Rust 代码行数 | 83,304 |
| 参考 C 代码行数 | 25,398 |
| 模块/文件数量 | 94 |
| 测试用例 | 994 (962 单元 + 31 集成 + 1 文档) |
| Helper 函数 | 211/211 (100%) |

## 功能特性

### 核心验证
- **寄存器状态跟踪**: 完整的 11 寄存器状态，包含类型和边界跟踪
- **内存安全**: 验证所有内存访问（栈、map、数据包、上下文、arena、用户空间）
- **控制流分析**: 探索所有可能的执行路径，带分支计数
- **引用跟踪**: 确保获取的资源（锁、引用、RCU）被正确释放
- **边界分析**: 使用 Tnum（追踪数字）跟踪数值边界，支持完整算术
- **精度回溯**: 寄存器依赖分析，用于准确的状态比较

### 高级功能
- **状态剪枝**: 哈希索引的等价性检查，带 SCC 循环处理和 Widening 支持
- **211 个 Helper 函数**: 完整的 BPF helper 函数原型和验证
- **Kfunc 支持**: 带 BTF 类型检查的内核函数调用验证
- **BTF 集成**: 完整的 BTF 类型系统，支持递归类型遍历和 enum64
- **Dynptr 支持**: 动态指针生命周期跟踪
- **迭代器支持**: BPF 迭代器状态和收敛跟踪，含 Widening 操作符
- **异常处理**: bpf_throw 和异常回调支持
- **间接跳转**: gotol/BPF_JA|X 指令验证
- **Spectre 缓解**: 路径敏感的推测执行安全检查和 nospec barrier 支持
- **指针溢出检查**: JIT 补丁生成
- **优化 Pass 框架**: 模块化的 PassManager 优化管道

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
bpf-verifier = "0.1"
```

## 快速开始

```rust
use bpf_verifier::{
    verifier::{VerifierEnv, MainVerifier, mark_prune_points},
    core::types::*,
};

// 创建一个简单的 BPF 程序
let program = vec![
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // r0 = 0
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // exit
];

// 创建验证器环境
let mut env = VerifierEnv::new(program, BpfProgType::SocketFilter, true)?;
mark_prune_points(&mut env);

// 运行验证
let mut verifier = MainVerifier::new(&mut env);
verifier.verify()?;
println!("程序验证成功！");
```

## 模块结构

| 模块 | 描述 | 完成度 |
|------|------|--------|
| `core` | 核心类型（200+ BPF 常量）、指令定义、错误处理 | 95% |
| `state` | 寄存器/栈/验证器状态、引用跟踪、锁状态 | 90% |
| `bounds` | Tnum 算术、标量边界、范围细化 | 85% |
| `analysis` | CFG、SCC、精度跟踪、状态剪枝、活跃性 | 85% |
| `check` | ALU、跳转、helper、kfunc、原子指令验证 | 90% |
| `mem` | 栈、map、数据包、上下文、arena、用户内存访问验证 | 85% |
| `special` | Dynptr、迭代器、异常、map 操作 | 80% |
| `btf` | BTF 类型系统、类型遍历、CO-RE、kfunc 元数据 | 90% |
| `sanitize` | Spectre 缓解、指针溢出检查 | 90% |
| `opt` | 死代码消除、Pass 框架、JIT 优化、杂项修复 | 80% |
| `verifier` | 主验证循环、环境管理 | 80% |

## 与内核 verifier.c 的对应

本项目完整对应 Linux 内核 `kernel/bpf/verifier.c` 的 25,398 行代码，包括：

| 功能区域 | C 代码行号 | Rust 模块 | 状态 |
|----------|------------|-----------|------|
| 核心结构和常量 | L1-600 | `core/`, `state/` | ✅ 95% |
| Dynptr/Iter/IRQ | L620-1350 | `special/` | ✅ 80% |
| 状态管理 | L1378-2100 | `state/` | ✅ 90% |
| SCC 和回边 | L1800-2100 | `analysis/scc.rs` | ✅ 85% |
| 寄存器操作 | L2100-2900 | `state/reg_state.rs`, `bounds/` | ✅ 90% |
| 子程序处理 | L2970-3600 | `analysis/subprog.rs`, `check/subprog.rs` | ✅ 85% |
| 精度跟踪 | L3800-4950 | `analysis/precision.rs` | ✅ 85% |
| 栈操作 | L5000-5700 | `mem/stack_access.rs` | ✅ 80% |
| 内存访问检查 | L5654-7850 | `mem/` | ✅ 85% |
| 原子操作 | L7859-8050 | `check/atomic.rs` | ✅ 85% |
| 锁和特殊处理 | L8400-8950 | `state/lock_state.rs`, `special/` | ✅ 80% |
| Helper 调用 | L10450-12010 | `check/helper.rs`, `check/helper_db.rs` | ✅ 100% |
| Kfunc 支持 | L12033-14300 | `check/kfunc.rs`, `check/kfunc_args.rs` | ✅ 85% |
| 指针安全检查 | L14296-14700 | `sanitize/` | ✅ 90% |
| ALU 操作 | L14654-15985 | `check/alu.rs`, `bounds/insn_bounds.rs` | ✅ 85% |
| 条件跳转 | L15987-17100 | `check/jump.rs`, `bounds/range_refine.rs` | ✅ 90% |
| 主验证循环 | L20100-20700 | `verifier/main_loop.rs` | ✅ 80% |
| 优化和 Fixup | L21197-23700 | `opt/` | ⚠️ 60-80% |

## 剩余差距

### 关键差距 (P0)
1. **用户内存访问验证集成** (60%) - 验证逻辑未完全集成到主循环
2. **状态合并精度保持** (70%) - 合并点精度损失处理不完整
3. **Struct Ops 验证** (50%) - 仅有类型定义，无验证逻辑

### 高优先级 (P1)
4. **IRQ 状态跟踪** (50%) - 基础设施缺失
5. **竞态条件检测** (40%) - 基础设施已建立但逻辑不完整
6. **睡眠上下文验证** (70%) - 未连接到 helper/kfunc 验证

### 中等优先级 (P2)
7. **BTF CO-RE 重定位** (50%) - 处理器未实现
8. **上下文访问转换** (60%) - 仅 socket_filter 实现
9. **Misc Fixups** (60%) - 多项优化未实现

详细差距分析请参见 [PLAN.md](PLAN.md)。

## 示例

运行示例：

```bash
# 基础演示
cargo run --example demo

# 程序验证
cargo run --example verify_program
```

## 测试

```bash
# 运行所有测试
cargo test

# 使用 release 优化运行
cargo test --release

# 运行特定模块测试
cargo test --lib bounds::
cargo test --lib check::
```

## 构建

```bash
# Debug 构建
cargo build

# Release 构建
cargo build --release

# 无 std 构建（用于内核集成）
cargo build --no-default-features --features kernel
```

## 特性标志

| 特性 | 说明 |
|------|------|
| `default` | 标准库支持 |
| `std` | 启用 thiserror 错误处理 |
| `kernel` | 无 std 模式，用于内核模块集成 |
| `verbose` | 增强日志输出 |
| `stats` | 性能统计收集 |

## 架构文档

详细架构设计请参见 [ARCHITECTURE.md](ARCHITECTURE.md)，包含：
- 完整的模块依赖图
- 核心数据结构定义
- 与内核函数的对应关系
- 验证流程详解

## 许可证

双重许可，可选择以下任一：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 参考资料

- [Linux kernel BPF verifier](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
