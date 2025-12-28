# Rust BPF Verifier

[English](#english) | [中文](#中文)

---

## English

A Rust implementation of the Linux kernel BPF verifier (`kernel/bpf/verifier.c`), designed for Rust for Linux (**Linux 6.18+ compatible**).

### Overview

This crate provides static code analysis for eBPF programs, ensuring they are safe before being loaded into the kernel. It is a `#![no_std]` library that can be integrated into the Linux kernel as a Rust-based BPF verifier.

**Status**: **RFC submitted** to rust-for-linux@vger.kernel.org | **94% feature parity** with Linux 6.18

### Features

#### Core Verification
- **Register State Tracking**: Complete 11-register state with type and bounds tracking
- **Memory Safety**: Validates all memory accesses (stack, map, packet, context, arena)
- **Control Flow Analysis**: Explores all possible execution paths
- **Reference Tracking**: Ensures acquired resources (locks, refs, RCU) are properly released
- **Bounds Analysis**: Uses Tnum (tracked numbers) for precise numeric bounds

#### Advanced Features
- **State Pruning**: Hash-indexed equivalence checking for performance
- **211 Helper Functions**: Complete BPF helper function validation
- **85+ Kfuncs**: Kernel function call verification (synced with kernel 6.18)
- **BTF Integration**: Full BTF type system support
- **Spectre Mitigation**: Speculative execution safety checks
- **IRQ Flag Tracking**: Interrupt state verification

#### Linux 6.13-6.18 Features 🆕
- **Load-Acquire/Store-Release**: Atomic memory barrier instructions
- **may_goto Loops**: Bounded loop support with guaranteed termination
- **Linked Registers**: Enhanced precision tracking for register relationships
- **Private Stack**: Isolated stack per subprogram for better security
- **Fastcall Optimization**: Reduced overhead for frequently-used helpers
- **BPF Features Flags**: Runtime feature toggle system
- **Extended Dynptr**: SKB metadata and file-backed dynamic pointers

### Project Structure

```
src/
├── core/       - Core types, instruction definitions, error handling
├── state/      - Register/stack/verifier state
├── bounds/     - Tnum arithmetic, scalar bounds
├── analysis/   - CFG, SCC, precision tracking, state pruning
├── check/      - ALU, jump, helper, kfunc verification
├── mem/        - Memory access verification
├── special/    - Dynptr, iterator, exception handling
├── btf/        - BTF type system
├── sanitize/   - Spectre mitigation
├── opt/        - Optimization passes
└── verifier/   - Main verification loop

kernel-integration/
├── rust_bpf_verifier.rs  - Pure Rust kernel module (Linux 6.12+ style)
├── Kconfig               - Kernel configuration options
└── Makefile              - Build configuration

patches/                  - Kernel integration patches
scripts/                  - Helper scripts for development
benches/                  - Criterion benchmarks
```

### Build

```bash
# Build the library
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Benchmark Results

Preliminary benchmark results on typical hardware:

| Benchmark | Time |
|-----------|------|
| simple_verification | ~14.6 µs |
| medium_verification | ~28.7 µs |
| complex_verification | ~736 µs |
| state_creation | ~406 ns |
| bounds_operations | ~5.8 ns |

### Kernel Integration (Linux 6.12+)

This library is designed for integration with Rust for Linux. The implementation uses pure Rust with no C glue code, following the modern kernel::Module pattern:

```rust
use kernel::prelude::*;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    license: "GPL",
}

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        Ok(Self { })
    }
}
```

#### Configuration

```
CONFIG_BPF_VERIFIER_RUST=y
echo 1 > /proc/sys/kernel/bpf_rust_verifier
```

### Requirements

- Rust (stable)
- `#![no_std]` environment
- `alloc` crate (for Vec, Box, etc.)
- `bitflags` crate

### License

GPL-2.0-only (Linux kernel compatible)

See [LICENSE](LICENSE) for details.

### Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### References

- [Rust for Linux](https://rust-for-linux.com/)
- [Rust for Linux Documentation](https://docs.kernel.org/rust/)
- [Kernel Crate API](https://rust-for-linux.github.io/docs/kernel/)
- [Linux kernel BPF verifier](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)

### Author

MCB-SMART-BOY - A sophomore student passionate about BPF and Rust.

This project was created out of curiosity and a desire to learn. Feedback and suggestions are always appreciated.

---

## 中文

Linux 内核 BPF 验证器 (`kernel/bpf/verifier.c`) 的 Rust 实现，专为 Rust for Linux (**Linux 6.18+ 兼容**) 设计。

### 概述

本 crate 提供 eBPF 程序的静态代码分析，确保程序在加载到内核之前是安全的。这是一个 `#![no_std]` 库，可以集成到 Linux 内核中作为 BPF 验证器的 Rust 实现。

**状态**：**RFC 已提交** 至 rust-for-linux@vger.kernel.org | **94% 功能对等** Linux 6.18

### 功能特性

#### 核心验证
- **寄存器状态跟踪**：完整的 11 寄存器状态，包含类型和边界跟踪
- **内存安全**：验证所有内存访问（栈、map、数据包、上下文、arena）
- **控制流分析**：探索所有可能的执行路径
- **引用跟踪**：确保获取的资源（锁、引用、RCU）被正确释放
- **边界分析**：使用 Tnum（追踪数字）跟踪数值边界

#### 高级功能
- **状态剪枝**：哈希索引的等价性检查，提升性能
- **211 个 Helper 函数**：完整的 BPF helper 函数验证
- **85+ Kfunc**：内核函数调用验证（同步至 kernel 6.18）
- **BTF 集成**：完整的 BTF 类型系统支持
- **Spectre 缓解**：推测执行安全检查
- **IRQ 标志跟踪**：中断状态验证

#### Linux 6.13-6.18 新特性 🆕
- **Load-Acquire/Store-Release**：原子内存屏障指令
- **may_goto 循环**：有界循环支持，保证终止
- **链接寄存器**：增强的寄存器关系精度追踪
- **私有栈**：子程序独立栈隔离，提升安全性
- **Fastcall 优化**：高频 helper 调用开销降低
- **BPF 特性标志**：运行时特性开关系统
- **扩展 Dynptr**：支持 SKB 元数据和文件动态指针

### 项目结构

```
src/
├── core/       - 核心类型、指令定义、错误处理
├── state/      - 寄存器/栈/验证器状态
├── bounds/     - Tnum 算术、标量边界
├── analysis/   - CFG、SCC、精度跟踪、状态剪枝
├── check/      - ALU、跳转、helper、kfunc 验证
├── mem/        - 内存访问验证
├── special/    - Dynptr、迭代器、异常处理
├── btf/        - BTF 类型系统
├── sanitize/   - Spectre 缓解
├── opt/        - 优化 Pass
└── verifier/   - 主验证循环

kernel-integration/
├── rust_bpf_verifier.rs  - 纯 Rust 内核模块（Linux 6.12+ 风格）
├── Kconfig               - 内核配置选项
└── Makefile              - 构建配置

patches/                  - 内核集成补丁
scripts/                  - 开发辅助脚本
benches/                  - Criterion 基准测试
```

### 构建

```bash
# 构建库
cargo build --release

# 运行测试
cargo test

# 运行基准测试
cargo bench
```

### 基准测试结果

典型硬件上的初步基准测试结果：

| 基准测试 | 时间 |
|---------|------|
| simple_verification | ~14.6 µs |
| medium_verification | ~28.7 µs |
| complex_verification | ~736 µs |
| state_creation | ~406 ns |
| bounds_operations | ~5.8 ns |

### 内核集成（Linux 6.12+）

本库设计用于与 Rust for Linux 集成。实现采用纯 Rust，无需 C 胶水代码，遵循现代 kernel::Module 模式：

```rust
use kernel::prelude::*;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    license: "GPL",
}

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        Ok(Self { })
    }
}
```

#### 配置

```
CONFIG_BPF_VERIFIER_RUST=y
echo 1 > /proc/sys/kernel/bpf_rust_verifier
```

### 依赖要求

- Rust（stable）
- `#![no_std]` 环境
- `alloc` crate（用于 Vec、Box 等）
- `bitflags` crate

### 许可证

GPL-2.0-only（与 Linux 内核兼容）

详见 [LICENSE](LICENSE)。

### 贡献

欢迎贡献！请随时提交 Issue 和 Pull Request。

### 参考资料

- [Rust for Linux](https://rust-for-linux.com/)
- [Rust for Linux 文档](https://docs.kernel.org/rust/)
- [Kernel Crate API](https://rust-for-linux.github.io/docs/kernel/)
- [Linux 内核 BPF 验证器](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)

### 作者

MCB-SMART-BOY - 一名对 BPF 和 Rust 充满热情的大二学生。

本项目出于好奇心和学习热情而创建。欢迎任何反馈和建议。
