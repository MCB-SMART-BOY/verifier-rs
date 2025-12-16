# BPF Verifier for Rust for Linux

Linux 内核 BPF 验证器 (`kernel/bpf/verifier.c`) 的 Rust 实现，专为 Rust for Linux 设计。

## 概述

本 crate 提供 eBPF 程序的静态代码分析，确保程序在加载到内核之前是安全的。
这是一个 `no_std` 库，可以集成到 Linux 内核中作为 BPF 验证器的 Rust 实现。

## 功能特性

### 核心验证
- **寄存器状态跟踪**: 完整的 11 寄存器状态，包含类型和边界跟踪
- **内存安全**: 验证所有内存访问（栈、map、数据包、上下文、arena）
- **控制流分析**: 探索所有可能的执行路径
- **引用跟踪**: 确保获取的资源（锁、引用、RCU）被正确释放
- **边界分析**: 使用 Tnum（追踪数字）跟踪数值边界

### 高级功能
- **状态剪枝**: 哈希索引的等价性检查
- **211 个 Helper 函数**: 完整的 BPF helper 函数验证
- **Kfunc 支持**: 内核函数调用验证
- **BTF 集成**: 完整的 BTF 类型系统
- **Spectre 缓解**: 推测执行安全检查

## 模块结构

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
```

## Rust for Linux 集成

本库设计为与 Rust for Linux 内核集成。要在内核中使用：

1. 将此 crate 放入内核源码树的 `rust/` 目录
2. 在 `kernel/bpf/` 中添加 Rust 绑定
3. 通过 Kconfig 选项启用 Rust BPF 验证器

### 依赖

- `no_std` 环境
- `alloc` crate（用于 Vec、Box 等）
- `bitflags` crate

## 许可证

GPL-2.0-only（与 Linux 内核兼容）

## 参考资料

- [Rust for Linux](https://rust-for-linux.com/)
- [Linux kernel BPF verifier](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)
- [Kernel Rust Documentation](https://docs.kernel.org/rust/)
