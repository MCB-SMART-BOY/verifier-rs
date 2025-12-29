```
 ____  ____  _____  __     __        _  __ _           
| __ )|  _ \|  ___| \ \   / /__ _ __(_)/ _(_) ___ _ __ 
|  _ \| |_) | |_     \ \ / / _ \ '__| | |_| |/ _ \ '__|
| |_) |  __/|  _|     \ V /  __/ |  | |  _| |  __/ |   
|____/|_|   |_|        \_/ \___|_|  |_|_| |_|\___|_|   
```

<div align="center">

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![Rust Version](https://img.shields.io/badge/rust-1.82.0%2B-orange.svg)](https://www.rust-lang.org/)
[![no_std](https://img.shields.io/badge/no__std-yes-green.svg)]()

**🔒 Memory-Safe | 🌍 Platform-Agnostic | ⚡ Zero-Cost Abstractions**

[English](#-english) | [中文](#-中文)

</div>

---

#📘 English

## 👋 Hey there, fellow hacker!

Ever wondered what it takes to verify that a piece of eBPF code won't crash your kernel? Well, you're looking at it!

This is a **from-scratch Rust implementation** of the BPF verifier - the gatekeeper that decides whether your eBPF programs are safe enough to run in kernel space. No C code, no FFI nightmares, just pure Rust goodness with `#![no_std]` compatibility.

### 🤔 Why does this exist?

Because I was curious. And because Rust makes systems programming *fun* again.

The Linux kernel's BPF verifier is a ~30,000 line C beast. I thought: "What if I could have all that power, but with Rust's safety guarantees?" So here it is.

### ✨ What makes this special?

```
┌─────────────────────────────────────────────────────────────┐
│                  🎭 The Magic Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────┐         ┌─────────────────────────┐  │
│   │  Your Platform  │────────▶│   bpf-verifier-core    │  │
│   │   (Linux, Your  │ traits  │   (the brain 🧠)       │  │
│   │    own OS, etc) │         │                         │  │
│   └─────────────────┘         └─────────────────────────┘  │
│                                                             │
│   Want to run BPF on your own OS? Just implement the       │
│   PlatformSpec trait. That's it. No kidding.               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 📦 The Crates

| Crate | What it does | Vibe |
|-------|--------------|------|
| `bpf-verifier-core` | The platform-agnostic brain | 🧠 Pure logic |
| `bpf-verifier-linux` | Linux-specific stuff | 🐧 Penguin approved |
| `bpf-verifier` | Convenience re-exports | 🎁 Easy mode |

### 🚀 Quick Start

```bash
# Clone it
git clone https://github.com/anthropics/verifier-rs
cd verifier-rs

# Build it
cargo build --release

# Test it (I have tests, lots of them)
cargo test --workspace

# Feeling fancy? Check for lint
cargo clippy --workspace
```

### 💻 Show me the code!

**Using with Linux:**

```rust
use bpf_verifier_core::verifier::{GenericVerifierEnv, GenericMainVerifier};
use bpf_verifier_linux::LinuxSpec;

// Create the platform - Linux in this case
let platform = LinuxSpec::new();

// Your BPF program (the instructions you want to verify)
let insns = vec![/* your BPF instructions here */];

// Set up the verifier environment
let mut env = GenericVerifierEnv::new(
    platform,
    insns,
    6,      // program type (XDP in this case)
    false,  // allow_ptr_leaks (usually false unless you're privileged)
)?;

// Let's verify! 🎉
let mut verifier = GenericMainVerifier::new(&mut env);
verifier.verify()?;

println!("✅ Your program is safe!");
```

**Building your own platform:**

```rust
use bpf_verifier_core::platform::*;

// Your custom platform - maybe for your own OS?
#[derive(Clone)]
struct MyAwesomeOS {
    helper: MyHelperProvider,
    // ... other providers
}

impl PlatformSpec for MyAwesomeOS {
    type Helper = MyHelperProvider;
    type ProgType = MyProgTypeProvider;
    type Kfunc = MyKfuncProvider;
    type Map = MyMapProvider;
    type Context = MyContextProvider;

    fn name(&self) -> &'static str { "my-awesome-os" }
    // implement the rest...
}

// Now use it!
let platform = MyAwesomeOS::new();
let mut env = GenericVerifierEnv::new(platform, insns, prog_type, false)?;
```

### 🧩 Platform Traits

The secret sauce that makes this all work:

| Trait | What it's for | Example |
|-------|---------------|---------|
| `PlatformSpec` | The main combo trait | Ties everything together |
| `HelperProvider` | BPF helper functions | `bpf_map_lookup_elem`, etc. |
| `ProgTypeProvider` | Program types | XDP, kprobe, tracepoint... |
| `KfuncProvider` | Kernel functions | The new hotness |
| `MapProvider` | Map types | HashMap, Array, RingBuf... |
| `ContextProvider` | Context structures | What's in R1 when you start |

### 🔥 Features that'll make you smile

- **Register tracking**: All 11 registers, with types and bounds. I know *exactly* what's in each one.
- **Memory safety**: Stack, maps, packets, context - I check 'em all.
- **Control flow**: Every path explored. No shortcuts.
- **Reference tracking**: Acquired a lock? I'll make sure you release it.
- **State pruning**: Smart equivalence checking so I don't explore the same state twice.

### 📁 Project Layout

```
verifier-rs/
├── crates/
│   ├── bpf-verifier-core/    # 🧠 The brain
│   ├── bpf-verifier-linux/   # 🐧 Linux specifics  
│   └── bpf-verifier/         # 🎁 Easy imports
├── docs/
│   ├── CHANGELOG.md          # 📝 What's new
│   ├── PERFORMANCE.md        # ⚡ Speed stuff
│   └── UNSAFE_AUDIT.md       # 🔒 Safety report
└── README.md                 # 👈 You are here
```

### 📚 Docs

| Doc | What's inside |
|-----|---------------|
| [CHANGELOG](docs/CHANGELOG.md) | The journey so far |
| [PERFORMANCE](docs/PERFORMANCE.md) | Numbers that go brrr |
| [UNSAFE_AUDIT](docs/UNSAFE_AUDIT.md) | My unsafe code confessions |

### 📋 Requirements

- **Rust 1.82.0+** (I use some nice features)
- **`#![no_std]` compatible** (no OS needed!)
- **`alloc` crate** (I do need some heap though)

### 📜 License

**GPL-2.0-only** - Because I believe in freedom.

### 🤝 Contributing

Found a bug? Have an idea? PRs and issues are welcome!

This project was born from curiosity and a love for Rust. Every contribution, no matter how small, makes it better.

---

**Built with 💜 and lots of ☕ by MCB-SMART-BOY**

*A sophomore student who just really likes BPF and Rust.*

---

# 📗 中文

## 👋 嘿，折腾代码的朋友！

有没有想过，怎样才能验证一段 eBPF 代码不会把内核搞崩？你现在看到的就是答案！

这是一个**从零开始用 Rust 写的** BPF 验证器——它负责决定你的 eBPF 程序是不是足够安全、能不能在内核里跑。没有 C 代码，没有 FFI 那些破事儿，就是纯纯的 Rust，而且还支持 `#![no_std]`。

### 🤔 为啥要搞这个？

因为好奇呗。而且 Rust 让系统编程重新变得*有意思*了。

Linux 内核的 BPF 验证器是个大约 30,000 行的 C 代码怪兽。我当时想："要是能把这些能力都拿过来，还能享受 Rust 的安全保证呢？" 于是就有了这玩意儿。

### ✨ 有啥特别的？

```
┌─────────────────────────────────────────────────────────────┐
│                  🎭 架构的魔法                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────┐         ┌─────────────────────────┐  │
│   │   你的平台       │────────▶│   bpf-verifier-core    │  │
│   │  (Linux, 你自己  │ traits  │   (大脑 🧠)            │  │
│   │   的OS, 随便啥)  │         │                         │  │
│   └─────────────────┘         └─────────────────────────┘  │
│                                                             │
│   想在自己的操作系统上跑 BPF？实现一下 PlatformSpec        │
│   trait 就行。就这么简单，没骗你。                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 📦 这几个 Crate

| Crate | 干啥的 | 感觉 |
|-------|-------|------|
| `bpf-verifier-core` | 平台无关的大脑 | 🧠 纯逻辑 |
| `bpf-verifier-linux` | Linux 专属的东西 | 🐧 企鹅认证 |
| `bpf-verifier` | 方便导入的重导出 | 🎁 简单模式 |

### 🚀 快速上手

```bash
# 克隆下来
git clone https://github.com/anthropics/verifier-rs
cd verifier-rs

# 编译
cargo build --release

# 跑测试（我写了一堆测试）
cargo test --workspace

# 想更专业点？跑个 lint
cargo clippy --workspace
```

### 💻 上代码！

**用 Linux 平台：**

```rust
use bpf_verifier_core::verifier::{GenericVerifierEnv, GenericMainVerifier};
use bpf_verifier_linux::LinuxSpec;

// 创建平台 - 这里用 Linux
let platform = LinuxSpec::new();

// 你的 BPF 程序（要验证的指令）
let insns = vec![/* 你的 BPF 指令 */];

// 设置验证器环境
let mut env = GenericVerifierEnv::new(
    platform,
    insns,
    6,      // 程序类型（这里是 XDP）
    false,  // allow_ptr_leaks（除非你是特权用户，不然一般是 false）
)?;

// 开始验证！🎉
let mut verifier = GenericMainVerifier::new(&mut env);
verifier.verify()?;

println!("✅ 你的程序是安全的！");
```

**搞个自己的平台：**

```rust
use bpf_verifier_core::platform::*;

// 你的自定义平台 - 也许是给你自己的操作系统？
#[derive(Clone)]
struct MyAwesomeOS {
    helper: MyHelperProvider,
    // ... 其他 provider
}

impl PlatformSpec for MyAwesomeOS {
    type Helper = MyHelperProvider;
    type ProgType = MyProgTypeProvider;
    type Kfunc = MyKfuncProvider;
    type Map = MyMapProvider;
    type Context = MyContextProvider;

    fn name(&self) -> &'static str { "my-awesome-os" }
    // 实现剩下的...
}

// 用起来！
let platform = MyAwesomeOS::new();
let mut env = GenericVerifierEnv::new(platform, insns, prog_type, false)?;
```

### 🧩 平台 Trait

让这一切运转的秘密武器：

| Trait | 干啥用的 | 举个例子 |
|-------|---------|---------|
| `PlatformSpec` | 主 trait，把所有东西串起来 | 组合器 |
| `HelperProvider` | BPF helper 函数 | `bpf_map_lookup_elem` 之类的 |
| `ProgTypeProvider` | 程序类型 | XDP, kprobe, tracepoint... |
| `KfuncProvider` | 内核函数 | 新玩意儿 |
| `MapProvider` | Map 类型 | HashMap, Array, RingBuf... |
| `ContextProvider` | 上下文结构 | 启动时 R1 里装的啥 |

### 🔥 这些功能你肯定喜欢

- **寄存器追踪**：全部 11 个寄存器，带类型和边界。我*精确*知道每个里面是啥。
- **内存安全**：栈、map、数据包、上下文——全都检查。
- **控制流**：每条路径都走一遍。不偷懒。
- **引用追踪**：拿了锁？我会确保你释放。
- **状态剪枝**：智能的等价性检查，同样的状态不会走两遍。

### 📁 项目结构

```
verifier-rs/
├── crates/
│   ├── bpf-verifier-core/    # 🧠 大脑
│   ├── bpf-verifier-linux/   # 🐧 Linux 相关
│   └── bpf-verifier/         # 🎁 方便导入
├── docs/
│   ├── CHANGELOG.md          # 📝 更新日志
│   ├── PERFORMANCE.md        # ⚡ 性能数据
│   └── UNSAFE_AUDIT.md       # 🔒 安全报告
└── README.md                 # 👈 你在这儿
```

### 📚 文档

| 文档 | 里面有啥 |
|-----|---------|
| [CHANGELOG](docs/CHANGELOG.md) | 一路走来的历程 |
| [PERFORMANCE](docs/PERFORMANCE.md) | 跑分数据 |
| [UNSAFE_AUDIT](docs/UNSAFE_AUDIT.md) | unsafe 代码的交代 |

### 📋 依赖要求

- **Rust 1.82.0+**（用了一些新特性）
- **`#![no_std]` 兼容**（不需要操作系统！）
- **`alloc` crate**（但确实需要点堆内存）

### 📜 许可证

**GPL-2.0-only** - 因为我信自由。

### 🤝 贡献

发现 bug 了？有想法？欢迎提 PR 和 issue！

这个项目源于好奇心和对 Rust 的热爱。每一份贡献，不管多小，都能让它变得更好。

---

**用 💜 和一堆 ☕ 打造，作者 MCB-SMART-BOY**

*一个就是很喜欢 BPF 和 Rust 的大二学生。*
