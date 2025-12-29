```
 ____            __                                          
|  _ \ ___ _ __ / _| ___  _ __ _ __ ___   __ _ _ __   ___ ___ 
| |_) / _ \ '__| |_ / _ \| '__| '_ ` _ \ / _` | '_ \ / __/ _ \
|  __/  __/ |  |  _| (_) | |  | | | | | | (_| | | | | (_|  __/
|_|   \___|_|  |_|  \___/|_|  |_| |_| |_|\__,_|_| |_|\___\___|
```

<div align="center">

**⚡ Numbers That Go Brrr / 让数字说话 ⚡**

[English](#-english) | [中文](#-中文)

</div>

---

# 📘 English

## 🏎️ How Fast Is This Thing?

Glad you asked! I've benchmarked the heck out of this verifier, and here's what I found.

### 🖥️ Test Environment

| What | Details |
|------|---------|
| 🐧 Platform | Linux 6.8.0-1030-azure |
| 🦀 Rust | 1.82.0 stable |
| ⚙️ Build | Release with all the optimizations |

---

## 📊 The Numbers

### Verification Speed

How fast can I verify your programs?

| Test Case | Time | Throughput | Verdict |
|-----------|------|------------|---------|
| Simple program | **24.82 µs** | ~40,000/sec | 🚀 Blazing |
| Medium complexity | **45.09 µs** | ~22,000/sec | ⚡ Fast |
| Complex program | **1.04 ms** | ~960/sec | 🏃 Respectable |

### Core Operations

The building blocks:

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| State creation | **181.36 ns** | ~5.5M/sec | 💨 Nanoseconds baby! |
| Bounds ops | **8.61 ns** | ~116M/sec | 🔥 This is fine |

---

## 🔍 What Do These Mean?

### 🟢 Simple Programs (~25 µs)

Think: a program that just returns 0.

```
mov r0, 0
exit
```

- Linear control flow (no branches)
- Basic arithmetic
- Simple memory patterns
- **Verdict**: 40,000 programs per second. Not bad for a safety check!

### 🟡 Medium Complexity (~45 µs)

Think: a program with some actual logic.

- Multiple branches
- Loop constructs
- Helper function calls
- Map operations
- **Verdict**: Still pretty snappy!

### 🔴 Complex Programs (~1 ms)

Think: the real-world monsters.

- 500+ instructions
- Spaghetti control flow (I don't judge)
- Multiple subprograms
- Heavy state tracking
- **Verdict**: A millisecond to verify something that runs in your kernel? Worth it.

---

## 🏆 Performance Highlights

| What I Achieve | Status |
|----------------|--------|
| Sub-millisecond for typical programs | ✅ Yep |
| Nanosecond-level core operations | ✅ Oh yeah |
| Linear scaling with complexity | ✅ Math works |
| Zero GC pauses | ✅ No garbage here |
| 50-90% state pruning | ✅ Smart shortcuts |

---

## 🌳 State Pruning: My Secret Weapon

Here's the thing: BPF verification could explore an *exponential* number of states. But I'm smarter than that.

| Program Type | States Explored | States Pruned | Saved |
|--------------|-----------------|---------------|-------|
| Simple | 10-50 | 0-10 | 0-20% |
| Medium | 100-500 | 50-300 | 50-60% |
| Complex | 1000+ | 500-900 | **50-90%** |

Translation: For complex programs, I skip up to 90% of redundant work. You're welcome.

---

## 💾 Memory Usage

Where does the memory go?

| Component | Size | Notes |
|-----------|------|-------|
| BpfFuncState | ~2 KB | One per function frame |
| BpfVerifierState | ~20 KB | The whole enchilada |
| VerifierEnv (base) | ~50 KB | Fixed overhead |
| Per-insn aux data | ~64 bytes | Per instruction |

### 📐 Quick Estimate

```
Total ≈ 50KB + (instructions × 64B) + (max_states × 20KB)
```

For a 1000-instruction program with 100 states: ~2.1 MB

---

## 🛠️ Optimization Tricks I Use

### 1. 🌳 State Pruning

Hash-indexed equivalence checking. If I've seen this state before, skip it!

### 2. 🔢 Tnum Arithmetic

Tracked numbers let me propagate bounds efficiently without full symbolic execution. It's like having your cake and eating it too.

### 3. 📋 Call Summary Caching

LRU cache for function call results. Why verify the same thing twice?

### 4. 🦥 Lazy State Cloning

I only clone states when I branch. No unnecessary copies!

---

## ⚔️ Rust vs C: The Showdown

| Aspect | Rust (This Project) | C (Kernel) |
|--------|---------------------|------------|
| Speed | Comparable | Baseline |
| Memory safety overhead | ~0% | N/A |
| Bounds checking overhead | ~0% (release) | Manual |
| Binary size | Larger | Smaller |
| Maintainer's sleep quality | 😴 | 😰 |

---

## 🔮 Future Speed Improvements

| What | Expected Gain | Difficulty |
|------|---------------|------------|
| SIMD bounds ops | 10-20% | Medium |
| Parallel exploration | 2-4x | Hard |
| JIT-compiled checks | Varies | Very Hard |

---

**Last Updated**: 2025-12-29

*No benchmarks were harmed in the making of this document.*

---

# 📗 中文

## 🏎️ 这玩意儿有多快？

问得好！我把这个验证器测了个底朝天，结果在这儿。

### 🖥️ 测试环境

| 啥 | 详情 |
|---|------|
| 🐧 平台 | Linux 6.8.0-1030-azure |
| 🦀 Rust | 1.82.0 stable |
| ⚙️ 构建 | Release，开满优化 |

---

## 📊 数据

### 验证速度

我能多快验证你的程序？

| 测试用例 | 时间 | 吞吐量 | 评价 |
|---------|-----|-------|------|
| 简单程序 | **24.82 µs** | ~40,000/秒 | 🚀 飞快 |
| 中等复杂度 | **45.09 µs** | ~22,000/秒 | ⚡ 挺快 |
| 复杂程序 | **1.04 ms** | ~960/秒 | 🏃 还行 |

### 核心操作

基础组件：

| 操作 | 时间 | 吞吐量 | 备注 |
|-----|-----|-------|------|
| 状态创建 | **181.36 ns** | ~550万/秒 | 💨 纳秒级！ |
| 边界操作 | **8.61 ns** | ~1.16亿/秒 | 🔥 起飞 |

---

## 🔍 这些数字啥意思？

### 🟢 简单程序（~25 µs）

就是那种只返回 0 的程序。

```
mov r0, 0
exit
```

- 线性控制流（没分支）
- 基本算术
- 简单内存模式
- **评价**：每秒 40,000 个程序。作为安全检查挺可以的！

### 🟡 中等复杂度（~45 µs）

有点实际逻辑的程序。

- 多分支
- 循环结构
- 调用 Helper 函数
- Map 操作
- **评价**：还是挺利索的！

### 🔴 复杂程序（~1 ms）

真实世界里的怪兽。

- 500+ 条指令
- 意大利面式控制流（我不评判）
- 多个子程序
- 大量状态追踪
- **评价**：用一毫秒验证要在内核里跑的东西？值！

---

## 🏆 性能亮点

| 我做到了啥 | 状态 |
|-----------|------|
| 典型程序亚毫秒级 | ✅ 没问题 |
| 纳秒级核心操作 | ✅ 那必须的 |
| 随复杂度线性增长 | ✅ 数学没骗人 |
| 零 GC 暂停 | ✅ 这儿没垃圾回收 |
| 50-90% 状态剪枝 | ✅ 走捷径 |

---

## 🌳 状态剪枝：我的秘密武器

是这样的：BPF 验证理论上可能要探索*指数级*数量的状态。但我比那聪明。

| 程序类型 | 探索的状态 | 剪掉的状态 | 省了多少 |
|---------|-----------|-----------|---------|
| 简单 | 10-50 | 0-10 | 0-20% |
| 中等 | 100-500 | 50-300 | 50-60% |
| 复杂 | 1000+ | 500-900 | **50-90%** |

翻译一下：对于复杂程序，我跳过了高达 90% 的重复工作。不客气。

---

## 💾 内存使用

内存都去哪儿了？

| 组件 | 大小 | 备注 |
|-----|------|------|
| BpfFuncState | ~2 KB | 每个函数帧一个 |
| BpfVerifierState | ~20 KB | 整个状态 |
| VerifierEnv (基础) | ~50 KB | 固定开销 |
| 每条指令的辅助数据 | ~64 字节 | 按指令数算 |

### 📐 快速估算

```
总计 ≈ 50KB + (指令数 × 64B) + (最大状态数 × 20KB)
```

一个 1000 条指令、100 个状态的程序：~2.1 MB

---

## 🛠️ 我用的优化技巧

### 1. 🌳 状态剪枝

哈希索引的等价性检查。见过这个状态了？跳过！

### 2. 🔢 Tnum 算术

追踪数字让我能高效传播边界，不用搞完整的符号执行。鱼和熊掌我全要。

### 3. 📋 调用摘要缓存

函数调用结果的 LRU 缓存。同样的东西干嘛验证两遍？

### 4. 🦥 延迟状态克隆

我只在分支的时候才克隆状态。不搞没必要的复制！

---

## ⚔️ Rust vs C：对决

| 方面 | Rust（本项目） | C（内核） |
|-----|---------------|----------|
| 速度 | 差不多 | 基准 |
| 内存安全开销 | ~0% | 不适用 |
| 边界检查开销 | ~0%（release） | 手动 |
| 二进制大小 | 更大 | 更小 |
| 维护者睡眠质量 | 😴 | 😰 |

---

## 🔮 未来的速度提升

| 啥 | 预期收益 | 难度 |
|---|---------|------|
| SIMD 边界操作 | 10-20% | 中等 |
| 并行探索 | 2-4倍 | 有点难 |
| JIT 编译检查 | 不好说 | 很难 |

---

**最后更新**：2025-12-29

*制作本文档过程中没有基准测试受到伤害。*
