# 将 Rust BPF 验证器集成到 Linux 内核

## 当前状态

- ✅ 内核模块可加载
- ✅ 基本 IOCTL 接口工作
- ❌ 完整验证在内核中崩溃（栈溢出）
- ❌ 未与内核 BPF 子系统集成

## 集成方案

### 方案 A：修改内核源码（推荐）

需要修改以下内核文件：

```
kernel/bpf/syscall.c     # 修改 bpf_prog_load() 调用 Rust 验证器
kernel/bpf/Makefile      # 添加 Rust 库链接
include/linux/bpf_verifier_rs.h  # 添加头文件
```

#### 步骤 1：修改 kernel/bpf/syscall.c

```c
// 在文件顶部添加
#include <linux/bpf_verifier_rs.h>

// 找到 bpf_prog_load() 函数中的 bpf_check() 调用
// 大约在第 2800 行左右

// 原代码：
// err = bpf_check(&prog, attr, uattr, uattr_size);

// 改为：
#ifdef CONFIG_BPF_VERIFIER_RUST
    err = bpf_check_rs_kernel(prog, attr);
#else
    err = bpf_check(&prog, attr, uattr, uattr_size);
#endif
```

#### 步骤 2：创建内核适配函数

需要新增一个函数，将内核的 `struct bpf_prog` 转换为我们的格式：

```c
// kernel/bpf/verifier_rs_adapter.c
int bpf_check_rs_kernel(struct bpf_prog *prog, union bpf_attr *attr)
{
    struct bpf_insn_rs *insns;
    int ret, i;
    
    // 转换指令格式
    insns = kvmalloc_array(prog->len, sizeof(*insns), GFP_KERNEL);
    if (!insns)
        return -ENOMEM;
    
    for (i = 0; i < prog->len; i++) {
        insns[i].code = prog->insnsi[i].code;
        insns[i].dst_reg = BPF_REG(prog->insnsi[i].dst_reg);
        insns[i].src_reg = BPF_REG(prog->insnsi[i].src_reg);
        insns[i].off = prog->insnsi[i].off;
        insns[i].imm = prog->insnsi[i].imm;
    }
    
    // 调用 Rust 验证器
    bpf_verifier_env_handle_t env = bpf_verifier_env_new(
        insns,
        prog->len,
        prog->type,
        capable(CAP_BPF)
    );
    
    if (!env) {
        kvfree(insns);
        return -ENOMEM;
    }
    
    ret = bpf_verify(env);
    
    bpf_verifier_env_free(env);
    kvfree(insns);
    
    return ret;
}
```

#### 步骤 3：添加 Kconfig 选项

在 `kernel/bpf/Kconfig` 添加：

```
config BPF_VERIFIER_RUST
    bool "Use Rust BPF verifier"
    depends on RUST
    help
      Use the Rust implementation of the BPF verifier instead
      of the C implementation. This is experimental.
```

### 方案 B：使用 Livepatch（不修改内核源码）

利用内核的 livepatch 机制动态替换函数：

```c
#include <linux/livepatch.h>

static int livepatch_bpf_check(struct bpf_verifier_env *env)
{
    // 调用 Rust 验证器
    return bpf_verify_rs(...);
}

static struct klp_func funcs[] = {
    {
        .old_name = "bpf_check",
        .new_func = livepatch_bpf_check,
    }, { }
};
```

**问题：** `bpf_check` 是 static 函数，不能直接 patch。

### 方案 C：修改 BTF/kallsyms 劫持

使用 kprobe + jmp 替换：

```c
// 不推荐，太 hacky
```

## 当前阻塞问题

### 1. 完整验证栈溢出

`MainVerifier::verify()` 调用链太深，需要：
- 将所有大结构体改为堆分配
- 将递归改为迭代（部分已完成）

### 2. 内核数据结构适配

需要处理：
- `struct bpf_prog` → `struct bpf_insn_rs`
- `struct bpf_verifier_env` 的内核内部字段
- BTF 信息传递
- Map 信息传递

## 建议的下一步

1. **先完成完整验证**：修复栈问题，让 `verify_full()` 在内核中工作
2. **创建适配层**：将内核数据结构转换为我们的格式
3. **选择集成方式**：修改内核源码是最干净的方案
4. **在 VM 中测试**：使用自定义内核启动 Alpine VM
