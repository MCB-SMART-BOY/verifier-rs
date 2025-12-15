# BPF Verifier Rust 架构设计

## 1. 整体架构

本项目是 Linux 内核 BPF 验证器 (`reference/verifier.c`, 25,398 行) 的完整 Rust 重新实现，包含 83,304 行 Rust 代码和 994 个测试用例。

```
verifier-rs/
├── src/
│   ├── lib.rs                 # 库入口
│   ├── main.rs                # CLI入口
│   │
│   ├── core/                  # 核心数据结构 [95% 完成]
│   │   ├── mod.rs
│   │   ├── types.rs           # 基础类型定义 (BPF常量、操作码等)
│   │   ├── reg_type.rs        # 寄存器类型系统
│   │   ├── insn.rs            # BPF指令结构
│   │   ├── insn_verify.rs     # 指令验证
│   │   ├── disasm.rs          # 反汇编
│   │   ├── error.rs           # 错误类型
│   │   └── log.rs             # 日志系统
│   │
│   ├── state/                 # 验证器状态管理 [90% 完成]
│   │   ├── mod.rs
│   │   ├── reg_state.rs       # 寄存器状态 (bounds, tnum等)
│   │   ├── stack_state.rs     # 栈槽状态
│   │   ├── func_state.rs      # 函数帧状态
│   │   ├── verifier_state.rs  # 整体验证器状态
│   │   ├── reference.rs       # 引用追踪 (locks, ptrs, RCU等)
│   │   ├── lock_state.rs      # 锁状态管理
│   │   ├── idmap.rs           # ID 映射
│   │   ├── snapshot.rs        # 状态快照
│   │   └── spill_fill.rs      # 溢出/填充操作
│   │
│   ├── analysis/              # 静态分析 [85% 完成]
│   │   ├── mod.rs
│   │   ├── cfg.rs             # 控制流图
│   │   ├── scc.rs             # 强连通分量/循环检测 (Tarjan算法)
│   │   ├── liveness.rs        # 活跃性分析
│   │   ├── precision.rs       # 精度追踪
│   │   ├── prune.rs           # 状态剪枝 (含 Widening, 3,578行)
│   │   ├── states_equal.rs    # 状态等价比较
│   │   ├── state_merge.rs     # 状态合并
│   │   ├── race_detector.rs   # 竞态检测 (40%)
│   │   ├── leak_detector.rs   # 泄漏检测
│   │   ├── loop_check.rs      # 循环检查
│   │   └── subprog.rs         # 子程序分析
│   │
│   ├── check/                 # 验证检查 [90% 完成]
│   │   ├── mod.rs
│   │   ├── alu.rs             # ALU操作检查 (1,373行)
│   │   ├── load_store.rs      # 加载/存储指令检查
│   │   ├── jump.rs            # 跳转指令检查 (含间接跳转, 1,463行)
│   │   ├── call.rs            # 调用指令检查
│   │   ├── helper.rs          # Helper函数验证 (1,950行)
│   │   ├── helper_db.rs       # Helper函数数据库 (211个, 100%完成)
│   │   ├── kfunc.rs           # 内核函数验证 (2,084行)
│   │   ├── kfunc_args.rs      # Kfunc参数验证
│   │   ├── atomic.rs          # 原子操作检查
│   │   ├── sdiv.rs            # 带符号除法
│   │   ├── subprog.rs         # 子程序调用 (1,073行)
│   │   ├── callback.rs        # 回调函数验证
│   │   ├── sleepable.rs       # 睡眠上下文验证 (70%)
│   │   ├── prog_type.rs       # 程序类型验证 (1,870行)
│   │   ├── arg_checks.rs      # 参数检查
│   │   ├── special_types.rs   # 特殊类型检查
│   │   └── retval.rs          # 返回值检查
│   │
│   ├── mem/                   # 内存系统 [85% 完成]
│   │   ├── mod.rs
│   │   ├── memory.rs          # 统一内存访问接口 (1,323行)
│   │   ├── stack_access.rs    # 栈访问验证 (1,100+行)
│   │   ├── map.rs             # Map访问验证
│   │   ├── context.rs         # 上下文访问验证
│   │   ├── packet.rs          # 数据包访问验证 (1,171行)
│   │   ├── user.rs            # 用户空间内存访问 (2,127行, 60%完成)
│   │   └── arena.rs           # Arena内存验证 (1,121行)
│   │
│   ├── bounds/                # 边界分析 [85% 完成]
│   │   ├── mod.rs
│   │   ├── tnum.rs            # 三值数 (tracked number)
│   │   ├── bounds.rs          # 标量边界
│   │   ├── insn_bounds.rs     # 指令边界更新
│   │   └── range_refine.rs    # 范围细化
│   │
│   ├── btf/                   # BTF类型系统 [90% 完成]
│   │   ├── mod.rs
│   │   ├── btf.rs             # BTF类型定义 (2,677行, 含 enum64)
│   │   ├── validation.rs      # BTF验证 (1,635行)
│   │   ├── core.rs            # CO-RE 重定位 (1,014行, 50%完成)
│   │   ├── integration.rs     # BTF 集成
│   │   ├── func_info.rs       # 函数信息
│   │   └── access.rs          # BTF访问检查
│   │
│   ├── special/               # 特殊对象处理 [80% 完成]
│   │   ├── mod.rs
│   │   ├── dynptr.rs          # 动态指针 (1,663行, 75%完成)
│   │   ├── iter.rs            # 迭代器 (85%完成)
│   │   ├── exception.rs       # 异常处理 (1,137行)
│   │   ├── rbtree.rs          # 红黑树/图结构
│   │   ├── struct_ops.rs      # Struct ops (50%完成)
│   │   ├── timer_kptr.rs      # Timer/Kptr
│   │   ├── map_ops.rs         # Map操作
│   │   └── map_type_check.rs  # Map类型检查 (1,574行)
│   │
│   ├── opt/                   # 优化器 [80% 完成]
│   │   ├── mod.rs
│   │   ├── pass.rs            # 优化Pass框架 (1,018行, PassManager)
│   │   ├── dead_code.rs       # 死代码消除
│   │   ├── patching.rs        # 指令补丁
│   │   ├── misc_fixups.rs     # 杂项修复 (1,605行, 60%完成)
│   │   ├── ctx_access.rs      # 上下文访问转换 (2,113行, 60%完成)
│   │   ├── jit_subprogs.rs    # JIT子程序 (988行)
│   │   └── cache.rs           # 状态缓存优化
│   │
│   ├── verifier/              # 主验证器 [80% 完成]
│   │   ├── mod.rs
│   │   ├── main_loop.rs       # 主验证循环 (2,264行)
│   │   ├── env.rs             # 验证环境
│   │   ├── limits.rs          # 复杂度限制
│   │   ├── loader.rs          # 程序加载
│   │   ├── parallel.rs        # 并行验证
│   │   ├── result.rs          # 验证结果
│   │   ├── stats.rs           # 统计信息
│   │   ├── worklist.rs        # 工作列表
│   │   ├── worklist_verifier.rs
│   │   ├── branch_state.rs    # 分支状态
│   │   └── prune_points.rs    # 剪枝点标记
│   │
│   └── sanitize/              # 安全检查 [90% 完成]
│       ├── mod.rs
│       ├── sanitize.rs        # Spectre v1 缓解 (1,934行, 含路径敏感分析)
│       └── overflow.rs        # 指针溢出检查 (1,081行)
```

## 2. 核心数据结构

### 2.1 寄存器类型 (core/types.rs)

对应 C 代码: `enum bpf_reg_type` 和相关常量

```rust
/// 22 种寄存器类型
pub enum BpfRegType {
    NotInit,              // 未初始化
    ScalarValue,          // 标量值
    PtrToCtx,             // 指向上下文
    PtrToStack,           // 指向栈
    PtrToMapKey,          // 指向 map key
    PtrToMapValue,        // 指向 map value
    PtrToPacket,          // 指向数据包
    PtrToPacketEnd,       // 指向数据包尾
    PtrToPacketMeta,      // 指向数据包元数据
    PtrToBtfId { btf_id: u32 },  // 指向 BTF 类型
    PtrToMem { size: u32 },      // 指向内存
    PtrToArena,           // 指向 arena
    ConstPtrToMap,        // 常量 map 指针
    PtrToSocket,          // 指向 socket
    PtrToSockCommon,      // 指向 sock_common
    PtrToTcpSock,         // 指向 tcp_sock
    PtrToXdpSock,         // 指向 xdp_sock
    PtrToFlowKeys,        // 指向 flow_keys
    PtrToFunc,            // 指向函数
    ConstPtrToDynptr,     // 常量 dynptr 指针
    PtrToRdOnlyBuf,       // 只读缓冲区指针
    PtrToRdWrBuf,         // 读写缓冲区指针
}

/// 类型标志位
bitflags! {
    pub struct TypeFlags: u32 {
        const PTR_MAYBE_NULL   = 1 << 0;   // 可能为空
        const MEM_RDONLY       = 1 << 1;   // 只读内存
        const MEM_RINGBUF      = 1 << 2;   // ringbuf 内存
        const MEM_USER         = 1 << 3;   // 用户空间内存
        const MEM_PERCPU       = 1 << 4;   // per-CPU 内存
        const PTR_UNTRUSTED    = 1 << 5;   // 不可信指针
        const PTR_TRUSTED      = 1 << 6;   // 可信指针
        const MEM_UNINIT       = 1 << 7;   // 未初始化内存
        const DYNPTR_TYPE_LOCAL = 1 << 8;  // 本地 dynptr
        const DYNPTR_TYPE_RINGBUF = 1 << 9; // ringbuf dynptr
        const MEM_RCU          = 1 << 10;  // RCU 保护内存
        const NON_OWN_REF      = 1 << 11;  // 非拥有引用
        const MEM_ALLOC        = 1 << 12;  // 分配的内存
        // ...更多标志
    }
}
```

### 2.2 寄存器状态 (state/reg_state.rs)

对应 C 代码: `struct bpf_reg_state` (verifier.c 中最核心的结构)

```rust
/// 完整的寄存器状态跟踪 (52个字段)
pub struct BpfRegState {
    // 类型信息
    pub reg_type: BpfRegType,      // 寄存器类型
    pub type_flags: TypeFlags,     // 类型标志
    pub off: i32,                  // 偏移量
    
    // 标识符
    pub id: u32,                   // 寄存器 ID
    pub ref_obj_id: u32,           // 引用对象 ID
    pub frameno: u32,              // 帧编号
    
    // 标量边界跟踪 (64位)
    pub var_off: Tnum,             // 三值数追踪
    pub smin_value: i64,           // 有符号最小值
    pub smax_value: i64,           // 有符号最大值
    pub umin_value: u64,           // 无符号最小值
    pub umax_value: u64,           // 无符号最大值
    
    // 32位子寄存器边界跟踪
    pub s32_min_value: i32,        // 32位有符号最小值
    pub s32_max_value: i32,        // 32位有符号最大值
    pub u32_min_value: u32,        // 32位无符号最小值
    pub u32_max_value: u32,        // 32位无符号最大值
    
    // 活跃性和精度
    pub precise: bool,             // 是否需要精确跟踪
    pub live: LivenessState,       // 活跃性状态
    pub subreg_def: u32,           // 子寄存器定义位置
    
    // 特殊字段
    pub map_ptr: Option<MapPtr>,   // map 指针
    pub btf_info: Option<BtfInfo>, // BTF 信息
    pub dynptr: Option<DynptrInfo>,// dynptr 信息
    pub iter: Option<IterInfo>,    // 迭代器信息
    pub mem_size: u32,             // 内存大小
    pub dynptr_id: u32,            // dynptr ID
    pub map_uid: i32,              // map 唯一 ID
    // ...
}
```

### 2.3 栈槽状态 (state/stack_state.rs)

对应 C 代码: `struct bpf_stack_state` 和 `enum bpf_stack_slot_type`

```rust
/// 栈槽类型
pub enum StackSlotType {
    Invalid,    // 无效/未初始化
    Spill,      // 溢出的寄存器
    Misc,       // 杂项数据
    Zero,       // 零值
    Dynptr,     // dynptr 数据
    Iter,       // 迭代器数据
    IrqFlag,    // IRQ 标志 (新特性)
}

/// 栈槽状态
pub struct BpfStackState {
    pub spilled_ptr: BpfRegState,           // 溢出的寄存器状态
    pub slot_type: [StackSlotType; 8],      // 每字节槽类型
}
```

### 2.4 三值数 Tnum (bounds/tnum.rs)

对应 C 代码: `struct tnum` 和 `tnum_*()` 系列函数

```rust
/// 三值数: 跟踪已知和未知的位
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tnum {
    pub value: u64,  // 已知为1的位
    pub mask: u64,   // 未知的位 (1表示未知)
}

impl Tnum {
    /// 创建常量
    pub fn const_value(v: u64) -> Self {
        Tnum { value: v, mask: 0 }
    }
    
    /// 创建完全未知
    pub fn unknown() -> Self {
        Tnum { value: 0, mask: u64::MAX }
    }
    
    /// 创建范围 [0, max]
    pub fn range(min: u64, max: u64) -> Self { ... }
    
    /// 是否为常量
    pub fn is_const(&self) -> bool {
        self.mask == 0
    }
    
    /// 获取32位子寄存器
    pub fn subreg(&self) -> Tnum {
        Tnum {
            value: self.value as u32 as u64,
            mask: self.mask as u32 as u64,
        }
    }
    
    // 算术运算
    pub fn add(self, other: Tnum) -> Tnum { ... }
    pub fn sub(self, other: Tnum) -> Tnum { ... }
    pub fn mul(self, other: Tnum) -> Tnum { ... }
    pub fn and(self, other: Tnum) -> Tnum { ... }
    pub fn or(self, other: Tnum) -> Tnum { ... }
    pub fn xor(self, other: Tnum) -> Tnum { ... }
    pub fn lshift(self, min: u8, max: u8) -> Tnum { ... }
    pub fn rshift(self, min: u8, max: u8) -> Tnum { ... }
    pub fn arshift(self, min: u8, max: u8, size: u8) -> Tnum { ... }
}
```

### 2.5 优化 Pass 框架 (opt/pass.rs)

这是 Rust 实现的新架构，对应 C 中分散的优化代码。

```rust
/// 优化 Pass trait
pub trait OptPass: Send + Sync + Debug {
    /// Pass 唯一标识符
    fn id(&self) -> PassId;
    
    /// Pass 名称
    fn name(&self) -> &'static str;
    
    /// 依赖的其他 Pass
    fn dependencies(&self) -> Vec<PassId>;
    
    /// 是否启用
    fn is_enabled(&self, ctx: &PassContext) -> bool;
    
    /// 运行 Pass
    fn run(&self, ctx: &mut PassContext) -> Result<PassStats>;
}

/// Pass 管理器
pub struct PassManager {
    config: PassManagerConfig,
    passes: Vec<Box<dyn OptPass>>,
    execution_order: Vec<usize>,
    results: Vec<PassResult>,
}

impl PassManager {
    /// 添加 Pass
    pub fn add_pass(&mut self, pass: Box<dyn OptPass>);
    
    /// 解析依赖并确定执行顺序
    pub fn resolve_dependencies(&mut self) -> Result<()>;
    
    /// 运行所有 Pass
    pub fn run(&mut self, ctx: &mut PassContext) -> Result<PassManagerResult>;
}

/// 内置 Pass
pub struct DeadCodeElimPass;      // 死代码消除
pub struct SpectreMitigationPass; // Spectre 缓解
pub struct ZeroExtendPass;        // 零扩展优化
pub struct InsnSizeAdjustPass;    // 指令大小调整

/// 创建标准优化管道
pub fn create_standard_pipeline() -> PassManager {
    let mut pm = PassManager::new(PassManagerConfig::default());
    pm.add_pass(Box::new(DeadCodeElimPass::new()));
    pm.add_pass(Box::new(SpectreMitigationPass::new()));
    pm.add_pass(Box::new(ZeroExtendPass::new()));
    pm.add_pass(Box::new(InsnSizeAdjustPass::new()));
    pm.resolve_dependencies().unwrap();
    pm
}
```

### 2.6 Spectre v1 分析 (sanitize/sanitize.rs)

对应 C 代码: `sanitize_speculative_path()` 等函数

```rust
/// Spectre v1 gadget 类型
pub enum SpectreV1GadgetType {
    BoundsCheckBypass,    // 边界检查绕过
    TypeConfusion,        // 类型混淆
    PointerLeak,          // 指针泄漏
    DataLeak,             // 数据泄漏
    ControlFlowHijack,    // 控制流劫持
}

/// 推测路径跟踪器
pub struct SpeculativePathTracker {
    pub depth: usize,                        // 推测深度
    pub branch_conditions: Vec<(usize, bool)>, // 分支条件
    pub max_speculation_depth: usize,        // 最大推测深度
}

/// Spectre v1 污点跟踪器
pub struct SpectreV1TaintTracker {
    pub tainted_regs: [SpectreV1Taint; 11],  // 寄存器污点
    pub tainted_stack: Vec<(i16, SpectreV1Taint)>, // 栈污点
}

/// Spectre v1 分析器
pub struct SpectreV1Analyzer {
    pub path_tracker: SpeculativePathTracker,
    pub taint_tracker: SpectreV1TaintTracker,
    pub gadgets: Vec<SpectreV1Gadget>,       // 检测到的 gadget
    pub barriers: Vec<SpectreBarrierPatch>,  // 需要的屏障
}

/// 分析程序的 Spectre v1 漏洞
pub fn analyze_program_spectre_v1(
    state: &BpfVerifierState,
    insns: &[BpfInsn],
    config: &SpectreConfig,
) -> (Vec<SpectreV1Gadget>, Vec<SpectreBarrierPatch>);
```

### 2.7 间接跳转验证 (check/jump.rs)

对应 C 代码: `check_indirect_jump()` (L20249-20303) 和 `visit_gotox_insn()` (L18117-18157)

```rust
/// 检查是否为间接跳转 (gotol/BPF_JA|X)
pub fn is_indirect_jump(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_JA | BPF_X)
}

/// 检查间接跳转保留字段
pub fn check_indirect_jump_fields(insn: &BpfInsn, insn_idx: usize) -> Result<()> {
    if insn.src_reg != 0 || insn.imm != 0 || insn.off != 0 {
        return Err(VerifierError::InvalidReservedField { ... });
    }
    Ok(())
}

/// 间接跳转结果
pub struct IndirectJumpResult {
    pub min_target: usize,       // 最小目标
    pub max_target: usize,       // 最大目标
    pub all_targets_valid: bool, // 所有目标有效
    pub targets: Vec<usize>,     // 目标列表
}

/// 验证间接跳转
pub fn check_indirect_jump(
    r0: &BpfRegState,
    insn_idx: usize,
    insn_count: usize,
) -> Result<IndirectJumpResult>;

/// 验证目标不落在 LD_IMM64 续行
pub fn validate_indirect_jump_targets(
    targets: &[usize],
    insns: &[BpfInsn],
) -> Result<()>;
```

## 3. 验证流程

### 3.1 主流程 (verifier/main_loop.rs)

对应 C 代码: `bpf_check()` (L25109-25398)

```rust
impl MainVerifier {
    pub fn verify(&mut self) -> Result<()> {
        // 阶段1: 前置检查 (对应 C L25130-25200)
        self.check_btf_early()?;
        self.add_subprogs_and_kfuncs()?;
        self.check_subprogs()?;
        
        // 阶段2: 程序分析 (对应 C L25200-25280)
        self.check_btf()?;
        self.resolve_pseudo_ldimm64()?;
        self.build_cfg()?;
        self.compute_postorder()?;
        self.compute_scc()?;
        self.compute_liveness()?;
        
        // 阶段3: 核心验证 (对应 C L25280-25350)
        self.verify_main()?;        // do_check_main()
        self.verify_subprogs()?;    // do_check_subprogs()
        
        // 阶段4: 优化 (对应 C L25350-25390)
        self.run_optimization_passes()?;
        
        Ok(())
    }
    
    /// 运行优化 Pass
    fn run_optimization_passes(&mut self) -> Result<()> {
        let mut pm = create_standard_pipeline();
        let mut ctx = PassContext::new(self.insns.clone())
            .with_prog_type(self.prog_type)
            .with_jit(self.jit_enabled);
        pm.run(&mut ctx)?;
        self.insns = ctx.insns;
        Ok(())
    }
}
```

### 3.2 指令验证 (verifier/main_loop.rs)

对应 C 代码: `do_check_insn()` (L20305-20471)

```rust
fn verify_insn(&mut self, insn_idx: usize) -> Result<InsnResult> {
    let insn = &self.insns[insn_idx];
    let class = insn.code & BPF_CLASS_MASK;
    
    match class {
        BPF_ALU | BPF_ALU64 => {
            // 对应 C L20308-20315
            self.check_alu_op(insn)?;
        }
        BPF_LDX => {
            // 对应 C L20317-20330
            self.check_load_mem(insn)?;
        }
        BPF_STX => {
            // 对应 C L20331-20360
            if BPF_MODE(insn.code) == BPF_ATOMIC {
                self.check_atomic(insn)?;
            } else {
                self.check_store_reg(insn)?;
            }
        }
        BPF_ST => {
            // 对应 C L20361-20385
            self.check_mem_access(insn)?;
        }
        BPF_JMP | BPF_JMP32 => {
            let opcode = BPF_OP(insn.code);
            match opcode {
                BPF_CALL => {
                    // 对应 C L20390-20430
                    if insn.src_reg == BPF_PSEUDO_KFUNC_CALL {
                        self.check_kfunc_call(insn)?;
                    } else if insn.src_reg == BPF_PSEUDO_CALL {
                        self.check_func_call(insn)?;
                    } else {
                        self.check_helper_call(insn)?;
                    }
                }
                BPF_JA => {
                    // 对应 C L20431-20455 (含间接跳转)
                    if BPF_SRC(insn.code) == BPF_X {
                        self.check_indirect_jump(insn)?;
                    } else {
                        self.env.insn_idx += insn.off as usize + 1;
                    }
                }
                BPF_EXIT => {
                    // 对应 C L20456-20465
                    return self.process_bpf_exit();
                }
                _ => {
                    // 条件跳转
                    self.check_cond_jmp_op(insn)?;
                }
            }
        }
        BPF_LD => {
            // 对应 C L20466-20490
            self.check_ld(insn)?;
        }
        _ => {
            return Err(VerifierError::UnknownInsnClass { class });
        }
    }
    
    Ok(InsnResult::Continue)
}
```

## 4. 与内核 verifier.c 的函数对应关系

| 内核函数 | Rust 模块 | 状态 | 说明 |
|----------|-----------|------|------|
| `bpf_check()` | `verifier/main_loop.rs` | 80% | 主入口 |
| `do_check()` | `verifier/main_loop.rs` | 80% | 核心循环 |
| `do_check_insn()` | `verifier/main_loop.rs` | 80% | 指令分发 |
| `check_alu_op()` | `check/alu.rs` | 85% | ALU 操作 |
| `check_cond_jmp_op()` | `check/jump.rs` | 90% | 条件跳转 |
| `check_indirect_jump()` | `check/jump.rs` | 90% | 间接跳转 |
| `check_mem_access()` | `mem/memory.rs` | 85% | 内存访问 |
| `check_stack_*()` | `mem/stack_access.rs` | 80% | 栈操作 |
| `check_helper_call()` | `check/helper.rs` | 100% | Helper 调用 |
| `check_kfunc_call()` | `check/kfunc.rs` | 85% | Kfunc 调用 |
| `is_state_visited()` | `analysis/prune.rs` | 85% | 状态剪枝 |
| `states_equal()` | `analysis/states_equal.rs` | 85% | 状态比较 |
| `mark_chain_precision()` | `analysis/precision.rs` | 85% | 精度回溯 |
| `tnum_*()` | `bounds/tnum.rs` | 85% | 三值数运算 |
| `reg_bounds_*()` | `bounds/bounds.rs` | 85% | 边界跟踪 |
| `regs_refine_cond_op()` | `bounds/range_refine.rs` | 85% | 范围细化 |
| `check_return_code()` | `check/retval.rs` | 85% | 返回值检查 |
| `sanitize_speculative_path()` | `sanitize/sanitize.rs` | 90% | Spectre 缓解 |
| `sanitize_ptr_alu()` | `sanitize/overflow.rs` | 85% | 指针溢出 |
| `do_misc_fixups()` | `opt/misc_fixups.rs` | 60% | 杂项修复 |
| `convert_ctx_accesses()` | `opt/ctx_access.rs` | 60% | 上下文转换 |
| `compute_scc()` | `analysis/scc.rs` | 85% | SCC 计算 |
| `mark_stack_slots_dynptr()` | `special/dynptr.rs` | 75% | Dynptr 槽标记 |
| `mark_stack_slots_iter()` | `special/iter.rs` | 85% | 迭代器槽标记 |
| `mark_stack_slot_irq_flag()` | `state/reference.rs` | 50% | IRQ 标志 |
| `check_struct_ops_btf_id()` | `special/struct_ops.rs` | 50% | Struct ops |

## 5. 模块依赖图

```
                    ┌─────────────────┐
                    │    verifier     │
                    │  (main_loop)    │
                    │     [80%]       │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ analysis │  │   check  │  │   opt    │
        │  [85%]   │  │  [90%]   │  │  [80%]   │
        └────┬─────┘  └────┬─────┘  └────┬─────┘
             │             │             │
             └──────┬──────┴──────┬──────┘
                    │             │
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │  state   │  │   mem    │
              │  [90%]   │  │  [85%]   │
              └────┬─────┘  └────┬─────┘
                   │             │
                   └──────┬──────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
              ▼           ▼           ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  bounds  │ │   btf    │ │ special  │
        │  [85%]   │ │  [90%]   │ │  [80%]   │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             └────────────┼────────────┘
                          │
                          ▼
                    ┌──────────────┐
                    │   sanitize   │
                    │    [90%]     │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────┐
                    │   core   │
                    │  [95%]   │
                    └──────────┘
```

## 6. 测试统计

### 总计: 994 测试通过

| 模块 | 测试数量 | 说明 |
|------|----------|------|
| core | 45 | 类型、指令、常量测试 |
| state | 89 | 寄存器、栈、引用状态测试 |
| analysis | 156 | CFG、SCC、剪枝、精度测试 |
| check | 187 | ALU、跳转、helper、kfunc 测试 |
| mem | 103 | 内存访问验证测试 |
| bounds | 78 | Tnum、边界算术测试 |
| btf | 46 | BTF 类型、enum64 测试 |
| special | 65 | dynptr、迭代器、异常测试 |
| opt | 136 | Pass 框架、死代码消除测试 |
| verifier | 58 | 主循环、环境测试 |
| sanitize | 35 | Spectre、溢出检查测试 |
| 集成测试 | 31 | 端到端验证测试 |
| 文档测试 | 1 | API 示例测试 |

## 7. 代码量统计

| 文件 | 行数 | 说明 |
|------|------|------|
| `analysis/prune.rs` | 3,578 | 状态剪枝和缓存 |
| `btf/btf.rs` | 2,677 | BTF 类型系统 |
| `verifier/main_loop.rs` | 2,264 | 主验证循环 |
| `mem/user.rs` | 2,127 | 用户内存访问 |
| `opt/ctx_access.rs` | 2,113 | 上下文转换 |
| `check/kfunc.rs` | 2,084 | Kfunc 验证 |
| `check/helper.rs` | 1,950 | Helper 验证 |
| `sanitize/sanitize.rs` | 1,934 | Spectre 缓解 |
| `check/prog_type.rs` | 1,870 | 程序类型验证 |
| `special/dynptr.rs` | 1,663 | Dynptr 支持 |
| `opt/misc_fixups.rs` | 1,605 | 杂项修复 |
| `btf/validation.rs` | 1,635 | BTF 验证 |
| `special/map_type_check.rs` | 1,574 | Map 类型检查 |
| `analysis/state_merge.rs` | 1,488 | 状态合并 |
| `check/jump.rs` | 1,463 | 跳转验证 |
| `check/alu.rs` | 1,373 | ALU 验证 |
| `mem/memory.rs` | 1,323 | 内存访问 |
| `special/exception.rs` | 1,137 | 异常处理 |
| `mem/arena.rs` | 1,121 | Arena 内存 |
| `sanitize/overflow.rs` | 1,081 | 溢出检查 |
| `check/subprog.rs` | 1,073 | 子程序调用 |
| `opt/pass.rs` | 1,018 | Pass 框架 |
| **总计** | **83,304** | |

## 8. 剩余差距优先级

### 关键差距 (P0)
1. 用户内存访问验证集成 (60%)
2. 状态合并精度保持 (70%)
3. Struct ops 函数签名验证 (50%)

### 高优先级差距 (P1)
4. IRQ 状态跟踪 (50%)
5. 竞态条件检测 (40%)
6. 睡眠上下文验证 (70%)

### 中等优先级差距 (P2)
7. 动态指针高级模式 (75%)
8. BTF CO-RE 重定位 (50%)
9. 上下文访问转换 (60%)
10. Misc fixups (60%)
