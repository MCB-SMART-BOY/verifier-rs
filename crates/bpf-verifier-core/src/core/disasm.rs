// SPDX-License-Identifier: GPL-2.0

//! BPF program disassembler
//! BPF 程序反汇编器
//!
//! This module provides disassembly of BPF bytecode into human-readable
//! assembly format. Useful for debugging and understanding BPF programs.
//!
//! 本模块提供将 BPF 字节码反汇编为人类可读汇编格式的功能。
//! 用于调试和理解 BPF 程序。

use crate::core::types::*;
use core::fmt::Write;

use alloc::{
    format,
    string::{String, ToString},
};

use alloc::collections::BTreeSet as HashSet;

/// Disassembly options
/// 反汇编选项
#[derive(Debug, Clone, Default)]
pub struct DisasmOptions {
    /// Show raw bytecode
    /// 显示原始字节码
    pub show_bytecode: bool,
    /// Show instruction offsets
    /// 显示指令偏移量
    pub show_offsets: bool,
    /// Annotate jump targets
    /// 标注跳转目标
    pub annotate_jumps: bool,
    /// Use symbolic names for helpers
    /// 对辅助函数使用符号名称
    pub symbolic_helpers: bool,
    /// Maximum width for instruction mnemonic column
    /// 指令助记符列的最大宽度
    pub mnemonic_width: usize,
}

impl DisasmOptions {
    /// Create default options
    /// 创建默认选项
    pub fn new() -> Self {
        Self {
            show_bytecode: false,
            show_offsets: true,
            annotate_jumps: true,
            symbolic_helpers: true,
            mnemonic_width: 40,
        }
    }

    /// Enable bytecode display
    /// 启用字节码显示
    pub fn with_bytecode(mut self) -> Self {
        self.show_bytecode = true;
        self
    }

    /// Disable offset display
    /// 禁用偏移量显示
    pub fn without_offsets(mut self) -> Self {
        self.show_offsets = false;
        self
    }
}

/// Disassemble a single instruction
/// 反汇编单条指令
pub fn disasm_insn(insn: &BpfInsn, idx: usize, opts: &DisasmOptions) -> String {
    let mut s = String::new();

    // Offset
    // 偏移量
    if opts.show_offsets {
        write!(s, "{:4}: ", idx).unwrap();
    }

    // Raw bytecode
    // 原始字节码
    if opts.show_bytecode {
        write!(
            s,
            "{:02x} {:02x} {:02x} {:02x} {:08x}  ",
            insn.code,
            insn.dst_reg | (insn.src_reg << 4),
            insn.off as u8,
            (insn.off >> 8) as u8,
            insn.imm as u32
        )
        .unwrap();
    }

    // Mnemonic
    // 助记符
    let mnemonic = disasm_mnemonic(insn, idx, opts);
    s.push_str(&mnemonic);

    s
}

/// Get the mnemonic for an instruction
/// 获取指令的助记符
fn disasm_mnemonic(insn: &BpfInsn, idx: usize, opts: &DisasmOptions) -> String {
    let class = insn.class();

    match class {
        BPF_ALU | BPF_ALU64 => disasm_alu(insn, class == BPF_ALU64),
        BPF_LDX => disasm_ldx(insn),
        BPF_STX => disasm_stx(insn),
        BPF_ST => disasm_st(insn),
        BPF_LD => disasm_ld(insn),
        BPF_JMP | BPF_JMP32 => disasm_jmp(insn, idx, class == BPF_JMP, opts),
        _ => format!(".byte {:#04x}", insn.code),
    }
}

/// Disassemble ALU instruction
/// 反汇编 ALU 指令
fn disasm_alu(insn: &BpfInsn, is_64: bool) -> String {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let suffix = if is_64 { "" } else { "32" };

    let op_name = match op {
        BPF_ADD => "add",
        BPF_SUB => "sub",
        BPF_MUL => "mul",
        BPF_DIV => "div",
        BPF_MOD => "mod",
        BPF_OR => "or",
        BPF_AND => "and",
        BPF_XOR => "xor",
        BPF_LSH => "lsh",
        BPF_RSH => "rsh",
        BPF_ARSH => "arsh",
        BPF_MOV => "mov",
        BPF_NEG => "neg",
        BPF_END => {
            return if insn.imm == 16 {
                format!("le16 r{}", insn.dst_reg)
            } else if insn.imm == 32 {
                format!("le32 r{}", insn.dst_reg)
            } else {
                format!("le64 r{}", insn.dst_reg)
            };
        }
        _ => return format!(".alu {:#04x}", insn.code),
    };

    if op == BPF_NEG {
        return format!("neg{} r{}", suffix, insn.dst_reg);
    }

    if src_type == BPF_X {
        format!("{}{} r{}, r{}", op_name, suffix, insn.dst_reg, insn.src_reg)
    } else {
        format!("{}{} r{}, {}", op_name, suffix, insn.dst_reg, insn.imm)
    }
}

/// Disassemble LDX instruction
/// 反汇编 LDX 指令
fn disasm_ldx(insn: &BpfInsn) -> String {
    let size = match insn.code & 0x18 {
        x if x == BPF_B => "b",
        x if x == BPF_H => "h",
        x if x == BPF_W => "w",
        x if x == BPF_DW => "dw",
        _ => "?",
    };

    let mode = insn.code & 0xe0;
    if mode == BPF_MEM {
        if insn.off >= 0 {
            format!(
                "ldx{} r{}, [r{}+{}]",
                size, insn.dst_reg, insn.src_reg, insn.off
            )
        } else {
            format!(
                "ldx{} r{}, [r{}{}]",
                size, insn.dst_reg, insn.src_reg, insn.off
            )
        }
    } else {
        format!(".ldx {:#04x}", insn.code)
    }
}

/// Disassemble STX instruction
/// 反汇编 STX 指令
fn disasm_stx(insn: &BpfInsn) -> String {
    let size = match insn.code & 0x18 {
        x if x == BPF_B => "b",
        x if x == BPF_H => "h",
        x if x == BPF_W => "w",
        x if x == BPF_DW => "dw",
        _ => "?",
    };

    let mode = insn.code & 0xe0;

    if mode == BPF_MEM {
        if insn.off >= 0 {
            format!(
                "stx{} [r{}+{}], r{}",
                size, insn.dst_reg, insn.off, insn.src_reg
            )
        } else {
            format!(
                "stx{} [r{}{}], r{}",
                size, insn.dst_reg, insn.off, insn.src_reg
            )
        }
    } else if mode == BPF_ATOMIC {
        disasm_atomic(insn, size)
    } else {
        format!(".stx {:#04x}", insn.code)
    }
}

/// Disassemble atomic operation
/// 反汇编原子操作
fn disasm_atomic(insn: &BpfInsn, size: &str) -> String {
    let atomic_op = insn.imm as u32;
    let fetch = if atomic_op & BPF_FETCH != 0 {
        "_fetch"
    } else {
        ""
    };

    let base_op = atomic_op & !BPF_FETCH;
    let op_name = match base_op {
        x if x == BPF_ADD as u32 => "add",
        x if x == BPF_OR as u32 => "or",
        x if x == BPF_AND as u32 => "and",
        x if x == BPF_XOR as u32 => "xor",
        x if x == BPF_XCHG => "xchg",
        x if x == BPF_CMPXCHG => "cmpxchg",
        _ => return format!(".atomic {:#04x}", atomic_op),
    };

    if insn.off >= 0 {
        format!(
            "atomic{}{}{} [r{}+{}], r{}",
            size, op_name, fetch, insn.dst_reg, insn.off, insn.src_reg
        )
    } else {
        format!(
            "atomic{}{}{} [r{}{}], r{}",
            size, op_name, fetch, insn.dst_reg, insn.off, insn.src_reg
        )
    }
}

/// Disassemble ST instruction
/// 反汇编 ST 指令
fn disasm_st(insn: &BpfInsn) -> String {
    let size = match insn.code & 0x18 {
        x if x == BPF_B => "b",
        x if x == BPF_H => "h",
        x if x == BPF_W => "w",
        x if x == BPF_DW => "dw",
        _ => "?",
    };

    if insn.off >= 0 {
        format!("st{} [r{}+{}], {}", size, insn.dst_reg, insn.off, insn.imm)
    } else {
        format!("st{} [r{}{}], {}", size, insn.dst_reg, insn.off, insn.imm)
    }
}

/// Disassemble LD instruction
/// 反汇编 LD 指令
fn disasm_ld(insn: &BpfInsn) -> String {
    if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
        let src = insn.src_reg;
        // Note: BPF_PSEUDO_MAP_FD (1) == BPF_PSEUDO_CALL (1)
        //       BPF_PSEUDO_MAP_VALUE (2) == BPF_PSEUDO_KFUNC_CALL (2)
        // 注意：BPF_PSEUDO_MAP_FD (1) == BPF_PSEUDO_CALL (1)
        //       BPF_PSEUDO_MAP_VALUE (2) == BPF_PSEUDO_KFUNC_CALL (2)
        // For LD_IMM64, we interpret these as map-related pseudo values
        // 对于 LD_IMM64，我们将这些解释为映射表相关的伪值
        let src_name = match src {
            0 => "",
            1 => "map_fd",    // BPF_PSEUDO_MAP_FD
            2 => "map_value", // BPF_PSEUDO_MAP_VALUE
            BPF_PSEUDO_MAP_IDX => "map_idx",
            BPF_PSEUDO_MAP_IDX_VALUE => "map_idx_value",
            _ => "?",
        };

        if src_name.is_empty() {
            format!("lddw r{}, {:#x}", insn.dst_reg, insn.imm as u32)
        } else {
            format!("lddw r{}, {}({:#x})", insn.dst_reg, src_name, insn.imm)
        }
    } else {
        format!(".ld {:#04x}", insn.code)
    }
}

/// Disassemble JMP instruction
/// 反汇编 JMP 指令
fn disasm_jmp(insn: &BpfInsn, idx: usize, is_64: bool, opts: &DisasmOptions) -> String {
    let op = insn.code & 0xf0;
    let src_type = insn.code & 0x08;
    let suffix = if is_64 { "" } else { "32" };

    match op {
        BPF_JA => {
            let target = idx as i32 + insn.off as i32 + 1;
            if opts.annotate_jumps {
                format!("ja +{} <{}>", insn.off, target)
            } else {
                format!("ja +{}", insn.off)
            }
        }
        BPF_CALL => disasm_call(insn, idx, opts),
        BPF_EXIT => "exit".to_string(),
        _ => {
            let op_name = match op {
                BPF_JEQ => "jeq",
                BPF_JNE => "jne",
                BPF_JGT => "jgt",
                BPF_JGE => "jge",
                BPF_JLT => "jlt",
                BPF_JLE => "jle",
                BPF_JSGT => "jsgt",
                BPF_JSGE => "jsge",
                BPF_JSLT => "jslt",
                BPF_JSLE => "jsle",
                BPF_JSET => "jset",
                _ => return format!(".jmp {:#04x}", insn.code),
            };

            let target = idx as i32 + insn.off as i32 + 1;
            let target_str = if opts.annotate_jumps {
                format!(" <{}>", target)
            } else {
                String::new()
            };

            if src_type == BPF_X {
                format!(
                    "{}{} r{}, r{}, +{}{}",
                    op_name, suffix, insn.dst_reg, insn.src_reg, insn.off, target_str
                )
            } else {
                format!(
                    "{}{} r{}, {}, +{}{}",
                    op_name, suffix, insn.dst_reg, insn.imm, insn.off, target_str
                )
            }
        }
    }
}

/// Disassemble CALL instruction
/// 反汇编 CALL 指令
fn disasm_call(insn: &BpfInsn, idx: usize, opts: &DisasmOptions) -> String {
    if insn.src_reg == BPF_PSEUDO_CALL {
        let target = idx as i32 + insn.imm + 1;
        if opts.annotate_jumps {
            format!("call pc+{} <{}>", insn.imm, target)
        } else {
            format!("call pc+{}", insn.imm)
        }
    } else if insn.src_reg == BPF_PSEUDO_KFUNC_CALL {
        format!("call kfunc#{}", insn.imm)
    } else {
        let helper_name = if opts.symbolic_helpers {
            get_helper_name(insn.imm as u32)
        } else {
            None
        };

        match helper_name {
            Some(name) => format!("call {}", name),
            None => format!("call #{}", insn.imm),
        }
    }
}

/// Get symbolic name for a helper function
/// 获取辅助函数的符号名称
pub fn get_helper_name(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("map_lookup_elem"),
        2 => Some("map_update_elem"),
        3 => Some("map_delete_elem"),
        4 => Some("probe_read"),
        5 => Some("ktime_get_ns"),
        6 => Some("trace_printk"),
        7 => Some("get_prandom_u32"),
        8 => Some("get_smp_processor_id"),
        12 => Some("tail_call"),
        14 => Some("get_current_pid_tgid"),
        15 => Some("get_current_uid_gid"),
        16 => Some("get_current_comm"),
        23 => Some("redirect"),
        25 => Some("perf_event_output"),
        35 => Some("get_current_task"),
        51 => Some("redirect_map"),
        67 => Some("get_stack"),
        93 => Some("spin_lock"),
        94 => Some("spin_unlock"),
        130 => Some("ringbuf_output"),
        131 => Some("ringbuf_reserve"),
        132 => Some("ringbuf_submit"),
        133 => Some("ringbuf_discard"),
        164 => Some("for_each_map_elem"),
        181 => Some("loop"),
        195 => Some("copy_from_user"),
        _ => None,
    }
}

/// Disassemble an entire program
/// 反汇编整个程序
pub fn disasm_program(insns: &[BpfInsn], opts: &DisasmOptions) -> String {
    let mut output = String::new();
    let mut i = 0;

    while i < insns.len() {
        let insn = &insns[i];
        let line = disasm_insn(insn, i, opts);
        output.push_str(&line);
        output.push('\n');

        // Handle LD_IMM64 which spans two instructions
        // 处理跨越两条指令的 LD_IMM64
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            i += 1;
            if i < insns.len() {
                let next = &insns[i];
                if opts.show_offsets {
                    write!(output, "{:4}: ", i).unwrap();
                }
                if opts.show_bytecode {
                    write!(
                        output,
                        "{:02x} {:02x} {:02x} {:02x} {:08x}  ",
                        next.code,
                        next.dst_reg | (next.src_reg << 4),
                        next.off as u8,
                        (next.off >> 8) as u8,
                        next.imm as u32
                    )
                    .unwrap();
                }
                // Show the upper 32 bits
                // 显示高 32 位
                output.push_str(&format!("     ; hi32={:#x}\n", next.imm as u32));
            }
        }

        i += 1;
    }

    output
}

/// Disassemble with annotations showing jump targets
/// 带有跳转目标标注的反汇编
pub fn disasm_annotated(insns: &[BpfInsn]) -> String {
    let opts = DisasmOptions::new();
    let mut output = String::new();

    // Find all jump targets
    // 查找所有跳转目标
    let mut targets = HashSet::new();
    for (i, insn) in insns.iter().enumerate() {
        let class = insn.class();
        if class == BPF_JMP || class == BPF_JMP32 {
            let op = insn.code & 0xf0;
            if op != BPF_CALL && op != BPF_EXIT {
                let target = (i as i32 + insn.off as i32 + 1) as usize;
                if target < insns.len() {
                    targets.insert(target);
                }
            }
            if op == BPF_CALL && insn.src_reg == BPF_PSEUDO_CALL {
                let target = (i as i32 + insn.imm + 1) as usize;
                if target < insns.len() {
                    targets.insert(target);
                }
            }
        }
    }

    // Disassemble with labels
    // 带标签的反汇编
    let mut i = 0;
    while i < insns.len() {
        if targets.contains(&i) {
            writeln!(output, "L{}:", i).unwrap();
        }

        let insn = &insns[i];
        let line = disasm_insn(insn, i, &opts);
        output.push_str("  ");
        output.push_str(&line);
        output.push('\n');

        // Handle LD_IMM64
        // 处理 LD_IMM64
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) && i + 1 < insns.len() {
            i += 1;
        }

        i += 1;
    }

    output
}

/// Program dumper that shows both disassembly and analysis
/// 显示反汇编和分析的程序转储器
#[derive(Debug)]
pub struct ProgramDumper<'a> {
    insns: &'a [BpfInsn],
    opts: DisasmOptions,
}

impl<'a> ProgramDumper<'a> {
    /// Create a new program dumper
    /// 创建新的程序转储器
    pub fn new(insns: &'a [BpfInsn]) -> Self {
        Self {
            insns,
            opts: DisasmOptions::new(),
        }
    }

    /// Set disassembly options
    /// 设置反汇编选项
    pub fn with_options(mut self, opts: DisasmOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Get program statistics
    /// 获取程序统计信息
    pub fn stats(&self) -> ProgramStats {
        let mut stats = ProgramStats {
            total_insns: self.insns.len(),
            ..Default::default()
        };

        for insn in self.insns {
            let class = insn.class();
            match class {
                BPF_ALU64 => stats.alu64_insns += 1,
                BPF_ALU => stats.alu32_insns += 1,
                BPF_LDX => stats.load_insns += 1,
                BPF_STX | BPF_ST => stats.store_insns += 1,
                BPF_JMP | BPF_JMP32 => {
                    let op = insn.code & 0xf0;
                    match op {
                        BPF_JA => stats.jump_insns += 1,
                        BPF_CALL => stats.call_insns += 1,
                        BPF_EXIT => stats.exit_insns += 1,
                        _ => stats.branch_insns += 1,
                    }
                }
                BPF_LD => stats.ld_imm64_insns += 1,
                _ => {}
            }
        }

        stats
    }

    /// Dump the program
    /// 转储程序
    pub fn dump(&self) -> String {
        let mut output = String::new();

        // Header
        // 头部
        output.push_str("; BPF Program Dump\n");
        output.push_str("; BPF 程序转储\n");
        output.push_str(&format!("; {} instructions\n", self.insns.len()));
        output.push_str(&format!("; {} 条指令\n\n", self.insns.len()));

        // Stats
        // 统计信息
        let stats = self.stats();
        output.push_str("; Statistics / 统计信息:\n");
        output.push_str(&format!(
            ";   ALU64: {}, ALU32: {}\n",
            stats.alu64_insns, stats.alu32_insns
        ));
        output.push_str(&format!(
            ";   Loads / 加载: {}, Stores / 存储: {}\n",
            stats.load_insns, stats.store_insns
        ));
        output.push_str(&format!(
            ";   Branches / 分支: {}, Jumps / 跳转: {}\n",
            stats.branch_insns, stats.jump_insns
        ));
        output.push_str(&format!(
            ";   Calls / 调用: {}, Exits / 退出: {}\n\n",
            stats.call_insns, stats.exit_insns
        ));

        // Disassembly
        // 反汇编
        output.push_str(&disasm_program(self.insns, &self.opts));

        output
    }
}

/// Basic program statistics
/// 基本程序统计信息
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct ProgramStats {
    /// Total instruction count / 总指令数
    pub total_insns: usize,
    /// 64-bit ALU instruction count / 64 位 ALU 指令数
    pub alu64_insns: usize,
    /// 32-bit ALU instruction count / 32 位 ALU 指令数
    pub alu32_insns: usize,
    /// Load instruction count / 加载指令数
    pub load_insns: usize,
    /// Store instruction count / 存储指令数
    pub store_insns: usize,
    /// Branch instruction count / 分支指令数
    pub branch_insns: usize,
    /// Jump instruction count / 跳转指令数
    pub jump_insns: usize,
    /// Call instruction count / 调用指令数
    pub call_insns: usize,
    /// Exit instruction count / 退出指令数
    pub exit_insns: usize,
    /// LD_IMM64 instruction count / LD_IMM64 指令数
    pub ld_imm64_insns: usize,
}
