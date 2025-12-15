//! BPF program disassembler
//!
//! This module provides disassembly of BPF bytecode into human-readable
//! assembly format. Useful for debugging and understanding BPF programs.

use crate::core::types::*;
use core::fmt::Write;

#[cfg(not(feature = "std"))]
use alloc::{string::{String, ToString}, format};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet as HashSet;
#[cfg(feature = "std")]
use std::collections::HashSet;

/// Disassembly options
#[derive(Debug, Clone, Default)]
pub struct DisasmOptions {
    /// Show raw bytecode
    pub show_bytecode: bool,
    /// Show instruction offsets
    pub show_offsets: bool,
    /// Annotate jump targets
    pub annotate_jumps: bool,
    /// Use symbolic names for helpers
    pub symbolic_helpers: bool,
    /// Maximum width for instruction mnemonic column
    pub mnemonic_width: usize,
}

impl DisasmOptions {
    /// Create default options
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
    pub fn with_bytecode(mut self) -> Self {
        self.show_bytecode = true;
        self
    }

    /// Disable offset display
    pub fn without_offsets(mut self) -> Self {
        self.show_offsets = false;
        self
    }
}

/// Disassemble a single instruction
pub fn disasm_insn(insn: &BpfInsn, idx: usize, opts: &DisasmOptions) -> String {
    let mut s = String::new();

    // Offset
    if opts.show_offsets {
        write!(s, "{:4}: ", idx).unwrap();
    }

    // Raw bytecode
    if opts.show_bytecode {
        write!(s, "{:02x} {:02x} {:02x} {:02x} {:08x}  ",
               insn.code, insn.dst_reg | (insn.src_reg << 4),
               insn.off as u8, (insn.off >> 8) as u8,
               insn.imm as u32).unwrap();
    }

    // Mnemonic
    let mnemonic = disasm_mnemonic(insn, idx, opts);
    s.push_str(&mnemonic);

    s
}

/// Get the mnemonic for an instruction
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
            format!("ldx{} r{}, [r{}+{}]", size, insn.dst_reg, insn.src_reg, insn.off)
        } else {
            format!("ldx{} r{}, [r{}{}]", size, insn.dst_reg, insn.src_reg, insn.off)
        }
    } else {
        format!(".ldx {:#04x}", insn.code)
    }
}

/// Disassemble STX instruction
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
            format!("stx{} [r{}+{}], r{}", size, insn.dst_reg, insn.off, insn.src_reg)
        } else {
            format!("stx{} [r{}{}], r{}", size, insn.dst_reg, insn.off, insn.src_reg)
        }
    } else if mode == BPF_ATOMIC {
        disasm_atomic(insn, size)
    } else {
        format!(".stx {:#04x}", insn.code)
    }
}

/// Disassemble atomic operation
fn disasm_atomic(insn: &BpfInsn, size: &str) -> String {
    let atomic_op = insn.imm as u32;
    let fetch = if atomic_op & BPF_FETCH != 0 { "_fetch" } else { "" };
    
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
        format!("atomic{}{}{} [r{}+{}], r{}", size, op_name, fetch,
                insn.dst_reg, insn.off, insn.src_reg)
    } else {
        format!("atomic{}{}{} [r{}{}], r{}", size, op_name, fetch,
                insn.dst_reg, insn.off, insn.src_reg)
    }
}

/// Disassemble ST instruction
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
fn disasm_ld(insn: &BpfInsn) -> String {
    if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
        let src = insn.src_reg;
        // Note: BPF_PSEUDO_MAP_FD (1) == BPF_PSEUDO_CALL (1)
        //       BPF_PSEUDO_MAP_VALUE (2) == BPF_PSEUDO_KFUNC_CALL (2)
        // For LD_IMM64, we interpret these as map-related pseudo values
        let src_name = match src {
            0 => "",
            1 => "map_fd",           // BPF_PSEUDO_MAP_FD
            2 => "map_value",        // BPF_PSEUDO_MAP_VALUE
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
                format!("{}{} r{}, r{}, +{}{}", op_name, suffix,
                        insn.dst_reg, insn.src_reg, insn.off, target_str)
            } else {
                format!("{}{} r{}, {}, +{}{}", op_name, suffix,
                        insn.dst_reg, insn.imm, insn.off, target_str)
            }
        }
    }
}

/// Disassemble CALL instruction
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
fn get_helper_name(id: u32) -> Option<&'static str> {
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
pub fn disasm_program(insns: &[BpfInsn], opts: &DisasmOptions) -> String {
    let mut output = String::new();
    let mut i = 0;

    while i < insns.len() {
        let insn = &insns[i];
        let line = disasm_insn(insn, i, opts);
        output.push_str(&line);
        output.push('\n');

        // Handle LD_IMM64 which spans two instructions
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            i += 1;
            if i < insns.len() {
                let next = &insns[i];
                if opts.show_offsets {
                    write!(output, "{:4}: ", i).unwrap();
                }
                if opts.show_bytecode {
                    write!(output, "{:02x} {:02x} {:02x} {:02x} {:08x}  ",
                           next.code, next.dst_reg | (next.src_reg << 4),
                           next.off as u8, (next.off >> 8) as u8,
                           next.imm as u32).unwrap();
                }
                // Show the upper 32 bits
                output.push_str(&format!("     ; hi32={:#x}\n", next.imm as u32));
            }
        }

        i += 1;
    }

    output
}

/// Disassemble with annotations showing jump targets
pub fn disasm_annotated(insns: &[BpfInsn]) -> String {
    let opts = DisasmOptions::new();
    let mut output = String::new();

    // Find all jump targets
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
        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) && i + 1 < insns.len() {
            i += 1;
        }

        i += 1;
    }

    output
}

/// Program dumper that shows both disassembly and analysis
#[derive(Debug)]
pub struct ProgramDumper<'a> {
    insns: &'a [BpfInsn],
    opts: DisasmOptions,
}

impl<'a> ProgramDumper<'a> {
    /// Create a new program dumper
    pub fn new(insns: &'a [BpfInsn]) -> Self {
        Self {
            insns,
            opts: DisasmOptions::new(),
        }
    }

    /// Set disassembly options
    pub fn with_options(mut self, opts: DisasmOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Get program statistics
    pub fn stats(&self) -> ProgramStats {
        let mut stats = ProgramStats::default();
        stats.total_insns = self.insns.len();

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
    pub fn dump(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str("; BPF Program Dump\n");
        output.push_str(&format!("; {} instructions\n\n", self.insns.len()));

        // Stats
        let stats = self.stats();
        output.push_str(&"; Statistics:\n".to_string());
        output.push_str(&format!(";   ALU64: {}, ALU32: {}\n", 
                                 stats.alu64_insns, stats.alu32_insns));
        output.push_str(&format!(";   Loads: {}, Stores: {}\n",
                                 stats.load_insns, stats.store_insns));
        output.push_str(&format!(";   Branches: {}, Jumps: {}\n",
                                 stats.branch_insns, stats.jump_insns));
        output.push_str(&format!(";   Calls: {}, Exits: {}\n\n",
                                 stats.call_insns, stats.exit_insns));

        // Disassembly
        output.push_str(&disasm_program(self.insns, &self.opts));

        output
    }
}

/// Basic program statistics
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct ProgramStats {
    pub total_insns: usize,
    pub alu64_insns: usize,
    pub alu32_insns: usize,
    pub load_insns: usize,
    pub store_insns: usize,
    pub branch_insns: usize,
    pub jump_insns: usize,
    pub call_insns: usize,
    pub exit_insns: usize,
    pub ld_imm64_insns: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_alu() {
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 42);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("add r0, 42"));
    }

    #[test]
    fn test_disasm_alu_reg() {
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("add r0, r1"));
    }

    #[test]
    fn test_disasm_mov32() {
        let insn = BpfInsn::new(BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, 100);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("mov32 r1, 100"));
    }

    #[test]
    fn test_disasm_ldx() {
        let insn = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, 0, 10, -8, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("ldxdw r0, [r10-8]"));
    }

    #[test]
    fn test_disasm_stx() {
        let insn = BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, 10, 1, -4, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("stxw [r10-4], r1"));
    }

    #[test]
    fn test_disasm_jmp() {
        let insn = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 5, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("ja +5"));
        assert!(s.contains("<6>")); // target annotation
    }

    #[test]
    fn test_disasm_jeq() {
        let insn = BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 3, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("jeq r1, 0, +3"));
    }

    #[test]
    fn test_disasm_call_helper() {
        let insn = BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 1);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert!(s.contains("map_lookup_elem"));
    }

    #[test]
    fn test_disasm_exit() {
        let insn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        let opts = DisasmOptions::new().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        assert_eq!(s.trim(), "exit");
    }

    #[test]
    fn test_disasm_program() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let opts = DisasmOptions::new();
        let s = disasm_program(&insns, &opts);
        assert!(s.contains("mov r0, 0"));
        assert!(s.contains("exit"));
    }

    #[test]
    fn test_program_dumper() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let dumper = ProgramDumper::new(&insns);
        let stats = dumper.stats();
        
        assert_eq!(stats.total_insns, 3);
        assert_eq!(stats.alu64_insns, 2);
        assert_eq!(stats.exit_insns, 1);
    }

    #[test]
    fn test_helper_names() {
        assert_eq!(get_helper_name(1), Some("map_lookup_elem"));
        assert_eq!(get_helper_name(12), Some("tail_call"));
        assert_eq!(get_helper_name(9999), None);
    }

    #[test]
    fn test_disasm_with_bytecode() {
        let insn = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42);
        let opts = DisasmOptions::new().with_bytecode().without_offsets();
        let s = disasm_insn(&insn, 0, &opts);
        // Should contain bytecode
        assert!(s.contains("b7")); // BPF_ALU64 | BPF_MOV | BPF_K = 0xb7
    }

    #[test]
    fn test_disasm_annotated() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), // jump to 2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        
        let s = disasm_annotated(&insns);
        assert!(s.contains("L2:")); // Label at jump target
    }
}
