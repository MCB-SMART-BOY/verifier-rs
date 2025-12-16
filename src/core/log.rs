//! Verbose logging for BPF verifier
//!
//! This module provides structured logging for the verification process,
//! useful for debugging and understanding why programs pass or fail.

use crate::state::reg_state::BpfRegState;
use crate::state::verifier_state::BpfVerifierState;
use crate::core::types::*;
use core::fmt::Write;


use alloc::{string::String, format};

/// Log level for verifier output
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// No logging
    #[default]
    Off = 0,
    /// Only errors
    Error = 1,
    /// Errors and warnings
    Warn = 2,
    /// General information (state changes, branches)
    Info = 3,
    /// Detailed debugging info
    Debug = 4,
    /// Very verbose (every instruction)
    Trace = 5,
}

/// Verifier log buffer
#[derive(Debug, Clone, Default)]
pub struct VerifierLog {
    /// Log level threshold
    pub level: LogLevel,
    /// Log buffer
    pub buffer: String,
    /// Maximum buffer size
    pub max_size: usize,
    /// Whether buffer has been truncated
    pub truncated: bool,
}

impl VerifierLog {
    /// Create a new log with specified level
    pub fn new(level: LogLevel) -> Self {
        Self {
            level,
            buffer: String::new(),
            max_size: 1024 * 1024, // 1MB default
            truncated: false,
        }
    }

    /// Create a log with custom max size
    pub fn with_max_size(level: LogLevel, max_size: usize) -> Self {
        Self {
            level,
            buffer: String::new(),
            max_size,
            truncated: false,
        }
    }

    /// Check if logging is enabled at the given level
    pub fn enabled(&self, level: LogLevel) -> bool {
        level <= self.level && level != LogLevel::Off
    }

    /// Log a message at the given level
    pub fn log(&mut self, level: LogLevel, msg: &str) {
        if !self.enabled(level) || self.truncated {
            return;
        }

        if self.buffer.len() + msg.len() + 1 > self.max_size {
            self.truncated = true;
            self.buffer.push_str("\n... log truncated ...\n");
            return;
        }

        self.buffer.push_str(msg);
        self.buffer.push('\n');
    }

    /// Log an error
    pub fn error(&mut self, msg: &str) {
        self.log(LogLevel::Error, msg);
    }

    /// Log a warning
    pub fn warn(&mut self, msg: &str) {
        self.log(LogLevel::Warn, msg);
    }

    /// Log info
    pub fn info(&mut self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }

    /// Log debug
    pub fn debug(&mut self, msg: &str) {
        self.log(LogLevel::Debug, msg);
    }

    /// Log trace
    pub fn trace(&mut self, msg: &str) {
        self.log(LogLevel::Trace, msg);
    }

    /// Get the log contents
    pub fn contents(&self) -> &str {
        &self.buffer
    }

    /// Clear the log
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.truncated = false;
    }

    /// Get the current length of the log buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the log buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Truncate the log buffer to the specified length
    /// 
    /// This is used for log rollback when popping states from the stack.
    pub fn truncate(&mut self, len: usize) {
        if len < self.buffer.len() {
            self.buffer.truncate(len);
            // If we truncate below max_size, we can log again
            if len < self.max_size {
                self.truncated = false;
            }
        }
    }
}

/// Format a register state for logging
pub fn fmt_reg(reg: &BpfRegState, regno: usize) -> String {
    let mut s = String::new();
    
    write!(s, "R{}", regno).unwrap();
    
    match reg.reg_type {
        BpfRegType::NotInit => {
            write!(s, "=<not_init>").unwrap();
        }
        BpfRegType::ScalarValue => {
            if reg.is_const() {
                write!(s, "={}", reg.const_value()).unwrap();
            } else {
                // Show bounds
                if reg.umin_value == reg.umax_value {
                    write!(s, "={}", reg.umin_value).unwrap();
                } else {
                    write!(s, "=scalar(umin={},umax={})", 
                           reg.umin_value, reg.umax_value).unwrap();
                }
                if reg.precise {
                    write!(s, " P").unwrap();
                }
            }
        }
        BpfRegType::PtrToCtx => {
            write!(s, "=ctx").unwrap();
            if reg.off != 0 {
                write!(s, "+{}", reg.off).unwrap();
            }
        }
        BpfRegType::PtrToStack => {
            write!(s, "=fp{:+}", reg.off).unwrap();
        }
        BpfRegType::PtrToPacket => {
            write!(s, "=pkt").unwrap();
            if reg.off != 0 {
                write!(s, "+{}", reg.off).unwrap();
            }
        }
        BpfRegType::PtrToPacketEnd => {
            write!(s, "=pkt_end").unwrap();
        }
        BpfRegType::PtrToMapValue => {
            write!(s, "=map_value").unwrap();
            if reg.off != 0 {
                write!(s, "+{}", reg.off).unwrap();
            }
            if reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                write!(s, "_or_null").unwrap();
            }
        }
        BpfRegType::PtrToMapKey => {
            write!(s, "=map_key").unwrap();
        }
        BpfRegType::ConstPtrToMap => {
            write!(s, "=map_ptr").unwrap();
        }
        BpfRegType::PtrToSocket => {
            write!(s, "=sock").unwrap();
            if reg.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
                write!(s, "_or_null").unwrap();
            }
        }
        BpfRegType::PtrToMem => {
            write!(s, "=mem").unwrap();
            if reg.type_flags.contains(BpfTypeFlag::MEM_ALLOC) {
                write!(s, "(alloc)").unwrap();
            }
        }
        _ => {
            write!(s, "={:?}", reg.reg_type).unwrap();
        }
    }

    if reg.id != 0 {
        write!(s, " id={}", reg.id).unwrap();
    }
    if reg.ref_obj_id != 0 {
        write!(s, " ref={}", reg.ref_obj_id).unwrap();
    }

    s
}

/// Format register state summary (only non-trivial registers)
pub fn fmt_regs(state: &BpfVerifierState) -> String {
    let mut s = String::new();
    
    if let Some(func) = state.cur_func() {
        let mut first = true;
        for (i, reg) in func.regs.iter().enumerate() {
            if reg.reg_type != BpfRegType::NotInit {
                if !first {
                    s.push(' ');
                }
                s.push_str(&fmt_reg(reg, i));
                first = false;
            }
        }
    }
    
    s
}

/// Format an instruction for logging
pub fn fmt_insn(insn: &BpfInsn, idx: usize) -> String {
    let class = insn.class();
    let mut s = String::new();

    write!(s, "{}: ", idx).unwrap();

    match class {
        BPF_ALU | BPF_ALU64 => {
            let op = insn.code & 0xf0;
            let is_64 = class == BPF_ALU64;
            let width = if is_64 { "" } else { "32" };
            let src_type = insn.code & 0x08;

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
                BPF_END => "end",
                _ => "alu?",
            };

            if src_type == BPF_X {
                write!(s, "{}{} r{}, r{}", op_name, width, 
                       insn.dst_reg, insn.src_reg).unwrap();
            } else {
                write!(s, "{}{} r{}, {}", op_name, width,
                       insn.dst_reg, insn.imm).unwrap();
            }
        }
        BPF_LDX => {
            let size = match insn.code & 0x18 {
                x if x == BPF_B => "8",
                x if x == BPF_H => "16",
                x if x == BPF_W => "32",
                x if x == BPF_DW => "64",
                _ => "?",
            };
            write!(s, "ldx{} r{}, [r{}+{}]", size,
                   insn.dst_reg, insn.src_reg, insn.off).unwrap();
        }
        BPF_STX | BPF_ST => {
            let size = match insn.code & 0x18 {
                x if x == BPF_B => "8",
                x if x == BPF_H => "16",
                x if x == BPF_W => "32",
                x if x == BPF_DW => "64",
                _ => "?",
            };
            if class == BPF_STX {
                write!(s, "stx{} [r{}+{}], r{}", size,
                       insn.dst_reg, insn.off, insn.src_reg).unwrap();
            } else {
                write!(s, "st{} [r{}+{}], {}", size,
                       insn.dst_reg, insn.off, insn.imm).unwrap();
            }
        }
        BPF_JMP | BPF_JMP32 => {
            let op = insn.code & 0xf0;
            let is_32 = class == BPF_JMP32;
            let width = if is_32 { "32" } else { "" };
            let src_type = insn.code & 0x08;

            match op {
                BPF_JA => {
                    write!(s, "goto +{}", insn.off).unwrap();
                }
                BPF_CALL => {
                    if insn.is_pseudo_call() {
                        write!(s, "call pc+{}", insn.imm).unwrap();
                    } else {
                        write!(s, "call #{}", insn.imm).unwrap();
                    }
                }
                BPF_EXIT => {
                    write!(s, "exit").unwrap();
                }
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
                        _ => "jmp?",
                    };
                    if src_type == BPF_X {
                        write!(s, "{}{} r{}, r{}, +{}", op_name, width,
                               insn.dst_reg, insn.src_reg, insn.off).unwrap();
                    } else {
                        write!(s, "{}{} r{}, {}, +{}", op_name, width,
                               insn.dst_reg, insn.imm, insn.off).unwrap();
                    }
                }
            }
        }
        BPF_LD => {
            if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                write!(s, "lddw r{}, {:#x}", insn.dst_reg, insn.imm).unwrap();
            } else {
                write!(s, "ld r{}, ...", insn.dst_reg).unwrap();
            }
        }
        _ => {
            write!(s, "??? {:#04x}", insn.code).unwrap();
        }
    }

    s
}

/// Log verifier progress at instruction
pub fn log_insn(log: &mut VerifierLog, insn: &BpfInsn, idx: usize, state: &BpfVerifierState) {
    if !log.enabled(LogLevel::Trace) {
        return;
    }

    let insn_str = fmt_insn(insn, idx);
    let regs_str = fmt_regs(state);
    
    let msg = format!("{} ; {}", insn_str, regs_str);
    log.trace(&msg);
}

/// Log a branch decision
pub fn log_branch(log: &mut VerifierLog, idx: usize, taken: bool, target: usize) {
    if !log.enabled(LogLevel::Debug) {
        return;
    }

    let msg = format!("{}: branch {} -> {}", 
                      idx, 
                      if taken { "taken" } else { "not taken" },
                      target);
    log.debug(&msg);
}

/// Log state push (exploring new branch)
pub fn log_state_push(log: &mut VerifierLog, idx: usize, stack_depth: usize) {
    if !log.enabled(LogLevel::Debug) {
        return;
    }

    let msg = format!("push state at {}, depth={}", idx, stack_depth);
    log.debug(&msg);
}

/// Log state pop
pub fn log_state_pop(log: &mut VerifierLog, idx: usize, stack_depth: usize) {
    if !log.enabled(LogLevel::Debug) {
        return;
    }

    let msg = format!("pop state to {}, depth={}", idx, stack_depth);
    log.debug(&msg);
}

/// Log verification error
pub fn log_error(log: &mut VerifierLog, idx: usize, error: &str) {
    let msg = format!("{}: ERROR: {}", idx, error);
    log.error(&msg);
}

/// Log state pruning
pub fn log_prune(log: &mut VerifierLog, idx: usize, reason: &str) {
    if !log.enabled(LogLevel::Info) {
        return;
    }

    let msg = format!("{}: pruned ({})", idx, reason);
    log.info(&msg);
}

/// Log function call
pub fn log_call(log: &mut VerifierLog, idx: usize, func_id: i32, is_helper: bool) {
    if !log.enabled(LogLevel::Info) {
        return;
    }

    let msg = if is_helper {
        format!("{}: helper call #{}", idx, func_id)
    } else {
        format!("{}: subprog call pc+{}", idx, func_id)
    };
    log.info(&msg);
}

/// Log function return
pub fn log_return(log: &mut VerifierLog, idx: usize, frame_depth: usize) {
    if !log.enabled(LogLevel::Info) {
        return;
    }

    let msg = format!("{}: return from frame {}", idx, frame_depth);
    log.info(&msg);
}
