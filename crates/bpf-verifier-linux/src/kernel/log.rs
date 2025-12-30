// SPDX-License-Identifier: GPL-2.0

//! BPF 验证器的内核日志设施模块
//!
//! Kernel Logging Facilities for the BPF Verifier.
//!
//! 本模块提供与内核日志基础设施集成的日志宏和函数。
//! 在内核中，这些映射到 `pr_info!`、`pr_warn!`、`pr_err!` 等。
//!
//! This module provides logging macros and functions that integrate with
//! the kernel's logging infrastructure. In the kernel, these map to
//! `pr_info!`, `pr_warn!`, `pr_err!`, etc.
//!
//! # 验证器日志 / Verifier Log
//!
//! BPF 验证器有自己的日志缓冲区，与内核的 printk 日志分开。
//! 用于向用户空间提供验证失败的详细信息。
//!
//! The BPF verifier has its own log buffer that is separate from the
//! kernel's printk log. This is used to provide detailed information
//! about verification failures back to userspace.
//!
//! # 内核集成 / Kernel Integration
//!
//! 使用 `kernel` 特性编译时，日志宏与内核的 printk 系统集成。
//! 在独立模式下，它们是空操作或写入缓冲区用于测试。
//!
//! When compiled with the `kernel` feature, the logging macros integrate
//! with the kernel's printk system. In standalone mode, they are no-ops
//! or write to a buffer for testing.

use crate::stdlib::{String, Vec};
use core::fmt::{self, Write};

// ============================================================================
// Log Levels
// ============================================================================

/// Log levels matching kernel's log levels.
///
/// These correspond to the kernel's KERN_* log levels:
/// - KERN_EMERG   "0"
/// - KERN_ALERT   "1"
/// - KERN_CRIT    "2"
/// - KERN_ERR     "3"
/// - KERN_WARNING "4"
/// - KERN_NOTICE  "5"
/// - KERN_INFO    "6"
/// - KERN_DEBUG   "7"
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u32)]
pub enum LogLevel {
    /// Emergency: system is unusable
    Emergency = 0,
    /// Alert: action must be taken immediately
    Alert = 1,
    /// Critical: critical conditions
    Critical = 2,
    /// Error: error conditions
    Error = 3,
    /// Warning: warning conditions
    Warning = 4,
    /// Notice: normal but significant condition
    Notice = 5,
    /// Info: informational
    #[default]
    Info = 6,
    /// Debug: debug-level messages
    Debug = 7,
}

impl LogLevel {
    /// Convert to kernel log level string prefix.
    pub const fn as_kern_str(&self) -> &'static str {
        match self {
            LogLevel::Emergency => "<0>",
            LogLevel::Alert => "<1>",
            LogLevel::Critical => "<2>",
            LogLevel::Error => "<3>",
            LogLevel::Warning => "<4>",
            LogLevel::Notice => "<5>",
            LogLevel::Info => "<6>",
            LogLevel::Debug => "<7>",
        }
    }

    /// Get the level name for display.
    pub const fn name(&self) -> &'static str {
        match self {
            LogLevel::Emergency => "EMERG",
            LogLevel::Alert => "ALERT",
            LogLevel::Critical => "CRIT",
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARN",
            LogLevel::Notice => "NOTICE",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

// ============================================================================
// Verifier Log Buffer
// ============================================================================

/// Maximum verifier log buffer size (1MB).
pub const VERIFIER_LOG_MAX_SIZE: usize = 1024 * 1024;

/// Verifier-specific log buffer.
///
/// This is separate from the kernel's printk log and is used to
/// provide detailed verification information to userspace.
///
/// The log buffer is allocated by userspace and passed to the kernel.
/// This Rust implementation mirrors the kernel's `bpf_verifier_log`.
#[derive(Debug)]
pub struct VerifierLog {
    /// Log buffer
    buffer: Vec<u8>,
    /// Maximum buffer size
    max_size: usize,
    /// Current log level threshold
    level: LogLevel,
    /// Whether truncation occurred
    truncated: bool,
    /// Total bytes that would have been written (for overflow detection)
    total_len: usize,
}

impl VerifierLog {
    /// Create a new verifier log with the given capacity.
    ///
    /// The capacity is capped at `VERIFIER_LOG_MAX_SIZE` (1MB).
    pub fn new(capacity: usize) -> Self {
        let max_size = capacity.min(VERIFIER_LOG_MAX_SIZE);
        Self {
            buffer: Vec::with_capacity(max_size.min(4096)), // Start small
            max_size,
            level: LogLevel::Info,
            truncated: false,
            total_len: 0,
        }
    }

    /// Create a log with a specific level threshold.
    pub fn with_level(capacity: usize, level: LogLevel) -> Self {
        let mut log = Self::new(capacity);
        log.level = level;
        log
    }

    /// Set the log level threshold.
    ///
    /// Messages below this level will not be logged.
    pub fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }

    /// Get the current log level threshold.
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Check if logging is enabled.
    pub fn is_enabled(&self) -> bool {
        self.max_size > 0
    }

    /// Check if a specific log level would be logged.
    pub fn is_level_enabled(&self, level: LogLevel) -> bool {
        self.is_enabled() && level <= self.level
    }

    /// Check if the log was truncated.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Get total bytes that would have been written.
    ///
    /// This may be larger than the buffer size if truncation occurred.
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// Write a message to the log.
    pub fn write(&mut self, msg: &str) {
        if !self.is_enabled() {
            return;
        }

        let bytes = msg.as_bytes();
        self.total_len = self.total_len.saturating_add(bytes.len());

        let remaining = self.max_size.saturating_sub(self.buffer.len());

        if remaining == 0 {
            self.truncated = true;
            return;
        }

        let to_write = bytes.len().min(remaining);
        self.buffer.extend_from_slice(&bytes[..to_write]);

        if to_write < bytes.len() {
            self.truncated = true;
        }
    }

    /// Write a message at a specific log level.
    pub fn write_level(&mut self, level: LogLevel, msg: &str) {
        if !self.is_level_enabled(level) {
            return;
        }
        self.write(msg);
    }

    /// Write a formatted message to the log.
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) {
        if !self.is_enabled() {
            return;
        }

        // Use a temporary string buffer
        let mut s = String::new();
        let _ = s.write_fmt(args);
        self.write(&s);
    }

    /// Write a line to the log (appends newline).
    pub fn writeln(&mut self, msg: &str) {
        self.write(msg);
        self.write("\n");
    }

    /// Clear the log.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.truncated = false;
        self.total_len = 0;
    }

    /// Get the log contents as a string.
    pub fn as_str(&self) -> &str {
        // SAFETY: We only write valid UTF-8 strings to the buffer
        core::str::from_utf8(&self.buffer).unwrap_or("<invalid utf8>")
    }

    /// Get the log contents as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the current log length.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get remaining capacity.
    pub fn remaining(&self) -> usize {
        self.max_size.saturating_sub(self.buffer.len())
    }

    /// Get the maximum size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl Default for VerifierLog {
    fn default() -> Self {
        Self::new(0) // Logging disabled by default
    }
}

impl Write for VerifierLog {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}

// ============================================================================
// Verifier Logging Macros
// ============================================================================

/// Log a message at the specified level to the verifier log.
///
/// # Example
///
/// ```ignore
/// verifier_log!(log, LogLevel::Error, "invalid instruction at {}", idx);
/// ```
#[macro_export]
macro_rules! verifier_log {
    ($log:expr, $level:expr, $($arg:tt)*) => {{
        if $log.is_level_enabled($level) {
            use core::fmt::Write;
            let _ = write!($log, $($arg)*);
            let _ = write!($log, "\n");
        }
    }};
}

/// Log an error message to the verifier log.
#[macro_export]
macro_rules! verifier_err {
    ($log:expr, $($arg:tt)*) => {
        $crate::verifier_log!($log, $crate::kernel::log::LogLevel::Error, $($arg)*)
    };
}

/// Log a warning message to the verifier log.
#[macro_export]
macro_rules! verifier_warn {
    ($log:expr, $($arg:tt)*) => {
        $crate::verifier_log!($log, $crate::kernel::log::LogLevel::Warning, $($arg)*)
    };
}

/// Log an info message to the verifier log.
#[macro_export]
macro_rules! verifier_info {
    ($log:expr, $($arg:tt)*) => {
        $crate::verifier_log!($log, $crate::kernel::log::LogLevel::Info, $($arg)*)
    };
}

/// Log a debug message to the verifier log.
#[macro_export]
macro_rules! verifier_debug {
    ($log:expr, $($arg:tt)*) => {
        $crate::verifier_log!($log, $crate::kernel::log::LogLevel::Debug, $($arg)*)
    };
}

// ============================================================================
// Kernel printk Integration
// ============================================================================

// In kernel mode, these macros call the real kernel logging functions.
// In standalone mode, they are no-ops or write to a test buffer.

#[cfg(feature = "kernel")]
mod kernel_log {
    // When building as part of the kernel, these would be:
    // pub use kernel::pr_info;
    // pub use kernel::pr_err;
    // pub use kernel::pr_warn;
    // pub use kernel::pr_debug;
    //
    // For now, we provide stubs that will be replaced during kernel integration.
}

/// Print informational message to kernel log.
///
/// In kernel mode, this calls `kernel::pr_info!`.
/// In standalone mode, this is a no-op.
#[macro_export]
#[cfg(not(feature = "kernel"))]
macro_rules! pr_info {
    ($($arg:tt)*) => {{
        // Standalone mode: no-op
        // To enable debug output, use cfg(feature = "verbose")
        #[cfg(feature = "verbose")]
        {
            // Could write to stderr or a debug buffer here
        }
    }};
}

/// Print error message to kernel log.
#[macro_export]
#[cfg(not(feature = "kernel"))]
macro_rules! pr_err {
    ($($arg:tt)*) => {{
        #[cfg(feature = "verbose")]
        {
            // Could write to stderr here
        }
    }};
}

/// Print warning message to kernel log.
#[macro_export]
#[cfg(not(feature = "kernel"))]
macro_rules! pr_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "verbose")]
        {
            // Could write to stderr here
        }
    }};
}

/// Print debug message to kernel log.
#[macro_export]
#[cfg(not(feature = "kernel"))]
macro_rules! pr_debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "verbose")]
        {
            // Could write to stderr here
        }
    }};
}

// Kernel mode implementations (placeholders)

/// Print an info message (kernel feature placeholder).
#[cfg(feature = "kernel")]
#[macro_export]
macro_rules! pr_info {
    ($($arg:tt)*) => {{
        // In real kernel build:
        // ::kernel::pr_info!($($arg)*);
    }};
}

/// Print an error message (kernel feature placeholder).
#[cfg(feature = "kernel")]
#[macro_export]
macro_rules! pr_err {
    ($($arg:tt)*) => {{
        // In real kernel build:
        // ::kernel::pr_err!($($arg)*);
    }};
}

/// Print a warning message (kernel feature placeholder).
#[cfg(feature = "kernel")]
#[macro_export]
macro_rules! pr_warn {
    ($($arg:tt)*) => {{
        // In real kernel build:
        // ::kernel::pr_warn!($($arg)*);
    }};
}

/// Print a debug message (kernel feature placeholder).
#[cfg(feature = "kernel")]
#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => {{
        // In real kernel build:
        // ::kernel::pr_debug!($($arg)*);
    }};
}

// ============================================================================
// BPF Verifier Log Formatting
// ============================================================================

/// BPF instruction opcodes for disassembly.
mod opcodes {
    pub const BPF_LD: u8 = 0x00;
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ST: u8 = 0x02;
    pub const BPF_STX: u8 = 0x03;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_JMP32: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;
}

use crate::core::types::BpfInsn;

/// Dump an instruction to the log.
///
/// Format matches kernel's `bpf_dump_insn` for consistency.
#[allow(clippy::let_unit_value)]
pub fn dump_insn(log: &mut VerifierLog, idx: usize, insn: &BpfInsn) {
    #[allow(unused_imports)]
    use core::fmt::Write;
    let _ = writeln!(
        log,
        "{}: ({:02x}) r{} {} r{} off:{} imm:{}",
        idx,
        insn.code,
        insn.dst_reg,
        op_name(insn.code),
        insn.src_reg,
        insn.off,
        insn.imm
    );
}

/// Dump multiple instructions to the log.
pub fn dump_insns(log: &mut VerifierLog, insns: &[BpfInsn], start: usize, count: usize) {
    for i in 0..count.min(insns.len().saturating_sub(start)) {
        dump_insn(log, start + i, &insns[start + i]);
    }
}

/// Get operation name from opcode for display.
fn op_name(code: u8) -> &'static str {
    let class = code & 0x07;
    let op = code & 0xf0;

    match class {
        opcodes::BPF_ALU | opcodes::BPF_ALU64 => match op {
            0x00 => "+=",
            0x10 => "-=",
            0x20 => "*=",
            0x30 => "/=",
            0x40 => "|=",
            0x50 => "&=",
            0x60 => "<<=",
            0x70 => ">>=",
            0x80 => "neg",
            0x90 => "%=",
            0xa0 => "^=",
            0xb0 => "=",
            0xc0 => "s>>=",
            0xd0 => "endian",
            _ => "?alu",
        },
        opcodes::BPF_JMP | opcodes::BPF_JMP32 => match op {
            0x00 => "goto",
            0x10 => "==",
            0x20 => ">",
            0x30 => ">=",
            0x40 => "&",
            0x50 => "!=",
            0x60 => "s>",
            0x70 => "s>=",
            0x80 => "call",
            0x90 => "exit",
            0xa0 => "<",
            0xb0 => "<=",
            0xc0 => "s<",
            0xd0 => "s<=",
            _ => "?jmp",
        },
        opcodes::BPF_LDX => "ldx",
        opcodes::BPF_ST => "st",
        opcodes::BPF_STX => "stx",
        opcodes::BPF_LD => "ld",
        _ => "???",
    }
}

// ============================================================================
// Register State Logging
// ============================================================================

use crate::state::reg_state::BpfRegState;
use crate::core::types::BpfRegType;

/// Format a register state for logging.
pub fn format_reg_state(reg: &BpfRegState, regno: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "R{}", regno);

    match reg.reg_type {
        BpfRegType::NotInit => {
            let _ = write!(s, "=<not_init>");
        }
        BpfRegType::ScalarValue => {
            if reg.is_const() {
                let _ = write!(s, "={}", reg.const_value());
            } else if reg.umin_value == reg.umax_value {
                let _ = write!(s, "={}", reg.umin_value);
            } else {
                let _ = write!(
                    s,
                    "=scalar(umin={},umax={})",
                    reg.umin_value, reg.umax_value
                );
            }
            if reg.precise {
                let _ = write!(s, " P");
            }
        }
        BpfRegType::PtrToCtx => {
            let _ = write!(s, "=ctx");
            if reg.off != 0 {
                let _ = write!(s, "+{}", reg.off);
            }
        }
        BpfRegType::PtrToStack => {
            let _ = write!(s, "=fp{:+}", reg.off);
        }
        BpfRegType::PtrToPacket => {
            let _ = write!(s, "=pkt");
            if reg.off != 0 {
                let _ = write!(s, "+{}", reg.off);
            }
        }
        BpfRegType::PtrToPacketEnd => {
            let _ = write!(s, "=pkt_end");
        }
        BpfRegType::PtrToMapValue => {
            let _ = write!(s, "=map_value");
            if reg.off != 0 {
                let _ = write!(s, "+{}", reg.off);
            }
        }
        BpfRegType::PtrToMapKey => {
            let _ = write!(s, "=map_key");
        }
        BpfRegType::ConstPtrToMap => {
            let _ = write!(s, "=map_ptr");
        }
        BpfRegType::PtrToSocket => {
            let _ = write!(s, "=sock");
        }
        BpfRegType::PtrToMem => {
            let _ = write!(s, "=mem");
        }
        _ => {
            let _ = write!(s, "={:?}", reg.reg_type);
        }
    }

    if reg.id != 0 {
        let _ = write!(s, " id={}", reg.id);
    }
    if reg.ref_obj_id != 0 {
        let _ = write!(s, " ref={}", reg.ref_obj_id);
    }

    s
}

/// Log all register states.
pub fn log_reg_states(log: &mut VerifierLog, regs: &[BpfRegState]) {
    for (i, reg) in regs.iter().enumerate() {
        if reg.reg_type != BpfRegType::NotInit {
            log.writeln(&format_reg_state(reg, i));
        }
    }
}


