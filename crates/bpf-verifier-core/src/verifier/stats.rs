// SPDX-License-Identifier: GPL-2.0

//! 验证统计和指标模块
//!
//! Verification statistics and metrics.
//!
//! 本模块在 BPF 程序验证期间跟踪统计信息，提供程序复杂度、资源使用和验证性能的洞察。
//!
//! This module tracks statistics during BPF program verification,
//! providing insights into program complexity, resource usage,
//! and verification performance.
//!
//! # 统计类型 / Statistics Types
//!
//! - **指令统计 / Instruction stats**: 按类别统计处理的指令数
//! - **状态统计 / State stats**: 创建、剪枝、合并的状态数
//! - **内存统计 / Memory stats**: 各类内存访问计数
//! - **复杂度指标 / Complexity metrics**: 圈复杂度、嵌套深度等

use alloc::collections::BTreeMap as HashMap;
use alloc::{format, string::String, vec::Vec};
use core::time::Duration;

/// Statistics collected during verification
#[derive(Debug, Clone, Default)]
pub struct VerifierStats {
    /// Total number of instructions in the program
    pub insn_count: usize,
    /// Number of instructions processed during verification
    pub insns_processed: u64,
    /// Peak number of states in the exploration stack
    pub peak_states: usize,
    /// Total number of states created
    pub total_states: u64,
    /// Number of states pruned
    pub states_pruned: u64,
    /// Maximum call stack depth reached
    pub max_call_depth: u32,
    /// Number of subprograms
    pub subprog_count: usize,
    /// Number of helper calls
    pub helper_calls: u64,
    /// Number of kfunc calls
    pub kfunc_calls: u64,
    /// Number of map operations
    pub map_ops: u64,
    /// Number of branches explored
    pub branches_explored: u64,
    /// Number of loops detected (bounded)
    pub bounded_loops: u32,
    /// Peak stack usage (bytes)
    pub peak_stack_bytes: i32,
    /// Number of precision backtracking operations
    pub precision_backtrack_ops: u64,
    /// Verification duration
    pub verification_time: Duration,
    /// Per-instruction class counts
    pub insn_class_counts: InsnClassCounts,
    /// Memory access statistics
    pub mem_stats: MemoryStats,
    /// Register usage statistics
    pub reg_stats: RegisterStats,
    /// Complexity metrics
    pub complexity: ComplexityMetrics,
}

/// Counts of instructions by class
#[derive(Debug, Clone, Default)]
pub struct InsnClassCounts {
    /// ALU64 instructions
    pub alu64: u32,
    /// ALU32 instructions
    pub alu32: u32,
    /// Load instructions (LDX)
    pub ldx: u32,
    /// Store instructions (STX)
    pub stx: u32,
    /// Store immediate (ST)
    pub st: u32,
    /// Jump instructions
    pub jmp: u32,
    /// Jump32 instructions
    pub jmp32: u32,
    /// Load immediate (LD_IMM64)
    pub ld_imm64: u32,
    /// Atomic operations
    pub atomic: u32,
    /// Call instructions
    pub call: u32,
    /// Exit instructions
    pub exit: u32,
}

/// Memory access statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    /// Stack reads
    pub stack_reads: u64,
    /// Stack writes
    pub stack_writes: u64,
    /// Map value reads
    pub map_reads: u64,
    /// Map value writes
    pub map_writes: u64,
    /// Packet reads
    pub packet_reads: u64,
    /// Packet writes
    pub packet_writes: u64,
    /// Context reads
    pub ctx_reads: u64,
    /// Context writes
    pub ctx_writes: u64,
    /// Total memory accesses
    pub total_accesses: u64,
}

/// Register usage statistics
#[derive(Debug, Clone, Default)]
pub struct RegisterStats {
    /// Number of times each register was written
    pub writes: [u32; 11],
    /// Number of times each register was read
    pub reads: [u32; 11],
    /// Number of scalar registers
    pub scalar_count: u32,
    /// Number of pointer registers
    pub pointer_count: u32,
    /// Number of precision-tracked registers
    pub precise_count: u32,
}

/// Program complexity metrics
#[derive(Debug, Clone, Default)]
pub struct ComplexityMetrics {
    /// Cyclomatic complexity (branches + 1)
    pub cyclomatic: u32,
    /// Maximum basic block size
    pub max_bb_size: u32,
    /// Number of basic blocks
    pub basic_block_count: u32,
    /// Control flow graph edges
    pub cfg_edges: u32,
    /// Nesting depth of loops/branches
    pub max_nesting: u32,
    /// Number of back edges (potential loops)
    pub back_edges: u32,
}

impl VerifierStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an instruction being processed
    pub fn record_insn(&mut self, class: u8, is_atomic: bool) {
        self.insns_processed += 1;

        match class {
            0x07 => self.insn_class_counts.alu64 += 1, // BPF_ALU64
            0x04 => self.insn_class_counts.alu32 += 1, // BPF_ALU
            0x01 => self.insn_class_counts.ldx += 1,   // BPF_LDX
            0x03 => {
                if is_atomic {
                    self.insn_class_counts.atomic += 1;
                } else {
                    self.insn_class_counts.stx += 1;
                }
            }
            0x02 => self.insn_class_counts.st += 1,  // BPF_ST
            0x05 => self.insn_class_counts.jmp += 1, // BPF_JMP
            0x06 => self.insn_class_counts.jmp32 += 1, // BPF_JMP32
            0x00 => self.insn_class_counts.ld_imm64 += 1, // BPF_LD
            _ => {}
        }
    }

    /// Record a call instruction
    pub fn record_call(&mut self, is_kfunc: bool) {
        self.insn_class_counts.call += 1;
        if is_kfunc {
            self.kfunc_calls += 1;
        } else {
            self.helper_calls += 1;
        }
    }

    /// Record an exit instruction
    pub fn record_exit(&mut self) {
        self.insn_class_counts.exit += 1;
    }

    /// Record a state creation
    pub fn record_state_created(&mut self) {
        self.total_states += 1;
    }

    /// Record a state being pruned
    pub fn record_state_pruned(&mut self) {
        self.states_pruned += 1;
    }

    /// Record peak states
    pub fn update_peak_states(&mut self, current: usize) {
        if current > self.peak_states {
            self.peak_states = current;
        }
    }

    /// Record call depth
    pub fn update_call_depth(&mut self, depth: u32) {
        if depth > self.max_call_depth {
            self.max_call_depth = depth;
        }
    }

    /// Record stack usage
    pub fn update_stack_usage(&mut self, bytes: i32) {
        if bytes > self.peak_stack_bytes {
            self.peak_stack_bytes = bytes;
        }
    }

    /// Record a memory access
    pub fn record_mem_access(&mut self, access_type: MemAccessType, is_write: bool) {
        self.mem_stats.total_accesses += 1;

        match access_type {
            MemAccessType::Stack => {
                if is_write {
                    self.mem_stats.stack_writes += 1;
                } else {
                    self.mem_stats.stack_reads += 1;
                }
            }
            MemAccessType::MapValue => {
                if is_write {
                    self.mem_stats.map_writes += 1;
                } else {
                    self.mem_stats.map_reads += 1;
                }
                self.map_ops += 1;
            }
            MemAccessType::Packet => {
                if is_write {
                    self.mem_stats.packet_writes += 1;
                } else {
                    self.mem_stats.packet_reads += 1;
                }
            }
            MemAccessType::Context => {
                if is_write {
                    self.mem_stats.ctx_writes += 1;
                } else {
                    self.mem_stats.ctx_reads += 1;
                }
            }
            MemAccessType::Other => {}
        }
    }

    /// Record register read
    pub fn record_reg_read(&mut self, regno: usize) {
        if regno < 11 {
            self.reg_stats.reads[regno] += 1;
        }
    }

    /// Record register write
    pub fn record_reg_write(&mut self, regno: usize) {
        if regno < 11 {
            self.reg_stats.writes[regno] += 1;
        }
    }

    /// Record a branch being explored
    pub fn record_branch(&mut self) {
        self.branches_explored += 1;
        self.complexity.cyclomatic += 1;
    }

    /// Record a bounded loop
    pub fn record_bounded_loop(&mut self) {
        self.bounded_loops += 1;
        self.complexity.back_edges += 1;
    }

    /// Record precision backtracking
    pub fn record_precision_backtrack(&mut self) {
        self.precision_backtrack_ops += 1;
    }

    /// Get pruning efficiency as percentage (0-100)
    pub fn pruning_efficiency_percent(&self) -> u32 {
        if self.total_states == 0 {
            return 0;
        }
        ((self.states_pruned * 100) / self.total_states) as u32
    }

    /// Get average instructions per state (scaled by 100 for precision)
    pub fn insns_per_state_scaled(&self) -> u64 {
        if self.total_states == 0 {
            return 0;
        }
        (self.insns_processed * 100) / self.total_states
    }

    /// Get verification rate (instructions per millisecond)
    pub fn verification_rate_per_ms(&self) -> u64 {
        let ms = self.verification_time.as_millis() as u64;
        if ms == 0 {
            return self.insns_processed; // Assume 1ms if too fast
        }
        self.insns_processed / ms
    }

    /// Generate a summary report
    pub fn summary(&self) -> String {
        let mut s = String::new();

        s.push_str("=== Verification Statistics ===\n\n");

        s.push_str(&format!("Program Size: {} instructions\n", self.insn_count));
        s.push_str(&format!("Subprograms: {}\n", self.subprog_count));
        s.push_str(&format!(
            "Instructions Processed: {}\n",
            self.insns_processed
        ));
        s.push_str(&format!(
            "Verification Time: {}ms\n",
            self.verification_time.as_millis()
        ));
        s.push_str(&format!(
            "Verification Rate: {} insns/ms\n\n",
            self.verification_rate_per_ms()
        ));

        s.push_str("--- State Exploration ---\n");
        s.push_str(&format!("Total States: {}\n", self.total_states));
        s.push_str(&format!(
            "States Pruned: {} ({}%)\n",
            self.states_pruned,
            self.pruning_efficiency_percent()
        ));
        s.push_str(&format!("Peak States: {}\n", self.peak_states));
        s.push_str(&format!(
            "Branches Explored: {}\n\n",
            self.branches_explored
        ));

        s.push_str("--- Call Statistics ---\n");
        s.push_str(&format!("Max Call Depth: {}\n", self.max_call_depth));
        s.push_str(&format!("Helper Calls: {}\n", self.helper_calls));
        s.push_str(&format!("Kfunc Calls: {}\n\n", self.kfunc_calls));

        s.push_str("--- Memory Access ---\n");
        s.push_str(&format!(
            "Stack: {} reads, {} writes\n",
            self.mem_stats.stack_reads, self.mem_stats.stack_writes
        ));
        s.push_str(&format!(
            "Map: {} reads, {} writes\n",
            self.mem_stats.map_reads, self.mem_stats.map_writes
        ));
        s.push_str(&format!(
            "Packet: {} reads, {} writes\n",
            self.mem_stats.packet_reads, self.mem_stats.packet_writes
        ));
        s.push_str(&format!("Peak Stack: {} bytes\n\n", self.peak_stack_bytes));

        s.push_str("--- Complexity Metrics ---\n");
        s.push_str(&format!(
            "Cyclomatic Complexity: {}\n",
            self.complexity.cyclomatic + 1
        ));
        s.push_str(&format!(
            "Basic Blocks: {}\n",
            self.complexity.basic_block_count
        ));
        s.push_str(&format!("Bounded Loops: {}\n", self.bounded_loops));
        s.push_str(&format!(
            "Precision Backtracks: {}\n",
            self.precision_backtrack_ops
        ));

        s
    }
}

/// Types of memory access
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemAccessType {
    /// Stack access
    Stack,
    /// Map value access
    MapValue,
    /// Packet data access
    Packet,
    /// Context access
    Context,
    /// Other memory type
    Other,
}

/// Statistics collector that can be used during verification
#[derive(Debug)]
pub struct StatsCollector {
    /// The stats being collected
    pub stats: VerifierStats,
    /// Per-instruction auxiliary stats
    pub insn_stats: HashMap<usize, InsnStats>,
}

/// Per-instruction statistics
#[derive(Debug, Clone, Default)]
pub struct InsnStats {
    /// Number of times this instruction was visited
    pub visit_count: u32,
    /// Number of states at this instruction
    pub state_count: u32,
    /// Whether this instruction is a prune point
    pub is_prune_point: bool,
    /// Whether this instruction was pruned
    pub was_pruned: bool,
    /// Whether this instruction forces a checkpoint
    pub is_force_checkpoint: bool,
    /// Whether this instruction is a jump point
    pub is_jmp_point: bool,
    /// Whether this instruction calls a callback function
    pub calls_callback: bool,
}

impl StatsCollector {
    /// Create a new stats collector
    pub fn new(insn_count: usize) -> Self {
        let mut stats = VerifierStats::new();
        stats.insn_count = insn_count;

        Self {
            stats,
            insn_stats: HashMap::new(),
        }
    }

    /// Start timing (no-op in no_std)
    pub fn start(&mut self) {
        // No-op in no_std
    }

    /// Stop timing and finalize stats (no-op in no_std)
    pub fn finish(&mut self) {
        // No-op in no_std
    }

    /// Record visiting an instruction
    pub fn visit_insn(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.visit_count += 1;
    }

    /// Record a state at an instruction
    pub fn record_state_at(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.state_count += 1;
        self.stats.record_state_created();
    }

    /// Mark instruction as prune point
    pub fn mark_prune_point(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.is_prune_point = true;
    }

    /// Mark instruction as pruned
    pub fn mark_pruned(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.was_pruned = true;
        self.stats.record_state_pruned();
    }

    /// Mark instruction as force checkpoint
    pub fn mark_force_checkpoint(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.is_force_checkpoint = true;
        entry.is_prune_point = true;
    }

    /// Mark instruction as jump point
    pub fn mark_jmp_point(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.is_jmp_point = true;
    }

    /// Mark instruction as calling a callback
    pub fn mark_calls_callback(&mut self, idx: usize) {
        let entry = self.insn_stats.entry(idx).or_default();
        entry.calls_callback = true;
        entry.is_force_checkpoint = true;
        entry.is_prune_point = true;
    }

    /// Check if instruction is a force checkpoint
    pub fn is_force_checkpoint(&self, idx: usize) -> bool {
        self.insn_stats
            .get(&idx)
            .is_some_and(|s| s.is_force_checkpoint)
    }

    /// Get hot instructions (most visited)
    pub fn hot_instructions(&self, top_n: usize) -> Vec<(usize, u32)> {
        let mut visits: Vec<_> = self
            .insn_stats
            .iter()
            .map(|(&idx, stats)| (idx, stats.visit_count))
            .collect();
        visits.sort_by(|a, b| b.1.cmp(&a.1));
        visits.truncate(top_n);
        visits
    }

    /// Get instructions with most states
    pub fn state_heavy_instructions(&self, top_n: usize) -> Vec<(usize, u32)> {
        let mut states: Vec<_> = self
            .insn_stats
            .iter()
            .map(|(&idx, stats)| (idx, stats.state_count))
            .collect();
        states.sort_by(|a, b| b.1.cmp(&a.1));
        states.truncate(top_n);
        states
    }

    /// Generate detailed report
    pub fn detailed_report(&self) -> String {
        let mut s = self.stats.summary();

        s.push_str("\n=== Hot Instructions ===\n");
        for (idx, count) in self.hot_instructions(10) {
            s.push_str(&format!("  insn {}: {} visits\n", idx, count));
        }

        s.push_str("\n=== State-Heavy Instructions ===\n");
        for (idx, count) in self.state_heavy_instructions(10) {
            s.push_str(&format!("  insn {}: {} states\n", idx, count));
        }

        s
    }
}
