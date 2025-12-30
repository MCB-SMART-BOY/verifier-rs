// SPDX-License-Identifier: GPL-2.0

//! Loop detection and bounding
//! 循环检测和边界确定
//!
//! This module implements loop detection and bounding for BPF programs.
//! 本模块实现 BPF 程序的循环检测和边界确定。
//! BPF programs traditionally couldn't have loops, but bounded loops are
//! BPF 程序传统上不能有循环，但现在支持有界循环，
//! now supported with proper verification.
//! 只要经过正确的验证即可。

use alloc::{format, vec, vec::Vec};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use crate::bounds::scalar::ScalarBounds;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// Maximum number of loop iterations for bounded loops
/// 有界循环的最大迭代次数
pub const BPF_MAX_LOOPS: u32 = 8 * 1024 * 1024;

/// Loop information
/// 循环信息
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// Loop header (first instruction of the loop)
    /// 循环头（循环的第一条指令）
    pub header: usize,
    /// Back edge source (instruction that jumps back to header)
    /// 回边源（跳回循环头的指令）
    pub back_edge: usize,
    /// Loop body instructions
    /// 循环体指令集合
    pub body: HashSet<usize>,
    /// Induction variable register (if detected)
    /// 归纳变量寄存器（如果检测到）
    pub induction_var: Option<u8>,
    /// Loop bound (if provable)
    /// 循环边界（如果可证明）
    pub bound: Option<u32>,
    /// Whether loop is bounded
    /// 循环是否有界
    pub is_bounded: bool,
}

impl LoopInfo {
    /// Create new loop info
    /// 创建新的循环信息
    pub fn new(header: usize, back_edge: usize) -> Self {
        Self {
            header,
            back_edge,
            body: HashSet::new(),
            induction_var: None,
            bound: None,
            is_bounded: false,
        }
    }

    /// Check if instruction is in loop body
    /// 检查指令是否在循环体中
    pub fn contains(&self, insn_idx: usize) -> bool {
        self.body.contains(&insn_idx) || insn_idx == self.header
    }
}

/// Loop detector
/// 循环检测器
#[derive(Debug, Default)]
pub struct LoopDetector {
    /// Detected loops
    /// 检测到的循环
    pub loops: Vec<LoopInfo>,
    /// Back edges found
    /// 发现的回边
    pub back_edges: Vec<(usize, usize)>,
    /// DFS state
    /// DFS 状态
    visited: HashSet<usize>,
    in_stack: HashSet<usize>,
}

impl LoopDetector {
    /// Create new loop detector
    /// 创建新的循环检测器
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect loops in instructions
    /// 在指令中检测循环
    pub fn detect(&mut self, insns: &[BpfInsn]) -> Result<()> {
        self.visited.clear();
        self.in_stack.clear();
        self.back_edges.clear();
        self.loops.clear();

        // DFS from entry point
        // 从入口点开始 DFS
        self.dfs(insns, 0)?;

        // Build loop info for each back edge
        // 为每条回边构建循环信息
        for &(src, dst) in &self.back_edges.clone() {
            let mut loop_info = LoopInfo::new(dst, src);
            self.find_loop_body(insns, &mut loop_info)?;
            self.loops.push(loop_info);
        }

        Ok(())
    }

    /// DFS to find back edges (iterative version to avoid stack overflow in kernel)
    /// DFS 查找回边（迭代版本以避免内核栈溢出）
    fn dfs(&mut self, insns: &[BpfInsn], start_idx: usize) -> Result<()> {
        if start_idx >= insns.len() {
            return Ok(());
        }

        // Use explicit stack instead of recursion
        // 使用显式栈代替递归
        // Each entry: (node_idx, next_successor_to_process, is_entering)
        // 每个条目：(节点索引, 下一个要处理的后继, 是否正在进入)
        // is_entering: true means we're just entering this node (need to mark visited/in_stack)
        // is_entering: true 表示我们刚进入此节点（需要标记 visited/in_stack）
        //              false means we're returning from a child
        //              false 表示我们从子节点返回
        let mut stack: Vec<(usize, usize, bool)> = Vec::new();
        stack.push((start_idx, 0, true));

        while let Some((idx, succ_idx, is_entering)) = stack.pop() {
            if is_entering {
                // First time visiting this node
                // 首次访问此节点
                if self.visited.contains(&idx) {
                    continue;
                }
                self.visited.insert(idx);
                self.in_stack.insert(idx);
            }

            let successors = self.get_successors(insns, idx);
            let mut found_unvisited = false;

            for (i, &succ) in successors.iter().enumerate().skip(succ_idx) {
                if self.in_stack.contains(&succ) {
                    // Back edge found
                    // 发现回边
                    self.back_edges.push((idx, succ));
                } else if !self.visited.contains(&succ) && succ < insns.len() {
                    // Push current node back to continue after child returns
                    // 将当前节点压回栈中，以便子节点返回后继续
                    stack.push((idx, i + 1, false));
                    // Push child to visit
                    // 将子节点压入栈中访问
                    stack.push((succ, 0, true));
                    found_unvisited = true;
                    break;
                }
            }

            // If no unvisited successors, we're done with this node
            // 如果没有未访问的后继，则此节点处理完成
            if !found_unvisited {
                self.in_stack.remove(&idx);
            }
        }

        Ok(())
    }

    /// Get successor instructions
    /// 获取后继指令
    fn get_successors(&self, insns: &[BpfInsn], idx: usize) -> Vec<usize> {
        let mut successors = Vec::new();

        if idx >= insns.len() {
            return successors;
        }

        let insn = &insns[idx];
        let class = insn.class();

        // Handle LD_IMM64 (two slots)
        // 处理 LD_IMM64（占用两个槽位）
        if insn.code == (BPF_LD | BPF_IMM | 0x18) {
            if idx + 2 < insns.len() {
                successors.push(idx + 2);
            }
            return successors;
        }

        match class {
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;
                match op {
                    BPF_EXIT => {
                        // No successors
                        // 无后继
                    }
                    BPF_JA => {
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            successors.push(target);
                        }
                    }
                    BPF_CALL => {
                        // Continue to next (non-tail call)
                        // 继续到下一条（非尾调用）
                        if idx + 1 < insns.len() {
                            successors.push(idx + 1);
                        }
                    }
                    _ => {
                        // Conditional jump
                        // 条件跳转
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            successors.push(target);
                        }
                        if idx + 1 < insns.len() {
                            successors.push(idx + 1);
                        }
                    }
                }
            }
            _ => {
                if idx + 1 < insns.len() {
                    successors.push(idx + 1);
                }
            }
        }

        successors
    }

    /// Find all instructions in loop body
    /// 查找循环体中的所有指令
    fn find_loop_body(&self, insns: &[BpfInsn], loop_info: &mut LoopInfo) -> Result<()> {
        // BFS backward from back edge source to header
        // 从回边源向后 BFS 到循环头
        let mut worklist = vec![loop_info.back_edge];
        let mut visited = HashSet::new();

        while let Some(idx) = worklist.pop() {
            if visited.contains(&idx) {
                continue;
            }
            visited.insert(idx);

            if idx == loop_info.header {
                continue;
            }

            loop_info.body.insert(idx);

            // Add predecessors
            // 添加前驱
            for pred in self.get_predecessors(insns, idx) {
                if !visited.contains(&pred) {
                    worklist.push(pred);
                }
            }
        }

        loop_info.body.insert(loop_info.header);
        Ok(())
    }

    /// Get predecessor instructions (reverse CFG)
    /// 获取前驱指令（反向 CFG）
    fn get_predecessors(&self, insns: &[BpfInsn], idx: usize) -> Vec<usize> {
        let mut predecessors = Vec::new();

        for (i, _insn) in insns.iter().enumerate() {
            let successors = self.get_successors(insns, i);
            if successors.contains(&idx) {
                predecessors.push(i);
            }
        }

        predecessors
    }

    /// Check if there are any unbounded loops
    /// 检查是否存在无界循环
    pub fn has_unbounded_loops(&self) -> bool {
        self.loops.iter().any(|l| !l.is_bounded)
    }

    /// Get loop containing instruction
    /// 获取包含指令的循环
    pub fn get_loop(&self, insn_idx: usize) -> Option<&LoopInfo> {
        self.loops.iter().find(|l| l.contains(insn_idx))
    }
}

/// Loop bound analysis
/// 循环边界分析
#[derive(Debug, Default)]
pub struct LoopBoundAnalyzer {
    /// Induction variable bounds at loop header
    /// 循环头处归纳变量的边界
    pub header_bounds: HashMap<usize, ScalarBounds>,
}

impl LoopBoundAnalyzer {
    /// Create new analyzer
    /// 创建新的分析器
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a loop to determine if it's bounded
    /// 分析循环以确定其是否有界
    pub fn analyze_loop(&mut self, insns: &[BpfInsn], loop_info: &mut LoopInfo) -> Result<()> {
        // Look for common loop patterns:
        // 查找常见的循环模式：
        // 1. Counter-based: r = 0; while (r < N) { r++; }
        // 1. 基于计数器：r = 0; while (r < N) { r++; }
        // 2. Iterator-based: bpf_loop helper
        // 2. 基于迭代器：bpf_loop 辅助函数
        // 3. For-each: bpf_for_each_map_elem
        // 3. For-each 遍历：bpf_for_each_map_elem

        // Try to find induction variable
        // 尝试找到归纳变量
        if let Some((var, bound)) = self.find_induction_variable(insns, loop_info)? {
            loop_info.induction_var = Some(var);
            loop_info.bound = Some(bound);
            loop_info.is_bounded = bound <= BPF_MAX_LOOPS;
        }

        Ok(())
    }

    /// Find induction variable and its bound
    /// 查找归纳变量及其边界
    fn find_induction_variable(
        &self,
        insns: &[BpfInsn],
        loop_info: &LoopInfo,
    ) -> Result<Option<(u8, u32)>> {
        // Look at the back edge instruction - it should be a conditional jump
        // 查看回边指令 - 应该是条件跳转
        let back_edge_insn = &insns[loop_info.back_edge];
        let class = back_edge_insn.class();

        if class != BPF_JMP && class != BPF_JMP32 {
            return Ok(None);
        }

        let op = back_edge_insn.code & 0xf0;

        // Check for comparison-based loops
        // 检查基于比较的循环
        match op {
            BPF_JLT | BPF_JLE | BPF_JGT | BPF_JGE | BPF_JSLT | BPF_JSLE | BPF_JSGT | BPF_JSGE => {
                let var = back_edge_insn.dst_reg;

                // If comparing against immediate, that's our bound
                // 如果与立即数比较，那就是我们的边界
                if back_edge_insn.code & BPF_X == 0 {
                    let bound = back_edge_insn.imm as u32;
                    return Ok(Some((var, bound)));
                }
            }
            _ => {}
        }

        Ok(None)
    }

    /// Check if loop uses bpf_loop helper
    /// 检查循环是否使用 bpf_loop 辅助函数
    pub fn check_bpf_loop_helper(&self, insns: &[BpfInsn], loop_info: &LoopInfo) -> Option<u32> {
        // Look for bpf_loop call which has explicit iteration limit
        // 查找具有显式迭代限制的 bpf_loop 调用
        for &idx in &loop_info.body {
            if idx >= insns.len() {
                continue;
            }

            let insn = &insns[idx];
            if insn.code == (BPF_JMP | BPF_CALL) {
                // Check if this is bpf_loop helper
                // 检查这是否是 bpf_loop 辅助函数
                // bpf_loop has helper ID that we would check here
                // bpf_loop 有辅助函数 ID，我们会在这里检查
                // For now, return None as we need helper database
                // 目前返回 None，因为我们需要辅助函数数据库
            }
        }
        None
    }
}

/// Verify that all loops are bounded
/// 验证所有循环都是有界的
pub fn verify_loops_bounded(insns: &[BpfInsn]) -> Result<()> {
    let mut detector = LoopDetector::new();
    detector.detect(insns)?;

    if detector.back_edges.is_empty() {
        return Ok(());
    }

    let mut analyzer = LoopBoundAnalyzer::new();

    for loop_info in &mut detector.loops {
        analyzer.analyze_loop(insns, loop_info)?;

        if !loop_info.is_bounded {
            return Err(VerifierError::TooComplex(format!(
                "unbounded loop at instruction {}",
                loop_info.header
            )));
        }
    }

    Ok(())
}

/// Check if instruction is a loop exit
/// 检查指令是否是循环出口
pub fn is_loop_exit(insns: &[BpfInsn], idx: usize, loop_info: &LoopInfo) -> bool {
    if idx >= insns.len() {
        return false;
    }

    let insn = &insns[idx];
    let class = insn.class();

    if class != BPF_JMP && class != BPF_JMP32 {
        return false;
    }

    let op = insn.code & 0xf0;

    // Check if jump target is outside loop
    // 检查跳转目标是否在循环外
    match op {
        BPF_JA => {
            let target = (idx as i32 + insn.off as i32 + 1) as usize;
            !loop_info.contains(target)
        }
        BPF_EXIT => true,
        _ if op != BPF_CALL => {
            // Conditional jump - check both targets
            // 条件跳转 - 检查两个目标
            let target = (idx as i32 + insn.off as i32 + 1) as usize;
            let fallthrough = idx + 1;
            !loop_info.contains(target) || !loop_info.contains(fallthrough)
        }
        _ => false,
    }
}
