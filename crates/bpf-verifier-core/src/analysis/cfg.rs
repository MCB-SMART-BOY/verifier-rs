// SPDX-License-Identifier: GPL-2.0

//! Control flow graph analysis
//! 控制流图分析
//!
//! This module handles control flow analysis including:
//! 本模块处理控制流分析，包括：
//! - Building the CFG from instructions
//! - 从指令构建 CFG
//! - Detecting loops and back-edges
//! - 检测循环和回边
//! - Managing exploration of all paths
//! - 管理所有路径的探索
//! - State pruning and merging
//! - 状态剪枝和合并

use crate::core::error::{Result, VerifierError};
use crate::core::insn::{check_alu_op, check_call, check_cond_jmp_op, check_exit, check_ld_imm64};
use crate::core::types::*;
use crate::state::verifier_state::{BpfVerifierStackElem, BpfVerifierState, ExplorationStack};

use alloc::{format, vec, vec::Vec};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use super::states_equal::states_equal;

/// Information about a basic block
/// 基本块信息
#[derive(Debug, Clone, Default)]
pub struct BasicBlock {
    /// Start instruction index
    /// 起始指令索引
    pub start: usize,
    /// End instruction index (inclusive)
    /// 结束指令索引（包含）
    pub end: usize,
    /// Successor blocks
    /// 后继块
    pub successors: Vec<usize>,
    /// Predecessor blocks
    /// 前驱块
    pub predecessors: Vec<usize>,
}

/// Control flow graph
/// 控制流图
#[derive(Debug, Default)]
pub struct ControlFlowGraph {
    /// Map from start instruction to basic block
    /// 从起始指令到基本块的映射
    pub blocks: HashMap<usize, BasicBlock>,
    /// Entry block index
    /// 入口块索引
    pub entry: usize,
    /// All instruction indices that are jump targets
    /// 所有作为跳转目标的指令索引
    pub jump_targets: HashSet<usize>,
}

impl ControlFlowGraph {
    /// Build CFG from instructions
    /// 从指令构建 CFG
    pub fn build(insns: &[BpfInsn]) -> Result<Self> {
        let mut cfg = Self::default();

        if insns.is_empty() {
            return Ok(cfg);
        }

        // First pass: find all jump targets
        // 第一遍：找到所有跳转目标
        cfg.jump_targets.insert(0); // Entry point / 入口点

        for (i, insn) in insns.iter().enumerate() {
            let class = insn.class();

            if class == BPF_JMP || class == BPF_JMP32 {
                let op = insn.code & 0xf0;

                match op {
                    BPF_CALL => {
                        // Call might transfer to subprogram
                        // 调用可能转移到子程序
                        if insn.is_pseudo_call() {
                            let target = (i as i32 + insn.imm + 1) as usize;
                            cfg.jump_targets.insert(target);
                        }
                        // Fall-through is also a target
                        // 顺序执行也是一个目标
                        if i + 1 < insns.len() {
                            cfg.jump_targets.insert(i + 1);
                        }
                    }
                    BPF_EXIT => {
                        // No successors
                        // 没有后继
                    }
                    BPF_JA => {
                        // Unconditional jump
                        // 无条件跳转
                        let target = (i as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            cfg.jump_targets.insert(target);
                        }
                    }
                    _ => {
                        // Conditional jump
                        // 条件跳转
                        let target = (i as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            cfg.jump_targets.insert(target);
                        }
                        // Fall-through
                        // 顺序执行
                        if i + 1 < insns.len() {
                            cfg.jump_targets.insert(i + 1);
                        }
                    }
                }
            }

            // LD_IMM64 takes two slots
            // LD_IMM64 占用两个槽位
            if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                // Skip the second instruction
                // 跳过第二条指令
            }
        }

        // Second pass: build basic blocks
        // 第二遍：构建基本块
        let mut sorted_targets: Vec<usize> = cfg.jump_targets.iter().copied().collect();
        sorted_targets.sort();

        for (block_idx, &start) in sorted_targets.iter().enumerate() {
            let end = if block_idx + 1 < sorted_targets.len() {
                sorted_targets[block_idx + 1] - 1
            } else {
                insns.len() - 1
            };

            // Find successors
            // 查找后继
            let mut successors = Vec::new();
            if end < insns.len() {
                let last_insn = &insns[end];
                let class = last_insn.class();

                if class == BPF_JMP || class == BPF_JMP32 {
                    let op = last_insn.code & 0xf0;

                    match op {
                        BPF_EXIT => {
                            // No successors
                            // 没有后继
                        }
                        BPF_JA => {
                            let target = (end as i32 + last_insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                successors.push(target);
                            }
                        }
                        BPF_CALL if last_insn.is_pseudo_call() => {
                            let target = (end as i32 + last_insn.imm + 1) as usize;
                            if target < insns.len() {
                                successors.push(target);
                            }
                            // Return continues after call
                            // 返回后继续执行
                            if end + 1 < insns.len() {
                                successors.push(end + 1);
                            }
                        }
                        _ if op != BPF_CALL && op != BPF_EXIT => {
                            // Conditional jump
                            // 条件跳转
                            let target = (end as i32 + last_insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                successors.push(target);
                            }
                            if end + 1 < insns.len() {
                                successors.push(end + 1);
                            }
                        }
                        _ => {
                            // Regular call, continues to next instruction
                            // 常规调用，继续执行下一条指令
                            if end + 1 < insns.len() {
                                successors.push(end + 1);
                            }
                        }
                    }
                } else if end + 1 < insns.len() {
                    // Not a jump, falls through
                    // 不是跳转，顺序执行
                    successors.push(end + 1);
                }
            }

            cfg.blocks.insert(
                start,
                BasicBlock {
                    start,
                    end,
                    successors,
                    predecessors: Vec::new(),
                },
            );
        }

        // Third pass: fill in predecessors
        // 第三遍：填充前驱
        let block_starts: Vec<usize> = cfg.blocks.keys().copied().collect();
        for start in &block_starts {
            let successors = cfg
                .blocks
                .get(start)
                .map(|b| b.successors.clone())
                .unwrap_or_default();
            for succ in successors {
                if let Some(block) = cfg.blocks.get_mut(&succ) {
                    block.predecessors.push(*start);
                }
            }
        }

        Ok(cfg)
    }

    /// Check if there's a back-edge from `from` to `to`
    /// 检查从 `from` 到 `to` 是否存在回边
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        // A back-edge goes to an earlier block (loop)
        // 回边指向更早的块（循环）
        to <= from
    }

    /// Get all blocks in the CFG
    /// 获取 CFG 中的所有块
    pub fn all_blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// Compute postorder traversal of instructions within each subprogram.
    /// 计算每个子程序中指令的后序遍历。
    /// Returns a vector of instruction indices in postorder.
    /// 返回后序中的指令索引向量。
    /// This is useful for optimization passes that need reverse postorder.
    /// 这对于需要逆后序的优化遍历很有用。
    pub fn compute_postorder(&self, insns: &[BpfInsn], subprog_starts: &[usize]) -> Vec<usize> {
        let mut postorder = Vec::new();
        let mut state: Vec<u8> = vec![0; insns.len()]; // 0=unvisited, 1=discovered, 2=explored
                                                        // 0=未访问, 1=已发现, 2=已探索

        const DISCOVERED: u8 = 1;
        const EXPLORED: u8 = 2;

        for &start in subprog_starts {
            if start >= insns.len() || state[start] != 0 {
                continue;
            }

            let mut stack: Vec<usize> = vec![start];

            while let Some(&top) = stack.last() {
                if state[top] & DISCOVERED == 0 {
                    state[top] |= DISCOVERED;
                }

                if state[top] & EXPLORED != 0 {
                    postorder.push(top);
                    stack.pop();
                    continue;
                }

                // Get successors for this instruction
                // 获取此指令的后继
                let successors = self.get_insn_successors(insns, top);
                let mut pushed_any = false;

                for succ in successors {
                    if succ < insns.len() && state[succ] == 0 {
                        stack.push(succ);
                        state[succ] |= DISCOVERED;
                        pushed_any = true;
                    }
                }

                if !pushed_any {
                    state[top] |= EXPLORED;
                }
            }
        }

        postorder
    }

    /// Get successors for a single instruction (not a basic block)
    /// 获取单条指令的后继（不是基本块）
    fn get_insn_successors(&self, insns: &[BpfInsn], idx: usize) -> Vec<usize> {
        let mut successors = Vec::new();

        if idx >= insns.len() {
            return successors;
        }

        let insn = &insns[idx];
        let class = insn.class();

        // Handle LD_IMM64 which takes two instruction slots
        // 处理占用两个指令槽位的 LD_IMM64
        if insn.code == (BPF_LD | BPF_IMM | 0x18) {
            if idx + 2 < insns.len() {
                successors.push(idx + 2);
            }
            return successors;
        }

        if class == BPF_JMP || class == BPF_JMP32 {
            let op = insn.code & 0xf0;

            match op {
                BPF_EXIT => {
                    // No successors
                    // 没有后继
                }
                BPF_JA => {
                    let target = (idx as i32 + insn.off as i32 + 1) as usize;
                    if target < insns.len() {
                        successors.push(target);
                    }
                }
                BPF_CALL => {
                    // Regular call continues to next instruction
                    // 常规调用继续执行下一条指令
                    if idx + 1 < insns.len() {
                        successors.push(idx + 1);
                    }
                }
                _ => {
                    // Conditional jump: both fall-through and target
                    // 条件跳转：顺序执行和跳转目标
                    let target = (idx as i32 + insn.off as i32 + 1) as usize;
                    if target < insns.len() {
                        successors.push(target);
                    }
                    if idx + 1 < insns.len() {
                        successors.push(idx + 1);
                    }
                }
            }
        } else {
            // Non-jump instruction falls through
            // 非跳转指令顺序执行
            if idx + 1 < insns.len() {
                successors.push(idx + 1);
            }
        }

        successors
    }

    /// Get reverse postorder (useful for forward dataflow analysis)
    /// 获取逆后序（对前向数据流分析有用）
    pub fn compute_reverse_postorder(
        &self,
        insns: &[BpfInsn],
        subprog_starts: &[usize],
    ) -> Vec<usize> {
        let mut rpo = self.compute_postorder(insns, subprog_starts);
        rpo.reverse();
        rpo
    }

    /// Detect loop headers (targets of back edges)
    /// 检测循环头（回边的目标）
    /// Uses iterative DFS to avoid stack overflow in kernel mode
    /// 使用迭代式 DFS 以避免内核模式下的栈溢出
    pub fn find_loop_headers(&self, insns: &[BpfInsn]) -> HashSet<usize> {
        let mut loop_headers = HashSet::new();
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        if insns.is_empty() {
            return loop_headers;
        }

        // Iterative DFS
        // 迭代式 DFS
        // Each entry: (node_idx, next_successor_to_process, is_entering)
        // 每个条目：(节点索引, 下一个要处理的后继, 是否正在进入)
        // is_entering: true means we're just entering this node
        // is_entering：true 表示我们刚进入这个节点
        //              false means we're returning from a child
        //              false 表示我们从子节点返回
        let mut stack: Vec<(usize, usize, bool)> = Vec::new();
        stack.push((0, 0, true));

        while let Some((idx, succ_idx, is_entering)) = stack.pop() {
            if is_entering {
                // First time visiting this node
                // 第一次访问这个节点
                if visited.contains(&idx) {
                    continue;
                }
                visited.insert(idx);
                in_stack.insert(idx);
            }

            let successors = self.get_insn_successors(insns, idx);
            let mut found_unvisited = false;

            for (i, &succ) in successors.iter().enumerate().skip(succ_idx) {
                if in_stack.contains(&succ) {
                    // Back edge found - succ is a loop header
                    // 找到回边 - succ 是循环头
                    loop_headers.insert(succ);
                } else if !visited.contains(&succ) && succ < insns.len() {
                    // Push current node back to continue after child returns
                    // 将当前节点压回以便子节点返回后继续
                    stack.push((idx, i + 1, false));
                    // Push child to visit
                    // 压入要访问的子节点
                    stack.push((succ, 0, true));
                    found_unvisited = true;
                    break;
                }
            }

            // If no unvisited successors, we're done with this node
            // 如果没有未访问的后继，则此节点处理完成
            if !found_unvisited {
                in_stack.remove(&idx);
            }
        }

        loop_headers
    }
}

/// Explored states at each instruction
/// 每条指令处的已探索状态
#[derive(Debug, Default)]
pub struct ExploredStates {
    /// States at each instruction index
    /// 每个指令索引处的状态
    states: HashMap<usize, Vec<BpfVerifierState>>,
    /// Total number of states
    /// 状态总数
    pub total_states: usize,
    /// Peak states encountered
    /// 遇到的峰值状态数
    pub peak_states: usize,
}

impl ExploredStates {
    /// Create a new explored states tracker
    /// 创建新的已探索状态跟踪器
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a state at an instruction
    /// 在某指令处添加状态
    pub fn add_state(&mut self, insn_idx: usize, state: BpfVerifierState) {
        self.states.entry(insn_idx).or_default().push(state);
        self.total_states += 1;
        self.peak_states = self.peak_states.max(self.total_states);
    }

    /// Get states at an instruction
    /// 获取某指令处的状态
    pub fn get_states(&self, insn_idx: usize) -> Option<&Vec<BpfVerifierState>> {
        self.states.get(&insn_idx)
    }

    /// Check if a state is equivalent to any existing state at this instruction
    /// 检查某状态是否与此指令处的任何现有状态等价
    pub fn find_equivalent(&self, insn_idx: usize, state: &BpfVerifierState) -> Option<usize> {
        if let Some(states) = self.states.get(&insn_idx) {
            for (i, existing) in states.iter().enumerate() {
                if states_equal(state, existing) {
                    return Some(i);
                }
            }
        }
        None
    }
}

// Note: states_equal is provided by the states_equal module for state comparison
// 注意：states_equal 由 states_equal 模块提供用于状态比较

/// Verifier context for CFG-based verification
/// 基于 CFG 的验证器上下文
pub struct Verifier {
    /// Program instructions
    /// 程序指令
    pub insns: Vec<BpfInsn>,
    /// Control flow graph
    /// 控制流图
    pub cfg: ControlFlowGraph,
    /// Current state
    /// 当前状态
    pub cur_state: BpfVerifierState,
    /// Exploration stack
    /// 探索栈
    pub stack: ExplorationStack,
    /// Explored states
    /// 已探索状态
    pub explored: ExploredStates,
    /// Subprogram information
    /// 子程序信息
    pub subprogs: Vec<BpfSubprogInfo>,
    /// Whether in privileged mode
    /// 是否处于特权模式
    pub allow_ptr_leaks: bool,
    /// Whether program is sleepable
    /// 程序是否可睡眠
    pub in_sleepable: bool,
    /// Current instruction index
    /// 当前指令索引
    pub insn_idx: usize,
    /// Previous instruction index
    /// 上一条指令索引
    pub prev_insn_idx: usize,
}

impl Verifier {
    /// Create a new verifier for a program
    /// 为程序创建新的验证器
    pub fn new(insns: Vec<BpfInsn>, allow_ptr_leaks: bool) -> Result<Self> {
        let cfg = ControlFlowGraph::build(&insns)?;

        Ok(Self {
            insns,
            cfg,
            cur_state: BpfVerifierState::new(),
            stack: ExplorationStack::new(),
            explored: ExploredStates::new(),
            subprogs: Vec::new(),
            allow_ptr_leaks,
            in_sleepable: false,
            insn_idx: 0,
            prev_insn_idx: 0,
        })
    }

    /// Verify the program
    /// 验证程序
    pub fn verify(&mut self) -> Result<()> {
        // First pass: check CFG structure
        // 第一遍：检查 CFG 结构
        self.check_cfg()?;

        // Add subprograms
        // 添加子程序
        self.add_subprogs()?;

        // Main verification loop
        // 主验证循环
        self.do_check()
    }

    /// Check CFG for issues (unreachable code, invalid jumps)
    /// 检查 CFG 是否有问题（不可达代码、无效跳转）
    fn check_cfg(&self) -> Result<()> {
        // Check all instructions are reachable
        // 检查所有指令是否可达
        let mut reachable = HashSet::new();
        let mut to_visit = vec![0usize];

        while let Some(idx) = to_visit.pop() {
            if reachable.contains(&idx) {
                continue;
            }
            if idx >= self.insns.len() {
                return Err(VerifierError::InvalidJumpDestination(idx as i32));
            }
            reachable.insert(idx);

            let insn = &self.insns[idx];
            let class = insn.class();

            // Handle LD_IMM64 which takes two instruction slots
            // 处理占用两个指令槽位的 LD_IMM64
            if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                to_visit.push(idx + 2);
                continue;
            }

            if class == BPF_JMP || class == BPF_JMP32 {
                let op = insn.code & 0xf0;

                match op {
                    BPF_EXIT => {
                        // No successors
                        // 没有后继
                    }
                    BPF_JA => {
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        to_visit.push(target);
                    }
                    BPF_CALL => {
                        to_visit.push(idx + 1);
                    }
                    _ => {
                        // Conditional
                        // 条件跳转
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        to_visit.push(target);
                        to_visit.push(idx + 1);
                    }
                }
            } else {
                to_visit.push(idx + 1);
            }
        }

        // Check for unreachable instructions
        // 检查不可达指令
        for i in 0..self.insns.len() {
            if !reachable.contains(&i) {
                // Skip second slot of LD_IMM64
                // 跳过 LD_IMM64 的第二个槽位
                if i > 0 && self.insns[i - 1].code == (BPF_LD | BPF_IMM | 0x18) {
                    continue;
                }
                return Err(VerifierError::UnreachableInstruction(i));
            }
        }

        Ok(())
    }

    /// Find and add subprograms
    /// 查找并添加子程序
    fn add_subprogs(&mut self) -> Result<()> {
        // Main program is subprog 0
        // 主程序是子程序 0
        self.subprogs.push(BpfSubprogInfo {
            start: 0,
            ..Default::default()
        });

        // Find call targets
        // 查找调用目标
        for (i, insn) in self.insns.iter().enumerate() {
            if insn.is_pseudo_call() {
                let target = (i as i32 + insn.imm + 1) as usize;
                if target >= self.insns.len() {
                    return Err(VerifierError::InvalidJumpDestination(target as i32));
                }

                // Check if already added
                // 检查是否已添加
                if !self.subprogs.iter().any(|s| s.start == target) {
                    self.subprogs.push(BpfSubprogInfo {
                        start: target,
                        ..Default::default()
                    });
                }
            }
        }

        // Sort by start
        // 按起始位置排序
        self.subprogs.sort_by_key(|s| s.start);

        Ok(())
    }

    /// Main verification loop
    /// 主验证循环
    fn do_check(&mut self) -> Result<()> {
        // Set up initial state
        // 设置初始状态
        if let Some(func) = self.cur_state.cur_func_mut() {
            // R1 is context pointer
            // R1 是上下文指针
            func.regs[1].reg_type = BpfRegType::PtrToCtx;
            func.regs[1].mark_known_zero();
        }

        loop {
            // Check state complexity
            // 检查状态复杂度
            if self.explored.total_states > BPF_COMPLEXITY_LIMIT_STATES * self.insns.len() {
                return Err(VerifierError::TooComplex(format!(
                    "exceeded {} states",
                    BPF_COMPLEXITY_LIMIT_STATES * self.insns.len()
                )));
            }

            // Check if this state was already visited
            // 检查此状态是否已被访问
            if self
                .explored
                .find_equivalent(self.insn_idx, &self.cur_state)
                .is_some()
            {
                // State is equivalent to an existing one, prune this path
                // 状态与现有状态等价，剪枝此路径
                if !self.pop_state()? {
                    break; // No more states to explore / 没有更多状态可探索
                }
                continue;
            }

            // Add current state to explored
            // 将当前状态添加到已探索集合
            self.explored
                .add_state(self.insn_idx, self.cur_state.clone());

            // Process the instruction
            // 处理指令
            let continue_check = self.do_check_insn()?;

            if !continue_check {
                // Instruction ended this path (EXIT or error)
                // 指令结束了此路径（EXIT 或错误）
                if !self.pop_state()? {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single instruction
    /// 处理单条指令
    fn do_check_insn(&mut self) -> Result<bool> {
        if self.insn_idx >= self.insns.len() {
            return Err(VerifierError::InvalidInstruction(self.insn_idx));
        }

        let insn = self.insns[self.insn_idx];
        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => {
                check_alu_op(&mut self.cur_state, &insn, self.allow_ptr_leaks)?;
                self.insn_idx += 1;
            }
            BPF_LDX => {
                // Load from memory
                // 从内存加载
                self.check_ldx(&insn)?;
                self.insn_idx += 1;
            }
            BPF_STX | BPF_ST => {
                // Store to memory
                // 存储到内存
                self.check_stx(&insn)?;
                self.insn_idx += 1;
            }
            BPF_LD => {
                if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                    // LD_IMM64
                    if self.insn_idx + 1 >= self.insns.len() {
                        return Err(VerifierError::InvalidInstruction(self.insn_idx));
                    }
                    let next_insn = self.insns[self.insn_idx + 1];
                    check_ld_imm64(&mut self.cur_state, &insn, &next_insn)?;
                    self.insn_idx += 2;
                } else {
                    // Other LD instructions
                    // 其他 LD 指令
                    self.insn_idx += 1;
                }
            }
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;

                match op {
                    BPF_EXIT => {
                        check_exit(&self.cur_state)?;
                        return Ok(false); // End of path / 路径结束
                    }
                    BPF_CALL => {
                        check_call(&mut self.cur_state, &insn, self.insn_idx)?;
                        self.insn_idx += 1;
                    }
                    BPF_JA => {
                        let target = (self.insn_idx as i32 + insn.off as i32 + 1) as usize;
                        self.insn_idx = target;
                    }
                    _ => {
                        // Conditional jump
                        // 条件跳转
                        let (fall_through, target) = check_cond_jmp_op(
                            &mut self.cur_state,
                            &insn,
                            self.insn_idx,
                            self.allow_ptr_leaks,
                        )?;

                        if let Some(target_idx) = target {
                            // Push target path to stack
                            // 将目标路径压入栈
                            let mut target_state = self.cur_state.clone();
                            target_state.branches += 1;
                            self.stack.push(BpfVerifierStackElem::new(
                                target_state,
                                target_idx,
                                self.insn_idx,
                            ))?;
                        }

                        if let Some(ft_idx) = fall_through {
                            self.insn_idx = ft_idx;
                        } else {
                            return Ok(false);
                        }
                    }
                }
            }
            _ => {
                return Err(VerifierError::InvalidInstruction(self.insn_idx));
            }
        }

        Ok(true)
    }

    /// Check LDX instruction
    /// 检查 LDX 指令
    fn check_ldx(&mut self, insn: &BpfInsn) -> Result<()> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;

        // Source must be a valid pointer
        // 源必须是有效指针
        let src = self
            .cur_state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
        if !(src.is_pointer() || (src.reg_type == BpfRegType::ScalarValue && src.is_const())) {
            return Err(VerifierError::InvalidMemoryAccess(
                "LDX source must be a pointer".into(),
            ));
        }

        // Perform load - result is usually a scalar
        // 执行加载 - 结果通常是标量
        if let Some(dst) = self.cur_state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
        }

        Ok(())
    }

    /// Check STX instruction
    /// 检查 STX 指令
    fn check_stx(&mut self, insn: &BpfInsn) -> Result<()> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;

        // Destination must be a valid pointer
        // 目标必须是有效指针
        let dst = self
            .cur_state
            .reg(dst_reg)
            .ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;
        if !dst.is_pointer() {
            return Err(VerifierError::InvalidMemoryAccess(
                "STX destination must be a pointer".into(),
            ));
        }

        // Source must be initialized
        // 源必须已初始化
        let src = self
            .cur_state
            .reg(src_reg)
            .ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check for pointer leaks
        // 检查指针泄漏
        if !self.allow_ptr_leaks && src.is_pointer() {
            // Storing pointers to maps or other memory may leak them
            // 将指针存储到 map 或其他内存可能会泄漏它们
            if dst.reg_type == BpfRegType::PtrToMapValue {
                // Check if map allows pointer storage
                // 检查 map 是否允许存储指针
            }
        }

        Ok(())
    }

    /// Pop next state from exploration stack
    /// 从探索栈弹出下一个状态
    fn pop_state(&mut self) -> Result<bool> {
        match self.stack.pop() {
            Some(elem) => {
                self.cur_state = elem.st;
                self.insn_idx = elem.insn_idx;
                self.prev_insn_idx = elem.prev_insn_idx;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
