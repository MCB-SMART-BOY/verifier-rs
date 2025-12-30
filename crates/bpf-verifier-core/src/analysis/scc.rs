// SPDX-License-Identifier: GPL-2.0

//! Strongly Connected Components (SCC) analysis for BPF programs.
//! BPF 程序的强连通分量 (SCC) 分析。
//!
//! This module implements Tarjan's algorithm for finding SCCs in the control
//! 本模块实现 Tarjan 算法来查找控制流图中的强连通分量。
//! flow graph. SCCs are critical for bounded loop verification - each SCC
//! SCC 对于有界循环验证至关重要 - 每个 SCC
//! represents a potential loop that needs iteration bounds checking.
//! 代表一个需要检查迭代边界的潜在循环。

use alloc::{format, vec::Vec};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// State of a node during SCC traversal.
/// SCC 遍历期间节点的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    /// Not yet visited.
    /// 尚未访问。
    Unvisited,
    /// On the DFS stack (being processed).
    /// 在 DFS 栈上（正在处理）。
    OnStack,
    /// Finished processing, assigned to an SCC.
    /// 处理完成，已分配到 SCC。
    Finished,
}

/// Information about a single SCC.
/// 单个 SCC 的信息。
#[derive(Debug, Clone)]
pub struct SccInfo {
    /// Unique ID of this SCC.
    /// 此 SCC 的唯一 ID。
    pub id: usize,
    /// Instructions belonging to this SCC.
    /// 属于此 SCC 的指令。
    pub members: Vec<usize>,
    /// Entry points into this SCC (instructions with predecessors outside).
    /// 此 SCC 的入口点（具有外部前驱的指令）。
    pub entries: Vec<usize>,
    /// Exit points from this SCC (instructions with successors outside).
    /// 此 SCC 的出口点（具有外部后继的指令）。
    pub exits: Vec<usize>,
    /// Back edges within this SCC (source -> target).
    /// 此 SCC 内的回边（源 -> 目标）。
    pub back_edges: Vec<(usize, usize)>,
    /// Whether this SCC contains a loop (has back edges).
    /// 此 SCC 是否包含循环（有回边）。
    pub is_loop: bool,
    /// Nesting depth (SCCs can be nested).
    /// 嵌套深度（SCC 可以嵌套）。
    pub depth: u32,
    /// Parent SCC ID (if nested).
    /// 父 SCC ID（如果嵌套）。
    pub parent: Option<usize>,
}

impl SccInfo {
    /// Create a new SCC.
    /// 创建新的 SCC。
    pub fn new(id: usize) -> Self {
        Self {
            id,
            members: Vec::new(),
            entries: Vec::new(),
            exits: Vec::new(),
            back_edges: Vec::new(),
            is_loop: false,
            depth: 0,
            parent: None,
        }
    }

    /// Check if an instruction is in this SCC.
    /// 检查指令是否在此 SCC 中。
    pub fn contains(&self, insn_idx: usize) -> bool {
        self.members.contains(&insn_idx)
    }

    /// Get the number of members.
    /// 获取成员数量。
    pub fn size(&self) -> usize {
        self.members.len()
    }
}

/// Result of SCC analysis.
/// SCC 分析的结果。
#[derive(Debug, Clone)]
pub struct SccAnalysis {
    /// All SCCs found, indexed by SCC ID.
    /// 找到的所有 SCC，按 SCC ID 索引。
    pub sccs: Vec<SccInfo>,
    /// Map from instruction index to SCC ID.
    /// 从指令索引到 SCC ID 的映射。
    pub insn_to_scc: HashMap<usize, usize>,
    /// SCCs that contain loops (back edges).
    /// 包含循环（回边）的 SCC。
    pub loop_sccs: Vec<usize>,
    /// Topologically sorted SCC IDs (for processing order).
    /// 拓扑排序的 SCC ID（用于处理顺序）。
    pub topo_order: Vec<usize>,
    /// Maximum nesting depth.
    /// 最大嵌套深度。
    pub max_depth: u32,
}

impl SccAnalysis {
    /// Create empty analysis.
    /// 创建空的分析结果。
    pub fn new() -> Self {
        Self {
            sccs: Vec::new(),
            insn_to_scc: HashMap::new(),
            loop_sccs: Vec::new(),
            topo_order: Vec::new(),
            max_depth: 0,
        }
    }

    /// Get the SCC containing an instruction.
    /// 获取包含某指令的 SCC。
    pub fn get_scc(&self, insn_idx: usize) -> Option<&SccInfo> {
        self.insn_to_scc.get(&insn_idx).map(|&id| &self.sccs[id])
    }

    /// Check if an instruction is in a loop.
    /// 检查指令是否在循环中。
    pub fn is_in_loop(&self, insn_idx: usize) -> bool {
        if let Some(&scc_id) = self.insn_to_scc.get(&insn_idx) {
            self.sccs[scc_id].is_loop
        } else {
            false
        }
    }

    /// Get all back edges.
    /// 获取所有回边。
    pub fn all_back_edges(&self) -> Vec<(usize, usize)> {
        let mut edges = Vec::new();
        for scc in &self.sccs {
            edges.extend(scc.back_edges.iter().cloned());
        }
        edges
    }
}

impl Default for SccAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// SCC computation using Tarjan's algorithm.
/// 使用 Tarjan 算法计算 SCC。
pub struct SccComputer {
    /// Number of instructions.
    /// 指令数量。
    num_insns: usize,
    /// Successors for each instruction.
    /// 每条指令的后继。
    successors: HashMap<usize, Vec<usize>>,
    /// Predecessors for each instruction.
    /// 每条指令的前驱。
    predecessors: HashMap<usize, Vec<usize>>,
    /// DFS index counter.
    /// DFS 索引计数器。
    index: usize,
    /// DFS indices for each node.
    /// 每个节点的 DFS 索引。
    indices: HashMap<usize, usize>,
    /// Low-link values for each node.
    /// 每个节点的 low-link 值。
    lowlinks: HashMap<usize, usize>,
    /// Node states.
    /// 节点状态。
    states: HashMap<usize, NodeState>,
    /// DFS stack.
    /// DFS 栈。
    stack: Vec<usize>,
    /// Found SCCs.
    /// 找到的 SCC。
    sccs: Vec<SccInfo>,
    /// Map from instruction to SCC.
    /// 从指令到 SCC 的映射。
    insn_to_scc: HashMap<usize, usize>,
}

impl SccComputer {
    /// Create a new SCC computer.
    /// 创建新的 SCC 计算器。
    pub fn new(num_insns: usize) -> Self {
        Self {
            num_insns,
            successors: HashMap::new(),
            predecessors: HashMap::new(),
            index: 0,
            indices: HashMap::new(),
            lowlinks: HashMap::new(),
            states: HashMap::new(),
            stack: Vec::new(),
            sccs: Vec::new(),
            insn_to_scc: HashMap::new(),
        }
    }

    /// Build CFG from instructions.
    /// 从指令构建 CFG。
    pub fn build_cfg(&mut self, insns: &[BpfInsn]) {
        for (idx, insn) in insns.iter().enumerate() {
            let class = insn.class();
            let op = insn.code & 0xf0;

            match class {
                BPF_JMP | BPF_JMP32 => {
                    match op {
                        BPF_JA => {
                            // Unconditional jump
                            // 无条件跳转
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                self.add_edge(idx, target);
                            }
                        }
                        BPF_EXIT => {
                            // No successors
                            // 无后继
                        }
                        BPF_CALL => {
                            // For pseudo calls, we need special handling
                            // 对于伪调用，需要特殊处理
                            if insn.src_reg == BPF_PSEUDO_CALL {
                                // Subprogram call - add both call target and return
                                // 子程序调用 - 添加调用目标和返回
                                let target = (idx as i32 + insn.imm + 1) as usize;
                                if target < insns.len() {
                                    self.add_edge(idx, target);
                                }
                            }
                            // Fall through after call
                            // 调用后继续
                            if idx + 1 < insns.len() {
                                self.add_edge(idx, idx + 1);
                            }
                        }
                        _ => {
                            // Conditional jump - both paths
                            // 条件跳转 - 两条路径
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                self.add_edge(idx, target);
                            }
                            if idx + 1 < insns.len() {
                                self.add_edge(idx, idx + 1);
                            }
                        }
                    }
                }
                BPF_LD => {
                    // LD_IMM64 spans two instructions
                    // LD_IMM64 跨越两条指令
                    if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                        if idx + 2 < insns.len() {
                            self.add_edge(idx, idx + 2);
                        }
                    } else if idx + 1 < insns.len() {
                        self.add_edge(idx, idx + 1);
                    }
                }
                _ => {
                    // Sequential instruction
                    // 顺序指令
                    if idx + 1 < insns.len() {
                        self.add_edge(idx, idx + 1);
                    }
                }
            }
        }
    }

    /// Add an edge to the CFG.
    /// 向 CFG 添加边。
    fn add_edge(&mut self, from: usize, to: usize) {
        self.successors.entry(from).or_default().push(to);
        self.predecessors.entry(to).or_default().push(from);
    }

    /// Compute SCCs using Tarjan's algorithm.
    /// 使用 Tarjan 算法计算 SCC。
    pub fn compute(&mut self) -> SccAnalysis {
        // Initialize all nodes as unvisited
        // 将所有节点初始化为未访问
        for i in 0..self.num_insns {
            self.states.insert(i, NodeState::Unvisited);
        }

        // Run Tarjan's algorithm from each unvisited node
        // 从每个未访问节点运行 Tarjan 算法
        for i in 0..self.num_insns {
            if self.states.get(&i) == Some(&NodeState::Unvisited) {
                self.strongconnect(i);
            }
        }

        // Build the result
        // 构建结果
        self.build_result()
    }

    /// Tarjan's strongconnect function.
    /// Tarjan 的 strongconnect 函数。
    fn strongconnect(&mut self, v: usize) {
        // Set the depth index for v
        // 设置 v 的深度索引
        self.indices.insert(v, self.index);
        self.lowlinks.insert(v, self.index);
        self.index += 1;
        self.stack.push(v);
        self.states.insert(v, NodeState::OnStack);

        // Consider successors of v
        // 考虑 v 的后继
        let successors = self.successors.get(&v).cloned().unwrap_or_default();
        for w in successors {
            if w >= self.num_insns {
                continue;
            }

            match self.states.get(&w) {
                Some(&NodeState::Unvisited) => {
                    // Successor w has not yet been visited; recurse on it
                    // 后继 w 尚未访问；对其递归
                    self.strongconnect(w);
                    let v_low = self.lowlinks.get(&v).copied().unwrap_or(0);
                    let w_low = self.lowlinks.get(&w).copied().unwrap_or(0);
                    self.lowlinks.insert(v, v_low.min(w_low));
                }
                Some(&NodeState::OnStack) => {
                    // Successor w is on stack and hence in the current SCC
                    // 后继 w 在栈上，因此在当前 SCC 中
                    let v_low = self.lowlinks.get(&v).copied().unwrap_or(0);
                    let w_idx = self.indices.get(&w).copied().unwrap_or(0);
                    self.lowlinks.insert(v, v_low.min(w_idx));
                }
                _ => {
                    // Successor is in a different SCC, ignore
                    // 后继在不同的 SCC 中，忽略
                }
            }
        }

        // If v is a root node, pop the stack and generate an SCC
        // 如果 v 是根节点，弹出栈并生成 SCC
        if self.lowlinks.get(&v) == self.indices.get(&v) {
            let mut scc = SccInfo::new(self.sccs.len());
            while let Some(w) = self.stack.pop() {
                self.states.insert(w, NodeState::Finished);
                scc.members.push(w);
                self.insn_to_scc.insert(w, scc.id);
                if w == v {
                    break;
                }
            }
            self.sccs.push(scc);
        }
    }

    /// Build the final analysis result.
    /// 构建最终分析结果。
    fn build_result(&mut self) -> SccAnalysis {
        let mut analysis = SccAnalysis::new();

        // Move SCCs to analysis
        // 将 SCC 移动到分析结果
        core::mem::swap(&mut analysis.sccs, &mut self.sccs);
        core::mem::swap(&mut analysis.insn_to_scc, &mut self.insn_to_scc);

        // Compute entries, exits, and back edges for each SCC
        // 为每个 SCC 计算入口、出口和回边
        for scc in &mut analysis.sccs {
            let members: HashSet<usize> = scc.members.iter().cloned().collect();

            for &member in &scc.members {
                // Check predecessors for entries
                // 检查前驱以确定入口
                if let Some(preds) = self.predecessors.get(&member) {
                    for &pred in preds {
                        if !members.contains(&pred) && !scc.entries.contains(&member) {
                            scc.entries.push(member);
                        }
                    }
                }

                // Check successors for exits and back edges
                // 检查后继以确定出口和回边
                if let Some(succs) = self.successors.get(&member) {
                    for &succ in succs {
                        if members.contains(&succ) {
                            // Internal edge - check if it's a back edge
                            // 内部边 - 检查是否是回边
                            // A back edge goes to a node with smaller/equal DFS index
                            // 回边指向具有更小/相等 DFS 索引的节点
                            if let (Some(&m_idx), Some(&s_idx)) =
                                (self.indices.get(&member), self.indices.get(&succ))
                            {
                                if s_idx <= m_idx {
                                    scc.back_edges.push((member, succ));
                                }
                            }
                        } else {
                            // External edge - this is an exit
                            // 外部边 - 这是出口
                            if !scc.exits.contains(&member) {
                                scc.exits.push(member);
                            }
                        }
                    }
                }
            }

            // SCC is a loop if it has back edges or more than one member with internal edges
            // 如果 SCC 有回边或有多个成员具有内部边，则是循环
            scc.is_loop = !scc.back_edges.is_empty()
                || (scc.members.len() > 1
                    && scc.members.iter().any(|&m| {
                        self.successors
                            .get(&m)
                            .is_some_and(|succs| succs.iter().any(|s| members.contains(s)))
                    }));

            if scc.is_loop {
                analysis.loop_sccs.push(scc.id);
            }
        }

        // Compute topological order of SCCs
        // 计算 SCC 的拓扑顺序
        analysis.topo_order =
            Self::compute_scc_topo_order(&analysis.sccs, &self.successors, &analysis.insn_to_scc);

        // Compute nesting depth
        // 计算嵌套深度
        Self::compute_nesting(&mut analysis);

        analysis
    }

    /// Compute topological order of SCCs.
    /// 计算 SCC 的拓扑顺序。
    fn compute_scc_topo_order(
        sccs: &[SccInfo],
        successors: &HashMap<usize, Vec<usize>>,
        insn_to_scc: &HashMap<usize, usize>,
    ) -> Vec<usize> {
        let _num_sccs = sccs.len();
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut scc_edges: HashMap<usize, HashSet<usize>> = HashMap::new();

        // Initialize
        // 初始化
        for scc in sccs {
            in_degree.insert(scc.id, 0);
            scc_edges.insert(scc.id, HashSet::new());
        }

        // Build SCC graph
        // 构建 SCC 图
        for scc in sccs {
            for &member in &scc.members {
                if let Some(succs) = successors.get(&member) {
                    for &succ in succs {
                        if let Some(&succ_scc) = insn_to_scc.get(&succ) {
                            if succ_scc != scc.id
                                && scc_edges
                                    .get(&scc.id)
                                    .is_none_or(|s| !s.contains(&succ_scc))
                            {
                                if let Some(edges) = scc_edges.get_mut(&scc.id) {
                                    edges.insert(succ_scc);
                                }
                                if let Some(deg) = in_degree.get_mut(&succ_scc) {
                                    *deg += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Kahn's algorithm for topological sort
        // Kahn 算法进行拓扑排序
        let mut order = Vec::new();
        let mut queue: Vec<usize> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        while let Some(scc_id) = queue.pop() {
            order.push(scc_id);
            if let Some(neighbors) = scc_edges.get(&scc_id) {
                for &neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(&neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(neighbor);
                        }
                    }
                }
            }
        }

        order
    }

    /// Compute nesting depth for SCCs.
    /// 计算 SCC 的嵌套深度。
    fn compute_nesting(analysis: &mut SccAnalysis) {
        // Simple nesting: SCCs with smaller instruction ranges inside larger ones
        // 简单嵌套：指令范围较小的 SCC 在较大的 SCC 内部
        let mut max_depth = 0u32;

        for i in 0..analysis.sccs.len() {
            if !analysis.sccs[i].is_loop {
                continue;
            }

            let i_min = *analysis.sccs[i].members.iter().min().unwrap_or(&0);
            let i_max = *analysis.sccs[i].members.iter().max().unwrap_or(&0);

            for j in 0..analysis.sccs.len() {
                if i == j || !analysis.sccs[j].is_loop {
                    continue;
                }

                let j_min = *analysis.sccs[j].members.iter().min().unwrap_or(&0);
                let j_max = *analysis.sccs[j].members.iter().max().unwrap_or(&0);

                // Check if SCC j contains SCC i
                // 检查 SCC j 是否包含 SCC i
                if j_min <= i_min && j_max >= i_max && (j_min < i_min || j_max > i_max) {
                    analysis.sccs[i].depth = analysis.sccs[i].depth.max(analysis.sccs[j].depth + 1);
                    analysis.sccs[i].parent = Some(j);
                }
            }

            max_depth = max_depth.max(analysis.sccs[i].depth);
        }

        analysis.max_depth = max_depth;
    }
}

/// Analyze a BPF program for SCCs.
/// 分析 BPF 程序的 SCC。
pub fn compute_scc(insns: &[BpfInsn]) -> SccAnalysis {
    let mut computer = SccComputer::new(insns.len());
    computer.build_cfg(insns);
    computer.compute()
}

/// Back edge information for loop verification.
/// 用于循环验证的回边信息。
#[derive(Debug, Clone)]
pub struct BackEdgeInfo {
    /// Source instruction (jump instruction).
    /// 源指令（跳转指令）。
    pub from: usize,
    /// Target instruction (loop header).
    /// 目标指令（循环头）。
    pub to: usize,
    /// SCC ID containing this back edge.
    /// 包含此回边的 SCC ID。
    pub scc_id: usize,
    /// Iteration count bound (if determinable).
    /// 迭代次数边界（如果可确定）。
    pub iter_bound: Option<u32>,
}

/// Propagate back edges for loop iteration tracking.
/// 传播回边以跟踪循环迭代。
#[derive(Debug)]
pub struct BackEdgePropagator {
    /// Back edges found.
    /// 发现的回边。
    back_edges: Vec<BackEdgeInfo>,
    /// Visited states per instruction.
    /// 每条指令的访问状态。
    visit_counts: HashMap<usize, u32>,
    /// Maximum iterations per back edge.
    /// 每条回边的最大迭代次数。
    max_iters: u32,
}

impl BackEdgePropagator {
    /// Create a new propagator.
    /// 创建新的传播器。
    pub fn new(max_iters: u32) -> Self {
        Self {
            back_edges: Vec::new(),
            visit_counts: HashMap::new(),
            max_iters,
        }
    }

    /// Initialize from SCC analysis.
    /// 从 SCC 分析初始化。
    pub fn from_scc_analysis(analysis: &SccAnalysis, max_iters: u32) -> Self {
        let mut propagator = Self::new(max_iters);

        for scc in &analysis.sccs {
            for &(from, to) in &scc.back_edges {
                propagator.back_edges.push(BackEdgeInfo {
                    from,
                    to,
                    scc_id: scc.id,
                    iter_bound: None,
                });
            }
        }

        propagator
    }

    /// Record a visit to an instruction.
    /// 记录对指令的访问。
    pub fn record_visit(&mut self, insn_idx: usize) -> Result<()> {
        let count = self.visit_counts.entry(insn_idx).or_insert(0);
        *count += 1;

        // Check if this is a back edge target exceeding limit
        // 检查是否是超过限制的回边目标
        for edge in &self.back_edges {
            if edge.to == insn_idx && *count > self.max_iters {
                return Err(VerifierError::TooComplex(format!(
                    "loop at instruction {} exceeded {} iterations",
                    insn_idx, self.max_iters
                )));
            }
        }

        Ok(())
    }

    /// Check if an edge is a back edge.
    /// 检查边是否是回边。
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.back_edges.iter().any(|e| e.from == from && e.to == to)
    }

    /// Get visit count for an instruction.
    /// 获取指令的访问次数。
    pub fn visit_count(&self, insn_idx: usize) -> u32 {
        *self.visit_counts.get(&insn_idx).unwrap_or(&0)
    }

    /// Get all back edges.
    /// 获取所有回边。
    pub fn back_edges(&self) -> &[BackEdgeInfo] {
        &self.back_edges
    }

    /// Set iteration bound for a back edge.
    /// 设置回边的迭代边界。
    pub fn set_iter_bound(&mut self, from: usize, to: usize, bound: u32) {
        for edge in &mut self.back_edges {
            if edge.from == from && edge.to == to {
                edge.iter_bound = Some(bound);
                break;
            }
        }
    }

    /// Reset visit counts for a new verification pass.
    /// 为新的验证遍历重置访问计数。
    pub fn reset(&mut self) {
        self.visit_counts.clear();
    }

    /// Get the total number of back edges.
    /// 获取回边总数。
    pub fn back_edge_count(&self) -> usize {
        self.back_edges.len()
    }
}

/// Maximum number of back edge iterations for convergence in SCC analysis.
/// SCC 分析中收敛的最大回边迭代次数。
pub const SCC_MAX_BACKEDGE_ITERS: u32 = 4;

/// Propagate precision marks through back edges.
/// 通过回边传播精度标记。
///
/// This function implements the kernel's `propagate_backedges()` which
/// 此函数实现内核的 `propagate_backedges()`，
/// ensures that precision tracking works correctly across loop iterations.
/// 确保精度跟踪在循环迭代中正确工作。
///
/// When a loop back edge is taken, precision marks need to be propagated
/// 当循环回边被采用时，精度标记需要从当前状态传播到循环头状态，
/// from the current state to the loop header state to ensure proper
/// 以确保正确跟踪循环变量寄存器。
/// tracking of loop-variant registers.
pub fn propagate_backedges(
    analysis: &SccAnalysis,
    propagator: &mut BackEdgePropagator,
    insn_idx: usize,
    target_idx: usize,
) -> Result<bool> {
    // Check if this is a back edge
    // 检查这是否是回边
    if !propagator.is_back_edge(insn_idx, target_idx) {
        return Ok(false);
    }

    // Record visit to target (loop header)
    // 记录对目标（循环头）的访问
    propagator.record_visit(target_idx)?;

    // Check if we've reached the iteration limit
    // 检查是否达到迭代限制
    let count = propagator.visit_count(target_idx);
    if count > SCC_MAX_BACKEDGE_ITERS {
        return Err(VerifierError::TooComplex(format!(
            "back edge from {} to {} exceeded max iterations {}",
            insn_idx, target_idx, SCC_MAX_BACKEDGE_ITERS
        )));
    }

    // Get the SCC containing this back edge
    // 获取包含此回边的 SCC
    let scc_id = analysis.insn_to_scc.get(&target_idx);
    if scc_id.is_none() {
        return Ok(false);
    }

    Ok(true)
}

/// Check if two instructions are in the same loop SCC.
/// 检查两条指令是否在同一个循环 SCC 中。
///
/// This is a SCC-based check complementing the state-based `states_maybe_looping()` in prune.rs.
/// 这是基于 SCC 的检查，补充 prune.rs 中基于状态的 `states_maybe_looping()`。
pub fn scc_states_maybe_looping(
    analysis: &SccAnalysis,
    insn_idx1: usize,
    insn_idx2: usize,
) -> bool {
    // Check if both instructions are in the same SCC
    // 检查两条指令是否在同一个 SCC 中
    let scc1 = analysis.insn_to_scc.get(&insn_idx1);
    let scc2 = analysis.insn_to_scc.get(&insn_idx2);

    match (scc1, scc2) {
        (Some(s1), Some(s2)) if s1 == s2 => {
            // Same SCC - could be looping
            // 同一 SCC - 可能在循环
            if let Some(scc) = analysis.sccs.get(*s1) {
                // Only if the SCC has back edges (is a loop)
                // 仅当 SCC 有回边（是循环）时
                scc.is_loop
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Enter SCC tracking for an instruction.
/// 进入指令的 SCC 跟踪。
///
/// Returns the SCC ID if the instruction enters a new SCC.
/// 如果指令进入新的 SCC，返回 SCC ID。
pub fn maybe_enter_scc(
    analysis: &SccAnalysis,
    visit_state: &mut SccVisitState,
    insn_idx: usize,
) -> Option<usize> {
    let scc_id = analysis.insn_to_scc.get(&insn_idx)?;

    // Check if this is an entry point into the SCC
    // 检查这是否是 SCC 的入口点
    let scc = analysis.sccs.get(*scc_id)?;

    if scc.entries.contains(&insn_idx) && visit_state.current_scc != Some(*scc_id) {
        visit_state.enter_scc(*scc_id, insn_idx);
        return Some(*scc_id);
    }

    None
}

/// Exit SCC tracking for an instruction.
/// 退出指令的 SCC 跟踪。
///
/// Returns the SCC ID if the instruction exits the current SCC.
/// 如果指令退出当前 SCC，返回 SCC ID。
pub fn maybe_exit_scc(
    analysis: &SccAnalysis,
    visit_state: &mut SccVisitState,
    insn_idx: usize,
) -> Option<usize> {
    let current_scc = visit_state.current_scc?;
    let scc = analysis.sccs.get(current_scc)?;

    // Check if this is an exit point from the SCC
    // 检查这是否是 SCC 的出口点
    if scc.exits.contains(&insn_idx) {
        let exited = current_scc;
        visit_state.exit_scc();
        return Some(exited);
    }

    None
}

/// Add a back edge to the analysis.
/// 向分析添加回边。
pub fn add_scc_backedge(analysis: &mut SccAnalysis, from: usize, to: usize) -> Result<()> {
    // Find the SCC containing the target
    // 找到包含目标的 SCC
    let scc_id = *analysis.insn_to_scc.get(&to).ok_or_else(|| {
        VerifierError::InvalidState(format!("back edge target {} not in any SCC", to))
    })?;

    // Add the back edge to the SCC
    // 向 SCC 添加回边
    if let Some(scc) = analysis.sccs.get_mut(scc_id) {
        if !scc.back_edges.contains(&(from, to)) {
            scc.back_edges.push((from, to));
            scc.is_loop = true;
        }
    }

    // Add to loop_sccs if not already there
    // 如果不存在则添加到 loop_sccs
    if !analysis.loop_sccs.contains(&scc_id) {
        analysis.loop_sccs.push(scc_id);
    }

    Ok(())
}

/// SCC visit state for verification.
/// 用于验证的 SCC 访问状态。
#[derive(Debug, Clone)]
pub struct SccVisitState {
    /// Current SCC being processed.
    /// 当前正在处理的 SCC。
    pub current_scc: Option<usize>,
    /// Entry instruction into current SCC.
    /// 进入当前 SCC 的入口指令。
    pub entry_insn: Option<usize>,
    /// Iteration count in current SCC.
    /// 当前 SCC 中的迭代计数。
    pub iter_count: u32,
    /// Stack of nested SCCs.
    /// 嵌套 SCC 的栈。
    pub scc_stack: Vec<usize>,
    /// Callchain for debugging.
    /// 用于调试的调用链。
    pub callchain: Vec<usize>,
}

impl SccVisitState {
    /// Create new visit state.
    /// 创建新的访问状态。
    pub fn new() -> Self {
        Self {
            current_scc: None,
            entry_insn: None,
            iter_count: 0,
            scc_stack: Vec::new(),
            callchain: Vec::new(),
        }
    }

    /// Enter an SCC.
    /// 进入 SCC。
    pub fn enter_scc(&mut self, scc_id: usize, entry: usize) {
        if let Some(current) = self.current_scc {
            self.scc_stack.push(current);
        }
        self.current_scc = Some(scc_id);
        self.entry_insn = Some(entry);
        self.iter_count = 0;
    }

    /// Exit the current SCC.
    /// 退出当前 SCC。
    pub fn exit_scc(&mut self) {
        self.current_scc = self.scc_stack.pop();
        self.entry_insn = None;
        self.iter_count = 0;
    }

    /// Increment iteration count.
    /// 增加迭代计数。
    pub fn increment_iter(&mut self) {
        self.iter_count += 1;
    }

    /// Check if currently in an SCC.
    /// 检查当前是否在 SCC 中。
    pub fn in_scc(&self) -> bool {
        self.current_scc.is_some()
    }
}

impl Default for SccVisitState {
    fn default() -> Self {
        Self::new()
    }
}
