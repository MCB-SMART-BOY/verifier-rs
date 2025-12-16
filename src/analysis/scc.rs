// SPDX-License-Identifier: GPL-2.0

//! Strongly Connected Components (SCC) analysis for BPF programs.
//!
//! This module implements Tarjan's algorithm for finding SCCs in the control
//! flow graph. SCCs are critical for bounded loop verification - each SCC
//! represents a potential loop that needs iteration bounds checking.

use alloc::{format, vec::Vec};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

/// State of a node during SCC traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    /// Not yet visited.
    Unvisited,
    /// On the DFS stack (being processed).
    OnStack,
    /// Finished processing, assigned to an SCC.
    Finished,
}

/// Information about a single SCC.
#[derive(Debug, Clone)]
pub struct SccInfo {
    /// Unique ID of this SCC.
    pub id: usize,
    /// Instructions belonging to this SCC.
    pub members: Vec<usize>,
    /// Entry points into this SCC (instructions with predecessors outside).
    pub entries: Vec<usize>,
    /// Exit points from this SCC (instructions with successors outside).
    pub exits: Vec<usize>,
    /// Back edges within this SCC (source -> target).
    pub back_edges: Vec<(usize, usize)>,
    /// Whether this SCC contains a loop (has back edges).
    pub is_loop: bool,
    /// Nesting depth (SCCs can be nested).
    pub depth: u32,
    /// Parent SCC ID (if nested).
    pub parent: Option<usize>,
}

impl SccInfo {
    /// Create a new SCC.
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
    pub fn contains(&self, insn_idx: usize) -> bool {
        self.members.contains(&insn_idx)
    }

    /// Get the number of members.
    pub fn size(&self) -> usize {
        self.members.len()
    }
}

/// Result of SCC analysis.
#[derive(Debug, Clone)]
pub struct SccAnalysis {
    /// All SCCs found, indexed by SCC ID.
    pub sccs: Vec<SccInfo>,
    /// Map from instruction index to SCC ID.
    pub insn_to_scc: HashMap<usize, usize>,
    /// SCCs that contain loops (back edges).
    pub loop_sccs: Vec<usize>,
    /// Topologically sorted SCC IDs (for processing order).
    pub topo_order: Vec<usize>,
    /// Maximum nesting depth.
    pub max_depth: u32,
}

impl SccAnalysis {
    /// Create empty analysis.
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
    pub fn get_scc(&self, insn_idx: usize) -> Option<&SccInfo> {
        self.insn_to_scc.get(&insn_idx).map(|&id| &self.sccs[id])
    }

    /// Check if an instruction is in a loop.
    pub fn is_in_loop(&self, insn_idx: usize) -> bool {
        if let Some(&scc_id) = self.insn_to_scc.get(&insn_idx) {
            self.sccs[scc_id].is_loop
        } else {
            false
        }
    }

    /// Get all back edges.
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
pub struct SccComputer {
    /// Number of instructions.
    num_insns: usize,
    /// Successors for each instruction.
    successors: HashMap<usize, Vec<usize>>,
    /// Predecessors for each instruction.
    predecessors: HashMap<usize, Vec<usize>>,
    /// DFS index counter.
    index: usize,
    /// DFS indices for each node.
    indices: HashMap<usize, usize>,
    /// Low-link values for each node.
    lowlinks: HashMap<usize, usize>,
    /// Node states.
    states: HashMap<usize, NodeState>,
    /// DFS stack.
    stack: Vec<usize>,
    /// Found SCCs.
    sccs: Vec<SccInfo>,
    /// Map from instruction to SCC.
    insn_to_scc: HashMap<usize, usize>,
}

impl SccComputer {
    /// Create a new SCC computer.
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
    pub fn build_cfg(&mut self, insns: &[BpfInsn]) {
        for (idx, insn) in insns.iter().enumerate() {
            let class = insn.class();
            let op = insn.code & 0xf0;

            match class {
                BPF_JMP | BPF_JMP32 => {
                    match op {
                        BPF_JA => {
                            // Unconditional jump
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            if target < insns.len() {
                                self.add_edge(idx, target);
                            }
                        }
                        BPF_EXIT => {
                            // No successors
                        }
                        BPF_CALL => {
                            // For pseudo calls, we need special handling
                            if insn.src_reg == BPF_PSEUDO_CALL {
                                // Subprogram call - add both call target and return
                                let target = (idx as i32 + insn.imm + 1) as usize;
                                if target < insns.len() {
                                    self.add_edge(idx, target);
                                }
                            }
                            // Fall through after call
                            if idx + 1 < insns.len() {
                                self.add_edge(idx, idx + 1);
                            }
                        }
                        _ => {
                            // Conditional jump - both paths
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
                    if idx + 1 < insns.len() {
                        self.add_edge(idx, idx + 1);
                    }
                }
            }
        }
    }

    /// Add an edge to the CFG.
    fn add_edge(&mut self, from: usize, to: usize) {
        self.successors.entry(from).or_default().push(to);
        self.predecessors.entry(to).or_default().push(from);
    }

    /// Compute SCCs using Tarjan's algorithm.
    pub fn compute(&mut self) -> SccAnalysis {
        // Initialize all nodes as unvisited
        for i in 0..self.num_insns {
            self.states.insert(i, NodeState::Unvisited);
        }

        // Run Tarjan's algorithm from each unvisited node
        for i in 0..self.num_insns {
            if self.states.get(&i) == Some(&NodeState::Unvisited) {
                self.strongconnect(i);
            }
        }

        // Build the result
        self.build_result()
    }

    /// Tarjan's strongconnect function.
    fn strongconnect(&mut self, v: usize) {
        // Set the depth index for v
        self.indices.insert(v, self.index);
        self.lowlinks.insert(v, self.index);
        self.index += 1;
        self.stack.push(v);
        self.states.insert(v, NodeState::OnStack);

        // Consider successors of v
        let successors = self.successors.get(&v).cloned().unwrap_or_default();
        for w in successors {
            if w >= self.num_insns {
                continue;
            }

            match self.states.get(&w) {
                Some(&NodeState::Unvisited) => {
                    // Successor w has not yet been visited; recurse on it
                    self.strongconnect(w);
                    let v_low = self.lowlinks.get(&v).copied().unwrap_or(0);
                    let w_low = self.lowlinks.get(&w).copied().unwrap_or(0);
                    self.lowlinks.insert(v, v_low.min(w_low));
                }
                Some(&NodeState::OnStack) => {
                    // Successor w is on stack and hence in the current SCC
                    let v_low = self.lowlinks.get(&v).copied().unwrap_or(0);
                    let w_idx = self.indices.get(&w).copied().unwrap_or(0);
                    self.lowlinks.insert(v, v_low.min(w_idx));
                }
                _ => {
                    // Successor is in a different SCC, ignore
                }
            }
        }

        // If v is a root node, pop the stack and generate an SCC
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
    fn build_result(&mut self) -> SccAnalysis {
        let mut analysis = SccAnalysis::new();

        // Move SCCs to analysis
        core::mem::swap(&mut analysis.sccs, &mut self.sccs);
        core::mem::swap(&mut analysis.insn_to_scc, &mut self.insn_to_scc);

        // Compute entries, exits, and back edges for each SCC
        for scc in &mut analysis.sccs {
            let members: HashSet<usize> = scc.members.iter().cloned().collect();

            for &member in &scc.members {
                // Check predecessors for entries
                if let Some(preds) = self.predecessors.get(&member) {
                    for &pred in preds {
                        if !members.contains(&pred) && !scc.entries.contains(&member) {
                            scc.entries.push(member);
                        }
                    }
                }

                // Check successors for exits and back edges
                if let Some(succs) = self.successors.get(&member) {
                    for &succ in succs {
                        if members.contains(&succ) {
                            // Internal edge - check if it's a back edge
                            // A back edge goes to a node with smaller/equal DFS index
                            if let (Some(&m_idx), Some(&s_idx)) =
                                (self.indices.get(&member), self.indices.get(&succ))
                            {
                                if s_idx <= m_idx {
                                    scc.back_edges.push((member, succ));
                                }
                            }
                        } else {
                            // External edge - this is an exit
                            if !scc.exits.contains(&member) {
                                scc.exits.push(member);
                            }
                        }
                    }
                }
            }

            // SCC is a loop if it has back edges or more than one member with internal edges
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
        analysis.topo_order =
            Self::compute_scc_topo_order(&analysis.sccs, &self.successors, &analysis.insn_to_scc);

        // Compute nesting depth
        Self::compute_nesting(&mut analysis);

        analysis
    }

    /// Compute topological order of SCCs.
    fn compute_scc_topo_order(
        sccs: &[SccInfo],
        successors: &HashMap<usize, Vec<usize>>,
        insn_to_scc: &HashMap<usize, usize>,
    ) -> Vec<usize> {
        let _num_sccs = sccs.len();
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut scc_edges: HashMap<usize, HashSet<usize>> = HashMap::new();

        // Initialize
        for scc in sccs {
            in_degree.insert(scc.id, 0);
            scc_edges.insert(scc.id, HashSet::new());
        }

        // Build SCC graph
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
    fn compute_nesting(analysis: &mut SccAnalysis) {
        // Simple nesting: SCCs with smaller instruction ranges inside larger ones
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
pub fn compute_scc(insns: &[BpfInsn]) -> SccAnalysis {
    let mut computer = SccComputer::new(insns.len());
    computer.build_cfg(insns);
    computer.compute()
}

/// Back edge information for loop verification.
#[derive(Debug, Clone)]
pub struct BackEdgeInfo {
    /// Source instruction (jump instruction).
    pub from: usize,
    /// Target instruction (loop header).
    pub to: usize,
    /// SCC ID containing this back edge.
    pub scc_id: usize,
    /// Iteration count bound (if determinable).
    pub iter_bound: Option<u32>,
}

/// Propagate back edges for loop iteration tracking.
#[derive(Debug)]
pub struct BackEdgePropagator {
    /// Back edges found.
    back_edges: Vec<BackEdgeInfo>,
    /// Visited states per instruction.
    visit_counts: HashMap<usize, u32>,
    /// Maximum iterations per back edge.
    max_iters: u32,
}

impl BackEdgePropagator {
    /// Create a new propagator.
    pub fn new(max_iters: u32) -> Self {
        Self {
            back_edges: Vec::new(),
            visit_counts: HashMap::new(),
            max_iters,
        }
    }

    /// Initialize from SCC analysis.
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
    pub fn record_visit(&mut self, insn_idx: usize) -> Result<()> {
        let count = self.visit_counts.entry(insn_idx).or_insert(0);
        *count += 1;

        // Check if this is a back edge target exceeding limit
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
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.back_edges.iter().any(|e| e.from == from && e.to == to)
    }

    /// Get visit count for an instruction.
    pub fn visit_count(&self, insn_idx: usize) -> u32 {
        *self.visit_counts.get(&insn_idx).unwrap_or(&0)
    }

    /// Get all back edges.
    pub fn back_edges(&self) -> &[BackEdgeInfo] {
        &self.back_edges
    }

    /// Set iteration bound for a back edge.
    pub fn set_iter_bound(&mut self, from: usize, to: usize, bound: u32) {
        for edge in &mut self.back_edges {
            if edge.from == from && edge.to == to {
                edge.iter_bound = Some(bound);
                break;
            }
        }
    }

    /// Reset visit counts for a new verification pass.
    pub fn reset(&mut self) {
        self.visit_counts.clear();
    }

    /// Get the total number of back edges.
    pub fn back_edge_count(&self) -> usize {
        self.back_edges.len()
    }
}

/// Maximum number of back edge iterations for convergence in SCC analysis.
pub const SCC_MAX_BACKEDGE_ITERS: u32 = 4;

/// Propagate precision marks through back edges.
///
/// This function implements the kernel's `propagate_backedges()` which
/// ensures that precision tracking works correctly across loop iterations.
///
/// When a loop back edge is taken, precision marks need to be propagated
/// from the current state to the loop header state to ensure proper
/// tracking of loop-variant registers.
pub fn propagate_backedges(
    analysis: &SccAnalysis,
    propagator: &mut BackEdgePropagator,
    insn_idx: usize,
    target_idx: usize,
) -> Result<bool> {
    // Check if this is a back edge
    if !propagator.is_back_edge(insn_idx, target_idx) {
        return Ok(false);
    }

    // Record visit to target (loop header)
    propagator.record_visit(target_idx)?;

    // Check if we've reached the iteration limit
    let count = propagator.visit_count(target_idx);
    if count > SCC_MAX_BACKEDGE_ITERS {
        return Err(VerifierError::TooComplex(format!(
            "back edge from {} to {} exceeded max iterations {}",
            insn_idx, target_idx, SCC_MAX_BACKEDGE_ITERS
        )));
    }

    // Get the SCC containing this back edge
    let scc_id = analysis.insn_to_scc.get(&target_idx);
    if scc_id.is_none() {
        return Ok(false);
    }

    Ok(true)
}

/// Check if two instructions are in the same loop SCC.
///
/// This is a SCC-based check complementing the state-based `states_maybe_looping()` in prune.rs.
pub fn scc_states_maybe_looping(
    analysis: &SccAnalysis,
    insn_idx1: usize,
    insn_idx2: usize,
) -> bool {
    // Check if both instructions are in the same SCC
    let scc1 = analysis.insn_to_scc.get(&insn_idx1);
    let scc2 = analysis.insn_to_scc.get(&insn_idx2);

    match (scc1, scc2) {
        (Some(s1), Some(s2)) if s1 == s2 => {
            // Same SCC - could be looping
            if let Some(scc) = analysis.sccs.get(*s1) {
                // Only if the SCC has back edges (is a loop)
                scc.is_loop
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Enter SCC tracking for an instruction.
///
/// Returns the SCC ID if the instruction enters a new SCC.
pub fn maybe_enter_scc(
    analysis: &SccAnalysis,
    visit_state: &mut SccVisitState,
    insn_idx: usize,
) -> Option<usize> {
    let scc_id = analysis.insn_to_scc.get(&insn_idx)?;

    // Check if this is an entry point into the SCC
    let scc = analysis.sccs.get(*scc_id)?;

    if scc.entries.contains(&insn_idx) && visit_state.current_scc != Some(*scc_id) {
        visit_state.enter_scc(*scc_id, insn_idx);
        return Some(*scc_id);
    }

    None
}

/// Exit SCC tracking for an instruction.
///
/// Returns the SCC ID if the instruction exits the current SCC.
pub fn maybe_exit_scc(
    analysis: &SccAnalysis,
    visit_state: &mut SccVisitState,
    insn_idx: usize,
) -> Option<usize> {
    let current_scc = visit_state.current_scc?;
    let scc = analysis.sccs.get(current_scc)?;

    // Check if this is an exit point from the SCC
    if scc.exits.contains(&insn_idx) {
        let exited = current_scc;
        visit_state.exit_scc();
        return Some(exited);
    }

    None
}

/// Add a back edge to the analysis.
pub fn add_scc_backedge(analysis: &mut SccAnalysis, from: usize, to: usize) -> Result<()> {
    // Find the SCC containing the target
    let scc_id = *analysis.insn_to_scc.get(&to).ok_or_else(|| {
        VerifierError::InvalidState(format!("back edge target {} not in any SCC", to))
    })?;

    // Add the back edge to the SCC
    if let Some(scc) = analysis.sccs.get_mut(scc_id) {
        if !scc.back_edges.contains(&(from, to)) {
            scc.back_edges.push((from, to));
            scc.is_loop = true;
        }
    }

    // Add to loop_sccs if not already there
    if !analysis.loop_sccs.contains(&scc_id) {
        analysis.loop_sccs.push(scc_id);
    }

    Ok(())
}

/// SCC visit state for verification.
#[derive(Debug, Clone)]
pub struct SccVisitState {
    /// Current SCC being processed.
    pub current_scc: Option<usize>,
    /// Entry instruction into current SCC.
    pub entry_insn: Option<usize>,
    /// Iteration count in current SCC.
    pub iter_count: u32,
    /// Stack of nested SCCs.
    pub scc_stack: Vec<usize>,
    /// Callchain for debugging.
    pub callchain: Vec<usize>,
}

impl SccVisitState {
    /// Create new visit state.
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
    pub fn enter_scc(&mut self, scc_id: usize, entry: usize) {
        if let Some(current) = self.current_scc {
            self.scc_stack.push(current);
        }
        self.current_scc = Some(scc_id);
        self.entry_insn = Some(entry);
        self.iter_count = 0;
    }

    /// Exit the current SCC.
    pub fn exit_scc(&mut self) {
        self.current_scc = self.scc_stack.pop();
        self.entry_insn = None;
        self.iter_count = 0;
    }

    /// Increment iteration count.
    pub fn increment_iter(&mut self) {
        self.iter_count += 1;
    }

    /// Check if currently in an SCC.
    pub fn in_scc(&self) -> bool {
        self.current_scc.is_some()
    }
}

impl Default for SccVisitState {
    fn default() -> Self {
        Self::new()
    }
}
