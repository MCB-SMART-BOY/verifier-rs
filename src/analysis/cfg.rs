//! Control flow graph analysis
//!
//! This module handles control flow analysis including:
//! - Building the CFG from instructions
//! - Detecting loops and back-edges
//! - Managing exploration of all paths
//! - State pruning and merging

use crate::state::verifier_state::{BpfVerifierState, BpfVerifierStackElem, ExplorationStack};
use crate::core::insn::{check_alu_op, check_cond_jmp_op, check_call, check_exit, check_ld_imm64};
use crate::core::types::*;
use crate::core::error::{Result, VerifierError};


use alloc::{vec, vec::Vec, format};

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};

use super::states_equal::states_equal;

/// Information about a basic block
#[derive(Debug, Clone, Default)]
pub struct BasicBlock {
    /// Start instruction index
    pub start: usize,
    /// End instruction index (inclusive)
    pub end: usize,
    /// Successor blocks
    pub successors: Vec<usize>,
    /// Predecessor blocks
    pub predecessors: Vec<usize>,
}

/// Control flow graph
#[derive(Debug, Default)]
pub struct ControlFlowGraph {
    /// Map from start instruction to basic block
    pub blocks: HashMap<usize, BasicBlock>,
    /// Entry block index
    pub entry: usize,
    /// All instruction indices that are jump targets
    pub jump_targets: HashSet<usize>,
}

impl ControlFlowGraph {
    /// Build CFG from instructions
    pub fn build(insns: &[BpfInsn]) -> Result<Self> {
        let mut cfg = Self::default();

        if insns.is_empty() {
            return Ok(cfg);
        }

        // First pass: find all jump targets
        cfg.jump_targets.insert(0); // Entry point

        for (i, insn) in insns.iter().enumerate() {
            let class = insn.class();

            if class == BPF_JMP || class == BPF_JMP32 {
                let op = insn.code & 0xf0;

                match op {
                    BPF_CALL => {
                        // Call might transfer to subprogram
                        if insn.is_pseudo_call() {
                            let target = (i as i32 + insn.imm + 1) as usize;
                            cfg.jump_targets.insert(target);
                        }
                        // Fall-through is also a target
                        if i + 1 < insns.len() {
                            cfg.jump_targets.insert(i + 1);
                        }
                    }
                    BPF_EXIT => {
                        // No successors
                    }
                    BPF_JA => {
                        // Unconditional jump
                        let target = (i as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            cfg.jump_targets.insert(target);
                        }
                    }
                    _ => {
                        // Conditional jump
                        let target = (i as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            cfg.jump_targets.insert(target);
                        }
                        // Fall-through
                        if i + 1 < insns.len() {
                            cfg.jump_targets.insert(i + 1);
                        }
                    }
                }
            }

            // LD_IMM64 takes two slots
            if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                // Skip the second instruction
            }
        }

        // Second pass: build basic blocks
        let mut sorted_targets: Vec<usize> = cfg.jump_targets.iter().copied().collect();
        sorted_targets.sort();

        for (block_idx, &start) in sorted_targets.iter().enumerate() {
            let end = if block_idx + 1 < sorted_targets.len() {
                sorted_targets[block_idx + 1] - 1
            } else {
                insns.len() - 1
            };

            // Find successors
            let mut successors = Vec::new();
            if end < insns.len() {
                let last_insn = &insns[end];
                let class = last_insn.class();

                if class == BPF_JMP || class == BPF_JMP32 {
                    let op = last_insn.code & 0xf0;

                    match op {
                        BPF_EXIT => {
                            // No successors
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
                            if end + 1 < insns.len() {
                                successors.push(end + 1);
                            }
                        }
                        _ if op != BPF_CALL && op != BPF_EXIT => {
                            // Conditional jump
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
                            if end + 1 < insns.len() {
                                successors.push(end + 1);
                            }
                        }
                    }
                } else if end + 1 < insns.len() {
                    // Not a jump, falls through
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
        let block_starts: Vec<usize> = cfg.blocks.keys().copied().collect();
        for start in &block_starts {
            let successors = cfg.blocks.get(start).map(|b| b.successors.clone()).unwrap_or_default();
            for succ in successors {
                if let Some(block) = cfg.blocks.get_mut(&succ) {
                    block.predecessors.push(*start);
                }
            }
        }

        Ok(cfg)
    }

    /// Check if there's a back-edge from `from` to `to`
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        // A back-edge goes to an earlier block (loop)
        to <= from
    }

    /// Get all blocks in the CFG
    pub fn all_blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// Compute postorder traversal of instructions within each subprogram.
    /// Returns a vector of instruction indices in postorder.
    /// This is useful for optimization passes that need reverse postorder.
    pub fn compute_postorder(&self, insns: &[BpfInsn], subprog_starts: &[usize]) -> Vec<usize> {
        let mut postorder = Vec::new();
        let mut state: Vec<u8> = vec![0; insns.len()]; // 0=unvisited, 1=discovered, 2=explored
        
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
    fn get_insn_successors(&self, insns: &[BpfInsn], idx: usize) -> Vec<usize> {
        let mut successors = Vec::new();
        
        if idx >= insns.len() {
            return successors;
        }

        let insn = &insns[idx];
        let class = insn.class();

        // Handle LD_IMM64 which takes two instruction slots
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
                }
                BPF_JA => {
                    let target = (idx as i32 + insn.off as i32 + 1) as usize;
                    if target < insns.len() {
                        successors.push(target);
                    }
                }
                BPF_CALL => {
                    // Regular call continues to next instruction
                    if idx + 1 < insns.len() {
                        successors.push(idx + 1);
                    }
                }
                _ => {
                    // Conditional jump: both fall-through and target
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
            if idx + 1 < insns.len() {
                successors.push(idx + 1);
            }
        }

        successors
    }

    /// Get reverse postorder (useful for forward dataflow analysis)
    pub fn compute_reverse_postorder(&self, insns: &[BpfInsn], subprog_starts: &[usize]) -> Vec<usize> {
        let mut rpo = self.compute_postorder(insns, subprog_starts);
        rpo.reverse();
        rpo
    }

    /// Detect loop headers (targets of back edges)
    /// Uses iterative DFS to avoid stack overflow in kernel mode
    pub fn find_loop_headers(&self, insns: &[BpfInsn]) -> HashSet<usize> {
        let mut loop_headers = HashSet::new();
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();
        
        if insns.is_empty() {
            return loop_headers;
        }

        // Iterative DFS
        // Each entry: (node_idx, next_successor_to_process, is_entering)
        // is_entering: true means we're just entering this node
        //              false means we're returning from a child
        let mut stack: Vec<(usize, usize, bool)> = Vec::new();
        stack.push((0, 0, true));

        while let Some((idx, succ_idx, is_entering)) = stack.pop() {
            if is_entering {
                // First time visiting this node
                if visited.contains(&idx) {
                    continue;
                }
                visited.insert(idx);
                in_stack.insert(idx);
            }

            let successors = self.get_insn_successors(insns, idx);
            let mut found_unvisited = false;

            for i in succ_idx..successors.len() {
                let succ = successors[i];

                if in_stack.contains(&succ) {
                    // Back edge found - succ is a loop header
                    loop_headers.insert(succ);
                } else if !visited.contains(&succ) && succ < insns.len() {
                    // Push current node back to continue after child returns
                    stack.push((idx, i + 1, false));
                    // Push child to visit
                    stack.push((succ, 0, true));
                    found_unvisited = true;
                    break;
                }
            }

            // If no unvisited successors, we're done with this node
            if !found_unvisited {
                in_stack.remove(&idx);
            }
        }
        
        loop_headers
    }
}

/// Explored states at each instruction
#[derive(Debug, Default)]
pub struct ExploredStates {
    /// States at each instruction index
    states: HashMap<usize, Vec<BpfVerifierState>>,
    /// Total number of states
    pub total_states: usize,
    /// Peak states encountered
    pub peak_states: usize,
}

impl ExploredStates {
    /// Create a new explored states tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a state at an instruction
    pub fn add_state(&mut self, insn_idx: usize, state: BpfVerifierState) {
        self.states.entry(insn_idx).or_default().push(state);
        self.total_states += 1;
        self.peak_states = self.peak_states.max(self.total_states);
    }

    /// Get states at an instruction
    pub fn get_states(&self, insn_idx: usize) -> Option<&Vec<BpfVerifierState>> {
        self.states.get(&insn_idx)
    }

    /// Check if a state is equivalent to any existing state at this instruction
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

/// Verifier context for CFG-based verification
pub struct Verifier {
    /// Program instructions
    pub insns: Vec<BpfInsn>,
    /// Control flow graph
    pub cfg: ControlFlowGraph,
    /// Current state
    pub cur_state: BpfVerifierState,
    /// Exploration stack
    pub stack: ExplorationStack,
    /// Explored states
    pub explored: ExploredStates,
    /// Subprogram information
    pub subprogs: Vec<BpfSubprogInfo>,
    /// Whether in privileged mode
    pub allow_ptr_leaks: bool,
    /// Whether program is sleepable
    pub in_sleepable: bool,
    /// Current instruction index
    pub insn_idx: usize,
    /// Previous instruction index
    pub prev_insn_idx: usize,
}

impl Verifier {
    /// Create a new verifier for a program
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
    pub fn verify(&mut self) -> Result<()> {
        // First pass: check CFG structure
        self.check_cfg()?;

        // Add subprograms
        self.add_subprogs()?;

        // Main verification loop
        self.do_check()
    }

    /// Check CFG for issues (unreachable code, invalid jumps)
    fn check_cfg(&self) -> Result<()> {
        // Check all instructions are reachable
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
            if insn.code == (BPF_LD | BPF_IMM | 0x18) {
                to_visit.push(idx + 2);
                continue;
            }

            if class == BPF_JMP || class == BPF_JMP32 {
                let op = insn.code & 0xf0;

                match op {
                    BPF_EXIT => {
                        // No successors
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
        for i in 0..self.insns.len() {
            if !reachable.contains(&i) {
                // Skip second slot of LD_IMM64
                if i > 0 && self.insns[i - 1].code == (BPF_LD | BPF_IMM | 0x18) {
                    continue;
                }
                return Err(VerifierError::UnreachableInstruction(i));
            }
        }

        Ok(())
    }

    /// Find and add subprograms
    fn add_subprogs(&mut self) -> Result<()> {
        // Main program is subprog 0
        self.subprogs.push(BpfSubprogInfo {
            start: 0,
            ..Default::default()
        });

        // Find call targets
        for (i, insn) in self.insns.iter().enumerate() {
            if insn.is_pseudo_call() {
                let target = (i as i32 + insn.imm + 1) as usize;
                if target >= self.insns.len() {
                    return Err(VerifierError::InvalidJumpDestination(target as i32));
                }

                // Check if already added
                if !self.subprogs.iter().any(|s| s.start == target) {
                    self.subprogs.push(BpfSubprogInfo {
                        start: target,
                        ..Default::default()
                    });
                }
            }
        }

        // Sort by start
        self.subprogs.sort_by_key(|s| s.start);

        Ok(())
    }

    /// Main verification loop
    fn do_check(&mut self) -> Result<()> {
        // Set up initial state
        if let Some(func) = self.cur_state.cur_func_mut() {
            // R1 is context pointer
            func.regs[1].reg_type = BpfRegType::PtrToCtx;
            func.regs[1].mark_known_zero();
        }

        loop {
            // Check state complexity
            if self.explored.total_states > BPF_COMPLEXITY_LIMIT_STATES * self.insns.len() {
                return Err(VerifierError::TooComplex(format!(
                    "exceeded {} states",
                    BPF_COMPLEXITY_LIMIT_STATES * self.insns.len()
                )));
            }

            // Check if this state was already visited
            if self.explored.find_equivalent(self.insn_idx, &self.cur_state).is_some() {
                // State is equivalent to an existing one, prune this path
                if !self.pop_state()? {
                    break; // No more states to explore
                }
                continue;
            }

            // Add current state to explored
            self.explored.add_state(self.insn_idx, self.cur_state.clone());

            // Process the instruction
            let continue_check = self.do_check_insn()?;

            if !continue_check {
                // Instruction ended this path (EXIT or error)
                if !self.pop_state()? {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single instruction
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
                self.check_ldx(&insn)?;
                self.insn_idx += 1;
            }
            BPF_STX | BPF_ST => {
                // Store to memory
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
                    self.insn_idx += 1;
                }
            }
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;

                match op {
                    BPF_EXIT => {
                        check_exit(&self.cur_state)?;
                        return Ok(false); // End of path
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
                        let (fall_through, target) = check_cond_jmp_op(
                            &mut self.cur_state,
                            &insn,
                            self.insn_idx,
                            self.allow_ptr_leaks,
                        )?;

                        if let Some(target_idx) = target {
                            // Push target path to stack
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
    fn check_ldx(&mut self, insn: &BpfInsn) -> Result<()> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;

        // Source must be a valid pointer
        let src = self.cur_state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
        if !src.is_pointer() && !(src.reg_type == BpfRegType::ScalarValue && src.is_const()) {
            return Err(VerifierError::InvalidMemoryAccess(
                "LDX source must be a pointer".into(),
            ));
        }

        // Perform load - result is usually a scalar
        if let Some(dst) = self.cur_state.reg_mut(dst_reg) {
            dst.mark_unknown(false);
        }

        Ok(())
    }

    /// Check STX instruction
    fn check_stx(&mut self, insn: &BpfInsn) -> Result<()> {
        let dst_reg = insn.dst_reg as usize;
        let src_reg = insn.src_reg as usize;

        // Destination must be a valid pointer
        let dst = self.cur_state.reg(dst_reg).ok_or(VerifierError::InvalidRegister(dst_reg as u8))?;
        if !dst.is_pointer() {
            return Err(VerifierError::InvalidMemoryAccess(
                "STX destination must be a pointer".into(),
            ));
        }

        // Source must be initialized
        let src = self.cur_state.reg(src_reg).ok_or(VerifierError::InvalidRegister(src_reg as u8))?;
        if src.reg_type == BpfRegType::NotInit {
            return Err(VerifierError::UninitializedRegister(src_reg as u8));
        }

        // Check for pointer leaks
        if !self.allow_ptr_leaks && src.is_pointer() {
            // Storing pointers to maps or other memory may leak them
            if dst.reg_type == BpfRegType::PtrToMapValue {
                // Check if map allows pointer storage
            }
        }

        Ok(())
    }

    /// Pop next state from exploration stack
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
