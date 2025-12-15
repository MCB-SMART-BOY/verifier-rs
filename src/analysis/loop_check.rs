//! Loop detection and bounding
//!
//! This module implements loop detection and bounding for BPF programs.
//! BPF programs traditionally couldn't have loops, but bounded loops are
//! now supported with proper verification.

#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use crate::core::types::*;
use crate::bounds::bounds::ScalarBounds;
use crate::core::error::{Result, VerifierError};

/// Maximum number of loop iterations for bounded loops
pub const BPF_MAX_LOOPS: u32 = 8 * 1024 * 1024;

/// Loop information
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// Loop header (first instruction of the loop)
    pub header: usize,
    /// Back edge source (instruction that jumps back to header)
    pub back_edge: usize,
    /// Loop body instructions
    pub body: HashSet<usize>,
    /// Induction variable register (if detected)
    pub induction_var: Option<u8>,
    /// Loop bound (if provable)
    pub bound: Option<u32>,
    /// Whether loop is bounded
    pub is_bounded: bool,
}

impl LoopInfo {
    /// Create new loop info
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
    pub fn contains(&self, insn_idx: usize) -> bool {
        self.body.contains(&insn_idx) || insn_idx == self.header
    }
}

/// Loop detector
#[derive(Debug, Default)]
pub struct LoopDetector {
    /// Detected loops
    pub loops: Vec<LoopInfo>,
    /// Back edges found
    pub back_edges: Vec<(usize, usize)>,
    /// DFS state
    visited: HashSet<usize>,
    in_stack: HashSet<usize>,
}

impl LoopDetector {
    /// Create new loop detector
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect loops in instructions
    pub fn detect(&mut self, insns: &[BpfInsn]) -> Result<()> {
        self.visited.clear();
        self.in_stack.clear();
        self.back_edges.clear();
        self.loops.clear();

        // DFS from entry point
        self.dfs(insns, 0)?;

        // Build loop info for each back edge
        for &(src, dst) in &self.back_edges.clone() {
            let mut loop_info = LoopInfo::new(dst, src);
            self.find_loop_body(insns, &mut loop_info)?;
            self.loops.push(loop_info);
        }

        Ok(())
    }

    /// DFS to find back edges
    fn dfs(&mut self, insns: &[BpfInsn], idx: usize) -> Result<()> {
        if idx >= insns.len() {
            return Ok(());
        }

        if self.in_stack.contains(&idx) {
            // Back edge found
            return Ok(());
        }

        if self.visited.contains(&idx) {
            return Ok(());
        }

        self.visited.insert(idx);
        self.in_stack.insert(idx);

        let _insn = &insns[idx];

        // Get successors
        let successors = self.get_successors(insns, idx);

        for succ in successors {
            if self.in_stack.contains(&succ) {
                // Back edge
                self.back_edges.push((idx, succ));
            } else {
                self.dfs(insns, succ)?;
            }
        }

        self.in_stack.remove(&idx);
        Ok(())
    }

    /// Get successor instructions
    fn get_successors(&self, insns: &[BpfInsn], idx: usize) -> Vec<usize> {
        let mut successors = Vec::new();
        
        if idx >= insns.len() {
            return successors;
        }

        let insn = &insns[idx];
        let class = insn.class();

        // Handle LD_IMM64 (two slots)
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
                    }
                    BPF_JA => {
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        if target < insns.len() {
                            successors.push(target);
                        }
                    }
                    BPF_CALL => {
                        // Continue to next (non-tail call)
                        if idx + 1 < insns.len() {
                            successors.push(idx + 1);
                        }
                    }
                    _ => {
                        // Conditional jump
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
    fn find_loop_body(&self, insns: &[BpfInsn], loop_info: &mut LoopInfo) -> Result<()> {
        // BFS backward from back edge source to header
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
    pub fn has_unbounded_loops(&self) -> bool {
        self.loops.iter().any(|l| !l.is_bounded)
    }

    /// Get loop containing instruction
    pub fn get_loop(&self, insn_idx: usize) -> Option<&LoopInfo> {
        self.loops.iter().find(|l| l.contains(insn_idx))
    }
}

/// Loop bound analysis
#[derive(Debug, Default)]
pub struct LoopBoundAnalyzer {
    /// Induction variable bounds at loop header
    pub header_bounds: HashMap<usize, ScalarBounds>,
}

impl LoopBoundAnalyzer {
    /// Create new analyzer
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a loop to determine if it's bounded
    pub fn analyze_loop(
        &mut self,
        insns: &[BpfInsn],
        loop_info: &mut LoopInfo,
    ) -> Result<()> {
        // Look for common loop patterns:
        // 1. Counter-based: r = 0; while (r < N) { r++; }
        // 2. Iterator-based: bpf_loop helper
        // 3. For-each: bpf_for_each_map_elem

        // Try to find induction variable
        if let Some((var, bound)) = self.find_induction_variable(insns, loop_info)? {
            loop_info.induction_var = Some(var);
            loop_info.bound = Some(bound);
            loop_info.is_bounded = bound <= BPF_MAX_LOOPS;
        }

        Ok(())
    }

    /// Find induction variable and its bound
    fn find_induction_variable(
        &self,
        insns: &[BpfInsn],
        loop_info: &LoopInfo,
    ) -> Result<Option<(u8, u32)>> {
        // Look at the back edge instruction - it should be a conditional jump
        let back_edge_insn = &insns[loop_info.back_edge];
        let class = back_edge_insn.class();

        if class != BPF_JMP && class != BPF_JMP32 {
            return Ok(None);
        }

        let op = back_edge_insn.code & 0xf0;
        
        // Check for comparison-based loops
        match op {
            BPF_JLT | BPF_JLE | BPF_JGT | BPF_JGE |
            BPF_JSLT | BPF_JSLE | BPF_JSGT | BPF_JSGE => {
                let var = back_edge_insn.dst_reg;
                
                // If comparing against immediate, that's our bound
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
    pub fn check_bpf_loop_helper(
        &self,
        insns: &[BpfInsn],
        loop_info: &LoopInfo,
    ) -> Option<u32> {
        // Look for bpf_loop call which has explicit iteration limit
        for &idx in &loop_info.body {
            if idx >= insns.len() {
                continue;
            }
            
            let insn = &insns[idx];
            if insn.code == (BPF_JMP | BPF_CALL) {
                // Check if this is bpf_loop helper
                // bpf_loop has helper ID that we would check here
                // For now, return None as we need helper database
            }
        }
        None
    }
}

/// Verify that all loops are bounded
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
            return Err(VerifierError::TooComplex(
                format!("unbounded loop at instruction {}", loop_info.header)
            ));
        }
    }

    Ok(())
}

/// Check if instruction is a loop exit
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
    match op {
        BPF_JA => {
            let target = (idx as i32 + insn.off as i32 + 1) as usize;
            !loop_info.contains(target)
        }
        BPF_EXIT => true,
        _ if op != BPF_CALL => {
            // Conditional jump - check both targets
            let target = (idx as i32 + insn.off as i32 + 1) as usize;
            let fallthrough = idx + 1;
            !loop_info.contains(target) || !loop_info.contains(fallthrough)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insns(codes: &[(u8, u8, u8, i16, i32)]) -> Vec<BpfInsn> {
        codes
            .iter()
            .map(|&(code, dst, src, off, imm)| BpfInsn::new(code, dst, src, off, imm))
            .collect()
    }

    #[test]
    fn test_no_loops() {
        // Linear program: r0 = 0; exit
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);

        let mut detector = LoopDetector::new();
        assert!(detector.detect(&insns).is_ok());
        assert!(detector.back_edges.is_empty());
    }

    #[test]
    fn test_simple_loop() {
        // Simple loop: r0 = 0; loop: r0++; if r0 < 10 goto loop; exit
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),      // 0: r0 = 0
            (BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),      // 1: r0++
            (BPF_JMP | BPF_JLT | BPF_K, 0, 0, -2, 10),      // 2: if r0 < 10 goto 1
            (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),               // 3: exit
        ]);

        let mut detector = LoopDetector::new();
        assert!(detector.detect(&insns).is_ok());
        assert_eq!(detector.back_edges.len(), 1);
        assert_eq!(detector.back_edges[0], (2, 1));
    }

    #[test]
    fn test_loop_info() {
        let mut loop_info = LoopInfo::new(1, 2);
        loop_info.body.insert(1);
        loop_info.body.insert(2);

        assert!(loop_info.contains(1));
        assert!(loop_info.contains(2));
        assert!(!loop_info.contains(0));
    }

    #[test]
    fn test_bounded_loop() {
        // Bounded loop with explicit bound
        let insns = make_insns(&[
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            (BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
            (BPF_JMP | BPF_JLT | BPF_K, 0, 0, -2, 100),
            (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);

        assert!(verify_loops_bounded(&insns).is_ok());
    }

    #[test]
    fn test_get_successors() {
        let detector = LoopDetector::new();
        
        // Unconditional jump
        let insns = make_insns(&[
            (BPF_JMP | BPF_JA, 0, 0, 2, 0),
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);

        let succs = detector.get_successors(&insns, 0);
        assert_eq!(succs, vec![3]);
    }

    #[test]
    fn test_conditional_successors() {
        let detector = LoopDetector::new();
        
        // Conditional jump
        let insns = make_insns(&[
            (BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0),
            (BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            (BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);

        let succs = detector.get_successors(&insns, 0);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&1));
        assert!(succs.contains(&2));
    }
}
