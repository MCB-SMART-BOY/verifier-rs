//! Dead code elimination
//!
//! This module implements dead code elimination for BPF programs.
//! It identifies and marks instructions that are never executed
//! (unreachable) or whose results are never used (dead stores).

use crate::core::types::*;
use crate::core::error::Result;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeSet as HashSet, VecDeque};
#[cfg(feature = "std")]
use std::collections::{HashSet, VecDeque};

/// Dead code elimination pass
#[derive(Debug)]
pub struct DeadCodeEliminator {
    /// Instructions in the program
    insns: Vec<BpfInsn>,
    /// Set of reachable instruction indices
    reachable: HashSet<usize>,
    /// Set of live registers at each instruction
    live_regs: Vec<HashSet<usize>>,
    /// Instructions marked for removal
    dead_insns: HashSet<usize>,
}

impl DeadCodeEliminator {
    /// Create a new dead code eliminator
    pub fn new(insns: Vec<BpfInsn>) -> Self {
        let len = insns.len();
        Self {
            insns,
            reachable: HashSet::new(),
            live_regs: vec![HashSet::new(); len],
            dead_insns: HashSet::new(),
        }
    }

    /// Run dead code elimination
    pub fn eliminate(&mut self) -> Result<Vec<usize>> {
        // Phase 1: Find reachable instructions
        self.find_reachable()?;

        // Phase 2: Backward liveness analysis
        self.analyze_liveness()?;

        // Phase 3: Mark dead instructions
        self.mark_dead_code();

        // Return indices of dead instructions
        Ok(self.dead_insns.iter().copied().collect())
    }

    /// Find all reachable instructions via CFG traversal
    fn find_reachable(&mut self) -> Result<()> {
        if self.insns.is_empty() {
            return Ok(());
        }

        let mut worklist = VecDeque::new();
        worklist.push_back(0);

        while let Some(idx) = worklist.pop_front() {
            if idx >= self.insns.len() || self.reachable.contains(&idx) {
                continue;
            }

            self.reachable.insert(idx);
            let insn = &self.insns[idx];
            let class = insn.class();

            match class {
                BPF_JMP | BPF_JMP32 => {
                    let op = insn.code & 0xf0;
                    match op {
                        BPF_EXIT => {
                            // No successors
                        }
                        BPF_JA => {
                            // Unconditional jump
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            worklist.push_back(target);
                        }
                        BPF_CALL => {
                            if insn.is_pseudo_call() {
                                // Subprogram call - follow both paths
                                let target = (idx as i32 + insn.imm + 1) as usize;
                                worklist.push_back(target);
                            }
                            // Fall through for helper calls
                            worklist.push_back(idx + 1);
                        }
                        _ => {
                            // Conditional jump - both paths
                            worklist.push_back(idx + 1);
                            let target = (idx as i32 + insn.off as i32 + 1) as usize;
                            worklist.push_back(target);
                        }
                    }
                }
                BPF_LD => {
                    // LD_IMM64 is two instructions
                    if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                        self.reachable.insert(idx + 1);
                        worklist.push_back(idx + 2);
                    } else {
                        worklist.push_back(idx + 1);
                    }
                }
                _ => {
                    // Fall through to next instruction
                    worklist.push_back(idx + 1);
                }
            }
        }

        Ok(())
    }

    /// Backward liveness analysis
    fn analyze_liveness(&mut self) -> Result<()> {
        // Initialize: at exit, R0 is live (return value)
        let mut changed = true;
        
        // Find exit points and initialize their live sets
        for (idx, insn) in self.insns.iter().enumerate() {
            if !self.reachable.contains(&idx) {
                continue;
            }
            if insn.class() == BPF_JMP && (insn.code & 0xf0) == BPF_EXIT {
                self.live_regs[idx].insert(BPF_REG_0);
            }
        }

        // Fixed-point iteration (backward)
        while changed {
            changed = false;
            
            for idx in (0..self.insns.len()).rev() {
                if !self.reachable.contains(&idx) {
                    continue;
                }

                let insn = &self.insns[idx];
                let old_live = self.live_regs[idx].clone();

                // Get successor's live set
                let mut new_live = self.get_successor_live(idx);

                // Remove defined register
                if let Some(def_reg) = self.get_def_reg(insn) {
                    new_live.remove(&def_reg);
                }

                // Add used registers
                for used_reg in self.get_used_regs(insn) {
                    new_live.insert(used_reg);
                }

                if new_live != old_live {
                    self.live_regs[idx] = new_live;
                    changed = true;
                }
            }
        }

        Ok(())
    }

    /// Get the union of live registers from successors
    fn get_successor_live(&self, idx: usize) -> HashSet<usize> {
        let mut live = HashSet::new();
        let insn = &self.insns[idx];
        let class = insn.class();

        match class {
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;
                match op {
                    BPF_EXIT => {
                        // No successors
                    }
                    BPF_JA => {
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        if target < self.live_regs.len() {
                            live.extend(&self.live_regs[target]);
                        }
                    }
                    BPF_CALL => {
                        // After call, merge from next instruction
                        if idx + 1 < self.live_regs.len() {
                            live.extend(&self.live_regs[idx + 1]);
                        }
                    }
                    _ => {
                        // Conditional: both paths
                        if idx + 1 < self.live_regs.len() {
                            live.extend(&self.live_regs[idx + 1]);
                        }
                        let target = (idx as i32 + insn.off as i32 + 1) as usize;
                        if target < self.live_regs.len() {
                            live.extend(&self.live_regs[target]);
                        }
                    }
                }
            }
            BPF_LD => {
                if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    // LD_IMM64 successor is idx + 2
                    if idx + 2 < self.live_regs.len() {
                        live.extend(&self.live_regs[idx + 2]);
                    }
                } else if idx + 1 < self.live_regs.len() {
                    live.extend(&self.live_regs[idx + 1]);
                }
            }
            _ => {
                if idx + 1 < self.live_regs.len() {
                    live.extend(&self.live_regs[idx + 1]);
                }
            }
        }

        live
    }

    /// Get the register defined by an instruction
    fn get_def_reg(&self, insn: &BpfInsn) -> Option<usize> {
        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => {
                Some(insn.dst_reg as usize)
            }
            BPF_LDX => {
                Some(insn.dst_reg as usize)
            }
            BPF_LD => {
                if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    Some(insn.dst_reg as usize)
                } else {
                    Some(BPF_REG_0)
                }
            }
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;
                if op == BPF_CALL {
                    Some(BPF_REG_0)
                } else {
                    None
                }
            }
            BPF_STX => {
                // Atomic fetch operations define a register
                if insn.mode() == BPF_ATOMIC {
                    let atomic_op = insn.imm as u32;
                    if atomic_op == BPF_CMPXCHG {
                        Some(BPF_REG_0)
                    } else if atomic_op & BPF_FETCH != 0 {
                        Some(insn.src_reg as usize)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get registers used by an instruction
    fn get_used_regs(&self, insn: &BpfInsn) -> Vec<usize> {
        let mut used = Vec::new();
        let class = insn.class();

        match class {
            BPF_ALU | BPF_ALU64 => {
                let op = insn.code & 0xf0;
                // NEG only uses dst
                if op == BPF_NEG {
                    used.push(insn.dst_reg as usize);
                } else if (insn.code & BPF_X) != 0 {
                    // Register source
                    used.push(insn.src_reg as usize);
                    if op != BPF_MOV {
                        used.push(insn.dst_reg as usize);
                    }
                } else {
                    // Immediate source
                    if op != BPF_MOV {
                        used.push(insn.dst_reg as usize);
                    }
                }
            }
            BPF_LDX => {
                used.push(insn.src_reg as usize);
            }
            BPF_STX => {
                used.push(insn.dst_reg as usize);
                used.push(insn.src_reg as usize);
                if insn.mode() == BPF_ATOMIC {
                    let atomic_op = insn.imm as u32;
                    if atomic_op == BPF_CMPXCHG {
                        used.push(BPF_REG_0); // Compare value
                    }
                }
            }
            BPF_ST => {
                used.push(insn.dst_reg as usize);
            }
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;
                if op == BPF_CALL {
                    // Calls use R1-R5 as arguments
                    for r in 1..=5 {
                        used.push(r);
                    }
                } else if op == BPF_EXIT {
                    used.push(BPF_REG_0);
                } else if op != BPF_JA {
                    // Conditional jumps use dst and possibly src
                    used.push(insn.dst_reg as usize);
                    if (insn.code & BPF_X) != 0 {
                        used.push(insn.src_reg as usize);
                    }
                }
            }
            _ => {}
        }

        used
    }

    /// Mark dead instructions
    fn mark_dead_code(&mut self) {
        for idx in 0..self.insns.len() {
            // Unreachable code is dead
            if !self.reachable.contains(&idx) {
                self.dead_insns.insert(idx);
                continue;
            }

            let insn = &self.insns[idx];

            // Instructions with side effects are always live
            if self.has_side_effect(insn) {
                continue;
            }

            // Check if the defined register is live
            if let Some(def_reg) = self.get_def_reg(insn) {
                // Check successors for liveness
                let successor_live = self.get_successor_live(idx);
                if !successor_live.contains(&def_reg) {
                    // Register is not live - this is dead code
                    self.dead_insns.insert(idx);
                }
            }
        }
    }

    /// Check if instruction has side effects
    fn has_side_effect(&self, insn: &BpfInsn) -> bool {
        let class = insn.class();

        match class {
            // Memory stores have side effects
            BPF_ST | BPF_STX => true,
            // Jumps and exits have control flow effects
            BPF_JMP | BPF_JMP32 => true,
            // ALU and loads are pure (no side effects)
            _ => false,
        }
    }

    /// Get list of unreachable instructions
    pub fn get_unreachable(&self) -> Vec<usize> {
        (0..self.insns.len())
            .filter(|idx| !self.reachable.contains(idx))
            .collect()
    }

    /// Get list of dead (but reachable) instructions
    pub fn get_dead_stores(&self) -> Vec<usize> {
        self.dead_insns
            .iter()
            .filter(|idx| self.reachable.contains(*idx))
            .copied()
            .collect()
    }
}

/// Check for unreachable code in a program
pub fn check_unreachable(insns: &[BpfInsn]) -> Result<Vec<usize>> {
    let mut eliminator = DeadCodeEliminator::new(insns.to_vec());
    eliminator.find_reachable()?;
    Ok(eliminator.get_unreachable())
}

/// Find dead stores in a program
pub fn find_dead_stores(insns: &[BpfInsn]) -> Result<Vec<usize>> {
    let mut eliminator = DeadCodeEliminator::new(insns.to_vec());
    eliminator.eliminate()?;
    Ok(eliminator.get_dead_stores())
}

/// NOP instruction: ja +0 (unconditional jump to next instruction)
const NOP: BpfInsn = BpfInsn {
    code: BPF_JMP | BPF_JA,
    dst_reg: 0,
    src_reg: 0,
    off: 0,
    imm: 0,
};

/// MAY_GOTO with offset 0 (effectively a NOP in may_goto context)
const MAY_GOTO_0: BpfInsn = BpfInsn {
    code: BPF_JMP | BPF_JCOND,
    dst_reg: 0,
    src_reg: 0,
    off: 0,
    imm: 0,
};

/// BPF_JCOND opcode for may_goto instruction
const BPF_JCOND: u8 = 0xe0;

/// Check if an instruction is a NOP (ja +0)
#[inline]
pub fn is_nop(insn: &BpfInsn) -> bool {
    insn.code == NOP.code 
        && insn.dst_reg == NOP.dst_reg 
        && insn.src_reg == NOP.src_reg 
        && insn.off == NOP.off 
        && insn.imm == NOP.imm
}

/// Check if an instruction is may_goto +0
#[inline]
pub fn is_may_goto_0(insn: &BpfInsn) -> bool {
    insn.code == MAY_GOTO_0.code 
        && insn.dst_reg == MAY_GOTO_0.dst_reg 
        && insn.src_reg == MAY_GOTO_0.src_reg 
        && insn.off == MAY_GOTO_0.off 
        && insn.imm == MAY_GOTO_0.imm
}

/// Result of NOP removal optimization
#[derive(Debug, Default)]
pub struct NopRemovalResult {
    /// Number of NOPs removed
    pub nops_removed: usize,
    /// Number of may_goto +0 removed
    pub may_goto_removed: usize,
    /// Total instructions removed
    pub total_removed: usize,
}

/// Remove NOP instructions from a program.
///
/// This function removes:
/// - `ja +0` (unconditional jump to next instruction)
/// - `may_goto +0` (may_goto with zero offset)
///
/// After removal, jump offsets are adjusted to maintain correct control flow.
///
/// This mirrors the kernel's `opt_remove_nops()` function.
pub fn opt_remove_nops(insns: &mut Vec<BpfInsn>) -> Result<NopRemovalResult> {
    let mut result = NopRemovalResult::default();
    let mut i = 0;

    while i < insns.len() {
        let is_may_goto = is_may_goto_0(&insns[i]);
        let is_ja = is_nop(&insns[i]);

        if !is_may_goto && !is_ja {
            i += 1;
            continue;
        }

        // Track what we're removing for statistics
        if is_may_goto {
            result.may_goto_removed += 1;
        } else {
            result.nops_removed += 1;
        }
        result.total_removed += 1;

        // Remove the NOP instruction
        let removed_idx = i;
        insns.remove(removed_idx);

        // Adjust jump targets in remaining instructions
        adjust_jumps_after_removal(insns, removed_idx);

        // Go back to catch sequences like: may_goto +1; may_goto +0
        // After removing may_goto +0, the may_goto +1 becomes may_goto +0
        if is_may_goto && i > 0 {
            i = i.saturating_sub(2);
        } else if i > 0 {
            i = i.saturating_sub(1);
        }
        // If i was 0, it stays at 0 to re-examine the new first instruction
    }

    Ok(result)
}

/// Adjust jump offsets after removing an instruction at `removed_idx`
fn adjust_jumps_after_removal(insns: &mut [BpfInsn], removed_idx: usize) {
    for (idx, insn) in insns.iter_mut().enumerate() {
        let class = insn.class();

        match class {
            BPF_JMP | BPF_JMP32 => {
                let op = insn.code & 0xf0;

                // Skip exit and call instructions (they don't use offset for control flow)
                if op == BPF_EXIT {
                    continue;
                }

                // For CALL with BPF_PSEUDO_CALL, adjust the immediate (relative target)
                if op == BPF_CALL && insn.src_reg == BPF_PSEUDO_CALL as u8 {
                    let target = (idx as i64 + insn.imm as i64 + 1) as usize;
                    
                    if idx < removed_idx && target > removed_idx {
                        // Jump crosses over removed instruction (forward)
                        insn.imm -= 1;
                    } else if idx > removed_idx && target <= removed_idx {
                        // Jump crosses over removed instruction (backward)
                        insn.imm += 1;
                    }
                    continue;
                }

                // Regular jumps use offset field
                if op == BPF_JA || (op >= BPF_JEQ && op <= BPF_JSLE) || op == BPF_JCOND {
                    let target = (idx as i64 + insn.off as i64 + 1) as usize;

                    if idx < removed_idx && target > removed_idx {
                        // Forward jump that crosses over removed instruction
                        insn.off -= 1;
                    } else if idx >= removed_idx && target < removed_idx {
                        // We're after the removal point, and jumping backward past it
                        // Note: idx is already adjusted (points to new position)
                        // but target was calculated with old offset
                        insn.off += 1;
                    }
                }
            }
            BPF_LD => {
                // LD_IMM64 pseudo instructions with BPF_PSEUDO_FUNC need adjustment
                if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
                    if insn.src_reg == BPF_PSEUDO_FUNC as u8 {
                        let target = (idx as i64 + insn.imm as i64 + 1) as usize;
                        
                        if idx < removed_idx && target > removed_idx {
                            insn.imm -= 1;
                        } else if idx > removed_idx && target <= removed_idx {
                            insn.imm += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Combined dead code and NOP removal optimization.
///
/// This function:
/// 1. Removes unreachable code (after unconditional jumps/exits)
/// 2. Removes dead stores (writes to registers never read)
/// 3. Removes NOP instructions
///
/// Returns indices of removed instructions before the actual removal.
pub fn optimize_dead_code(insns: &mut Vec<BpfInsn>) -> Result<OptimizationResult> {
    let mut result = OptimizationResult::default();

    // Phase 1: Find and remove unreachable/dead code
    let mut eliminator = DeadCodeEliminator::new(insns.clone());
    let dead_indices = eliminator.eliminate()?;
    
    // Remove dead instructions in reverse order to preserve indices
    let mut sorted_dead: Vec<_> = dead_indices.into_iter().collect();
    sorted_dead.sort_by(|a, b| b.cmp(a)); // Reverse sort

    for idx in sorted_dead {
        if idx < insns.len() {
            insns.remove(idx);
            adjust_jumps_after_removal(insns, idx);
            result.dead_code_removed += 1;
        }
    }

    // Phase 2: Remove NOPs
    let nop_result = opt_remove_nops(insns)?;
    result.nops_removed = nop_result.total_removed;

    result.total_removed = result.dead_code_removed + result.nops_removed;
    Ok(result)
}

/// Result of combined optimization
#[derive(Debug, Default)]
pub struct OptimizationResult {
    /// Number of dead code instructions removed
    pub dead_code_removed: usize,
    /// Number of NOP instructions removed
    pub nops_removed: usize,
    /// Total instructions removed
    pub total_removed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_reachable() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert!(unreachable.is_empty());
    }

    #[test]
    fn test_unreachable_after_exit() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Unreachable
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert_eq!(unreachable, vec![2]);
    }

    #[test]
    fn test_unreachable_after_unconditional_jump() {
        let insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), // Jump to insn 2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Unreachable
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert_eq!(unreachable, vec![1]);
    }

    #[test]
    fn test_conditional_both_paths_reachable() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0), // Jump to 3 if r0 == 0
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), // Fall through path
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let unreachable = check_unreachable(&insns).unwrap();
        assert!(unreachable.is_empty());
    }

    #[test]
    fn test_dead_store() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Dead: r1 never used
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let dead = find_dead_stores(&insns).unwrap();
        assert_eq!(dead, vec![0]);
    }

    #[test]
    fn test_live_store() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 42), // Live: r1 used below
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),  // r0 = r1
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let dead = find_dead_stores(&insns).unwrap();
        assert!(dead.is_empty());
    }

    #[test]
    fn test_dead_code_eliminator() {
        let insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100), // Dead: r2 overwritten
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 200), // Dead: r2 never used
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let mut eliminator = DeadCodeEliminator::new(insns);
        let dead = eliminator.eliminate().unwrap();
        assert!(dead.contains(&0));
        assert!(dead.contains(&1));
    }

    #[test]
    fn test_is_nop() {
        // ja +0 is a NOP
        let nop = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0);
        assert!(is_nop(&nop));

        // ja +1 is not a NOP
        let not_nop = BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0);
        assert!(!is_nop(&not_nop));

        // Other instructions are not NOPs
        let mov = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0);
        assert!(!is_nop(&mov));
    }

    #[test]
    fn test_opt_remove_nops_single() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(result.total_removed, 1);
        assert_eq!(insns.len(), 2);
    }

    #[test]
    fn test_opt_remove_nops_multiple() {
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 3);
        assert_eq!(insns.len(), 2);
    }

    #[test]
    fn test_opt_remove_nops_preserves_real_jumps() {
        // Original program:
        // 0: ja +2    -> jumps to insn 3 (exit)
        // 1: ja +0    <- NOP
        // 2: mov r0, 42  (unreachable from ja +2, but doesn't matter for this test)
        // 3: exit
        //
        // After NOP removal:
        // 0: ja +1    -> jumps to insn 2 (exit) - offset decremented by 1
        // 1: mov r0, 42
        // 2: exit
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 2, 0), // Jump to exit (offset 2)
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(insns.len(), 3);
        
        // First instruction: original target was index 3 (idx 0 + off 2 + 1 = 3)
        // After removing index 1, target index 3 becomes 2
        // New offset: 2 - 0 - 1 = 1
        assert_eq!(insns[0].off, 1); // ja +2 becomes ja +1
    }

    #[test]
    fn test_opt_remove_nops_adjusts_forward_jumps() {
        let mut insns = vec![
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 0), // Jump to exit if r0 == 0
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = opt_remove_nops(&mut insns).unwrap();
        assert_eq!(result.nops_removed, 1);
        assert_eq!(insns.len(), 3);
        
        // Conditional jump should now point to exit (offset 1 instead of 2)
        assert_eq!(insns[0].off, 1);
    }

    #[test]
    fn test_opt_remove_nops_no_nops() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 42),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let original_len = insns.len();
        let result = opt_remove_nops(&mut insns).unwrap();
        
        assert_eq!(result.total_removed, 0);
        assert_eq!(insns.len(), original_len);
    }

    #[test]
    fn test_optimize_dead_code_combined() {
        let mut insns = vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100), // Dead store
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 0, 0), // NOP
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let result = optimize_dead_code(&mut insns).unwrap();
        
        // Should remove dead store and NOP
        assert!(result.dead_code_removed >= 1);
        assert!(result.total_removed >= 1);
    }
}
