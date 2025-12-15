//! Scalar value range refinement on conditional branches.
//!
//! This module implements range refinement for scalar values based on
//! conditional branch outcomes. When a branch condition is known to be
//! true or false, the value ranges of the compared registers can be
//! narrowed accordingly.

use crate::bounds::tnum::Tnum;
use crate::core::types::{BpfRegType, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JNE, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_JSET};
use crate::state::reg_state::BpfRegState;

/// Branch condition for refinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchCond {
    /// Equal (JEQ).
    Eq,
    /// Not equal (JNE).
    Ne,
    /// Greater than unsigned (JGT).
    Gt,
    /// Greater or equal unsigned (JGE).
    Ge,
    /// Less than unsigned (JLT).
    Lt,
    /// Less or equal unsigned (JLE).
    Le,
    /// Signed greater than (JSGT).
    Sgt,
    /// Signed greater or equal (JSGE).
    Sge,
    /// Signed less than (JSLT).
    Slt,
    /// Signed less or equal (JSLE).
    Sle,
    /// Bit test (JSET).
    Set,
}

impl BranchCond {
    /// Create from BPF jump opcode.
    pub fn from_opcode(op: u8) -> Option<Self> {
        match op {
            BPF_JEQ => Some(BranchCond::Eq),
            BPF_JNE => Some(BranchCond::Ne),
            BPF_JGT => Some(BranchCond::Gt),
            BPF_JGE => Some(BranchCond::Ge),
            BPF_JLT => Some(BranchCond::Lt),
            BPF_JLE => Some(BranchCond::Le),
            BPF_JSGT => Some(BranchCond::Sgt),
            BPF_JSGE => Some(BranchCond::Sge),
            BPF_JSLT => Some(BranchCond::Slt),
            BPF_JSLE => Some(BranchCond::Sle),
            BPF_JSET => Some(BranchCond::Set),
            _ => None,
        }
    }

    /// Get the negated condition (for the false branch).
    pub fn negate(self) -> Self {
        match self {
            BranchCond::Eq => BranchCond::Ne,
            BranchCond::Ne => BranchCond::Eq,
            BranchCond::Gt => BranchCond::Le,
            BranchCond::Ge => BranchCond::Lt,
            BranchCond::Lt => BranchCond::Ge,
            BranchCond::Le => BranchCond::Gt,
            BranchCond::Sgt => BranchCond::Sle,
            BranchCond::Sge => BranchCond::Slt,
            BranchCond::Slt => BranchCond::Sge,
            BranchCond::Sle => BranchCond::Sgt,
            BranchCond::Set => BranchCond::Set, // !JSET doesn't have simple negation
        }
    }

    /// Check if this is a signed comparison.
    pub fn is_signed(self) -> bool {
        matches!(self, BranchCond::Sgt | BranchCond::Sge | BranchCond::Slt | BranchCond::Sle)
    }
}

/// Result of range refinement.
#[derive(Debug, Clone)]
pub struct RefinementResult {
    /// Whether refinement was applied.
    pub refined: bool,
    /// New unsigned minimum.
    pub umin: u64,
    /// New unsigned maximum.
    pub umax: u64,
    /// New signed minimum.
    pub smin: i64,
    /// New signed maximum.
    pub smax: i64,
    /// New tnum.
    pub var_off: Tnum,
}

impl RefinementResult {
    /// Create from existing register bounds.
    pub fn from_reg(reg: &BpfRegState) -> Self {
        Self {
            refined: false,
            umin: reg.umin_value,
            umax: reg.umax_value,
            smin: reg.smin_value,
            smax: reg.smax_value,
            var_off: reg.var_off,
        }
    }

    /// Mark as refined.
    pub fn mark_refined(&mut self) {
        self.refined = true;
    }

    /// Check if the range is empty (no valid values).
    pub fn is_empty(&self) -> bool {
        self.umin > self.umax || self.smin > self.smax
    }

    /// Apply refinement to a register.
    pub fn apply_to(&self, reg: &mut BpfRegState) {
        if self.refined {
            reg.umin_value = self.umin;
            reg.umax_value = self.umax;
            reg.smin_value = self.smin;
            reg.smax_value = self.smax;
            reg.var_off = self.var_off;
        }
    }
}

/// Refine register range based on comparison with a constant.
pub fn refine_reg_const(
    reg: &BpfRegState,
    val: u64,
    cond: BranchCond,
    branch_taken: bool,
) -> RefinementResult {
    let mut result = RefinementResult::from_reg(reg);
    
    // Get the effective condition based on branch direction
    let eff_cond = if branch_taken { cond } else { cond.negate() };
    
    // Only refine scalar values
    if reg.reg_type != BpfRegType::ScalarValue {
        return result;
    }

    let sval = val as i64;

    match eff_cond {
        BranchCond::Eq => {
            // reg == val
            result.umin = val;
            result.umax = val;
            result.smin = sval;
            result.smax = sval;
            result.var_off = Tnum::const_value(val);
            result.mark_refined();
        }
        BranchCond::Ne => {
            // reg != val
            // Can only refine if val is at a boundary
            if result.umin == val && result.umin < result.umax {
                result.umin = val + 1;
                result.mark_refined();
            }
            if result.umax == val && result.umax > result.umin {
                result.umax = val - 1;
                result.mark_refined();
            }
            if result.smin == sval && result.smin < result.smax {
                result.smin = sval + 1;
                result.mark_refined();
            }
            if result.smax == sval && result.smax > result.smin {
                result.smax = sval - 1;
                result.mark_refined();
            }
        }
        BranchCond::Gt => {
            // reg > val (unsigned)
            if val < u64::MAX {
                let new_min = val + 1;
                if new_min > result.umin {
                    result.umin = new_min;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Ge => {
            // reg >= val (unsigned)
            if val > result.umin {
                result.umin = val;
                result.mark_refined();
            }
        }
        BranchCond::Lt => {
            // reg < val (unsigned)
            if val > 0 {
                let new_max = val - 1;
                if new_max < result.umax {
                    result.umax = new_max;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Le => {
            // reg <= val (unsigned)
            if val < result.umax {
                result.umax = val;
                result.mark_refined();
            }
        }
        BranchCond::Sgt => {
            // reg > val (signed)
            if sval < i64::MAX {
                let new_min = sval + 1;
                if new_min > result.smin {
                    result.smin = new_min;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Sge => {
            // reg >= val (signed)
            if sval > result.smin {
                result.smin = sval;
                result.mark_refined();
            }
        }
        BranchCond::Slt => {
            // reg < val (signed)
            if sval > i64::MIN {
                let new_max = sval - 1;
                if new_max < result.smax {
                    result.smax = new_max;
                    result.mark_refined();
                }
            }
        }
        BranchCond::Sle => {
            // reg <= val (signed)
            if sval < result.smax {
                result.smax = sval;
                result.mark_refined();
            }
        }
        BranchCond::Set => {
            // reg & val != 0 (when taken)
            // When taken, at least one bit in the mask must be set
            if branch_taken && val != 0 {
                // Can't easily refine range, but we know at least one bit is set
                // Update tnum to reflect this
                result.var_off = result.var_off.and(Tnum::const_value(val));
                if result.var_off.value != 0 {
                    result.mark_refined();
                }
            }
        }
    }

    // Synchronize signed and unsigned bounds
    if result.refined {
        sync_bounds(&mut result);
    }

    result
}

/// Refine both registers based on comparison between them.
pub fn refine_reg_reg(
    dst: &BpfRegState,
    src: &BpfRegState,
    cond: BranchCond,
    branch_taken: bool,
) -> (RefinementResult, RefinementResult) {
    let mut dst_result = RefinementResult::from_reg(dst);
    let mut src_result = RefinementResult::from_reg(src);

    // Only refine scalars
    if dst.reg_type != BpfRegType::ScalarValue || src.reg_type != BpfRegType::ScalarValue {
        return (dst_result, src_result);
    }

    let eff_cond = if branch_taken { cond } else { cond.negate() };

    match eff_cond {
        BranchCond::Eq => {
            // dst == src: ranges must intersect
            let new_umin = dst_result.umin.max(src_result.umin);
            let new_umax = dst_result.umax.min(src_result.umax);
            let new_smin = dst_result.smin.max(src_result.smin);
            let new_smax = dst_result.smax.min(src_result.smax);

            if new_umin != dst_result.umin || new_umax != dst_result.umax {
                dst_result.umin = new_umin;
                dst_result.umax = new_umax;
                dst_result.mark_refined();
            }
            if new_smin != dst_result.smin || new_smax != dst_result.smax {
                dst_result.smin = new_smin;
                dst_result.smax = new_smax;
                dst_result.mark_refined();
            }
            
            // Apply same to src
            if new_umin != src_result.umin || new_umax != src_result.umax {
                src_result.umin = new_umin;
                src_result.umax = new_umax;
                src_result.mark_refined();
            }
            if new_smin != src_result.smin || new_smax != src_result.smax {
                src_result.smin = new_smin;
                src_result.smax = new_smax;
                src_result.mark_refined();
            }
        }
        BranchCond::Ne => {
            // dst != src: limited refinement at boundaries
            // If src is a constant, refine dst
            if src_result.umin == src_result.umax {
                let const_val = src_result.umin;
                if dst_result.umin == const_val && dst_result.umin < dst_result.umax {
                    dst_result.umin = const_val + 1;
                    dst_result.mark_refined();
                }
                if dst_result.umax == const_val && dst_result.umax > dst_result.umin {
                    dst_result.umax = const_val - 1;
                    dst_result.mark_refined();
                }
            }
            // Similarly for dst constant
            if dst_result.umin == dst_result.umax {
                let const_val = dst_result.umin;
                if src_result.umin == const_val && src_result.umin < src_result.umax {
                    src_result.umin = const_val + 1;
                    src_result.mark_refined();
                }
                if src_result.umax == const_val && src_result.umax > src_result.umin {
                    src_result.umax = const_val - 1;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Gt => {
            // dst > src (unsigned)
            // dst_min > src_min possible, dst_max > src_max possible
            if src_result.umin < u64::MAX {
                let new_dst_min = src_result.umin + 1;
                if new_dst_min > dst_result.umin {
                    dst_result.umin = new_dst_min;
                    dst_result.mark_refined();
                }
            }
            if dst_result.umax > 0 {
                let new_src_max = dst_result.umax - 1;
                if new_src_max < src_result.umax {
                    src_result.umax = new_src_max;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Ge => {
            // dst >= src (unsigned)
            if src_result.umin > dst_result.umin {
                dst_result.umin = src_result.umin;
                dst_result.mark_refined();
            }
            if dst_result.umax < src_result.umax {
                src_result.umax = dst_result.umax;
                src_result.mark_refined();
            }
        }
        BranchCond::Lt => {
            // dst < src (unsigned)
            if dst_result.umin > 0 {
                let new_src_min = dst_result.umin + 1;
                if new_src_min > src_result.umin {
                    src_result.umin = new_src_min;
                    src_result.mark_refined();
                }
            }
            if src_result.umax > 0 {
                let new_dst_max = src_result.umax - 1;
                if new_dst_max < dst_result.umax {
                    dst_result.umax = new_dst_max;
                    dst_result.mark_refined();
                }
            }
        }
        BranchCond::Le => {
            // dst <= src (unsigned)
            if dst_result.umin > src_result.umin {
                src_result.umin = dst_result.umin;
                src_result.mark_refined();
            }
            if src_result.umax < dst_result.umax {
                dst_result.umax = src_result.umax;
                dst_result.mark_refined();
            }
        }
        BranchCond::Sgt => {
            // dst > src (signed)
            if src_result.smin < i64::MAX {
                let new_dst_min = src_result.smin + 1;
                if new_dst_min > dst_result.smin {
                    dst_result.smin = new_dst_min;
                    dst_result.mark_refined();
                }
            }
            if dst_result.smax > i64::MIN {
                let new_src_max = dst_result.smax - 1;
                if new_src_max < src_result.smax {
                    src_result.smax = new_src_max;
                    src_result.mark_refined();
                }
            }
        }
        BranchCond::Sge => {
            // dst >= src (signed)
            if src_result.smin > dst_result.smin {
                dst_result.smin = src_result.smin;
                dst_result.mark_refined();
            }
            if dst_result.smax < src_result.smax {
                src_result.smax = dst_result.smax;
                src_result.mark_refined();
            }
        }
        BranchCond::Slt => {
            // dst < src (signed)
            if dst_result.smin > i64::MIN {
                let new_src_min = dst_result.smin + 1;
                if new_src_min > src_result.smin {
                    src_result.smin = new_src_min;
                    src_result.mark_refined();
                }
            }
            if src_result.smax > i64::MIN {
                let new_dst_max = src_result.smax - 1;
                if new_dst_max < dst_result.smax {
                    dst_result.smax = new_dst_max;
                    dst_result.mark_refined();
                }
            }
        }
        BranchCond::Sle => {
            // dst <= src (signed)
            if dst_result.smin > src_result.smin {
                src_result.smin = dst_result.smin;
                src_result.mark_refined();
            }
            if src_result.smax < dst_result.smax {
                dst_result.smax = src_result.smax;
                dst_result.mark_refined();
            }
        }
        BranchCond::Set => {
            // dst & src != 0
            // Limited refinement possible
        }
    }

    // Synchronize bounds
    if dst_result.refined {
        sync_bounds(&mut dst_result);
    }
    if src_result.refined {
        sync_bounds(&mut src_result);
    }

    (dst_result, src_result)
}

/// Synchronize signed and unsigned bounds.
fn sync_bounds(result: &mut RefinementResult) {
    // If umin/umax fit in signed range, update smin/smax
    if result.umax <= i64::MAX as u64 {
        result.smin = result.smin.max(result.umin as i64);
        result.smax = result.smax.min(result.umax as i64);
    }
    
    // If smin/smax are non-negative, update umin/umax
    if result.smin >= 0 {
        result.umin = result.umin.max(result.smin as u64);
        if result.smax >= 0 {
            result.umax = result.umax.min(result.smax as u64);
        }
    }
}

/// Check if a branch condition can be determined statically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchOutcome {
    /// Branch is always taken.
    AlwaysTaken,
    /// Branch is never taken.
    NeverTaken,
    /// Branch outcome is unknown.
    Unknown,
}

/// Determine branch outcome from register ranges.
pub fn determine_branch_outcome(
    dst: &BpfRegState,
    src_val: u64,
    cond: BranchCond,
) -> BranchOutcome {
    if dst.reg_type != BpfRegType::ScalarValue {
        return BranchOutcome::Unknown;
    }

    let sval = src_val as i64;

    match cond {
        BranchCond::Eq => {
            if dst.umin_value == dst.umax_value && dst.umin_value == src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value < src_val || dst.umin_value > src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Ne => {
            if dst.umax_value < src_val || dst.umin_value > src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value == dst.umax_value && dst.umin_value == src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Gt => {
            if dst.umin_value > src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value <= src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Ge => {
            if dst.umin_value >= src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umax_value < src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Lt => {
            if dst.umax_value < src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value >= src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Le => {
            if dst.umax_value <= src_val {
                BranchOutcome::AlwaysTaken
            } else if dst.umin_value > src_val {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sgt => {
            if dst.smin_value > sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smax_value <= sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sge => {
            if dst.smin_value >= sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smax_value < sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Slt => {
            if dst.smax_value < sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smin_value >= sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Sle => {
            if dst.smax_value <= sval {
                BranchOutcome::AlwaysTaken
            } else if dst.smin_value > sval {
                BranchOutcome::NeverTaken
            } else {
                BranchOutcome::Unknown
            }
        }
        BranchCond::Set => {
            // reg & val != 0
            let known_bits = !dst.var_off.mask;
            let known_value = dst.var_off.value;
            
            // If we know all bits of (reg & val), we can determine outcome
            if (known_bits & src_val) == src_val {
                if (known_value & src_val) != 0 {
                    BranchOutcome::AlwaysTaken
                } else {
                    BranchOutcome::NeverTaken
                }
            } else {
                BranchOutcome::Unknown
            }
        }
    }
}

/// Convenience wrapper for register-to-register comparison refinement.
///
/// This refines both registers based on the given condition being true
/// (branch taken). Returns refinement results for both registers.
///
/// # Arguments
/// * `dst` - Destination register state
/// * `src` - Source register state  
/// * `cond` - The branch condition
/// * `is_32bit` - Whether this is a 32-bit comparison
///
/// # Returns
/// Tuple of (dst_refinement, src_refinement)
pub fn refine_regs(
    dst: &BpfRegState,
    src: &BpfRegState,
    cond: BranchCond,
    _is_32bit: bool,
) -> (RefinementResult, RefinementResult) {
    // Use refine_reg_reg with branch_taken=true since the condition
    // represents what we know to be true on this path
    refine_reg_reg(dst, src, cond, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scalar(umin: u64, umax: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = umin;
        reg.umax_value = umax;
        reg.smin_value = umin as i64;
        reg.smax_value = umax as i64;
        reg.var_off = Tnum::unknown();
        reg
    }

    fn make_scalar_signed(smin: i64, smax: i64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.smin_value = smin;
        reg.smax_value = smax;
        reg.umin_value = 0;
        reg.umax_value = u64::MAX;
        reg.var_off = Tnum::unknown();
        reg
    }

    #[test]
    fn test_branch_cond_from_opcode() {
        assert_eq!(BranchCond::from_opcode(BPF_JEQ), Some(BranchCond::Eq));
        assert_eq!(BranchCond::from_opcode(BPF_JGT), Some(BranchCond::Gt));
        assert_eq!(BranchCond::from_opcode(BPF_JSLT), Some(BranchCond::Slt));
        assert_eq!(BranchCond::from_opcode(0xFF), None);
    }

    #[test]
    fn test_branch_cond_negate() {
        assert_eq!(BranchCond::Eq.negate(), BranchCond::Ne);
        assert_eq!(BranchCond::Gt.negate(), BranchCond::Le);
        assert_eq!(BranchCond::Slt.negate(), BranchCond::Sge);
    }

    #[test]
    fn test_refine_reg_eq_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 42, BranchCond::Eq, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 42);
        assert_eq!(result.umax, 42);
    }

    #[test]
    fn test_refine_reg_gt_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Gt, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 51);
        assert_eq!(result.umax, 100);
    }

    #[test]
    fn test_refine_reg_lt_const() {
        let reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Lt, true);
        
        assert!(result.refined);
        assert_eq!(result.umin, 0);
        assert_eq!(result.umax, 49);
    }

    #[test]
    fn test_refine_reg_ne_at_boundary() {
        let reg = make_scalar(10, 20);
        
        // NE with min value
        let result = refine_reg_const(&reg, 10, BranchCond::Ne, true);
        assert!(result.refined);
        assert_eq!(result.umin, 11);
        
        // NE with max value
        let result = refine_reg_const(&reg, 20, BranchCond::Ne, true);
        assert!(result.refined);
        assert_eq!(result.umax, 19);
    }

    #[test]
    fn test_refine_reg_signed() {
        let reg = make_scalar_signed(-100, 100);
        
        // JSGT 0 (r > 0)
        let result = refine_reg_const(&reg, 0, BranchCond::Sgt, true);
        assert!(result.refined);
        assert_eq!(result.smin, 1);
        
        // JSLT 0 (r < 0)
        let result = refine_reg_const(&reg, 0, BranchCond::Slt, true);
        assert!(result.refined);
        assert_eq!(result.smax, -1);
    }

    #[test]
    fn test_refine_reg_reg_eq() {
        let dst = make_scalar(0, 100);
        let src = make_scalar(50, 150);
        
        let (dst_result, src_result) = refine_reg_reg(&dst, &src, BranchCond::Eq, true);
        
        // Intersection should be [50, 100]
        assert!(dst_result.refined);
        assert!(src_result.refined);
        assert_eq!(dst_result.umin, 50);
        assert_eq!(dst_result.umax, 100);
        assert_eq!(src_result.umin, 50);
        assert_eq!(src_result.umax, 100);
    }

    #[test]
    fn test_refine_reg_reg_gt() {
        let dst = make_scalar(0, 100);
        let src = make_scalar(0, 100);
        
        // dst > src
        let (dst_result, src_result) = refine_reg_reg(&dst, &src, BranchCond::Gt, true);
        
        assert!(dst_result.refined);
        assert!(src_result.refined);
        // dst > src means dst >= 1 and src <= 99
        assert_eq!(dst_result.umin, 1);
        assert_eq!(src_result.umax, 99);
    }

    #[test]
    fn test_branch_outcome_always_taken() {
        let reg = make_scalar(100, 200);
        
        // 100..200 > 50 is always true
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Gt),
            BranchOutcome::AlwaysTaken
        );
        
        // 100..200 >= 100 is always true
        assert_eq!(
            determine_branch_outcome(&reg, 100, BranchCond::Ge),
            BranchOutcome::AlwaysTaken
        );
    }

    #[test]
    fn test_branch_outcome_never_taken() {
        let reg = make_scalar(100, 200);
        
        // 100..200 < 50 is always false
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Lt),
            BranchOutcome::NeverTaken
        );
        
        // 100..200 == 50 is always false
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Eq),
            BranchOutcome::NeverTaken
        );
    }

    #[test]
    fn test_branch_outcome_unknown() {
        let reg = make_scalar(0, 100);
        
        // 0..100 > 50 could be either
        assert_eq!(
            determine_branch_outcome(&reg, 50, BranchCond::Gt),
            BranchOutcome::Unknown
        );
    }

    #[test]
    fn test_refinement_result_is_empty() {
        let mut result = RefinementResult {
            refined: true,
            umin: 100,
            umax: 50, // Invalid: min > max
            smin: 0,
            smax: 0,
            var_off: Tnum::unknown(),
        };
        assert!(result.is_empty());
        
        result.umin = 0;
        result.umax = 100;
        result.smin = 50;
        result.smax = 10; // Invalid: smin > smax
        assert!(result.is_empty());
    }

    #[test]
    fn test_branch_false_path() {
        let reg = make_scalar(0, 100);
        
        // if (r > 50) {} else { /* r <= 50 here */ }
        let result = refine_reg_const(&reg, 50, BranchCond::Gt, false);
        
        assert!(result.refined);
        assert_eq!(result.umax, 50); // Not taken means r <= 50
    }

    #[test]
    fn test_refine_applies_to_reg() {
        let mut reg = make_scalar(0, 100);
        let result = refine_reg_const(&reg, 50, BranchCond::Lt, true);
        
        result.apply_to(&mut reg);
        
        assert_eq!(reg.umax_value, 49);
    }
}
