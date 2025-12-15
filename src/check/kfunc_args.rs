//!

//! This module provides detailed validation for kernel function arguments,

//! including type checking, nullability, size validation, and reference handling.


#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use crate::core::error::{Result, VerifierError};
use crate::core::types::BpfRegType;
use crate::state::reg_state::BpfRegState;

/// Argument kind for kfuncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Scalar value (integer).
    Scalar,
    /// Pointer to memory.
    PtrToMem,
    /// Pointer to context.
    PtrToCtx,
    /// Pointer to BTF ID (typed pointer).
    PtrToBtfId,
    /// Reference that will be acquired.
    RefAcquire,
    /// Reference that will be released.
    RefRelease,
    /// RCU-protected pointer.
    RcuPtr,
    /// Callback function pointer.
    Callback,
    /// Dynptr.
    Dynptr,
    /// Any pointer type.
    AnyPtr,
    /// Constant size (compile-time known).
    ConstSize,
    /// Variable size from other argument.
    VarSize,
}

/// Argument constraint for validation.
#[derive(Debug, Clone)]
pub struct ArgConstraint {
    /// Argument kind.
    pub kind: ArgKind,
    /// Whether the argument can be NULL.
    pub nullable: bool,
    /// Expected BTF type ID (0 for any).
    pub btf_id: u32,
    /// Minimum size in bytes (for sized pointers).
    pub min_size: u32,
    /// Maximum size in bytes (0 for unlimited).
    pub max_size: u32,
    /// Fixed size (if > 0, must match exactly).
    pub fixed_size: u32,
    /// Argument index for size reference (for VarSize).
    pub size_arg_idx: Option<usize>,
    /// Whether pointer must be aligned.
    pub aligned: bool,
    /// Required alignment (0 for default).
    pub alignment: u32,
    /// Whether the memory must be initialized.
    pub initialized: bool,
    /// Whether the memory is read-only.
    pub readonly: bool,
}

impl Default for ArgConstraint {
    fn default() -> Self {
        Self {
            kind: ArgKind::Scalar,
            nullable: false,
            btf_id: 0,
            min_size: 0,
            max_size: 0,
            fixed_size: 0,
            size_arg_idx: None,
            aligned: true,
            alignment: 0,
            initialized: true,
            readonly: false,
        }
    }
}

impl ArgConstraint {
    /// Create a scalar argument constraint.
    pub fn scalar() -> Self {
        Self {
            kind: ArgKind::Scalar,
            ..Default::default()
        }
    }

    /// Create a pointer-to-memory constraint.
    pub fn ptr_to_mem(min_size: u32) -> Self {
        Self {
            kind: ArgKind::PtrToMem,
            min_size,
            ..Default::default()
        }
    }

    /// Create a pointer-to-BTF-ID constraint.
    pub fn ptr_to_btf_id(btf_id: u32) -> Self {
        Self {
            kind: ArgKind::PtrToBtfId,
            btf_id,
            ..Default::default()
        }
    }

    /// Create a reference acquire constraint.
    pub fn ref_acquire(btf_id: u32) -> Self {
        Self {
            kind: ArgKind::RefAcquire,
            btf_id,
            nullable: true, // Return can be NULL
            ..Default::default()
        }
    }

    /// Create a reference release constraint.
    pub fn ref_release(btf_id: u32) -> Self {
        Self {
            kind: ArgKind::RefRelease,
            btf_id,
            ..Default::default()
        }
    }

    /// Create a context pointer constraint.
    pub fn ptr_to_ctx() -> Self {
        Self {
            kind: ArgKind::PtrToCtx,
            ..Default::default()
        }
    }

    /// Create an any-pointer constraint.
    pub fn any_ptr() -> Self {
        Self {
            kind: ArgKind::AnyPtr,
            ..Default::default()
        }
    }

    /// Create a const-size constraint.
    pub fn const_size(size: u32) -> Self {
        Self {
            kind: ArgKind::ConstSize,
            fixed_size: size,
            ..Default::default()
        }
    }

    /// Create a variable-size constraint.
    pub fn var_size(size_arg_idx: usize) -> Self {
        Self {
            kind: ArgKind::VarSize,
            size_arg_idx: Some(size_arg_idx),
            ..Default::default()
        }
    }

    /// Mark as nullable.
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }

    /// Set minimum size.
    pub fn with_min_size(mut self, size: u32) -> Self {
        self.min_size = size;
        self
    }

    /// Set maximum size.
    pub fn with_max_size(mut self, size: u32) -> Self {
        self.max_size = size;
        self
    }

    /// Set alignment requirement.
    pub fn with_alignment(mut self, alignment: u32) -> Self {
        self.alignment = alignment;
        self.aligned = true;
        self
    }

    /// Mark as read-only.
    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }

    /// Mark as uninitialized allowed.
    pub fn uninit_ok(mut self) -> Self {
        self.initialized = false;
        self
    }
}

/// Kfunc signature for validation.
#[derive(Debug, Clone)]
pub struct KfuncSignature {
    /// Function name.
    pub name: String,
    /// Argument constraints.
    pub args: Vec<ArgConstraint>,
    /// Return type constraint.
    pub ret: Option<ArgConstraint>,
    /// Whether the function is sleepable.
    pub sleepable: bool,
    /// Whether the function is destructive.
    pub destructive: bool,
}

impl KfuncSignature {
    /// Create a new kfunc signature.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            args: Vec::new(),
            ret: None,
            sleepable: false,
            destructive: false,
        }
    }

    /// Add an argument constraint.
    pub fn arg(mut self, constraint: ArgConstraint) -> Self {
        self.args.push(constraint);
        self
    }

    /// Set return type constraint.
    pub fn returns(mut self, constraint: ArgConstraint) -> Self {
        self.ret = Some(constraint);
        self
    }

    /// Mark as sleepable.
    pub fn sleepable(mut self) -> Self {
        self.sleepable = true;
        self
    }

    /// Mark as destructive.
    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    /// Get number of arguments.
    pub fn arg_count(&self) -> usize {
        self.args.len()
    }
}

/// Result of argument validation.
#[derive(Debug, Clone)]
pub struct ArgValidationResult {
    /// Whether validation passed.
    pub valid: bool,
    /// Argument index.
    pub arg_idx: usize,
    /// Error message if invalid.
    pub error: Option<String>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Inferred size (for VarSize arguments).
    pub inferred_size: Option<u32>,
}

impl ArgValidationResult {
    /// Create a successful result.
    pub fn success(arg_idx: usize) -> Self {
        Self {
            valid: true,
            arg_idx,
            error: None,
            warnings: Vec::new(),
            inferred_size: None,
        }
    }

    /// Create a failed result.
    pub fn failure(arg_idx: usize, error: String) -> Self {
        Self {
            valid: false,
            arg_idx,
            error: Some(error),
            warnings: Vec::new(),
            inferred_size: None,
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }

    /// Set inferred size.
    pub fn with_size(mut self, size: u32) -> Self {
        self.inferred_size = Some(size);
        self
    }
}

/// Validate a kfunc argument against its constraint.
pub fn validate_arg(
    reg: &BpfRegState,
    constraint: &ArgConstraint,
    arg_idx: usize,
    size_from_arg: Option<u64>,
) -> ArgValidationResult {
    // Check nullability
    if !constraint.nullable && reg.may_be_null() {
        return ArgValidationResult::failure(
            arg_idx,
            format!("argument {} cannot be NULL", arg_idx),
        );
    }

    match constraint.kind {
        ArgKind::Scalar => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be a scalar, got {:?}", arg_idx, reg.reg_type),
                );
            }
            // Check if value is within expected range
            if constraint.min_size > 0
                && reg.umax_value < constraint.min_size as u64 {
                    return ArgValidationResult::failure(
                        arg_idx,
                        format!(
                            "argument {} value {} is below minimum {}",
                            arg_idx, reg.umax_value, constraint.min_size
                        ),
                    );
                }
            if constraint.max_size > 0 && reg.umin_value > constraint.max_size as u64 {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!(
                        "argument {} value {} exceeds maximum {}",
                        arg_idx, reg.umin_value, constraint.max_size
                    ),
                );
            }
        }

        ArgKind::PtrToMem | ArgKind::AnyPtr => {
            if !reg.is_ptr() {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be a pointer, got {:?}", arg_idx, reg.reg_type),
                );
            }
            // Size validation would require memory tracking
        }

        ArgKind::PtrToCtx => {
            if reg.reg_type != BpfRegType::PtrToCtx {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be context pointer, got {:?}", arg_idx, reg.reg_type),
                );
            }
        }

        ArgKind::PtrToBtfId => {
            if !reg.is_ptr() {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be a BTF-typed pointer", arg_idx),
                );
            }
            // BTF ID check would require btf_info from register
            if constraint.btf_id != 0 {
                if let Some(ref btf_info) = reg.btf_info {
                    if btf_info.btf_id != constraint.btf_id {
                        return ArgValidationResult::failure(
                            arg_idx,
                            format!(
                                "argument {} BTF ID mismatch: expected {}, got {}",
                                arg_idx, constraint.btf_id, btf_info.btf_id
                            ),
                        );
                    }
                }
            }
        }

        ArgKind::RefAcquire | ArgKind::RefRelease => {
            // Reference arguments must be valid pointers
            if !reg.is_ptr() && reg.reg_type != BpfRegType::ScalarValue {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be a reference pointer", arg_idx),
                );
            }
            // ref_obj_id tracking would be checked separately
        }

        ArgKind::RcuPtr => {
            if !reg.is_ptr() {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} must be an RCU pointer", arg_idx),
                );
            }
            // RCU protection check would happen at call site
        }

        ArgKind::Callback => {
            // Callback must be a valid function pointer
            // This would be validated against subprog info
        }

        ArgKind::Dynptr => {
            if reg.reg_type != BpfRegType::PtrToStack {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} dynptr must be on stack", arg_idx),
                );
            }
        }

        ArgKind::ConstSize => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} size must be a constant scalar", arg_idx),
                );
            }
            if reg.umin_value != reg.umax_value {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} size must be a compile-time constant", arg_idx),
                );
            }
            if constraint.fixed_size > 0 && reg.umin_value != constraint.fixed_size as u64 {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!(
                        "argument {} size mismatch: expected {}, got {}",
                        arg_idx, constraint.fixed_size, reg.umin_value
                    ),
                );
            }
            return ArgValidationResult::success(arg_idx).with_size(reg.umin_value as u32);
        }

        ArgKind::VarSize => {
            if reg.reg_type != BpfRegType::ScalarValue {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!("argument {} size must be a scalar", arg_idx),
                );
            }
            // Use the size from the referenced argument
            if let Some(size) = size_from_arg {
                if constraint.min_size > 0 && size < constraint.min_size as u64 {
                    return ArgValidationResult::failure(
                        arg_idx,
                        format!("size {} is below minimum {}", size, constraint.min_size),
                    );
                }
                if constraint.max_size > 0 && size > constraint.max_size as u64 {
                    return ArgValidationResult::failure(
                        arg_idx,
                        format!("size {} exceeds maximum {}", size, constraint.max_size),
                    );
                }
            }
        }
    }

    // Check alignment if required
    if constraint.aligned && constraint.alignment > 0
        && reg.is_ptr() && reg.off != 0 {
            let off = reg.off.unsigned_abs();
            if !off.is_multiple_of(constraint.alignment) {
                return ArgValidationResult::failure(
                    arg_idx,
                    format!(
                        "argument {} offset {} not aligned to {}",
                        arg_idx, reg.off, constraint.alignment
                    ),
                );
            }
        }

    let mut result = ArgValidationResult::success(arg_idx);

    // Add warnings for potentially unsafe patterns
    if constraint.kind == ArgKind::PtrToMem && !constraint.readonly
        && reg.reg_type == BpfRegType::PtrToPacket {
            result = result.with_warning(format!(
                "argument {} writes to packet data",
                arg_idx
            ));
        }

    result
}

/// Validate all arguments for a kfunc call.
pub fn validate_kfunc_call(
    signature: &KfuncSignature,
    regs: &[&BpfRegState],
) -> Result<Vec<ArgValidationResult>> {
    if regs.len() != signature.args.len() {
        return Err(VerifierError::InvalidFunctionCall(format!(
            "kfunc {} expects {} arguments, got {}",
            signature.name,
            signature.args.len(),
            regs.len()
        )));
    }

    let mut results = Vec::new();
    let mut sizes: Vec<Option<u64>> = vec![None; regs.len()];

    // First pass: collect sizes from ConstSize arguments
    for (idx, (reg, constraint)) in regs.iter().zip(signature.args.iter()).enumerate() {
        if constraint.kind == ArgKind::ConstSize
            && reg.reg_type == BpfRegType::ScalarValue && reg.umin_value == reg.umax_value {
                sizes[idx] = Some(reg.umin_value);
            }
    }

    // Second pass: validate all arguments
    for (idx, (reg, constraint)) in regs.iter().zip(signature.args.iter()).enumerate() {
        let size_from_arg = if let Some(size_idx) = constraint.size_arg_idx {
            sizes.get(size_idx).copied().flatten()
        } else {
            None
        };

        let result = validate_arg(reg, constraint, idx, size_from_arg);
        if !result.valid {
            return Err(VerifierError::InvalidFunctionCall(
                result.error.unwrap_or_else(|| format!("argument {} validation failed", idx))
            ));
        }
        results.push(result);
    }

    Ok(results)
}

/// Common kfunc signatures.
pub mod signatures {
    use super::*;

    /// bpf_kfunc_call_test1 (scalar arg)
    pub fn bpf_kfunc_call_test1() -> KfuncSignature {
        KfuncSignature::new("bpf_kfunc_call_test1")
            .arg(ArgConstraint::scalar())
    }

    /// bpf_kptr_xchg (pointer exchange)
    pub fn bpf_kptr_xchg() -> KfuncSignature {
        KfuncSignature::new("bpf_kptr_xchg")
            .arg(ArgConstraint::ptr_to_btf_id(0)) // kptr location
            .arg(ArgConstraint::any_ptr().nullable()) // new value
            .returns(ArgConstraint::any_ptr().nullable())
    }

    /// bpf_obj_new (object allocation)
    pub fn bpf_obj_new(btf_id: u32) -> KfuncSignature {
        KfuncSignature::new("bpf_obj_new")
            .arg(ArgConstraint::const_size(0)) // local_type_id__nullable
            .returns(ArgConstraint::ref_acquire(btf_id))
    }

    /// bpf_obj_drop (object deallocation)
    pub fn bpf_obj_drop(btf_id: u32) -> KfuncSignature {
        KfuncSignature::new("bpf_obj_drop")
            .arg(ArgConstraint::ref_release(btf_id))
            .destructive()
    }

    /// bpf_refcount_acquire
    pub fn bpf_refcount_acquire(btf_id: u32) -> KfuncSignature {
        KfuncSignature::new("bpf_refcount_acquire")
            .arg(ArgConstraint::ptr_to_btf_id(btf_id))
            .returns(ArgConstraint::ref_acquire(btf_id))
    }

    /// bpf_rbtree_add
    pub fn bpf_rbtree_add() -> KfuncSignature {
        KfuncSignature::new("bpf_rbtree_add")
            .arg(ArgConstraint::ptr_to_btf_id(0)) // rbtree root
            .arg(ArgConstraint::ref_release(0))   // node to add
            .arg(ArgConstraint::scalar())         // less callback
    }

    /// bpf_list_push_front/back
    pub fn bpf_list_push() -> KfuncSignature {
        KfuncSignature::new("bpf_list_push")
            .arg(ArgConstraint::ptr_to_btf_id(0)) // list head
            .arg(ArgConstraint::ref_release(0))   // node to add
    }

    /// bpf_list_pop_front/back
    pub fn bpf_list_pop(btf_id: u32) -> KfuncSignature {
        KfuncSignature::new("bpf_list_pop")
            .arg(ArgConstraint::ptr_to_btf_id(0)) // list head
            .returns(ArgConstraint::ref_acquire(btf_id).nullable())
    }

    /// bpf_task_acquire
    pub fn bpf_task_acquire() -> KfuncSignature {
        KfuncSignature::new("bpf_task_acquire")
            .arg(ArgConstraint::ptr_to_btf_id(0)) // task_struct
            .returns(ArgConstraint::ref_acquire(0).nullable())
    }

    /// bpf_task_release
    pub fn bpf_task_release() -> KfuncSignature {
        KfuncSignature::new("bpf_task_release")
            .arg(ArgConstraint::ref_release(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scalar_reg(val: u64) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = val;
        reg.umax_value = val;
        reg.smin_value = val as i64;
        reg.smax_value = val as i64;
        reg
    }

    fn make_ptr_reg(reg_type: BpfRegType) -> BpfRegState {
        let mut reg = BpfRegState::new_not_init();
        reg.reg_type = reg_type;
        reg
    }

    #[test]
    fn test_arg_constraint_scalar() {
        let constraint = ArgConstraint::scalar();
        assert_eq!(constraint.kind, ArgKind::Scalar);
        assert!(!constraint.nullable);
    }

    #[test]
    fn test_arg_constraint_builder() {
        let constraint = ArgConstraint::ptr_to_mem(64)
            .nullable()
            .with_alignment(8)
            .readonly();

        assert_eq!(constraint.kind, ArgKind::PtrToMem);
        assert!(constraint.nullable);
        assert_eq!(constraint.min_size, 64);
        assert_eq!(constraint.alignment, 8);
        assert!(constraint.readonly);
    }

    #[test]
    fn test_kfunc_signature_builder() {
        let sig = KfuncSignature::new("test_kfunc")
            .arg(ArgConstraint::ptr_to_ctx())
            .arg(ArgConstraint::scalar())
            .returns(ArgConstraint::scalar())
            .sleepable();

        assert_eq!(sig.name, "test_kfunc");
        assert_eq!(sig.arg_count(), 2);
        assert!(sig.sleepable);
        assert!(sig.ret.is_some());
    }

    #[test]
    fn test_validate_scalar_arg() {
        let reg = make_scalar_reg(42);
        let constraint = ArgConstraint::scalar();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_scalar_wrong_type() {
        let reg = make_ptr_reg(BpfRegType::PtrToStack);
        let constraint = ArgConstraint::scalar();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("scalar"));
    }

    #[test]
    fn test_validate_ptr_arg() {
        let reg = make_ptr_reg(BpfRegType::PtrToMem);
        let constraint = ArgConstraint::ptr_to_mem(0);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_ptr_wrong_type() {
        let reg = make_scalar_reg(0);
        let constraint = ArgConstraint::ptr_to_mem(0);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("pointer"));
    }

    #[test]
    fn test_validate_ctx_ptr() {
        let reg = make_ptr_reg(BpfRegType::PtrToCtx);
        let constraint = ArgConstraint::ptr_to_ctx();

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);

        let wrong_reg = make_ptr_reg(BpfRegType::PtrToStack);
        let result = validate_arg(&wrong_reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_const_size() {
        let reg = make_scalar_reg(64);
        let constraint = ArgConstraint::const_size(64);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);
        assert_eq!(result.inferred_size, Some(64));
    }

    #[test]
    fn test_validate_const_size_mismatch() {
        let reg = make_scalar_reg(32);
        let constraint = ArgConstraint::const_size(64);

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_kfunc_call() {
        let sig = KfuncSignature::new("test")
            .arg(ArgConstraint::ptr_to_ctx())
            .arg(ArgConstraint::scalar());

        let r1 = make_ptr_reg(BpfRegType::PtrToCtx);
        let r2 = make_scalar_reg(100);

        let result = validate_kfunc_call(&sig, &[&r1, &r2]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_kfunc_call_wrong_count() {
        let sig = KfuncSignature::new("test")
            .arg(ArgConstraint::scalar())
            .arg(ArgConstraint::scalar());

        let r1 = make_scalar_reg(1);

        let result = validate_kfunc_call(&sig, &[&r1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_common_signatures() {
        let sig = signatures::bpf_task_acquire();
        assert_eq!(sig.name, "bpf_task_acquire");
        assert_eq!(sig.arg_count(), 1);
        assert!(sig.ret.is_some());

        let sig = signatures::bpf_obj_drop(100);
        assert!(sig.destructive);
    }

    #[test]
    fn test_dynptr_validation() {
        let reg = make_ptr_reg(BpfRegType::PtrToStack);
        let constraint = ArgConstraint {
            kind: ArgKind::Dynptr,
            ..Default::default()
        };

        let result = validate_arg(&reg, &constraint, 0, None);
        assert!(result.valid);

        let wrong_reg = make_ptr_reg(BpfRegType::PtrToMem);
        let result = validate_arg(&wrong_reg, &constraint, 0, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_arg_validation_result() {
        let result = ArgValidationResult::success(0)
            .with_warning("test warning".to_string())
            .with_size(64);

        assert!(result.valid);
        assert!(!result.warnings.is_empty());
        assert_eq!(result.inferred_size, Some(64));
    }
}
