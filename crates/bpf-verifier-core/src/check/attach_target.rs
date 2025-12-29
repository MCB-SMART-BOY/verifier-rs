// SPDX-License-Identifier: GPL-2.0

//! Attach target validation for BPF tracing and extension programs.
//!
//! This module implements the `bpf_check_attach_target` functionality which
//! validates that a BPF program (tracing, LSM, or extension) can legally
//! attach to a target function or program.
//!
//! # Attach Types Supported
//!
//! - `BPF_TRACE_FENTRY`: Attach to function entry
//! - `BPF_TRACE_FEXIT`: Attach to function exit
//! - `BPF_TRACE_RAW_TP`: Attach to raw tracepoint
//! - `BPF_TRACE_ITER`: Attach to BPF iterator
//! - `BPF_MODIFY_RETURN`: Modify function return value
//! - `BPF_LSM_MAC`: LSM security hook
//! - `BPF_LSM_CGROUP`: Cgroup LSM hook
//! - Program extension (freplace)

use alloc::string::String;
use alloc::vec::Vec;

use crate::btf::database::{Btf, BtfKind};
use crate::check::prog_type::BpfAttachType;
use crate::core::error::{Result, VerifierError};
use crate::core::types::BpfProgType;

/// Information about the attach target.
#[derive(Debug, Clone, Default)]
pub struct AttachTargetInfo {
    /// Target function address (0 if unknown or BPF program target).
    pub tgt_addr: u64,
    /// Target function name.
    pub tgt_name: String,
    /// BTF type ID of the target function.
    pub tgt_btf_id: u32,
    /// Whether the target is a BPF program (vs kernel function).
    pub is_bpf_prog: bool,
    /// Subprogram index if attaching to BPF program.
    pub subprog_idx: Option<u32>,
    /// Function model (argument types, return type).
    pub fmodel: FuncModel,
}

/// Target BPF program information for attach validation.
#[derive(Debug, Clone)]
pub struct TargetProgInfo {
    /// Target program type.
    pub prog_type: BpfProgType,
    /// Target attach type.
    pub attach_type: BpfAttachType,
    /// Target BTF ID.
    pub btf_id: u32,
    /// Number of functions in target.
    pub func_cnt: u32,
    /// Whether target is JITed.
    pub is_jited: bool,
    /// Whether target is a tracing program.
    pub is_tracing: bool,
    /// Subprogram index to attach to.
    pub subprog_idx: u32,
}

/// Function model describing the signature.
#[derive(Debug, Clone, Default)]
pub struct FuncModel {
    /// Return type BTF ID.
    pub ret_btf_id: u32,
    /// Return type size in bytes.
    pub ret_size: u32,
    /// Number of arguments.
    pub nr_args: u32,
    /// Argument BTF IDs.
    pub arg_btf_ids: Vec<u32>,
    /// Argument sizes.
    pub arg_sizes: Vec<u32>,
    /// Argument flags (e.g., PTR_TO_CTX).
    pub arg_flags: Vec<u32>,
}

/// Sleepable hook information for LSM programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepableHook {
    /// Hook is always sleepable.
    Always,
    /// Hook is never sleepable.
    Never,
    /// Hook sleepability depends on context.
    Conditional,
}

/// List of LSM hooks that are known to be sleepable.
const SLEEPABLE_LSM_HOOKS: &[&str] = &[
    "bpf_lsm_bprm_committed_creds",
    "bpf_lsm_bprm_creds_for_exec",
    "bpf_lsm_file_alloc_security",
    "bpf_lsm_file_free_security",
    "bpf_lsm_file_ioctl",
    "bpf_lsm_file_lock",
    "bpf_lsm_file_open",
    "bpf_lsm_file_receive",
    "bpf_lsm_inode_create",
    "bpf_lsm_inode_free_security",
    "bpf_lsm_inode_getattr",
    "bpf_lsm_inode_link",
    "bpf_lsm_inode_mkdir",
    "bpf_lsm_inode_mknod",
    "bpf_lsm_inode_permission",
    "bpf_lsm_inode_rename",
    "bpf_lsm_inode_rmdir",
    "bpf_lsm_inode_setattr",
    "bpf_lsm_inode_setxattr",
    "bpf_lsm_inode_symlink",
    "bpf_lsm_inode_unlink",
    "bpf_lsm_kernel_read_file",
    "bpf_lsm_mmap_file",
    "bpf_lsm_path_chmod",
    "bpf_lsm_path_chown",
    "bpf_lsm_path_chroot",
    "bpf_lsm_path_link",
    "bpf_lsm_path_mkdir",
    "bpf_lsm_path_mknod",
    "bpf_lsm_path_rename",
    "bpf_lsm_path_rmdir",
    "bpf_lsm_path_symlink",
    "bpf_lsm_path_truncate",
    "bpf_lsm_path_unlink",
    "bpf_lsm_sb_alloc_security",
    "bpf_lsm_sb_free_security",
    "bpf_lsm_sb_kern_mount",
    "bpf_lsm_sb_mount",
    "bpf_lsm_sb_remount",
    "bpf_lsm_sb_set_mnt_opts",
    "bpf_lsm_sb_show_options",
    "bpf_lsm_sb_statfs",
    "bpf_lsm_sb_umount",
    "bpf_lsm_sk_alloc_security",
    "bpf_lsm_sk_free_security",
    "bpf_lsm_socket_accept",
    "bpf_lsm_socket_bind",
    "bpf_lsm_socket_connect",
    "bpf_lsm_socket_create",
    "bpf_lsm_socket_getpeername",
    "bpf_lsm_socket_getpeersec_dgram",
    "bpf_lsm_socket_getsockname",
    "bpf_lsm_socket_getsockopt",
    "bpf_lsm_socket_listen",
    "bpf_lsm_socket_post_create",
    "bpf_lsm_socket_recvmsg",
    "bpf_lsm_socket_sendmsg",
    "bpf_lsm_socket_setsockopt",
    "bpf_lsm_socket_shutdown",
    "bpf_lsm_socket_socketpair",
    "bpf_lsm_syslog",
    "bpf_lsm_task_alloc",
    "bpf_lsm_task_free",
    "bpf_lsm_task_setpgid",
    "bpf_lsm_task_setscheduler",
];

/// Functions that are in the deny list for tracing.
const TRACING_DENY_LIST: &[&str] = &[
    "migrate_disable",
    "migrate_enable",
    "rcu_read_unlock_strict",
    "preempt_count_add",
    "preempt_count_sub",
    "__rcu_read_lock",
    "__rcu_read_unlock",
];

/// Functions that allow error injection (and thus fmod_ret).
const ERROR_INJECTION_LIST: &[&str] = &[
    // Common kernel functions that allow error injection
    "should_failslab",
    "should_fail_alloc_page",
    "should_fail_bio",
    "should_fail_request",
    "should_fail_futex",
    "should_fail_usercopy",
];

/// Check if a function is in the tracing deny list.
fn is_in_deny_list(name: &str) -> bool {
    TRACING_DENY_LIST.contains(&name)
}

/// Check if a function allows error injection.
fn allows_error_injection(name: &str) -> bool {
    ERROR_INJECTION_LIST.contains(&name)
}

/// Check if an LSM hook is sleepable.
pub fn is_sleepable_lsm_hook(name: &str) -> bool {
    SLEEPABLE_LSM_HOOKS.contains(&name)
}

/// Attach target validator.
pub struct AttachTargetValidator {
    /// Program type being validated.
    prog_type: BpfProgType,
    /// Expected attach type.
    attach_type: BpfAttachType,
    /// Whether the program is sleepable.
    is_sleepable: bool,
    /// Whether the program is an extension.
    is_extension: bool,
}

impl AttachTargetValidator {
    /// Create a new attach target validator.
    pub fn new(
        prog_type: BpfProgType,
        attach_type: BpfAttachType,
        is_sleepable: bool,
    ) -> Self {
        let is_extension = prog_type == BpfProgType::Ext;
        Self {
            prog_type,
            attach_type,
            is_sleepable,
            is_extension,
        }
    }

    /// Check attach target for a BPF program attaching to another BPF program.
    ///
    /// This is used for fentry/fexit/freplace attaching to BPF programs.
    pub fn check_bpf_prog_target(&self, tgt: &TargetProgInfo) -> Result<AttachTargetInfo> {
        // Target must be JITed
        if !tgt.is_jited {
            return Err(VerifierError::AttachFailed(
                "Can attach to only JITed progs".into(),
            ));
        }

        // Validate subprogram index
        if tgt.subprog_idx >= tgt.func_cnt {
            return Err(VerifierError::AttachFailed(
                "Subprog doesn't exist".into(),
            ));
        }

        // Extension programs have additional restrictions
        if self.is_extension {
            // Cannot recursively attach extension to extension
            if tgt.prog_type == BpfProgType::Ext {
                return Err(VerifierError::AttachFailed(
                    "Cannot recursively attach".into(),
                ));
            }

            // Cannot extend fentry/fexit programs
            if tgt.prog_type == BpfProgType::Tracing
                && (tgt.attach_type == BpfAttachType::TraceFentry
                    || tgt.attach_type == BpfAttachType::TraceFexit)
            {
                return Err(VerifierError::AttachFailed(
                    "Cannot extend fentry/fexit".into(),
                ));
            }
        }

        // Tracing programs cannot nest more than once
        if self.prog_type == BpfProgType::Tracing && tgt.is_tracing {
            return Err(VerifierError::AttachFailed(
                "Cannot nest tracing program attach more than once".into(),
            ));
        }

        Ok(AttachTargetInfo {
            tgt_addr: 0,
            tgt_name: String::new(),
            tgt_btf_id: tgt.btf_id,
            is_bpf_prog: true,
            subprog_idx: Some(tgt.subprog_idx),
            fmodel: FuncModel::default(),
        })
    }

    /// Check attach target for a kernel function by name.
    ///
    /// This validates that the function name can be traced/modified.
    pub fn check_kernel_func_by_name(&self, tname: &str, btf_id: u32) -> Result<AttachTargetInfo> {
        // Extension programs cannot replace kernel functions
        if self.is_extension {
            return Err(VerifierError::AttachFailed(
                "Cannot replace kernel functions".into(),
            ));
        }

        // Check deny list
        if is_in_deny_list(tname) {
            return Err(VerifierError::AttachFailed(
                alloc::format!("{} is in the deny list and cannot be traced", tname),
            ));
        }

        // Check sleepable constraints
        if self.is_sleepable {
            self.check_sleepable_target(tname)?;
        }

        // Check modify_return constraints
        if self.attach_type == BpfAttachType::ModifyReturn {
            self.check_modify_return_target(tname)?;
        }

        Ok(AttachTargetInfo {
            tgt_addr: 0,
            tgt_name: tname.into(),
            tgt_btf_id: btf_id,
            is_bpf_prog: false,
            subprog_idx: None,
            fmodel: FuncModel::default(),
        })
    }

    /// Check that a sleepable program can attach to the target.
    fn check_sleepable_target(&self, tname: &str) -> Result<()> {
        match self.prog_type {
            BpfProgType::Tracing => {
                // fentry/fexit/fmod_ret can be sleepable if attached to
                // error injection functions or sleepable kfuncs
                if !allows_error_injection(tname) {
                    return Err(VerifierError::AttachFailed(
                        alloc::format!("{} is not sleepable", tname),
                    ));
                }
            }
            BpfProgType::Lsm => {
                // LSM hooks must be in the sleepable list
                if !is_sleepable_lsm_hook(tname) {
                    return Err(VerifierError::AttachFailed(
                        alloc::format!("{} is not sleepable", tname),
                    ));
                }
            }
            _ => {
                return Err(VerifierError::AttachFailed(
                    alloc::format!("{} is not sleepable", tname),
                ));
            }
        }
        Ok(())
    }

    /// Check that a function can have its return value modified.
    fn check_modify_return_target(&self, tname: &str) -> Result<()> {
        // Only certain functions allow return value modification
        if !allows_error_injection(tname) {
            return Err(VerifierError::AttachFailed(
                alloc::format!("{}() is not modifiable", tname),
            ));
        }
        Ok(())
    }

    /// Check raw tracepoint attach target.
    pub fn check_raw_tracepoint(&self, tp_name: &str, btf_id: u32) -> Result<AttachTargetInfo> {
        Ok(AttachTargetInfo {
            tgt_addr: 0,
            tgt_name: tp_name.into(),
            tgt_btf_id: btf_id,
            is_bpf_prog: false,
            subprog_idx: None,
            fmodel: FuncModel::default(),
        })
    }
}

/// Check attach target when attaching to another BPF program.
pub fn check_attach_target_prog(
    prog_type: BpfProgType,
    attach_type: BpfAttachType,
    is_sleepable: bool,
    tgt: &TargetProgInfo,
) -> Result<AttachTargetInfo> {
    let validator = AttachTargetValidator::new(prog_type, attach_type, is_sleepable);
    validator.check_bpf_prog_target(tgt)
}

/// Validate that an extension program is compatible with its target.
pub fn check_extension_compatibility(
    ext_changes_pkt_data: bool,
    ext_might_sleep: bool,
    tgt_changes_pkt_data: bool,
    tgt_might_sleep: bool,
) -> Result<()> {
    // Extension cannot add packet data changes if target doesn't have them
    if ext_changes_pkt_data && !tgt_changes_pkt_data {
        return Err(VerifierError::AttachFailed(
            "Extension program changes packet data, while original does not".into(),
        ));
    }

    // Extension cannot be sleepable if target isn't
    if ext_might_sleep && !tgt_might_sleep {
        return Err(VerifierError::AttachFailed(
            "Extension program may sleep, while original does not".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// BTF Integration
// ============================================================================

/// Resolve function model from BTF.
///
/// This extracts the function signature (arguments and return type) from BTF
/// for a given function BTF ID.
pub fn resolve_func_model_from_btf(btf: &Btf, func_btf_id: u32) -> Result<FuncModel> {
    // Get the function type
    let func_type = btf.get_type(func_btf_id).ok_or_else(|| {
        VerifierError::AttachFailed(alloc::format!(
            "BTF type {} not found",
            func_btf_id
        ))
    })?;

    // Must be a FUNC type
    if func_type.kind != BtfKind::Func {
        return Err(VerifierError::AttachFailed(alloc::format!(
            "BTF type {} is not a function (kind={:?})",
            func_btf_id,
            func_type.kind
        )));
    }

    // Get the function prototype
    let proto_id = func_type.type_ref;
    let proto = btf.get_type(proto_id).ok_or_else(|| {
        VerifierError::AttachFailed(alloc::format!(
            "Function prototype {} not found",
            proto_id
        ))
    })?;

    if proto.kind != BtfKind::FuncProto {
        return Err(VerifierError::AttachFailed(alloc::format!(
            "BTF type {} is not a function prototype",
            proto_id
        )));
    }

    // Build function model
    let mut fmodel = FuncModel {
        ret_btf_id: proto.type_ref,
        ret_size: btf.type_size(proto.type_ref).unwrap_or(0),
        ..Default::default()
    };

    // Arguments
    fmodel.nr_args = proto.params.len() as u32;
    for param in &proto.params {
        fmodel.arg_btf_ids.push(param.type_id);
        fmodel.arg_sizes.push(btf.type_size(param.type_id).unwrap_or(0));
        fmodel.arg_flags.push(0); // Flags determined by context analysis
    }

    Ok(fmodel)
}

/// Find a kernel function by name in BTF.
///
/// Returns the BTF ID of the function if found.
pub fn find_kernel_func_btf_id(btf: &Btf, func_name: &str) -> Option<u32> {
    let ids = btf.find_by_name(func_name);
    // Return the first match that is a FUNC type
    for &id in ids {
        if let Some(ty) = btf.get_type(id) {
            if ty.kind == BtfKind::Func {
                return Some(id);
            }
        }
    }
    None
}

/// Validate attach target with full BTF information.
///
/// This is the main entry point for attach target validation with BTF.
pub fn bpf_check_attach_target(
    btf: &Btf,
    prog_type: BpfProgType,
    attach_type: BpfAttachType,
    is_sleepable: bool,
    attach_btf_id: u32,
    attach_func_name: Option<&str>,
) -> Result<AttachTargetInfo> {
    let validator = AttachTargetValidator::new(prog_type, attach_type, is_sleepable);

    // Determine the target BTF ID
    let tgt_btf_id = if attach_btf_id != 0 {
        attach_btf_id
    } else if let Some(name) = attach_func_name {
        find_kernel_func_btf_id(btf, name).ok_or_else(|| {
            VerifierError::AttachFailed(alloc::format!(
                "Function '{}' not found in BTF",
                name
            ))
        })?
    } else {
        return Err(VerifierError::AttachFailed(
            "No attach target specified".into(),
        ));
    };

    // Get function name from BTF
    let func_type = btf.get_type(tgt_btf_id).ok_or_else(|| {
        VerifierError::AttachFailed(alloc::format!(
            "BTF type {} not found",
            tgt_btf_id
        ))
    })?;

    let tgt_name = func_type
        .name
        .clone()
        .unwrap_or_else(|| alloc::format!("func_{}", tgt_btf_id));

    // Validate the target based on attach type
    match attach_type {
        BpfAttachType::TraceFentry
        | BpfAttachType::TraceFexit
        | BpfAttachType::ModifyReturn => {
            validator.check_kernel_func_by_name(&tgt_name, tgt_btf_id)?;
        }
        BpfAttachType::TraceRawTp => {
            validator.check_raw_tracepoint(&tgt_name, tgt_btf_id)?;
        }
        BpfAttachType::LsmMac | BpfAttachType::LsmCgroup => {
            // LSM hooks - check sleepability
            if is_sleepable && !is_sleepable_lsm_hook(&tgt_name) {
                return Err(VerifierError::AttachFailed(alloc::format!(
                    "LSM hook '{}' is not sleepable",
                    tgt_name
                )));
            }
        }
        _ => {
            // Other attach types - basic validation
        }
    }

    // Resolve function model from BTF
    let fmodel = resolve_func_model_from_btf(btf, tgt_btf_id)?;

    Ok(AttachTargetInfo {
        tgt_addr: 0,
        tgt_name,
        tgt_btf_id,
        is_bpf_prog: false,
        subprog_idx: None,
        fmodel,
    })
}

/// Check if the program's context type matches the target.
///
/// For tracing programs, the context is a pointer to the target function's
/// first argument (for fentry) or all arguments (for fexit with return value).
pub fn check_ctx_type_match(
    btf: &Btf,
    prog_ctx_btf_id: u32,
    _target_info: &AttachTargetInfo,
    attach_type: BpfAttachType,
) -> Result<()> {
    // For fentry/fexit, the context type should match
    match attach_type {
        BpfAttachType::TraceFentry | BpfAttachType::TraceFexit => {
            // Context is a pointer to struct with target function args
            // Validate that prog_ctx matches expected layout
            if prog_ctx_btf_id == 0 {
                return Ok(()); // No BTF context to validate
            }

            let ctx_type = btf.get_type(prog_ctx_btf_id);
            if ctx_type.is_none() {
                return Err(VerifierError::AttachFailed(
                    "Program context type not found in BTF".into(),
                ));
            }

            // Further validation would check struct field types match
            // the target function's argument types
        }
        _ => {}
    }

    Ok(())
}

/// Validate that fentry/fexit arguments are compatible.
///
/// For fentry: args[0..n] = target function args
/// For fexit: args[0..n] = target function args, args[n] = return value
pub fn validate_tracing_args(
    target_info: &AttachTargetInfo,
    attach_type: BpfAttachType,
    prog_arg_count: u32,
) -> Result<()> {
    let expected_args = match attach_type {
        BpfAttachType::TraceFentry => target_info.fmodel.nr_args,
        BpfAttachType::TraceFexit => {
            // fexit has target args + return value
            target_info.fmodel.nr_args + 1
        }
        BpfAttachType::ModifyReturn => {
            // fmod_ret has target args + return value pointer
            target_info.fmodel.nr_args + 1
        }
        _ => return Ok(()),
    };

    if prog_arg_count != expected_args {
        return Err(VerifierError::AttachFailed(alloc::format!(
            "Expected {} args for {:?}, got {}",
            expected_args,
            attach_type,
            prog_arg_count
        )));
    }

    Ok(())
}
