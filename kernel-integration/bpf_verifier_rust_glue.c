// SPDX-License-Identifier: GPL-2.0
/*
 * C glue code for Rust BPF verifier integration
 *
 * This file provides the interface between the kernel's BPF subsystem
 * and the Rust BPF verifier implementation.
 */

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/module.h>
#include <linux/sysctl.h>

/* Rust verifier entry point - defined in Rust code */
extern int rust_bpf_verify(struct bpf_verifier_env *env);

/* Sysctl to enable/disable Rust verifier */
#ifdef CONFIG_BPF_VERIFIER_RUST_DEFAULT
static int use_rust_verifier = 1;
#else
static int use_rust_verifier = 0;
#endif

static struct ctl_table_header *rust_verifier_sysctl_header;

static struct ctl_table rust_verifier_sysctls[] = {
	{
		.procname	= "bpf_rust_verifier",
		.data		= &use_rust_verifier,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{ }
};

/**
 * bpf_rust_verify_prog - Verify BPF program using Rust verifier
 * @env: BPF verifier environment
 *
 * This function is called from the kernel's BPF loading path when
 * the Rust verifier is enabled. It delegates to the Rust implementation.
 *
 * Return: 0 on success, negative error code on failure
 */
int bpf_rust_verify_prog(struct bpf_verifier_env *env)
{
	if (!use_rust_verifier)
		return -ENOSYS; /* Fall back to C verifier */

	return rust_bpf_verify(env);
}
EXPORT_SYMBOL_GPL(bpf_rust_verify_prog);

/**
 * bpf_rust_verifier_enabled - Check if Rust verifier is enabled
 *
 * Return: true if Rust verifier is enabled, false otherwise
 */
bool bpf_rust_verifier_enabled(void)
{
	return use_rust_verifier != 0;
}
EXPORT_SYMBOL_GPL(bpf_rust_verifier_enabled);

static int __init bpf_rust_verifier_init(void)
{
	rust_verifier_sysctl_header = register_sysctl("kernel", rust_verifier_sysctls);
	if (!rust_verifier_sysctl_header)
		return -ENOMEM;

	pr_info("BPF Rust verifier loaded (enabled=%d)\n", use_rust_verifier);
	return 0;
}

static void __exit bpf_rust_verifier_exit(void)
{
	if (rust_verifier_sysctl_header)
		unregister_sysctl_table(rust_verifier_sysctl_header);

	pr_info("BPF Rust verifier unloaded\n");
}

module_init(bpf_rust_verifier_init);
module_exit(bpf_rust_verifier_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MCB-SMART-BOY");
MODULE_DESCRIPTION("Rust implementation of BPF verifier");
