// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF Verifier Rust Kernel Module
 *
 * This module provides a kernel interface to the Rust BPF verifier
 * implementation for testing and comparison with the C verifier.
 *
 * Copyright (c) 2024 MCB-SMART-BOY
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bpf.h>

#include "bpf_verifier_rs.h"

#define DEVICE_NAME "bpf_verifier_rs"
#define MAX_INSN_CNT 4096
#define MAX_LOG_SIZE (1024 * 1024)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MCB-SMART-BOY");
MODULE_DESCRIPTION("Rust BPF Verifier Kernel Module");
MODULE_VERSION("0.1.0");

/* IOCTL commands */
#define BPF_VERIFY_RS_MAGIC 'B'
#define BPF_VERIFY_RS_VERIFY    _IOWR(BPF_VERIFY_RS_MAGIC, 1, struct bpf_verify_request)
#define BPF_VERIFY_RS_GET_STATS _IOR(BPF_VERIFY_RS_MAGIC, 2, struct bpf_verifier_stats_rs)

/* Request structure for verification */
struct bpf_verify_request {
    __u32 prog_type;
    __u32 insn_cnt;
    __u64 insns_ptr;      /* User pointer to instructions */
    __u32 log_level;
    __u32 log_size;
    __u64 log_buf_ptr;    /* User pointer to log buffer */
    __s32 result;         /* Output: verification result */
};

/* Module state */
static struct {
    struct miscdevice misc;
    bool initialized;
} verifier_mod;

/* External Rust functions (from staticlib) */
extern bpf_verifier_env_handle_t bpf_verifier_env_new(
    const struct bpf_insn_rs *insns,
    uint32_t insn_cnt,
    uint32_t prog_type,
    bool is_privileged
);
extern void bpf_verifier_env_free(bpf_verifier_env_handle_t handle);
extern int bpf_verify(bpf_verifier_env_handle_t handle);
extern int bpf_verifier_get_stats(
    bpf_verifier_env_handle_t handle,
    struct bpf_verifier_stats_rs *stats
);

/* ============================================================================
 * Memory allocation wrappers for Rust
 * 
 * These are called by the Rust global allocator. We provide them here because
 * kmalloc/kfree may be inline functions or macros in some kernel configurations.
 * ============================================================================
 */

void *__kmalloc(size_t size, gfp_t flags);

void *rust_kmalloc(size_t size, unsigned int flags)
{
    void *ptr;
    
    /* Use the passed flags, but also accept GFP_KERNEL (0xCC0) from Rust */
    if (flags == 0xCC0)
        flags = GFP_KERNEL;
    
    ptr = kmalloc(size, flags);
    if (!ptr && size > 0) {
        pr_warn("bpf_verifier_rs: kmalloc(%zu) failed\n", size);
    }
    return ptr;
}
EXPORT_SYMBOL_GPL(rust_kmalloc);

void rust_kfree(const void *ptr)
{
    kfree(ptr);
}
EXPORT_SYMBOL_GPL(rust_kfree);

/* Log callback for kernel logging */
static void kernel_log_callback(uint32_t level, const uint8_t *msg, size_t len)
{
    char *buf;

    if (len == 0 || !msg)
        return;

    buf = kmalloc(len + 1, GFP_KERNEL);
    if (!buf)
        return;

    memcpy(buf, msg, len);
    buf[len] = '\0';

    switch (level) {
    case 0:
        pr_err("bpf_verifier_rs: %s\n", buf);
        break;
    case 1:
        pr_warn("bpf_verifier_rs: %s\n", buf);
        break;
    case 2:
        pr_info("bpf_verifier_rs: %s\n", buf);
        break;
    default:
        pr_debug("bpf_verifier_rs: %s\n", buf);
        break;
    }

    kfree(buf);
}

/* File operations */
static int verifier_open(struct inode *inode, struct file *file)
{
    pr_debug("bpf_verifier_rs: device opened\n");
    return 0;
}

static int verifier_release(struct inode *inode, struct file *file)
{
    pr_debug("bpf_verifier_rs: device closed\n");
    return 0;
}

static long verifier_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct bpf_verify_request req;
    struct bpf_verifier_stats_rs stats;
    struct bpf_insn_rs *insns = NULL;
    bpf_verifier_env_handle_t handle = NULL;
    int ret = 0;

    switch (cmd) {
    case BPF_VERIFY_RS_VERIFY:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        /* Validate input */
        if (req.insn_cnt == 0 || req.insn_cnt > MAX_INSN_CNT)
            return -EINVAL;

        /* Allocate and copy instructions */
        insns = kvmalloc_array(req.insn_cnt, sizeof(struct bpf_insn_rs),
                               GFP_KERNEL);
        if (!insns)
            return -ENOMEM;

        if (copy_from_user(insns, (void __user *)req.insns_ptr,
                          req.insn_cnt * sizeof(struct bpf_insn_rs))) {
            ret = -EFAULT;
            goto out_free;
        }

        /* Create verifier environment */
        pr_info("bpf_verifier_rs: creating env for %u insns, type %u\n",
                req.insn_cnt, req.prog_type);
        handle = bpf_verifier_env_new(insns, req.insn_cnt, req.prog_type,
                                      capable(CAP_BPF) || capable(CAP_SYS_ADMIN));
        if (!handle) {
            pr_err("bpf_verifier_rs: env creation failed\n");
            ret = -ENOMEM;
            goto out_free;
        }
        pr_info("bpf_verifier_rs: env created, running verify\n");

        /* Run verification */
        req.result = bpf_verify(handle);
        pr_info("bpf_verifier_rs: verify returned %d\n", req.result);

        /* Copy result back */
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            ret = -EFAULT;

        bpf_verifier_env_free(handle);
out_free:
        kvfree(insns);
        return ret;

    case BPF_VERIFY_RS_GET_STATS:
        /* This requires an active handle, which we don't have in this simple design */
        memset(&stats, 0, sizeof(stats));
        if (copy_to_user((void __user *)arg, &stats, sizeof(stats)))
            return -EFAULT;
        return 0;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations verifier_fops = {
    .owner = THIS_MODULE,
    .open = verifier_open,
    .release = verifier_release,
    .unlocked_ioctl = verifier_ioctl,
    .compat_ioctl = verifier_ioctl,
};

static int __init bpf_verifier_rs_init(void)
{
    int ret;

    pr_info("bpf_verifier_rs: initializing module v%d.%d.%d\n",
            BPF_VERIFIER_RS_VERSION_MAJOR,
            BPF_VERIFIER_RS_VERSION_MINOR,
            BPF_VERIFIER_RS_VERSION_PATCH);

    verifier_mod.misc.minor = MISC_DYNAMIC_MINOR;
    verifier_mod.misc.name = DEVICE_NAME;
    verifier_mod.misc.fops = &verifier_fops;

    ret = misc_register(&verifier_mod.misc);
    if (ret) {
        pr_err("bpf_verifier_rs: failed to register misc device: %d\n", ret);
        return ret;
    }

    verifier_mod.initialized = true;
    pr_info("bpf_verifier_rs: module loaded, device /dev/%s created\n", DEVICE_NAME);
    return 0;
}

static void __exit bpf_verifier_rs_exit(void)
{
    if (verifier_mod.initialized) {
        misc_deregister(&verifier_mod.misc);
        verifier_mod.initialized = false;
    }
    pr_info("bpf_verifier_rs: module unloaded\n");
}

module_init(bpf_verifier_rs_init);
module_exit(bpf_verifier_rs_exit);
