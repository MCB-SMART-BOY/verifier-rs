/*
 * BPF Verifier Rust Implementation - C Header
 *
 * This header provides the C interface for the Rust BPF verifier.
 * It mirrors the kernel's bpf_check() API for drop-in replacement.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2024 MCB-SMART-BOY
 */

#ifndef _BPF_VERIFIER_RS_H
#define _BPF_VERIFIER_RS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version information
 */
#define BPF_VERIFIER_RS_VERSION_MAJOR 0
#define BPF_VERIFIER_RS_VERSION_MINOR 1
#define BPF_VERIFIER_RS_VERSION_PATCH 0

/*
 * Error codes (matching kernel errno values)
 */
#define BPF_VERIFIER_OK       0
#define BPF_VERIFIER_EINVAL   (-22)  /* Invalid argument */
#define BPF_VERIFIER_ENOMEM   (-12)  /* Out of memory */
#define BPF_VERIFIER_EACCES   (-13)  /* Permission denied */
#define BPF_VERIFIER_E2BIG    (-7)   /* Complexity limit exceeded */
#define BPF_VERIFIER_EPERM    (-1)   /* Operation not permitted */

/*
 * Opaque handle to verifier environment
 */
typedef void* bpf_verifier_env_handle_t;

/*
 * BPF instruction (matches struct bpf_insn)
 */
struct bpf_insn_rs {
    uint8_t code;       /* opcode */
    uint8_t dst_reg;    /* destination register */
    uint8_t src_reg;    /* source register */
    int16_t off;        /* signed offset */
    int32_t imm;        /* signed immediate */
};

/*
 * Program attributes for verification
 */
struct bpf_prog_attr_rs {
    uint32_t prog_type;           /* BPF program type */
    uint32_t insn_cnt;            /* Number of instructions */
    const struct bpf_insn_rs *insns;  /* Instruction array */
    const uint8_t *license;       /* License string */
    uint32_t log_level;           /* Logging verbosity */
    uint32_t log_size;            /* Log buffer size */
    uint8_t *log_buf;             /* Log buffer */
    uint32_t kern_version;        /* Kernel version */
    uint32_t prog_flags;          /* Program flags */
    uint32_t expected_attach_type; /* Expected attach type */
};

/*
 * Verification statistics
 */
struct bpf_verifier_stats_rs {
    uint64_t insns_processed;     /* Instructions processed */
    uint64_t states_explored;     /* States explored */
    uint64_t peak_states;         /* Peak state count */
    uint64_t total_states;        /* Total states created */
    uint64_t pruned_states;       /* States pruned */
};

/*
 * Log callback function type
 */
typedef void (*bpf_log_callback_t)(uint32_t level, const uint8_t *msg, size_t len);

/*
 * Core API Functions
 */

/**
 * bpf_verifier_env_new - Create a new verifier environment
 * @insns: Pointer to instruction array
 * @insn_cnt: Number of instructions
 * @prog_type: BPF program type
 * @is_privileged: Whether the caller is privileged
 *
 * Returns: Handle to verifier environment, or NULL on failure
 */
bpf_verifier_env_handle_t bpf_verifier_env_new(
    const struct bpf_insn_rs *insns,
    uint32_t insn_cnt,
    uint32_t prog_type,
    bool is_privileged
);

/**
 * bpf_verifier_env_free - Free a verifier environment
 * @handle: Handle from bpf_verifier_env_new()
 */
void bpf_verifier_env_free(bpf_verifier_env_handle_t handle);

/**
 * bpf_verify - Run verification on a program
 * @handle: Handle from bpf_verifier_env_new()
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_verify(bpf_verifier_env_handle_t handle);

/**
 * bpf_check_rs - Main entry point (matches kernel's bpf_check)
 * @attr: Program attributes
 *
 * This function creates an environment, runs verification, and cleans up.
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_check_rs(const struct bpf_prog_attr_rs *attr);

/**
 * bpf_verifier_get_insn_cnt - Get instruction count
 * @handle: Verifier environment handle
 *
 * Returns: Number of instructions in the program
 */
uint32_t bpf_verifier_get_insn_cnt(bpf_verifier_env_handle_t handle);

/**
 * bpf_verifier_get_stats - Get verification statistics
 * @handle: Verifier environment handle
 * @stats: Pointer to stats structure to fill
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_verifier_get_stats(
    bpf_verifier_env_handle_t handle,
    struct bpf_verifier_stats_rs *stats
);

/**
 * bpf_verifier_set_log_callback - Set logging callback
 * @callback: Function to call for log messages
 */
void bpf_verifier_set_log_callback(bpf_log_callback_t callback);

/**
 * bpf_verifier_clear_log_callback - Clear logging callback
 */
void bpf_verifier_clear_log_callback(void);

/*
 * BPF Program Types (matching kernel values)
 */
enum bpf_prog_type_rs {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER = 1,
    BPF_PROG_TYPE_KPROBE = 2,
    BPF_PROG_TYPE_SCHED_CLS = 3,
    BPF_PROG_TYPE_SCHED_ACT = 4,
    BPF_PROG_TYPE_TRACEPOINT = 5,
    BPF_PROG_TYPE_XDP = 6,
    BPF_PROG_TYPE_PERF_EVENT = 7,
    BPF_PROG_TYPE_CGROUP_SKB = 8,
    BPF_PROG_TYPE_CGROUP_SOCK = 9,
    BPF_PROG_TYPE_LWT_IN = 10,
    BPF_PROG_TYPE_LWT_OUT = 11,
    BPF_PROG_TYPE_LWT_XMIT = 12,
    BPF_PROG_TYPE_SOCK_OPS = 13,
    BPF_PROG_TYPE_SK_SKB = 14,
    BPF_PROG_TYPE_CGROUP_DEVICE = 15,
    BPF_PROG_TYPE_SK_MSG = 16,
    BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
    BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
    BPF_PROG_TYPE_LIRC_MODE2 = 20,
    BPF_PROG_TYPE_SK_REUSEPORT = 21,
    BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
    BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
    BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
    BPF_PROG_TYPE_TRACING = 26,
    BPF_PROG_TYPE_STRUCT_OPS = 27,
    BPF_PROG_TYPE_EXT = 28,
    BPF_PROG_TYPE_LSM = 29,
    BPF_PROG_TYPE_SK_LOOKUP = 30,
    BPF_PROG_TYPE_SYSCALL = 31,
    BPF_PROG_TYPE_NETFILTER = 32,
};

#ifdef __cplusplus
}
#endif

#endif /* _BPF_VERIFIER_RS_H */
