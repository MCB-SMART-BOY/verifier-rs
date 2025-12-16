// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test loader for BPF Verifier Rust kernel module
 *
 * This program loads BPF programs and tests them through both
 * the kernel's native verifier and the Rust verifier module.
 *
 * Usage: sudo ./test_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

/* Device path */
#define DEVICE_PATH "/dev/bpf_verifier_rs"

/* IOCTL commands (must match kernel module) */
#define BPF_VERIFY_RS_MAGIC 'B'
#define BPF_VERIFY_RS_VERIFY    _IOWR(BPF_VERIFY_RS_MAGIC, 1, struct bpf_verify_request)
#define BPF_VERIFY_RS_GET_STATS _IOR(BPF_VERIFY_RS_MAGIC, 2, struct bpf_verifier_stats_rs)

/* BPF instruction encoding helpers */
#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_CLASS(code) ((code) & 0x07)

/* Instruction classes */
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_ALU64 0x07

/* ALU operations */
#define BPF_ADD  0x00
#define BPF_SUB  0x10
#undef BPF_MOV  /* Avoid conflict with linux/bpf.h */
#define BPF_MOV  0xb0

/* Source */
#define BPF_K    0x00
#define BPF_X    0x08

/* Jump operations */
#define BPF_EXIT 0x90

/* Registers */
#define BPF_REG_0  0
#define BPF_REG_1  1
#define BPF_REG_2  2
#define BPF_REG_10 10

/* Request structure */
struct bpf_verify_request {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns_ptr;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf_ptr;
    int32_t result;
};

struct bpf_verifier_stats_rs {
    uint64_t insns_processed;
    uint64_t states_explored;
    uint64_t peak_states;
    uint64_t total_states;
    uint64_t pruned_states;
};

/* BPF instruction */
struct bpf_insn {
    uint8_t code;
    uint8_t dst_reg:4;
    uint8_t src_reg:4;
    int16_t off;
    int32_t imm;
};

/* Instruction macros */
#define BPF_MOV64_IMM(dst, imm_val) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm_val })

#define BPF_MOV64_REG(dst, src) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = dst, .src_reg = src, .off = 0, .imm = 0 })

#define BPF_ALU64_IMM(op, dst, imm_val) \
    ((struct bpf_insn) { .code = BPF_ALU64 | op | BPF_K, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm_val })

#define BPF_EXIT_INSN() \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })

#define BPF_JMP_IMM(op, dst, imm_val, off_val) \
    ((struct bpf_insn) { .code = BPF_JMP | op | BPF_K, .dst_reg = dst, .src_reg = 0, .off = off_val, .imm = imm_val })

/* Test case structure */
struct test_case {
    const char *name;
    struct bpf_insn *insns;
    int insn_cnt;
    uint32_t prog_type;
    bool expect_pass;
    const char *description;
};

/* Global state */
static int device_fd = -1;
static int tests_passed = 0;
static int tests_failed = 0;

/* ========== Test Programs ========== */

/* Test 1: Simple return 0 */
static struct bpf_insn prog_simple_return[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
};

/* Test 2: Return immediate value */
static struct bpf_insn prog_return_42[] = {
    BPF_MOV64_IMM(BPF_REG_0, 42),
    BPF_EXIT_INSN(),
};

/* Test 3: ALU add operation */
static struct bpf_insn prog_alu_add[] = {
    BPF_MOV64_IMM(BPF_REG_0, 10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 20),
    BPF_EXIT_INSN(),
};

/* Test 4: ALU sub operation */
static struct bpf_insn prog_alu_sub[] = {
    BPF_MOV64_IMM(BPF_REG_0, 50),
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 20),
    BPF_EXIT_INSN(),
};

/* Test 5: Register move */
static struct bpf_insn prog_reg_move[] = {
    BPF_MOV64_IMM(BPF_REG_1, 100),
    BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
    BPF_EXIT_INSN(),
};

/* Test 6: Invalid - uninitialized register read (should fail) */
static struct bpf_insn prog_uninit_reg[] = {
    BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),  /* R2 not initialized */
    BPF_EXIT_INSN(),
};

/* Test 7: Invalid - reading from R10 directly (should work, it's FP) */
static struct bpf_insn prog_read_fp[] = {
    BPF_MOV64_REG(BPF_REG_0, BPF_REG_10),
    BPF_MOV64_IMM(BPF_REG_0, 0),  /* Clear to avoid pointer leak */
    BPF_EXIT_INSN(),
};

/* Test 8: Multiple ALU operations */
static struct bpf_insn prog_multi_alu[] = {
    BPF_MOV64_IMM(BPF_REG_0, 100),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 50),
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 30),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 10),
    BPF_EXIT_INSN(),
};

/* Test 9: Empty program (just exit) - edge case */
static struct bpf_insn prog_empty[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
};

/* Test 10: XDP return codes */
static struct bpf_insn prog_xdp_drop[] = {
    BPF_MOV64_IMM(BPF_REG_0, 1),  /* XDP_DROP */
    BPF_EXIT_INSN(),
};

/* Test array */
static struct test_case test_cases[] = {
    {
        .name = "simple_return",
        .insns = prog_simple_return,
        .insn_cnt = sizeof(prog_simple_return) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Simple return 0",
    },
    {
        .name = "return_42",
        .insns = prog_return_42,
        .insn_cnt = sizeof(prog_return_42) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Return immediate value 42",
    },
    {
        .name = "alu_add",
        .insns = prog_alu_add,
        .insn_cnt = sizeof(prog_alu_add) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "ALU add immediate",
    },
    {
        .name = "alu_sub",
        .insns = prog_alu_sub,
        .insn_cnt = sizeof(prog_alu_sub) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "ALU subtract immediate",
    },
    {
        .name = "reg_move",
        .insns = prog_reg_move,
        .insn_cnt = sizeof(prog_reg_move) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Register to register move",
    },
    {
        .name = "uninit_reg",
        .insns = prog_uninit_reg,
        .insn_cnt = sizeof(prog_uninit_reg) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = false,
        .description = "Read uninitialized register (should fail)",
    },
    {
        .name = "read_fp",
        .insns = prog_read_fp,
        .insn_cnt = sizeof(prog_read_fp) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Read frame pointer register",
    },
    {
        .name = "multi_alu",
        .insns = prog_multi_alu,
        .insn_cnt = sizeof(prog_multi_alu) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Multiple ALU operations",
    },
    {
        .name = "empty",
        .insns = prog_empty,
        .insn_cnt = sizeof(prog_empty) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .expect_pass = true,
        .description = "Minimal valid program",
    },
    {
        .name = "xdp_drop",
        .insns = prog_xdp_drop,
        .insn_cnt = sizeof(prog_xdp_drop) / sizeof(struct bpf_insn),
        .prog_type = BPF_PROG_TYPE_XDP,
        .expect_pass = true,
        .description = "XDP drop program",
    },
};

#define NUM_TESTS (sizeof(test_cases) / sizeof(test_cases[0]))

/* Verify using kernel's native verifier */
static int verify_native(struct test_case *tc)
{
    union bpf_attr attr = {0};
    char log_buf[4096] = {0};
    int fd;

    attr.prog_type = tc->prog_type;
    attr.insns = (uint64_t)tc->insns;
    attr.insn_cnt = tc->insn_cnt;
    attr.license = (uint64_t)"GPL";
    attr.log_buf = (uint64_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return errno;
}

/* Verify using Rust verifier module */
static int verify_rust(struct test_case *tc)
{
    struct bpf_verify_request req = {0};
    int ret;

    req.prog_type = tc->prog_type;
    req.insn_cnt = tc->insn_cnt;
    req.insns_ptr = (uint64_t)tc->insns;
    req.log_level = 1;
    req.log_size = 0;
    req.log_buf_ptr = 0;

    ret = ioctl(device_fd, BPF_VERIFY_RS_VERIFY, &req);
    if (ret < 0)
        return errno;

    return req.result;
}

/* Run a single test */
static void run_test(struct test_case *tc)
{
    int native_result, rust_result;
    bool native_pass, rust_pass;
    const char *status;

    printf("  %-20s: ", tc->name);
    fflush(stdout);

    /* Test with native verifier */
    native_result = verify_native(tc);
    native_pass = (native_result == 0);

    /* Test with Rust verifier */
    rust_result = verify_rust(tc);
    rust_pass = (rust_result == 0);

    /* Compare results */
    if (rust_pass == tc->expect_pass) {
        if (native_pass == rust_pass) {
            status = "\033[32mPASS\033[0m";
            tests_passed++;
        } else {
            /* Different from native, but matches expected */
            status = "\033[33mPASS (differs from native)\033[0m";
            tests_passed++;
        }
    } else {
        status = "\033[31mFAIL\033[0m";
        tests_failed++;
    }

    printf("%s\n", status);
    printf("    Description: %s\n", tc->description);
    printf("    Expected: %s, Native: %s (err=%d), Rust: %s (err=%d)\n",
           tc->expect_pass ? "pass" : "fail",
           native_pass ? "pass" : "fail", native_result,
           rust_pass ? "pass" : "fail", rust_result);
}

/* Main function */
int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    size_t i;

    printf("BPF Verifier Rust Test Suite\n");
    printf("============================\n\n");

    /* Check for root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program must be run as root\n");
        return 1;
    }

    /* Open device */
    device_fd = open(DEVICE_PATH, O_RDWR);
    if (device_fd < 0) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", DEVICE_PATH, strerror(errno));
        fprintf(stderr, "Make sure the kernel module is loaded: sudo insmod bpf_verifier_rs.ko\n");
        return 1;
    }

    printf("Device opened: %s\n\n", DEVICE_PATH);
    printf("Running %zu tests:\n\n", NUM_TESTS);

    /* Run all tests */
    for (i = 0; i < NUM_TESTS; i++) {
        run_test(&test_cases[i]);
        printf("\n");
    }

    /* Print summary */
    printf("============================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("============================\n");

    close(device_fd);

    return tests_failed > 0 ? 1 : 0;
}
