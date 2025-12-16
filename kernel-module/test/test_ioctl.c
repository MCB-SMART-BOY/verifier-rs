// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test program for BPF Verifier Rust kernel module IOCTL interface
 *
 * This program tests the /dev/bpf_verifier_rs device by submitting
 * various BPF programs for verification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* Match the header definitions */
struct bpf_insn_rs {
    uint8_t code;
    uint8_t dst_reg;
    uint8_t src_reg;
    int16_t off;
    int32_t imm;
};

struct bpf_verifier_stats_rs {
    uint64_t insns_processed;
    uint64_t states_explored;
    uint64_t peak_states;
    uint64_t total_states;
    uint64_t pruned_states;
};

struct bpf_verify_request {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns_ptr;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf_ptr;
    int32_t result;
};

/* IOCTL commands */
#define BPF_VERIFY_RS_MAGIC 'B'
#define BPF_VERIFY_RS_VERIFY    _IOWR(BPF_VERIFY_RS_MAGIC, 1, struct bpf_verify_request)
#define BPF_VERIFY_RS_GET_STATS _IOR(BPF_VERIFY_RS_MAGIC, 2, struct bpf_verifier_stats_rs)

/* BPF instruction encoding helpers */
#define BPF_OP(code)   ((code) & 0xf0)
#define BPF_CLASS(code) ((code) & 0x07)

/* Instruction classes */
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_RET   0x06
#define BPF_MISC  0x07
#define BPF_ALU64 0x07

/* ALU operations */
#define BPF_MOV   0xb0
#define BPF_ADD   0x00
#define BPF_EXIT  0x90

/* Source */
#define BPF_K     0x00
#define BPF_X     0x08

/* Registers */
#define BPF_REG_0  0
#define BPF_REG_1  1
#define BPF_REG_2  2
#define BPF_REG_10 10

/* Program types */
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_PROG_TYPE_XDP 6

/* Helper to create instruction struct */
static inline struct bpf_insn_rs make_insn(uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t immval)
{
    struct bpf_insn_rs insn = { code, dst, src, off, immval };
    return insn;
}

/* Instruction builders */
#define BPF_MOV64_IMM(dst, immval) \
    make_insn(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, immval)

#define BPF_EXIT_INSN() \
    make_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_ALU64_IMM(op, dst, immval) \
    make_insn(BPF_ALU64 | (op) | BPF_K, dst, 0, 0, immval)

#define BPF_JMP_A(offset) \
    make_insn(BPF_JMP | 0x00, 0, 0, offset, 0)

/* Colors for output */
#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[0;33m"
#define RESET   "\033[0m"

static const char *DEVICE_PATH = "/dev/bpf_verifier_rs";

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

static void print_result(const char *test_name, int expected, int actual)
{
    test_count++;
    int pass = (expected == 0 && actual == 0) || (expected != 0 && actual != 0);
    
    if (pass) {
        pass_count++;
        printf(GREEN "[PASS]" RESET " %s (result=%d)\n", test_name, actual);
    } else {
        fail_count++;
        printf(RED "[FAIL]" RESET " %s (expected=%d, got=%d)\n", test_name, expected, actual);
    }
}

static int verify_program(int fd, struct bpf_insn_rs *insns, uint32_t insn_cnt,
                          uint32_t prog_type, const char *test_name, int expect_success)
{
    struct bpf_verify_request req = {
        .prog_type = prog_type,
        .insn_cnt = insn_cnt,
        .insns_ptr = (uint64_t)insns,
        .log_level = 1,
        .log_size = 0,
        .log_buf_ptr = 0,
        .result = -1,
    };

    int ret = ioctl(fd, BPF_VERIFY_RS_VERIFY, &req);
    if (ret < 0) {
        printf(YELLOW "[ERROR]" RESET " %s: ioctl failed: %s\n", test_name, strerror(errno));
        fail_count++;
        test_count++;
        return -1;
    }

    print_result(test_name, expect_success ? 0 : -1, req.result);
    return req.result;
}

/* Test 1: Minimal valid program (mov r0, 0; exit) */
static void test_minimal_program(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    verify_program(fd, prog, 2, BPF_PROG_TYPE_SOCKET_FILTER,
                   "Minimal valid program (mov r0, 0; exit)", 1);
}

/* Test 2: Program returning non-zero */
static void test_return_one(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    verify_program(fd, prog, 2, BPF_PROG_TYPE_SOCKET_FILTER,
                   "Program returning 1", 1);
}

/* Test 3: Program with arithmetic */
static void test_arithmetic(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 5),
        BPF_EXIT_INSN(),
    };
    verify_program(fd, prog, 3, BPF_PROG_TYPE_SOCKET_FILTER,
                   "Program with arithmetic (10 + 5)", 1);
}

/* Test 4: Empty program (should fail) */
static void test_empty_program(int fd)
{
    struct bpf_verify_request req = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = 0,
        .insns_ptr = 0,
        .log_level = 0,
        .log_size = 0,
        .log_buf_ptr = 0,
        .result = -1,
    };

    int ret = ioctl(fd, BPF_VERIFY_RS_VERIFY, &req);
    test_count++;
    if (ret < 0 && errno == EINVAL) {
        pass_count++;
        printf(GREEN "[PASS]" RESET " Empty program rejected (EINVAL)\n");
    } else {
        fail_count++;
        printf(RED "[FAIL]" RESET " Empty program should be rejected\n");
    }
}

/* Test 5: XDP program type */
static void test_xdp_program(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 2),  /* XDP_PASS */
        BPF_EXIT_INSN(),
    };
    verify_program(fd, prog, 2, BPF_PROG_TYPE_XDP,
                   "XDP program returning XDP_PASS", 1);
}

/* Test 6: Program without exit (should fail) */
static void test_no_exit(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
    };
    verify_program(fd, prog, 1, BPF_PROG_TYPE_SOCKET_FILTER,
                   "Program without exit (should fail)", 0);
}

/* Test 7: Program with forward jump */
static void test_forward_jump(int fd)
{
    struct bpf_insn_rs prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_JMP_A(1),                  /* skip next instruction */
        BPF_MOV64_IMM(BPF_REG_0, 1),   /* skipped */
        BPF_EXIT_INSN(),
    };
    verify_program(fd, prog, 4, BPF_PROG_TYPE_SOCKET_FILTER,
                   "Program with forward jump", 1);
}

/* Test 8: Get stats IOCTL */
static void test_get_stats(int fd)
{
    struct bpf_verifier_stats_rs stats;
    memset(&stats, 0xff, sizeof(stats));

    int ret = ioctl(fd, BPF_VERIFY_RS_GET_STATS, &stats);
    test_count++;
    if (ret == 0) {
        pass_count++;
        printf(GREEN "[PASS]" RESET " Get stats IOCTL succeeded\n");
    } else {
        fail_count++;
        printf(RED "[FAIL]" RESET " Get stats IOCTL failed: %s\n", strerror(errno));
    }
}

int main(void)
{
    printf("=================================================\n");
    printf("BPF Verifier Rust Kernel Module Test\n");
    printf("=================================================\n\n");

    /* Open device */
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", DEVICE_PATH, strerror(errno));
        fprintf(stderr, "\nMake sure the module is loaded:\n");
        fprintf(stderr, "  sudo insmod bpf_verifier_rs.ko\n");
        return 1;
    }

    printf("Device %s opened successfully\n\n", DEVICE_PATH);

    /* Run tests */
    printf("Running tests...\n\n");

    test_minimal_program(fd);
    test_return_one(fd);
    test_arithmetic(fd);
    test_empty_program(fd);
    test_xdp_program(fd);
    test_no_exit(fd);
    test_forward_jump(fd);
    test_get_stats(fd);

    /* Summary */
    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed", pass_count, test_count);
    if (fail_count > 0) {
        printf(", " RED "%d failed" RESET, fail_count);
    }
    printf("\n=================================================\n");

    close(fd);
    return fail_count > 0 ? 1 : 0;
}
