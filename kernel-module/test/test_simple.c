// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple test for BPF Verifier Rust kernel module
 * Tests basic IOCTL without actual verification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

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

#define BPF_VERIFY_RS_MAGIC 'B'
#define BPF_VERIFY_RS_VERIFY    _IOWR(BPF_VERIFY_RS_MAGIC, 1, struct bpf_verify_request)
#define BPF_VERIFY_RS_GET_STATS _IOR(BPF_VERIFY_RS_MAGIC, 2, struct bpf_verifier_stats_rs)

/* BPF instruction constants */
#define BPF_ALU64 0x07
#define BPF_MOV   0xb0
#define BPF_K     0x00
#define BPF_JMP   0x05
#define BPF_EXIT  0x90

int main(void)
{
    int fd;
    int ret;
    struct bpf_verify_request req;
    struct bpf_verifier_stats_rs stats;

    /* Simple program: mov r0, 0; exit */
    struct bpf_insn_rs prog[2] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
    };

    printf("=== Simple BPF Verifier Test ===\n\n");

    /* Open device */
    fd = open("/dev/bpf_verifier_rs", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    printf("Device opened (fd=%d)\n", fd);

    /* Test 1: Get stats (should work even without verification) */
    printf("\nTest 1: GET_STATS ioctl\n");
    memset(&stats, 0, sizeof(stats));
    ret = ioctl(fd, BPF_VERIFY_RS_GET_STATS, &stats);
    printf("  ioctl returned: %d (errno=%d)\n", ret, ret < 0 ? errno : 0);

    /* Test 2: Try verification with invalid request (insn_cnt = 0) */
    printf("\nTest 2: VERIFY with insn_cnt=0 (should fail with EINVAL)\n");
    memset(&req, 0, sizeof(req));
    req.prog_type = 1; /* socket filter */
    req.insn_cnt = 0;
    req.insns_ptr = 0;
    ret = ioctl(fd, BPF_VERIFY_RS_VERIFY, &req);
    printf("  ioctl returned: %d (errno=%d, expected EINVAL=%d)\n",
           ret, ret < 0 ? errno : 0, EINVAL);

    /* Test 3: Prepare valid request but don't send yet */
    printf("\nTest 3: Preparing valid request struct\n");
    memset(&req, 0, sizeof(req));
    req.prog_type = 1;  /* socket filter */
    req.insn_cnt = 2;
    req.insns_ptr = (uint64_t)prog;
    req.log_level = 0;
    req.log_size = 0;
    req.log_buf_ptr = 0;
    req.result = -999;

    printf("  prog_type: %u\n", req.prog_type);
    printf("  insn_cnt: %u\n", req.insn_cnt);
    printf("  insns_ptr: %p\n", (void*)req.insns_ptr);
    printf("  Program bytes:\n");
    for (int i = 0; i < 2; i++) {
        printf("    [%d] code=%02x dst=%d src=%d off=%d imm=%d\n",
               i, prog[i].code, prog[i].dst_reg, prog[i].src_reg,
               prog[i].off, prog[i].imm);
    }

    /* Test 4: Actually run verification */
    printf("\nTest 4: VERIFY with valid program\n");
    printf("  Calling ioctl...\n");
    fflush(stdout);

    ret = ioctl(fd, BPF_VERIFY_RS_VERIFY, &req);

    printf("  ioctl returned: %d\n", ret);
    if (ret < 0) {
        printf("  errno: %d (%s)\n", errno, strerror(errno));
    } else {
        printf("  result: %d\n", req.result);
    }

    close(fd);
    printf("\n=== Test complete ===\n");
    return 0;
}
