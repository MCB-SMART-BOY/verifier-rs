// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF program testing bounds checking
 */

#include <linux/bpf.h>

#define MAX_SIZE 64

/* Test array bounds checking */
__attribute__((section("socket"), used))
int test_bounds(void *ctx)
{
    volatile unsigned char buf[MAX_SIZE];
    volatile int idx = 10;

    /* This should pass - index within bounds */
    if (idx >= 0 && idx < MAX_SIZE) {
        buf[idx] = 42;
    }

    /* Bounds check with variable */
    idx = 32;
    if (idx < MAX_SIZE) {
        buf[idx] = buf[0] + 1;
    }

    return 0;
}

/* Test pointer arithmetic bounds */
__attribute__((section("socket"), used))
int test_ptr_bounds(void *ctx)
{
    volatile unsigned char buf[32];
    volatile unsigned char *ptr = buf;
    volatile unsigned char *end = buf + 32;

    /* Safe pointer iteration */
    while (ptr < end) {
        *ptr = 0;
        ptr++;
    }

    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
