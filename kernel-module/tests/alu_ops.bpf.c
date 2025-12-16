// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF program testing ALU operations
 */

#include <linux/bpf.h>

/* Test basic ALU operations */
__attribute__((section("socket"), used))
int test_alu(void *ctx)
{
    volatile int a = 10;
    volatile int b = 20;
    volatile int c;

    /* Addition */
    c = a + b;
    if (c != 30)
        return 1;

    /* Subtraction */
    c = b - a;
    if (c != 10)
        return 1;

    /* Multiplication */
    c = a * 3;
    if (c != 30)
        return 1;

    /* Division */
    c = b / a;
    if (c != 2)
        return 1;

    /* Bitwise AND */
    c = 0xFF & 0x0F;
    if (c != 0x0F)
        return 1;

    /* Bitwise OR */
    c = 0xF0 | 0x0F;
    if (c != 0xFF)
        return 1;

    /* Bitwise XOR */
    c = 0xFF ^ 0x0F;
    if (c != 0xF0)
        return 1;

    /* Left shift */
    c = 1 << 4;
    if (c != 16)
        return 1;

    /* Right shift */
    c = 16 >> 2;
    if (c != 4)
        return 1;

    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
