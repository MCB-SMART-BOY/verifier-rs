// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple BPF program that just returns 0
 * This is the most basic test case for the verifier.
 */

#include <linux/bpf.h>

/* XDP program that drops all packets */
__attribute__((section("xdp"), used))
int xdp_drop(void *ctx)
{
    return 1; /* XDP_DROP */
}

/* Socket filter that accepts all packets */
__attribute__((section("socket"), used))
int socket_pass(void *ctx)
{
    return 0; /* Accept */
}

char _license[] __attribute__((section("license"), used)) = "GPL";
