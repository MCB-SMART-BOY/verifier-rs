// SPDX-License-Identifier: GPL-2.0-only
/*
 * Invalid BPF programs that should be rejected by the verifier
 * These are used to test that the verifier properly rejects bad programs.
 *
 * NOTE: These programs are intentionally invalid and should NOT compile
 * or should be rejected at verification time. They are provided as
 * reference for what the verifier should reject.
 */

/*
 * The following are examples of invalid programs represented as raw
 * instruction arrays. They will be loaded directly in the test loader.
 */

/*
 * Invalid program 1: Uninitialized register read
 * mov r0, r1  ; r1 is not initialized
 * exit
 *
 * Instructions:
 * BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),  // 0xbf 0x10 0x00 0x00 0x00 0x00 0x00 0x00
 * BPF_EXIT_INSN(),                       // 0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00
 */

/*
 * Invalid program 2: Out of bounds stack access
 * mov r1, r10      ; r10 = frame pointer
 * sub r1, 520      ; access beyond 512 byte stack limit
 * ldx r0, [r1]     ; load from invalid stack location
 * exit
 */

/*
 * Invalid program 3: Division by zero (potential)
 * mov r0, 10
 * mov r1, 0
 * div r0, r1       ; divide by zero
 * exit
 */

/*
 * Invalid program 4: Infinite loop
 * loop:
 *   ja loop        ; unconditional jump to self
 */

/*
 * Invalid program 5: Unreachable code after exit
 * exit
 * mov r0, 1        ; unreachable
 * exit
 */

/*
 * Invalid program 6: Invalid opcode
 * .byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
 */

/*
 * Invalid program 7: Pointer leak (returning pointer as scalar)
 * mov r0, r10      ; r10 = stack pointer
 * exit             ; returning pointer to userspace
 */

/*
 * Invalid program 8: Reading uninitialized stack
 * mov r1, r10
 * sub r1, 8
 * ldx r0, [r1]     ; reading uninitialized stack slot
 * exit
 */

/*
 * Note: The actual test cases using these patterns are defined in
 * test_loader.c as raw instruction arrays, since clang won't compile
 * intentionally invalid BPF code.
 */

char _license[] __attribute__((section("license"), used)) = "GPL";
