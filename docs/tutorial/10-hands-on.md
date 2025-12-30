# 第十章：动手实践

# Chapter 10: Hands-on Practice

---

## 概述 | Overview

本章提供一系列实践练习，帮助你通过动手实验来加深对 BPF 验证器的理解。

This chapter provides a series of hands-on exercises to help you deepen
your understanding of the BPF verifier through practical experimentation.

```
+-----------------------------------------------------------------------------------+
|                         Exercise Overview                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Basic Exercises:                                                        |
|  +--------------------------------------------------------------------+  |
|  | Exercise 1: Instruction Decoding - Parse BPF bytecode manually     |  |
|  | Exercise 2: State Tracking - Track register state changes          |  |
|  | Exercise 3: Tnum Calculation - Understand bit-level tracking       |  |
|  | Exercise 4: Bounds Refinement - Conditional jump effects           |  |
|  +--------------------------------------------------------------------+  |
|                                    |                                     |
|                                    v                                     |
|  Advanced Exercises:                                                     |
|  +--------------------------------------------------------------------+  |
|  | Exercise 5: State Pruning - Determine pruning conditions           |  |
|  | Exercise 6: Code Reading - Read project source code                |  |
|  | Exercise 7: Write Verifier - Implement simplified verification     |  |
|  +--------------------------------------------------------------------+  |
|                                    |                                     |
|                                    v                                     |
|  Challenge Tasks:                                                        |
|  +--------------------------------------------------------------------+  |
|  | Challenge 1: Add a new helper function                             |  |
|  | Challenge 2: Implement loop detection                              |  |
|  | Challenge 3: Optimize pruning strategy                             |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## Exercise 1: Understanding Instruction Decoding

## 练习1：理解指令解码

### Goal | 目标

Manually decode BPF instructions and understand the 64-bit instruction format.

手动解码 BPF 指令，理解 64 位指令格式。

### Background | 背景知识

```
+-----------------------------------------------------------------------------------+
|                   BPF Instruction Format (64-bit LE)                     |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Byte Position:                                                          |
|  +----------+----------+-------------+-----------------------------------+
|  | Byte 0   | Byte 1   | Byte 2-3    | Byte 4-7                          |
|  +----------+----------+-------------+-----------------------------------+
|  | opcode   | regs     | offset      | immediate                         |
|  | 8 bit    | 8 bit    | 16 bit (LE) | 32 bit (LE)                       |
|  +----------+----------+-------------+-----------------------------------+
|                                                                                   |
|  Register Byte Parsing:                                                  |
|  +--------------------------------------------------------------------+  |
|  |              regs (8 bit)                                          |  |
|  |  +----------------------------+----------------------------+       |  |
|  |  | bit 7-4                    | bit 3-0                    |       |  |
|  |  | src_reg                    | dst_reg                    |       |  |
|  |  +----------------------------+----------------------------+       |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Opcode Parsing:                                                         |
|  +--------------------------------------------------------------------+  |
|  |              opcode (8 bit)                                        |  |
|  |  +------------------+------------------+------------------+        |  |
|  |  | bit 7-4          | bit 3            | bit 2-0          |        |  |
|  |  | operation        | source           | class            |        |  |
|  |  +------------------+------------------+------------------+        |  |
|  |                                                                    |  |
|  |  Class Values:                                                     |  |
|  |  - 0x00: LD    (64-bit immediate load)                             |  |
|  |  - 0x01: LDX   (memory load)                                       |  |
|  |  - 0x02: ST    (immediate store)                                   |  |
|  |  - 0x03: STX   (register store)                                    |  |
|  |  - 0x04: ALU   (32-bit arithmetic)                                 |  |
|  |  - 0x05: JMP   (jump)                                              |  |
|  |  - 0x06: JMP32 (32-bit jump)                                       |  |
|  |  - 0x07: ALU64 (64-bit arithmetic)                                 |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Example Decoding | 示例解码

Given the following 8-byte hexadecimal data:

给定以下 8 字节的十六进制数据：

```
07 01 00 00 05 00 00 00
```

Decode this instruction:

```
+-----------------------------------------------------------------------------------+
|                        Decoding Process                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Step 1: Break down bytes                                                |
|  +--------------------------------------------------------------------+  |
|  |   07     01     00 00     05 00 00 00                              |  |
|  |   |      |      |         |                                        |  |
|  |   v      v      v         v                                        |  |
|  | opcode  regs   offset    immediate                                 |  |
|  | = 0x07  = 0x01 = 0x0000  = 0x00000005 (LE)                         |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Step 2: Parse opcode                                                    |
|  +--------------------------------------------------------------------+  |
|  |  0x07 = 0b0000_0111                                                |  |
|  |                                                                    |  |
|  |  operation: 0x00 (ADD)                                             |  |
|  |  source:    0    (K, use immediate)                                |  |
|  |  class:     0x07 (ALU64)                                           |  |
|  |                                                                    |  |
|  |  => ALU64_ADD_K = 64-bit add with immediate                        |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Step 3: Parse registers                                                 |
|  +--------------------------------------------------------------------+  |
|  |  0x01 = 0b0000_0001                                                |  |
|  |                                                                    |  |
|  |  src_reg: 0x01 >> 4 = 0 (unused, source=K)                         |  |
|  |  dst_reg: 0x01 & 0xF = 1 (R1)                                      |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Step 4: Combine result                                                  |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   Instruction: r1 += 5                                             |  |
|  |   Assembly: ALU64_ADD_K dst=R1 imm=5                               |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Practice Problem | 练习题

Decode the following instruction:

解码以下指令：

```
bf 21 00 00 00 00 00 00
```

Hints:
- `0xbf`: class = 0x07 (ALU64), source = 1 (X, use register)
- `0xbf`: operation = 0xb0 >> 4 = 0x0b = MOV

<details>
<summary>Click to see answer | 点击查看答案</summary>

```
+-----------------------------------------------------------------------------------+
|                            Answer                                        |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Byte breakdown:                                                         |
|  +--------------------------------------------------------------------+  |
|  |   bf     21     00 00     00 00 00 00                              |  |
|  |   |      |      |         |                                        |  |
|  |   v      v      v         v                                        |  |
|  | opcode  regs   offset    immediate                                 |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Opcode parsing:                                                         |
|  +--------------------------------------------------------------------+  |
|  |  0xbf = 0b1011_1111                                                |  |
|  |                                                                    |  |
|  |  operation: 0xb0 >> 4 = 11 = MOV                                   |  |
|  |  source:    1 (X, use register)                                    |  |
|  |  class:     0x07 (ALU64)                                           |  |
|  |                                                                    |  |
|  |  => ALU64_MOV_X = 64-bit register move                             |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Register parsing:                                                       |
|  +--------------------------------------------------------------------+  |
|  |  0x21 = 0b0010_0001                                                |  |
|  |                                                                    |  |
|  |  src_reg: 0x21 >> 4 = 2 (R2)                                       |  |
|  |  dst_reg: 0x21 & 0xF = 1 (R1)                                      |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Final result:                                                           |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   Instruction: r1 = r2                                             |  |
|  |   Assembly: ALU64_MOV_X dst=R1 src=R2                              |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

### Additional Practice | 额外练习

Try decoding these instructions:

```
Instruction 1: 85 00 00 00 01 00 00 00    (Hint: class=0x05 is JMP)
Instruction 2: 61 12 04 00 00 00 00 00    (Hint: class=0x01 is LDX)
Instruction 3: 95 00 00 00 00 00 00 00    (Hint: this is exit)
```

<details>
<summary>Click to see answers | 点击查看答案</summary>

```
Instruction 1: 85 00 00 00 01 00 00 00
  opcode: 0x85 = JMP_CALL (call helper function)
  imm: 0x01 = helper function ID 1 (bpf_map_lookup_elem)
  Instruction: call 1

Instruction 2: 61 12 04 00 00 00 00 00
  opcode: 0x61 = LDX_MEM_W (32-bit memory load)
  regs: 0x12 => dst=R2, src=R1
  offset: 0x0004
  Instruction: r2 = *(u32*)(r1 + 4)

Instruction 3: 95 00 00 00 00 00 00 00
  opcode: 0x95 = JMP_EXIT
  Instruction: exit
```

</details>

---

## Exercise 2: Tracking Register State

## 练习2：追踪寄存器状态

### Goal | 目标

Manually trace register state changes through BPF code to understand
how the verifier maintains state.

手动追踪一段 BPF 代码的寄存器状态变化，理解验证器如何维护状态。

### Background | 背景知识

```
+-----------------------------------------------------------------------------------+
|                     Register State Types                                 |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +------------------------+----------------------------------------------+
|  | Type                   | Description                                  |
|  +------------------------+----------------------------------------------+
|  | NOT_INIT               | Register not initialized, cannot be read     |
|  | SCALAR_VALUE           | Scalar value with range [min, max]           |
|  | PTR_TO_CTX             | Pointer to program context                   |
|  | PTR_TO_STACK           | Pointer to stack with offset                 |
|  | PTR_TO_MAP_VALUE       | Pointer to map value                         |
|  | PTR_TO_MAP_KEY         | Pointer to map key                           |
|  | PTR_TO_PACKET          | Pointer to network packet data               |
|  +------------------------+----------------------------------------------+
|                                                                                   |
|  Initial State (program entry):                                          |
|  +--------------------------------------------------------------------+  |
|  | R0:  NOT_INIT        (return value, uninitialized)                 |  |
|  | R1:  PTR_TO_CTX      (first argument, program context)             |  |
|  | R2:  NOT_INIT                                                      |  |
|  | ...                                                                |  |
|  | R9:  NOT_INIT                                                      |  |
|  | R10: PTR_TO_STACK    (frame pointer, offset=0)                     |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Exercise | 练习

Trace the register state for the following code:

追踪以下代码的寄存器状态：

```
Initial State:
  r1 = PTR_TO_CTX
  r10 = PTR_TO_STACK (offset=0)
  Other registers = NOT_INIT

Code:
  0: r0 = 0              ; Assign constant 0 to r0
  1: r2 = *(u32*)(r1+0)  ; Load 32-bit value from CTX offset 0
  2: if r2 > 100 goto 5  ; Conditional jump
  3: r0 = 1              ; False branch: set return value to 1
  4: goto 6              ; Jump to exit
  5: r0 = 2              ; True branch: set return value to 2
  6: exit                ; Exit program
```

Control Flow Graph:

```
                            +---------+
                            | 0: r0=0 |
                            +----+----+
                                 |
                                 v
                       +---------------------+
                       | 1: r2=*(u32*)(r1+0) |
                       +----------+----------+
                                  |
                                  v
                      +-----------------------+
                      | 2: if r2 > 100 goto 5 |
                      +-----------+-----------+
                     false        |        true
                    (r2<=100)     |      (r2>100)
                    +-------------+-------------+
                    |                           |
                    v                           v
              +----------+                +----------+
              | 3: r0=1  |                | 5: r0=2  |
              +----+-----+                +----+-----+
                   |                           |
                   v                           |
              +----------+                     |
              | 4: goto 6|                     |
              +----+-----+                     |
                   +-----------+---------------+
                               |
                               v
                         +----------+
                         | 6: exit  |
                         +----------+
```

Fill in the state table:

| Insn | r0 State | r2 State | Notes |
|------|----------|----------|-------|
| Init | NOT_INIT | NOT_INIT | |
| After 0 | ? | ? | |
| After 1 | ? | ? | |
| After 2 (false) | ? | ? | |
| After 3 | ? | ? | |
| After 2 (true) | ? | ? | |
| After 5 | ? | ? | |

<details>
<summary>Click to see answer | 点击查看答案</summary>

```
+-----------------------------------------------------------------------------------+
|                        State Tracking Answer                             |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +--------+------------------------+------------------------+------------+
|  | Insn   | r0 State               | r2 State               | Notes      |
|  +--------+------------------------+------------------------+------------+
|  | Init   | NOT_INIT               | NOT_INIT               | Entry      |
|  +--------+------------------------+------------------------+------------+
|  | Aft 0  | SCALAR [0,0]           | NOT_INIT               | Const 0    |
|  |        | (constant 0)           |                        |            |
|  +--------+------------------------+------------------------+------------+
|  | Aft 1  | SCALAR [0,0]           | SCALAR [0, 2^32-1]     | From CTX   |
|  |        |                        | (32-bit unsigned)      |            |
|  +--------+------------------------+------------------------+------------+
|  | Aft 2F | SCALAR [0,0]           | SCALAR [0, 100]        | Refined    |
|  | (false)|                        | r2 <= 100              |            |
|  +--------+------------------------+------------------------+------------+
|  | Aft 3  | SCALAR [1,1]           | SCALAR [0, 100]        | Set r0=1   |
|  |        | (constant 1)           |                        |            |
|  +--------+------------------------+------------------------+------------+
|  | Aft 2T | SCALAR [0,0]           | SCALAR [101, 2^32-1]   | Refined    |
|  | (true) |                        | r2 > 100               |            |
|  +--------+------------------------+------------------------+------------+
|  | Aft 5  | SCALAR [2,2]           | SCALAR [101, 2^32-1]   | Set r0=2   |
|  |        | (constant 2)           |                        |            |
|  +--------+------------------------+------------------------+------------+
|                                                                                   |
|  Key Observations:                                                       |
|  +--------------------------------------------------------------------+  |
|  | 1. Conditional jumps refine bounds on both branches                |  |
|  | 2. False branch: r2 <= 100, so r2 in [0, 100]                      |  |
|  | 3. True branch: r2 > 100, so r2 in [101, 2^32-1]                   |  |
|  | 4. Different paths may have different states                       |  |
|  | 5. Verifier verifies each path separately                          |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

---

## Exercise 3: Tnum Calculation

## 练习3：Tnum 计算

### Goal | 目标

Understand Tnum's bit-level tracking mechanism and manually calculate
Tnum operation results.

理解 Tnum 的位级追踪机制，手动计算 Tnum 运算结果。

### Background | 背景知识

```
+-----------------------------------------------------------------------------------+
|                        Tnum Structure                                    |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Tnum consists of two fields:                                            |
|  +--------------------------------------------------------------------+  |
|  |  value: u64  - bits known to be 1                                  |  |
|  |  mask:  u64  - unknown bits (1 means bit is uncertain)             |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Bit State Interpretation:                                               |
|  +------------+------------+---------------------------------------------+
|  | mask bit   | value bit  | Meaning                                     |
|  +------------+------------+---------------------------------------------+
|  |     0      |     0      | Bit is definitely 0                         |
|  |     0      |     1      | Bit is definitely 1                         |
|  |     1      |     0      | Bit is uncertain (could be 0 or 1)          |
|  |     1      |     1      | Invalid state (should not occur)            |
|  +------------+------------+---------------------------------------------+
|                                                                                   |
|  Examples:                                                               |
|  +--------------------------------------------------------------------+  |
|  |  Tnum { value: 0x10, mask: 0x0F }                                  |  |
|  |  Binary: value = 0001_0000                                         |  |
|  |          mask  = 0000_1111                                         |  |
|  |  Represents: 0001_????  (high bits=0001, low 4 bits unknown)       |  |
|  |  Range: [0x10, 0x1F] = [16, 31]                                    |  |
|  |                                                                    |  |
|  |  Tnum { value: 0x05, mask: 0x00 }                                  |  |
|  |  Binary: value = 0000_0101                                         |  |
|  |          mask  = 0000_0000                                         |  |
|  |  Represents: 0000_0101  (all bits known)                           |  |
|  |  Range: [5, 5] = constant 5                                        |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Tnum Operation Rules

```
+-----------------------------------------------------------------------------------+
|                      Tnum Operation Rules                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  AND Operation (A & B):                                                  |
|  +--------------------------------------------------------------------+  |
|  |  Rule: Bits known to be 0 result in definite 0                     |  |
|  |  result.value = a.value & b.value                                  |  |
|  |  result.mask  = (a.mask | b.mask) & ~(known_zeros)                 |  |
|  |                                                                    |  |
|  |  Simplified:                                                       |  |
|  |  - Both known 0 -> result is 0                                     |  |
|  |  - Either known 0 -> result is 0                                   |  |
|  |  - Both known 1 -> result is 1                                     |  |
|  |  - Otherwise -> result is uncertain                                |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  OR Operation (A | B):                                                   |
|  +--------------------------------------------------------------------+  |
|  |  Rule: Bits known to be 1 result in definite 1                     |  |
|  |  result.value = a.value | b.value                                  |  |
|  |  result.mask  = (a.mask | b.mask) & ~(a.value | b.value)           |  |
|  |                                                                    |  |
|  |  Simplified:                                                       |  |
|  |  - Either known 1 -> result is 1                                   |  |
|  |  - Both known 0 -> result is 0                                     |  |
|  |  - Otherwise -> result is uncertain                                |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  ADD Operation (A + B):                                                  |
|  +--------------------------------------------------------------------+  |
|  |  Rule: Carry propagation increases uncertainty                     |  |
|  |  Most complex because low-bit uncertainty affects high bits        |  |
|  |                                                                    |  |
|  |  Algorithm:                                                        |  |
|  |  sv = a.value + b.value                                            |  |
|  |  sm = a.mask + b.mask                                              |  |
|  |  sigma = sv + sm                                                   |  |
|  |  chi = sigma ^ sv  // positions where carry may occur              |  |
|  |  mu = chi | a.mask | b.mask  // all uncertain bits                 |  |
|  |  result.value = sv & ~mu                                           |  |
|  |  result.mask = mu                                                  |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Exercise | 练习

Calculate the following Tnum operation results:

计算以下 Tnum 运算的结果：

```
Tnum A: value=0x10, mask=0x0F
        Binary: 0001_????
        Range: [16, 31]

Tnum B: value=0x03, mask=0x00
        Binary: 0000_0011
        Represents: constant 3

Question 1: A & B = ?
Question 2: A | B = ?
Question 3: A + B = ?
```

<details>
<summary>Click to see answer | 点击查看答案</summary>

```
+-----------------------------------------------------------------------------------+
|                      Tnum Operation Answers                              |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Question 1: A & B                                                       |
|  +--------------------------------------------------------------------+  |
|  |  A: 0001_????  (value=0x10, mask=0x0F)                             |  |
|  |  B: 0000_0011  (value=0x03, mask=0x00)                             |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - A high 4 bits (0001) & B high 4 bits (0000) = 0000 (definite)   |  |
|  |  - A low 4 bits (????) & B low 4 bits (0011):                      |  |
|  |    - bit 3: ? & 0 = 0 (definite 0)                                 |  |
|  |    - bit 2: ? & 0 = 0 (definite 0)                                 |  |
|  |    - bit 1: ? & 1 = ? (uncertain)                                  |  |
|  |    - bit 0: ? & 1 = ? (uncertain)                                  |  |
|  |                                                                    |  |
|  |  Result: 0000_00??                                                 |  |
|  |  Tnum { value: 0x00, mask: 0x03 }                                  |  |
|  |  Range: [0, 3]                                                     |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Question 2: A | B                                                       |
|  +--------------------------------------------------------------------+  |
|  |  A: 0001_????  (value=0x10, mask=0x0F)                             |  |
|  |  B: 0000_0011  (value=0x03, mask=0x00)                             |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - A high 4 bits (0001) | B high 4 bits (0000) = 0001 (definite)   |  |
|  |  - A low 4 bits (????) | B low 4 bits (0011):                      |  |
|  |    - bit 3: ? | 0 = ? (uncertain)                                  |  |
|  |    - bit 2: ? | 0 = ? (uncertain)                                  |  |
|  |    - bit 1: ? | 1 = 1 (definite 1)                                 |  |
|  |    - bit 0: ? | 1 = 1 (definite 1)                                 |  |
|  |                                                                    |  |
|  |  Result: 0001_??11                                                 |  |
|  |  Tnum { value: 0x13, mask: 0x0C }                                  |  |
|  |  Range: [0x13, 0x1F] = [19, 31]                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Question 3: A + B                                                       |
|  +--------------------------------------------------------------------+  |
|  |  A: [16, 31]  (value=0x10, mask=0x0F)                              |  |
|  |  B: 3         (value=0x03, mask=0x00)                              |  |
|  |                                                                    |  |
|  |  Mathematical range: [16+3, 31+3] = [19, 34] = [0x13, 0x22]        |  |
|  |                                                                    |  |
|  |  Tnum calculation:                                                 |  |
|  |  sv = 0x10 + 0x03 = 0x13                                           |  |
|  |  sm = 0x0F + 0x00 = 0x0F                                           |  |
|  |  sigma = 0x13 + 0x0F = 0x22                                        |  |
|  |  chi = 0x22 ^ 0x13 = 0x31  (carry positions)                       |  |
|  |  mu = 0x31 | 0x0F | 0x00 = 0x3F                                    |  |
|  |  result.value = 0x13 & ~0x3F = 0x00                                |  |
|  |  result.mask = 0x3F                                                |  |
|  |                                                                    |  |
|  |  Result: Tnum { value: 0x00, mask: 0x3F }                          |  |
|  |  Represents: 00??_????                                             |  |
|  |  Range: [0, 63] (conservative estimate)                            |  |
|  |                                                                    |  |
|  |  Note: Tnum range is wider than actual [19, 34] because            |  |
|  |        Tnum only tracks bits, not carry constraints.               |  |
|  |        Verifier combines umin/umax for more precise bounds.        |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

---

## Exercise 4: Bounds Refinement

## 练习4：边界细化

### Goal | 目标

Understand how conditional jumps refine register bounds.

理解条件跳转对寄存器边界的细化作用。

### Background | 背景知识

```
+-----------------------------------------------------------------------------------+
|                    Bounds Refinement Rules                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Conditional jump format: if r1 <op> r2 goto target                      |
|  (or: if r1 <op> imm goto target)                                        |
|                                                                                   |
|  +----------+---------------------------+---------------------------+    |
|  | Operator | True branch (jump)        | False branch (continue)   |    |
|  +----------+---------------------------+---------------------------+    |
|  |    >     | r1.umin = max(r1.umin,    | r1.umax = min(r1.umax,    |    |
|  |          |              r2.umax+1)   |              r2.umax)     |    |
|  +----------+---------------------------+---------------------------+    |
|  |    >=    | r1.umin = max(r1.umin,    | r1.umax = min(r1.umax,    |    |
|  |          |              r2.umin)     |              r2.umin-1)   |    |
|  +----------+---------------------------+---------------------------+    |
|  |    ==    | r1 range tightens to      | Bounds unchanged          |    |
|  |          | intersect with r2         | (but excludes r2)         |    |
|  +----------+---------------------------+---------------------------+    |
|  |    !=    | Bounds unchanged          | r1 range tightens to      |    |
|  |          | (but excludes r2)         | intersect with r2         |    |
|  +----------+---------------------------+---------------------------+    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Exercise | 练习

Given register state:

```
r1: umin=0, umax=1000, smin=0, smax=1000
```

What are the bounds for true and false branches after these conditions?

```
1. if r1 > 500
2. if r1 >= 500
3. if r1 == 500
4. if r1 != 500
```

<details>
<summary>Click to see answer | 点击查看答案</summary>

```
+-----------------------------------------------------------------------------------+
|                      Bounds Refinement Answers                           |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Initial state: r1 in [0, 1000]                                          |
|                                                                                   |
|  1. if r1 > 500                                                          |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   [0-----------------------1000]  Initial range                    |  |
|  |                     500                                            |  |
|  |                      |                                             |  |
|  |                false | true                                        |  |
|  |   [0-----------500]  [501-----------1000]                          |  |
|  |                                                                    |  |
|  |   True branch (jump):     umin=501, umax=1000                      |  |
|  |   False branch (continue): umin=0,   umax=500                      |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  2. if r1 >= 500                                                         |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   [0-----------------------1000]  Initial range                    |  |
|  |                     500                                            |  |
|  |                      |                                             |  |
|  |               false  | true                                        |  |
|  |   [0---------499]  [500-----------1000]                            |  |
|  |                                                                    |  |
|  |   True branch (jump):     umin=500, umax=1000                      |  |
|  |   False branch (continue): umin=0,   umax=499                      |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  3. if r1 == 500                                                         |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   [0-----------------------1000]  Initial range                    |  |
|  |                     500                                            |  |
|  |                      |                                             |  |
|  |               false  v true                                        |  |
|  |   [0---------------]x[-----------1000]      [500]                  |  |
|  |                    exclude 500            constant!                |  |
|  |                                                                    |  |
|  |   True branch (jump):     umin=500, umax=500 (constant!)           |  |
|  |   False branch (continue): umin=0,   umax=1000 (excludes 500)      |  |
|  |   Note: False is actually [0,499] U [501,1000]                     |  |
|  |         but bounds tracking cannot represent this                  |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  4. if r1 != 500                                                         |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |   [0-----------------------1000]  Initial range                    |  |
|  |                     500                                            |  |
|  |                      |                                             |  |
|  |               true   v false                                       |  |
|  |   [0---------------]x[-----------1000]      [500]                  |  |
|  |                    exclude 500            constant!                |  |
|  |                                                                    |  |
|  |   True branch (jump):     umin=0,   umax=1000 (excludes 500)       |  |
|  |   False branch (continue): umin=500, umax=500 (constant!)          |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Important Observations:                                                 |
|  +--------------------------------------------------------------------+  |
|  | 1. == and != have symmetric true/false branches                    |  |
|  | 2. Equality can tighten range to a constant                        |  |
|  | 3. "Exclude" effect cannot be represented with continuous range    |  |
|  | 4. This is why Tnum supplements bounds tracking                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

---

## Exercise 5: State Pruning Judgment

## 练习5：状态剪枝判断

### Goal | 目标

Determine whether two states satisfy the pruning condition.

判断两个状态是否满足剪枝条件。

### Background | 背景知识

```
+-----------------------------------------------------------------------------------+
|                       State Pruning Rules                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Pruning condition: old state "subsumes" current state                   |
|                                                                                   |
|  +--------------------------------------------------------------------+  |
|  |                       Subsumption                                  |  |
|  |                                                                    |  |
|  |  old subsumes cur <=> all behaviors reachable from old             |  |
|  |                       are also reachable from cur                  |  |
|  |                                                                    |  |
|  |  Intuition:                                                        |  |
|  |  - If old has wider range, cur's execution is subset of old's     |  |
|  |  - If old already verified, cur will also pass                     |  |
|  |                                                                    |  |
|  |         old: [0------------------100]                              |  |
|  |         cur:       [20-------80]                                   |  |
|  |                    ^ cur c old, can prune                          |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Specific Rules:                                                         |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |  1. Scalar type: old.range >= cur.range                            |  |
|  |     - old.umin <= cur.umin                                         |  |
|  |     - old.umax >= cur.umax                                         |  |
|  |     - old.smin <= cur.smin                                         |  |
|  |     - old.smax >= cur.smax                                         |  |
|  |                                                                    |  |
|  |  2. Pointer type: must match exactly                               |  |
|  |     - Same type                                                    |  |
|  |     - Same offset                                                  |  |
|  |     - Same id (if applicable)                                      |  |
|  |                                                                    |  |
|  |  3. NOT_INIT: can match any type                                   |  |
|  |     - old = NOT_INIT means "don't care about this register"        |  |
|  |     - Can match any state for cur                                  |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Exercise | 练习

Determine if pruning is possible (does old subsume cur):

判断以下情况是否可以剪枝 (old 是否覆盖 cur)：

```
Case 1:
  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)
  cur: r0=[20, 80], r1=PTR_TO_STACK(off=0)

Case 2:
  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)
  cur: r0=[50, 150], r1=PTR_TO_STACK(off=0)

Case 3:
  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)
  cur: r0=[0, 100], r1=PTR_TO_STACK(off=-8)

Case 4:
  old: r0=NOT_INIT, r1=PTR_TO_CTX
  cur: r0=SCALAR[0,0], r1=PTR_TO_CTX
```

<details>
<summary>Click to see answer | 点击查看答案</summary>

```
+-----------------------------------------------------------------------------------+
|                      State Pruning Answers                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Case 1: YES - Can prune                                                 |
|  +--------------------------------------------------------------------+  |
|  |  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)                          |  |
|  |  cur: r0=[20, 80], r1=PTR_TO_STACK(off=0)                          |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - r0: [20, 80] c [0, 100]  YES                                    |  |
|  |        old.umin(0) <= cur.umin(20)  YES                            |  |
|  |        old.umax(100) >= cur.umax(80)  YES                          |  |
|  |  - r1: PTR_TO_STACK(off=0) == PTR_TO_STACK(off=0)  YES             |  |
|  |                                                                    |  |
|  |  Conclusion: old subsumes cur, safe to prune                       |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Case 2: NO - Cannot prune                                               |
|  +--------------------------------------------------------------------+  |
|  |  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)                          |  |
|  |  cur: r0=[50, 150], r1=PTR_TO_STACK(off=0)                         |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - r0: [50, 150] NOT c [0, 100]  NO                                |  |
|  |        old.umax(100) < cur.umax(150)  NO                           |  |
|  |                                                                    |  |
|  |        [0------------100]      old                                 |  |
|  |              [50-----------150]  cur                               |  |
|  |                        ^ cur exceeds old                           |  |
|  |                                                                    |  |
|  |  Conclusion: cur contains values not verified in old               |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Case 3: NO - Cannot prune                                               |
|  +--------------------------------------------------------------------+  |
|  |  old: r0=[0, 100], r1=PTR_TO_STACK(off=0)                          |  |
|  |  cur: r0=[0, 100], r1=PTR_TO_STACK(off=-8)                         |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - r0: [0, 100] == [0, 100]  YES                                   |  |
|  |  - r1: PTR_TO_STACK(off=0) != PTR_TO_STACK(off=-8)  NO             |  |
|  |        Pointer offsets differ!                                     |  |
|  |                                                                    |  |
|  |        Stack:                                                      |  |
|  |        +----------+ off=0   <- old.r1 points here                  |  |
|  |        |          |                                                |  |
|  |        +----------+ off=-8  <- cur.r1 points here                  |  |
|  |        +----------+                                                |  |
|  |                                                                    |  |
|  |  Conclusion: Pointers point to different locations                 |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Case 4: YES - Can prune                                                 |
|  +--------------------------------------------------------------------+  |
|  |  old: r0=NOT_INIT, r1=PTR_TO_CTX                                   |  |
|  |  cur: r0=SCALAR[0,0], r1=PTR_TO_CTX                                |  |
|  |                                                                    |  |
|  |  Analysis:                                                         |  |
|  |  - r0: old = NOT_INIT  YES                                         |  |
|  |        NOT_INIT means "don't care about this register"             |  |
|  |        Can match any state for cur                                 |  |
|  |  - r1: PTR_TO_CTX == PTR_TO_CTX  YES                               |  |
|  |                                                                    |  |
|  |  Conclusion: old doesn't use r0, so cur's r0 doesn't matter        |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

---

## Exercise 6: Code Reading

## 练习6：代码阅读

### Goal | 目标

Read project code and understand implementation details.

阅读项目代码，理解实现细节。

### Exercise | 练习

Read the following files and answer the questions:

阅读以下文件，回答问题：

```
File paths:
- crates/bpf-verifier-core/src/bounds/tnum.rs
- crates/bpf-verifier-core/src/state/reg_state.rs
```

**Question 1**: Find the `Tnum::add` method in `tnum.rs`. Explain the purpose
of the `chi` variable.

**Question 2**: Find the `Tnum::is_const` method in `tnum.rs`. Explain its
implementation principle.

**Question 3**: Find the `BpfRegState` structure in `reg_state.rs`. List all
fields that track value ranges.

**Question 4**: Explain the purpose of the `id` field in `BpfRegState`.

<details>
<summary>Click to see reference answer | 点击查看参考答案</summary>

```
+-----------------------------------------------------------------------------------+
|                       Code Reading Answers                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Question 1: Purpose of chi variable                                     |
|  +--------------------------------------------------------------------+  |
|  |  In Tnum::add:                                                     |  |
|  |                                                                    |  |
|  |  let sv = self.value.wrapping_add(other.value);                    |  |
|  |  let sm = self.mask.wrapping_add(other.mask);                      |  |
|  |  let sigma = sv.wrapping_add(sm);                                  |  |
|  |  let chi = sigma ^ sv;  // <-- chi is here                         |  |
|  |  let mu = chi | self.mask | other.mask;                            |  |
|  |                                                                    |  |
|  |  chi meaning:                                                      |  |
|  |  - chi = (sv + sm) ^ sv                                            |  |
|  |  - When mask bits cause carry, sigma and sv differ at that bit     |  |
|  |  - Bits set to 1 in chi indicate "possible carry" positions        |  |
|  |  - These bits are uncertain and must be added to mask              |  |
|  |                                                                    |  |
|  |  Example:                                                          |  |
|  |  sv = 0x0F, sm = 0x01                                              |  |
|  |  sigma = 0x0F + 0x01 = 0x10                                        |  |
|  |  chi = 0x10 ^ 0x0F = 0x1F                                          |  |
|  |  Shows low 5 bits may be affected by carry                         |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Question 2: is_const implementation principle                           |
|  +--------------------------------------------------------------------+  |
|  |  pub fn is_const(&self) -> bool {                                  |  |
|  |      self.mask == 0                                                |  |
|  |  }                                                                 |  |
|  |                                                                    |  |
|  |  Principle:                                                        |  |
|  |  - Bits set to 1 in mask indicate uncertainty                      |  |
|  |  - If mask == 0, all bits are known                                |  |
|  |  - Then value is the definite constant value                       |  |
|  |                                                                    |  |
|  |  Example:                                                          |  |
|  |  Tnum { value: 5, mask: 0 } -> is_const() = true, value is 5       |  |
|  |  Tnum { value: 4, mask: 3 } -> is_const() = false, value is 4~7    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Question 3: Range tracking fields in BpfRegState                        |
|  +--------------------------------------------------------------------+  |
|  |  pub struct BpfRegState {                                          |  |
|  |      pub reg_type: BpfRegType,      // Register type               |  |
|  |      pub off: i32,                  // Pointer offset              |  |
|  |      pub id: u32,                   // Unique identifier           |  |
|  |                                                                    |  |
|  |      // Range tracking fields:                                     |  |
|  |      pub var_off: Tnum,             // Bit-level tracking          |  |
|  |      pub umin_value: u64,           // Unsigned minimum            |  |
|  |      pub umax_value: u64,           // Unsigned maximum            |  |
|  |      pub smin_value: i64,           // Signed minimum              |  |
|  |      pub smax_value: i64,           // Signed maximum              |  |
|  |                                                                    |  |
|  |      // Other fields...                                            |  |
|  |  }                                                                 |  |
|  |                                                                    |  |
|  |  These fields work together:                                       |  |
|  |  - umin/umax: unsigned range [umin, umax]                          |  |
|  |  - smin/smax: signed range [smin, smax]                            |  |
|  |  - var_off: bit-level precise tracking                             |  |
|  |  All three constrain each other for most precise range             |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Question 4: Purpose of id field                                         |
|  +--------------------------------------------------------------------+  |
|  |  The id field tracks the origin of pointers/values:                |  |
|  |                                                                    |  |
|  |  1. Pointer association tracking:                                  |  |
|  |     When two registers point to same resource, they share id       |  |
|  |     Example: after r1 = r2, r1.id == r2.id                         |  |
|  |                                                                    |  |
|  |  2. Reference counting:                                            |  |
|  |     Same id pointers can track resource references                 |  |
|  |     Ensures resource released only after all references gone       |  |
|  |                                                                    |  |
|  |  3. Helper function return value tracking:                         |  |
|  |     Pointers from helpers get new id                               |  |
|  |     Used to track pointer lifetime                                 |  |
|  |                                                                    |  |
|  |  4. Pointer comparison in conditional jumps:                       |  |
|  |     When r1 == r2 and r1.id == r2.id                               |  |
|  |     Verifier knows they point to same object                       |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

</details>

---

## Exercise 7: Simple Verification Implementation

## 练习7：编写简单验证器

### Goal | 目标

Implement a simplified instruction verifier to experience the core
verification logic.

实现一个简化的指令验证器，体验验证器的核心逻辑。

### Exercise | 练习

Complete the following code framework:

完成以下代码框架：

```rust
/// Simplified register state
#[derive(Clone, Debug)]
struct SimpleRegState {
    is_init: bool,      // Whether initialized
    min_value: i64,     // Minimum value
    max_value: i64,     // Maximum value
}

impl Default for SimpleRegState {
    fn default() -> Self {
        Self {
            is_init: false,
            min_value: 0,
            max_value: 0,
        }
    }
}

/// Simplified verifier
struct SimpleVerifier {
    regs: [SimpleRegState; 11],  // R0-R10
}

impl SimpleVerifier {
    /// Create new verifier instance
    fn new() -> Self {
        // TODO: Initialize all registers as uninitialized
        todo!()
    }
    
    /// Simulate immediate assignment: r_dst = imm
    fn mov_imm(&mut self, dst: usize, imm: i64) {
        // TODO: Implement immediate assignment
        todo!()
    }
    
    /// Simulate register addition: r_dst = r_dst + r_src
    fn add_reg(&mut self, dst: usize, src: usize) -> Result<(), &'static str> {
        // TODO: Implement register addition
        // Note: Return error if source or destination is uninitialized
        todo!()
    }
    
    /// Simulate bounds refinement after conditional jump: if r_reg > imm
    /// Returns (true_branch_state, false_branch_state)
    fn jgt_imm(&self, reg: usize, imm: i64) 
        -> Result<(SimpleRegState, SimpleRegState), &'static str> 
    {
        // TODO: Implement bounds refinement after conditional jump
        todo!()
    }
    
    /// Check if register is within the specified range
    fn check_bounds(&self, reg: usize, min: i64, max: i64) -> bool {
        // TODO: Check if register's range is entirely within [min, max]
        todo!()
    }
}
```

<details>
<summary>Click to see reference implementation | 点击查看参考实现</summary>

```rust
impl SimpleVerifier {
    fn new() -> Self {
        Self {
            regs: std::array::from_fn(|_| SimpleRegState::default()),
        }
    }
    
    fn mov_imm(&mut self, dst: usize, imm: i64) {
        self.regs[dst] = SimpleRegState {
            is_init: true,
            min_value: imm,
            max_value: imm,
        };
    }
    
    fn add_reg(&mut self, dst: usize, src: usize) -> Result<(), &'static str> {
        // Check if registers are initialized
        if !self.regs[dst].is_init {
            return Err("destination register not initialized");
        }
        if !self.regs[src].is_init {
            return Err("source register not initialized");
        }
        
        // Range addition (simplified, no overflow handling)
        self.regs[dst].min_value = self.regs[dst].min_value
            .saturating_add(self.regs[src].min_value);
        self.regs[dst].max_value = self.regs[dst].max_value
            .saturating_add(self.regs[src].max_value);
        
        Ok(())
    }
    
    fn jgt_imm(&self, reg: usize, imm: i64) 
        -> Result<(SimpleRegState, SimpleRegState), &'static str> 
    {
        if !self.regs[reg].is_init {
            return Err("register not initialized");
        }
        
        let r = &self.regs[reg];
        
        // True branch: r > imm, so min = max(r.min, imm+1)
        let true_branch = SimpleRegState {
            is_init: true,
            min_value: r.min_value.max(imm.saturating_add(1)),
            max_value: r.max_value,
        };
        
        // False branch: r <= imm, so max = min(r.max, imm)
        let false_branch = SimpleRegState {
            is_init: true,
            min_value: r.min_value,
            max_value: r.max_value.min(imm),
        };
        
        Ok((true_branch, false_branch))
    }
    
    fn check_bounds(&self, reg: usize, min: i64, max: i64) -> bool {
        let r = &self.regs[reg];
        r.is_init && r.min_value >= min && r.max_value <= max
    }
}

// Test code
fn test_simple_verifier() {
    let mut v = SimpleVerifier::new();
    
    // r0 = 10
    v.mov_imm(0, 10);
    assert!(v.check_bounds(0, 10, 10));
    
    // r1 = 20
    v.mov_imm(1, 20);
    assert!(v.check_bounds(1, 20, 20));
    
    // r0 = r0 + r1
    v.add_reg(0, 1).unwrap();
    assert!(v.check_bounds(0, 30, 30));
    
    // r2 not initialized, should fail
    assert!(v.add_reg(0, 2).is_err());
    
    // Test conditional jump
    v.mov_imm(3, 0);
    v.regs[3].max_value = 100; // Simulate range [0, 100]
    
    let (true_br, false_br) = v.jgt_imm(3, 50).unwrap();
    assert_eq!(true_br.min_value, 51);
    assert_eq!(true_br.max_value, 100);
    assert_eq!(false_br.min_value, 0);
    assert_eq!(false_br.max_value, 50);
    
    println!("All tests passed!");
}
```

</details>

### Extended Exercises | 扩展练习

Try extending the verifier with these features:

1. **More ALU operations**: Implement `sub_reg`, `mul_imm`, `and_imm`
2. **Memory access check**: Implement stack bounds checking
3. **More jump types**: Implement `jge_imm`, `jeq_imm`

---

## Exercise 8: Debugging Real Programs

## 练习8：调试真实程序

### Goal | 目标

Use the project's verifier to analyze real BPF programs.

使用项目的验证器分析真实的 BPF 程序。

### Steps | 步骤

```
+-----------------------------------------------------------------------------------+
|                         Debugging Steps                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Build the project                                                    |
|  +--------------------------------------------------------------------+  |
|  |  $ cd /path/to/verifier-rs                                         |  |
|  |  $ cargo build                                                     |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  2. Run tests to see verification output                                 |
|  +--------------------------------------------------------------------+  |
|  |  $ cargo test -- --nocapture                                       |  |
|  |                                                                    |  |
|  |  This shows detailed verification logs including:                  |  |
|  |  - Step-by-step instruction verification                          |  |
|  |  - Register state changes                                         |  |
|  |  - Error messages and locations                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  3. Observe verification logs to understand:                             |
|  +--------------------------------------------------------------------+  |
|  |  - How instructions are verified step by step                      |  |
|  |  - How state changes                                               |  |
|  |  - What conditions trigger errors                                  |  |
|  |  - When state pruning occurs                                       |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  4. Try modifying test cases                                             |
|  +--------------------------------------------------------------------+  |
|  |  Find test files:                                                  |  |
|  |  crates/bpf-verifier-core/src/core/insn_verify.rs                  |  |
|  |                                                                    |  |
|  |  Modify or add test cases to observe verifier behavior             |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Log Interpretation Example | 日志解读示例

```
+-----------------------------------------------------------------------------------+
|                       Log Example                                        |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Assuming verification of:                                               |
|  +--------------------------------------------------------------------+  |
|  |  0: r1 = *(u32*)(r1 + 0)                                           |  |
|  |  1: if r1 > 100 goto 3                                             |  |
|  |  2: r0 = 0                                                         |  |
|  |  3: exit                                                           |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Possible log output:                                                    |
|  +--------------------------------------------------------------------+  |
|  |  [INFO] === Verifying instruction 0 ===                            |  |
|  |  [DEBUG] r1 = PTR_TO_CTX                                           |  |
|  |  [DEBUG] Loading u32 from CTX+0                                    |  |
|  |  [INFO] r1: PTR_TO_CTX -> SCALAR [0, 4294967295]                   |  |
|  |                                                                    |  |
|  |  [INFO] === Verifying instruction 1 ===                            |  |
|  |  [DEBUG] Conditional jump: r1 > 100                                |  |
|  |  [INFO] Pushing state for fallthrough (insn 2)                     |  |
|  |  [DEBUG]   r1 refined to [0, 100]                                  |  |
|  |  [INFO] Jumping to instruction 3                                   |  |
|  |  [DEBUG]   r1 refined to [101, 4294967295]                         |  |
|  |                                                                    |  |
|  |  [INFO] === Verifying instruction 3 (from jump) ===                |  |
|  |  [DEBUG] Exit instruction                                          |  |
|  |  [WARN] R0 not initialized at exit!                                |  |
|  |  [ERROR] Verification failed: R0 must be initialized before exit   |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  This log tells us:                                                      |
|  - Program loads data from CTX into r1                                   |
|  - Conditional jump splits path into two                                 |
|  - When r1 > 100, jumps directly to exit                                 |
|  - But r0 is not initialized, verification fails                         |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## Advanced Challenges

## 进阶挑战

### Challenge 1: Add a New Helper Function

### 挑战1：添加新的辅助函数

```
+-----------------------------------------------------------------------------------+
|                 Challenge 1: Add a New Helper Function                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Task: Add support for a new helper function to the verifier             |
|                                                                                   |
|  Function signature:                                                     |
|  +--------------------------------------------------------------------+  |
|  |  u64 my_helper(void *ptr, u32 len)                                 |  |
|  |                                                                    |  |
|  |  Parameters:                                                       |  |
|  |  - ptr: pointer to buffer                                          |  |
|  |  - len: buffer length (1-4096)                                     |  |
|  |                                                                    |  |
|  |  Return value:                                                     |  |
|  |  - Success: 0                                                      |  |
|  |  - Failure: negative error code                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Steps:                                                                  |
|  +--------------------------------------------------------------------+  |
|  |  1. Add function definition to HelperProvider trait                |  |
|  |  2. Define parameter type constraints (ptr must be valid pointer)  |  |
|  |  3. Define length constraints (len must be in [1, 4096])           |  |
|  |  4. Define return type (SCALAR, range includes 0 and negatives)    |  |
|  |  5. Write test cases to verify implementation                      |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Hints:                                                                  |
|  +--------------------------------------------------------------------+  |
|  |  Reference existing helper implementations:                        |  |
|  |  crates/bpf-verifier-linux/src/special/helpers.rs                  |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Challenge 2: Implement Simple Loop Detection

### 挑战2：实现简单的循环检测

```
+-----------------------------------------------------------------------------------+
|               Challenge 2: Implement Simple Loop Detection               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Task: Implement a detector that identifies potentially infinite loops   |
|                                                                                   |
|  Algorithm idea:                                                         |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |  1. Build Control Flow Graph (CFG)                                 |  |
|  |     +------------------------------------------------------------+ |  |
|  |     |  Traverse all instructions, record:                        | |  |
|  |     |  - Sequential execution edges                              | |  |
|  |     |  - Jump edges (both branches for conditional)              | |  |
|  |     +------------------------------------------------------------+ |  |
|  |                                                                    |  |
|  |  2. Detect Back Edges                                              |  |
|  |     +------------------------------------------------------------+ |  |
|  |     |  Back edge = edge from high address to low address         | |  |
|  |     |  Presence of back edge means possible loop                 | |  |
|  |     +------------------------------------------------------------+ |  |
|  |                                                                    |  |
|  |  3. Analyze Loop Termination Condition                             |  |
|  |     +------------------------------------------------------------+ |  |
|  |     |  Check if loop body has:                                   | |  |
|  |     |  - Loop variable increment/decrement                       | |  |
|  |     |  - Comparison with bounds                                  | |  |
|  |     |  - Conditional jump that may terminate loop                | |  |
|  |     +------------------------------------------------------------+ |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Reference code:                                                         |
|  +--------------------------------------------------------------------+  |
|  |  crates/bpf-verifier-core/src/analysis/loop_check.rs               |  |
|  |  crates/bpf-verifier-core/src/analysis/cfg.rs                      |  |
|  |  crates/bpf-verifier-core/src/analysis/scc.rs                      |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Challenge 3: Optimize Pruning Strategy

### 挑战3：优化剪枝策略

```
+-----------------------------------------------------------------------------------+
|              Challenge 3: Optimize Pruning Strategy                      |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Task: Analyze current pruning implementation and propose improvements   |
|                                                                                   |
|  Analysis directions:                                                    |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |  1. Precision vs Performance tradeoff                              |  |
|  |     - Is current pruning too conservative?                         |  |
|  |     - Can we be more aggressive while maintaining safety?          |  |
|  |                                                                    |  |
|  |  2. State caching strategy                                         |  |
|  |     - How many states to cache?                                    |  |
|  |     - How to select states to keep?                                |  |
|  |     - LRU? Widest range? Other strategies?                         |  |
|  |                                                                    |  |
|  |  3. State merging                                                  |  |
|  |     - Can we merge similar states?                                 |  |
|  |     - How much precision loss from merging?                        |  |
|  |                                                                    |  |
|  |  4. Precision tracking optimization                                |  |
|  |     - Is current precision tracking necessary?                     |  |
|  |     - Which cases can be simplified?                               |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Experiment methodology:                                                 |
|  +--------------------------------------------------------------------+  |
|  |  1. Collect benchmark programs                                     |  |
|  |  2. Measure current implementation:                                |  |
|  |     - Verification time                                            |  |
|  |     - States explored                                              |  |
|  |     - Memory usage                                                 |  |
|  |  3. Implement improvements                                         |  |
|  |  4. Compare before/after data                                      |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Reference code:                                                         |
|  +--------------------------------------------------------------------+  |
|  |  crates/bpf-verifier-core/src/analysis/states_equal.rs             |  |
|  |  crates/bpf-verifier-core/src/analysis/state_merge.rs              |  |
|  |  crates/bpf-verifier-core/src/analysis/precision.rs                |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## Summary | 总结

```
+-----------------------------------------------------------------------------------+
|                       Learning Outcomes                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Through these exercises, you should be able to:                         |
|                                                                                   |
|  +--------------------------------------------------------------------+  |
|  |                                                                    |  |
|  |  [x] Manually decode BPF instructions                              |  |
|  |                                                                    |  |
|  |  [x] Track register state changes                                  |  |
|  |                                                                    |  |
|  |  [x] Understand Tnum bit-level tracking                            |  |
|  |                                                                    |  |
|  |  [x] Apply bounds refinement rules                                 |  |
|  |                                                                    |  |
|  |  [x] Determine state pruning conditions                            |  |
|  |                                                                    |  |
|  |  [x] Read and understand project code                              |  |
|  |                                                                    |  |
|  |  [x] Implement simple verification logic                           |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## Further Learning | 继续学习

```
+-----------------------------------------------------------------------------------+
|                    Further Learning Resources                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Official Resources:                                                     |
|  +--------------------------------------------------------------------+  |
|  |  - Linux kernel BPF verifier source code                           |  |
|  |    kernel/bpf/verifier.c                                           |  |
|  |                                                                    |  |
|  |  - BPF and XDP official documentation                              |  |
|  |    https://docs.kernel.org/bpf/                                    |  |
|  |                                                                    |  |
|  |  - eBPF official website                                           |  |
|  |    https://ebpf.io/                                                |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Development Tools:                                                      |
|  +--------------------------------------------------------------------+  |
|  |  - libbpf - C BPF development library                              |  |
|  |  - bcc - BPF Compiler Collection                                   |  |
|  |  - bpftrace - High-level BPF tracing language                      |  |
|  |  - aya - Rust BPF development framework                            |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
|  Advanced Topics:                                                        |
|  +--------------------------------------------------------------------+  |
|  |  - BPF JIT Compiler                                                |  |
|  |    Understand how BPF bytecode is compiled to native machine code  |  |
|  |                                                                    |  |
|  |  - BPF CO-RE (Compile Once, Run Everywhere)                        |  |
|  |    Cross-kernel version compatibility technology                   |  |
|  |                                                                    |  |
|  |  - BTF (BPF Type Format)                                           |  |
|  |    BPF type information format                                     |  |
|  |                                                                    |  |
|  |  - BPF Security Research                                           |  |
|  |    Verifier vulnerability analysis and protection                  |  |
|  +--------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

[Previous: Platform Abstraction](09-platform-abstraction.md) |
[Back to Table of Contents](00-introduction.md)

---

```
+-----------------------------------------------------------------------------------+
|                                                                                   |
|          Congratulations on Completing the Tutorial!                     |
|                                                                                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|    You have completed the BPF Verifier project tutorial. You should      |
|    now have a deep understanding of the project's overall architecture,  |
|    core concepts, and implementation details.                            |
|                                                                                   |
|    +----------------------------------------------------------------+    |
|    |                                                                |    |
|    |    Continue exploring the code, and happy coding!              |    |
|    |                                                                |    |
|    +----------------------------------------------------------------+    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```
