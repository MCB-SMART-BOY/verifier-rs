Subject: [RFC] Rust implementation of BPF verifier for Rust for Linux

To: rust-for-linux@vger.kernel.org
Cc: bpf@vger.kernel.org
Cc: Alexei Starovoitov <ast@kernel.org>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Andrii Nakryiko <andrii@kernel.org>

Hi everyone,

I would like to propose a Rust implementation of the BPF verifier for
potential inclusion in Rust for Linux. This RFC aims to gather feedback
on the design, approach, and interest from the community before
proceeding with formal patch submission.

== Motivation ==

The BPF verifier (kernel/bpf/verifier.c) is one of the most complex
subsystems in the Linux kernel, comprising approximately 30,000 lines
of intricate C code. It performs static analysis on BPF programs to
ensure memory safety, control flow safety, and resource management
before programs are loaded into the kernel.

A Rust implementation could provide several benefits:

1. **Compile-time safety guarantees**: Rust's ownership system can
   catch many classes of bugs at compile time that would be runtime
   errors in C.

2. **Type-safe state tracking**: Register states, bounds tracking,
   and reference counting can be modeled more precisely using Rust's
   type system.

3. **Reduced undefined behavior**: Rust's strict aliasing rules and
   bounds checking reduce the attack surface.

4. **Better maintainability**: Pattern matching, enums, and traits
   make complex state machines more readable and maintainable.

== Implementation Status ==

The implementation is feature-complete and includes:

  Component                    | Lines of Code | Description
  -----------------------------|---------------|---------------------------
  Core types & instructions    | ~5,000        | BPF instruction set, types
  Register/stack state         | ~8,000        | State tracking
  Bounds analysis (Tnum)       | ~4,000        | Scalar bounds tracking
  Control flow analysis        | ~10,000       | CFG, SCC, pruning, loops
  Instruction verification     | ~12,000       | ALU, jumps, helpers, kfuncs
  Memory access verification   | ~8,000        | Stack, packet, context, arena
  Special objects              | ~6,000        | Dynptr, iterators, exceptions
  BTF support                  | ~5,000        | Type format integration
  Spectre mitigation           | ~3,000        | Speculation safety
  Optimization passes          | ~7,000        | Dead code, fixups
  Main verifier loop           | ~10,000       | Verification engine
  -----------------------------|---------------|---------------------------
  Total                        | ~78,000       | (includes tests & docs)

Key features implemented:
  - Full register state tracking (R0-R10 + frame pointer)
  - Tnum (tracked number) arithmetic for precise bounds
  - 211 BPF helper function signatures
  - 85 kernel function (kfunc) definitions
  - State pruning with hash-indexed equivalence checking
  - Reference tracking (locks, RCU, acquired references)
  - IRQ flag state tracking
  - All memory region types (stack, packet, context, map, arena)
  - Spectre v1/v4 mitigation checks

Technical characteristics:
  - #![no_std] compatible
  - Uses only `alloc` crate (Vec, Box, BTreeMap, BTreeSet)
  - GPL-2.0-only license
  - SPDX identifiers on all files
  - 300+ unit tests

== Design Decisions ==

1. **Standalone implementation**: This is a clean-room Rust
   implementation, not a line-by-line translation of the C code.
   The algorithms are equivalent but the code structure leverages
   Rust idioms.

2. **State representation**: Register states use Rust enums for
   type safety:

   ```rust
   pub enum BpfRegType {
       NotInit,
       ScalarValue,
       PtrToCtx,
       PtrToMap(MapUid),
       PtrToStack(StackOffset),
       PtrToPacket,
       PtrToPacketEnd,
       // ... 30+ pointer types
   }
   ```

3. **Bounds tracking**: Uses the same Tnum algorithm as the C
   verifier but with Rust's checked arithmetic:

   ```rust
   pub struct Tnum {
       pub value: u64,  // Known bits
       pub mask: u64,   // Unknown bits
   }
   ```

4. **Error handling**: Uses Result<T, VerifierError> throughout,
   with detailed error variants matching kernel error codes.

== Integration Approach ==

I propose a phased integration:

Phase 1: Review and feedback (this RFC)
  - Gather community input on design
  - Identify any architectural concerns
  - Discuss coexistence with C verifier

Phase 2: Kernel integration layer
  - Add bindings to kernel BPF infrastructure
  - Implement kernel memory allocator integration
  - Create Kconfig options for Rust verifier

Phase 3: Testing and validation
  - Port kernel BPF selftests to test Rust verifier
  - Performance benchmarking against C verifier
  - Fuzzing with syzkaller BPF programs

Phase 4: Gradual adoption
  - Initially as CONFIG_BPF_VERIFIER_RUST=n default
  - Allow runtime selection between C and Rust
  - Eventually consider as primary verifier

== Questions for the Community ==

1. **Interest level**: Is there interest in a Rust BPF verifier
   for the kernel? The BPF maintainers' input is crucial here.

2. **Coexistence strategy**: Should the Rust verifier:
   a) Replace the C verifier entirely (long-term)?
   b) Coexist as an alternative (selectable at build/runtime)?
   c) Be used only for specific use cases?

3. **Integration depth**: Should this be:
   a) A complete replacement of verifier.c?
   b) A separate verification pass (double-checking)?
   c) Specific subsystem replacement (e.g., just bounds checking)?

4. **Performance requirements**: What performance benchmarks
   would be required to demonstrate acceptability?

5. **Testing requirements**: Beyond the existing tests, what
   additional validation would be needed?

== Repository ==

The code is available at:
  https://github.com/MCB-SMART-BOY/verifier-rs

I welcome any feedback, questions, or concerns about this proposal.

Best regards,
MCB-SMART-BOY
mcb2720838051@gmail.com
