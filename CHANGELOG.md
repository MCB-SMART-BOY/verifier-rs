# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Performance Optimization

#### Call Summary Caching (Linux 6.13+)
- **Call Summary Optimization** ([src/opt/call_summary.rs](src/opt/call_summary.rs))
  - Caches verification results for repeated function calls with identical states
  - Reduces verification time for programs with many subprogram calls
  - LRU-based cache eviction (max 16 summaries per subprogram)
  - Statistics tracking (hit rate, cache performance metrics)
  - Functions: `try_apply_call_summary()`, `record_call_summary()`
  - New types: `CallSummary`, `CallSummaryCache`, `CallSummaryManager`

#### Helper Function Verification
- Verified all 211 BPF helper functions are defined
- Added helper verification script ([scripts/verify_helpers.sh](scripts/verify_helpers.sh))
- Renamed `CallSummary` to `FuncCallPattern` in misc_fixups.rs to avoid naming conflict

### Added - Linux 6.13-6.18 Features

#### Core Verification Features
- **Load-Acquire/Store-Release Instructions** ([src/check/atomic.rs](src/check/atomic.rs))
  - Added atomic memory barrier instruction support
  - Implemented `BPF_LOAD_ACQ` and `BPF_STORE_REL` opcodes
  - Added validation for memory ordering semantics
  - Functions: `check_load_acquire()`, `check_store_release()`, `is_load_acquire()`, `is_store_release()`

- **may_goto Bounded Loops** ([src/check/jump.rs](src/check/jump.rs))
  - Added support for bounded loop construct via `BPF_JCOND` with `BPF_MAY_GOTO` flag
  - Implemented iteration limit enforcement (default 8192, max 8192)
  - Added backward jump validation for loop structures
  - Functions: `check_may_goto()`, `validate_may_goto_loop()`
  - Constant: `MAX_MAY_GOTO_ITERATIONS = 8192`

- **Linked Registers** ([src/state/reg_state.rs](src/state/reg_state.rs))
  - Enhanced precision tracking for register relationships
  - Added `BPF_ADD_CONST` flag (bit 31) to mark linked registers
  - Implemented constant delta tracking between related registers
  - New struct: `LinkedRegs` for tracking register sets
  - Functions: `is_linked()`, `base_id()`, `mark_linked()`, `linked_delta()`, `linked_to_same_base()`

#### Subprogram and Optimization Features
- **Private Stack** ([src/check/subprog.rs](src/check/subprog.rs))
  - Per-subprogram isolated stack implementation
  - 64-byte minimum threshold (`BPF_PRIV_STACK_MIN_SIZE`)
  - Adaptive mode selection based on stack depth
  - New enum: `PrivStackMode` (NoPrivStack, Unknown, Adaptive)
  - Functions: `determine_priv_stack_mode()`, `get_stack_depths()`, `round_stack_size()`
  - Incompatible with tail calls and main subprogram

- **Fastcall Optimization** ([src/check/helper.rs](src/check/helper.rs))
  - Reduced overhead calling convention for frequently-used helpers
  - Support for 7 high-frequency helper functions:
    - `bpf_map_lookup_elem`
    - `bpf_map_update_elem`
    - `bpf_map_delete_elem`
    - `bpf_get_prandom_u32`
    - `bpf_get_smp_processor_id`
    - `bpf_ktime_get_ns`
    - `bpf_ktime_get_boot_ns`
  - 8-byte stack alignment contract enforcement
  - Optimization levels: 0 (none), 1 (basic), 2 (advanced for XDP/tc)
  - Functions: `is_fastcall_helper()`, `check_fastcall_stack_contract()`, `get_fastcall_opt_level()`

#### Type System Features
- **BPF Features Flags** ([src/core/types.rs](src/core/types.rs))
  - Runtime feature toggle system using bitflags
  - Current features:
    - `RDONLY_CAST_TO_VOID`: Support readonly cast to void
    - `STREAMS`: Streams support (Linux 6.13)
  - Functions: `all()`, `has_feature()`

- **Extended Dynptr Types** ([src/special/dynptr.rs](src/special/dynptr.rs))
  - Added `BpfDynptrType::SkbMeta` for SKB metadata access
  - Added `BpfDynptrType::File` for file-backed dynamic pointers
  - Updated all match statements to handle new types
  - Enhanced slice operation support for SKB/XDP/SkbMeta/File types

#### Error Handling
- **New Error Types** ([src/core/error.rs](src/core/error.rs))
  - `VerifierError::TooManyLinkedRegisters`: Linked register overflow
  - `VerifierError::InvalidValue(String)`: Generic value validation errors
  - `VerifierError::ProgramTooComplex`: Complexity threshold exceeded

### Changed

- **Kernel Compatibility**: Updated from Linux 6.12+ to **Linux 6.18+**
- **Feature Parity**: Improved from 90% to **94%** feature parity with upstream kernel verifier
- **README**: Updated documentation to reflect new features and compatibility
  - Added Linux 6.13-6.18 Features section in both English and Chinese
  - Updated status to show RFC submission
  - Updated compatibility version information

### Project Status

- **Status**: RFC submitted to rust-for-linux@vger.kernel.org
- **Compatibility**: Linux 6.18+ (kernel 6.13-6.18 features)
- **Feature Parity**: 94% with upstream Linux kernel verifier
- **Helper Functions**: 211 complete
- **Kfuncs**: 85+ verified (synced with kernel 6.18)

## [0.1.0] - 2024

### Added

#### Core Verification
- Register state tracking (11 registers with type and bounds)
- Memory safety validation (stack, map, packet, context, arena)
- Control flow analysis (all execution paths)
- Reference tracking (locks, refs, RCU)
- Bounds analysis using Tnum (tracked numbers)

#### Advanced Features
- State pruning with hash-indexed equivalence checking
- 211 BPF helper function validation
- 85+ Kfunc verification
- BTF integration (full type system support)
- Spectre mitigation (speculative execution safety)
- IRQ flag tracking

#### Infrastructure
- `#![no_std]` library design
- Kernel module integration support
- Criterion benchmarks
- Comprehensive test suite

#### Modules
- `core/`: Core types, instruction definitions, error handling
- `state/`: Register/stack/verifier state
- `bounds/`: Tnum arithmetic, scalar bounds
- `analysis/`: CFG, SCC, precision tracking, state pruning
- `check/`: ALU, jump, helper, kfunc verification
- `mem/`: Memory access verification
- `special/`: Dynptr, iterator, exception handling
- `btf/`: BTF type system
- `sanitize/`: Spectre mitigation
- `opt/`: Optimization passes
- `verifier/`: Main verification loop

### License

GPL-2.0-only (Linux kernel compatible)

---

**Author**: MCB-SMART-BOY <mcb2720838051@gmail.com>

**Repository**: https://github.com/MCB-SMART-BOY/verifier-rs
