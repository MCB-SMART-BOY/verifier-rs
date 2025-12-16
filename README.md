# Rust BPF Verifier

A Rust implementation of the Linux kernel BPF verifier (`kernel/bpf/verifier.c`), designed for Rust for Linux (Linux 6.12+).

## Overview

This crate provides static code analysis for eBPF programs, ensuring they are safe before being loaded into the kernel. It is a `#![no_std]` library that can be integrated into the Linux kernel as a Rust-based BPF verifier.

**Status**: RFC submitted to rust-for-linux@vger.kernel.org

## Features

### Core Verification
- **Register State Tracking**: Complete 11-register state with type and bounds tracking
- **Memory Safety**: Validates all memory accesses (stack, map, packet, context, arena)
- **Control Flow Analysis**: Explores all possible execution paths
- **Reference Tracking**: Ensures acquired resources (locks, refs, RCU) are properly released
- **Bounds Analysis**: Uses Tnum (tracked numbers) for precise numeric bounds

### Advanced Features
- **State Pruning**: Hash-indexed equivalence checking for performance
- **211 Helper Functions**: Complete BPF helper function validation
- **85+ Kfuncs**: Kernel function call verification (synced with kernel 6.12)
- **BTF Integration**: Full BTF type system support
- **Spectre Mitigation**: Speculative execution safety checks
- **IRQ Flag Tracking**: Interrupt state verification

## Project Structure

```
src/
├── core/       - Core types, instruction definitions, error handling
├── state/      - Register/stack/verifier state
├── bounds/     - Tnum arithmetic, scalar bounds
├── analysis/   - CFG, SCC, precision tracking, state pruning
├── check/      - ALU, jump, helper, kfunc verification
├── mem/        - Memory access verification
├── special/    - Dynptr, iterator, exception handling
├── btf/        - BTF type system
├── sanitize/   - Spectre mitigation
├── opt/        - Optimization passes
└── verifier/   - Main verification loop

kernel-integration/
├── rust_bpf_verifier.rs  - Pure Rust kernel module (Linux 6.12+ style)
├── Kconfig               - Kernel configuration options
└── Makefile              - Build configuration

patches/                  - Kernel integration patches
scripts/                  - Helper scripts for development
benches/                  - Criterion benchmarks
```

## Build

```bash
# Build the library
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Benchmark Results

Preliminary benchmark results on typical hardware:

| Benchmark | Time |
|-----------|------|
| simple_verification | ~14.6 µs |
| medium_verification | ~28.7 µs |
| complex_verification | ~736 µs |
| state_creation | ~406 ns |
| bounds_operations | ~5.8 ns |

## Kernel Integration (Linux 6.12+)

This library is designed for integration with Rust for Linux. The implementation uses pure Rust with no C glue code, following the modern kernel::Module pattern:

```rust
use kernel::prelude::*;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    license: "GPL",
}

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        Ok(Self { })
    }
}
```

### Configuration

```
CONFIG_BPF_VERIFIER_RUST=y
echo 1 > /proc/sys/kernel/bpf_rust_verifier
```

## Requirements

- Rust (stable)
- `#![no_std]` environment
- `alloc` crate (for Vec, Box, etc.)
- `bitflags` crate

## License

GPL-2.0-only (Linux kernel compatible)

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## References

- [Rust for Linux](https://rust-for-linux.com/)
- [Rust for Linux Documentation](https://docs.kernel.org/rust/)
- [Kernel Crate API](https://rust-for-linux.github.io/docs/kernel/)
- [Linux kernel BPF verifier](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)

## Author

MCB-SMART-BOY - A sophomore student passionate about BPF and Rust.

This project was created out of curiosity and a desire to learn. Feedback and suggestions are always appreciated.
