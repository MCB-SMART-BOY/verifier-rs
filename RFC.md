# RFC: Rust Implementation of BPF Verifier

> **To:** rust-for-linux@vger.kernel.org  
> **Cc:** bpf@vger.kernel.org, Alexei Starovoitov, Daniel Borkmann, Miguel Ojeda, Andrii Nakryiko

## Summary

With Rust now officially adopted as a core language in the Linux kernel (2025 Kernel Maintainer Summit), this RFC proposes a Rust implementation of the BPF verifier.

## Motivation

The BPF verifier (`kernel/bpf/verifier.c`) is ~30,000 lines of complex C code. A Rust implementation provides:

| Benefit | Description |
|---------|-------------|
| **Compile-time safety** | Ownership model catches memory bugs at compile time |
| **Type-safe state tracking** | Strong types for register states and bounds |
| **Reduced attack surface** | Strict aliasing rules reduce vulnerabilities |
| **Maintainability** | Pattern matching makes state machines readable |

## Implementation Status

**~78,000 lines** (including tests), feature-complete:

### Core Features
- Full register state tracking (R0-R10)
- Tnum arithmetic for precise bounds
- 211 BPF helper function signatures
- 85+ kfunc definitions (synced with 6.12)
- State pruning with hash-indexed equivalence
- Reference tracking (locks, RCU, acquired refs)
- IRQ flag state tracking

### Memory Verification
- Stack, packet, context, map, arena
- Spectre v1/v4 mitigation checks

### Technical
- `#![no_std]` compatible
- GPL-2.0-only license
- **Pure Rust** - no C glue code (Linux 6.12+ style)
- 300+ unit tests

## Integration Approach

Using native `kernel::Module` trait:

```rust
use kernel::prelude::*;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    license: "GPL",
}

struct RustBpfVerifier { /* state */ }

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        Ok(Self { })
    }
}
```

### Configuration

```bash
# Enable in kernel config
CONFIG_BPF_VERIFIER_RUST=y

# Runtime switch
echo 1 > /proc/sys/kernel/bpf_rust_verifier
```

## Proposed Phases

| Phase | Description |
|-------|-------------|
| **1. RFC** | Design review and feedback (this document) |
| **2. Abstractions** | Add kernel crate APIs for BPF |
| **3. Validation** | Selftests, benchmarks, security audit |
| **4. Adoption** | Initially disabled, runtime switchable |

## Questions for Community

1. With Rust now official, is there appetite for a Rust BPF verifier?

2. Should the Rust verifier:
   - a) Eventually replace C implementation?
   - b) Coexist as selectable alternative?
   - c) Handle specific verification passes only?

3. What kernel crate APIs need to be added for BPF?

4. What validation/benchmarks are required?

## Repository

**GitHub:** https://github.com/MCB-SMART-BOY/verifier-rs

## References

- [Rust for Linux Documentation](https://docs.kernel.org/rust/)
- [Kernel Crate API](https://rust-for-linux.github.io/docs/kernel/)
- [BPF Verifier Source](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)

---

*Before sending to mailing list: Subscribe to rust-for-linux@vger.kernel.org and use `git send-email`*
