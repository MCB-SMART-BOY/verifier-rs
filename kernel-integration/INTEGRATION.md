# Kernel Integration Guide (Linux 6.12+)

This document describes how to integrate the Rust BPF verifier into
the Linux kernel using the native Rust support available in Linux 6.12+.

## Prerequisites

- Linux kernel 6.12+ source with Rust support enabled
- Rust toolchain 1.83.0+ (as required by kernel)
- bindgen 0.69.0+
- LLVM/Clang 18+

## Key Changes from Earlier Versions

Starting with Linux 6.12, Rust for Linux has matured significantly:

1. **No C glue code required** - Pure Rust modules using `kernel::Module` trait
2. **Native kernel crate** - Full access to kernel APIs via `kernel::prelude::*`
3. **Improved build system** - Kbuild handles Rust compilation natively
4. **Better abstractions** - `KVec`, `Arc`, synchronization primitives available

## Integration Steps

### Step 1: Enable Rust Support in Kernel

```bash
cd $KERNEL_SRC

# Check Rust availability
make LLVM=1 rustavailable

# Configure kernel
make LLVM=1 menuconfig
```

Enable these options:
```
General setup --->
    [*] Rust support
    
Networking support --->
    Networking options --->
        [*] BPF subsystem --->
            [*] Rust implementation of BPF verifier
```

### Step 2: Copy Verifier Source

```bash
# Create directory in kernel tree
mkdir -p $KERNEL_SRC/rust/kernel/bpf_verifier

# Copy source files
cp -r src/* $KERNEL_SRC/rust/kernel/bpf_verifier/

# Copy integration module
cp kernel-integration/rust_bpf_verifier.rs $KERNEL_SRC/kernel/bpf/
```

### Step 3: Modify Kernel Build Files

Add to `kernel/bpf/Kconfig`:
```kconfig
source "kernel/bpf/Kconfig.rust"
```

Add to `kernel/bpf/Makefile`:
```makefile
obj-$(CONFIG_BPF_VERIFIER_RUST) += rust_bpf_verifier.o
```

### Step 4: Hook into BPF Verification Path

Modify `kernel/bpf/verifier.c`:

```c
#ifdef CONFIG_BPF_VERIFIER_RUST
// Rust entry point - no separate declaration file needed
// The symbol is exported by the Rust module
extern int rust_bpf_check(struct bpf_verifier_env *env);

static bool use_rust_verifier(void)
{
    // Check sysctl or config default
    return sysctl_bpf_rust_verifier;
}
#endif

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
              bpfptr_t uattr, u32 uattr_size)
{
    // ... existing setup ...

#ifdef CONFIG_BPF_VERIFIER_RUST
    if (use_rust_verifier()) {
        ret = rust_bpf_check(env);
        if (ret != -ENOSYS)
            goto cleanup;
        // Fall through if Rust returns ENOSYS
    }
#endif

    // ... existing C verifier code ...
}
```

### Step 5: Build the Kernel

```bash
make LLVM=1 -j$(nproc)
```

## Runtime Configuration

```bash
# Check if Rust verifier is available
cat /proc/sys/kernel/bpf_rust_verifier

# Enable Rust verifier
echo 1 > /proc/sys/kernel/bpf_rust_verifier

# Disable (use C verifier)
echo 0 > /proc/sys/kernel/bpf_rust_verifier
```

## Module Structure (Linux 6.12+ Style)

```rust
use kernel::prelude::*;

module! {
    type: RustBpfVerifier,
    name: "rust_bpf_verifier",
    authors: ["BPF Contributors"],
    description: "Rust BPF verifier",
    license: "GPL",
}

struct RustBpfVerifier { /* state */ }

impl kernel::Module for RustBpfVerifier {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust BPF verifier loaded\n");
        Ok(Self { /* init */ })
    }
}

impl Drop for RustBpfVerifier {
    fn drop(&mut self) {
        pr_info!("Rust BPF verifier unloaded\n");
    }
}
```

## Available Kernel APIs

The `kernel` crate provides:

| Module | Description |
|--------|-------------|
| `kernel::sync` | Mutex, SpinLock, RwSemaphore |
| `kernel::alloc` | KVec, KBox allocation |
| `kernel::prelude` | Common imports |
| `kernel::error` | Error handling, Result |
| `kernel::print` | pr_info!, pr_err!, etc. |

## Testing

```bash
# Load test BPF program
bpftool prog load test.bpf.o /sys/fs/bpf/test

# Check kernel logs
dmesg | grep -i rust.*bpf

# Run BPF selftests
cd tools/testing/selftests/bpf
./test_verifier
```

## Debugging

Enable debug config:
```
CONFIG_BPF_VERIFIER_RUST_DEBUG=y
```

View detailed logs:
```bash
dmesg | grep rust_bpf
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│                  bpf() syscall                          │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    bpf_check()                          │
│                        │                                │
│         ┌──────────────┴──────────────┐                │
│         │                             │                 │
│         ▼                             ▼                 │
│    C Verifier                  Rust Verifier           │
│   (verifier.c)              (rust_bpf_verifier.rs)     │
│                                      │                  │
│                                      ▼                  │
│                            ┌─────────────────┐         │
│                            │ kernel::Module  │         │
│                            │ (pure Rust)     │         │
│                            └─────────────────┘         │
│                                      │                  │
│                                      ▼                  │
│                            ┌─────────────────┐         │
│                            │ bpf_verifier    │         │
│                            │ crate (our lib) │         │
│                            └─────────────────┘         │
└─────────────────────────────────────────────────────────┘
```

## Compatibility Matrix

| Kernel | Rust | bindgen | Status |
|--------|------|---------|--------|
| 6.12   | 1.82 | 0.69    | Supported |
| 6.13   | 1.83 | 0.70    | Supported |
| 6.14+  | 1.84+| 0.71+   | Recommended |

## References

- [Rust for Linux Documentation](https://docs.kernel.org/rust/)
- [Kernel Crate API](https://rust-for-linux.github.io/docs/kernel/)
- [Rust for Linux GitHub](https://github.com/Rust-for-Linux/linux)
