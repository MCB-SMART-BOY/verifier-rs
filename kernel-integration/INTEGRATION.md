# Kernel Integration Guide

This document describes how to integrate the Rust BPF verifier into the Linux kernel.

## Prerequisites

1. Linux kernel source with Rust support (6.1+)
2. Rust toolchain compatible with the kernel version
3. This Rust BPF verifier crate

## Integration Steps

### Step 1: Copy Files to Kernel Source Tree

```bash
# Copy Rust source
cp -r src/ $KERNEL_SRC/rust/kernel/bpf_verifier/

# Copy integration files
cp kernel-integration/Kconfig $KERNEL_SRC/kernel/bpf/Kconfig.rust
cp kernel-integration/Makefile $KERNEL_SRC/kernel/bpf/Makefile.rust
cp kernel-integration/bpf_verifier_rust_glue.c $KERNEL_SRC/kernel/bpf/
```

### Step 2: Modify Kernel BPF Kconfig

Add to `kernel/bpf/Kconfig`:

```kconfig
source "kernel/bpf/Kconfig.rust"
```

### Step 3: Modify Kernel BPF Makefile

Add to `kernel/bpf/Makefile`:

```makefile
include $(src)/Makefile.rust
```

### Step 4: Hook into BPF Verification Path

Modify `kernel/bpf/verifier.c` to optionally use Rust verifier:

```c
#ifdef CONFIG_BPF_VERIFIER_RUST
extern int bpf_rust_verify_prog(struct bpf_verifier_env *env);
extern bool bpf_rust_verifier_enabled(void);
#endif

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
              bpfptr_t uattr, u32 uattr_size)
{
    struct bpf_verifier_env *env;
    int ret;

    /* ... existing setup code ... */

#ifdef CONFIG_BPF_VERIFIER_RUST
    if (bpf_rust_verifier_enabled()) {
        ret = bpf_rust_verify_prog(env);
        if (ret != -ENOSYS)
            goto cleanup;
        /* Fall through to C verifier if Rust returns ENOSYS */
    }
#endif

    /* ... existing C verifier code ... */
}
```

### Step 5: Configure and Build

```bash
cd $KERNEL_SRC

# Enable Rust support
make LLVM=1 rustavailable

# Configure kernel
make menuconfig
# Enable: General setup -> Rust support
# Enable: Networking -> BPF -> Rust BPF verifier

# Build
make LLVM=1 -j$(nproc)
```

## Runtime Configuration

The Rust verifier can be enabled/disabled at runtime via sysctl:

```bash
# Check current status
cat /proc/sys/kernel/bpf_rust_verifier

# Enable Rust verifier
echo 1 > /proc/sys/kernel/bpf_rust_verifier

# Disable Rust verifier (use C verifier)
echo 0 > /proc/sys/kernel/bpf_rust_verifier
```

## Testing

1. Load a simple BPF program and verify it works:
   ```bash
   bpftool prog load test.bpf.o /sys/fs/bpf/test
   ```

2. Check kernel logs for verifier output:
   ```bash
   dmesg | grep -i "bpf.*verifier"
   ```

3. Run BPF selftests:
   ```bash
   cd tools/testing/selftests/bpf
   make
   ./test_verifier
   ```

## Debugging

Enable debug output by setting `CONFIG_BPF_VERIFIER_RUST_DEBUG=y` in kernel config.

Debug messages will appear in kernel log (`dmesg`).

## Architecture

```
                    User Space
                        |
                        | bpf() syscall
                        v
    +-------------------------------------------+
    |              bpf_check()                  |
    |                   |                       |
    |    +--------------+--------------+        |
    |    |                             |        |
    |    v                             v        |
    | C Verifier              Rust Verifier     |
    | (verifier.c)            (this crate)      |
    |                               |           |
    |                               v           |
    |                    +------------------+   |
    |                    | rust_bpf_verify  |   |
    |                    | (FFI entry)      |   |
    |                    +------------------+   |
    |                               |           |
    |                               v           |
    |                    +------------------+   |
    |                    | MainVerifier     |   |
    |                    | (pure Rust)      |   |
    |                    +------------------+   |
    +-------------------------------------------+
                    Kernel Space
```

## Compatibility

- Kernel version: 6.1+ (with Rust support)
- Architecture: x86_64, arm64 (tested)
- Rust version: As required by kernel (currently 1.78+)
