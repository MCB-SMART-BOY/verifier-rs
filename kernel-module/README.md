# BPF Verifier Rust Kernel Module

This directory contains infrastructure for building and testing the Rust BPF
verifier as a Linux kernel module.

## Status: Working ✓

The kernel module successfully builds and loads on Linux 6.12+.

**Current Limitation**: Full verification is disabled in kernel mode due to
stack size constraints. The kernel stack (typically 8-16KB) is too small for
the verifier's state structures. A simplified verification path is used that
only checks basic program structure.

## Quick Start

### Prerequisites

- Linux kernel headers (matching your running kernel)
- Rust nightly toolchain with `rust-src` component
- Standard build tools (make, gcc, binutils)

### Build and Load

```bash
# 1. Install Rust nightly and rust-src
rustup install nightly
rustup component add rust-src --toolchain nightly

# 2. Build the Rust library with kernel target
cd /path/to/verifier-rs
cargo +nightly build --release --features kernel,ffi --no-default-features \
    -Z build-std=core,alloc --target x86_64-linux-kernel.json

# 3. Build the kernel module
cd kernel-module
make module

# 4. Load the module
sudo insmod bpf_verifier_rs.ko

# 5. Check it's loaded
lsmod | grep bpf_verifier
ls -la /dev/bpf_verifier_rs

# 6. Unload when done
sudo rmmod bpf_verifier_rs
```

### Testing in QEMU VM (Safe)

For safe testing without affecting your host system:

```bash
cd kernel-module/vm
expect test-module.exp
```

This uses an Alpine Linux VM with 9p filesystem sharing.

## Technical Details

### The GOT Relocation Problem (Solved)

The Linux kernel module loader only supports a limited set of x86_64 ELF
relocation types. Standard Rust compilation generates `R_X86_64_GOTPCREL`
relocations (type 9) for position-independent code, which the kernel rejects.

**Solution**: Use a custom target specification (`x86_64-linux-kernel.json`)
with:
- `"code-model": "kernel"` - Use kernel code model
- `"relocation-model": "static"` - Avoid GOT-based relocations
- `"disable-redzone": true` - Required for kernel code
- `"panic-strategy": "abort"` - No unwinding in kernel

### Build Process

1. **Rust Library**: Built with custom kernel target using `build-std` to
   recompile `core` and `alloc` with kernel-compatible settings.

2. **Library Processing**: The `strip-rust-lib.sh` script:
   - Links all objects into a single relocatable file
   - Removes problematic sections (`.eh_frame`, `.got`, etc.)
   - Verifies no GOT relocations remain

3. **Kernel Module**: Standard Kbuild process links the processed Rust
   library with the C wrapper module.

### Module Interface

The module creates `/dev/bpf_verifier_rs` with IOCTL interface:

- `BPF_VERIFY_RS_VERIFY` - Verify a BPF program
- `BPF_VERIFY_RS_GET_STATS` - Get verification statistics

### Stack Size Limitation

The full Rust BPF verifier uses large state structures:
- `BpfRegState`: ~200-300 bytes per register
- `BpfFuncState`: ~3000+ bytes (11 registers + stack manager)
- `BpfVerifierState`: Multiple frames, each with BpfFuncState

These structures are normally allocated on the stack during verification.
The Linux kernel stack (8-16KB) is insufficient for full verification.

**Future Work**: To enable full verification in kernel mode:
1. Use `Box` allocation for all large structures
2. Implement a custom stack-less state exploration algorithm
3. Or use kernel workqueues for verification in process context

### Files

```
kernel-module/
├── Kbuild                    # Kernel build configuration
├── Makefile                  # Top-level build script
├── strip-rust-lib.sh         # Rust library processor
├── src/
│   └── bpf_verifier_mod.c    # C wrapper module
├── include/
│   └── bpf_verifier_rs.h     # C header (generated)
└── vm/
    ├── test-module.exp       # VM test script
    ├── auto-build.exp        # Full build in VM
    └── alpine-disk.qcow2     # Alpine Linux VM disk
```

## References

- [Rust for Linux](https://rust-for-linux.com/)
- [Linux Kernel Rust Quick Start](https://docs.kernel.org/rust/quick-start.html)
- [Custom Target Specification](https://doc.rust-lang.org/rustc/targets/custom.html)
