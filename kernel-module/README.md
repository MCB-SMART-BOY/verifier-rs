# BPF Verifier Rust - Kernel Module

This directory contains the kernel module for testing the Rust BPF verifier implementation in a real kernel environment.

## Prerequisites

### System Requirements

- Linux kernel 6.1+ with BPF support enabled
- Kernel headers installed (`linux-headers-$(uname -r)`)
- Rust toolchain (stable)
- GCC and build essentials
- Root privileges for loading/testing

### Install Dependencies

```bash
# Arch Linux
sudo pacman -S linux-headers base-devel rustup clang

# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r) build-essential rustup clang

# Fedora
sudo dnf install kernel-devel gcc rust cargo clang
```

### Rust Setup

```bash
rustup default stable
rustup target add x86_64-unknown-linux-gnu
```

## Directory Structure

```
kernel-module/
├── Makefile           # Build system
├── Kbuild             # Kernel build configuration
├── README.md          # This file
├── src/
│   └── bpf_verifier_mod.c    # Kernel module source
├── include/
│   └── (symlinked headers)
└── tests/
    ├── test_loader.c         # Userspace test program
    ├── simple_return.bpf.c   # Simple BPF test
    ├── alu_ops.bpf.c         # ALU operations test
    ├── bounds_check.bpf.c    # Bounds checking test
    └── invalid_programs.bpf.c # Invalid programs (should fail)
```

## Building

### Quick Start

```bash
cd kernel-module

# Build everything (Rust library + kernel module)
make

# This will:
# 1. Build the Rust library as a static archive
# 2. Compile the kernel module
# 3. Link them together
```

### Step by Step

```bash
# 1. Build Rust static library
make rust_lib

# 2. Build kernel module
make module

# 3. Build test programs
make tests
```

## Loading the Module

```bash
# Load the module
sudo make install

# Check if loaded
make status

# View kernel log
make log
# or
dmesg | grep bpf_verifier_rs
```

## Running Tests

```bash
# Build and run all tests
sudo make test

# Or manually:
sudo make install
sudo ./tests/test_loader
sudo make uninstall
```

### Test Output Example

```
BPF Verifier Rust Test Suite
============================

Device opened: /dev/bpf_verifier_rs

Running 10 tests:

  simple_return      : PASS
    Description: Simple return 0
    Expected: pass, Native: pass (err=0), Rust: pass (err=0)

  return_42          : PASS
    Description: Return immediate value 42
    Expected: pass, Native: pass (err=0), Rust: pass (err=0)

  ...

============================
Results: 9 passed, 1 failed
============================
```

## Unloading

```bash
sudo make uninstall
# or
sudo rmmod bpf_verifier_rs
```

## Troubleshooting

### Module fails to load

1. Check kernel version compatibility:
   ```bash
   uname -r
   ```

2. Check for missing symbols:
   ```bash
   dmesg | tail -20
   ```

3. Verify Rust library was built:
   ```bash
   ls -la ../target/x86_64-unknown-linux-gnu/release/libbpf_verifier.a
   ```

### Build errors

1. Missing kernel headers:
   ```bash
   # Check if headers exist
   ls /lib/modules/$(uname -r)/build
   ```

2. Rust compilation fails:
   ```bash
   cd .. && cargo build --release --features "kernel,ffi" --no-default-features
   ```

### Test failures

1. Device not created:
   ```bash
   ls -la /dev/bpf_verifier_rs
   ```

2. Permission denied:
   ```bash
   # Must run as root
   sudo ./tests/test_loader
   ```

## Development

### Adding New Tests

1. Add test program in `tests/`:
   ```c
   static struct bpf_insn prog_new_test[] = {
       BPF_MOV64_IMM(BPF_REG_0, 0),
       BPF_EXIT_INSN(),
   };
   ```

2. Add to `test_cases` array:
   ```c
   {
       .name = "new_test",
       .insns = prog_new_test,
       .insn_cnt = sizeof(prog_new_test) / sizeof(struct bpf_insn),
       .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
       .expect_pass = true,
       .description = "Description of new test",
   },
   ```

### Modifying the Module

1. Edit `src/bpf_verifier_mod.c`
2. Rebuild: `make clean && make`
3. Reload: `sudo make uninstall && sudo make install`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│  ┌──────────────┐                                       │
│  │ test_loader  │                                       │
│  └──────┬───────┘                                       │
│         │ ioctl(BPF_VERIFY_RS_VERIFY)                   │
├─────────┼───────────────────────────────────────────────┤
│         ▼                     Kernel Space              │
│  ┌──────────────────────────────────────────────────┐  │
│  │         bpf_verifier_rs.ko                        │  │
│  │  ┌─────────────────┐  ┌─────────────────────┐    │  │
│  │  │  C Wrapper      │──│  Rust Static Lib    │    │  │
│  │  │  (IOCTL)        │  │  (libbpf_verifier.a)│    │  │
│  │  └─────────────────┘  └─────────────────────┘    │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## API Reference

### IOCTL Commands

| Command | Direction | Description |
|---------|-----------|-------------|
| `BPF_VERIFY_RS_VERIFY` | IOWR | Verify a BPF program |
| `BPF_VERIFY_RS_GET_STATS` | IOR | Get verification statistics |

### Request Structure

```c
struct bpf_verify_request {
    __u32 prog_type;      // BPF program type
    __u32 insn_cnt;       // Number of instructions
    __u64 insns_ptr;      // Pointer to instructions
    __u32 log_level;      // Log verbosity
    __u32 log_size;       // Log buffer size
    __u64 log_buf_ptr;    // Pointer to log buffer
    __s32 result;         // Output: verification result
};
```

## License

GPL-2.0-only (Linux kernel compatible)
