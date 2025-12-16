# BPF Verifier Performance Benchmarks

This directory contains benchmarks for comparing the Rust BPF verifier
against the C implementation in the Linux kernel.

## Benchmark Categories

### 1. Verification Time

Measure the time to verify various BPF programs:

| Program Type | Description |
|--------------|-------------|
| Simple | Basic programs (< 100 instructions) |
| Medium | Moderate complexity (100-1000 instructions) |
| Complex | Complex programs (1000-10000 instructions) |
| Maximum | Programs near BPF_MAXINSNS limit |

### 2. Memory Usage

Measure peak memory consumption during verification:

- State storage
- Explored states hash table
- Temporary allocations

### 3. Instruction Types

Benchmark specific instruction verification:

- ALU operations
- Memory loads/stores
- Helper function calls
- Kfunc calls
- Map operations
- Control flow (branches, loops)

## Running Benchmarks

### Prerequisites

```bash
# Build the verifier with benchmarking support
cargo build --release --features stats

# For kernel comparison, you need:
# - Linux kernel source with BPF selftests
# - Root privileges for BPF program loading
```

### Userspace Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench verification_time

# Generate detailed report
cargo bench -- --save-baseline rust_verifier
```

### Kernel Comparison

```bash
# Run kernel BPF selftests with timing
cd $KERNEL_SRC/tools/testing/selftests/bpf
./test_verifier --timing

# Compare with Rust verifier
./benchmark_compare.sh
```

## Benchmark Programs

### simple_return.bpf

```c
// Minimal program - just returns 0
SEC("socket")
int simple_return(struct __sk_buff *skb) {
    return 0;
}
```

### bounds_check.bpf

```c
// Tests bounds tracking performance
SEC("socket")
int bounds_check(struct __sk_buff *skb) {
    int i;
    for (i = 0; i < 100; i++) {
        if (skb->len > i)
            return 1;
    }
    return 0;
}
```

### map_access.bpf

```c
// Tests map verification performance
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} my_map SEC(".maps");

SEC("socket")
int map_access(struct __sk_buff *skb) {
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&my_map, &key);
    if (value)
        return *value;
    return 0;
}
```

### helper_calls.bpf

```c
// Tests helper function verification
SEC("socket")
int helper_calls(struct __sk_buff *skb) {
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    return (ts + cpu) & 0xff;
}
```

## Expected Results

Based on preliminary testing:

| Metric | C Verifier | Rust Verifier | Notes |
|--------|------------|---------------|-------|
| Simple programs | ~10us | ~12us | Rust slightly slower due to FFI |
| Complex programs | ~1ms | ~0.9ms | Rust faster due to better optimization |
| Memory usage | Baseline | +5-10% | Rust has more metadata |
| State pruning | Baseline | Similar | Same algorithm |

## Profiling

### CPU Profiling

```bash
# Using perf
perf record -g cargo bench
perf report

# Using flamegraph
cargo flamegraph --bench verification_time
```

### Memory Profiling

```bash
# Using heaptrack
heaptrack cargo bench --bench memory_usage
heaptrack_gui heaptrack.*.gz
```

## Reporting

Benchmark results should include:

1. Hardware specification (CPU, RAM)
2. Kernel version
3. Rust compiler version
4. Number of iterations
5. Statistical analysis (mean, stddev, percentiles)

Example report format:

```
Benchmark: complex_program_verification
  Hardware: AMD Ryzen 9 5900X, 32GB RAM
  Kernel: 6.12.0
  Rust: 1.78.0
  
  C Verifier:
    Mean: 1.234ms
    Stddev: 0.045ms
    P95: 1.312ms
    
  Rust Verifier:
    Mean: 1.156ms (-6.3%)
    Stddev: 0.038ms
    P95: 1.221ms
```
