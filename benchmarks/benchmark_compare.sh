#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Benchmark comparison script for C vs Rust BPF verifier
#
# Usage: ./benchmark_compare.sh [options]
#
# Options:
#   -n NUM    Number of iterations (default: 100)
#   -o FILE   Output file for results (default: benchmark_results.txt)
#   -v        Verbose output

set -e

# Default values
ITERATIONS=100
OUTPUT_FILE="benchmark_results.txt"
VERBOSE=0

# Parse arguments
while getopts "n:o:v" opt; do
    case $opt in
        n) ITERATIONS=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        v) VERBOSE=1 ;;
        *) echo "Usage: $0 [-n iterations] [-o output] [-v]" >&2; exit 1 ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    
    if ! command -v bpftool &> /dev/null; then
        echo "Error: bpftool not found"
        exit 1
    fi
    
    if [ ! -f /proc/sys/kernel/bpf_rust_verifier ]; then
        echo "Warning: Rust BPF verifier not available in kernel"
        echo "Only Rust userspace benchmarks will be run"
        KERNEL_RUST=0
    else
        KERNEL_RUST=1
    fi
}

# Generate test BPF programs
generate_test_programs() {
    echo "Generating test BPF programs..."
    
    mkdir -p /tmp/bpf_bench
    
    # Simple program
    cat > /tmp/bpf_bench/simple.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int simple_prog(struct __sk_buff *skb) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Medium complexity
    cat > /tmp/bpf_bench/medium.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("socket")
int medium_prog(struct __sk_buff *skb) {
    __u32 key = skb->protocol;
    __u64 *val, init_val = 1;
    
    val = bpf_map_lookup_elem(&counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        bpf_map_update_elem(&counter, &key, &init_val, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Complex program with loops
    cat > /tmp/bpf_bench/complex.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("socket")
int complex_prog(struct __sk_buff *skb) {
    __u32 i;
    __u64 sum = 0;
    
    #pragma unroll
    for (i = 0; i < 64; i++) {
        __u64 *val = bpf_map_lookup_elem(&stats, &i);
        if (val)
            sum += *val;
    }
    
    if (skb->len > 100) {
        __u32 key = sum & 0xff;
        __u64 new_val = bpf_ktime_get_ns();
        bpf_map_update_elem(&stats, &key, &new_val, BPF_ANY);
    }
    
    return sum > 1000 ? 1 : 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Compile programs
    for prog in simple medium complex; do
        clang -O2 -target bpf -c /tmp/bpf_bench/${prog}.bpf.c \
            -o /tmp/bpf_bench/${prog}.bpf.o 2>/dev/null || true
    done
}

# Run kernel benchmark with specific verifier
run_kernel_benchmark() {
    local verifier=$1
    local program=$2
    local iterations=$3
    
    if [ "$verifier" = "rust" ]; then
        echo 1 > /proc/sys/kernel/bpf_rust_verifier
    else
        echo 0 > /proc/sys/kernel/bpf_rust_verifier
    fi
    
    local total_time=0
    local times=()
    
    for i in $(seq 1 $iterations); do
        # Time the program load (verification happens during load)
        start=$(date +%s%N)
        bpftool prog load /tmp/bpf_bench/${program}.bpf.o \
            /sys/fs/bpf/bench_${program} 2>/dev/null || true
        end=$(date +%s%N)
        
        # Cleanup
        rm -f /sys/fs/bpf/bench_${program} 2>/dev/null || true
        
        elapsed=$((end - start))
        times+=($elapsed)
        total_time=$((total_time + elapsed))
        
        if [ $VERBOSE -eq 1 ]; then
            echo "  Iteration $i: ${elapsed}ns"
        fi
    done
    
    # Calculate statistics
    local mean=$((total_time / iterations))
    echo $mean
}

# Run Rust userspace benchmark
run_rust_benchmark() {
    echo "Running Rust userspace benchmarks..."
    
    cd "$(dirname "$0")/.."
    cargo bench --quiet 2>/dev/null || echo "Cargo benchmarks not available"
}

# Main benchmark routine
run_benchmarks() {
    echo "Starting benchmarks..."
    echo "Iterations: $ITERATIONS"
    echo ""
    
    {
        echo "BPF Verifier Benchmark Results"
        echo "=============================="
        echo "Date: $(date)"
        echo "Iterations: $ITERATIONS"
        echo "Kernel: $(uname -r)"
        echo ""
        
        if [ $KERNEL_RUST -eq 1 ]; then
            echo "Kernel Benchmarks"
            echo "-----------------"
            
            for prog in simple medium complex; do
                if [ -f /tmp/bpf_bench/${prog}.bpf.o ]; then
                    echo ""
                    echo "Program: $prog"
                    
                    c_time=$(run_kernel_benchmark "c" "$prog" "$ITERATIONS")
                    echo "  C Verifier:    ${c_time}ns"
                    
                    rust_time=$(run_kernel_benchmark "rust" "$prog" "$ITERATIONS")
                    echo "  Rust Verifier: ${rust_time}ns"
                    
                    if [ $c_time -gt 0 ]; then
                        diff=$((100 * (c_time - rust_time) / c_time))
                        echo "  Difference:    ${diff}%"
                    fi
                fi
            done
        fi
        
        echo ""
        echo "Userspace Benchmarks"
        echo "--------------------"
        run_rust_benchmark
        
    } | tee "$OUTPUT_FILE"
    
    echo ""
    echo "Results saved to: $OUTPUT_FILE"
}

# Cleanup
cleanup() {
    rm -rf /tmp/bpf_bench
    rm -f /sys/fs/bpf/bench_* 2>/dev/null || true
    
    # Restore default verifier
    if [ -f /proc/sys/kernel/bpf_rust_verifier ]; then
        echo 0 > /proc/sys/kernel/bpf_rust_verifier 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Main
check_prerequisites
generate_test_programs
run_benchmarks

echo "Benchmark complete!"
