#!/bin/sh
# Strip problematic sections from Rust static library for kernel module linking
#
# Usage: ./strip-rust-lib.sh [--kernel-target]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Check for kernel target build first, fall back to release
if [ -f "$PROJECT_DIR/target/x86_64-linux-kernel/release/libbpf_verifier.a" ]; then
    RUST_LIB="$PROJECT_DIR/target/x86_64-linux-kernel/release/libbpf_verifier.a"
    echo "Using kernel-target build"
elif [ -f "$PROJECT_DIR/target/release/libbpf_verifier.a" ]; then
    RUST_LIB="$PROJECT_DIR/target/release/libbpf_verifier.a"
    echo "Using standard release build"
else
    echo "Error: Rust library not found"
    echo "Please build it first with:"
    echo "  For kernel: cargo +nightly build --release --features kernel,ffi --no-default-features -Z build-std=core,alloc --target x86_64-linux-kernel.json"
    echo "  Or standard: cargo build --release --features kernel,ffi --no-default-features"
    exit 1
fi

OUTPUT="$SCRIPT_DIR/rust_lib_stripped.o"
CMD_FILE="$SCRIPT_DIR/.rust_lib_stripped.o.cmd"

echo "Processing Rust static library: $RUST_LIB"

# Link all objects from the static library into a single relocatable object
ld -r -o "$OUTPUT.tmp" --whole-archive "$RUST_LIB"

# Strip sections that cause problems with kernel build system
objcopy \
    --remove-section=.debug_gdb_scripts \
    --remove-section=.note.GNU-stack \
    --remove-section=.eh_frame \
    --remove-section=.eh_frame_hdr \
    --remove-section=.comment \
    --remove-section=.note.gnu.build-id \
    --remove-section=.note.gnu.property \
    --remove-section=.got \
    --remove-section=.got.plt \
    "$OUTPUT.tmp" "$OUTPUT" 2>/dev/null || mv "$OUTPUT.tmp" "$OUTPUT"

rm -f "$OUTPUT.tmp" 2>/dev/null || true

# Create the .cmd file that modpost expects
cat > "$CMD_FILE" << EOF
cmd_${SCRIPT_DIR}/rust_lib_stripped.o := ld -r -o ${OUTPUT} --whole-archive ${RUST_LIB}
EOF

echo "Created: $OUTPUT"
echo "Created: $CMD_FILE"
echo "Size: $(ls -lh "$OUTPUT" | awk '{print $5}')"

# Check for remaining problematic relocations
echo ""
echo "Checking for GOT relocations..."
GOT_COUNT=$(readelf -r "$OUTPUT" 2>/dev/null | grep -E "R_X86_64_GOTPCREL|R_X86_64_REX_GOTPCRELX|R_X86_64_GOTPCRELX" | wc -l)
if [ "$GOT_COUNT" -gt 0 ]; then
    echo "WARNING: $GOT_COUNT GOT relocations still present."
    echo "Relocations found:"
    readelf -r "$OUTPUT" 2>/dev/null | grep "GOTPCREL" | head -10
else
    echo "SUCCESS: No problematic GOT relocations found!"
fi
