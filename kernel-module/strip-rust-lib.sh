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

# Extract objects from the static library, excluding problematic ones
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Extract all objects
ar x "$RUST_LIB"

# Remove objects with FMA/FMA4 instructions that objtool can't decode
# These are compiler_builtins floating point functions not needed for our code
rm -f *fma* *libm* 2>/dev/null || true

# Link remaining objects into a single relocatable object
# Use --gc-sections to remove unused sections (requires -ffunction-sections in compilation)
ld -r --gc-sections -o "$OUTPUT.tmp" *.o 2>/dev/null || ld -r -o "$OUTPUT.tmp" $(ls *.o)

cd "$SCRIPT_DIR"
rm -rf "$TEMP_DIR"

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
    "$OUTPUT.tmp" "$OUTPUT.tmp2" 2>/dev/null || mv "$OUTPUT.tmp" "$OUTPUT.tmp2"

# Remove FMA sections that use unsupported FMA4 instructions (AMD-specific)
# These sections contain vfmaddsd/vfmaddss instructions that objtool can't decode
# Find all sections with fma_with in the name (these use FMA4 instructions)
FMA_SECTIONS=$(objdump -h "$OUTPUT.tmp2" 2>/dev/null | grep -E '\.text\.[^ ]*fma[f]?_with' | awk '{print $2}' | tr '\n' ' ')
if [ -n "$FMA_SECTIONS" ]; then
    echo "Removing FMA sections: $FMA_SECTIONS"
    REMOVE_ARGS=""
    for sect in $FMA_SECTIONS; do
        REMOVE_ARGS="$REMOVE_ARGS --remove-section=$sect"
    done
    objcopy $REMOVE_ARGS "$OUTPUT.tmp2" "$OUTPUT.tmp3" 2>/dev/null || cp "$OUTPUT.tmp2" "$OUTPUT.tmp3"
    mv "$OUTPUT.tmp3" "$OUTPUT.tmp2"
fi

# Also remove fmaf_with sections
FMAF_SECTIONS=$(objdump -h "$OUTPUT.tmp2" 2>/dev/null | grep -E '\.text\.[^ ]*fmaf_with' | awk '{print $2}' | tr '\n' ' ')
if [ -n "$FMAF_SECTIONS" ]; then
    echo "Removing FMAf sections: $FMAF_SECTIONS"
    REMOVE_ARGS=""
    for sect in $FMAF_SECTIONS; do
        REMOVE_ARGS="$REMOVE_ARGS --remove-section=$sect"
    done
    objcopy $REMOVE_ARGS "$OUTPUT.tmp2" "$OUTPUT.tmp3" 2>/dev/null || cp "$OUTPUT.tmp2" "$OUTPUT.tmp3"
    mv "$OUTPUT.tmp3" "$OUTPUT.tmp2"
fi

mv "$OUTPUT.tmp2" "$OUTPUT"

rm -f "$OUTPUT.tmp2" 2>/dev/null || true

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
