#!/bin/bash
# Setup script for kernel integration in Alpine VM
# Run this inside the VM after mounting shared folder
#
# Usage:
#   mount -t 9p -o trans=virtio host0 /mnt
#   cd /mnt
#   ./setup-kernel-integration.sh

set -e

echo "=========================================="
echo "  BPF Verifier Rust - Kernel Integration"
echo "=========================================="

# Check if running in VM
if [ ! -d /mnt/verifier-rs ]; then
    echo "Error: Run this script inside the VM with shared folder mounted at /mnt"
    exit 1
fi

# Install dependencies
echo ""
echo "[1/6] Installing build dependencies..."
apk update
apk add \
    build-base \
    linux-headers \
    linux-virt-dev \
    rust \
    cargo \
    ncurses-dev \
    openssl-dev \
    elfutils-dev \
    flex \
    bison \
    bc \
    perl \
    wget \
    xz \
    git \
    llvm \
    lld \
    clang

# Get kernel version
KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)

echo ""
echo "[2/6] Current kernel: $(uname -r)"
echo "      Will download Linux ${KERNEL_MAJOR}.${KERNEL_MINOR}.x source"

# Download kernel source
KERNEL_DIR="/usr/src/linux-${KERNEL_VERSION}"
if [ ! -d "${KERNEL_DIR}" ]; then
    echo ""
    echo "[3/6] Downloading kernel source..."
    cd /usr/src
    
    # Try to get exact version or close match
    KERNEL_TAR="linux-${KERNEL_VERSION}.tar.xz"
    KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/${KERNEL_TAR}"
    
    if ! wget -q "${KERNEL_URL}" 2>/dev/null; then
        # Try without patch level
        KERNEL_VERSION="${KERNEL_MAJOR}.${KERNEL_MINOR}"
        KERNEL_TAR="linux-${KERNEL_VERSION}.tar.xz"
        KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/${KERNEL_TAR}"
        wget "${KERNEL_URL}"
    fi
    
    echo "Extracting..."
    tar xf "${KERNEL_TAR}"
    mv "linux-${KERNEL_VERSION}" "${KERNEL_DIR}" 2>/dev/null || true
    rm -f "${KERNEL_TAR}"
else
    echo ""
    echo "[3/6] Kernel source already exists at ${KERNEL_DIR}"
fi

# Build Rust verifier library
echo ""
echo "[4/6] Building Rust verifier library..."
cd /mnt/verifier-rs

# Use nightly for kernel features
export RUSTUP_HOME=/root/.rustup
export CARGO_HOME=/root/.cargo
if [ ! -f "${CARGO_HOME}/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
fi
source "${CARGO_HOME}/env"
rustup default nightly
rustup component add rust-src

# Build for kernel
cargo build --release --features kernel,ffi --no-default-features \
    -Z build-std=core,alloc \
    --target x86_64-linux-kernel.json

# Copy library to kernel source
echo ""
echo "[5/6] Integrating into kernel source..."
RUST_LIB="/mnt/verifier-rs/target/x86_64-linux-kernel/release/libbpf_verifier.a"
if [ ! -f "${RUST_LIB}" ]; then
    echo "Error: Rust library not found at ${RUST_LIB}"
    exit 1
fi

# Create integration directory
mkdir -p "${KERNEL_DIR}/rust_bpf_verifier"
cp "${RUST_LIB}" "${KERNEL_DIR}/rust_bpf_verifier/"
cp /mnt/verifier-rs/kernel-module/include/bpf_verifier_rs.h "${KERNEL_DIR}/include/linux/"

# Apply patch
echo ""
echo "[6/6] Applying kernel patch..."
cd "${KERNEL_DIR}"
if [ -f /mnt/kernel-bpf-rust.patch ]; then
    patch -p1 < /mnt/kernel-bpf-rust.patch || echo "Patch may have already been applied"
fi

echo ""
echo "=========================================="
echo "  Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. cd ${KERNEL_DIR}"
echo "  2. make menuconfig  # Enable CONFIG_BPF_VERIFIER_RUST"
echo "  3. make -j\$(nproc)"
echo "  4. make modules_install"
echo "  5. make install"
echo "  6. reboot"
echo ""
