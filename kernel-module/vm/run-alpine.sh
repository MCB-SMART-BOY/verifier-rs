#!/bin/bash
# Run Alpine Linux VM for kernel module testing
#
# First run: boots from ISO for installation
# After installation: boots from disk
#
# Usage:
#   ./run-alpine.sh install   # First time - install Alpine
#   ./run-alpine.sh           # Normal boot from disk

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ISO="${SCRIPT_DIR}/alpine-virt.iso"
DISK="${SCRIPT_DIR}/alpine-disk.qcow2"
SHARED_DIR="${SCRIPT_DIR}/shared"

# Create shared directory
mkdir -p "${SHARED_DIR}"

# Copy files to shared directory
MODULE_DIR="$(dirname "${SCRIPT_DIR}")"
PROJECT_DIR="$(dirname "${MODULE_DIR}")"

# Copy source files for building in VM
if [ -d "${PROJECT_DIR}/src" ]; then
    echo "Syncing project to shared folder..."
    rsync -a --exclude='target' --exclude='.git' --exclude='kernel-module/vm' \
        "${PROJECT_DIR}/" "${SHARED_DIR}/verifier-rs/" 2>/dev/null || \
        cp -r "${PROJECT_DIR}/src" "${PROJECT_DIR}/Cargo.toml" "${PROJECT_DIR}/include" \
            "${SHARED_DIR}/" 2>/dev/null || true
fi

# Copy kernel module source
cp -r "${MODULE_DIR}/src" "${MODULE_DIR}/Kbuild" "${MODULE_DIR}/Makefile" \
    "${SHARED_DIR}/" 2>/dev/null || true

# Copy test files
cp -r "${MODULE_DIR}/tests" "${SHARED_DIR}/" 2>/dev/null || true

MEMORY="2G"
CPUS="2"

# Common QEMU options
QEMU_COMMON=(
    -m "${MEMORY}"
    -smp "${CPUS}"
    -enable-kvm
    -cpu host
    -drive "file=${DISK},format=qcow2,if=virtio"
    -virtfs "local,path=${SHARED_DIR},mount_tag=host0,security_model=mapped-xattr,id=host0"
    -nic user,model=virtio,hostfwd=tcp::2222-:22
    -nographic
)

if [ "$1" = "install" ]; then
    echo "=========================================="
    echo "  Alpine Linux Installation Mode"
    echo "=========================================="
    echo ""
    echo "After boot, run: setup-alpine"
    echo "Use 'vda' as disk, 'sys' mode"
    echo "After installation, type 'poweroff'"
    echo ""
    echo "Press Ctrl+A, X to force quit"
    echo "=========================================="
    
    qemu-system-x86_64 \
        "${QEMU_COMMON[@]}" \
        -cdrom "${ISO}" \
        -boot d
else
    if [ ! -f "${DISK}" ]; then
        echo "Error: Disk image not found. Run './run-alpine.sh install' first"
        exit 1
    fi
    
    echo "=========================================="
    echo "  Alpine Linux VM"
    echo "=========================================="
    echo ""
    echo "Login: root (password you set during install)"
    echo "Shared folder: mount -t 9p -o trans=virtio host0 /mnt"
    echo ""
    echo "Setup build environment:"
    echo "  apk add build-base linux-virt-dev rust cargo"
    echo ""
    echo "Build module:"
    echo "  cd /mnt/verifier-rs"
    echo "  cargo build --release --features kernel,ffi --no-default-features"
    echo "  cd kernel-module"
    echo "  make"
    echo ""
    echo "Press Ctrl+A, X to exit"
    echo "=========================================="
    
    qemu-system-x86_64 \
        "${QEMU_COMMON[@]}" \
        -boot c
fi
