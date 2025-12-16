#!/bin/bash
# Run QEMU VM for testing BPF verifier kernel module
#
# Usage: ./run-vm.sh [options]
#   -k, --kernel PATH   Use custom kernel (default: host kernel)
#   -m, --memory SIZE   Memory size (default: 1G)
#   -c, --cpus NUM      Number of CPUs (default: 2)
#   -g, --graphic       Enable graphical console
#   -h, --help          Show help

set -e

# Default settings
KERNEL="/boot/vmlinuz-linux-zen"
INITRD=""  # We'll use our rootfs as initrd-style boot
MEMORY="1G"
CPUS="2"
GRAPHIC=""
CONSOLE="console=ttyS0"

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTFS="${SCRIPT_DIR}/rootfs.img"
MODULE_DIR="$(dirname "${SCRIPT_DIR}")"
PROJECT_DIR="$(dirname "${MODULE_DIR}")"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--kernel)
            KERNEL="$2"
            shift 2
            ;;
        -m|--memory)
            MEMORY="$2"
            shift 2
            ;;
        -c|--cpus)
            CPUS="$2"
            shift 2
            ;;
        -g|--graphic)
            GRAPHIC="yes"
            CONSOLE=""
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  -k, --kernel PATH   Use custom kernel"
            echo "  -m, --memory SIZE   Memory size (default: 1G)"
            echo "  -c, --cpus NUM      Number of CPUs (default: 2)"
            echo "  -g, --graphic       Enable graphical console"
            echo "  -h, --help          Show help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
if [ ! -f "${ROOTFS}" ]; then
    echo "Error: rootfs.img not found. Run ./create-rootfs.sh first"
    exit 1
fi

if [ ! -f "${KERNEL}" ]; then
    echo "Error: Kernel not found at ${KERNEL}"
    echo "Available kernels:"
    ls -la /boot/vmlinuz* 2>/dev/null || echo "  (none found in /boot)"
    exit 1
fi

# Prepare shared directory with module and tests
SHARED_DIR="${SCRIPT_DIR}/shared"
mkdir -p "${SHARED_DIR}"

# Copy kernel module if built
if [ -f "${MODULE_DIR}/bpf_verifier_rs.ko" ]; then
    cp "${MODULE_DIR}/bpf_verifier_rs.ko" "${SHARED_DIR}/"
    echo "Copied kernel module to shared folder"
fi

# Copy test loader if built
if [ -f "${MODULE_DIR}/tests/test_loader" ]; then
    cp "${MODULE_DIR}/tests/test_loader" "${SHARED_DIR}/"
    chmod +x "${SHARED_DIR}/test_loader"
    echo "Copied test loader to shared folder"
fi

# Copy Rust static library for reference
if [ -f "${PROJECT_DIR}/target/release/libbpf_verifier.a" ]; then
    cp "${PROJECT_DIR}/target/release/libbpf_verifier.a" "${SHARED_DIR}/"
    echo "Copied Rust static library to shared folder"
fi

echo ""
echo "=========================================="
echo "  Starting QEMU VM"
echo "=========================================="
echo "Kernel:      ${KERNEL}"
echo "Memory:      ${MEMORY}"
echo "CPUs:        ${CPUS}"
echo "Rootfs:      ${ROOTFS}"
echo "Shared dir:  ${SHARED_DIR}"
echo ""
echo "Press Ctrl+A, X to exit QEMU"
echo "=========================================="
echo ""

# Build QEMU command
QEMU_ARGS=(
    -kernel "${KERNEL}"
    -drive "file=${ROOTFS},format=raw,if=virtio"
    -append "root=/dev/vda rw init=/init ${CONSOLE}"
    -m "${MEMORY}"
    -smp "${CPUS}"
    -enable-kvm
    -cpu host
    # 9p filesystem for sharing files with host
    -virtfs "local,path=${SHARED_DIR},mount_tag=host0,security_model=mapped-xattr,id=host0"
    # Network (optional, for debugging)
    -nic user,model=virtio
)

# Console settings
if [ -z "${GRAPHIC}" ]; then
    QEMU_ARGS+=(-nographic)
else
    QEMU_ARGS+=(-vga std)
fi

# Run QEMU
exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
