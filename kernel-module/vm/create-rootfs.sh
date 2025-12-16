#!/bin/bash
# Create a minimal rootfs for testing the BPF verifier kernel module
# This script creates a small ext4 image with busybox and necessary tools

set -e

ROOTFS_SIZE="512M"
ROOTFS_IMG="rootfs.img"
MOUNT_DIR="rootfs_mount"

echo "=== Creating minimal rootfs for kernel module testing ==="

# Check for required tools
for cmd in mkfs.ext4 mount busybox; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done

# Create image file
echo "[1/6] Creating ${ROOTFS_SIZE} image file..."
dd if=/dev/zero of=${ROOTFS_IMG} bs=1M count=512 status=progress

# Format as ext4
echo "[2/6] Formatting as ext4..."
mkfs.ext4 -F ${ROOTFS_IMG}

# Mount
echo "[3/6] Mounting image..."
mkdir -p ${MOUNT_DIR}
sudo mount -o loop ${ROOTFS_IMG} ${MOUNT_DIR}

# Create directory structure
echo "[4/6] Creating directory structure..."
sudo mkdir -p ${MOUNT_DIR}/{bin,sbin,etc,proc,sys,dev,tmp,root,lib,lib64,usr/bin,usr/lib,mnt/host}

# Install busybox
echo "[5/6] Installing busybox..."
sudo cp $(which busybox) ${MOUNT_DIR}/bin/
sudo chmod +x ${MOUNT_DIR}/bin/busybox

# Create busybox symlinks
for cmd in sh ash ls cat echo mkdir mount umount insmod rmmod lsmod dmesg \
           cp mv rm ln chmod chown mknod sleep ps grep sed awk head tail \
           vi less more modprobe depmod uname; do
    sudo ln -sf busybox ${MOUNT_DIR}/bin/$cmd
done

# Create init script
sudo tee ${MOUNT_DIR}/init << 'EOF'
#!/bin/sh
# Minimal init for testing

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Create device nodes if needed
[ -e /dev/console ] || mknod /dev/console c 5 1
[ -e /dev/null ] || mknod /dev/null c 1 3
[ -e /dev/zero ] || mknod /dev/zero c 1 5

# Mount 9p shared folder (for passing files from host)
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/host 2>/dev/null || \
    echo "Note: 9p mount failed (no shared folder)"

echo ""
echo "=========================================="
echo "  BPF Verifier Kernel Module Test VM"
echo "=========================================="
echo ""
echo "Kernel: $(uname -r)"
echo "Shared folder: /mnt/host"
echo ""
echo "Quick commands:"
echo "  insmod /mnt/host/bpf_verifier_rs.ko  - Load module"
echo "  lsmod                                 - List modules"  
echo "  dmesg | tail                          - View kernel log"
echo "  rmmod bpf_verifier_rs                 - Unload module"
echo "  /mnt/host/test_loader                 - Run tests"
echo "  poweroff                              - Shutdown VM"
echo ""

# Start shell
exec /bin/sh
EOF
sudo chmod +x ${MOUNT_DIR}/init

# Create basic /etc files
sudo tee ${MOUNT_DIR}/etc/passwd << 'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

sudo tee ${MOUNT_DIR}/etc/group << 'EOF'
root:x:0:
EOF

# Unmount
echo "[6/6] Unmounting..."
sudo umount ${MOUNT_DIR}
rmdir ${MOUNT_DIR}

echo ""
echo "=== Done! Created ${ROOTFS_IMG} ==="
echo ""
echo "To test, run: ./run-vm.sh"
