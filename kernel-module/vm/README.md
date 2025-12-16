# QEMU VM Testing Environment

This directory contains scripts for safely testing the BPF verifier kernel module in a QEMU virtual machine.

## Why Use a VM?

Testing kernel modules can cause:
- System crashes (kernel panic)
- System hangs
- Data loss from unsaved work

Using QEMU completely isolates the test from your main system.

## Quick Start

### Step 1: Create the rootfs image (one-time setup)

```bash
cd kernel-module/vm
sudo ./create-rootfs.sh
```

This creates a minimal ~512MB Linux filesystem with busybox.

### Step 2: Build the kernel module

```bash
cd kernel-module
make
```

### Step 3: Run the VM

```bash
cd kernel-module/vm
./run-vm.sh
```

### Step 4: Test inside VM

Once the VM boots, you'll see a shell prompt. The shared folder from your host is mounted at `/mnt/host`:

```bash
# Inside VM
ls /mnt/host           # See shared files
insmod /mnt/host/bpf_verifier_rs.ko   # Load module
lsmod                  # Verify loaded
dmesg | tail           # Check kernel log
/mnt/host/test_loader  # Run tests
rmmod bpf_verifier_rs  # Unload module
poweroff               # Shutdown VM
```

## VM Options

```bash
./run-vm.sh --help

Options:
  -k, --kernel PATH   Use custom kernel (default: /boot/vmlinuz-linux-zen)
  -m, --memory SIZE   Memory size (default: 1G)
  -c, --cpus NUM      Number of CPUs (default: 2)
  -g, --graphic       Enable graphical console
  -h, --help          Show help
```

## File Sharing

Files in `kernel-module/vm/shared/` are automatically available inside the VM at `/mnt/host/`.

The `run-vm.sh` script automatically copies:
- `bpf_verifier_rs.ko` (if built)
- `tests/test_loader` (if built)
- `libbpf_verifier.a` (for reference)

## Exiting QEMU

- Type `poweroff` in the VM shell for clean shutdown
- Press `Ctrl+A`, then `X` to force quit QEMU

## Troubleshooting

### "KVM not available"

```bash
# Check if KVM is enabled
lsmod | grep kvm

# Load KVM modules
sudo modprobe kvm
sudo modprobe kvm_intel  # or kvm_amd
```

### "Permission denied" for KVM

```bash
# Add yourself to kvm group
sudo usermod -aG kvm $USER
# Then logout and login again
```

### "9p mount failed"

This is usually harmless - it means the shared folder feature isn't working, but you can still test by copying files to the rootfs image.

### VM hangs or crashes

This is expected when testing buggy kernel modules! Simply close the QEMU window or press `Ctrl+A, X`. Your host system is unaffected.

## Architecture

```
Host System
├── kernel-module/
│   ├── vm/
│   │   ├── create-rootfs.sh    # Creates minimal Linux image
│   │   ├── run-vm.sh           # Launches QEMU
│   │   ├── rootfs.img          # Generated filesystem image
│   │   └── shared/             # Shared with VM at /mnt/host
│   ├── bpf_verifier_rs.ko      # Kernel module (after build)
│   └── tests/
│       └── test_loader         # Test program (after build)
│
└── QEMU VM (isolated)
    ├── /mnt/host               # Mounted from shared/
    └── /                       # rootfs.img contents
```
