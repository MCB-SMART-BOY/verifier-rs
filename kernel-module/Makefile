# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the BPF Verifier Rust kernel module
#
# Usage:
#   make              - Build the kernel module
#   make clean        - Clean build artifacts
#   make install      - Install the module
#   make uninstall    - Remove the module
#   make test         - Build and run tests
#

# Module name
MODULE_NAME := bpf_verifier_rs

# Rust project root
RUST_ROOT := $(shell dirname $(PWD))

# Rust library output (release build)
RUST_LIB := $(RUST_ROOT)/target/release/libbpf_verifier.a

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Architecture
ARCH ?= x86

# Extra CFLAGS
EXTRA_CFLAGS := -I$(RUST_ROOT)/include -I$(PWD)/include

# Object files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/bpf_verifier_mod.o

# Link with Rust static library
KBUILD_EXTRA_SYMBOLS :=
EXTRA_LDFLAGS := -L$(RUST_ROOT)/target/release -lbpf_verifier

# Default target
all: rust_lib module

# Build Rust static library
rust_lib:
	@echo "Building Rust static library..."
	cd $(RUST_ROOT) && cargo build --release --features "kernel,ffi" --no-default-features
	@echo "Rust library built: $(RUST_LIB)"

# Build kernel module
module: rust_lib
	@echo "Building kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean everything
clean:
	@echo "Cleaning..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	cd $(RUST_ROOT) && cargo clean
	rm -f *.o *.ko *.mod.c *.mod.o .*.cmd Module.symvers modules.order
	rm -rf .tmp_versions

# Install module
install: module
	@echo "Installing module..."
	sudo insmod $(MODULE_NAME).ko
	@echo "Module installed. Check dmesg for output."

# Uninstall module
uninstall:
	@echo "Removing module..."
	-sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	@echo "Module removed."

# Build test programs
tests: test_loader test_programs

test_loader:
	@echo "Building test loader..."
	$(CC) -o tests/test_loader tests/test_loader.c -Wall -Wextra

test_programs:
	@echo "Building test BPF programs..."
	@if command -v clang >/dev/null 2>&1; then \
		for f in tests/*.bpf.c; do \
			[ -f "$$f" ] && clang -O2 -target bpf -c "$$f" -o "$${f%.c}.o" || true; \
		done; \
	else \
		echo "Warning: clang not found, skipping BPF program compilation"; \
	fi

# Run tests
test: install tests
	@echo "Running verification tests..."
	sudo ./tests/test_loader
	$(MAKE) uninstall

# Check if module is loaded
status:
	@lsmod | grep $(MODULE_NAME) || echo "Module not loaded"
	@ls -la /dev/$(MODULE_NAME) 2>/dev/null || echo "Device not found"

# Show kernel log
log:
	@dmesg | grep bpf_verifier_rs | tail -50

# Help
help:
	@echo "BPF Verifier Rust Kernel Module"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build Rust lib and kernel module (default)"
	@echo "  rust_lib  - Build Rust static library only"
	@echo "  module    - Build kernel module only"
	@echo "  clean     - Clean all build artifacts"
	@echo "  install   - Load module into kernel"
	@echo "  uninstall - Remove module from kernel"
	@echo "  test      - Build and run tests"
	@echo "  status    - Show module status"
	@echo "  log       - Show kernel log messages"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR      - Kernel build directory (default: /lib/modules/$(shell uname -r)/build)"
	@echo "  ARCH      - Target architecture (default: x86)"

.PHONY: all rust_lib module clean install uninstall tests test_loader test_programs test status log help
