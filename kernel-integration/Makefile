# SPDX-License-Identifier: GPL-2.0

# Rust BPF Verifier kernel module Makefile

obj-$(CONFIG_BPF_VERIFIER_RUST) += bpf_verifier_rust.o

bpf_verifier_rust-y := bpf_verifier_rust_glue.o

# Rust source files are compiled separately by the Rust toolchain
# The resulting .o files are linked with the C glue code

# Build the Rust library
$(obj)/bpf_verifier_rust.o: $(obj)/libbpf_verifier.a

# Compile Rust code using kernel's Rust infrastructure
$(obj)/libbpf_verifier.a: $(src)/rust/lib.rs FORCE
	$(call if_changed,rustc_library)

# C glue code for interfacing with kernel BPF subsystem
$(obj)/bpf_verifier_rust_glue.o: $(src)/bpf_verifier_rust_glue.c

clean-files := libbpf_verifier.a
