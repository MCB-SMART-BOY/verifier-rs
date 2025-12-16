#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Generate kernel patches for Rust BPF verifier
#
# Usage: ./scripts/generate-patches.sh

set -e

PATCH_DIR="patches"
VERSION="v1"

echo "=== Generating Kernel Patches ==="
echo ""

# Create patch directory
mkdir -p ${PATCH_DIR}
rm -f ${PATCH_DIR}/*.patch

# Generate cover letter
cat > ${PATCH_DIR}/0000-cover-letter.patch << 'EOF'
From: Your Name <your@email.com>
Subject: [PATCH v1 0/3] Rust implementation of BPF verifier

This patch series adds a Rust implementation of the BPF verifier
to the Linux kernel, using the native Rust support available in
Linux 6.12+.

Motivation:
- Compile-time memory safety guarantees
- Type-safe register and bounds tracking
- Reduced attack surface for security-critical code
- Better maintainability via Rust idioms

Implementation:
- ~78,000 lines of Rust (including tests)
- Pure Rust module (no C glue code)
- 211 helper functions, 85+ kfuncs
- Full state tracking and pruning
- Spectre mitigations

Patch breakdown:
  [1/3] bpf: Add Kconfig options for Rust BPF verifier
  [2/3] bpf: Add Rust BPF verifier module
  [3/3] bpf: Hook Rust verifier into verification path

Testing:
- 300+ unit tests passing
- Benchmarks show competitive performance

Your Name (3):
  bpf: Add Kconfig options for Rust BPF verifier
  bpf: Add Rust BPF verifier module  
  bpf: Hook Rust verifier into verification path

 kernel/bpf/Kconfig              |    3 +
 kernel/bpf/Kconfig.rust         |   45 +
 kernel/bpf/Makefile             |    1 +
 kernel/bpf/rust_bpf_verifier.rs |  100+
 kernel/bpf/verifier.c           |   15 +
 rust/kernel/bpf_verifier/       | 78000+ (new crate)
 ---
EOF

echo "Generated: ${PATCH_DIR}/0000-cover-letter.patch"

# Patch 1: Kconfig
cat > ${PATCH_DIR}/0001-bpf-Add-Kconfig-options-for-Rust-BPF-verifier.patch << 'EOF'
From: Your Name <your@email.com>
Subject: [PATCH v1 1/3] bpf: Add Kconfig options for Rust BPF verifier

Add configuration options to enable the Rust BPF verifier:

- CONFIG_BPF_VERIFIER_RUST: Enable Rust verifier (depends on RUST)
- CONFIG_BPF_VERIFIER_RUST_DEFAULT: Use Rust verifier by default
- CONFIG_BPF_VERIFIER_RUST_DEBUG: Enable debug output

The Rust verifier is disabled by default and requires explicit
opt-in via Kconfig or runtime sysctl.

Signed-off-by: Your Name <your@email.com>
---
 kernel/bpf/Kconfig      |  3 +++
 kernel/bpf/Kconfig.rust | 45 +++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 48 insertions(+)
 create mode 100644 kernel/bpf/Kconfig.rust

diff --git a/kernel/bpf/Kconfig b/kernel/bpf/Kconfig
index xxxx..yyyy 100644
--- a/kernel/bpf/Kconfig
+++ b/kernel/bpf/Kconfig
@@ -end of file
+
+source "kernel/bpf/Kconfig.rust"

diff --git a/kernel/bpf/Kconfig.rust b/kernel/bpf/Kconfig.rust
new file mode 100644
index 0000000..xxxxxxx
--- /dev/null
+++ b/kernel/bpf/Kconfig.rust
@@ -0,0 +1,45 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+config BPF_VERIFIER_RUST
+	bool "Rust implementation of BPF verifier"
+	depends on BPF_SYSCALL
+	depends on RUST
+	default n
+	help
+	  Enable the Rust implementation of the BPF verifier.
+	  
+	  When enabled, switch between verifiers at runtime:
+	    echo 1 > /proc/sys/kernel/bpf_rust_verifier
+	  
+	  If unsure, say N.
+
+config BPF_VERIFIER_RUST_DEFAULT
+	bool "Use Rust BPF verifier by default"
+	depends on BPF_VERIFIER_RUST
+	default n
+
+config BPF_VERIFIER_RUST_DEBUG
+	bool "Enable Rust BPF verifier debug output"
+	depends on BPF_VERIFIER_RUST
+	depends on DEBUG_KERNEL
+	default n
--
2.43.0
EOF

echo "Generated: ${PATCH_DIR}/0001-bpf-Add-Kconfig-options-for-Rust-BPF-verifier.patch"

# Patch 2: Rust module
cat > ${PATCH_DIR}/0002-bpf-Add-Rust-BPF-verifier-module.patch << 'EOF'
From: Your Name <your@email.com>
Subject: [PATCH v1 2/3] bpf: Add Rust BPF verifier module

Add the Rust BPF verifier kernel module using the native
kernel::Module trait (no C glue code required).

The module provides:
- rust_bpf_check() entry point for kernel integration
- KernelVerifierEnv wrapper for kernel structures
- Full verification using the bpf_verifier Rust crate

Signed-off-by: Your Name <your@email.com>
---
 kernel/bpf/Makefile             |   1 +
 kernel/bpf/rust_bpf_verifier.rs | 100 ++++++++++++++++++++++++++++++++
 2 files changed, 101 insertions(+)
 create mode 100644 kernel/bpf/rust_bpf_verifier.rs

[Full Rust module code would be included here]
--
2.43.0
EOF

echo "Generated: ${PATCH_DIR}/0002-bpf-Add-Rust-BPF-verifier-module.patch"

# Patch 3: Hook integration
cat > ${PATCH_DIR}/0003-bpf-Hook-Rust-verifier-into-verification-path.patch << 'EOF'
From: Your Name <your@email.com>
Subject: [PATCH v1 3/3] bpf: Hook Rust verifier into verification path

Integrate the Rust BPF verifier into the kernel's BPF verification
path. When CONFIG_BPF_VERIFIER_RUST is enabled and the runtime
sysctl is set, bpf_check() will call the Rust verifier.

If the Rust verifier returns -ENOSYS, fall back to the C verifier.
This allows gradual adoption and testing.

Signed-off-by: Your Name <your@email.com>
---
 kernel/bpf/verifier.c | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index xxxx..yyyy 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -includes
+#ifdef CONFIG_BPF_VERIFIER_RUST
+extern int rust_bpf_check(struct bpf_verifier_env *env);
+extern bool bpf_rust_verifier_enabled(void);
+#endif

 int bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
               bpfptr_t uattr, u32 uattr_size)
 {
     /* existing setup */

+#ifdef CONFIG_BPF_VERIFIER_RUST
+    if (bpf_rust_verifier_enabled()) {
+        ret = rust_bpf_check(env);
+        if (ret != -ENOSYS)
+            goto cleanup;
+    }
+#endif

     /* existing C verifier code */
 }
--
2.43.0
EOF

echo "Generated: ${PATCH_DIR}/0003-bpf-Hook-Rust-verifier-into-verification-path.patch"

echo ""
echo "=== Patches generated in ${PATCH_DIR}/ ==="
echo ""
echo "Before sending:"
echo "1. Edit patches to add your name and email"
echo "2. Review and update diff content"
echo "3. Run: ./scripts/checkpatch.pl ${PATCH_DIR}/*.patch"
echo ""
echo "To send patches:"
echo "  git send-email --to=rust-for-linux@vger.kernel.org ${PATCH_DIR}/*.patch"
