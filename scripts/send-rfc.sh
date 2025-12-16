#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Script to send RFC email to Rust for Linux mailing list
#
# Usage: ./scripts/send-rfc.sh [--dry-run]

set -e

# Configuration - EDIT THESE
YOUR_NAME="Your Name"
YOUR_EMAIL="your@email.com"

# Mailing lists
TO_LIST="rust-for-linux@vger.kernel.org"
CC_LIST="bpf@vger.kernel.org"
CC_MAINTAINERS="ast@kernel.org,daniel@iogearbox.net,ojeda@kernel.org,andrii@kernel.org"

# Check for dry-run mode
DRY_RUN=""
if [ "$1" == "--dry-run" ]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN MODE ==="
fi

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    
    if ! command -v git &> /dev/null; then
        echo "Error: git not found"
        exit 1
    fi
    
    # Check git send-email configuration
    if ! git config --get sendemail.smtpserver &> /dev/null; then
        echo "Error: git send-email not configured"
        echo ""
        echo "Please configure git send-email first:"
        echo "  git config --global sendemail.smtpserver smtp.gmail.com"
        echo "  git config --global sendemail.smtpserverport 587"
        echo "  git config --global sendemail.smtpencryption tls"
        echo "  git config --global sendemail.smtpuser your@gmail.com"
        echo ""
        exit 1
    fi
    
    echo "Prerequisites OK"
}

# Create RFC email file
create_rfc_email() {
    echo "Creating RFC email..."
    
    cat > /tmp/rfc-email.txt << EOF
From: ${YOUR_NAME} <${YOUR_EMAIL}>
To: ${TO_LIST}
Cc: ${CC_LIST}, ${CC_MAINTAINERS}
Subject: [RFC] Rust implementation of BPF verifier

Hi everyone,

With Rust now officially adopted as a core language in the Linux kernel
(2025 Kernel Maintainer Summit), I would like to propose a Rust
implementation of the BPF verifier for consideration.

== Motivation ==

The BPF verifier (kernel/bpf/verifier.c) is ~30,000 lines of complex C
code. A Rust implementation provides:

1. Compile-time safety via Rust's ownership model
2. Type-safe state tracking for registers and bounds
3. Reduced attack surface with strict aliasing rules
4. Better maintainability with pattern matching

== Implementation Status ==

~78,000 lines (including tests), feature-complete:

- Full register state tracking (R0-R10)
- Tnum arithmetic for precise bounds
- 211 BPF helper function signatures
- 85+ kfunc definitions (synced with 6.12)
- State pruning with hash-indexed equivalence
- Reference tracking (locks, RCU, acquired refs)
- IRQ flag state tracking
- Memory verification (stack, packet, context, map, arena)
- Spectre v1/v4 mitigation checks
- 300+ unit tests

Technical characteristics:
- #![no_std] compatible
- GPL-2.0-only license
- Pure Rust - no C glue code (Linux 6.12+ style)

== Benchmark Results ==

  Test                    Time
  ----------------------- -----------
  simple_verification     ~14.6 µs
  medium_verification     ~28.7 µs
  complex_verification    ~736 µs
  state_creation          ~406 ns
  bounds_operations       ~5.8 ns

== Integration Approach ==

Using native kernel::Module trait:

  use kernel::prelude::*;

  module! {
      type: RustBpfVerifier,
      name: "rust_bpf_verifier",
      license: "GPL",
  }

Configuration:
  CONFIG_BPF_VERIFIER_RUST=y
  echo 1 > /proc/sys/kernel/bpf_rust_verifier

== Questions for Community ==

1. Is there interest in a Rust BPF verifier now that Rust is official?
2. Should it replace, coexist with, or supplement the C verifier?
3. What kernel crate APIs need to be added for BPF?
4. What validation/benchmarks are required for acceptance?

Repository: https://github.com/MCB-SMART-BOY/verifier-rs

I welcome any feedback, questions, or concerns.

Best regards,
${YOUR_NAME}
EOF

    echo "RFC email created at /tmp/rfc-email.txt"
}

# Send the email
send_email() {
    echo "Sending RFC email..."
    
    git send-email \
        --to="${TO_LIST}" \
        --cc="${CC_LIST}" \
        --cc="${CC_MAINTAINERS}" \
        --confirm=always \
        ${DRY_RUN} \
        /tmp/rfc-email.txt
    
    if [ -z "$DRY_RUN" ]; then
        echo ""
        echo "=== RFC email sent successfully! ==="
        echo ""
        echo "Next steps:"
        echo "1. Monitor rust-for-linux@vger.kernel.org for responses"
        echo "2. Reply to feedback within 1-2 days"
        echo "3. Prepare patches based on community input"
    fi
}

# Main
echo "=== Rust BPF Verifier RFC Sender ==="
echo ""

check_prerequisites
create_rfc_email

echo ""
echo "Review the email at /tmp/rfc-email.txt"
echo ""
read -p "Send the RFC email? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    send_email
else
    echo "Aborted. Email saved at /tmp/rfc-email.txt"
fi
