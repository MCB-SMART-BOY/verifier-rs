# Linux Kernel Submission Guide for BPF Verifier Rust Implementation

This document provides step-by-step instructions for submitting the Rust BPF verifier
to the Linux kernel community.

## Prerequisites

1. **Git Setup**
   ```bash
   git config --global user.name "MCB-SMART-BOY"
   git config --global user.email "mcb2720838051@gmail.com"
   ```

2. **Email Client**
   - Install `git-email`: `sudo apt-get install git-email`
   - Configure SMTP settings for sending patches via email

## Submission Process

### Step 1: Prepare Patch Series

The code is already committed. To generate patches for kernel submission:

```bash
# Generate patch from latest commit
git format-patch -1 HEAD --subject-prefix="RFC PATCH" \
  --add-header="To: rust-for-linux@vger.kernel.org" \
  --add-header="Cc: bpf@vger.kernel.org" \
  --add-header="Cc: linux-kernel@vger.kernel.org"
```

### Step 2: Review Patch Format

Each patch must follow Linux kernel standards:

**Subject Line Format:**
```
[RFC PATCH] rust: bpf: Add Rust implementation of BPF verifier
```

**Commit Message Structure:**
```
Short subject (50 chars max)

Detailed description explaining:
- What changes are being made
- Why these changes are needed
- How the implementation works
- Any relevant background

Signed-off-by: MCB-SMART-BOY <mcb2720838051@gmail.com>
```

### Step 3: Add Developer's Certificate of Origin

All patches MUST include `Signed-off-by` line certifying:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Step 4: Send RFC Patch

**Option A: Using git send-email (Recommended)**

```bash
# Configure git send-email
git config sendemail.smtpserver smtp.gmail.com
git config sendemail.smtpserverport 587
git config sendemail.smtpencryption tls
git config sendemail.smtpuser mcb2720838051@gmail.com

# Send the patch
git send-email \
  --to=rust-for-linux@vger.kernel.org \
  --cc=bpf@vger.kernel.org \
  --cc=linux-kernel@vger.kernel.org \
  --subject-prefix="RFC PATCH" \
  0001-*.patch
```

**Option B: Manual Email**

1. Generate patch file: `git format-patch -1 HEAD`
2. Open your email client
3. Create plain-text email (NO HTML formatting)
4. Paste RFC_COVER_LETTER.md as email body
5. Attach the generated .patch file
6. Send to: rust-for-linux@vger.kernel.org
7. Cc: bpf@vger.kernel.org, linux-kernel@vger.kernel.org

### Step 5: Respond to Feedback

After submission, monitor the mailing lists for responses:

1. **Subscribe to Mailing Lists**
   ```bash
   # Send email to these addresses with subject "subscribe"
   majordomo@vger.kernel.org
   ```
   Body: `subscribe rust-for-linux`
   Body: `subscribe bpf`

2. **Read All Feedback**
   - Check https://lore.kernel.org/rust-for-linux/
   - Set up email filters for thread tracking

3. **Respond Professionally**
   - Reply inline (interleaved style, not top-posting)
   - Address all technical concerns
   - Be open to suggestions and criticism
   - Thank reviewers for their time

4. **Submit Revised Versions**
   - If changes requested, make updates
   - Generate new patch with version: `[RFC PATCH v2]`
   - Include changelog in cover letter:
     ```
     v2 changes:
     - Fixed issue X as suggested by Reviewer Y
     - Added test case for scenario Z
     ```

## Kernel Coding Style Compliance

Before submission, verify code follows kernel standards:

```bash
# Check for coding style issues (if checkpatch.pl available)
# Note: Rust code has different style than C, use clippy instead
cargo clippy --all-targets --all-features

# Ensure all tests pass
cargo test --all-features

# Build without warnings
cargo build --release
```

## Key Contacts

### Mailing Lists
- **Primary**: rust-for-linux@vger.kernel.org
- **Secondary**: bpf@vger.kernel.org
- **General**: linux-kernel@vger.kernel.org

### Maintainers
Use `scripts/get_maintainers.pl` from Linux kernel source to identify:
- Rust for Linux maintainers
- BPF subsystem maintainers
- Relevant reviewers

### Resources
- Rust for Linux: https://rust-for-linux.com/contributing
- BPF Documentation: https://docs.kernel.org/bpf/
- Submitting Patches: https://docs.kernel.org/process/submitting-patches.html
- Email Clients: https://docs.kernel.org/process/email-clients.html

## Timeline Expectations

- **Initial Response**: 1-2 weeks (maintainers review when available)
- **Review Cycles**: 2-5 rounds of feedback/revision common
- **Acceptance**: Can take 3-6 months for major new features
- **Merge Window**: Accepted patches merged during next merge window

## Common Pitfalls to Avoid

1. **HTML Emails**: Always use plain text
2. **Attachments**: Inline patches preferred over attachments
3. **Threading**: Keep discussions in same email thread
4. **Top-Posting**: Always reply inline
5. **Missing Sign-off**: Every patch needs Signed-off-by
6. **Large Patches**: Consider splitting if reviewers request
7. **Impatience**: Don't ping maintainers, they'll respond when available

## After Acceptance

If accepted for inclusion:

1. Patch will be merged into rust-next or bpf-next tree
2. Will be part of next Linux kernel release
3. Ongoing maintenance responsibility
4. Continue monitoring bug reports and feedback

## License

This submission uses GPL-2.0-only license, compatible with Linux kernel.
All files include SPDX-License-Identifier headers.

---

**Author:** MCB-SMART-BOY <mcb2720838051@gmail.com>
**Repository:** https://github.com/MCB-SMART-BOY/verifier-rs
**Date:** December 2025
