# Email Templates for Kernel Submission

This document contains email templates for communicating with Linux kernel maintainers
during the RFC and patch submission process.

---

## Template 1: Initial RFC Submission Email

**To:** rust-for-linux@vger.kernel.org
**Cc:** bpf@vger.kernel.org, linux-kernel@vger.kernel.org
**Subject:** [RFC PATCH 0/1] Rust BPF Verifier Implementation
**Format:** Plain text (NO HTML)

```
Hello Rust for Linux and BPF maintainers,

I would like to submit an RFC for a complete Rust implementation of the
Linux kernel's BPF verifier (kernel/bpf/verifier.c) as part of the Rust
for Linux project.

# Overview

This implementation provides memory-safe BPF program verification while
maintaining 94% feature parity with the upstream C implementation in
Linux 6.18. The project is designed as a #![no_std] library for seamless
kernel module integration.

# Key Features

Core Verification (100%):
- Register state tracking (11 registers with type and bounds)
- Memory safety validation (stack, map, packet, context, arena)
- Control flow analysis and reference tracking
- Bounds analysis using Tnum (tracked numbers)

Linux 6.13-6.18 Features (100%):
- Load-Acquire/Store-Release atomic instructions
- may_goto bounded loops with 8192 iteration limit
- Linked Registers for precision tracking
- Private Stack per-subprogram isolation
- Fastcall optimization for 7 high-frequency helpers
- BPF Features runtime flags
- Extended Dynptr types (SkbMeta, File)
- Call Summary caching optimization

Helper Functions & Kfuncs:
- 211 BPF helper function validation
- 85+ Kfunc verification (synced with kernel 6.18)

# Benefits

1. Memory Safety: Rust's ownership system eliminates use-after-free,
   buffer overflows, and null pointer dereferences
2. Maintainability: Clearer type system reduces bugs and improves code clarity
3. Performance: Zero-cost abstractions maintain C-level performance
4. Testing: Comprehensive test suite (900+ tests, all passing)

# Code Quality

- Zero compiler warnings
- Zero clippy warnings
- GPL-2.0-only license (kernel-compatible)
- Comprehensive documentation
- Benchmark suite available

# Repository

Development repository: https://github.com/MCB-SMART-BOY/verifier-rs

Complete documentation including CHANGELOG, architecture details, and
submission guidelines are available in the repository.

# Request for Comments

I am seeking feedback on:

1. Architecture: Is the module organization appropriate for kernel integration?
2. API Design: Are the public APIs suitable for kernel use?
3. Performance: Any concerns about runtime performance vs C implementation?
4. Integration Path: Best approach for integration into Rust for Linux?
5. Testing: Additional kernel-specific tests needed?

The attached patch contains the complete implementation. If accepted, I can
split this into a logical patch series for easier review.

Thank you for your time and consideration. I look forward to your feedback.

Best regards,
MCB-SMART-BOY

Signed-off-by: MCB-SMART-BOY <mcb2720838051@gmail.com>
```

---

## Template 2: Response to Initial Feedback

**Subject:** Re: [RFC PATCH 0/1] Rust BPF Verifier Implementation
**Format:** Plain text, inline replies

```
On [Date], [Reviewer Name] wrote:
> [Reviewer's comment]

Thank you for the feedback! I'll address your points below:

> [Specific technical question or concern]

[Your detailed technical response explaining the implementation choice,
providing code references, or acknowledging the issue]

[If changes needed:]
I'll make this change in v2 of the patch. The updated approach will be:
[Brief description of planned change]

[If clarification needed:]
To clarify the current implementation: [detailed explanation with
code references like src/check/helper.rs:123]

> [Another comment]

[Your response]

[Closing]
Thank you again for the thorough review. I'll prepare v2 addressing
these points and post it by [reasonable timeframe].

Best regards,
MCB-SMART-BOY
```

---

## Template 3: Submitting Patch v2 (After Revisions)

**To:** rust-for-linux@vger.kernel.org
**Cc:** bpf@vger.kernel.org, linux-kernel@vger.kernel.org
**Subject:** [RFC PATCH v2 0/1] Rust BPF Verifier Implementation

```
Hello,

This is version 2 of the Rust BPF verifier implementation RFC,
addressing feedback from the initial submission.

# Changes in v2

- Fixed [specific issue] as suggested by [Reviewer Name]
  [Brief technical description of the fix]

- Added [new feature/test] per [Reviewer Name]'s recommendation
  [Brief description]

- Improved [aspect] to address concerns about [topic]
  [Brief description]

- Updated documentation to clarify [topic]

# Unchanged from v1

The core architecture and feature set remain the same:
- 94% feature parity with Linux 6.18
- 211 helper functions, 85+ kfuncs
- All 900+ tests passing
- Zero warnings

# Outstanding Questions

[If any questions remain unresolved from v1 discussion]

Thank you to everyone who provided feedback on v1. The discussion
helped improve the implementation significantly.

Best regards,
MCB-SMART-BOY

Signed-off-by: MCB-SMART-BOY <mcb2720838051@gmail.com>
```

---

## Template 4: Following Up (If No Response After 2-3 Weeks)

**Subject:** Re: [RFC PATCH 0/1] Rust BPF Verifier Implementation

```
Hello,

I wanted to follow up on the RFC I submitted on [date] for a Rust
implementation of the BPF verifier.

I understand maintainers are busy, and I'm happy to wait for feedback.
I'm sending this note to ensure the submission didn't get lost in the
mailing list traffic.

If there are any immediate concerns or if I should resubmit in a
different format, please let me know.

Thank you for your time.

Best regards,
MCB-SMART-BOY
```

---

## Template 5: Thanking Reviewers

**Subject:** Re: [RFC PATCH 0/1] Rust BPF Verifier Implementation

```
On [Date], [Reviewer Name] wrote:
> [Review comments]

Thank you for the detailed and thoughtful review! Your feedback is
invaluable and has helped identify several important areas for
improvement.

I appreciate you taking the time to review this thoroughly. I'll
implement these suggestions and submit v2 soon.

Best regards,
MCB-SMART-BOY
```

---

## Template 6: Addressing Critical Issues

**Subject:** Re: [RFC PATCH 0/1] Rust BPF Verifier Implementation

```
On [Date], [Reviewer Name] wrote:
> [Critical issue identified]

Thank you for catching this critical issue. You're absolutely right
that [acknowledgment of the problem].

I've investigated this and found that [root cause analysis].

The fix is [proposed solution with technical details].

I'll include this fix in v2 along with additional tests to prevent
regression:
- [Test case 1]
- [Test case 2]

Would this approach address your concerns?

Best regards,
MCB-SMART-BOY
```

---

## Template 7: Request for Testing Help

**Subject:** [RFC PATCH 0/1] Rust BPF Verifier - Testing Request
**To:** rust-for-linux@vger.kernel.org

```
Hello,

I've submitted an RFC for a Rust BPF verifier implementation and would
appreciate help testing it in various environments.

Repository: https://github.com/MCB-SMART-BOY/verifier-rs

Testing needed:
- Different architectures (ARM, x86_64, RISC-V)
- Various BPF program types
- Edge cases in verification
- Performance comparison with C verifier

To test:
```bash
git clone https://github.com/MCB-SMART-BOY/verifier-rs
cd verifier-rs
cargo test --all-features
cargo bench
```

Any feedback on bugs, performance, or API design would be greatly
appreciated.

Thank you,
MCB-SMART-BOY
```

---

## Template 8: Patch Split Proposal

**Subject:** Re: [RFC PATCH 0/1] Rust BPF Verifier Implementation

```
On [Date], [Reviewer Name] wrote:
> This patch is quite large. Consider splitting it for easier review.

Thank you for the suggestion. I propose splitting the implementation
into the following logical patch series:

 1/10: rust: bpf: Add core types and error handling
 2/10: rust: bpf: Add state management infrastructure
 3/10: rust: bpf: Add bounds tracking (Tnum)
 4/10: rust: bpf: Add analysis passes (CFG, pruning)
 5/10: rust: bpf: Add instruction verification (ALU, jump)
 6/10: rust: bpf: Add helper and kfunc verification
 7/10: rust: bpf: Add memory access verification
 8/10: rust: bpf: Add special features (dynptr, iterator)
 9/10: rust: bpf: Add BTF integration
10/10: rust: bpf: Add optimization passes and Linux 6.13-6.18 features

Each patch will be independently compilable and testable.

Does this split make sense? Should I adjust the granularity?

Best regards,
MCB-SMART-BOY
```

---

## Email Best Practices

### Format Rules
1. **Always use plain text** (no HTML formatting)
2. **Reply inline** (interleaved, not top-posting)
3. **Wrap lines at 72-75 characters**
4. **Use standard quote marker** (> for quoted text)
5. **No attachments** (inline patches preferred)

### Content Guidelines
1. **Be professional and respectful**
2. **Be concise but complete**
3. **Provide technical details with code references**
4. **Acknowledge mistakes graciously**
5. **Thank reviewers for their time**
6. **Respond to all points raised**

### Timing
1. **Don't rush responses** - take time to think through technical issues
2. **Don't be impatient** - maintainers respond when available
3. **Follow up after 2-3 weeks** if no response
4. **Respond within 1-2 days** to reviewer questions

### Technical Details
1. **Include file paths and line numbers** when referencing code
2. **Quote relevant code snippets** for context
3. **Link to documentation** when explaining design choices
4. **Provide test results** to demonstrate fixes
5. **Use git commit references** when discussing history

---

## Common Scenarios

### Scenario: Reviewer Disagrees with Design Choice

```
I understand your concern about [design choice]. The reason I chose
this approach is [technical justification with references].

However, I see the merit in your suggestion of [alternative approach].
The tradeoffs are:

Current approach:
  + [Advantages]
  - [Disadvantages]

Suggested approach:
  + [Advantages]
  - [Disadvantages]

I'm happy to change to the suggested approach if that's the preference
of the maintainers. Which would you prefer?
```

### Scenario: Unable to Implement Suggestion

```
Thank you for the suggestion to [requested change]. Unfortunately,
implementing this would require [technical blocker], which isn't
feasible because [reason].

As an alternative, I could [alternative approach] which would achieve
[similar benefits] while avoiding [blocker].

Would this alternative be acceptable?
```

### Scenario: Need Clarification on Feedback

```
Thank you for the feedback. I want to make sure I understand your
concern correctly.

You mentioned that [paraphrase of concern]. Do you mean that
[interpretation 1] or [interpretation 2]?

Once I understand the concern better, I can propose an appropriate
solution.
```

---

**Author:** MCB-SMART-BOY <mcb2720838051@gmail.com>
**Repository:** https://github.com/MCB-SMART-BOY/verifier-rs
**Date:** December 2025
