// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::core::log

use bpf_verifier::prelude::*;
use bpf_verifier::core::log::*;


    #[test]
    fn test_log_levels() {
        let log = VerifierLog::new(LogLevel::Info);
        assert!(log.enabled(LogLevel::Error));
        assert!(log.enabled(LogLevel::Warn));
        assert!(log.enabled(LogLevel::Info));
        assert!(!log.enabled(LogLevel::Debug));
        assert!(!log.enabled(LogLevel::Trace));
    }

    #[test]
    fn test_log_messages() {
        let mut log = VerifierLog::new(LogLevel::Info);
        log.error("error message");
        log.warn("warn message");
        log.info("info message");
        log.debug("debug message"); // Should not appear

        let contents = log.contents();
        assert!(contents.contains("error message"));
        assert!(contents.contains("warn message"));
        assert!(contents.contains("info message"));
        assert!(!contents.contains("debug message"));
    }

    #[test]
    fn test_log_truncation() {
        let mut log = VerifierLog::with_max_size(LogLevel::Info, 50);
        log.info("this is a fairly long message that will be truncated");
        
        // Buffer should indicate truncation
        assert!(log.truncated);
    }

    #[test]
    fn test_fmt_insn() {
        let insn = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 42);
        let s = fmt_insn(&insn, 5);
        assert!(s.contains("5:"));
        assert!(s.contains("add"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_fmt_reg_scalar() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::ScalarValue;
        reg.umin_value = 0;
        reg.umax_value = 100;
        
        let s = fmt_reg(&reg, 1);
        assert!(s.contains("R1"));
        assert!(s.contains("scalar"));
    }

    #[test]
    fn test_fmt_reg_ptr() {
        let mut reg = BpfRegState::default();
        reg.reg_type = BpfRegType::PtrToStack;
        reg.off = -8;
        
        let s = fmt_reg(&reg, 10);
        assert!(s.contains("R10"));
        assert!(s.contains("fp"));
        assert!(s.contains("-8"));
    }
