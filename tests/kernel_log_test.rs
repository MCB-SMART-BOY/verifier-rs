// SPDX-License-Identifier: GPL-2.0

//! Tests for kernel logging utilities.

#![cfg(feature = "kernel")]

use bpf_verifier::kernel::log::{LogLevel, VerifierLog};

#[test]
fn test_verifier_log_basic() {
    let mut log = VerifierLog::new(1024);
    assert!(log.is_enabled());
    assert!(log.is_empty());

    log.write("Hello");
    assert_eq!(log.len(), 5);
    assert_eq!(log.as_str(), "Hello");

    log.writeln(" World");
    assert_eq!(log.as_str(), "Hello World\n");
}

#[test]
fn test_verifier_log_truncation() {
    let mut log = VerifierLog::new(10);
    log.write("This is a long message");

    assert!(log.is_truncated());
    assert_eq!(log.len(), 10);
    assert_eq!(log.as_str(), "This is a ");
}

#[test]
fn test_verifier_log_disabled() {
    let mut log = VerifierLog::new(0);
    assert!(!log.is_enabled());

    log.write("This should not be logged");
    assert!(log.is_empty());
}

#[test]
fn test_log_level() {
    let log = VerifierLog::with_level(1024, LogLevel::Warning);

    assert!(log.is_level_enabled(LogLevel::Error));
    assert!(log.is_level_enabled(LogLevel::Warning));
    assert!(!log.is_level_enabled(LogLevel::Info));
    assert!(!log.is_level_enabled(LogLevel::Debug));
}

#[test]
fn test_log_level_names() {
    assert_eq!(LogLevel::Error.name(), "ERROR");
    assert_eq!(LogLevel::Warning.name(), "WARN");
    assert_eq!(LogLevel::Info.name(), "INFO");
}
