// SPDX-License-Identifier: GPL-2.0
//! Tests for bpf_verifier::bounds::tnum

use bpf_verifier::prelude::*;


#[test]
fn test_const() {
    let t = Tnum::const_value(42);
    assert!(t.is_const());
    assert_eq!(t.value, 42);
    assert_eq!(t.mask, 0);
}

#[test]
fn test_unknown() {
    let t = Tnum::unknown();
    assert!(!t.is_const());
    assert_eq!(t.mask, u64::MAX);
}

#[test]
fn test_range() {
    let t = Tnum::range(0, 255);
    assert_eq!(t.value, 0);
    assert_eq!(t.mask, 255);

    let t2 = Tnum::range(0, 0);
    assert!(t2.is_const());
    assert_eq!(t2.value, 0);
}

#[test]
fn test_add() {
    let a = Tnum::const_value(5);
    let b = Tnum::const_value(3);
    let c = a.add(b);
    assert!(c.is_const());
    assert_eq!(c.value, 8);
}

#[test]
fn test_and() {
    let a = Tnum::const_value(0xFF);
    let b = Tnum::const_value(0x0F);
    let c = a & b;
    assert!(c.is_const());
    assert_eq!(c.value, 0x0F);
}

#[test]
fn test_or() {
    let a = Tnum::const_value(0xF0);
    let b = Tnum::const_value(0x0F);
    let c = a | b;
    assert!(c.is_const());
    assert_eq!(c.value, 0xFF);
}

#[test]
fn test_intersect() {
    let a = Tnum::new(0x10, 0x0F); // 0x1? where ? is unknown
    let b = Tnum::new(0x12, 0x01); // 0x12 or 0x13
    let c = a.intersect(b);
    assert_eq!(c.value, 0x12);
    assert_eq!(c.mask, 0x01);
}
