#![feature(slicing_syntax)]

extern crate secrets;
extern crate libc;

use secrets::Secret;
use std::slice;

#[test]
fn test_create_empty_secret() {
    let secret = Secret::empty(4);

    assert_eq!(secret.len(), 4);
}

#[test]
fn test_create_null_secret() {
    let secret = Secret::empty(0);

    assert_eq!(secret.len(), 0);
}

#[test]
fn test_create_secret_from_bytes() {
    let bytes  = &mut [0, 1, 2, 3];
    let secret = Secret::new(bytes);

    assert!(secret.read() == [0, 1, 2, 3]);
}

#[test]
fn test_create_secret_clears_input_bytes() {
    let bytes = &mut [0, 1, 2, 3];

    Secret::new(bytes);

    assert_eq!(bytes[], [0, 0, 0, 0]);
}

#[test]
fn test_secret_self_referential_equality() {
    let secret = Secret::new(&mut [192, 168, 1, 1]);

    assert!(secret == secret);
}

#[test]
fn test_secret_equality() {
    let s1 = Secret::new(&mut [3, 4, 1, 9]);
    let s2 = Secret::new(&mut [3, 4, 1, 9]);

    assert!(s1 == s2);
    assert!(s2 == s1);
}

#[test]
fn test_secret_inequality() {
    let s1 = Secret::new(&mut [255, 255, 255, 0]);
    let s2 = Secret::new(&mut [255, 255, 255, 1]);

    assert!(s1 != s2);
    assert!(s2 != s1);
}

#[test]
fn test_secret_clone() {
    let s1 = Secret::new(&mut [0, 1, 2, 3, 4, 5]);
    let s2 = s1.clone();

    assert!(s1 == s2);
}

#[test]
fn test_secret_add() {
    let s1 = Secret::new(&mut [1, 2]);
    let s2 = Secret::new(&mut [3]);
    let s3 = Secret::new(&mut [1, 2, 3]);

    assert!(s1 + s2 == s3);
}

#[test]
fn test_secret_write() {
    let mut secret = Secret::empty(2);
    let mut slice  = secret.write();

    slice::bytes::copy_memory(&mut *slice, &[42]);
    assert!(slice == [42, 0xd0]);
}

#[test]
fn test_secret_slice() {
    let s1 = Secret::new(&mut [100, 101]);
    let s2 = s1.slice(0, 0);
    let s3 = s1.slice(1, 2);
    let s4 = s1.slice(0, 2);

    assert_eq!(&*s2.read(), []);
    assert_eq!(&*s3.read(), [101]);

    assert!(s1 == s4);
}

#[test]
#[should_fail(expected = "out of bounds")]
fn test_secret_slice_overflow() {
    Secret::empty(256).slice(256, 257);
}

#[test]
#[should_fail(expected = "negative-length slice")]
fn test_secret_slice_negative_length() {
    Secret::empty(95).slice(51, 50);
}
