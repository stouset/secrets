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
fn test_create_secret_from_bytes() {
    let bytes  = &mut [0, 1, 2, 3];
    let secret = Secret::new(bytes);

    secret.read(|slice| {
        assert_eq!(slice, [0, 1, 2, 3]);
    });
}

#[test]
fn test_create_secret_clears_input_bytes() {
    let bytes = &mut [0, 1, 2, 3];

    Secret::new(bytes);

    assert_eq!(bytes.as_slice(), [0, 0, 0, 0]);
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
fn test_secret_write() {
    let mut secret = Secret::empty(2);

    secret.write(|slice| {
        slice::bytes::copy_memory(slice, &[1]);
    });

    secret.read(|slice| {
        // 0xd0 is the value of uninitialized memory returned by
        // sodium_malloc
        assert_eq!(slice, [1, 0xd0]);
    });
}

#[test]
fn test_secret_slice() {
    let s1 = Secret::new(&mut [100, 101]);
    let s2 = s1.slice(0, 0);
    let s3 = s1.slice(1, 1);
    let s4 = s1.slice(0, 1);

    s2.read(|slice| {
        assert_eq!(slice, [100]);
    });

    s3.read(|slice| {
        assert_eq!(slice, [101]);
    });

    assert!(s1 == s4);
}

#[test]
#[should_fail(expected = "out of bounds")]
fn test_secret_slice_overflow() {
    Secret::empty(256).slice(256, 256);
}

#[test]
#[should_fail(expected = "negative-length slice")]
fn test_secret_slice_negative_length() {
    Secret::empty(95).slice(51, 50);
}
