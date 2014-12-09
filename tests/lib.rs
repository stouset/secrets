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
        assert!(slice == &[0, 1, 2, 3])
    });
}

#[test]
fn test_create_secret_clears_input_bytes() {
    let bytes = &mut [0, 1, 2, 3];

    Secret::new(bytes);

    assert!(bytes.iter().all (|x| { *x == 0 }))
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
        assert!(slice == &[1, 0xd0]);
    });
}

#[test]
fn test_secret_slice() {
    let s1 = Secret::new(&mut [100, 101]);
    let s2 = s1.slice(0, 0);
    let s3 = s1.slice(1, 1);

    s2.read(|slice| {
        assert!(slice == &[100])
    });

    s3.read(|slice| {
        assert!(slice == &[101])
    });
}

#[test]
#[should_fail]
fn test_secret_slice_overflow() {
    let secret = Secret::empty(256);

    secret.slice(256, 256);
}

#[test]
fn test_secret_split() {
    let s1       = Secret::new(&mut [47, 41, 210, 0, 0, 1]);
    let (s2, s3) = s1.split(2);

    s2.read(|slice| {
        assert!(slice == &[47, 41])
    });

    s3.read(|slice| {
        assert!(slice == &[210, 0, 0, 1])
    })
}
