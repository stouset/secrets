//! Rust bindings to libsodium functions.

#![allow(unsafe_code)]

use std::mem;
use std::ptr;
use std::sync::{Once, ONCE_INIT};

use libc::{c_int, c_void, size_t};

static     INIT:        Once = ONCE_INIT;
static mut INITIALIZED: bool = false;

#[link(name = "sodium")]
extern "C" {
    fn sodium_init() -> c_int;

    fn sodium_allocarray(count: size_t, size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_mprotect_noaccess(ptr: *const c_void) -> c_int;
    fn sodium_mprotect_readonly(ptr: *const c_void) -> c_int;
    fn sodium_mprotect_readwrite(ptr: *const c_void) -> c_int;

    fn sodium_memcmp(l: *const c_void, r: *const c_void, len: size_t) -> c_int;
    fn sodium_memzero(ptr: *mut c_void, len: size_t);

    fn randombytes_buf(ptr: *mut c_void, len: size_t);
}

pub(crate) fn init() -> bool {
    unsafe {
        INIT.call_once(|| {
            // TODO: https://www.reddit.com/r/rust/comments/6e0s3g/asserting_static_properties_in_rust/
            // assert sizeof for casts
            debug_assert_eq!(mem::size_of::<usize>(), mem::size_of::<size_t>());

            INITIALIZED = sodium_init() != -1;
        });

        INITIALIZED
    }
}

pub(crate) unsafe fn allocarray<T>(count: usize) -> *mut T {
    sodium_allocarray(count, mem::size_of::<T>()) as *mut _
}

pub(crate) unsafe fn free<T>(ptr: *mut T) {
    sodium_free(ptr as *mut _)
}

pub(crate) unsafe fn mprotect_noaccess<T>(ptr: *const T) -> bool {
    sodium_mprotect_noaccess(ptr as *const _) == 0
}

pub(crate) unsafe fn mprotect_readonly<T>(ptr: *const T) -> bool {
    sodium_mprotect_readonly(ptr as *const _) == 0
}

pub(crate) unsafe fn mprotect_readwrite<T>(ptr: *const T) -> bool {
    sodium_mprotect_readwrite(ptr as *const _) == 0
}

/// Compares `l` and `r` for equality in constant time, preventing side-channel
/// attacks when comparing equality of secret data. `l` and `r` *must* be of the
/// same length.
pub(crate) fn memcmp(l: &[u8], r: &[u8]) -> bool {
    debug_assert_eq!(l.len(), r.len());

    unsafe {
        sodium_memcmp(
            l.as_ptr() as *const _,
            r.as_ptr() as *const _,
            r.len(),
        ) == 0
    }
}

/// Copies bytes from `src` to `dst` before zeroing the bytes in `src`. `dst`
/// *must* be at least as long as `src` and *must not* overlap `src`.
pub(crate) unsafe fn memtransfer(src: &mut [u8], dst: &mut [u8]) {
    debug_assert!(src.len() <= dst.len());

    // based on the requirements of `ptr::copy_nonoverlapping`, we need
    // to ensure that either:
    //
    //   * `src` is lower than `dst` and `src` doesn't extend into `dst`, or
    //   * `src` is higher than `dst` and so we can write into `dst` without
    //     accidentally clobbering unread bytes of `src`
    debug_assert!(
        (src.as_ptr() < dst.as_ptr() && src.as_ptr().add(src.len()) <= dst.as_ptr()) ||
        (src.as_ptr() > dst.as_ptr())
    );

    ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    memzero(src);
}

/// Fills `bytes` with zeroes.
pub(crate) fn memzero(bytes: &mut [u8]) {
    unsafe { sodium_memzero(bytes.as_mut_ptr() as *mut _, bytes.len()) }
}

/// Fills `ptr` with `count` random bytes.
pub(crate) fn memrandom(bytes: &mut [u8]) {
    unsafe { randombytes_buf(bytes.as_mut_ptr() as *mut _, bytes.len()) }
}
