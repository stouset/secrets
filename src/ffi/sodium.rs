//! Rust bindings to libsodium functions.

#![allow(unsafe_code)]

use std::mem;
use std::sync::{Once, ONCE_INIT};

use libc::{self, c_int, c_void, size_t};

static     INIT:        Once = ONCE_INIT;
static mut INITIALIZED: bool = false;

#[cfg(test)]
thread_local! {
    static FAIL: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

extern "C" {
    fn sodium_init() -> c_int;

    fn sodium_allocarray(count: size_t, size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_mlock(ptr: *mut c_void, len: size_t) -> c_int;
    fn sodium_munlock(ptr: *mut c_void, len: size_t) -> c_int;

    fn sodium_mprotect_noaccess(ptr: *mut c_void) -> c_int;
    fn sodium_mprotect_readonly(ptr: *mut c_void) -> c_int;
    fn sodium_mprotect_readwrite(ptr: *mut c_void) -> c_int;

    fn sodium_memcmp(l: *const c_void, r: *const c_void, len: size_t) -> c_int;
    fn sodium_memzero(ptr: *mut c_void, len: size_t);

    fn randombytes_buf(ptr: *mut c_void, len: size_t);
}

#[cfg(test)]
pub(crate) fn fail() {
    FAIL.with(|f| f.set(true))
}

pub(crate) fn init() -> bool {
    unsafe {
        #[cfg(test)]
        { if FAIL.with(|f| f.get()) { return false } };

        INIT.call_once(|| {
            // TODO: https://www.reddit.com/r/rust/comments/6e0s3g/asserting_static_properties_in_rust/
            // assert sizeof for casts
            debug_assert_eq!(mem::size_of::<usize>(), mem::size_of::<size_t>());

            // core dumps should be disabled for any programs dealing with
            // cryptographic secrets
            let rlimit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            // sodium_init returns 0 on success, -1 on failure, and 1 if
            // the library is already initialized; someone else might
            // have already initialized it before us, so we only care
            // about failure
            INITIALIZED =
                ( libc::setrlimit(libc::RLIMIT_CORE, &rlimit) != -1 ) &&
                ( sodium_init() != -1 );
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

pub(crate) unsafe fn mlock<T>(ptr: *const T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.get()) { return false } };

    sodium_mlock(ptr as *mut _, mem::size_of::<T>()) == 0
}

pub(crate) unsafe fn munlock<T>(ptr: *const T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.get()) { return false } };

    sodium_munlock(ptr as *mut _, mem::size_of::<T>()) == 0
}

pub(crate) unsafe fn mprotect_noaccess<T>(ptr: *const T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.get()) { return false } };

    sodium_mprotect_noaccess(ptr as *mut _) == 0
}

pub(crate) unsafe fn mprotect_readonly<T>(ptr: *const T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.get()) { return false } };

    sodium_mprotect_readonly(ptr as *mut _) == 0
}

pub(crate) unsafe fn mprotect_readwrite<T>(ptr: *const T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.get()) { return false } };

    sodium_mprotect_readwrite(ptr as *mut _) == 0
}

///
/// Compares `l` and `r` for equality in constant time, preventing
/// side-channel attacks when comparing equality of secret data.
///
pub(crate) fn memcmp(l: &[u8], r: &[u8]) -> bool {
    if l.len() != r.len() {
        return false
    }

    unsafe {
        sodium_memcmp(
            l.as_ptr() as *const _,
            r.as_ptr() as *const _,
            r.len(),
        ) == 0
    }
}

///
/// Copies bytes from `src` to `dst` before zeroing the bytes in `src`.
/// `dst` *must* be at least as long as `src` and *must not* overlap
/// `src`.
///
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

    src.as_ptr().copy_to_nonoverlapping(dst.as_mut_ptr(), src.len());
    memzero(src);
}

///
/// Fills `bytes` with zeroes.
///
pub(crate) fn memzero(bytes: &mut [u8]) {
    unsafe { sodium_memzero(bytes.as_mut_ptr() as *mut _, bytes.len()) }
}

///
/// Fills `bytes` with random bytes.
///
pub(crate) fn memrandom(bytes: &mut [u8]) {
    unsafe { randombytes_buf(bytes.as_mut_ptr() as *mut _, bytes.len()) }
}

// LCOV_EXCL_START

#[cfg(test)]
mod test {
    #![allow(warnings)]

    use super::*;

    include!(concat!(env!("OUT_DIR"), "/sodium_ctest.rs"));

    #[test]
    fn ctest() { main(); }

    #[test]
    fn memcmp_compares_equality() {
        let a = [0xfd, 0xa1, 0x92, 0x4b];
        let b = a;

        assert!(memcmp(&a, &b));
    }

    #[test]
    fn memcmp_compares_inequality_for_different_lengths() {
        let a = [0xb8, 0xa4, 0x06, 0xd1];
        let b = [0xb8, 0xa4, 0x06];
        let c = [0xb8, 0xa4, 0x06, 0xd1, 0x3a];

        assert!(memcmp(&a, &b) == false);
        assert!(memcmp(&b, &a) == false);
        assert!(memcmp(&a, &c) == false);
        assert!(memcmp(&c, &a) == false);
    }
}

// LCOV_EXCL_STOP
