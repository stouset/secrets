//! Rust bindings to libsodium functions.

#![allow(unsafe_code)]

use std::sync::Once;

use libc::{self, size_t};

#[cfg(not(feature = "use-libsodium-sys"))]
use libc::{c_void, c_int};

#[cfg(feature = "use-libsodium-sys")]
use libsodium_sys::{
    randombytes_buf, sodium_allocarray, sodium_free, sodium_init,
    sodium_memcmp, sodium_memzero, sodium_mlock, sodium_mprotect_noaccess,
    sodium_mprotect_readonly, sodium_mprotect_readwrite, sodium_munlock,
};

/// The global [`sync::Once`] that ensures we only perform
/// library initialization one time.
static INIT: Once = Once::new();

/// A flag that returns whether or not this library has been safely
/// initialized.
static mut INITIALIZED: bool = false;

#[cfg(test)]
thread_local! {
    static FAIL: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

#[cfg(not(feature = "use-libsodium-sys"))]
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

/// Initialized libsodium. This function *must* be called at least once
/// prior to using any of the other functions in this library, and
/// callers *must* verify that it returns `true`. If it returns `false`,
/// libsodium was unable to be properly set up and this library *must
/// not* be used.
///
/// Calling it multiple times is a no-op.
pub(crate) fn init() -> bool {
    unsafe {
        #[cfg(test)]
        { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

        INIT.call_once(|| {
            // NOTE: Calls to transmute fail to compile if the source
            // and destination type have a different size. We (ab)use
            // this fact to statically assert the size of types at
            // compile-time.
            //
            // We assume that we can freely cast between rust array
            // sizes and [`libc::size_t`]. If that's not true, DO NOT
            // COMPILE.
            #[allow(clippy::useless_transmute)]
            let _ = std::mem::transmute::<usize, size_t>(0);

            let mut failure = false;

            // in non-development builds, ensure that core dumps are
            // disabled
            // This functionality exists only on UNIX systems.
            #[cfg(unix)]
            #[cfg(any(profile = "release", profile = "coverage"))]
            #[cfg(not(feature = "allow-coredumps"))]
            {
                failure |= libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                }) == -1;
            }

            // sodium_init returns 0 on success, -1 on failure, and 1 if
            // the library is already initialized; someone else might
            // have already initialized it before us, so we only care
            // about failure
            failure |= sodium_init() == -1;

            INITIALIZED = !failure;
        });

        INITIALIZED
    }
}

/// Allocates memory that can store `count` objects of type `T` and
/// fills that memory with garbage bytes. Callers must ensure that they
/// call [`sodium::free`] when this memory is no longer used.
pub(crate) unsafe fn allocarray<T>(count: usize) -> *mut T {
    sodium_allocarray(count, size_of::<T>()).cast()
}

/// Releases memory acquired with [`sodium::allocarray`]. This function
/// may panic if it detects that certain soundness and safety guarantees
/// have been violated (e.g., an underflowing write).
pub(crate) unsafe fn free<T>(ptr: *mut T) {
    sodium_free(ptr.cast());
}

/// Calls the platform's underlying `mlock(2)` implementation.
pub(crate) unsafe fn mlock<T>(ptr: *mut T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

    sodium_mlock(ptr.cast(), size_of::<T>()) == 0
}

/// Calls the platform's underlying `munlock(2)` implementation.
pub(crate) unsafe fn munlock<T>(ptr: *mut T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

    sodium_munlock(ptr.cast(), size_of::<T>()) == 0
}

/// Sets the page protection level of [`sodium::allocarray`]-allocated
/// memory to `PROT_NONE`. This must be used in lieu of a raw call to
/// `mprotect` which is unaware of the specific allocation pattern used
/// by libsodium.
pub(crate) unsafe fn mprotect_noaccess<T>(ptr: *mut T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

    sodium_mprotect_noaccess(ptr.cast()) == 0
}

/// Sets the page protection level of [`sodium::allocarray`]-allocated
/// memory to `PROT_READ`. This must be used in lieu of a raw call to
/// `mprotect` which is unaware of the specific allocation pattern used
/// by libsodium.
pub(crate) unsafe fn mprotect_readonly<T>(ptr: *mut T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

    sodium_mprotect_readonly(ptr.cast()) == 0
}

/// Sets the page protection level of [`sodium::allocarray`]-allocated
/// memory to `PROT_WRITE`. This must be used in lieu of a raw call to
/// `mprotect` which is unaware of the specific allocation pattern used
/// by libsodium.
pub(crate) unsafe fn mprotect_readwrite<T>(ptr: *mut T) -> bool {
    #[cfg(test)]
    { if FAIL.with(|f| f.replace(false)) { return false }; let _x = 0; };

    sodium_mprotect_readwrite(ptr.cast()) == 0
}

/// Compares `l` and `r` for equality in constant time, preventing
/// side-channel attacks when comparing equality of secret data.
pub(crate) fn memcmp(l: &[u8], r: &[u8]) -> bool {
    if l.len() != r.len() {
        return false;
    }

    unsafe {
        sodium_memcmp(
            l.as_ptr().cast(),
            r.as_ptr().cast(),
            r.len(),
        ) == 0
    }
}

/// Copies bytes from `src` to `dst` before zeroing the bytes in `src`.
/// `dst` *must* be at least as long as `src` and *must not* overlap
/// `src`.
pub(crate) unsafe fn memtransfer(src: &mut [u8], dst: &mut [u8]) {
    never!(src.len() > dst.len(),
        "secrets: may not transfer a smaller `src` into a larger `dst`");

    // Based on the requirements of `ptr::copy_nonoverlapping` and the
    // that we're going to clobber `src`, we ensure that either
    //
    // * `src` is lower than `dst`, and `src` doesn't extend into `dst`, or
    // * `dst` is lower than `src`, and `dst` doesn't extend into `src`
    //
    // this is proven since in safe rust, two mutable slices may not
    // overlap with one-another
    proven!(
        (src.as_ptr() < dst.as_ptr() && src.as_ptr().add(src.len()) <= dst.as_ptr()) ||
        (dst.as_ptr() < src.as_ptr() && dst.as_ptr().add(dst.len()) <= src.as_ptr()),
        "secrets: may not transfer overlapping slices into one-another"
    );

    src.as_ptr().copy_to_nonoverlapping(dst.as_mut_ptr(), src.len());
    memzero(src);
}

/// Fills `bytes` with zeroes.
pub(crate) fn memzero(bytes: &mut [u8]) {
    unsafe { sodium_memzero(bytes.as_mut_ptr().cast(), bytes.len()) }
}

/// Fills `bytes` with random bytes.
pub(crate) fn memrandom(bytes: &mut [u8]) {
    unsafe { randombytes_buf(bytes.as_mut_ptr().cast(), bytes.len()) }
}

// LCOV_EXCL_START

#[cfg(test)]
mod test {
    use super::*;

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

        assert!(!memcmp(&a, &b));
        assert!(!memcmp(&b, &a));
        assert!(!memcmp(&a, &c));
        assert!(!memcmp(&c, &a));
    }
}

// LCOV_EXCL_STOP
