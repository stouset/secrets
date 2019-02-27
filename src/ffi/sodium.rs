//! Rust bindings to libsodium functions.

#![allow(unsafe_code)]

use libc::{c_int, c_void, size_t};

// TODO: https://www.reddit.com/r/rust/comments/6e0s3g/asserting_static_properties_in_rust/
// assert sizeof for casts

#[link(name = "sodium")]
extern "C" {
    fn randombytes_buf(ptr: *mut c_void, len: size_t);

    fn sodium_memcmp(l: *const c_void, r: *const c_void, len: size_t) -> c_int;
    fn sodium_memzero(ptr: *mut c_void, len: size_t);
}

/// Compares `l` and `r` for equality in constant time, preventing
/// side-channel attacks when comparing equality of secret data.
pub(crate) unsafe fn memcmp<T>(l: &T, r: &T) -> bool {
    // the double-cast is necessary, I believe this warning is spurious;
    // "fixing" it just involves assignment to an intermediate variable
    // which is pointless
    #![allow(trivial_casts)]
    sodium_memcmp(
        l as *const T as *const _,
        r as *const T as *const _,
        std::mem::size_of::<T>(),
    ) == 0
}

/// Copies `src` to `dst` before zeroing the bytes in `src`.
pub(crate) unsafe fn memmove<T>(src: &mut T, dst: &mut T) {
    std::ptr::copy_nonoverlapping(src, dst, 1);
    memzero(src);
}

/// Fills `val` with zero bytes.
pub(crate) unsafe fn memzero<T>(val: &mut T) {
    // the double-cast is necessary, I believe this warning is spurious;
    // "fixing" it just involves assignment to an intermediate variable
    // which is pointless
    #![allow(trivial_casts)]
    sodium_memzero(val as *mut T as *mut _, std::mem::size_of::<T>())
}

/// Fills `val` with random bytes.
pub(crate) unsafe fn memrandom<T>(val: &mut T) {
    // the double-cast is necessary, I believe this warning is spurious;
    // "fixing" it just involves assignment to an intermediate variable
    // which is pointless
    #![allow(trivial_casts)]
    randombytes_buf(val as *mut T as *mut _, std::mem::size_of::<T>())
}
