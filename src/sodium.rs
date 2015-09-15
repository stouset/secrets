#![allow(unsafe_code)]

use std::mem;
use std::sync::{Once, ONCE_INIT};

use libc::{c_void, c_int, size_t};

static INIT: Once = ONCE_INIT;

#[link(name="sodium")]
extern {
    fn sodium_init() -> c_int;

    fn sodium_allocarray(count: size_t, size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *const c_void);

    fn sodium_memzero(ptr: *const c_void, len: size_t);

    fn sodium_mprotect_noaccess(ptr: *const c_void) -> c_int;
    fn sodium_mprotect_readonly(ptr: *const c_void) -> c_int;
    fn sodium_mprotect_readwrite(ptr: *const c_void) -> c_int;

    fn randombytes_buf(ptr: *mut c_void, len: size_t);
}

pub fn init() {
    INIT.call_once(|| {
        if unsafe { sodium_init() } < 0 {
            panic!("sodium: couldn't initialize libsodium");
        }
    })
}

pub fn allocarray<T>(count: usize) -> *mut T {
    unsafe {
        let ptr = sodium_allocarray(
            count               as size_t,
            mem::size_of::<T>() as size_t,
        ) as *mut T;

        if ptr.is_null() {
            panic!("sodium: couldn't allocate memory")
        }

        ptr
    }
}

pub fn free<T>(ptr: *const T) {
    unsafe { sodium_free(ptr as *const _) }
}

pub unsafe fn memzero<T>(ptr: *const T, count: usize) {
    sodium_memzero(
        ptr                          as * const _,
        (mem::size_of::<T>() * count) as size_t
    )
}

pub unsafe fn mprotect_noaccess<T>(ptr: *const T) -> c_int {
    sodium_mprotect_noaccess(ptr as *const _)
}

pub unsafe fn mprotect_readonly<T>(ptr: *const T) -> c_int {
    sodium_mprotect_readonly(ptr as *const _)
}

pub unsafe fn mprotect_readwrite<T>(ptr: *const T) -> c_int {
    sodium_mprotect_readwrite(ptr as *const _)
}

pub unsafe fn randomarray<T>(ptr: *mut T, count: usize) {
    randombytes_buf(
        ptr                           as * mut _,
        (mem::size_of::<T>() * count) as size_t,
    )
}
