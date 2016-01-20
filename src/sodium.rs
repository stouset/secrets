// This comment prevents Emacs from thinking this file is executable
#![allow(unsafe_code)]

use std::mem;
use std::ptr;
use std::sync::{Once, ONCE_INIT};

use libc::{c_void, c_int, size_t};

static INIT: Once = ONCE_INIT;

#[link(name="sodium")]
extern "C" {
    fn sodium_init() -> c_int;

    fn sodium_malloc(len: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_memzero(ptr: *mut c_void, len: size_t);
    fn sodium_memcmp(l: *const c_void, r: *const c_void, len: size_t) -> c_int;

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

pub fn malloc<T>(count: usize) -> *mut T {
    unsafe {
        let len = size_of::<T>(count);
        let ptr = sodium_malloc(len);

        if ptr.is_null() {
            panic!("sodium: couldn't allocate memory")
        }

        ptr as *mut _
    }
}

pub fn free<T>(ptr: *mut T) {
    unsafe { sodium_free(ptr as *mut _) }
}

pub unsafe fn memzero<T>(ptr: *mut T, count: usize) {
    sodium_memzero(ptr as *mut _, size_of::<T>(count));
}

pub unsafe fn memmove<T>(src: *mut T, dst: *mut T, count: usize) {
    ptr::copy_nonoverlapping(src, dst, count);
    sodium_memzero(src as *mut _, size_of::<T>(count));
}

pub unsafe fn memcmp<T>(l: *const T, r: *const T, count: usize) -> bool {
    sodium_memcmp(l as *const _, r as *const _, size_of::<T>(count)) == 0
}

pub unsafe fn mprotect_noaccess<T>(ptr: *const T) -> bool {
    sodium_mprotect_noaccess(ptr as *const _) == 0
}

pub unsafe fn mprotect_readonly<T>(ptr: *const T) -> bool {
    sodium_mprotect_readonly(ptr as *const _) == 0
}

pub unsafe fn mprotect_readwrite<T>(ptr: *const T) -> bool {
    sodium_mprotect_readwrite(ptr as *const _) == 0
}

pub unsafe fn random<T>(ptr: *mut T, count: usize) {
    randombytes_buf(ptr as *mut _, size_of::<T>(count));
}

fn size_of<T>(count: usize) -> size_t {
    (mem::size_of::<T>() * count) as size_t
}
