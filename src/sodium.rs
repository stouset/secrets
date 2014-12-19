use libc::{c_void, c_int, size_t};
use std::sync;

static SODIUM_INIT: sync::Once = sync::ONCE_INIT;

#[deriving(Copy, PartialEq, Show)]
/// The possible levels of access granted to a `SecretPointer`.
pub enum Protection {
    /// The memory may not be read or written to.
    NoAccess,

    /// The memory may only be read from.
    ReadOnly,

    /// The memory may be read from or written to.
    ReadWrite,
}

#[link(name = "sodium")]
extern {
    fn sodium_init() -> c_int;

    fn sodium_malloc(size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_mprotect_noaccess(ptr: *const c_void)  -> c_int;
    fn sodium_mprotect_readonly(ptr: *const c_void)  -> c_int;
    fn sodium_mprotect_readwrite(ptr: *const c_void) -> c_int;

    fn sodium_memzero(ptr: *mut c_void, size: size_t);

    fn sodium_memcmp(b1: *const c_void, b2: *const c_void, size: size_t) -> c_int;
}

/// Initializes the Sodium library, which is used for memory
/// allocation. Uses std::sync::Once to ensure it's not called
/// simultaneously between threads.
///
/// This is automatically called for you when allocating new
/// secrets. However, if you are linking to another library that uses
/// libsodium, that library may try to initialize it at the same time
/// we do (in a separate thread). If this is the case, you may call
/// this function manually before invoking threads.
pub fn init() {
    SODIUM_INIT.doit(|| {
        // ensure sodium is initialized before we call any
        // sodium_* functions
        assert!(unsafe { sodium_init() >= 0 }, "sodium couldn't be initialized");
    });
}

/// Uses libsodium to allocate the requested amount of memory. The
/// memory is `mprotect`ed to allow no access before this function
/// returns.
///
/// Panics if memory cannot be allocated.
pub unsafe fn alloc(len: size_t) -> *mut c_void {
    let ptr = sodium_malloc(len as size_t);

    assert!(!ptr.is_null(), "memory for a secret couldn't be allocated");

    protect(ptr, Protection::NoAccess);

    ptr
}

/// Frees memory allocated with `alloc`. Panics if the pointer is null.
pub unsafe fn free(ptr: *mut c_void) {
    // FIXME: workaround for a bug in libsodium 1.0.1, to be fixed
    // in next release
    sodium_mprotect_readwrite(ptr as *const c_void);

    sodium_free(ptr)
}

/// Changes the protection level on the provided pointer.
pub unsafe fn protect(ptr: *mut c_void, prot: Protection) {
    let ret = match prot {
        Protection::NoAccess  => sodium_mprotect_noaccess(ptr as *const c_void),
        Protection::ReadOnly  => sodium_mprotect_readonly(ptr as *const c_void),
        Protection::ReadWrite => sodium_mprotect_readwrite(ptr as *const c_void),
    };

    assert!(ret == 0, "couldn't set memory protection to {}", prot);
}

pub unsafe fn zero(ptr: *mut c_void, len: size_t) {
    sodium_memzero(ptr, len)
}

pub unsafe fn memcmp(ptr: *const c_void, other: *const c_void, len: size_t) -> c_int {
    sodium_memcmp(ptr, other, len)
}
