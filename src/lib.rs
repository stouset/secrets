//! A type for securely storing cryptographic secrets.

#![crate_name = "secrets"]
#![crate_type = "lib"]

#![feature(unsafe_destructor)]

#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]

extern crate libc;

use std::{cell, ptr, slice, sync, uint};
use libc::{c_void, c_int, size_t};

#[cfg(test)]
use std::finally::Finally;

#[link(name = "sodium")]
extern {
    fn sodium_init() -> c_int;

    fn sodium_malloc(size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_mprotect_noaccess(ptr: *const c_void)  -> c_int;
    fn sodium_mprotect_readonly(ptr: *const c_void)  -> c_int;
    fn sodium_mprotect_readwrite(ptr: *const c_void) -> c_int;

    fn sodium_memcmp(b1: *const c_void, b2: *const c_void, size: size_t) -> c_int;
}

static SODIUM_INIT: sync::Once = sync::ONCE_INIT;

#[deriving(Copy, PartialEq, Show)]
/// The possible levels of access granted to a `SecretPointer`.
enum Protection {
    /// The memory may not be read or written to.
    NoAccess,

    /// The memory may only be read from.
    ReadOnly,

    /// The memory may be read from or written to.
    ReadWrite,
}

/// A value that represents a byte buffer suitable for in-memory
/// storage of cryptographic secrets.
///
/// The memory for the contained secret uses guard pages to protect it
/// from being accessed by buffer overflows in the rest of the
/// system. Direct reads and writes are prohibited outside of scopes
/// where that permission is explicitly requested.
pub struct Secret {
    /// A mprotected pointer to the memory containing secret data.
    ptr: SecretPointer,

    /// The length in bytes of the secret data.
    len: uint,
}

/// A value that dereferences (mutably and immutably) to a slice
/// pointing at secret data. When the `SecretSlice` is dropped, it
/// ensures that the memory pointed to is re-mprotected.
pub struct SecretSlice<'a> {
    /// A reference to the `SecretPointer` containing the real pointer
    /// we're using for the data behind the slice. This is held onto
    /// so we can release the pointer when the `SecretSlice` is
    /// `drop()`ed.
    ptr: &'a SecretPointer,

    /// The internal slice pointing at the secret data.
    slice: &'a mut [u8],
}

struct SecretPointer {
    /// A C pointer to a memory location suitable for the storage of
    /// cryptographic secrets.
    ptr: *mut c_void,

    /// The number of live references to the contents of the
    /// `SecretPointer`. When the ref count drops to zero, the memory is
    /// reprotected.
    refs: cell::Cell<uint>,

    /// The current level of access granted to the pointer.
    prot: cell::Cell<Protection>,
}

impl Secret {
    /// Creates an empty secret capable of holding `len` bytes. The
    /// secret is initialized with garbage (rather than zeroes) in
    /// order to more easily detect the use of uninitialized data.
    ///
    /// ```rust
    /// let secret = secrets::Secret::empty(4);
    ///
    /// assert_eq!(secret.len(), 4);
    /// ```
    pub fn empty(len: uint) -> Secret {
        Secret {
            ptr:  SecretPointer::alloc(len as size_t),
            len:  len,
        }
    }

    /// Creates a secret containing the given bytes. The byte slice
    /// passed in has its contents set to all zero bytes, and should
    /// no longer be used.
    ///
    /// ```rust
    /// let bytes  = &mut [1, 2, 3];
    /// let secret = secrets::Secret::new(bytes);
    ///
    /// assert_eq!(bytes, &[0, 0, 0]);
    /// ```
    pub fn new(src: &mut [u8]) -> Secret {
        let     len    = src.len();
        let mut secret = Secret::empty(len);

        unsafe {
            let mut dst = secret.write();

            ptr::copy_nonoverlapping_memory(
                dst.as_mut_ptr(),
                src.as_ptr(),
                len
            );

            ptr::set_memory(
                src.as_mut_ptr(),
                0,
                len
            );
        }

        secret
    }

    /// Returns the length of the secret.
    pub fn len(&self) -> uint {
        self.len
    }

    /// Returns a `SecretSlice` that derefs into a slice from which the
    /// contents of the `Secret` can be read.
    ///
    /// ```rust
    /// let secret = secrets::Secret::new(&mut [1, 2, 3, 4]);
    ///
    /// println!("{}", &*secret.read());
    /// ```
    pub fn read(&self) -> SecretSlice {
        SecretSlice::new(&self.ptr, self.len, Protection::ReadOnly)
    }

    /// Returns a `SecretSlice` that derefs into a slice from which the
    /// contents of the Secret can be read from or written to.
    ///
    /// Take care when writing in to a Secret using this mechanism. It
    /// is not possible for this library to manage the lifetime and
    /// page protection of the memory the secret data written was read
    /// from.
    ///
    /// ```rust
    /// let mut secret = secrets::Secret::empty(1);
    ///
    /// {
    ///     secret.write()[0] = 42;
    /// }
    ///
    /// assert!(secret == secrets::Secret::new(&mut [42]));
    /// ```
    pub fn write(&mut self) -> SecretSlice {
        SecretSlice::new(&self.ptr, self.len, Protection::ReadWrite)
    }

    /// Returns a new `Secret` containing the data sliced between the
    /// provided indices.
    ///
    /// ```rust
    /// let secret = secrets::Secret::new(&mut [255, 255, 255, 0]);
    ///
    /// assert!(secret.slice(0, 1) == secret.slice(1, 2));
    /// assert!(secret.slice(0, 1) == secret.slice(2, 3));
    /// assert!(secret.slice(0, 1) != secret.slice(3, 4));
    /// ```
    pub fn slice(&self, from: uint, to: uint) -> Secret {
        assert!(from <= to,       "negative-length slice");
        assert!(to   <= self.len, "index out of bounds");

        let     len    = to - from;
        let mut secret = Secret::empty(len);

        unsafe {
            let     src = self  .read();
            let mut dst = secret.write();

            ptr::copy_nonoverlapping_memory(
                dst.as_mut_ptr(),
                src.as_ptr().offset(from as int),
                len
            );
        }

        secret
    }
}

impl PartialEq for Secret {
    /// Compares equality against another `Secret` in constant
    /// time.
    fn eq(&self, other: &Secret) -> bool {
        self.read() == other.read()
    }
}

impl Eq for Secret {
}

impl Clone for Secret {
    /// Clones the secret, creating a complete independent copy of its
    /// contents.
    fn clone(&self) -> Secret {
        let mut secret = Secret::empty(self.len);

        unsafe {
            let     src = self.read();
            let mut dst = secret.write();

            ptr::copy_nonoverlapping_memory(
                dst.as_mut_ptr(),
                src.as_ptr(),
                self.len
            )
        }

        secret
    }
}

impl Add<Secret, Secret> for Secret {
    /// Appends another secret to the current secret, returning a new
    /// one with the contents of both.
    fn add(self, other: Secret) -> Secret {
        let mut secret = Secret::empty(self.len + other.len);

        unsafe {
            let     src1 = self  .read();
            let     src2 = other .read();
            let mut dst  = secret.write();

            ptr::copy_nonoverlapping_memory(
                dst .as_mut_ptr(),
                src1.as_ptr(),
                self.len
            );

            ptr::copy_nonoverlapping_memory(
                dst  .as_mut_ptr().offset(self.len as int),
                src2 .as_ptr(),
                other.len
            );
        }

        secret
    }
}

impl SecretPointer {
    /// Allocates memory for a pointer of the given length. When this
    /// function returns, this memory is `mprotect`ed such that it
    /// cannot be read from or written to. It is also `mlock`ed to
    /// prevent being swapped to disk.
    pub fn alloc(len: size_t) -> SecretPointer {
        init();

        SecretPointer {
            ptr:  alloc(len),
            refs: cell::Cell::new(0u),
            prot: cell::Cell::new(Protection::NoAccess),
        }
    }

    /// Requests a copy of the internal pointer with a specific access
    /// level and increases the ref count.
    ///
    /// Each `retain` *must* be paired with a corresponding `release`;
    /// when the ref count hits zero, the memory is re-`mprotect`ed to
    /// be inaccessible. Panics if going directly from any
    /// non-NoAccess protection level to another non-NoAccess
    /// protection level, because we don't want to change the
    /// `mprotect` level of a pointer someone else might still have
    /// access to.
    pub fn retain(&self, prot: Protection) -> *mut c_void {
        let refs = self.refs.get() + 1;

        self.protect(prot);
        self.refs.set(refs);

        self.ptr
    }

    /// Manually releases access to the SecretPointer and decreases
    /// the ref count. If the ref count goes below zero, panics.
    pub fn release(&self) {
        let refs = self.refs.get() - 1;

        // technically this can also happen if we just call retain
        // 2^64 times, though something tells me this won't ever
        // happen in practice
        if refs == uint::MAX {
            panic!("released a SecretPointer that was not retained");
        }

        if refs == 0 {
            self.protect(Protection::NoAccess);
        }

        self.refs.set(refs);
    }

    /// Changes the protection level on the underlying pointer. Panics
    /// if we try to change directly between two non-NoAccess levels.
    fn protect(&self, prot: Protection) {
        let current = self.prot.get();

        // short-circuit if we're already at the same protection level
        if current == prot {
            return;
        }

        // disallow everything except NoAccess => access, or access =>
        // NoAccess (either the requested protection or the current
        // protection should be NoAccess)
        if prot != Protection::NoAccess && current != Protection::NoAccess {
            panic!("secret is already unlocked for {}", current);
        }

        protect(self.ptr, prot);

        self.prot.set(prot);
    }
}

impl Drop for SecretPointer {
    /// Sanitizes and frees the memory located at the pointer. Panics
    /// if the ref count isn't zero.
    fn drop(&mut self) {
        if self.refs.get() != 0 {
            panic!("secrets bug: retained SecretPointer was dropped")
        }

        free(self.ptr)
    }
}

impl<'a> SecretSlice<'a> {
    /// Creates a new `SecretSlice` that references the data at the
    /// given `SecretPointer` and allows access to `len` bytes through
    /// that pointer.
    fn new(ptr: &'a SecretPointer, len: uint, prot: Protection) -> SecretSlice {
        let slice = unsafe {
            // technically we don't *know* that this is a mutable
            // pointer (we might have readonly access to it), but as
            // long as the user doesn't try to `deref_mut` us we'll be okay
            slice::from_raw_mut_buf(
                std::mem::transmute(&ptr.retain(prot)),
                len
            )
        };

        SecretSlice {
            ptr:   ptr,
            slice: slice,
        }
    }
}

impl<'a> PartialEq for SecretSlice<'a> {
    /// Compares the contents against another `SecretSlice in constant
    /// time.
    fn eq(&self, other: &SecretSlice) -> bool {
        unsafe {
            sodium_memcmp(
                self .as_ptr() as *const _,
                other.as_ptr() as *const _,
                other.len()    as size_t
            ) == 0
        }
    }
}

impl<'a> Eq for SecretSlice<'a> {
}

impl<'a> Deref<[u8]> for SecretSlice<'a> {
    /// Returns a reference to a slice containing the underlying
    /// data. This slice may be read from.
    fn deref(&self) -> &[u8] {
        self.slice.as_slice()
    }
}

impl<'a> DerefMut<[u8]> for SecretSlice<'a> {
    /// Returns a reference to a slice containing the underlying
    /// data. This slice may be read from or written to.
    ///
    /// It is a bug (and will cause a segfault) if you attempt to
    /// write to a mutable reference for a `SecretSlice` whose
    /// contents are only readable. Thankfully, the Rust type system
    /// makes this difficult to do without jumping through multiple
    /// casting hoops.
    fn deref_mut(&mut self) -> &mut [u8] {
        self.slice
    }
}

// NOTE: this appears to be necessary due to a compiler bug; the
// struct doesn't really have a type parameter, it's just a lifetime
// annotation
#[unsafe_destructor]
impl<'a> Drop for SecretSlice<'a> {
    /// Balances the `retain` called in the constructor with a
    /// `release` when the object goes out of scope.
    fn drop(&mut self) {
        self.ptr.release();
    }
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
fn alloc(len: size_t) -> *mut c_void {
    let ptr : *mut c_void;

    unsafe {
        ptr = sodium_malloc(len as size_t);
        assert!(!ptr.is_null(), "memory for a secret couldn't be allocated");
    }

    protect(ptr, Protection::NoAccess);

    ptr
}

/// Frees memory allocated with `alloc`. Panics if the pointer is null.
fn free(ptr: *mut c_void) {
    assert!(!ptr.is_null(), "tried to free a null pointer");

    unsafe {
        // FIXME: workaround for a bug in libsodium 1.0.1, to be fixed
        // in next release
        sodium_mprotect_readwrite(ptr as *const c_void);

        sodium_free(ptr)
    };
}

/// Changes the protection level on the provided pointer.
fn protect(ptr: *mut c_void, prot: Protection) {
    assert!(!ptr.is_null(), "tried to protect a null pointer");

    unsafe {
        let ret = match prot {
            Protection::NoAccess  => sodium_mprotect_noaccess(ptr as *const c_void),
            Protection::ReadOnly  => sodium_mprotect_readonly(ptr as *const c_void),
            Protection::ReadWrite => sodium_mprotect_readwrite(ptr as *const c_void),
        };

        assert!(ret == 0, "couldn't set memory protection to {}", prot);
    }
}

#[test]
fn test_read_protection_reset() {
    let secret = Secret::empty(256);

    {
        let a = secret.read();
        let b = secret.read();
        let c = secret.read();

        assert_eq!(a     .ptr.prot.get(), Protection::ReadOnly);
        assert_eq!(b     .ptr.prot.get(), Protection::ReadOnly);
        assert_eq!(c     .ptr.prot.get(), Protection::ReadOnly);
        assert_eq!(secret.ptr.prot.get(), Protection::ReadOnly);
        assert_eq!(secret.ptr.refs.get(), 3u);
    }

    assert_eq!(secret.ptr.prot.get(), Protection::NoAccess);
    assert_eq!(secret.ptr.refs.get(), 0u);
}

#[test]
fn test_write_protection_reset() {
    let mut secret = Secret::empty(1509);

    {
        let a = secret.write();

        assert_eq!(a.ptr.prot.get(), Protection::ReadWrite);
        assert_eq!(a.ptr.refs.get(), 1u);
    }

    assert_eq!(secret.ptr.prot.get(), Protection::NoAccess);
    assert_eq!(secret.ptr.refs.get(), 0u);
}

#[test]
#[should_fail(expected = "secret is already unlocked for ReadOnly")]
fn test_no_switching_read_to_write() {
    let ptr = SecretPointer::alloc(12);

    (|&mut:| {
        ptr.retain(Protection::ReadOnly);
        ptr.retain(Protection::ReadWrite);
    }).finally(|| {
        ptr.release();
    });
}

#[test]
#[should_fail(expected = "secret is already unlocked for ReadWrite")]
fn test_no_switching_write_to_read() {
    let ptr = SecretPointer::alloc(90);

    (|&mut:| {
        ptr.retain(Protection::ReadWrite);
        ptr.retain(Protection::ReadOnly);
    }).finally(|| {
        ptr.release();
    });
}

#[test]
#[should_fail(expected = "secrets bug: retained SecretPointer was dropped")]
fn test_unmatched_retain() {
    let ptr = SecretPointer::alloc(42);

    ptr.retain(Protection::ReadOnly);
}

#[test]
#[should_fail(expected = "released a SecretPointer that was not retained")]
fn test_unmatched_release() {
    let ptr = SecretPointer::alloc(42);

    ptr.release();
}

#[test]
#[should_fail(expected = "tried to free a null pointer")]
fn test_free_null_ptr() {
    free(0 as *mut c_void);
}
