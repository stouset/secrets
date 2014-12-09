#![crate_name = "secrets"]
#![crate_type = "lib"]

// #![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]

extern crate libc;

use std::{cell, ptr, finally, slice, sync};
use libc::{c_void, c_int, size_t};

#[link(name = "sodium")]
extern {
    fn sodium_init() -> c_int;

    fn sodium_malloc(size: size_t) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);

    fn sodium_mprotect_noaccess(ptr: *const c_void);
    fn sodium_mprotect_readonly(ptr: *const c_void);
    fn sodium_mprotect_readwrite(ptr: *const c_void);

    fn sodium_memcmp(b1: *const c_void, b2: *const c_void, size: size_t) -> c_int;
}

static START: sync::Once = sync::ONCE_INIT;

pub struct Secret {
    ptr: cell::RefCell<ProtectedPointer>,
    len: uint,
}

impl Secret {
    pub fn empty(len: uint) -> Secret {
        let pp  = ProtectedPointer::new(len as size_t);
        let ptr = cell::RefCell::new(pp);

        Secret {
            ptr: ptr,
            len: len,
        }
    }

    pub fn new(data: &mut [u8]) -> Secret {
        let len    = data.len();
        let secret = Secret::empty(len);

        secret.ptr.borrow_mut().write(|ptr| {
            unsafe {
                ptr::copy_nonoverlapping_memory(ptr, data.as_ptr() as *const c_void, len);
                ptr::set_memory(data.as_mut_ptr(), 0, len);
            }
        });

        secret
    }

    pub fn len(&self) -> uint {
        self.len
    }

    pub fn read<T>(&self, reader: |&[u8]| ->T) -> T {
        self.ptr.borrow_mut().read(|ptr| {
            unsafe {
                let ptr   = ptr as *const u8;
                let slice = slice::from_raw_buf(&ptr, self.len);

                reader(slice)
            }
        })
    }

    pub fn write<T>(&mut self, writer: |&mut [u8]| -> T) -> T {
        self.ptr.borrow_mut().write(|ptr| {
            unsafe {
                let ptr   = ptr as *mut u8;
                let slice = slice::from_raw_mut_buf(&ptr, self.len);

                writer(slice)
            }
        })
    }

    pub fn slice(&self, from: uint, to: uint) -> Secret {
        assert!(from <= to,       "negative-length slice");
        assert!(to   <  self.len, "index out of bounds");

        let len   = to - from + 1;
        let slice = Secret::empty(len);

        self.ptr.borrow_mut().read(|src| {
            slice.ptr.borrow_mut().write(|dst| {
                unsafe {
                    ptr::copy_nonoverlapping_memory(
                        dst,
                        src.offset(from as int),
                        len
                    );
                }
            });
        });

        slice
    }

    fn equal(&self, other: &Secret) -> bool {
        // short circuit the test if we're pointing to the same
        // memory, otherwise we'd nest calls to `read`.
        if self as *const Secret == other as *const Secret {
            return true;
        }

        // short circuit if the two objects have different lengths;
        // they can't possibly be equal
        if self.len != other.len {
            return false;
        }

        unsafe {
            self.ptr.borrow_mut().read(|left| {
                other.ptr.borrow_mut().read(|right| {
                    sodium_memcmp(left, right, self.len as size_t) == 0
                })
            })
        }
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Secret) -> bool {
        self.equal(other)
    }
}

impl Eq for Secret {
}

enum Protection {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

struct ProtectedPointer {
    ptr:  *mut c_void,
}

impl ProtectedPointer {
    pub fn new(len: size_t) -> ProtectedPointer {
        init();

        ProtectedPointer {
            ptr: alloc(len),
        }
    }

    pub fn read<T>(&mut self, reader: |*const c_void| -> T) -> T {
        self.unlock(Protection::ReadOnly, |ptr| { reader(ptr as *const c_void) })
    }

    pub fn write<T>(&mut self, writer: |*mut c_void| -> T) -> T {
        self.unlock(Protection::ReadWrite, |ptr| { writer(ptr) })
    }

    fn unlock<T>(&mut self, prot: Protection, callback: |*mut c_void| -> T) -> T {
        finally::try_finally(
            self, callback,
            |pp, cb| { pp.protect(prot); cb(pp.ptr) },
            |pp    | { pp.protect(Protection::NoAccess); }
        )
    }

    fn protect(&mut self, prot: Protection) {
        unsafe { protect(self.ptr as *const c_void, prot) }
    }
}

fn init() {
    // ensure sodium is initialized before we call any
    // sodium_* functions
    START.doit(|| {
        assert!(unsafe { sodium_init() >= 0 });
    });
}

fn alloc(len: size_t) -> *mut c_void {
    let ptr : *mut c_void;

    unsafe {
        ptr = sodium_malloc(len as size_t);
        assert!(!ptr.is_null());

        sodium_mprotect_noaccess(ptr as *const c_void);
    }

    ptr
}

fn free(ptr: *mut c_void) {
    assert!(!ptr.is_null());

    unsafe { sodium_free(ptr) };
}

unsafe fn protect(ptr: *const c_void, prot: Protection) {
    match prot {
        Protection::NoAccess  => sodium_mprotect_noaccess(ptr),
        Protection::ReadOnly  => sodium_mprotect_readonly(ptr),
        Protection::ReadWrite => sodium_mprotect_readwrite(ptr),
    }
}

impl Drop for ProtectedPointer {
    fn drop(&mut self) { free(self.ptr) }
}
