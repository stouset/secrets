#![allow(unsafe_code)]

use sodium;

use std::borrow::{Borrow, BorrowMut};
use std::cell::Cell;
use std::fmt::{self, Debug};
use std::ptr;
use std::slice;

pub struct Sec<T> {
    ptr:  *mut T,
    len:  usize,
    refs: Cell<u8>
}

impl<T> Drop for Sec<T> {
    fn drop(&mut self) { sodium::free(self.ptr) }
}

impl<T> Debug for Sec<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.len)
    }
}

impl<T> PartialEq for Sec<T> {
    fn eq(&self, other: &Sec<T>) -> bool {
        if self.len != other.len {
            return false;
        }

        self .read();
        other.read();
        let ret = unsafe { sodium::memcmp(other.ptr, self.ptr, self.len) };
        other.lock();
        self .lock();

        ret
    }
}

impl<T> Eq for Sec<T> {}

impl<T> Borrow<*const T> for Sec<T> {
    fn borrow(&self) -> &*const T {
        let ptr : *const *mut   T = &self.ptr;
        let ptr : *const *const T = ptr as *const *const T;

        unsafe { &*ptr }
    }
}

impl<T> Borrow<*mut T> for Sec<T> {
    fn borrow(&self) -> &*mut T { &self.ptr }
}

impl<T> Borrow<[T]> for Sec<T> {
    fn borrow(&self) -> &[T] { unsafe { slice::from_raw_parts(self.ptr, self.len) } }
}

impl<T> BorrowMut<[T]> for Sec<T> {
    fn borrow_mut(&mut self) -> &mut [T] { unsafe { slice::from_raw_parts_mut(self.ptr, self.len) } }
}

impl<'a> From<&'a mut [u8]> for Sec<u8> {
    fn from(bytes: &'a mut [u8]) -> Self {
        let ptr   = bytes.as_mut_ptr();
        let len   = bytes.len();

        let mut sec = Sec::new(len);

        unsafe {
            sec.write();
            ptr::copy_nonoverlapping(ptr, sec.ptr, len);
            sodium::memzero(ptr, len);
            sec.lock();
        }

        sec
    }
}

impl Sec<u8> {
    pub fn random(len: usize) -> Self {
        let mut sec = Sec::new(len);

        unsafe {
            sec.write();
            sodium::randomarray(sec.ptr, sec.len);
            sec.lock();
        }

        sec
    }
}

impl<T> Sec<T> {
    pub fn new(len: usize) -> Self {
        sodium::init();

        let ptr = sodium::allocarray::<T>(len);
        let sec = Sec { ptr: ptr, len: len, refs: Cell::new(1) };

        sec.lock();

        sec
    }

    pub fn len(&self) -> usize { self.len }

    pub fn read(&self) {
        self.retain(|ptr| unsafe { sodium::mprotect_readonly(ptr) });
    }

    pub fn write(&mut self) {
        self.retain(|ptr| unsafe { sodium::mprotect_readwrite(ptr) });
    }

    pub fn lock(&self) {
        self.release(|ptr| unsafe {sodium::mprotect_noaccess(ptr) });
    }

    fn retain<F>(&self, cb: F) where F: Fn(*const T) -> bool {
        if self.refs.get() == 0 {
            if !cb(self.ptr) {
                panic!("error retaining secret pointer");
            }
        }

        self.refs.set(self.refs.get() + 1);
    }

    fn release<F>(&self, cb: F) where F: Fn(*const T) -> bool {
        self.refs.set(self.refs.get() - 1);

        if self.refs.get() == 0 {
            if !cb(self.ptr) {
                panic!("error releasing secret pointer");
            }
        }
    }
}
