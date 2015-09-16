// This comment prevents Emacs from thinking this file is executable
#![allow(unsafe_code)]

use sodium;

use std::borrow::{Borrow, BorrowMut};
use std::cell::Cell;
use std::fmt::{self, Debug};
use std::ptr;
use std::slice;
use std::thread;

#[derive(Copy)]
#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq)]
enum Prot {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

pub struct Sec<T> {
    ptr:  *mut T,
    len:  usize,
    prot: Cell<Prot>,
    refs: Cell<u8>
}

impl<T> Drop for Sec<T> {
    fn drop(&mut self) {
        if !thread::panicking() {
            debug_assert_eq!(0,              self.refs.get());
            debug_assert_eq!(Prot::NoAccess, self.prot.get());
        }

        sodium::free(self.ptr) }
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

        let ret;

        unsafe {
            self .read();
            other.read();
            ret = sodium::memcmp(other.ptr, self.ptr, self.len);
            other.lock();
            self .lock();
        };


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
        let sec = Sec {
            ptr:  ptr,
            len:  len,
            prot: Cell::new(Prot::ReadOnly),
            refs: Cell::new(1)
        };

        sec.lock();

        sec
    }

    pub fn len(&self) -> usize { self.len }
    pub fn read(&self)         { self.retain(Prot::ReadOnly) }
    pub fn write(&mut self)    { self.retain(Prot::ReadWrite) }
    pub fn lock(&self)         { self.release() }

    fn retain(&self, prot: Prot) {
        let refs = self.refs.get();

        if refs != 0 {
            debug_assert_eq!(self.prot.get(), prot);
            debug_assert!(self.prot.get() != Prot::ReadWrite);
        }

        if refs == 0 {
            self.prot.set(prot);
            mprotect(self.ptr, prot);
        }

        self.refs.set(refs + 1);
    }

    fn release(&self) {
        let refs = self.refs.get() - 1;

        self.refs.set(refs);

        if refs == 0 {
            self.prot.set(Prot::NoAccess);
            mprotect(self.ptr, Prot::NoAccess);
        }
    }
}

fn mprotect<T>(ptr: *const T, prot: Prot) {
    if !match prot {
        Prot::NoAccess  => unsafe { sodium::mprotect_noaccess(ptr)  },
        Prot::ReadOnly  => unsafe { sodium::mprotect_readonly(ptr)  },
        Prot::ReadWrite => unsafe { sodium::mprotect_readwrite(ptr) },
    } {
        panic!("secrets: error protecting secret as {:?}", prot);
    }
}

#[cfg(test)]
mod tests {
    use super::Sec;

    #[test]
    fn it_starts_with_zero_refs() {
        let sec = Sec::<u8>::new(10);

        assert_eq!(0, sec.refs.get());
    }

    #[test]
    fn it_tracks_ref_counts_accurately() {
        let mut sec = Sec::<u8>::new(10);

        {
            sec.read(); sec.read(); sec.read();
            assert_eq!(3, sec.refs.get());
            sec.lock(); sec.lock(); sec.lock();
        }

        assert_eq!(0, sec.refs.get());

        {
            sec.write();
            assert_eq!(1, sec.refs.get());
            sec.lock();
        }

        assert_eq!(0, sec.refs.get());
    }

    #[test]
    #[should_panic]
    fn it_doesnt_allow_multiple_writers() {
        let mut sec = Sec::<u64>::new(1);

        sec.write();
        sec.write();
    }

    #[test]
    #[should_panic]
    fn it_doesnt_allow_different_access_types() {
        let mut sec = Sec::<u8>::new(5);

        sec.read();
        sec.write();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_dropped_with_outstanding_refs() {
        let sec = Sec::<f64>::new(1);

        sec.read();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_released_too_often() {
        let sec = Sec::<u32>::new(10000);

        sec.read();
        sec.lock();
        sec.lock();
    }
}
