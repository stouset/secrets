// This comment prevents Emacs from thinking this file is executable
#![allow(unsafe_code)]

use marker::{BytewiseEq, Randomizable, Zeroable};

use sodium;

use std::borrow::{Borrow, BorrowMut};
use std::cell::Cell;
use std::fmt::{self, Debug};
use std::mem;
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
    refs: Cell<u8>,
}

impl<T> Drop for Sec<T> {
    fn drop(&mut self) {
        if !thread::panicking() {
            debug_assert_eq!(0,              self.refs.get());
            debug_assert_eq!(Prot::NoAccess, self.prot.get());
        }

        sodium::free(self.ptr)
    }
}

impl<T> Debug for Sec<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.size())
    }
}

impl<T: BytewiseEq> PartialEq for Sec<T> {
    fn eq(&self, s: &Self) -> bool {
        let len = self.len;
        let ret;

        if len != s.len {
            return false;
        }

        unsafe {
            self.read();
            s   .read();
            ret = sodium::memcmp(s.ptr, self.ptr, len);
            s   .lock();
            self.lock();
        }

        ret
    }
}

impl<T: BytewiseEq> Eq for Sec<T> {}

impl<T> Borrow<T> for Sec<T> {
    fn borrow(&self) -> &T {
        unsafe { &*self.ptr }
    }
}

impl<T> BorrowMut<T> for Sec<T> {
    fn borrow_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }
}

impl<T> Borrow<[T]> for Sec<T> {
    fn borrow(&self) -> &[T] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T> BorrowMut<[T]> for Sec<T> {
    fn borrow_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<'a, T: Zeroable> From<&'a mut T> for Sec<T> {
    fn from(data: &mut T) -> Self {
        Self::from_raw_parts(data, 1)
    }
}

impl<'a, T: Zeroable> From<&'a mut [T]> for Sec<T> {
    fn from(data: &mut [T]) -> Self {
        Self::from_raw_parts(data.as_mut_ptr(), data.len())
    }
}

impl<T: Randomizable> Sec<T> {
    pub fn random(len: usize) -> Self {
        unsafe { Sec::new(len, |sec| sodium::random(sec.ptr, sec.len)) }
    }
}

impl<T: Default> Sec<T> {
    pub fn default(len: usize) -> Self {
        unsafe {
            Sec::new(len, |sec| {
                let default = T::default();

                for i in 0..len {
                    ptr::copy_nonoverlapping(&default, sec.ptr.offset(i as isize), 1);
                }
            })
        }
    }
}

impl<T: Zeroable> Sec<T> {
    pub fn zero(len: usize) -> Self {
        unsafe { Sec::new(len, |sec| sodium::memzero(sec.ptr, sec.len)) }
    }

    fn from_raw_parts(ptr: *mut T, len: usize) -> Self {
        unsafe { Sec::new(len, |sec| sodium::memmove(ptr, sec.ptr, sec.len)) }
    }
}

impl<T> Sec<T> {
    pub unsafe fn uninitialized(len: usize) -> Self {
        sodium::init();

        let sec = Sec {
            ptr:  sodium::malloc(len),
            len:  len,
            prot: Cell::new(Prot::ReadOnly),
            refs: Cell::new(1),
        };

        sec.lock();
        sec
    }

    pub unsafe fn new<F>(len: usize, init: F) -> Self
        where F: FnOnce(&mut Sec<T>) {
        let mut sec = Self::uninitialized(len);

        sec.write();
        init(&mut sec);
        sec.lock();

        sec
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn size(&self) -> usize {
        self.len() * mem::size_of::<T>()
    }

    pub fn read(&self) {
        self.retain(Prot::ReadOnly)
    }
    pub fn write(&mut self) {
        self.retain(Prot::ReadWrite)
    }

    pub fn lock(&self) {
        self.release()
    }

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

    use std::borrow::Borrow;
    use std::ptr;

    #[test]
    fn it_allows_custom_initialization() {
        let s = unsafe {
            Sec::<u8>::new(1, |sec| {
                ptr::write(sec.ptr, 4);
            })
        };

        s.read();
        assert_eq!(*b"\x04", s.borrow());
        s.lock();
    }

    #[test]
    fn it_initializes_with_zeroes() {
        let s = Sec::<u8>::zero(4);

        s.read();
        assert_eq!(*b"\x00\x00\x00\x00", s.borrow());
        s.lock();
    }

    #[test]
    fn it_compares_equality() {
        let s1 = Sec::<i32>::default(32);
        let s2 = Sec::<i32>::default(32);

        assert_eq!(s1, s2);
        assert_eq!(s2, s1);
    }

    #[test]
    fn it_compares_inequality() {
        let s1 = Sec::<u16>::random(2);
        let s2 = Sec::<u16>::random(2);

        assert!(s1 != s2);
        assert!(s2 != s1);

    }

    #[test]
    fn it_compares_inequality_on_length() {
        let s1 = Sec::<u8>::default(1);
        let s2 = Sec::<u8>::default(2);

        assert!(s1 != s2);
        assert!(s2 != s1);
    }

    #[test]
    fn it_starts_with_zero_refs() {
        let sec = Sec::<u8>::default(10);

        assert_eq!(0, sec.refs.get());
    }

    #[test]
    fn it_tracks_ref_counts_accurately() {
        let mut sec = Sec::<u8>::default(10);

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
        let mut sec = Sec::<u64>::default(1);

        sec.write();
        sec.write();
    }

    #[test]
    #[should_panic]
    fn it_doesnt_allow_different_access_types() {
        let mut sec = Sec::<u8>::default(5);

        sec.read();
        sec.write();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_dropped_with_outstanding_refs() {
        let sec = Sec::<f64>::default(1);

        sec.read();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_released_too_often() {
        let sec = Sec::<u32>::default(10000);

        sec.read();
        sec.lock();
        sec.lock();
    }
}
