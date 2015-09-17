// This comment prevents Emacs from thinking this file is executable
#![allow(unsafe_code)]

use marker::{Randomizable, Zeroable};

use sodium;

use std::borrow::{Borrow, BorrowMut};
use std::cell::Cell;
use std::fmt::{self, Debug};
use std::mem;
use std::ptr;
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

        sodium::free(self.ptr)
    }
}

impl<T> Debug for Sec<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.len)
    }
}

impl<T> PartialEq for Sec<T> {
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
        };

        ret
    }
}

impl<T> Eq for Sec<T> {}

impl<T> Borrow<T> for Sec<T> {
    fn borrow(&self) -> &T { unsafe { &*self.ptr } }
}

impl<T> BorrowMut<T> for Sec<T> {
    fn borrow_mut(&mut self) -> &mut T { unsafe { &mut *self.ptr } }
}

impl<'a, T> From<&'a mut T> for Sec<T> where T: Zeroable {
    fn from(data: &mut T) -> Self {
        let mut sec;

        unsafe {
            sec = Sec::new(1);

            sec.write();
            sodium::memmove(data, sec.ptr, 1);
            sec.lock();
        }

        sec
    }
}

impl<T> Sec<T> where T: Randomizable {
    pub fn random(len: usize) -> Self {
        let mut sec;

        unsafe {
            sec = Sec::new(len);

            sec.write();
            sodium::random(sec.ptr, sec.len);
            sec.lock();
        }

        sec
    }
}

impl<T> Sec<T> where T: Default {
    pub fn default(len: usize) -> Self {
        let mut sec     : Sec<T>;
        let     default : T = T::default();

        unsafe {
            sec = Sec::new(len);

            sec.write();
            for i in 1..len {
                ptr::copy_nonoverlapping(&default, sec.ptr.offset(i as isize), 1);
            }
            sec.lock();
        }

        sec
    }
}

impl<T> Sec<T> where T: Zeroable {
    pub fn zero(len: usize) -> Self {
        let mut sec : Sec<T>;

        unsafe {
            sec = Sec::new(len);

            sec.write();
            sodium::memzero(sec.ptr, sec.len);
            sec.lock();
        }

        sec
    }
}

impl<T> Sec<T> {
    pub unsafe fn new(len: usize) -> Self {
        sodium::init();

        let sec = Sec {
            ptr:  sodium::malloc(len),
            len:  len,
            prot: Cell::new(Prot::ReadOnly),
            refs: Cell::new(1)
        };

        sec.lock();

        sec
    }

    pub fn len(&self)  -> usize { self.len }
    pub fn size(&self) -> usize { self.len() * mem::size_of::<T>() }

    pub fn read(&self)      { self.retain(Prot::ReadOnly) }
    pub fn write(&mut self) { self.retain(Prot::ReadWrite) }
    pub fn lock(&self)      { self.release() }

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
    fn it_compares_equality() {
        let s1 = Sec::<f32>::default(32);
        let s2 = Sec::<f32>::default(32);

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
