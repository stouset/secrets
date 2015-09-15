use sec::Sec;

use std::borrow::{Borrow, BorrowMut};
use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

pub struct Ref<'a, T: 'a> {
    sec: &'a Sec<T>,
}

pub struct RefMut<'a, T: 'a> {
    sec: &'a mut Sec<T>,
}

impl<'a, T: 'a> Drop for Ref<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T: 'a> Drop for RefMut<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T: 'a> Debug for Ref<'a, T> where T: Debug {
    fn fmt(&self, f: &mut Formatter) -> Result { self.as_slice().fmt(f) }
}

impl<'a, T: 'a> Debug for RefMut<'a, T> where T: Debug {
    fn fmt(&self, f: &mut Formatter) -> Result { self.as_slice().fmt(f) }
}

impl<'a, T: 'a> Deref for Ref<'a, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target { self.as_slice() }
}

impl<'a, T: 'a> Deref for RefMut<'a, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target { self.as_slice() }
}

impl<'a, T: 'a> DerefMut for RefMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_slice() }
}

impl<'a, T: 'a> Borrow<*const T> for Ref<'a, T> {
    fn borrow(&self) -> &*const T { (*self.sec).borrow() }
}

impl<'a, T: 'a> Borrow<*const T> for RefMut<'a, T> {
    fn borrow(&self) -> &*const T { (*self.sec).borrow() }
}

impl<'a, T: 'a> Borrow<*mut T> for RefMut<'a, T> {
    fn borrow(&self) -> &*mut T { (*self.sec).borrow() }
}

impl<'a, T: 'a> Ref<'a, T> {
    pub fn new(sec: &Sec<T>) -> Ref<T> {
        sec.read();

        Ref { sec: sec }
    }

    pub fn len(&self) -> usize { self.sec.len() }

    pub fn as_ptr(&self)   -> *const T { *self.sec.borrow() }
    pub fn as_slice(&self) -> &[T]     {  self.sec.borrow() }
}

impl<'a, T: 'a> RefMut<'a, T> {
    pub fn new(sec: &mut Sec<T>) -> RefMut<T> {
        sec.write();

        RefMut { sec: sec }
    }

    pub fn len(&self) -> usize { self.sec.len() }

    pub fn as_ptr(&self)           -> *const T { *(*self.sec).borrow() }
    pub fn as_mut_ptr(&mut self)   -> *mut T   { *(*self.sec).borrow() }
    pub fn as_slice(&self)         -> &[T]     {  (*self.sec).borrow() }
    pub fn as_mut_slice(&mut self) -> &mut [T] { self.sec.borrow_mut() }
}
