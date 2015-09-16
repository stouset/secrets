use sec::Sec;

use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

/// Wraps an immutably borrowed reference to the contents of a `Secret`.
///
/// The contents of the `Secret` can be accessed through this `Ref`
/// via slice or pointer semantics. See the documentation for `Secret`
/// for details.
#[derive(Debug)]
pub struct Ref<'a, T: 'a> {
    sec: &'a Sec<T>,
}

/// Wraps an mutably borrowed reference to the contents of a `Secret`.
///
/// The contents of the `Secret` can be accessed through this `RefMut`
/// via slice or pointer semantics. See the documentation for `Secret`
/// for details.
#[derive(Debug)]
pub struct RefMut<'a, T: 'a> {
    sec: &'a mut Sec<T>,
}

impl<'a, T: 'a> Drop for Ref<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T: 'a> Drop for RefMut<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
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
    #[doc(hidden)]
    pub fn new(sec: &Sec<T>) -> Ref<T> {
        sec.read();

        Ref { sec: sec }
    }

    /// Allows the contents to be accessed via a raw pointer.
    pub fn as_ptr(&self)   -> *const T { *self.sec.borrow() }

    /// Allows the contents to be accessed via a slice.
    pub fn as_slice(&self) -> &[T]     {  self.sec.borrow() }
}

impl<'a, T: 'a> RefMut<'a, T> {
    #[doc(hidden)]
    pub fn new(sec: &mut Sec<T>) -> RefMut<T> {
        sec.write();

        RefMut { sec: sec }
    }

    /// Allows the contents to be accessed via a raw pointer.
    pub fn as_ptr(&self)           -> *const T { *(*self.sec).borrow() }

    /// Allows the contents to be accessed mutably via a raw pointer.
    pub fn as_mut_ptr(&mut self)   -> *mut T   { *(*self.sec).borrow() }

    /// Allows the contents to be accessed via a slice.
    pub fn as_slice(&self)         -> &[T]     {  (*self.sec).borrow() }

    /// Allows the contents to be accessed mutably via a slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] { self.sec.borrow_mut() }
}
