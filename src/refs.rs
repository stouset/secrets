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

impl<'a, T> Drop for Ref<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T> Drop for RefMut<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T> Deref for Ref<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target { (*self.sec).borrow() }
}

impl<'a, T> Deref for RefMut<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target { (*self.sec).borrow() }
}

impl<'a, T> DerefMut for RefMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target { (*self.sec).borrow_mut() }
}

impl<'a, T> Ref<'a, T> {
    #[doc(hidden)]
    pub fn new(sec: &Sec<T>) -> Ref<T> {
        sec.read();
        Ref { sec: sec }
    }
}

impl<'a, T> RefMut<'a, T> {
    #[doc(hidden)]
    pub fn new(sec: &mut Sec<T>) -> RefMut<T> {
        sec.write();
        RefMut { sec: sec }
    }
}
