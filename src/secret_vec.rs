use crate::boxed::Box;
use crate::traits::*;

use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

#[derive(Eq)]
pub struct SecretVec<T: ByteValue> {
    boxed: Box<T>,
}

#[derive(Eq)]
pub struct Ref<'a, T: ByteValue> {
    boxed: &'a Box<T>,
}

#[derive(Eq)]
pub struct RefMut<'a, T: ByteValue> {
    boxed: &'a mut Box<T>,
}

impl<T: ByteValue> SecretVec<T> {
    pub fn len(&self) -> usize {
        self.boxed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.boxed.is_empty()
    }

    pub fn size(&self) -> usize {
        self.boxed.size()
    }

    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::new(&self.boxed)
    }

    pub fn borrow_mut(&mut self) -> RefMut<'_, T> {
        RefMut::new(&mut self.boxed)
    }
}

impl<T: ByteValue + Uninitializable> SecretVec<T> {
    pub fn new<F>(len: usize, f: F) -> Self where F: FnOnce(&mut [T]) {
        Self { boxed: Box::new(len, f) }
    }

    pub fn uninitialized(len: usize) -> Self {
        Self { boxed: Box::uninitialized(len) }
    }
}

impl<T: ByteValue + Randomizable> SecretVec<T> {
    pub fn random(len: usize) -> Self {
        Self { boxed: Box::random(len) }
    }
}

impl<T: ByteValue + Zeroable> SecretVec<T> {
    pub fn zero(len: usize) -> Self {
        Self { boxed: Box::zero(len) }
    }
}

impl<T: ByteValue> Debug for SecretVec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result { self.boxed.fmt(f) }
}

impl<T: ByteValue + ConstantEq> PartialEq for SecretVec<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<'a, T: ByteValue> Ref<'a, T> {
    fn new(boxed: &'a Box<T>) -> Self {
        Self { boxed: boxed.unlock() }
    }
}

impl<T: ByteValue> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: ByteValue> Deref for Ref<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: ByteValue> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result { self.boxed.fmt(f) }
}

impl<T: ByteValue> PartialEq for Ref<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.as_ref().constant_eq(rhs.as_ref())
    }
}

impl<T: ByteValue> PartialEq<RefMut<'_, T>> for Ref<'_, T> {
    fn eq(&self, rhs: &RefMut<'_, T>) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.as_ref().constant_eq(rhs.as_ref())
    }
}

impl<'a, T: ByteValue> RefMut<'a, T> {
    fn new(boxed: &'a mut Box<T>) -> Self {
        Self { boxed: boxed.unlock_mut() }
    }
}

impl<T: ByteValue> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: ByteValue> Deref for RefMut<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: ByteValue> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut()
    }
}

impl<T: ByteValue> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result { self.boxed.fmt(f) }
}

impl<T: ByteValue> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since it's already
        // unlocked
        self.as_ref().constant_eq(rhs.as_ref())
    }
}

impl<T: ByteValue> PartialEq<Ref<'_, T>> for RefMut<'_, T> {
    fn eq(&self, rhs: &Ref<'_, T>) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.as_ref().constant_eq(rhs.as_ref())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_allows_custom_initialization() {
        let _ = SecretVec::<u64>::new(4, |s| {
            s.clone_from_slice(&[1, 2, 3, 4][..]);

            assert_eq!(*s, [1, 2, 3, 4]);
        });
    }

    #[test]
    fn it_allows_borrowing_immutably() {
        let secret = SecretVec::<u64>::zero(2);
        let s      = secret.borrow();

        assert_eq!(*s, [0, 0]);
    }

    #[test]
    fn it_allows_borrowing_mutably() {
        let mut secret = SecretVec::<u64>::zero(2);
        let mut s      = secret.borrow_mut();

        s.clone_from_slice(&[7, 1][..]);

        assert_eq!(*s, [7, 1]);
    }

    #[test]
    fn it_allows_storing_fixed_size_arrays() {
        let secret = SecretVec::<[u8; 2]>::new(2, |s| {
            s.clone_from_slice(&[[1, 2], [3, 4]][..]);
        });

        assert_eq!(*secret.borrow(), [[1, 2], [3, 4]]);
    }
}
