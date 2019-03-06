#![allow(unsafe_code)]

// `crate::buf::BufMut` is reexported in the crate root (and `buf` isn't public)
// so users will never type the repeated name
#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]

use crate::traits::*;

use std::borrow::{Borrow, BorrowMut};
use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

pub struct Buf<'a, T: ConstantEq> {
    data: &'a T,
}

impl<'a, T: ConstantEq> Buf<'a, T> {
    pub(crate) fn new(data: &'a T) -> Self {
        Self { data }
    }
}

impl<T: ConstantEq> Debug for Buf<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{{ {} bytes redacted }}", self.data.size())
    }
}

impl<T: ConstantEq> Borrow<T> for Buf<'_, T> {
    fn borrow(&self) -> &T {
        self.data
    }
}

impl<T: ConstantEq> Deref for Buf<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T: ConstantEq> PartialEq for Buf<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.data.constant_eq(rhs.data)
    }
}

impl<T: ConstantEq> Eq for Buf<'_, T> {}

pub struct BufMut<'a, T: ConstantEq> {
    data: &'a mut T,
}

impl<'a, T: ConstantEq> BufMut<'a, T> {
    pub(crate) fn new(data: &'a mut T) -> Self {
        Self { data }
    }
}

impl<T: ConstantEq> Debug for BufMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{{ {} bytes redacted }}", self.data.size())
    }
}

impl<T: ConstantEq> Borrow<T> for BufMut<'_, T> {
    fn borrow(&self) -> &T {
        self.data
    }
}

impl<T: ConstantEq> BorrowMut<T> for BufMut<'_, T> {
    fn borrow_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<T: ConstantEq> Deref for BufMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}
impl<T: ConstantEq> DerefMut for BufMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: ConstantEq> PartialEq for BufMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.data.constant_eq(rhs.data)
    }
}

impl<T: ConstantEq> Eq for BufMut<'_, T> {}
