#![allow(unsafe_code)]

// `crate::buf::BufMut` is reexported in the crate root (and `buf` isn't public)
// so users will never type the repeated name
#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]

use crate::ffi::sodium;
use crate::traits::*;

use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

pub struct Buf<'a, T: Bytes> {
    data: &'a T,
}

impl<'a, T: Bytes> Buf<'a, T> {
    pub(crate) fn new(data: &'a T) -> Self {
        Self { data }
    }

    pub fn as_ptr(&self) -> *const T {
        self.data
    }
}

impl<T: Bytes> Debug for Buf<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "[REDACTED]")
    }
}

impl<T: Bytes> Deref for Buf<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T: Bytes> PartialEq for Buf<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        unsafe { sodium::memcmp(self.data, rhs.data) }
    }
}

impl<T: Bytes> Eq for Buf<'_, T> {}

pub struct BufMut<'a, T: Bytes> {
    data: &'a mut T,
}

impl<'a, T: Bytes> BufMut<'a, T> {
    pub(crate) fn new(data: &'a mut T) -> Self {
        Self { data }
    }

    pub fn as_ptr(&self) -> *const T {
        self.data
    }

    pub fn as_mut_ptr(&self) -> *const T {
        self.data
    }
}

impl<T: Bytes> Debug for BufMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "[REDACTED]")
    }
}

impl<T: Bytes> Deref for BufMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}
impl<T: Bytes> DerefMut for BufMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: Bytes> PartialEq for BufMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        unsafe { sodium::memcmp(self.data, rhs.data) }
    }
}

impl<T: Bytes> Eq for BufMut<'_, T> {}
