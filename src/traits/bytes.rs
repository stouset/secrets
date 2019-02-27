#![allow(unsafe_code)]

use super::*;

/// Types whose semantics allow them to be treated as a bag of bytes that may
/// safely take on any random value.
///
/// The trait is marked unsafe in order to restrict implementors to types that
/// can safely have their underlying memory randomized.

pub unsafe trait Bytes: Sized {}

unsafe impl<T: Bytes> Randomizable for T {}

unsafe impl Bytes for u8 {}
unsafe impl Bytes for u16 {}
unsafe impl Bytes for u32 {}
unsafe impl Bytes for u64 {}
unsafe impl Bytes for u128 {}
unsafe impl Bytes for i8 {}
unsafe impl Bytes for i16 {}
unsafe impl Bytes for i32 {}
unsafe impl Bytes for i64 {}
unsafe impl Bytes for i128 {}
