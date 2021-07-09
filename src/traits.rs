//! Marker traits to allow types to be contained as secrets.

#![allow(unsafe_code)]

// `clippy` currently warns when trait functions could be `const fn`s, but this
// is not actually allowed by the language
#![cfg_attr(feature = "cargo-clippy", allow(clippy::missing_const_for_fn))]

/// Traits for types that are considered buckets of bytes.
mod bytes;

/// Traits for types that should be compared for equality in constant
/// time.
mod constant_eq;

/// Traits for types that can have their underlying storage safely set
/// to any arbitrary bytes.
mod randomizable;

/// Traits for types that can have their underlying storage safely
/// zeroed.
mod zeroable;

pub use bytes::{AsContiguousBytes, Bytes};
pub use constant_eq::ConstantEq;
pub use randomizable::Randomizable;
pub use zeroable::Zeroable;

use std::num::*;

unsafe impl Bytes for ()   {}
unsafe impl Bytes for bool {}
unsafe impl Bytes for char {}
unsafe impl Bytes for f32  {}
unsafe impl Bytes for f64  {}

unsafe impl Bytes for i8    {}
unsafe impl Bytes for i16   {}
unsafe impl Bytes for i32   {}
unsafe impl Bytes for i64   {}
unsafe impl Bytes for i128  {}
unsafe impl Bytes for isize {}

unsafe impl Bytes for u8    {}
unsafe impl Bytes for u16   {}
unsafe impl Bytes for u32   {}
unsafe impl Bytes for u64   {}
unsafe impl Bytes for u128  {}
unsafe impl Bytes for usize {}

unsafe impl Bytes for NonZeroI8   {}
unsafe impl Bytes for NonZeroI16  {}
unsafe impl Bytes for NonZeroI32  {}
unsafe impl Bytes for NonZeroI64  {}
unsafe impl Bytes for NonZeroI128 {}

unsafe impl Bytes for NonZeroU8   {}
unsafe impl Bytes for NonZeroU16  {}
unsafe impl Bytes for NonZeroU32  {}
unsafe impl Bytes for NonZeroU64  {}
unsafe impl Bytes for NonZeroU128 {}

unsafe impl<T: Bytes, const N: usize> Bytes for [T; N] {}
