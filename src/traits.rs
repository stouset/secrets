//! Marker traits to allow types to be contained as secrets.
//!
//! Example: compare two values in constant time
//!
//! ```rust
//! # use secrets::traits::ConstantEq;
//! assert!(!8u32.constant_eq(&4u32));
//! ```
//!
//! Example: randomize the contents of some bytes
//!
//! ```rust
//! # use secrets::traits::Randomizable;
//! let mut bytes = [0u64; 2];
//! bytes.randomize();
//!
//! assert_ne!(bytes, [0, 0])
//! ```
//!
//! Example: zero out the contents of some bytes
//!
//! ```rust
//! # use secrets::traits::Zeroable;
//! let mut bytes = [1u8, 2, 3, 4];
//! bytes.zero();
//!
//! assert_eq!(bytes, [0, 0, 0, 0]);
//! ```
//!
//! Example: copy bytes into a target, zeroing out the original bytes
//!
//! ```rust
//! # use secrets::traits::Zeroable;
//! let mut src = [4u8; 4];
//! let mut dst = [1u8; 4];
//!
//! unsafe { src.transfer(&mut dst) };
//!
//! assert_eq!(src, [0, 0, 0, 0]);
//! assert_eq!(dst, [4, 4, 4, 4]);
//! ```

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

unsafe impl Bytes for f32 {}
unsafe impl Bytes for f64 {}

unsafe impl<T: Bytes, const N: usize> Bytes for [T; N] {}

unsafe impl                                             Bytes for ()               {}
unsafe impl<T1: Bytes, T2: Bytes>                       Bytes for (T1, T2)         {}
unsafe impl<T1: Bytes, T2: Bytes, T3: Bytes>            Bytes for (T1, T2, T3)     {}
unsafe impl<T1: Bytes, T2: Bytes, T3: Bytes, T4: Bytes> Bytes for (T1, T2, T3, T4) {}
