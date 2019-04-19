#![allow(unsafe_code)]

// `clippy` currently warns when trait functions could be `const fn`s, but this
// is not actually allowed by the language
#![cfg_attr(feature = "cargo-clippy", allow(clippy::missing_const_for_fn))]

mod bytes;
mod constant_eq;
mod randomizable;
mod zeroable;

pub use bytes::{Bytes, AsContiguousBytes};
pub use constant_eq::ConstantEq;
pub use randomizable::Randomizable;
pub use zeroable::Zeroable;

macro_rules! impls {
    ($($ty:ty),* ; $ns:tt) => {$(
        impls!{prim  $ty}
        impls!{array $ty; $ns}
    )*};

    (prim $ty:ty) => {
        #[allow(trivial_casts)]
        unsafe impl Bytes for $ty {
            fn as_u8_ptr(&self) -> *const u8 { self as *const Self as *const _ }
            fn as_mut_u8_ptr(&mut self) -> *mut u8 { self as *mut Self as *mut _ }
        }

        unsafe impl Randomizable for $ty {}
    };

    (array $ty:ty; ($($n:tt)*)) => {$(
        #[allow(trivial_casts)]
        unsafe impl Bytes for [$ty; $n] {
            fn as_u8_ptr(&self) -> *const u8 { self.as_ptr() as *const _ }
            fn as_mut_u8_ptr(&mut self) -> *mut u8 { self.as_mut_ptr() as *mut _ }
        }

        unsafe impl Randomizable for [$ty; $n] {}
    )*};
}

impls!{
    u8, u16, u32, u64, u128; (

     0  1  2  3  4  5  6  7  8  9
    10 11 12 13 14 15 16 17 18 19
    20 21 22 23 24 25 26 27 28 29
    30 31 32 33 34 35 36 37 38 39
    40 41 42 43 44 45 46 47 48 49
    50 51 52 53 54 55 56 57 58 59
    60 61 62 63 64

    // 521-bit (8 * 65.25) keys are a thing (ECDH / ECDSA)
    66

    // "million-bit keys ought to be enough for anybody"
    128 256 384 512 1024 2048 4096 8192
)}
