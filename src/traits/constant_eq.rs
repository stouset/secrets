use crate::ffi::sodium;
use super::*;

pub trait ConstantEq : AsContiguousBytes {
    fn constant_eq(&self, rhs: &Self) -> bool {
        sodium::memcmp(self.as_bytes(), rhs.as_bytes())
    }
}

// Any type that can be represented as bytes can be compared in constant time.
impl<T: AsContiguousBytes> ConstantEq for T {}
impl<T: Bytes> ConstantEq for [T] {}
