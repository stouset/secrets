use crate::ffi::sodium;
use crate::traits::*;

/// A marker trait for types that can be compared for equality bitwise
/// in constant time.
///
/// Note that this trait does not *force* types to be compared in
/// constant time. When dealing with types that must be guaranteed to
/// compare in constant time, it is highly encouraged to use wrappers
/// that implement [`PartialEq`] by calling
/// [`constant_eq`](ConstantEq::constant_eq).
pub trait ConstantEq: AsContiguousBytes {
    /// Compares `self` and `rhs`. Guaranteed to return false when the
    /// two arguments differen in size, and guaranteed to perform the
    /// bitwise comparison in constant O(size) time without
    /// short-circuiting.
    fn constant_eq(&self, rhs: &Self) -> bool {
        sodium::memcmp(self.as_bytes(), rhs.as_bytes())
    }
}

// Any type that can be represented as bytes can be compared in constant time.
impl<T: AsContiguousBytes> ConstantEq for T {}
impl<T: Bytes> ConstantEq for [T] {}
