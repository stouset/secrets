#![allow(unsafe_code)]

use crate::ffi::sodium;
use super::*;

/// Types that can be safely initialized by setting their memory to all zeroes.
///
/// The trait is marked unsafe in order to restrict implementors to types that
/// can safely have their underlying memory set to all zeroes.
pub unsafe trait Zeroable : AsContiguousBytes {
    ///
    /// Zeroes out the underlying storage.
    ///
    /// We use `sodium::memzero` rather than `ptr::write_bytes` because the
    /// libsodium version is more resilient against being optimized out
    /// by a smart compiler.
    fn zero(&mut self) {
        sodium::memzero(self.as_mut_bytes())
    }

    ///
    /// Copies all bytes from `self` into `other` before zeroing out
    /// `self`.
    ///
    /// `other` must be at least as large as `self`, and the two may
    /// not overlap.
    ///
    unsafe fn transfer(&mut self, other: &mut Self) {
        sodium::memtransfer(
            self .as_mut_bytes(),
            other.as_mut_bytes(),
        )
    }
}

// Anything that can have its underlying storage randomized can inherently have
// its underlying storage zeroed out (since zero is a potentially random
// value).
unsafe impl<T: Randomizable> Zeroable for T {}
unsafe impl<T: ByteValue + Zeroable> Zeroable for [T] {}
