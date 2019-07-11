#![allow(unsafe_code)]

use super::*;
use crate::ffi::sodium;

/// Types that can be safely initialized by setting their memory to a
/// random value.
///
/// The trait is marked unsafe in order to restrict implementors to
/// types that can safely have their underlying memory randomized.
pub unsafe trait Randomizable: AsContiguousBytes {
    /// Randomizes the contents of `self`.
    fn randomize(&mut self) {
        sodium::memrandom(self.as_mut_bytes())
    }
}

unsafe impl<T: AsContiguousBytes + ?Sized> Randomizable for T {}
