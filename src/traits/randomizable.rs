#![allow(unsafe_code)]

use super::Zeroable;
use crate::ffi::sodium;

/// Marker value for uninitialized data. This value is reused from
/// `src/libsodium/sodium/utils.c` in libsodium. The lowest byte was chosen so
/// that, if accidentally used as the LSB of a pointer, it would be unaligned
/// and thus more likely to trigger noticeable bugs.
const GARBAGE_VALUE: u8 = 0xdb;

/// Types that can be safely initialized by setting their memory to a random
/// value.
///
/// The trait is marked unsafe in order to restrict implementors to types that
/// can safely have their underlying memory randomized.
pub unsafe trait Randomizable: Sized {
    /// Returns a new instance of `Self` with its bytes set to a fixed garbage
    /// value.
    fn uninitialized() -> Self {
        let mut val : Self = unsafe { std::mem::uninitialized() };
        val.garbage();
        val
    }

    /// Randomizes the contents of `self`.
    fn randomize(&mut self) {
        unsafe { sodium::memrandom(self) };
    }

    /// Sets the contents of `self` to a known garbage value.
    fn garbage(&mut self) {
        unsafe { std::ptr::write_bytes(self, GARBAGE_VALUE, 1) };
    }
}

/// Anything that can have its underlying storage randomized can inherently have
/// its underlying storage zeroed out (since zero is a potentially random
/// value).
unsafe impl<T: Randomizable> Zeroable for T {}
