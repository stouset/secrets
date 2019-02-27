#![allow(unsafe_code)]

use crate::ffi::sodium;

/// Types that can be safely initialized by setting their memory to all zeroes.
///
/// The trait is marked unsafe in order to restrict implementors to types that
/// can safely have their underlying memory set to all zeroes.
pub unsafe trait Zeroable: Sized {
    /// Zeroes out the underlying storage.
    ///
    /// We use `sodium::memzero` rather than `ptr::write_bytes` because the
    /// libsodium version is more resilient against being optimized out
    /// by a smart compiler.
    fn zero(&mut self) {
        unsafe { sodium::memzero(self) }
    }
}
