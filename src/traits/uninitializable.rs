use super::*;
use std::ptr;

/// Marker value for uninitialized data. This value is reused from
/// `src/libsodium/sodium/utils.c` in libsodium. The lowest byte was chosen so
/// that, if accidentally used as the LSB of a pointer, it would be unaligned
/// and thus more likely to trigger noticeable bugs.
const GARBAGE_VALUE: u8 = 0xdb;

pub unsafe trait Uninitializable : AsContiguousBytes + Sized {
    /// Sets the contents of `self` to a known garbage value.
    fn garbage(&mut self) {
        unsafe {
            ptr::write_bytes(
                self.as_mut_u8_ptr(),
                GARBAGE_VALUE,
                self.size()
            );
        }
    }
}

unsafe impl<T: Randomizable> Uninitializable for T {}
