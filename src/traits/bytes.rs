use std::mem::{self, MaybeUninit};
use std::slice;

/// Marker value for uninitialized data.
///
/// This value is reused from `src/libsodium/sodium/utils.c` in
/// libsodium. The lowest byte was chosen so that, if accidentally used
/// as the LSB of a pointer, it would be unaligned and thus more likely
/// to trigger noticeable bugs.
///
/// Note that this value was changed in libsodium from an earlier value
/// of `0xd0`. This library makes no specific guarantees to the exact
/// value of this constant, nor that it will always produce consistent
/// garbage values (e.g., memory we fill with garbage values will use
/// this value, but memory allocated by libsodium will use whatever
/// value is defined by the spefiic version of that library being used).
const GARBAGE_VALUE: u8 = 0xdb;

/// A marker trait for types whose size is known at compile time and can
/// be treated as raw buckets of bytes. Any type that implements `Bytes`
/// must not exhibit undefined behavior when its underlying bits are set
/// to any arbitrary bit pattern.
pub unsafe trait Bytes: Sized + Copy {
    /// Returns an uninitialized value.
    ///
    /// Note that this is *not* the same as [`mem::uninitialized`].
    /// Values returned by this function are guaranteed to be set to a
    /// well-defined bit pattern, though this function makes no
    /// guarantees to what specific bit pattern will be used. The bit
    /// pattern has been chosen to maximize the likelihood of catching
    /// bugs due to uninitialized data.
    fn uninitialized() -> Self {
        let mut val = MaybeUninit::<Self>::uninit();

        unsafe {
            val.as_mut_ptr().write_bytes(GARBAGE_VALUE, 1);
            val.assume_init()
        }
    }

    /// Returns the size in bytes of `Self`.
    fn size() -> usize {
        mem::size_of::<Self>()
    }

    /// Returns a `*const u8` pointer to the beginning of the data.
    #[allow(trivial_casts)] // the cast is actually required
    fn as_u8_ptr(&self) -> *const u8 {
        self as *const Self as *const _
    }

    /// Returns a `*mut u8` pointer to the beginning of the data.
    #[allow(trivial_casts)] // the cast is actually required
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self as *mut Self as *mut _
    }
}

/// Marker trait for types who are intrepretable as a series of
/// contiguous bytes, where the exact size may not be known at
/// compile-time. Any type that implements [`AsContiguousBytes`] must
/// not exhibit undefined behavior when its underlying bits are set to
/// any arbitrary bit pattern.
pub unsafe trait AsContiguousBytes {
    /// Returns the size in bytes of `Self`.
    fn size(&self) -> usize;

    /// Returns a `*const u8` pointer to the beginning of the data.
    fn as_u8_ptr(&self) -> *const u8;

    /// Returns a `*mut u8` pointer to the beginning of the data.
    fn as_mut_u8_ptr(&mut self) -> *mut u8;

    /// Returns a byte slice to the underlying data.
    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_u8_ptr(), self.size()) }
    }

    /// Returns a mutable byte slice to the underlying data.
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.as_mut_u8_ptr(), self.size()) }
    }
}

unsafe impl<T: Bytes> AsContiguousBytes for T {
    fn size(&self) -> usize {
        Self::size()
    }

    fn as_u8_ptr(&self) -> *const u8 {
        self.as_u8_ptr()
    }

    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self.as_mut_u8_ptr()
    }
}

unsafe impl<T: Bytes> AsContiguousBytes for [T] {
    fn size(&self) -> usize {
        self.len() * T::size()
    }

    fn as_u8_ptr(&self) -> *const u8 {
        self.as_ptr() as *const _
    }

    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self.as_ptr() as *mut _
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone)]
    struct Byte (u8);

    unsafe impl Bytes for Byte {}

    #[test]
    fn it_uninitializes_to_a_garbage_value() {
        let b = Byte::uninitialized();

        assert_eq!(b.0, GARBAGE_VALUE);
    }

    #[test]
    fn it_reports_size_correctly() {
        assert_eq!(<Byte as Bytes>::size(), 1);
    }

    #[test]
    fn it_provides_ptr_access() {
        unsafe {
            let b = Byte(255);
            assert_eq!(*Bytes::as_u8_ptr(&b), 255);
        }
    }

    #[test]
    fn it_provides_mut_ptr_access() {
        unsafe {
            let mut b = Byte(10);
            *Bytes::as_mut_u8_ptr(&mut b) = 42;
            assert_eq!(b.0, 42);
        }
    }
}
