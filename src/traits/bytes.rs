#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]

use std::mem;
use std::slice;

/// Marker value for uninitialized data. This value is reused from
/// `src/libsodium/sodium/utils.c` in libsodium. The lowest byte was chosen so
/// that, if accidentally used as the LSB of a pointer, it would be unaligned
/// and thus more likely to trigger noticeable bugs.
const GARBAGE_VALUE: u8 = 0xdb;

pub unsafe trait Bytes : Sized + Copy {
    fn as_u8_ptr(&self) -> *const u8;
    fn as_mut_u8_ptr(&mut self) -> *mut u8;

    // TODO: when MaybeUninit is stable, rework this to return
    // actually-uninitialized data, and have callers either write zeroes
    // or garbage or real data into it as necessary
    fn uninitialized() -> Self {
        unsafe {
            let mut val : Self = mem::uninitialized();
            val.as_mut_u8_ptr().write_bytes(GARBAGE_VALUE, val.size());
            val
        }
    }

    fn size() -> usize {
        mem::size_of::<Self>()
    }
}

pub unsafe trait AsContiguousBytes {
    fn size(&self) -> usize;
    fn as_u8_ptr(&self) -> *const u8;
    fn as_mut_u8_ptr(&mut self) -> *mut u8;

    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_u8_ptr(), self.size()) }
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.as_mut_u8_ptr(), self.size()) }
    }
}

unsafe impl<T: Bytes> AsContiguousBytes for T {
    fn size(&self) -> usize { Self::size() }
    fn as_u8_ptr(&self) -> *const u8 { self.as_u8_ptr() }
    fn as_mut_u8_ptr(&mut self) -> *mut u8 { self.as_mut_u8_ptr() }
}

unsafe impl<T: Bytes> AsContiguousBytes for [T] {
    fn size(&self) -> usize { self.len() * T::size() }
    fn as_u8_ptr(&self) -> *const u8 { self.as_ptr() as *const _ }
    fn as_mut_u8_ptr(&mut self) -> *mut u8 { self.as_ptr() as *mut _ }
}
