#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]

use std::mem;
use std::slice;

pub unsafe trait ByteValue : Sized + Copy {
    fn as_u8_ptr(&self) -> *const u8;
    fn as_mut_u8_ptr(&mut self) -> *mut u8;

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

unsafe impl<T: ByteValue> AsContiguousBytes for T {
    fn size(&self) -> usize { Self::size() }
    fn as_u8_ptr(&self) -> *const u8 { self.as_u8_ptr() }
    fn as_mut_u8_ptr(&mut self) -> *mut u8 { self.as_mut_u8_ptr() }
}

unsafe impl<T: ByteValue> AsContiguousBytes for [T] {
    fn size(&self) -> usize { self.len() * T::size() }
    fn as_u8_ptr(&self) -> *const u8 { self.as_ptr() as *const _ }
    fn as_mut_u8_ptr(&mut self) -> *mut u8 { self.as_ptr() as *mut _ }
}
