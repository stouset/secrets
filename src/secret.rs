#![allow(missing_debug_implementations)]
#![allow(unsafe_code)]

use crate::BufMut;
use crate::ffi::sodium;
use crate::traits::*;

use std::borrow::BorrowMut;
use std::mem;

///
/// A buffer to arbitrary data which will be zeroed in-place automatically when
/// it leaves scope.
///
pub struct Secret<T: ByteValue> {
    data: T,
}

impl<T: ByteValue> Secret<T> {
    unsafe fn _new<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        let mut secret = Self { data: mem::uninitialized() };

        f(BufMut::new(&mut secret.data));
    }
}

impl<T: ByteValue + Uninitializable> Secret<T> {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::new_ret_no_self))]
    pub fn new<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        unsafe { Self::_new(|mut s| { s.garbage(); f(s) }) }
    }
}

impl<T: ByteValue + Zeroable> Secret<T> {
    pub fn zero<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        unsafe { Self::_new(|mut s| { s.zero(); f(s) }) }
    }

    pub fn from<F>(v: &mut T, f: F) where F: FnOnce(BufMut<'_, T>) {
        unsafe { Self::_new(|mut s| { v.transfer(s.borrow_mut()); f(s) }) }
    }
}

impl<T: ByteValue + Randomizable> Secret<T> {
    pub fn random<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        unsafe { Self::_new(|mut s| { s.randomize(); f(s) })}
    }
}

impl<T: ByteValue> Drop for Secret<T> {
    fn drop(&mut self) {
        sodium::memzero(self.data.as_mut_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_defaults_to_garbage_data() {
        Secret::<u16>::new(|s| assert_eq!(*s, 0xdbdb));
    }

    #[test]
    fn it_zeroes_when_leaving_scope() {
        unsafe {
            let mut ptr: *const _ = std::mem::uninitialized();

            Secret::<u128>::new(|mut s| {
                *s  = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
                ptr = &*s;
            });

            // This is extremely brittle. It works with integers because
            // they compare equality directly but it doesn't work with
            // arrays since they compare using a function call which
            // clobbers the value of `ptr` since it's pointing to the
            // stack.
            //
            // Still, a test here is better than no test here. It would
            // just be nice if we could also test with arrays, but the
            // logic should work regardless. This was spot-checked in a
            // debugger as well.
            assert_eq!(*ptr, 0);
        }
    }

    #[test]
    fn it_initializes_from_values() {
        let mut value = 5;

        Secret::from(&mut value, |s| assert_eq!(*s, 5_u8));
    }

    #[test]
    fn it_zeroes_values_when_initializing_from() {
        let mut value = 5_u8;

        Secret::from(&mut value, |_| { });

        assert_eq!(value, 0);
    }

    #[test]
    fn it_compares_equality() {
        Secret::<u32>::from(&mut 0x0123_4567, |a| {
            Secret::<u32>::from(&mut 0x0123_4567, |b| {
                assert_eq!(a, b);
            });
        });
    }

    #[test]
    fn it_compares_inequality() {
        Secret::<[u64; 4]>::random(|a| {
            Secret::<[u64; 4]>::random(|b| {
                assert_ne!(a, b);
            });
        });
    }

    #[test]
    fn it_preserves_secrecy() {
        Secret::<u64>::random(|s| {
            assert_eq!(
                format!("{{ {} bytes redacted }}", s.size()),
                format!("{:?}", s),
            );
        }
    }
}
