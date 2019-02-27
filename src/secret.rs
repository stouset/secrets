#![allow(missing_debug_implementations)]
#![allow(unsafe_code)]

use crate::BufMut;
use crate::ffi::sodium;
use crate::traits::*;

/// A buffer to arbitrary data which will be zeroed in-place automatically when
/// it leaves scope.
pub struct Secret<T: Bytes> {
    data: T,
}

impl<T: Bytes> Secret<T> {
    pub fn uninitialized<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        let mut secret = Self { data: T::uninitialized() };

        f(BufMut::new(&mut secret.data));
    }

    pub fn random<F>(f: F) where F: FnOnce(BufMut<'_, T>) {
        let mut secret = Self { data: T::uninitialized() };
        secret.data.randomize();

        f(BufMut::new(&mut secret.data));
    }

    pub fn from<F>(v: &mut T, f: F) where F: FnOnce(BufMut<'_, T>) {
        let mut secret = Self { data: T::uninitialized() };

        unsafe { sodium::memmove(v, &mut secret.data) };

        f(BufMut::new(&mut secret.data));
    }
}

impl<T: Bytes> Drop for Secret<T> {
    fn drop(&mut self) {
        self.data.zero();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_defaults_to_garbage_data() {
        Secret::<u16>::uninitialized(|s| assert_eq!(*s, 0xdbdb));
    }

    #[test]
    fn it_zeroes_when_leaving_scope() {
        unsafe {
            let mut ptr: *const _ = std::mem::uninitialized();

            // since we're not assigning the result of this, the `Secret`
            // leaves scope immediately and should zero its storage
            Secret::uninitialized(|mut s| {
                *s  = 0xae;
                ptr = s.as_ptr();
            });

            assert_eq!(*ptr, 0);
        }
    }

    #[test]
    fn it_initializes_from_values() {
        let mut value = 5;

        Secret::from(&mut value, |s| assert_eq!(*s, 5));
    }

    #[test]
    fn it_zeroes_values_when_initializing_from() {
        let mut value = 5;

        Secret::from(&mut value, |_| { });

        assert_eq!(value, 0);
    }

    #[test]
    fn it_zeroes_on_drop() {
        unsafe {
            let mut ptr: *const u64 = std::mem::uninitialized();
            Secret::<u64>::uninitialized(|s| ptr = s.as_ptr());

            assert_eq!(*ptr, 0x0);
        }
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
        Secret::<i128>::random(|a| {
            Secret::<i128>::random(|b| {
                assert_ne!(a, b);
            });
        });
    }

    #[test]
    fn it_preserves_secrecy() {
        Secret::<u64>::random(|s| {
            assert_eq!("[REDACTED]", format!("{:?}", s));
        }
    }
}
