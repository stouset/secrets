#![allow(missing_debug_implementations)]
#![allow(unsafe_code)]

use crate::ffi::sodium;
use crate::traits::*;

use std::borrow::BorrowMut;
use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

///
/// A buffer to arbitrary data which will be zeroed in-place automatically when
/// it leaves scope.
///
pub struct Secret<T: Bytes> {
    data: T,
}

#[derive(Eq)]
pub struct Buf<'a, T: ConstantEq> {
    data: &'a mut T,
}

impl<T: Bytes> Secret<T> {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::new_ret_no_self))]
    pub fn new<F>(f: F) where F: FnOnce(Buf<'_, T>) {
        let mut secret = Self {
            data: T::uninitialized()
        };

        if unsafe { !sodium::mlock(&secret.data) } {
            panic!("secrets: unable to mlock memory for a Secret")
        };

        f(Buf::new(&mut secret.data));
    }
}

impl<T: Bytes + Zeroable> Secret<T> {
    pub fn zero<F>(f: F) where F: FnOnce(Buf<'_, T>) {
        Self::new(|mut s| { s.zero(); f(s) })
    }

    pub fn from<F>(v: &mut T, f: F) where F: FnOnce(Buf<'_, T>) {
        Self::new(|mut s| { unsafe { v.transfer(s.borrow_mut()) }; f(s) })
    }
}

impl<T: Bytes + Randomizable> Secret<T> {
    pub fn random<F>(f: F) where F: FnOnce(Buf<'_, T>) {
        Self::new(|mut s| { s.randomize(); f(s) })
    }
}

impl<T: Bytes> Drop for Secret<T> {
    fn drop(&mut self) {
        if unsafe { !sodium::munlock(&self.data) } {
            panic!("secrets: unable to munlock memory for a Secret")
        };
    }
}

impl<'a, T: ConstantEq> Buf<'a, T> {
    pub(crate) fn new(data: &'a mut T) -> Self {
        Self { data }
    }
}

impl<T: Bytes + Clone> Clone for Buf<'_, T> {
    fn clone(&self) -> Self {
        panic!("secrets: a Secret may not be cloned")
    }
}

impl<T: ConstantEq> Debug for Buf<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{{ {} bytes redacted }}", self.data.size())
    }
}

impl<T: ConstantEq> Deref for Buf<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}
impl<T: ConstantEq> DerefMut for Buf<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: ConstantEq> PartialEq for Buf<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.data.constant_eq(rhs.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn it_defaults_to_garbage_data() {
        Secret::<u16>::new(|s| assert_eq!(*s, 0xdbdb));
    }

    #[test]
    fn it_zeroes_when_leaving_scope() {
        unsafe {
            let mut ptr: *const _ = ptr::null();

            Secret::<u128>::new(|mut s| {
                // Funnily enough, this test also fails (in release
                // mode) if we set `s` to since the Rust compiler
                // rightly determines that this entire block does
                // nothing and can be optimized away.
                //
                // So we use `sodium::memrandom` which `rustc` doesn't
                // get to perform analysis on to force the compiler to
                // not optimize this whole thing away.
                sodium::memrandom(s.as_mut_bytes());

                // Assign to a pointer that outlives this, which is
                // totally undefined behavior but there's no real other
                // way to test that this works.
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
        Secret::<[u64; 2]>::random(|s| {
            assert_eq!(
                format!("{{ {} bytes redacted }}", 16),
                format!("{:?}", s),
            );
        })
    }

    #[test]
    #[should_panic(expected = "secrets: a Secret may not be cloned")]
    fn it_panics_when_cloned() {
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::redundant_clone))]
        Secret::<u16>::zero(|s| { let _ = s.clone(); });
    }
}
