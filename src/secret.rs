#![allow(missing_debug_implementations)]
#![allow(unsafe_code)]

use crate::ffi::sodium;
use crate::traits::*;

use std::borrow::BorrowMut;
use std::fmt::{Debug, Formatter, Result};
use std::ops::{Deref, DerefMut};

///
/// A type for protecting secrets allocated on the stack.
///
/// Stack-allocated secrets have distinct security needs from
/// heap-allocated secrets, and should be preferred when possible. They
/// provide the following guarantees:
///
/// * [`mlock(2)`][mlock] is called on the underlying memory
/// * [`munlock(2)`][mlock] is called on the underlying memory when no longer in use
/// * the underlying memory is zeroed out when no longer in use
/// * they are borrowed for their entire lifespan, so cannot be moved
/// * they are best-effort compared in constant time
/// * they are best-effort prevented from being printed by [`Debug`]
/// * they are best-effort prevented from being [`Clone`]d
///
/// To fulfill these guarantees, [`Secret`]s are constructed in an
/// atypical pattern. Rather than having [`new`](Secret::new) return a
/// newly-created instance, [`new`](Secret::new) accepts a callback
/// argument that is provided with a mutably borrowed wrapper around the
/// data in question. This wrapper [`Deref`]s into the desired type,
/// with replacement implementations of [`Debug`], [`PartialEq`], and
/// [`Eq`] to prevent accidental misuse.
///
/// Users *must* take care when dereferencing secrets as this will
/// provide direct access to the underlying type. If the bare type
/// implements traits like [`Clone`], [`Debug`], and [`PartialEq`],
/// those methods can be called directly and will not benefit from the
/// protections provided by this wrapper.
///
/// Users *must* also take care to avoid unintentionally invoking
/// [`Copy`] on the underlying data, as doing so will result in
/// secret data being copied out of the [`Secret`], thus losing the
/// protections provided by this library. Be careful not to invoke
/// methods that take ownership of `self` or functions that move
/// parameters with secret data, since doing so will implicitly create
/// copies.
///
/// # Example: generate a cryptographically-random 128-bit [`Secret`]
///
/// Initialize a [`Secret`] with cryptographically random data:
///
/// ```
/// # use secrets::Secret;
/// Secret::<[u8; 16]>::random(|s| {
///     // use `s` as if it were a `[u8; 16]`
/// });
/// ```
///
/// # Example: move mutable data into a [`Secret`]
///
/// Existing data can be moved into a [`Secret`]. When doing so, we make
/// a best-effort attempt to zero out the data in the original location.
/// Any prior copies will be unaffected, so please exercise as much
/// caution as possible when handling data before it can be protected.
///
/// ```
/// # use secrets::Secret;
/// let mut value = [1u8, 2, 3, 4];
///
/// // the contents of `value` will be copied into the Secret before
/// // being zeroed out
/// Secret::from(&mut value, |s| {
///     assert_eq!(*s, [1, 2, 3, 4]);
/// });
///
/// // the contents of `value` have been zeroed
/// assert_eq!(value, [0, 0, 0, 0]);
/// ```
///
/// [mlock]: http://man7.org/linux/man-pages/man2/mlock.2.html
///
pub struct Secret<T: Bytes> {
    data: T,
}

#[derive(Eq)]
pub struct RefMut<'a, T: ConstantEq> {
    data: &'a mut T,
}

impl<T: Bytes> Secret<T> {
    ///
    /// Creates a new [`Secret`] and invokes the provided callback with
    /// a wrapper to the protected memory.
    ///
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::new_ret_no_self))]
    pub fn new<F>(f: F) where F: FnOnce(RefMut<'_, T>) {
        let mut secret = Self {
            data: T::uninitialized()
        };

        if unsafe { !sodium::mlock(&secret.data) } {
            panic!("secrets: unable to mlock memory for a Secret")
        };

        f(RefMut::new(&mut secret.data));
    }
}

impl<T: Bytes + Zeroable> Secret<T> {
    ///
    /// Creates a new [`Secret`] filled with zeroed bytes and invokes the
    /// callback with a wrapper to the protected memory.
    ///
    pub fn zero<F>(f: F) where F: FnOnce(RefMut<'_, T>) {
        Self::new(|mut s| { s.zero(); f(s) })
    }

    ///
    /// Creates a new [`Secret`] from existing, unprotected data, and
    /// immediately zeroes out the memory of the data being moved in.
    /// Invokes the callback with a wrapper to the protected memory.
    ///
    pub fn from<F>(v: &mut T, f: F) where F: FnOnce(RefMut<'_, T>) {
        Self::new(|mut s| { unsafe { v.transfer(s.borrow_mut()) }; f(s) })
    }
}

impl<T: Bytes + Randomizable> Secret<T> {
    ///
    /// Creates a new [`Secret`] filled with random bytes and invokes the
    /// callback with a wrapper to the protected memory.
    ///
    pub fn random<F>(f: F) where F: FnOnce(RefMut<'_, T>) {
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

impl<'a, T: ConstantEq> RefMut<'a, T> {
    pub(crate) fn new(data: &'a mut T) -> Self {
        Self { data }
    }
}

impl<T: Bytes + Clone> Clone for RefMut<'_, T> {
    fn clone(&self) -> Self {
        panic!("secrets: a Secret may not be cloned")
    }
}

impl<T: ConstantEq> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{{ {} bytes redacted }}", self.data.size())
    }
}

impl<T: ConstantEq> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}
impl<T: ConstantEq> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: ConstantEq> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.data.constant_eq(rhs.data)
    }
}

// LCOV_EXCL_START

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
        Secret::from(&mut 5, |s| assert_eq!(*s, 5_u8));
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
        Secret::<[u64; 2]>::zero(|s| {
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

// LCOV_EXCL_STOP
