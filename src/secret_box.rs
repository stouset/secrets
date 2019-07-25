use crate::boxed::Box;
use crate::traits::*;

use std::fmt::{self, Debug, Formatter};
use std::ops::{Deref, DerefMut};

///
/// A type for protecting fixed-length secrets allocated on the heap.
///
/// Heap-allocated secrets have distinct security needs from
/// stack-allocated ones. They provide the following guarantees:
///
/// * any attempt to access the memory without having been borrowed
///   appropriately will result in immediate program termination; the
///   memory is protected with [`mprotect(2)`][mprotect] as follows:
///   * [`PROT_NONE`][mprotect] when the [`SecretBox`] has no
///     outstanding borrows
///   * [`PROT_READ`][mprotect] when it has outstanding immutable
///     borrows
///   * [`PROT_WRITE`][mprotect] when it has an outstanding mutable
///     borrow
/// * the allocated region has guard pages preceding and following
///   it—both set to [`PROT_NONE`][mprotect]—ensuring that overflows and
///   (large enough) underflows cause immediate program termination
/// * a canary is placed just before the memory location (and after the
///   guard page) in order to detect smaller underflows; if this memory
///   has been written to (and the canary modified), the program will
///   immediately abort when the [`SecretBox`] is [`drop`](Drop)ped
/// * [`mlock(2)`][mlock] is called on the underlying memory
/// * [`munlock(2)`][mlock] is called on the underlying memory when no longer in use
/// * the underlying memory is zeroed when no longer in use
/// * they are best-effort compared in constant time
/// * they are best-effort prevented from being printed by [`Debug`].
/// * they are best-effort protected from [`Clone`]ing the interior data
///
/// To fulfill these guarantees, [`SecretBox`] uses an API similar to
/// (but not exactly like) that of [`RefCell`][refcell]. You must call
/// [`borrow`](SecretBox::borrow) to (immutably) borrow the protected
/// data inside and you must call [`borrow_mut`](SecretBox::borrow_mut)
/// to access it mutably. Unlike [`RefCell`][refcell] which hides
/// interior mutability with immutable borrows, these two calls follow
/// standard borrowing rules: [`borrow_mut`](SecretBox::borrow_mut)
/// takes a `&mut self`, so the borrow checker statically ensures the
/// exclusivity of mutable borrows.
///
/// These [`borrow`](SecretBox::borrow) and
/// [`borrow_mut`](SecretBox::borrow_mut) calls return a wrapper around
/// the interior that ensures the memory is re-[`mprotect`][mprotect]ed
/// when all active borrows leave scope. These wrappers [`Deref`] to the
/// underlying value so you can to work with them as if they were the
/// underlying type, with a few excepitons: they have specific
/// implementations for [`Clone`], [`Debug`], [`PartialEq`], and [`Eq`]
/// that try to ensure that the underlying memory isn't copied out of
/// protected area, that the contents are never printed, and that two
/// secrets are only ever compared in constant time.
///
/// Care *must* be taken not to over-aggressively dereference these
/// wrappers, as once you're working with the real underlying type, we
/// can't prevent direct calls to their implementations of these traits.
/// Care must also be taken not to call any other methods on these types
/// that introduce copying.
///
/// # Example: generate a cryptographically-random 128-bit [`SecretBox`]
///
/// Initialize a [`SecretBox`] with cryptographically random data:
///
/// ```
/// # use secrets::SecretBox;
/// let secret = SecretBox::<u128>::random();
///
/// assert_eq!(secret.size(), 16);
/// ```
///
/// # Example: move mutable data into a [`SecretBox`]
///
/// Existing data can be moved into a [`SecretBox`]. When doing so, we
/// make a best-effort attempt to zero out the data in the original
/// location. Any prior copies will be unaffected, so please exercise as
/// much caution as possible when handling data before it can be
/// protected.
///
/// ```
/// # use secrets::SecretBox;
/// let mut value = 0x0011223344556677u128;
///
/// // the contents of `value` will be copied into the SecretBox before
/// // being zeroed out
/// let secret = SecretBox::from(&mut value);
///
/// // the contents of `value` have been zeroed
/// assert_eq!(value, 0);
/// ```
///
/// # Example: compilation failure from incompatible borrows
///
/// Unlike [`RefCell`][refcell], which hides interior mutability behind
/// immutable borrows, a [`SecretBox`] can't have an outstanding
/// [`borrow`](SecretBox::borrow) and
/// [`borrow_mut`](SecretBox::borrow_mut) at the same time.
///
/// ```compile_fail
/// # use secrets::SecretBox;
/// let mut secret   = SecretBox::<u32>::zero(8);
/// let     secret_r = secret.borrow();
///
/// // error[E0502]: cannot borrow `secret` as mutable because it is
/// // also borrowed as immutable
/// secret.borrow_mut();
/// ```
///
/// # Example: compilation failure from multiple mutable borrows
///
/// Unlike [`RefCell`][refcell], which hides interior mutability behind
/// immutable borrows, a [`SecretBox`] can't have multiple outstanding
/// [`borrow_mut`](SecretBox::borrow_mut)s at the same time.
///
/// ```compile_fail
/// # use secrets::SecretBox;
/// let mut secret   = SecretBox::<u32>::zero(8);
/// let     secret_w = secret.borrow_mut();
///
/// // error[E0499]: cannot borrow `secret` as mutable more than once
/// // at a time
/// secret.borrow_mut();
/// ```
///
/// [mprotect]: http://man7.org/linux/man-pages/man2/mprotect.2.html
/// [mlock]: http://man7.org/linux/man-pages/man2/mlock.2.html
/// [refcell]: std::cell::RefCell
#[derive(Clone, Eq)]
pub struct SecretBox<T: Bytes> {
    /// The internal protected memory underlying the [`SecretBox`].
    boxed: Box<T>,
}

/// An immutable wrapper around the internal contents of a
/// [`SecretBox`]. This wrapper [`Deref`]s to its slice representation
/// for convenience.
///
/// When this wrapper is dropped, it ensures that the underlying memory
/// is re-locked.
#[derive(Eq)]
pub struct Ref<'a, T: Bytes> {
    /// an imutably-unlocked reference to the protected memory of a
    /// [`SecretBox`].
    boxed: &'a Box<T>,
}

/// A mutable wrapper around the internal contents of a
/// [`SecretBox`]. This wrapper [`Deref`]s to its slice representation
/// for convenience.
///
/// When this wrapper is dropped, it ensures that the underlying memory
/// is re-locked.
#[derive(Eq)]
pub struct RefMut<'a, T: Bytes> {
    /// a mutably-unlocked reference to the protected memory of a
    /// [`SecretBox`].
    boxed: &'a mut Box<T>,
}

impl<T: Bytes> SecretBox<T> {
    /// Instantiates and returns a new [`SecretBox`].
    ///
    /// Accepts a callback function that is responsible for initializing
    /// its contents. The value yielded to the initialization callback
    /// will be filled with garbage bytes.
    ///
    /// Example:
    ///
    /// ```
    /// # use secrets::SecretBox;
    /// let secret = SecretBox::<u8>::new(|s| *s = 0x20);
    ///
    /// assert_eq!(*secret.borrow(), 0x20);
    /// ```
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        Self {
            boxed: Box::new(1, |b| f(b.as_mut())),
        }
    }

    /// Instantiates and returns a new [`SecretBox`]. Has equivalent
    /// semantics to [`new`][SecretBox::new], but allows the callback to
    /// return success or failure through a [`Result`].
    pub fn try_new<U, E, F>(f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut T) -> Result<U, E>,
    {
        Box::try_new(1, |b| f(b.as_mut()))
            .map(|b| Self { boxed: b })
    }

    /// Returns the size in bytes of the [`SecretBox`].
    pub fn size(&self) -> usize {
        self.boxed.size()
    }

    /// Immutably borrows the contents of the [`SecretBox`]. Returns a
    /// wrapper that ensures the underlying memory is
    /// [`mprotect(2)`][mprotect]ed once all borrows exit scope.
    ///
    /// Example:
    ///
    /// ```
    /// # use secrets::SecretBox;
    /// let secret    = SecretBox::<u8>::from(&mut 127);
    /// let secret_r1 = secret.borrow();
    /// let secret_r2 = secret.borrow();
    ///
    /// assert_eq!(*secret_r1, 127);
    /// assert_eq!(*secret_r2, 127);
    /// assert_eq!(secret_r1, secret_r2);
    /// ```
    ///
    /// [mprotect]: http://man7.org/linux/man-pages/man2/mprotect.2.html
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::new(&self.boxed)
    }

    /// Mutably borrows the contents of the [`SecretBox`]. Returns a
    /// wrapper that ensures the underlying memory is
    /// [`mprotect(2)`][mprotect]ed once this borrow exits scope.
    ///
    /// Example:
    ///
    /// ```
    /// # use secrets::SecretBox;
    /// let mut secret   = SecretBox::<u8>::zero();
    /// let mut secret_w = secret.borrow_mut();
    ///
    /// *secret_w = 0xaa;
    ///
    /// assert_eq!(*secret_w, 0xaa);
    /// ```
    ///
    /// [mprotect]: http://man7.org/linux/man-pages/man2/mprotect.2.html
    pub fn borrow_mut(&mut self) -> RefMut<'_, T> {
        RefMut::new(&mut self.boxed)
    }
}

impl<T: Bytes + Randomizable> SecretBox<T> {
    /// Creates a new [`SecretBox`] filled with cryptographically-random
    /// bytes.
    pub fn random() -> Self {
        Self {
            boxed: Box::random(1),
        }
    }
}

impl<T: Bytes + Zeroable> SecretBox<T> {
    /// Creates a new [`SecretBox`] filled with zeroes.
    pub fn zero() -> Self {
        Self {
            boxed: Box::zero(1),
        }
    }
}

impl<T: Bytes + Zeroable> From<&mut T> for SecretBox<T> {
    /// Creates a new [`SecretBox`] from existing, unprotected data, and
    /// immediately zeroes out the memory of the data being moved in.
    fn from(data: &mut T) -> Self {
        Self { boxed: data.into() }
    }
}

impl<T: Bytes> Debug for SecretBox<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + ConstantEq> PartialEq for SecretBox<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<'a, T: Bytes> Ref<'a, T> {
    /// Instantiates a new `Ref`.
    fn new(boxed: &'a Box<T>) -> Self {
        proven!(boxed.len() == 1,
            "secrets: attempted to dereference a box with zero length");

        Self {
            boxed: boxed.unlock(),
        }
    }
}

impl<T: Bytes> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self {
            boxed: self.boxed.unlock(),
        }
    }
}

impl<T: Bytes> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> PartialEq for Ref<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.constant_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<RefMut<'_, T>> for Ref<'_, T> {
    fn eq(&self, rhs: &RefMut<'_, T>) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.constant_eq(rhs)
    }
}

impl<'a, T: Bytes> RefMut<'a, T> {
    /// Instantiates a new RefMut.
    fn new(boxed: &'a mut Box<T>) -> Self {
        proven!(boxed.len() == 1,
            "secrets: attempted to dereference a box with zero length");

        Self {
            boxed: boxed.unlock_mut(),
        }
    }
}

impl<T: Bytes> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut()
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since it's already
        // unlocked
        self.constant_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<Ref<'_, T>> for RefMut<'_, T> {
    fn eq(&self, rhs: &Ref<'_, T>) -> bool {
        // technically we could punt to `self.boxed.eq(&other.boxed),
        // but the handler for that performs some extra locks and
        // unlocks which are unnecessary here since we know both sides
        // are already unlocked
        self.constant_eq(rhs)
    }
}

// LCOV_EXCL_START

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_allows_custom_initialization() {
        let _ = SecretBox::<u64>::new(|s| {
            *s = 0x8f1a;

            assert_eq!(*s, 0x8f1a);
        });
    }

    #[test]
    fn it_allows_failing_initialization() {
        assert!(SecretBox::<u8>::try_new(|_| Err::<(), ()>(())).is_err());
    }

    #[test]
    fn it_allows_borrowing_immutably() {
        let secret = SecretBox::<u64>::zero();
        let s      = secret.borrow();

        assert_eq!(*s, 0);
    }

    #[test]
    fn it_allows_borrowing_mutably() {
        let mut secret = SecretBox::<u64>::zero();
        let mut s      = secret.borrow_mut();

        *s = 0x01ab_cdef;

        assert_eq!(*s, 0x01ab_cdef);
    }

    #[test]
    fn it_allows_storing_fixed_size_arrays() {
        let secret = SecretBox::<[u8; 2]>::new(|s| {
            *s = [0xdd, 0xa1];
        });

        assert_eq!(*secret.borrow(), [0xdd, 0xa1]);
    }

    #[test]
    fn it_provides_its_size() {
        let secret = SecretBox::<[u128; 4]>::zero();
        assert_eq!(secret.size(), 64);
    }

    #[test]
    fn it_preserves_secrecy() {
        let mut secret = SecretBox::<u64>::random();

        assert_eq!(
            format!("{{ {} bytes redacted }}", 8),
            format!("{:?}", secret),
        );

        assert_eq!(
            format!("{{ {} bytes redacted }}", 8),
            format!("{:?}", secret.borrow()),
        );

        assert_eq!(
            format!("{{ {} bytes redacted }}", 8),
            format!("{:?}", secret.borrow_mut()),
        );
    }

    #[test]
    fn it_moves_safely() {
        let secret_1 = SecretBox::<u8>::zero();
        let secret_2 = secret_1;

        assert_eq!(*secret_2.borrow(), 0);
    }

    #[test]
    fn it_safely_clones_immutable_references() {
        let secret   = SecretBox::<u8>::random();
        let borrow_1 = secret.borrow();
        let borrow_2 = borrow_1.clone();

        assert_eq!(borrow_1, borrow_2);
    }

    #[test]
    fn it_compares_equality() {
        let secret_1 = SecretBox::<u8>::from(&mut 0xaf);
        let secret_2 = secret_1.clone();

        assert_eq!(secret_1, secret_2);
    }

    #[test]
    fn it_compares_inequality() {
        let secret_1 = SecretBox::<[u128; 8]>::random();
        let secret_2 = SecretBox::<[u128; 8]>::random();

        assert_ne!(secret_1, secret_2);
    }

    #[test]
    fn it_compares_equality_immutably_on_refs() {
        let secret_1 = SecretBox::<u8>::from(&mut 0xaf);
        let secret_2 = secret_1.clone();

        assert_eq!(secret_1.borrow(), secret_2.borrow());
    }

    #[test]
    fn it_compares_equality_immutably_on_ref_muts() {
        let mut secret_1 = SecretBox::<u8>::from(&mut 0xaf);
        let mut secret_2 = secret_1.clone();

        assert_eq!(secret_1.borrow_mut(), secret_2.borrow_mut());
    }

    #[test]
    fn it_compares_equality_immutably_regardless_of_mut() {
        let mut secret_1 = SecretBox::<u8>::from(&mut 0xaf);
        let mut secret_2 = secret_1.clone();

        assert_eq!(secret_1.borrow_mut(), secret_2.borrow());
        assert_eq!(secret_2.borrow_mut(), secret_1.borrow());
    }
}

#[cfg(all(test, profile = "debug"))]
mod tests_proven_statements {
    #![allow(unsafe_code)]

    use super::*;

    #[test]
    #[should_panic(expected = "secrets: attempted to dereference a zero-length pointer")]
    fn it_doesnt_allow_borrowing_zero_length() {
        let boxed = Box::<u8>::zero(0);
        let _     = boxed.as_ref();
    }

    #[test]
    #[should_panic(expected = "secrets: attempted to dereference a zero-length pointer")]
    fn it_doesnt_allow_mutably_borrowing_zero_length() {
        let mut boxed = Box::<u8>::zero(0);
        let     _     = boxed.as_mut();
    }
}

// LCOV_EXCL_STOP
