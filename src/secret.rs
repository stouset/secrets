use traits::{BytewiseEq, Randomizable, Zeroable};
use sec::Sec;

use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

/// A type that wraps allocated memory suitable for cryptographic
/// secrets.
///
/// When initialized with existing data, the memory of the existing
/// data is zeroed out. That said, this library cannot guarantee that
/// that memory has not been copied elsewhere, swapped to disk, or
/// otherwise handled insecurely so rely on this with caution.
///
/// # Examples
///
/// Generating cryptographic keys:
///
/// ```
/// use secrets::Secret;
///
/// let secret   = Secret::<[u8; 32]>::random();
/// let secret_r = secret.borrow();
///
/// println!("{:?}", secret_r);
/// ```
///
/// Secrets from existing mutable data:
///
/// ```
/// use secrets::Secret;
///
/// // static data for the test; static data *can't* be wiped, but
/// // copies of it will be
/// let reference : &'static [u8; 4] = b"\xfa\x12\x00\xd9";
/// let zeroes    : &'static [u8; 4] = b"\x00\x00\x00\x00";
///
/// let mut bytes    = *reference;
/// let     secret   = Secret::from(&mut bytes);
/// let     secret_r = secret.borrow();
///
/// assert_eq!(*reference, *secret_r);
/// assert_eq!(*zeroes,    bytes);
/// ```
///
/// Accessing array contents through pointers:
///
/// ```
/// use secrets::Secret;
/// use std::ptr;
///
/// let mut secret   = unsafe { Secret::<[u8; 4]>::uninitialized() };
/// let mut secret_w = secret.borrow_mut();
///
/// unsafe {
///     ptr::write_bytes(
///         secret_w.as_mut_ptr(),
///         0xd0,
///         secret_w.len(),
///     );
/// }
///
/// assert_eq!(*b"\xd0\xd0\xd0\xd0", *secret_w);
/// ```
///
/// Wrapping custom struct types:
///
/// ```
/// use secrets::Secret;
/// use secrets::traits::Zeroable;
///
/// #[derive(Debug)]
/// #[derive(PartialEq)]
/// struct SensitiveData { a: u64, b: u8 };
///
/// impl Zeroable for SensitiveData {};
/// impl Default  for SensitiveData {
///     fn default() -> Self { SensitiveData { a: 100, b: 255 } }
/// }
///
/// let zeroed  = Secret::<SensitiveData>::zero();
/// let default = Secret::<SensitiveData>::default();
///
/// assert_eq!(SensitiveData { a: 0, b: 0 }, *zeroed .borrow());
/// assert_eq!(SensitiveData::default(),     *default.borrow());
/// ```
///
#[derive(Debug)]
pub struct Secret<T> {
    sec: Sec<T>,
}

impl<T: BytewiseEq> PartialEq for Secret<T> {
    fn eq(&self, s: &Self) -> bool {
        self.sec == s.sec
    }
}

impl<T: BytewiseEq> Eq for Secret<T> {}

impl<'a, T: Zeroable + Copy> From<&'a mut T> for Secret<T> {
    /// Moves the contents of `data` into a `Secret` and zeroes out
    /// the contents of `data`.
    fn from(data: &mut T) -> Self {
        Secret { sec: Sec::from(data) }
    }
}

impl<T: Default> Default for Secret<T> {
    /// Creates a new `Secret` with the default value for `T`.
    fn default() -> Self {
        Secret { sec: Sec::default(1) }
    }
}

impl<T: Randomizable> Secret<T> {
    /// Creates a new `Secret` capable of storing an object of type `T`
    /// and initialized with a cryptographically random value.
    pub fn random() -> Self {
        Secret { sec: Sec::random(1) }
    }
}

impl<T: Zeroable> Secret<T> {
    /// Creates a new `Secret` capable of storing an object of type `T`
    /// and initialized to all zeroes.
    pub fn zero() -> Self {
        Secret { sec: Sec::zero(1) }
    }
}

impl<T> Secret<T> {
    /// Creates a new `Secret` capable of storing an object of type `T`.
    ///
    /// By default, the allocated region is filled with 0xd0 bytes in
    /// order to help catch bugs due to uninitialized data. This
    /// method is marked as unsafe because filling an arbitrary type
    /// with garbage data is undefined behavior.
    #[allow(unsafe_code)]
    pub unsafe fn uninitialized() -> Self {
        Secret { sec: Sec::uninitialized(1) }
    }

    /// Creates and initializes a new `Secret` capable of storing an
    /// object of type `T`.
    ///
    /// Initialization is handled by a closure passed to method, which
    /// accepts a reference to the object to be initialized. The data
    /// in this reference will be uninitialized until written to, so
    /// care must be taken to initialize its memory without reading
    /// from it to avoid undefined behavior.
    #[allow(unsafe_code)]
    pub unsafe fn new<F>(init: F) -> Self
        where F: FnOnce(&mut T) {
        Secret { sec: Sec::<T>::new(1, |sec| init(sec.borrow_mut())) }
    }

    /// Returns the size in bytes of the data contained in the `Secret`
    pub fn size(&self) -> usize {
        self.sec.size()
    }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from.
    pub fn borrow(&self) -> Ref<T> {
        Ref::new(&self.sec)
    }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from or written to.
    pub fn borrow_mut(&mut self) -> RefMut<T> {
        RefMut::new(&mut self.sec)
    }
}

/// Wraps an immutably borrowed reference to the contents of a `Secret`.
#[derive(Debug)]
pub struct Ref<'a, T: 'a> {
    sec: &'a Sec<T>,
}

/// Wraps an mutably borrowed reference to the contents of a `Secret`.
#[derive(Debug)]
pub struct RefMut<'a, T: 'a> {
    sec: &'a mut Sec<T>,
}

impl<'a, T> Drop for Ref<'a, T> {
    fn drop(&mut self) {
        self.sec.lock();
    }
}

impl<'a, T> Drop for RefMut<'a, T> {
    fn drop(&mut self) {
        self.sec.lock();
    }
}

impl<'a, T> Deref for Ref<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        (*self.sec).borrow()
    }
}

impl<'a, T> Deref for RefMut<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        (*self.sec).borrow()
    }
}

impl<'a, T> DerefMut for RefMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        (*self.sec).borrow_mut()
    }
}

impl<'a, T> Ref<'a, T> {
    fn new(sec: &Sec<T>) -> Ref<T> {
        sec.read();
        Ref { sec: sec }
    }
}

impl<'a, T> RefMut<'a, T> {
    fn new(sec: &mut Sec<T>) -> RefMut<T> {
        sec.write();
        RefMut { sec: sec }
    }
}
