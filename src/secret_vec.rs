use marker::{Randomizable, Zeroable};
use sec::Sec;

use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

/// A type that wraps a dynamic amount of allocated memory suitable
/// for cryptographic secrets.
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
/// use secrets::SecretVec;
///
/// let secret   = SecretVec::<u8>::random(32);
/// let secret_r = secret.borrow();
///
/// println!("{:?}", secret_r);
/// ```
///
/// Secrets from existing mutable data:
///
/// ```
/// use secrets::SecretVec;
///
/// // static data for the test; static data *can't* be wiped, but
/// // copies of it will be
/// let reference : &'static [u8; 4] = b"\xfa\x12\x00\xd9";
/// let zeroes    : &'static [u8; 4] = b"\x00\x00\x00\x00";
///
/// let mut bytes = *reference;
/// let secret    = SecretVec::from(&mut bytes[..]);
/// let secret_r  = secret.borrow();
///
/// assert_eq!(*reference, &*secret_r);
/// assert_eq!(*zeroes,    bytes);
/// ```
///
/// Accessing array contents through pointers:
///
/// ```
/// use secrets::SecretVec;
/// use std::ptr;
///
/// let mut secret   = unsafe { SecretVec::<u8>::uninitialized(4) };
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
/// assert_eq!(*b"\xd0\xd0\xd0\xd0", &*secret_w);
/// ```
///
/// Wrapping custom struct types:
///
/// ```
/// use secrets::{SecretVec, Zeroable};
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
/// let zeroed  = SecretVec::<SensitiveData>::zero(1);
/// let default = SecretVec::<SensitiveData>::default(1);
///
/// assert_eq!(SensitiveData { a: 0, b: 0 }, zeroed .borrow()[0]);
/// assert_eq!(SensitiveData::default(),     default.borrow()[0]);
/// ```
///
#[derive(Debug)]
pub struct SecretVec<T> {
    sec: Sec<T>,
}

impl<T> PartialEq for SecretVec<T> { fn eq(&self, s: &Self) -> bool { self.sec == s.sec } }
impl<T> Eq        for SecretVec<T> {}

impl<'a, T> From<&'a mut [T]> for SecretVec<T> where T: Zeroable {
    /// Moves the contents of `data` into a `SecretVec` and zeroes out
    /// the contents of `data`.
    fn from(data: &mut [T]) -> Self { SecretVec { sec: Sec::from(data) } }
}

impl<T> SecretVec<T> where T: Default {
    /// Creates a new `SecretVec` filled with `len` of the default
    /// value for `T`.
    pub fn default(len: usize) -> Self { SecretVec { sec: Sec::default(len) } }
}

impl<T> SecretVec<T> where T: Randomizable {
    /// Creates a new `SecretVec` filled with `len` cryptographically
    /// random objects of type `T`.
    pub fn random(len: usize) -> Self { SecretVec { sec: Sec::random(len) } }
}

impl<T> SecretVec<T> where T: Zeroable {
    /// Creates a new `SecretVec` filled with `len` zeroed objects of
    /// type `T`.
    pub fn zero(len: usize) -> Self { SecretVec { sec: Sec::zero(len) } }
}

impl<T> SecretVec<T> {
    /// Creates a new `SecretVec` capable of storing `len` objects of
    /// type `T`.
    ///
    /// By default, the allocated region is filled with 0xd0 bytes in
    /// order to help catch bugs due to uninitialized data. This
    /// method is marked as unsafe because filling an arbitrary type
    /// with garbage data is undefined behavior.
    #[allow(unsafe_code)]
    pub unsafe fn uninitialized(len: usize) -> Self { SecretVec { sec: Sec::uninitialized(len) } }

    /// Creates and initializes a new `SecretVec` capable of storing
    /// an object of type `T`.
    ///
    /// Initialization is handled by a closure passed to method, which
    /// accepts a reference to the object to be initialized. The data
    /// in this reference will be uninitialized until written to, so
    /// care must be taken to initialize its memory without reading
    /// from it to avoid undefined behavior.
    #[allow(unsafe_code)]
    pub unsafe fn new<F>(len: usize, init: F) -> Self where F: FnOnce(&mut T) {
        SecretVec { sec: Sec::<T>::new(len, |sec| init(sec.borrow_mut())) }
    }

    /// Returns the number of elements in the `SecretVec`.
    pub fn len(&self)  -> usize { self.sec.len() }

    /// Returns the size in bytes of the data contained in the
    /// `SecretVec`
    pub fn size(&self) -> usize { self.sec.size() }

    /// Returns a `RefVec<T>` from which elements in the `SecretVec` can
    /// be safely read from using slice semantics.
    pub fn borrow(&self) -> RefVec<T> { RefVec::new(&self.sec) }

    /// Returns a `RefVecMut<T>` from which elements in the `SecretVec` can
    /// be safely read from or written to using slice semantics.
    pub fn borrow_mut(&mut self) -> RefVecMut<T> { RefVecMut::new(&mut self.sec) }
}

/// Wraps an immutably borrowed reference to the contents of a `SecretVec`.
#[derive(Debug)]
pub struct RefVec<'a, T: 'a> {
    sec: &'a Sec<T>,
}

/// Wraps an mutably borrowed reference to the contents of a `SecretVec`.
#[derive(Debug)]
pub struct RefVecMut<'a, T: 'a> {
    sec: &'a mut Sec<T>,
}

impl<'a, T> Drop for RefVec<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T> Drop for RefVecMut<'a, T> {
    fn drop(&mut self) { self.sec.lock(); }
}

impl<'a, T> Deref for RefVec<'a, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target { (*self.sec).borrow() }
}

impl<'a, T> Deref for RefVecMut<'a, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target { (*self.sec).borrow() }
}

impl<'a, T> DerefMut for RefVecMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target { (*self.sec).borrow_mut() }
}

impl<'a, T> RefVec<'a, T> {
    fn new(sec: &Sec<T>) -> RefVec<T> {
        sec.read();
        RefVec { sec: sec }
    }
}

impl<'a, T> RefVecMut<'a, T> {
    fn new(sec: &mut Sec<T>) -> RefVecMut<T> {
        sec.write();
        RefVecMut { sec: sec }
    }
}
