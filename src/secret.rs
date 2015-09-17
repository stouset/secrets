use marker::{Randomizable, Zeroable};
use refs::{Ref, RefMut};
use sec::Sec;

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
/// let mut bytes    = reference.clone();
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
/// let mut secret   = unsafe { Secret::<[u8; 4]>::new() };
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
#[derive(Debug)]
pub struct Secret<T> {
    sec: Sec<T>,
}

impl<T> PartialEq for Secret<T> { fn eq(&self, s: &Self) -> bool { self.sec == s.sec } }
impl<T> Eq        for Secret<T> {}

impl<'a, T> From<&'a mut T> for Secret<T> where T: Zeroable {
    /// Moves the contents of `data` into a `Secret` and zeroes out
    /// the contents of `data`.
    fn from(data: &mut T) -> Self { Secret { sec: Sec::from(data) } }
}

impl<T> Default for Secret<T> where T: Default {
    /// Creates a new `Secret` with the default value for `T`.
    fn default() -> Self { Secret { sec: Sec::default(1) } }
}

impl<T> Secret<T> where T: Randomizable {
    /// Creates a new `Secret` capable of storing an object of type `T`
    /// and initialized with a cryptographically random value.
    pub fn random() -> Self { Secret { sec: Sec::random(1) } }
}

impl<T> Secret<T> where T: Zeroable {
    /// Creates a new `Secret` capable of storing an object of type `T`
    /// and initialized to all zeroes.
    pub fn zero() -> Self { Secret { sec: Sec::zero(1) } }
}

impl<T> Secret<T> {
    /// Creates a new `Secret` capable of storing an object of type `T`.
    ///
    /// By default, the allocated region is filled with 0xd0 bytes in
    /// order to help catch bugs due to uninitialized data. This
    /// method is marked as unsafe because filling an arbitrary type
    /// with garbage data is undefined behavior.
    #[allow(unsafe_code)]
    pub unsafe fn new() -> Self { Secret { sec: Sec::new(1) } }

    /// Returns the size in bytes of the data contained in the `Secret`
    pub fn size(&self) -> usize { self.sec.size() }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from.
    pub fn borrow(&self) -> Ref<T> { Ref::new(&self.sec) }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from or written to.
    pub fn borrow_mut(&mut self) -> RefMut<T> { RefMut::new(&mut self.sec) }
}
