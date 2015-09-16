use refs::{Ref, RefMut};
use sec::Sec;

use std::borrow::BorrowMut;

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
/// Random secrets:
///
/// ```
/// use secrets::Secret;
///
/// let secret   = Secret::random(32);
/// let secret_r = secret.borrow();
///
/// println!("{:?}", secret_r.as_slice());
/// ```
///
/// Secrets from existing mutable data:
///
/// ```
/// use secrets::Secret;
///
/// let mut string   = "string".to_string();
/// let     secret   = Secret::from(unsafe { string.as_mut_vec() });
/// let     secret_r = secret.borrow();
///
/// assert_eq!("\0\0\0\0\0\0", string);
/// assert_eq!(b"string",      secret_r.as_slice());
/// ```
///
/// Secrets as pointers:
///
/// ```
/// use secrets::Secret;
/// use std::ptr;
///
/// let mut secret   = Secret::bytes(4);
/// let mut secret_w = secret.borrow_mut();
///
/// unsafe { ptr::write_bytes(secret_w.as_mut_ptr(), 0xff, secret_w.len()) };
///
/// assert_eq!([0xff, 0xff, 0xff, 0xff], secret_w.as_slice());
/// ```
///
#[derive(Debug)]
pub struct Secret<T> {
    sec: Sec<T>,
}

impl<'a, T> From<&'a mut T> for Secret<u8> where T: BorrowMut<[u8]> {
    fn from(bytes: &'a mut T) -> Secret<u8> {
        Secret { sec: Sec::from(bytes.borrow_mut()) }
    }
}

impl<T> PartialEq for Secret<T> {
    fn eq(&self, other: &Secret<T>) -> bool {
        self.sec == other.sec
    }
}

impl<T> Eq for Secret<T> {}

impl Secret<u8> {
    /// Creates a new Secret capable of storing `len` bytes.
    ///
    /// By default, the allocated region is filled with 0xd0 bytes in
    /// order to help catch bugs due to uninitialized data.
    pub fn bytes(len: usize) -> Self {
        Secret::new(len)
    }

    /// Creates a new Secret filled with `len` bytes of
    /// cryptographically random data.
    pub fn random(len: usize) -> Self {
        Secret { sec: Sec::random(len) }
    }
}

impl<T> Secret<T> {
    /// Creates a new Secret capable of storing `len` elements of type
    /// `T`.
    ///
    /// By default, the allocated region is filled with 0xd0 bytes in
    /// order to help catch bugs due to uninitialized data.
    pub fn new(len: usize) -> Self {
        Secret { sec: Sec::new(len) }
    }

    /// Returns the number of elements in the Secret.
    pub fn len(&self) -> usize { self.sec.len() }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from, via either pointer or slice semantics.
    pub fn borrow(&self) -> Ref<T> {
        Ref::new(&self.sec)
    }

    /// Returns a `Ref<T>` from which elements in the `Secret` can be
    /// safely read from or written to, via either pointer or slice
    /// semantics.
    pub fn borrow_mut(&mut self) -> RefMut<T> {
        RefMut::new(&mut self.sec)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]
    use super::Secret;

    #[test]
    fn it_creates_byte_buffers() {
        let secret = Secret::bytes(1397);

        assert_eq!(1397, secret.len());
    }

    #[test]
    fn it_creates_random_byte_buffers() {
        let secret_1 = Secret::random(128);
        let secret_2 = Secret::random(128);

        // if this ever fails, modern crypto is doomed
        assert!(secret_1 != secret_2);
    }

    #[test]
    fn it_copies_input_memory() {
        let mut string   = "string".to_string();
        let     secret   = Secret::from(unsafe { string.as_mut_vec() });
        let     secret_r = secret.borrow();

        assert_eq!(b"string", secret_r.as_slice());
    }

    #[test]
    fn it_zeroes_out_input_memory() {
        let mut string = "string".to_string();
        let     _      = Secret::from(unsafe { string.as_mut_vec() });

        assert_eq!("\0\0\0\0\0\0", string);
    }
}
