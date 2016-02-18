//! A collection of fixed-size byte types useful as an abstraction over cryptographic keys.
use traits::{ByteArray, BytewiseEq, IsMutRef, Randomizable, Zeroable};

use std::fmt;
use std::mem;

/// Type for keys of arbitrary byte lengths. Unlike standard arrays of bytes, `Key`s do not
/// implement `std::marker::Copy` and don't have a constructor that accepts or returns value
/// directly (likely resulting in copying), making them somewhat more resistant to accidental
/// misuse.
pub struct Key<T: ByteArray> {
    _k: T,
}

/// A convenience type for 128-bit keys.
pub type Key128 = Key<[u8; 16]>;

/// A convenience type for 256-bit keys.
pub type Key256 = Key<[u8; 32]>;

/// A convenience type for 384-bit keys.
pub type Key384 = Key<[u8; 48]>;

/// A convenience type for 512-bit keys.
pub type Key512 = Key<[u8; 64]>;

impl<T: ByteArray> Key<T> {
    /// Creates a new, uninitialized Key.
    #[allow(unsafe_code)]
    #[inline]
    pub unsafe fn uninitialized() -> Self {
        mem::uninitialized()
    }

    /// Converts the key into an immutable array of bytes.
    #[inline]
    pub fn as_bytes(&self) -> &T {
        &self._k
    }

    /// Converts the key into a mutable array of bytes.
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut T {
        &mut self._k
    }

    /// Converts the key into an immutable slice of bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self._k.as_slice()
    }

    /// Converts the key into a mutable slice of bytes.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self._k.as_mut_slice()
    }

    /// Converts the key into a raw pointer to constant bytes.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    /// Converts the key into a raw pointer to mutable bytes.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    /// The length of the key in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl<T: ByteArray> IsMutRef<T> for Key<T> {
    fn as_mut_ref(&mut self) -> &mut T {
        &mut self._k
    }
}

impl<T: ByteArray> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in self.as_slice() {
            try!(write!(f, "{:02x}", byte))
        }

        Ok(())
    }
}

impl<T: ByteArray + BytewiseEq> PartialEq<Key<T>> for Key<T> {
    fn eq(&self, other: &Key<T>) -> bool {
        BytewiseEq::eq(&self._k, &other._k)
    }
}

impl<T: ByteArray + BytewiseEq> BytewiseEq for Key<T> {}
impl<T: ByteArray + Randomizable> Randomizable for Key<T> {}
impl<T: ByteArray + Zeroable> Zeroable for Key<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use traits::*;

    impl<T: ByteArray + Copy> Key<T> {
        fn new(data: &T) -> Key<T> {
            Key { _k: data.clone() }
        }
    }

    #[test]
    fn it_debugs_as_hex() {
        let k = Key::new(b"\xff\x01\x02\x03");
        let s = format!("{:?}", k);

        assert_eq!(s, "ff010203");
    }

    #[test]
    fn it_initializes_with_zeroes() {
        let k = Key::<[u8; 4]>::zeroed();

        assert_eq!(k.as_slice(), [0; 4]);
    }

    #[test]
    fn it_zeroes() {
        let mut k = Key::<[u8; 8]>::randomized();
        k.zero();

        assert_eq!(k.as_slice(), [0; 8]);
    }

    #[test]
    fn it_initializes_with_random() {
        let k1 = Key256::randomized();
        let k2 = Key256::randomized();
        let k3 = Key256::zeroed();

        assert!(k1 != k2);
        assert!(k1 != k3);
        assert!(k2 != k3);
    }

    #[test]
    fn it_randomizes() {
        let mut k1 = Key512::zeroed();
        k1.randomize();

        assert!(k1.as_slice() != &[0; 64][..]);
    }

    #[test]
    fn it_compares_equality() {
        let k1 = Key::new(b"\x4f\xd1\xaa\xc9");
        let k2 = Key::new(b"\x4f\xd1\xaa\xc9");

        assert_eq!(k1, k2);
    }

    #[test]
    fn it_compares_inequality() {
        let k1 = Key::new(b"\x00\x00\xff\xd1");
        let k2 = Key::new(b"\x00\x01\xff\xd1");

        assert!(k1 != k2);
    }
}
