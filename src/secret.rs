use refs::{Ref, RefMut};
use sec::Sec;

use std::borrow::BorrowMut;

#[derive(Debug)]
pub struct Secret<T> {
    sec: Sec<T>,
}

impl<'a, T> From<&'a mut T> for Secret<u8> where T: BorrowMut<[u8]> {
    fn from(bytes: &'a mut T) -> Secret<u8> {
        Secret { sec: Sec::from(bytes.borrow_mut()) }
    }
}

impl Secret<u8> {
    pub fn bytes(len: usize) -> Self {
        Secret::new(len)
    }

    pub fn random(len: usize) -> Self {
        Secret { sec: Sec::random(len) }
    }
}

impl<T> Secret<T> {
    pub fn new(len: usize) -> Self {
        Secret { sec: Sec::<T>::new(len) }
    }

    pub fn len(&self) -> usize { self.sec.len() }

    pub fn borrow(&self) -> Ref<T> {
        Ref::new(&self.sec)
    }

    pub fn borrow_mut(&mut self) -> RefMut<T> {
        RefMut::new(&mut self.sec)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]
    use super::Secret;

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
