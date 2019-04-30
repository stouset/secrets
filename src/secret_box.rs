#![allow(missing_debug_implementations)]

use crate::traits::*;

pub struct SecretBox<T: Bytes> {
    ptr: *mut T,
}
