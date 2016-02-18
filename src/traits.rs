//! A collection of traits useful for bytewise manipulation of data.

#![allow(unsafe_code)]

use sodium;
use std::mem;

/// Types that are fixed-size byte arrays.
pub trait ByteArray {
    /// Converts the array to an immutable slice of bytes.
    fn as_slice(&self) -> &[u8];

    /// Converts the array to a mutable slice of bytes.
    fn as_mut_slice(&mut self) -> &mut [u8];
}

/// Types that are considered equal if and only if their backing memory is equal.
//
// This should have a trait bound on Eq, as bytewise equality is an even stronger requirement than
// being an equivalence relation, and we want to have this logic occur for the `==` operator.
// However, Rust doesn't impl Eq on arrays with more than 32 entries, and we implement traits on
// everything up to 64 entries.
pub trait BytewiseEq : Sized {
    /// Compares `self` and `other` for equality by comparing the contents of their memory
    /// directly in constant time.
    fn eq(&self, other: &Self) -> bool {
        unsafe { sodium::memcmp(self, other, 1) }
    }
}

/// Types whose contents can be completely represented by and manipulated through an underlying
/// mutable reference to another type `T`
pub trait IsMutRef<T> {
    /// Cheaply converts `self` to a mutable reference to `T`, through which the original object
    /// can be safely mutated without loss of consistency.
    fn as_mut_ref(&mut self) -> &mut T;
}

/// Types that can be safely initialized by setting their memory to random values.
pub trait Randomizable : Sized {
    /// Returns a randomized instance of the type.
    fn randomized() -> Self {
        let mut v = unsafe { mem::uninitialized::<Self>() };
        v.randomize();
        v
    }

    /// Randomizes the contents of self.
    fn randomize(&mut self) {
        unsafe { sodium::random(self, 1) };
    }
}

/// Types that can be safely initialized by setting their memory to all zeroes.
pub trait Zeroable : Sized {
    /// Returns a zeroed instance of the type.
    fn zeroed() -> Self {
        let mut v = unsafe { mem::uninitialized::<Self>() };
        v.zero();
        v
    }

    /// Ensures the contents of self are zeroed out. This is guaranteed not to be optimized away,
    /// even if the object is never later used.
    fn zero(&mut self) {
        unsafe { sodium::memzero(self, 1) }
    }
}

impl<T> IsMutRef<T> for T {
    fn as_mut_ref(&mut self) -> &mut T {
        self
    }
}

macro_rules! impls {
    (array $($tt:tt)*) => { impls!{ [] $(($tt))* } };
    (tuple $($tt:tt)*) => { impls!{ () void $($tt)* } };
    (prim $($prim:ident)*) => {$(
        impl BytewiseEq for $prim {}
        impl Randomizable for $prim {}
        impl Zeroable for $prim {}
    )*};

    ([] $(($n:expr))*) => {$(
        impl<T: BytewiseEq> BytewiseEq for [T; $n] {}
        impl<T: Randomizable> Randomizable for [T; $n] {}
        impl<T: Zeroable> Zeroable for [T; $n] {}

        impl ByteArray for [u8; $n] {
            fn as_slice(&self) -> &[u8] { self }
            fn as_mut_slice(&mut self) -> &mut [u8] { self }
        }
    )*};

    (()) => { };
    (() $head:ident $($tail:ident)*) => {
        impl<$($tail: BytewiseEq),*> BytewiseEq for ($($tail,)*) {}
        impl<$($tail: Randomizable),*> Randomizable for ($($tail,)*) {}
        impl<$($tail: Zeroable),*> Zeroable for ($($tail,)*) {}
        impls!{ () $($tail)* }
    };
}

impls!{prim
    u8 u16 u32 u64
    i8 i16 i32 i64
}

impls!{array
    64 63 62 61 60 59 58 57
    56 55 54 53 52 51 50 49
    48 47 46 45 44 43 42 41
    40 39 38 37 36 35 34 33
    32 31 30 29 28 27 26 25
    24 23 22 21 20 19 18 17
    16 15 14 13 12 11 10  9
     8  7  6  5  4  3  2  1
     0
}

impls!{tuple
    A B C D E F
    G H I J K L
}
