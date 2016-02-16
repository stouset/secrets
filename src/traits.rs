//! A collection of traits useful for bytewise manipulation of data.

/// Types able to be compared bytewise for equality.
///
/// This probably ought to put a trait bound on Eq, as bytewise
/// equality is an even stronger requirement than being an equivalence
/// relation. However, Rust doesn't impl Eq on arrays with more than
/// 32 entries, and we implement traits on everything up to 64
/// entries.
pub trait BytewiseEq {}

/// Types able to be initialized with random data.
pub trait Randomizable {}

/// Types able to be initialized with zeroed data.
pub trait Zeroable {}

impl<T: BytewiseEq> BytewiseEq for [T] {}
impl<T: Randomizable> Randomizable for [T] {}
impl<T: Zeroable> Zeroable for [T] {}

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
