/// Types able to be initialized with random data.
pub trait Randomizable {}

impl Randomizable for i8  {}
impl Randomizable for i16 {}
impl Randomizable for i32 {}
impl Randomizable for i64 {}
impl Randomizable for u8  {}
impl Randomizable for u16 {}
impl Randomizable for u32 {}
impl Randomizable for u64 {}

impl<T> Randomizable for [T]     where T: Randomizable {}
impl<T> Randomizable for [T;  1] where T: Randomizable {}
impl<T> Randomizable for [T;  2] where T: Randomizable {}
impl<T> Randomizable for [T;  3] where T: Randomizable {}
impl<T> Randomizable for [T;  4] where T: Randomizable {}
impl<T> Randomizable for [T;  5] where T: Randomizable {}
impl<T> Randomizable for [T;  6] where T: Randomizable {}
impl<T> Randomizable for [T;  7] where T: Randomizable {}
impl<T> Randomizable for [T;  8] where T: Randomizable {}
impl<T> Randomizable for [T;  9] where T: Randomizable {}
impl<T> Randomizable for [T; 10] where T: Randomizable {}
impl<T> Randomizable for [T; 11] where T: Randomizable {}
impl<T> Randomizable for [T; 12] where T: Randomizable {}
impl<T> Randomizable for [T; 13] where T: Randomizable {}
impl<T> Randomizable for [T; 14] where T: Randomizable {}
impl<T> Randomizable for [T; 15] where T: Randomizable {}
impl<T> Randomizable for [T; 16] where T: Randomizable {}
impl<T> Randomizable for [T; 17] where T: Randomizable {}
impl<T> Randomizable for [T; 18] where T: Randomizable {}
impl<T> Randomizable for [T; 19] where T: Randomizable {}
impl<T> Randomizable for [T; 20] where T: Randomizable {}
impl<T> Randomizable for [T; 21] where T: Randomizable {}
impl<T> Randomizable for [T; 22] where T: Randomizable {}
impl<T> Randomizable for [T; 23] where T: Randomizable {}
impl<T> Randomizable for [T; 24] where T: Randomizable {}
impl<T> Randomizable for [T; 25] where T: Randomizable {}
impl<T> Randomizable for [T; 26] where T: Randomizable {}
impl<T> Randomizable for [T; 27] where T: Randomizable {}
impl<T> Randomizable for [T; 28] where T: Randomizable {}
impl<T> Randomizable for [T; 29] where T: Randomizable {}
impl<T> Randomizable for [T; 30] where T: Randomizable {}
impl<T> Randomizable for [T; 31] where T: Randomizable {}
impl<T> Randomizable for [T; 32] where T: Randomizable {}
impl<T> Randomizable for [T; 33] where T: Randomizable {}
impl<T> Randomizable for [T; 34] where T: Randomizable {}
impl<T> Randomizable for [T; 35] where T: Randomizable {}
impl<T> Randomizable for [T; 36] where T: Randomizable {}
impl<T> Randomizable for [T; 37] where T: Randomizable {}
impl<T> Randomizable for [T; 38] where T: Randomizable {}
impl<T> Randomizable for [T; 39] where T: Randomizable {}
impl<T> Randomizable for [T; 40] where T: Randomizable {}
impl<T> Randomizable for [T; 41] where T: Randomizable {}
impl<T> Randomizable for [T; 42] where T: Randomizable {}
impl<T> Randomizable for [T; 43] where T: Randomizable {}
impl<T> Randomizable for [T; 44] where T: Randomizable {}
impl<T> Randomizable for [T; 45] where T: Randomizable {}
impl<T> Randomizable for [T; 46] where T: Randomizable {}
impl<T> Randomizable for [T; 47] where T: Randomizable {}
impl<T> Randomizable for [T; 48] where T: Randomizable {}
impl<T> Randomizable for [T; 49] where T: Randomizable {}
impl<T> Randomizable for [T; 50] where T: Randomizable {}
impl<T> Randomizable for [T; 51] where T: Randomizable {}
impl<T> Randomizable for [T; 52] where T: Randomizable {}
impl<T> Randomizable for [T; 53] where T: Randomizable {}
impl<T> Randomizable for [T; 54] where T: Randomizable {}
impl<T> Randomizable for [T; 55] where T: Randomizable {}
impl<T> Randomizable for [T; 56] where T: Randomizable {}
impl<T> Randomizable for [T; 57] where T: Randomizable {}
impl<T> Randomizable for [T; 58] where T: Randomizable {}
impl<T> Randomizable for [T; 59] where T: Randomizable {}
impl<T> Randomizable for [T; 60] where T: Randomizable {}
impl<T> Randomizable for [T; 61] where T: Randomizable {}
impl<T> Randomizable for [T; 62] where T: Randomizable {}
impl<T> Randomizable for [T; 63] where T: Randomizable {}
impl<T> Randomizable for [T; 64] where T: Randomizable {}

/// Types able to be initialized with zeroed data.
pub trait Zeroable {}

impl Zeroable for i8  {}
impl Zeroable for i16 {}
impl Zeroable for i32 {}
impl Zeroable for i64 {}
impl Zeroable for u8  {}
impl Zeroable for u16 {}
impl Zeroable for u32 {}
impl Zeroable for u64 {}

impl<T> Zeroable for [T]     where T: Zeroable {}
impl<T> Zeroable for [T;  1] where T: Zeroable {}
impl<T> Zeroable for [T;  2] where T: Zeroable {}
impl<T> Zeroable for [T;  3] where T: Zeroable {}
impl<T> Zeroable for [T;  4] where T: Zeroable {}
impl<T> Zeroable for [T;  5] where T: Zeroable {}
impl<T> Zeroable for [T;  6] where T: Zeroable {}
impl<T> Zeroable for [T;  7] where T: Zeroable {}
impl<T> Zeroable for [T;  8] where T: Zeroable {}
impl<T> Zeroable for [T;  9] where T: Zeroable {}
impl<T> Zeroable for [T; 10] where T: Zeroable {}
impl<T> Zeroable for [T; 11] where T: Zeroable {}
impl<T> Zeroable for [T; 12] where T: Zeroable {}
impl<T> Zeroable for [T; 13] where T: Zeroable {}
impl<T> Zeroable for [T; 14] where T: Zeroable {}
impl<T> Zeroable for [T; 15] where T: Zeroable {}
impl<T> Zeroable for [T; 16] where T: Zeroable {}
impl<T> Zeroable for [T; 17] where T: Zeroable {}
impl<T> Zeroable for [T; 18] where T: Zeroable {}
impl<T> Zeroable for [T; 19] where T: Zeroable {}
impl<T> Zeroable for [T; 20] where T: Zeroable {}
impl<T> Zeroable for [T; 21] where T: Zeroable {}
impl<T> Zeroable for [T; 22] where T: Zeroable {}
impl<T> Zeroable for [T; 23] where T: Zeroable {}
impl<T> Zeroable for [T; 24] where T: Zeroable {}
impl<T> Zeroable for [T; 25] where T: Zeroable {}
impl<T> Zeroable for [T; 26] where T: Zeroable {}
impl<T> Zeroable for [T; 27] where T: Zeroable {}
impl<T> Zeroable for [T; 28] where T: Zeroable {}
impl<T> Zeroable for [T; 29] where T: Zeroable {}
impl<T> Zeroable for [T; 30] where T: Zeroable {}
impl<T> Zeroable for [T; 31] where T: Zeroable {}
impl<T> Zeroable for [T; 32] where T: Zeroable {}
impl<T> Zeroable for [T; 33] where T: Zeroable {}
impl<T> Zeroable for [T; 34] where T: Zeroable {}
impl<T> Zeroable for [T; 35] where T: Zeroable {}
impl<T> Zeroable for [T; 36] where T: Zeroable {}
impl<T> Zeroable for [T; 37] where T: Zeroable {}
impl<T> Zeroable for [T; 38] where T: Zeroable {}
impl<T> Zeroable for [T; 39] where T: Zeroable {}
impl<T> Zeroable for [T; 40] where T: Zeroable {}
impl<T> Zeroable for [T; 41] where T: Zeroable {}
impl<T> Zeroable for [T; 42] where T: Zeroable {}
impl<T> Zeroable for [T; 43] where T: Zeroable {}
impl<T> Zeroable for [T; 44] where T: Zeroable {}
impl<T> Zeroable for [T; 45] where T: Zeroable {}
impl<T> Zeroable for [T; 46] where T: Zeroable {}
impl<T> Zeroable for [T; 47] where T: Zeroable {}
impl<T> Zeroable for [T; 48] where T: Zeroable {}
impl<T> Zeroable for [T; 49] where T: Zeroable {}
impl<T> Zeroable for [T; 50] where T: Zeroable {}
impl<T> Zeroable for [T; 51] where T: Zeroable {}
impl<T> Zeroable for [T; 52] where T: Zeroable {}
impl<T> Zeroable for [T; 53] where T: Zeroable {}
impl<T> Zeroable for [T; 54] where T: Zeroable {}
impl<T> Zeroable for [T; 55] where T: Zeroable {}
impl<T> Zeroable for [T; 56] where T: Zeroable {}
impl<T> Zeroable for [T; 57] where T: Zeroable {}
impl<T> Zeroable for [T; 58] where T: Zeroable {}
impl<T> Zeroable for [T; 59] where T: Zeroable {}
impl<T> Zeroable for [T; 60] where T: Zeroable {}
impl<T> Zeroable for [T; 61] where T: Zeroable {}
impl<T> Zeroable for [T; 62] where T: Zeroable {}
impl<T> Zeroable for [T; 63] where T: Zeroable {}
impl<T> Zeroable for [T; 64] where T: Zeroable {}
