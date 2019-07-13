// LCOV_EXCL_LINE

//! Protected-access memory for cryptographic secrets.
//!
//! Provides a convenient way to allocate and access memory for
//! secret data. Data is protected from being read from and/or written
//! to outside of limited scopes, where it may be accessed through
//! pointer semantics or slice semantics.
//!
//! Memory allocations are protected by guard pages before after the
//! allocation, an underflow canary (to catch underflows before a
//! guard page), and are zeroed out when freed.
//!

// TODO: README
// TODO: examples directory
// TODO: sqlite-like assert, always, never, testcase
// TODO: replace sodium::fail() with mocks for testing cleanliness

#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(rustdoc)]
#![warn(unused)]

#![warn(bare_trait_objects)]
#![warn(dead_code)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unreachable_pub)]
#![warn(unstable_features)]
#![warn(unused_import_braces)]
#![warn(unused_lifetimes)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![warn(unsafe_code)]
#![warn(variant_size_differences)]

#![cfg_attr(feature = "cargo-clippy", warn(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::pedantic))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::nursery))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::clone_on_ref_ptr))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::decimal_literal_representation))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::else_if_without_else))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::float_arithmetic))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::float_cmp_const))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::indexing_slicing))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::mem_forget))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::missing_docs_in_private_items))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::print_stdout))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::result_unwrap_used))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_reuse))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_same))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::unimplemented))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::use_debug))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::wrong_pub_self_convention))]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]

/// Macros for ensuring code correctness inspired by [sqlite].
///
/// [sqlite]: https://www.sqlite.org/assert.html
#[cfg(profile = "debug")]
#[macro_use]
mod assert {
    #![allow(unused_macros)]

    /// Results in an `assert!` in debug builds but is a no-op in
    /// coverage and release builds, since we have extraordinarily high
    /// guarantees that it is impossible for this condition to happen in
    /// released code.
    macro_rules! proven {
        ($($arg:tt)*) => {
            assert!($($arg)*)
        }
    }

    /// This is intended to be used in a conditional expression, and
    /// must have the negative case handled in the event that we're wrong;
    /// in debug builds it performs an `assert!`, in coverage builds it
    /// expands to `true`, and in production builds it evaluates to the
    /// condition itself.
    macro_rules! always {
        ($cond:expr) => { {
            assert!($cond); true
        } }
    }

    /// The logical opposite of `always`
    macro_rules! never {
        ($cond:expr) => { {
            assert!(!$cond); true
        } }
    }

    /// Ensures, for code-coverage purposes, that we have tests for
    /// which the condition provided evaluates to `true`, this allows
    /// us to ensure at the source location itself that known edge cases
    /// are considered and tested; in debug and release builds it's a
    /// no-op, and in coverage builds it does some work that can't be
    /// optimized away, so the coverage tool can ensure that that work
    /// is performed at least once (and therefore the condition was
    /// tested).
    macro_rules! tested {
        ($cond:expr)  => ()
    }
}

/// See above.
#[cfg(profile = "coverage")]
#[macro_use]
mod assert {
    #![allow(unused_macros)]
    macro_rules! proven { ($($arg:tt)*) => () }
    macro_rules! always { ($cond:expr)  => { true } }
    macro_rules! never  { ($cond:expr)  => { true } }

    // Well, this sucks. The intent here is that code coverage tools
    // will be able to detect if this line isn't run due to the
    // condition never being satisfied. But right now, they aren't smart
    // enough to do it due to how coverage is tracked. Macros are
    // expanded, but their line hits aren't tracked separately. So just
    // evaluating the condition is enough for the whole thing to be
    // considered run.
    //
    // Still, we'll leave this in place with the hopes that some day it
    // will start working and we'll live in a happy world where we can
    // verify edge cases are tracked.
    macro_rules! tested { ($cond:expr) => {
        if $cond {
            // TODO: replace with [`test::black_box`] when stable
            let _ = crate::ffi::sodium::memcmp(&[], &[]);
        }
    } }
}

/// See above.
#[cfg(profile = "release")]
#[macro_use]
mod assert {
    #![allow(unused_macros)]
    macro_rules! proven { ($($arg:tt)*) => () }
    macro_rules! always { ($cond:expr)  => ($cond) }
    macro_rules! never  { ($cond:expr)  => (!$cond) }
    macro_rules! tested { ($cond:expr)  => () }
}

/// Container for FFI-related code.
mod ffi {
    pub(crate) mod sodium;
}

/// Container for `Box`.
mod boxed;

/// Container for `Secret`.
mod secret;

/// Container for `SecretBox`.
mod secret_box;

/// Container for `SecretVec`.
mod secret_vec;

pub mod traits;

pub use secret::Secret;
pub use secret_box::SecretBox;
pub use secret_vec::SecretVec;
