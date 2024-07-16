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
//! # Core dumps
//!
//! This library explicitly disables core dumps in release builds that
//! target UNIX systems. This is done to avoid retrival of a secret
//! from it. You can still opt-in on allowing code dumps with
//! `allow-coredumps` feature flag.
//!
//! # Example: generating crytographic keys
//!
//! ```
//! use secrets::Secret;
//!
//! Secret::<[u8; 16]>::random(|s| {
//!     // use `s` as if it were a `&mut [u8; 16]`
//!     //
//!     // the memory is `mlock(2)`ed and will be zeroed when this closure
//!     // exits
//! });
//! ```
//!
//! # Example: load a master key from disk and generate subkeys from it
//!
//! ```
//! use std::fs::File;
//! use std::io::Read;
//!
//! use libsodium_sys as sodium;
//! use secrets::SecretBox;
//!
//! const KEY_LEN : usize = sodium::crypto_kdf_KEYBYTES     as _;
//! const CTX_LEN : usize = sodium::crypto_kdf_CONTEXTBYTES as _;
//!
//! const CONTEXT : &[u8; CTX_LEN] = b"example\0";
//!
//! fn derive_subkey(
//!     key:       &[u8; KEY_LEN],
//!     context:   &[u8; CTX_LEN],
//!     subkey_id: u64,
//!     subkey:    &mut [u8],
//! ) {
//!     unsafe {
//!         libsodium_sys::crypto_kdf_derive_from_key(
//!             subkey.as_mut_ptr(),
//!             subkey.len(),
//!             subkey_id,
//!             context.as_ptr() as *const i8,
//!             key.as_ptr()
//!         );
//!     }
//! }
//!
//! let master_key = SecretBox::<[u8; KEY_LEN]>::try_new(|mut s| {
//!     File::open("example/master_key/key")?.read_exact(s)
//! })?;
//!
//! let subkey_0 = SecretBox::<[u8; 16]>::new(|mut s| {
//!     derive_subkey(&master_key.borrow(), CONTEXT, 0, s);
//! });
//!
//! let subkey_1 = SecretBox::<[u8; 16]>::new(|mut s| {
//!     derive_subkey(&master_key.borrow(), CONTEXT, 1, s);
//! });
//!
//! assert_ne!(
//!     subkey_0.borrow(),
//!     subkey_1.borrow(),
//! );
//!
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Example: securely storing a decrypted ciphertext in memory
//!
//! ```
//! use std::fs::File;
//! use std::io::Read;
//!
//! use libsodium_sys as sodium;
//! use secrets::{SecretBox, SecretVec};
//!
//! const KEY_LEN   : usize = sodium::crypto_secretbox_KEYBYTES   as _;
//! const NONCE_LEN : usize = sodium::crypto_secretbox_NONCEBYTES as _;
//! const MAC_LEN   : usize = sodium::crypto_secretbox_MACBYTES   as _;
//!
//! let mut key        = SecretBox::<[u8; KEY_LEN]>::zero();
//! let mut nonce      = [0; NONCE_LEN];
//! let mut ciphertext = Vec::new();
//!
//! File::open("example/decrypted_ciphertext/key")?
//!     .read_exact(key.borrow_mut().as_mut())?;
//!
//! File::open("example/decrypted_ciphertext/nonce")?
//!     .read_exact(&mut nonce)?;
//!
//! File::open("example/decrypted_ciphertext/ciphertext")?
//!     .read_to_end(&mut ciphertext)?;
//!
//! let plaintext = SecretVec::<u8>::new(ciphertext.len() - MAC_LEN, |mut s| {
//!     if -1 == unsafe {
//!         sodium::crypto_secretbox_open_easy(
//!             s.as_mut_ptr(),
//!             ciphertext.as_ptr(),
//!             ciphertext.len() as _,
//!             nonce.as_ptr(),
//!             key.borrow().as_ptr(),
//!         )
//!     } {
//!         panic!("failed to authenticate ciphertext during decryption");
//!     }
//! });
//!
//! assert_eq!(
//!     *b"attack at dawn",
//!     *plaintext.borrow(),
//! );
//!
//! # Ok::<(), std::io::Error>(())
//! ```

// TODO: examples directory
// TODO: replace sodium::fail() with mocks for testing cleanliness

#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(rust_2021_compatibility)]
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
#![cfg_attr(
    feature = "cargo-clippy",
    warn(clippy::decimal_literal_representation)
)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::else_if_without_else))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::float_arithmetic))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::float_cmp_const))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::indexing_slicing))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::mem_forget))]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(clippy::missing_docs_in_private_items)
)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::print_stdout))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::unwrap_used))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_reuse))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_same))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::unimplemented))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::use_debug))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::must_use_candidate))]
// disabled due to https://github.com/rust-lang/rust-clippy/issues/5369
#![cfg_attr(feature = "cargo-clippy", allow(clippy::redundant_pub_crate))]
// disabled due to https://github.com/rust-lang/rust/issues/69952
#![cfg_attr(feature = "cargo-clippy", allow(clippy::wildcard_imports))]

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
        };
    }

    /// This is intended to be used in a conditional expression, and
    /// must have the negative case handled in the event that we're wrong;
    /// in debug builds it performs an `assert!`, in coverage builds it
    /// expands to `true`, and in production builds it evaluates to the
    /// condition itself.
    macro_rules! always {
        ($cond:expr) => { {
            assert!($cond); true
        } };

        ($cond:expr, $($arg:tt)*) => {
            assert!($cond, $($arg)*)
        };
    }

    /// The logical opposite of `always`
    macro_rules! never {
        ($cond:expr) => { {
            assert!(!$cond); false
        } };

        ($cond:expr, $($arg:tt)*) => {
            assert!(!$cond, $($arg)*)
        };
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
        ($cond:expr) => {};
    }
}

/// See above.
#[cfg(profile = "coverage")]
#[macro_use]
mod assert {
    #![allow(unused_macros)]
    macro_rules! proven {
        ($($arg:tt)*) => {};
    }

    macro_rules! always {
        ($cond:expr) => {
            true
        };

        ($cond:expr, $($arg:tt)*) => {
            assert!($cond, $($arg)*)
        };
    }

    macro_rules! never {
        ($cond:expr) => {
            false
        };

        ($cond:expr, $($arg:tt)*) => {
            assert!(!$cond, $($arg)*)
        };
    }

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
    macro_rules! tested {
        ($cond:expr) => {
            if $cond {
                // TODO: replace with [`test::black_box`] when stable
                let _ = crate::ffi::sodium::memcmp(&[], &[]);
            }
        };
    }
}

/// See above.
#[cfg(profile = "release")]
#[macro_use]
mod assert {
    #![allow(unused_macros)]
    macro_rules! proven {
        ($($arg:tt)*) => {};
    }

    macro_rules! always {
        ($cond:expr) => {
            $cond
        };

        ($cond:expr, $($arg:tt)*) => {
            assert!($cond, $($arg)*)
        };
    }

    macro_rules! never {
        ($cond:expr) => {
            $cond
        };

        ($cond:expr, $($arg:tt)*) => {
            assert!(!$cond, $($arg)*)
        };
    }

    macro_rules! tested {
        ($cond:expr) => {};
    }
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
pub mod secret_box;

/// Container for `SecretVec`.
pub mod secret_vec;

pub mod traits;

pub use secret::Secret;
pub use secret_box::SecretBox;
pub use secret_vec::SecretVec;
