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

#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(rustdoc)]
#![warn(unused)]

#![warn(bare_trait_objects)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
// #![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unreachable_pub)]
#![warn(unstable_features)]
#![warn(unused_import_braces)]
#![warn(unused_lifetimes)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
#![warn(variant_size_differences)]

#![warn(unsafe_code)]
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
// #![cfg_attr(feature = "cargo-clippy", warn(clippy::missing_docs_in_private_items))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::multiple_inherent_impl))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::print_stdout))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::result_unwrap_used))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_reuse))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::shadow_same))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::unimplemented))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::use_debug))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::wrong_pub_self_convention))]

mod ffi {
    pub(crate) mod sodium;
}

mod boxed;
mod buf;
mod secret;
pub mod secret_box;

pub mod traits;

pub use buf::{Buf, BufMut};
pub use secret::Secret;
// pub use secret_box::SecretBox;
