secrets
=======

[![Build Status][badge-ci]][ci]
<!-- [![Test Coverage][badge-coverage]][coverage] -->
[![Cargo Crate][badge-package]][package]
[![Docs][badge-docs]][docs]
[![License][badge-license]][license]

`secrets` is a library to help Rust programmers safely hold cryptographic
secrets in memory.

It is mostly an ergonomic wrapper around the memory-protection utilities
provided by [libsodium].

Fixed-size buffers allocated on the stack gain the following protections:

* [`mlock(2)`][mlock] is called on the underlying memory
* the underlying memory is zeroed out when no longer in use
* they are borrowed for their entire lifespan, so cannot be moved
* they are compared in constant time
* they are prevented from being printed by `Debug`
* they are prevented from being `Clone`d

Fixed and variable-sized buffers can be allocated on the heap and gain
the following protections:

* the underlying memory is protected from being read from or written to
  with [`mprotect(2)`][mprotect] unless an active borrow is in scope
* [`mlock(2)`][mlock] is called on the allocated memory
* the underlying memory is zeroed out when no longer in use
* overflows and underflows are detected using inaccessible guard pages,
  causing an immediate segmentation fault and program termination
* short underflows that write to memory are detected when memory is
  freed using canaries, and will result in a segmentation fault and
  program termination

Panic Safety
------------

This library is explicitly not panic-safe. To ensure the safety of
protected memory space, this library can and will panic if it is unable
to enforce its advertised guarantees.

Similarly, this library will cause segmentation faults if (and only if)
it detects certain safety violations. For example, this can happen if
a process attempts to directly read or write to the contents of memory
that hasn't been properly unlocked, or if canaries have been
overwritten. This library has been written to ensure that such
violations should be impossible to cause through well-formed Rust, and
so should only occur as a result of a security vulnerability.

Examples
--------

### Example: generating cryptographic keys

```rust
Secret::<[u8; 16]>::random(|s| {
    // use `s` as if it were a `&mut [u8; 16]`
    //
    // the memory is `mlock(2)`ed and will be zeroed when this closure
    // exits
});
```

### Example: load a master key from disk and generate subkeys from it

```rust
use std::fs::File;
use std::io::Read;

use libsodium_sys as sodium;
use secrets::SecretBox;

const KEY_LEN : usize = sodium::crypto_kdf_KEYBYTES     as _;
const CTX_LEN : usize = sodium::crypto_kdf_CONTEXTBYTES as _;

const CONTEXT : &[u8; CTX_LEN] = b"example\0";

fn derive_subkey(
    key:       &[u8; KEY_LEN],
    context:   &[u8; CTX_LEN],
    subkey_id: u64,
    subkey:    &mut [u8],
) {
    unsafe {
        libsodium_sys::crypto_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey.len(),
            subkey_id,
            context.as_ptr().cast(),
            key.as_ptr()
        );
    }
}

let master_key = SecretBox::<[u8; KEY_LEN]>::try_new(|mut s| {
    File::open("example/master_key/key")?.read_exact(s)
})?;

let subkey_0 = SecretBox::<[u8; 16]>::new(|mut s| {
    derive_subkey(&master_key.borrow(), CONTEXT, 0, s);
});

let subkey_1 = SecretBox::<[u8; 16]>::new(|mut s| {
    derive_subkey(&master_key.borrow(), CONTEXT, 1, s);
});

assert_ne!(
    subkey_0.borrow(),
    subkey_1.borrow(),
);
```

### Example: securely storing a decrypted ciphertext in memory

```rust
use std::fs::File;
use std::io::Read;

use libsodium_sys as sodium;
use secrets::{SecretBox, SecretVec};

const KEY_LEN   : usize = sodium::crypto_secretbox_KEYBYTES   as _;
const NONCE_LEN : usize = sodium::crypto_secretbox_NONCEBYTES as _;
const MAC_LEN   : usize = sodium::crypto_secretbox_MACBYTES   as _;

let mut key        = SecretBox::<[u8; KEY_LEN]>::zero();
let mut nonce      = [0; NONCE_LEN];
let mut ciphertext = Vec::new();

File::open("example/decrypted_ciphertext/key")?
    .read_exact(key.borrow_mut().as_mut())?;

File::open("example/decrypted_ciphertext/nonce")?
    .read_exact(&mut nonce)?;

File::open("example/decrypted_ciphertext/ciphertext")?
    .read_to_end(&mut ciphertext)?;

let plaintext = SecretVec::<u8>::new(ciphertext.len() - MAC_LEN, |mut s| {
    if -1 == unsafe {
        sodium::crypto_secretbox_open_easy(
            s.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as _,
            nonce.as_ptr(),
            key.borrow().as_ptr(),
        )
    } {
        panic!("failed to authenticate ciphertext during decryption");
    }
});

assert_eq!(
    *b"attack at dawn",
    *plaintext.borrow(),
);
```

License
-------

Licensed under either of

 * [Apache License, Version 2.0](LICENSE-APACHE)
 * [MIT license](LICENSE-MIT)

at your option.

[ci]:       https://github.com/stouset/secrets/actions/workflows/test.yml
<!-- [coverage]: https://coveralls.io/github/stouset/secrets -->
[docs]:     https://stouset.github.io/secrets
[license]:  https://github.com/stouset/secrets/blob/master/LICENSE
[package]:  https://crates.io/crates/secrets

[badge-ci]:       https://github.com/stouset/secrets/actions/workflows/test.yml/badge.svg
<!-- [badge-coverage]: https://coveralls.io/repos/github/stouset/secrets/badge.svg -->
[badge-docs]:     https://docs.rs/secrets/badge.svg
[badge-license]:  https://img.shields.io/crates/l/secrets.svg
[badge-package]:  https://img.shields.io/crates/v/secrets.svg

[libsodium]: https://download.libsodium.org/doc/memory_management
[mlock]:     http://man7.org/linux/man-pages/man2/mlock.2.html
[mprotect]:  http://man7.org/linux/man-pages/man2/mprotect.2.html
