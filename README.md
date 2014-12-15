[![Build Status][travis-badge]][travis-url]

secrets
=======

A library to help safely hold cryptographic secrets in memory.

Buffers allocated through this library:

* restrict themselves from being read from and written to by default
* allow access to their contents in explicit, limited scopes
* are never included in core dumps
* are never swapped to permanent storage (using `mlock`)
* are protected from overflows and underflows by inaccessible guard pages (using `mprotect`)
* are protected from underflows by a random canary
* immediately sanitize the contents of the memory used to initialize them
* immediately sanitize the contents of their own memory when they leave scope

Example
-------

```rust
extern crate secrets;

use secrets::Secret;

fn main() {
  let secret = Secret.new( /* &mut [u8] */);
  let slice  = secret.read();

  println!("{}", &*slice);
}
```

License
-------

`secrets` is distributed under the [MIT license](./LICENSE).

Links
-----

* [crate](https://crates.io/crates/secrets)
* [docs](https://stouset.github.io/secrets)

[travis-badge]: https://travis-ci.org/stouset/secrets.svg?branch=master
[travis-url]:   https://travis-ci.org/stouset/secrets
