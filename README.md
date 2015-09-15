[![Build Status][travis-badge]][travis-url]
[![crates.io][cargo-badge]][cargo-url]

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
* immediately zero out the contents of the memory used to initialize them
* immediately zero out the contents of their allocated memory when they leave scope

Example
-------

Coming soon. Library very much in flux.

License
-------

`secrets` is distributed under the [MIT license](./LICENSE).

Links
-----
* [crate](https://crates.io/crates/secrets)
* [docs](https://stouset.github.io/secrets)

[cargo-badge]:  http://meritbadge.herokuapp.com/secrets
[cargo-url]:    https://crates.io/crates/secrets
[travis-badge]: https://travis-ci.org/stouset/secrets.svg?branch=master
[travis-url]:   https://travis-ci.org/stouset/secrets
