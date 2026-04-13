# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] 2026-04-13

### Security
- [#109](https://github.com/stouset/secrets/issues/109): Two `Secret`s can no
  longer accidentally occupy the same page, which would cause the unlocking of
  one to unintentionally unlock the other.

### Soundness
- [#100](https://github.com/stouset/secrets/issues/100): Tuple types may contain
  padding and so cannot safely implement the `Bytes` trait. This trait has been
  removed from tuples.
- [#100](https://github.com/stouset/secrets/issues/100): `bool` and `char` 
  cannot contain arbitrary byte sequences, and have similarly had their `Bytes`
  implementation removed.

### Fixed
- [#115](https://github.com/stouset/secrets/issues/115): `SecretVec::try_new` now
  accepts a length parameter as originally intended.  This is technically
  backwards-incompatible, but it is unlikely anyone in the wild was relying on 
  this since it would have been noticed immediately.

## [1.2.0] 2022-03-26

### Added
- Preliminary support for Windows
- Support for additional core types
  - bool
  - char
  - i8, i16, i32, i64, i128
  - f32, f64
- Support for arrays of all sizes via const generics
- Support for tuples of size 2-4, with any combination of supported underlying types

### Fixed
- Various newer rust/clippy lints

## [1.1.0] 2020-07-27

### Added
- Support for using `libsodium-sys` as the source of our `libsodium` C
  bindings. Speficying `--feature use-libsodium-sys` will bypass linking with
  `pkg-config` and rely on `libsodium-sys` to provide a suitable library to link
  against.

### Fixed
- Intra-rustdoc links corrected.

## [1.0.0] 2020-03-12

### Fixed
- Resolved warnings caused by newer versions of Rust and clippy.

### Removed
- Removed development dependency on `ctest` since it is fragile and
  uses unmaintained dependencies.

## [0.12.1] 2019-07-26

### Added
- SecretBox::try_new to indicate initialization success/failure.
- SecretVec::try_new to indicate initialization success/failure.

### Changed
- Reworked internals of Box initialization
- Core dumps are now only disabled via `setrlimit(2)` in release builds

## [0.12.0] 2019-07-19

### Changed
- Almost a ground-up rewrite from 0.11.0. This version will become 1.0
  after a short break-in period.

[Unreleased]: https://github.com/stouset/secrets/compare/v1.2.0...HEAD
[1.2.0]:      https://github.com/stouset/secrets/compare/v1.1.0...v1.2.0
[1.1.0]:      https://github.com/stouset/secrets/compare/v1.0.0...v1.1.0
[1.0.0]:      https://github.com/stouset/secrets/compare/v0.12.1...v1.0.0
[0.12.1]:     https://github.com/stouset/secrets/compare/v0.12.0...v0.12.1
[0.12.0]:     https://github.com/stouset/secrets/compare/v0.11.1...v0.12.0
