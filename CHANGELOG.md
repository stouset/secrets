# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stouset/secrets/compare/v1.0.0...HEAD
[1.0.0]:      https://github.com/stouset/secrets/compare/v0.12.1...v1.0.0
[0.12.1]:     https://github.com/stouset/secrets/compare/v0.12.0...v0.12.1
[0.12.0]:     https://github.com/stouset/secrets/compare/v0.11.1...v0.12.0
