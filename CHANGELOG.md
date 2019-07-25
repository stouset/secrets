# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
