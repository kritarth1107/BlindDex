# Changelog

All notable changes to BlindDex will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-10

### Added

- First public slice: computational PIR (SimplePIR-style matvec) over fixed-width catalogs.
- Content-addressed rows with SHA-256 Merkle commitment root.
- Library crate (`blinddex`) with `Catalog`, `PirClient`/`PirServer`, thin client/server wrappers.
- CLI (`blinddex-cli`): `put`, `get-blind`, `root`.
- Toy params: N ≤ 4096, row ≤ 256 bytes; exact one-hot query recovery for demos.
- CI: rustfmt, clippy `-D warnings`, `cargo test`.
