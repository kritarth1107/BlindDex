# Changelog

All notable changes to BlindDex will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-11

### Added

- Merkle inclusion proofs (`MerkleProof`) with sibling-path verify against the catalog root.
- Catalog `prove(index)` / `open_leaf_hash` and server `prove` / `answer_proven`.
- Client `get_blind_proven` (row + verified proof) and `get_blind_batch` (multiple independent matvecs, max 16).
- JSON wire codec (`wire`): `WireQuery`, `WireAnswer`, `WireProvenRow`, `WireBatchProven`.
- CLI: `prove`, `get-blind-proven`, `batch-get-blind` (plus `--json` where useful).
- `examples/wire_roundtrip.rs` host-embedding sketch (no HTTP deps).
- `THREAT_MODEL.md` and `SECURITY.md` with honest limitations.
- Tests: proof verify, tamper fail, batch roundtrip, wire roundtrip.

### Changed

- Workspace version bumped to **0.2.0**.
- README modules / quickstart updated for proofs, batch, and wire.

## [0.1.0] — 2026-09-10

### Added

- First public slice: computational PIR (SimplePIR-style matvec) over fixed-width catalogs.
- Content-addressed rows with SHA-256 Merkle commitment root.
- Library crate (`blinddex`) with `Catalog`, PIR engine, thin client/server wrappers.
- CLI (`blinddex-cli`): `put`, `get-blind`, `root`.
- Toy params: N ≤ 4096, row ≤ 256 bytes; exact one-hot query recovery for demos.
- CI: rustfmt, clippy `-D warnings`, `cargo test`.
