# Changelog

All notable changes to BlindDex will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-09-12

### Added

- **Parameter presets**: `Params::preset_tiny()`, `preset_small()`, `preset_medium()`,
  `preset_demo()` with honest scope documentation. `from_preset_name()` for CLI.
- **Offline hint scaffolding** (`hint` module): seeded PRNG expansion for future
  SimplePIR offline phase. `Hint::generate(params, seed)` with JSON/bytes serde.
  Includes params fingerprint matching. Does NOT provide query privacy.
- **Toy noisy query**: `PirEngine::query_noisy(index, noise_budget, seed)` adds
  modular noise to non-target coordinates. Educational only — does NOT hide index.
  `recover_row_exact()` alias for clarity.
- **Snapshot sealing** (`snapshot` module): `SnapshotMeta` captures params +
  merkle root + row count for offline verification. Sidecar file support.
- **CLI commands**: `hint-gen` (write hint file), `snapshot` (print/write meta),
  `presets` (list available presets).
- **Examples**: `hint_roundtrip.rs` (offline hint API demo), `bench_matvec.rs`
  (criterion-free timing benchmark for all presets).
- **THREAT_MODEL**: Offline hint and toy noisy query sections explaining why
  these features do NOT provide privacy and their intended purpose.

### Changed

- Workspace version bumped to **0.3.0**.
- README modules table and quickstart updated for new features.
- Downgrade blake3 to 1.8.0 and clap to 4.5.0 for stable Rust 1.83 compatibility.
- Use `slice::chunks()` instead of unstable `as_chunks()` for stable Rust.

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
