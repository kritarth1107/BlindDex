# Changelog

All notable changes to BlindDex will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-09-15

### Added

- **Query receipts / nonce echo** (`receipt` module): Client-generated 16–32 byte
  nonces for answer verification. Client attaches `client_nonce` to `WireQuery`;
  server echoes it in `WireAnswer`. Helpers: `generate_nonce_hex_default()`,
  `verify_nonce_echo()`, `WireQuery::with_nonce()`, `WireAnswer::verify_nonce()`.
- **Replay window** (`receipt` module): Server-side bounded LRU (`ReplayWindow`)
  tracks recent nonces and rejects duplicates. Enable with
  `BlindServer::with_replay_protection(capacity)`. Demo anti-replay only (not
  distributed, not authenticated).
- **Constant-size answer padding** (`wire` module): `WireAnswer::with_padding(total_bytes)`
  pads answers to a fixed wire size, hiding payload length variation.
  `WireAnswer::strip_padding()` verifies and removes padding.
- **New error variants**: `BlindDexError::ReceiptMismatch` for nonce verification
  failures, `BlindDexError::ReplayDetected` for duplicate nonce rejection,
  `BlindDexError::PaddingError` for padding issues.
- **HTTP demo updates** (`examples/http_demo.rs`): Environment variables
  `REPLAY_PROTECT=1` to enable replay protection, `PADDING=<bytes>` for answer
  padding. Nonces in `WireQuery` are automatically echoed.
- **CLI updates**: `--nonce` and `--nonce-hex` flags on `get-blind` and
  `get-blind-proven` for receipt verification. New `receipt-check` command demos
  nonce roundtrip and optional replay detection.
- **Tests**: `tests/receipt_padding.rs` integration tests covering nonce echo
  success/fail, replay detection, padding constancy, and combined features.

### Changed

- Workspace version bumped to **0.6.0**.
- `WireQuery` and `WireAnswer` now have optional `client_nonce` fields (additive,
  backward-compatible with `#[serde(default)]`).
- `WireAnswer` has optional `padded_answer` and `pad_len` fields for padding.
- `BlindServer` can now be configured with replay protection and/or answer padding
  via builder methods.
- README updated with receipt module, padding docs, and CLI examples.
- THREAT_MODEL updated with query receipts and answer padding sections (honest
  non-claims about what these features do NOT provide).
- SECURITY updated with 0.6.x supported versions row.

## [0.5.0] — 2026-09-14

### Added

- **Sync handshake** (`sync` module): `SyncOffer` and `SyncAck` types for catalog
  epoch binding. Server announces its catalog state (merkle root, directory seal,
  params fingerprint, row count); client verifies against a `PinnedEpoch` before
  proceeding with queries.
- **Epoch-bound wire types**: `WireSyncOffer` and `WireSyncAck` for JSON interchange.
  `WireQuery` and `WireAnswer` now support optional `directory_seal` and `merkle_root`
  fields for epoch binding. `verify_epoch()` helpers on both types.
- **Epoch-bound retrieval** (`client` module):
  - `get_blind_epoch()` / `get_blind_proven_epoch()` — index-based with epoch check
  - `get_blind_by_key_epoch()` / `get_blind_proven_by_key_epoch()` — keyed with epoch
  - `verify_answer_epoch()` — check answer against pinned epoch
- **Server epoch support** (`server` module):
  - `directory_seal()` / `directory_seal_hex()` — access cached directory seal
  - `verify_query_epoch()` — reject queries with mismatched epoch fields
  - `answer_wire()` / `answer_wire_proven()` — answer with epoch verification
  - `sync_offer()` — build `SyncOffer` from current state
  - `export_directory()` — re-export directory convenience
- **HTTP demo** (`examples/http_demo.rs`): Minimal HTTP server using `tiny_http` (no
  async, lib stays HTTP-free). Endpoints: `GET /directory`, `GET /sync`, `POST /query`,
  `POST /query-proven`. Shows wire protocol in action.
- **Sync roundtrip example** (`examples/sync_roundtrip.rs`): Demonstrates full sync
  handshake → epoch verification → epoch-bound query workflow.
- **CLI commands**: `sync-check` (verify catalog against seal/root/offer), `sync-offer`
  (emit WireSyncOffer JSON).
- **Error variant**: `BlindDexError::EpochMismatch` for clear epoch verification failures.
- **Tests**: `epoch_binding.rs` integration tests covering happy paths, mismatch
  rejection on query and answer sides, and sync offer verification.

### Changed

- Workspace version bumped to **0.5.0**.
- `BlindServer::from_catalog()` now caches directory seal for epoch binding.
- README updated with sync/epoch module descriptions and quickstart examples.
- THREAT_MODEL updated with sync/epoch binding section.
- SECURITY updated with 0.5.x supported versions row.

## [0.4.0] — 2026-09-13

### Added

- **Public directory** (`directory` module): `Directory` and `DirectoryEntry` types
  for name→index resolution. The directory contains entry metadata (index, key,
  content hash, leaf hash) but NOT payloads. Clients download the directory,
  resolve keys locally, then issue PIR queries by index.
- **Directory seal/fingerprint**: `Directory::seal()` computes a blake3 hash over
  canonical JSON of entries + merkle root. `verify_seal()` / `verify_seal_hex()`
  let clients pin a directory epoch and detect changes.
- **Keyed blind retrieval** (`client` module):
  - `get_blind_by_key_dir` / `get_blind_proven_by_key_dir` — resolve via Directory
  - `get_blind_by_hash_dir` / `get_blind_proven_by_hash_dir` — resolve via Directory
  - `get_blind_by_key` / `get_blind_proven_by_key` — local demo via server.catalog()
- **Wire directory types** (`wire` module): `WireDirectory` and `WireDirectoryEntry`
  for JSON interchange. Includes embedded seal for integrity verification.
- **Catalog export**: `Catalog::export_directory()` thin wrapper for convenience.
- **CLI commands**: `directory` (export JSON), `get-blind-key`, `get-blind-proven-key`,
  `get-blind-hash` (with `--proven` flag).
- **Example**: `directory_roundtrip.rs` demonstrating directory export, seal
  verification, and keyed retrieval patterns.
- **THREAT_MODEL**: New "Public directories" section explaining what is revealed
  (keys + hashes) vs hidden (which skill was fetched, with future LWE).

### Changed

- Workspace version bumped to **0.4.0**.
- README updated with directory module, keyed retrieval quickstart, and privacy notes.
- Client module documentation updated for keyed retrieval methods.

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
