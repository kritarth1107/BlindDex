# BlindDex

**Your agent just downloaded the wire_transfer skill. The registry shouldn’t get to write that down.**

BlindDex is a **single-server computational PIR** library for opaque catalogs — MCP tool descriptors, skill packs, and similar fixed-width blobs. A client retrieves entry `i` (or a hash-keyed row). With a real cryptographic query layer the server learns neither the index nor the payload.

This repository is a **public research slice**: a clean, tested toy of SimplePIR-style matrix–vector PIR plus a SHA-256 Merkle commitment, **inclusion proofs**, **batch retrieval**, and a **JSON wire codec**. It is meant to be read, run, and extended — not dropped into production as-is.

## Honest scope (read this)

| Claim | Reality in this slice |
| --- | --- |
| Computational PIR (SimplePIR-style matvec) | **Yes** — database as matrix, query as vector, answer = matvec |
| Fully homomorphic encryption (FHE) | **No** — not FHE |
| Toy params | **N ≤ 2¹² (4096)**, **row ≤ 256 bytes** |
| Query privacy on the wire | Toy path uses an **exact one-hot** query for demo correctness; production SimplePIR needs **LWE noise + packing**. JSON encoding does **not** add privacy |
| Merkle inclusion proofs | **Yes** — `prove` / `get_blind_proven` verify against a pinned root |
| Batch retrieval | **Yes** — **multiple independent matvecs** (not packed multi-query) |
| Public directory for keyed retrieval | **Yes** — reveals which skills exist (keys + hashes), not payloads; with LWE, hides which is *fetched* |
| Hiding that a query happened | **No** — server sees query **size** / that a query occurred |
| Production parameters | **No** |
| Vector search / ANN | **No** |

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`SECURITY.md`](SECURITY.md).

## Modules

| Module | Role |
| --- | --- |
| `params` | Toy `Params { n_rows, row_bytes, modulus }` (`q = 2³²` by default); preset factories |
| `catalog` | Fixed-width rows, blake3 content-addressing, SHA-256 Merkle root, `prove` / `open_leaf_hash` |
| `directory` | Public directory for name→index resolution (keys + hashes, no payloads); seal/fingerprint |
| `sync` | Catalog sync handshake (`SyncOffer` / `SyncAck`) for epoch binding between client and server |
| `receipt` | Query receipts: client nonces for answer verification + server replay window (demo anti-replay) |
| `merkle` | `MerkleProof` + path verify against root |
| `pir` | Encode DB as `Z_q` matrix; query vector; server matvec; client recover; `query_noisy` (toy) |
| `hint` | Offline hint scaffolding: seeded PRNG expansion for future SimplePIR offline phase |
| `snapshot` | `SnapshotMeta` for catalog sealing (params + merkle root + row count) |
| `client` | `get_blind` / `get_blind_proven` / `get_blind_by_key` / `get_blind_by_hash` + proven and epoch-bound variants |
| `server` | Hold catalog + matrix + root + seal; answer matvecs; replay protection; answer padding |
| `wire` | JSON codec for `WireQuery` / `WireAnswer` (with nonce + padding fields) / `WireProvenRow` / `WireDirectory` / `WireSyncOffer` / `WireSyncAck` |
| `blinddex` CLI | `put` · `get-blind` · `get-blind-proven` · `batch-get-blind` · `directory` · `get-blind-key` · `get-blind-proven-key` · `get-blind-hash` · `prove` · `root` · `hint-gen` · `snapshot` · `sync-check` · `sync-offer` · `presets` · `receipt-check` |

## Quick start

```bash
cargo build --release -p blinddex-cli
cargo test --workspace

# Insert into a catalog (creates fixtures/catalog_toy.json-style files)
./target/release/blinddex put /tmp/cat.json wire_transfer "skill bytes here"

# Blind retrieve by index (toy exact query)
./target/release/blinddex get-blind /tmp/cat.json 0

# Blind retrieve + verify Merkle inclusion proof
./target/release/blinddex get-blind-proven /tmp/cat.json 0

# Batch (comma-separated indices; one matvec each)
./target/release/blinddex batch-get-blind /tmp/cat.json 0,1,2

# Export public directory (keys + hashes, no payloads)
./target/release/blinddex directory /tmp/cat.json

# Blind retrieve by key (resolves key→index locally)
./target/release/blinddex get-blind-key /tmp/cat.json wire_transfer

# Blind retrieve by key with Merkle proof
./target/release/blinddex get-blind-proven-key /tmp/cat.json wire_transfer

# Blind retrieve by content hash
./target/release/blinddex get-blind-hash /tmp/cat.json <64-char-blake3-hex>

# Emit inclusion proof JSON
./target/release/blinddex prove /tmp/cat.json 0

# Print Merkle root
./target/release/blinddex root /tmp/cat.json

# Generate offline hint (scaffolding, not privacy)
./target/release/blinddex hint-gen /tmp/cat.json

# Create catalog snapshot
./target/release/blinddex snapshot /tmp/cat.json --write

# List available presets
./target/release/blinddex presets

# Sync check: print catalog epoch info
./target/release/blinddex sync-check /tmp/cat.json

# Sync check: verify against expected seal/root
./target/release/blinddex sync-check /tmp/cat.json --seal <hex> --root <hex>

# Emit sync offer JSON
./target/release/blinddex sync-offer /tmp/cat.json

# Query with nonce (receipt verification)
./target/release/blinddex get-blind /tmp/cat.json 0 --nonce

# Query with explicit nonce
./target/release/blinddex get-blind-proven /tmp/cat.json 0 --nonce-hex deadbeef01234567

# Receipt check demo (nonce echo + optional replay detection)
./target/release/blinddex receipt-check /tmp/cat.json 0 --replay-protect --padding 256

# Wire codec demo (no HTTP deps)
cargo run -p blinddex --example wire_roundtrip

# Sync handshake + epoch-bound query demo
cargo run -p blinddex --example sync_roundtrip

# Minimal HTTP server demo (tiny_http)
cargo run -p blinddex --example http_demo

# Hint roundtrip demo
cargo run -p blinddex --example hint_roundtrip

# Directory + keyed retrieval demo
cargo run -p blinddex --example directory_roundtrip

# Timing benchmark
cargo run -p blinddex --example bench_matvec --release
```

A committed toy catalog lives at [`fixtures/catalog_toy.json`](fixtures/catalog_toy.json).

```bash
cargo run -p blinddex-cli -- root fixtures/catalog_toy.json
cargo run -p blinddex-cli -- get-blind-proven fixtures/catalog_toy.json 0 --json
cargo run -p blinddex-cli -- batch-get-blind fixtures/catalog_toy.json 0,1,2
```

## How the toy PIR works

1. Each catalog row is packed into `u32` limbs in `Z_q` (`q = 2³²`).
2. The server stores matrix `Db` of shape `n_rows × L`.
3. The client builds query `q = e_i` (one-hot at the desired index).
4. Server returns `answer[ℓ] = Σ_i Db[i][ℓ] · q[i] (mod q)`.
5. Client unpacks `answer` back to `row_bytes`.
6. Optionally the server attaches a Merkle sibling path; the client checks the
   leaf hash of the recovered row opens to the pinned root.

**Production SimplePIR** encrypts `q` under LWE, adds noise, and packs multiple DB rows into ciphertext coefficients. This slice deliberately keeps the algebra visible and the round-trip exact so the API, proofs, and wire codec are easy to test.

## HTTP demo

A minimal HTTP server example (`examples/http_demo.rs`) is included using `tiny_http`:

```bash
# Run the demo server (port 8080 or PORT env var)
cargo run -p blinddex --example http_demo

# With replay protection enabled
REPLAY_PROTECT=1 cargo run -p blinddex --example http_demo

# With answer padding (256 bytes)
PADDING=256 cargo run -p blinddex --example http_demo

# In another terminal:
curl http://localhost:8080/directory    # WireDirectory JSON
curl http://localhost:8080/sync         # WireSyncOffer JSON

# Query with nonce for receipt verification
curl -X POST -H "Content-Type: application/json" \
     -d '{"version":1,"params":{"n_rows":16,...},"query":[1,0,...],
          "client_nonce":"deadbeef01234567deadbeef01234567"}' \
     http://localhost:8080/query        # WireAnswer JSON (nonce echoed)
```

The library crate remains HTTP-free. For production use:
- `examples/wire_roundtrip.rs` — serialize Query/Answer/ProvenRow as JSON
- the `wire` module types as HTTP request/response bodies
- a thin axum/warp wrapper can replace the demo without changing message shapes

## Library sketch

```rust
use blinddex::{
    BlindClient, BlindServer, Catalog, Hint, Params, PinnedEpoch, SnapshotMeta, SyncOffer,
};

// Use a preset or custom params
let params = Params::preset_small(); // or Params::new(16, 64, 1u64 << 32)?
let mut cat = Catalog::new(params)?;
cat.insert(Some("wire_transfer".into()), b"skill bytes")?;
let root = cat.merkle_root_hex();

let server = BlindServer::from_catalog(&cat)?;
let client = BlindClient::new(&cat)?;
let proven = client.get_blind_proven(&server, 0)?;
assert_eq!(&proven.row[..11], b"skill bytes");
assert_eq!(server.merkle_root_hex(), root);

let batch = client.get_blind_batch(&server, &[0, 1])?;
assert_eq!(batch.len(), 2);

// Public directory for name→index resolution
let dir = cat.export_directory();
assert_eq!(dir.resolve_key("wire_transfer"), Some(0));
let seal = dir.seal_hex();
assert!(dir.verify_seal_hex(&seal));

// Keyed retrieval via directory (production pattern)
let proven = client.get_blind_proven_by_key_dir(&dir, &server, "wire_transfer")?;
assert_eq!(&proven.row[..11], b"skill bytes");

// Sync handshake: server offers, client verifies, then queries with epoch binding
let offer = server.sync_offer();
let pinned = PinnedEpoch::from_directory(&dir);
offer.verify(&pinned)?; // fails closed if epoch changed

// Epoch-bound retrieval (query + answer both carry epoch fields)
let proven = client.get_blind_proven_by_key_epoch(&dir, &server, "wire_transfer", &pinned)?;
assert_eq!(&proven.row[..11], b"skill bytes");

// Offline hint scaffolding (not privacy, just API shape)
let seed = [42u8; 32];
let hint = Hint::generate(&params, seed)?;
assert!(hint.matches_params(&params));

// Snapshot for catalog sealing
let snap = SnapshotMeta::from_catalog(&cat);
assert!(snap.matches_catalog(&cat));
```

## Workspace layout

```
crates/blinddex/          # library crate
crates/blinddex-cli/      # `blinddex` binary
examples/
  wire_roundtrip.rs       # JSON codec demo
  hint_roundtrip.rs       # offline hint API demo
  directory_roundtrip.rs  # directory + keyed retrieval demo
  sync_roundtrip.rs       # sync handshake + epoch-bound query demo
  http_demo.rs            # minimal HTTP server demo (tiny_http)
  bench_matvec.rs         # timing benchmark
fixtures/catalog_toy.json
THREAT_MODEL.md
SECURITY.md
```

## License

MIT © Kritarth Agrawal

## Author

**Kritarth Agrawal** — GitHub [`kritarth1107`](https://github.com/kritarth1107)
