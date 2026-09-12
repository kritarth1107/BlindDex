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
| Hiding that a query happened | **No** — server sees query **size** / that a query occurred |
| Production parameters | **No** |
| Vector search / ANN | **No** |

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`SECURITY.md`](SECURITY.md).

## Modules

| Module | Role |
| --- | --- |
| `params` | Toy `Params { n_rows, row_bytes, modulus }` (`q = 2³²` by default); preset factories |
| `catalog` | Fixed-width rows, blake3 content-addressing, SHA-256 Merkle root, `prove` / `open_leaf_hash` |
| `merkle` | `MerkleProof` + path verify against root |
| `pir` | Encode DB as `Z_q` matrix; query vector; server matvec; client recover; `query_noisy` (toy) |
| `hint` | Offline hint scaffolding: seeded PRNG expansion for future SimplePIR offline phase |
| `snapshot` | `SnapshotMeta` for catalog sealing (params + merkle root + row count) |
| `client` | `get_blind` / `get_blind_proven` / `get_blind_batch` |
| `server` | Hold catalog + matrix + root; answer matvecs; `prove` / `answer_proven` |
| `wire` | JSON codec for `WireQuery` / `WireAnswer` / `WireProvenRow` |
| `blinddex` CLI | `put` · `get-blind` · `get-blind-proven` · `batch-get-blind` · `prove` · `root` · `hint-gen` · `snapshot` · `presets` |

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

# Wire codec demo (no HTTP deps)
cargo run -p blinddex --example wire_roundtrip

# Hint roundtrip demo
cargo run -p blinddex --example hint_roundtrip

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

## Embedding / host sketch

There is **no** heavyweight HTTP binary in this release. Use:

- `examples/wire_roundtrip.rs` — serialize Query/Answer/ProvenRow as JSON
- the `wire` module types as the future HTTP request/response bodies

A thin `blinddex-host` (axum/warp) can wrap the same codec later without changing message shapes.

## Library sketch

```rust
use blinddex::{BlindClient, BlindServer, Catalog, Hint, Params, SnapshotMeta};

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
  bench_matvec.rs         # timing benchmark
fixtures/catalog_toy.json
THREAT_MODEL.md
SECURITY.md
```

## License

MIT © Kritarth Agrawal

## Author

**Kritarth Agrawal** — GitHub [`kritarth1107`](https://github.com/kritarth1107)
