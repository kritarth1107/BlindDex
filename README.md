# BlindDex

**Your agent just downloaded the wire_transfer skill. The registry shouldn’t get to write that down.**

BlindDex is a **single-server computational PIR** library for opaque catalogs — MCP tool descriptors, skill packs, and similar fixed-width blobs. A client retrieves entry `i` (or a hash-keyed row). With a real cryptographic query layer the server learns neither the index nor the payload.

This repository is the **first public slice**: a clean, tested toy of SimplePIR-style matrix–vector PIR plus a SHA-256 Merkle commitment over the catalog. It is meant to be read, run, and extended — not dropped into production as-is.

## Honest scope (read this)

| Claim | Reality in this slice |
| --- | --- |
| Computational PIR (SimplePIR-style matvec) | **Yes** — database as matrix, query as vector, answer = matvec |
| Fully homomorphic encryption (FHE) | **No** — not FHE |
| Toy params | **N ≤ 2¹² (4096)**, **row ≤ 256 bytes** |
| Query privacy on the wire | Toy path uses an **exact one-hot** query for demo correctness; production SimplePIR needs **LWE noise + packing** |
| Hiding that a query happened | **No** — server sees query **size** / that a query occurred |
| Production parameters | **No** |
| Vector search / ANN | **No** |

## Modules

| Module | Role |
| --- | --- |
| `params` | Toy `Params { n_rows, row_bytes, modulus }` (`q = 2³²` by default) |
| `catalog` | Fixed-width rows, blake3 content-addressing, SHA-256 Merkle root |
| `pir` | Encode DB as `Z_q` matrix; query vector; server matvec; client recover |
| `client` | Thin `get_blind` / `get_blind_by_hash` wrappers |
| `server` | Hold matrix + Merkle root; answer matvecs; `put_entry` helper |
| `blinddex` CLI | `put` · `get-blind` · `root` |

## Quick start

```bash
cargo build --release -p blinddex-cli
cargo test --workspace

# Insert into a catalog (creates fixtures/catalog_toy.json-style files)
./target/release/blinddex put /tmp/cat.json wire_transfer "skill bytes here"

# Blind retrieve by index (toy exact query)
./target/release/blinddex get-blind /tmp/cat.json 0

# Print Merkle root
./target/release/blinddex root /tmp/cat.json
```

A committed toy catalog lives at [`fixtures/catalog_toy.json`](fixtures/catalog_toy.json).

```bash
cargo run -p blinddex-cli -- root fixtures/catalog_toy.json
cargo run -p blinddex-cli -- get-blind fixtures/catalog_toy.json 0
```

## How the toy PIR works

1. Each catalog row is packed into `u32` limbs in `Z_q` (`q = 2³²`).
2. The server stores matrix `Db` of shape `n_rows × L`.
3. The client builds query `q = e_i` (one-hot at the desired index).
4. Server returns `answer[ℓ] = Σ_i Db[i][ℓ] · q[i] (mod q)`.
5. Client unpacks `answer` back to `row_bytes`.

**Production SimplePIR** encrypts `q` under LWE, adds noise, and packs multiple DB rows into ciphertext coefficients. This slice deliberately keeps the algebra visible and the round-trip exact so the API and Merkle commitment are easy to test.

## Library sketch

```rust
use blinddex::{BlindClient, BlindServer, Catalog, Params};

let params = Params::new(16, 64, 1u64 << 32)?;
let mut cat = Catalog::new(params)?;
cat.insert(Some("wire_transfer".into()), b"skill bytes")?;
let root = cat.merkle_root_hex();

let server = BlindServer::from_catalog(&cat)?;
let client = BlindClient::new(&cat)?;
let row = client.get_blind(&server, 0)?;
assert_eq!(&row[..11], b"skill bytes");
assert_eq!(server.merkle_root_hex(), root);
```

## Workspace layout

```
blinddex/                 # library crate
blinddex-cli/             # `blinddex` binary
fixtures/catalog_toy.json
```

## License

MIT © Kritarth Agrawal

## Author

**Kritarth Agrawal** — GitHub [`kritarth1107`](https://github.com/kritarth1107)
