# BlindDex threat model (honest)

This document describes what BlindDex **claims**, what it **does not claim**, and
who the adversary is for the public toy slices (v0.1–v0.3).

## Assets

- **Catalog confidentiality of the query index** — which skill / tool / row the
  client wants (the PIR goal).
- **Catalog integrity** — rows match a published Merkle root (inclusion proofs).
- **Payload confidentiality from third parties** — not a primary goal of this
  slice; payloads are whatever the catalog operator stored.

## Adversaries

| Adversary | Capability assumed in this repo |
| --- | --- |
| Curious server (toy path) | Reads cleartext one-hot queries; learns the index today |
| Curious server (future LWE path) | Sees ciphertext size / that a query happened; should not learn index |
| Network observer | Sees message sizes and timing; JSON codec does not hide structure |
| Malicious catalog publisher | Can put arbitrary bytes in rows; Merkle only binds *what was published* |
| Client with wrong root | Must pin the expected root out-of-band; otherwise proofs are meaningless |

## Guarantees in v0.2–v0.3

1. **Integrity via Merkle** — `prove` / `get_blind_proven` let a client check
   that a recovered row’s leaf hash sits under a pinned root. Tampering with
   siblings, leaf hash, or row bytes fails verification in tests.
2. **Exact recovery (toy PIR)** — matvec + one-hot query recovers the row under
   the documented params (`N ≤ 4096`, row ≤ 256 B).
3. **Batch API honesty** — `get_blind_batch` runs **multiple independent
   matvecs**, not a packed multi-query ciphertext.
4. **Deterministic hint expansion** — `Hint::generate` produces the same output
   for the same seed; the client can verify cached hints match expected params.
5. **Snapshot sealing** — `SnapshotMeta` captures params + merkle root + row
   count for offline verification that a catalog matches a known state.

## Non-guarantees (read carefully)

- **Query privacy on the wire is still toy.** The exact one-hot vector reveals
  the index to anyone who can read the query (including a JSON `WireQuery`).
- **Not FHE. Not ANN. Not production SimplePIR parameters.**
- **Does not hide that a query occurred** — server and observers see query size.
- **Does not authenticate the server** beyond “this row opens to root R”; root
  distribution / pinning is out of band.
- **Does not prevent a malicious server from answering a different index** on
  the toy path (the client asked in the clear). With a real LWE query the
  server still returns *some* row; combining PIR with the Merkle open binds the
  *payload* to the root once the client knows which index it requested locally.

## Batch & wire notes

- Batch = repeated single-index PIR + proof. Latency and leakage scale with
  batch size (`MAX_BATCH_SIZE = 16` in this slice).
- The wire codec is for host interoperability (CLI pipes, future HTTP). It is
  **not** a privacy boundary.

## Offline hint (v0.3)

The `hint` module provides **scaffolding** for SimplePIR-style offline
precomputation. A seeded PRNG expands a 32-byte seed into a reusable blob the
client can cache between queries.

**Why the hint does NOT provide query privacy by itself:**

- The current query path is still exact one-hot (`q[i] = 1`, else `0`).
- A curious server reading the clear query vector learns the target index.
- The hint is only the **API shape** for a future offline phase where the
  client precomputes part of the LWE encryption.

The hint is useful for:
- Testing serialization and caching infrastructure.
- Designing the client-side workflow before adding LWE.
- Documenting expected offline/online split in SimplePIR.

## Toy noisy query (v0.3)

`PirEngine::query_noisy(index, noise_budget, seed)` adds small modular noise
to non-target coordinates. This is **educational, NOT secure**:

- The target coordinate still has the largest magnitude.
- A curious server can easily identify the index by inspecting the query.
- Real SimplePIR uses discrete Gaussian noise under LWE, not uniform modular
  noise on top of an otherwise clear query.

The noisy query demonstrates:
- How noise affects recovery (small noise → correct, large noise → garbage).
- The API shape for a future LWE query layer.
- Why production PIR needs error-correcting structure.

## Public directories (v0.4)

A **Directory** is a public listing of catalog entry metadata: indices, optional
keys (skill/tool names), blake3 content hashes, and SHA-256 leaf hashes. The
directory does NOT include payloads.

### What directories reveal

Publishing a directory **reveals which skills exist**:

- All entry keys (e.g., `"wire_transfer"`, `"calendar"`)
- All content hashes (blake3 of normalized row bytes)
- All leaf hashes (SHA-256 for Merkle proof verification)
- The Merkle root and catalog parameters

An observer who sees the directory learns the full list of available skills.
This is intentional: the directory is meant to be public.

### What directories do NOT reveal

With a future **LWE query layer**, the directory enables a privacy-preserving
workflow:

1. Client downloads the public directory.
2. Client resolves `"wire_transfer"` → index 3 locally.
3. Client issues a **blind PIR query** for index 3.
4. Server cannot determine which index was requested.

In this model, the directory reveals **what exists** but not **what was fetched**.

### Seal and pinning

`Directory::seal()` computes a blake3 fingerprint over the canonical JSON of
entries + merkle root. A client can:

- Pin a known seal to detect directory changes between epochs.
- Verify that a downloaded directory matches an expected seal.
- Reject tampered directories before resolving keys.

The seal does NOT authenticate the directory's origin — that requires out-of-band
trust (e.g., HTTPS to a known host, signed metadata).

### Current limitations (v0.4)

- **Toy PIR path still reveals the index.** The exact one-hot query lets the
  server learn which index was requested. The directory workflow is useful
  now for local demos and will provide real privacy once LWE queries exist.
- **Directory authenticity is out of band.** The seal binds content but not
  origin; clients must obtain directories via trusted channels.
- **Key→index resolution is local.** The client must have the full directory
  to resolve keys; there is no private directory lookup.

## Intended evolution

1. Replace exact queries with LWE / SimplePIR-style noisy queries.
2. Wire the offline hint into actual precomputation for online savings.
3. Optional packed multi-query API with documented leakage.
4. Thin HTTP host wrapping the same wire types (`examples/wire_roundtrip.rs`
   is the embedding sketch until then).
