//! # BlindDex
//!
//! Single-server **computational PIR** for opaque catalogs (MCP tool
//! descriptors, skill packs). A client retrieves entry `i` (or a hash-keyed
//! row); with a cryptographic query layer the server learns neither index nor
//! payload.
//!
//! This crate ships a **toy SimplePIR-style matvec** with exact one-hot queries
//! for demos, plus a SHA-256 Merkle commitment over fixed-width rows, inclusion
//! proofs, batch retrieval (multiple matvecs), and a JSON wire codec.
//!
//! ## Honest non-claims
//!
//! - Computational PIR (SimplePIR-style), **not** FHE.
//! - Toy params: `N ≤ 2^12` (4096), row ≤ 256 bytes.
//! - Server sees query **size**; we do not hide that a query happened.
//! - Query privacy on the wire is still **toy** (exact one-hot); JSON encoding
//!   does not add privacy.
//! - Not production parameters; not ANN / vector search.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod catalog;
pub mod client;
pub mod directory;
pub mod error;
pub mod hint;
pub mod merkle;
pub mod params;
pub mod pir;
pub mod receipt;
pub mod server;
pub mod snapshot;
pub mod sync;
pub mod wire;

pub use catalog::{Catalog, CatalogFile, CatalogFileEntry};
pub use client::{BlindClient, ProvenRow, MAX_BATCH_SIZE};
pub use directory::{Directory, DirectoryEntry, DirectoryParams, DIRECTORY_VERSION};
pub use error::{BlindDexError, Result};
pub use hint::{Hint, HINT_VERSION};
pub use merkle::{MerkleProof, ProofStep, SiblingSide};
pub use params::{
    Params, DEFAULT_MODULUS, DEFAULT_N_ROWS, DEFAULT_ROW_BYTES, MAX_N_ROWS, MAX_ROW_BYTES,
};
pub use pir::{DatabaseMatrix, PirEngine};
pub use receipt::{
    generate_nonce, generate_nonce_default, generate_nonce_hex, generate_nonce_hex_default,
    verify_nonce_echo, ReplayWindow, DEFAULT_NONCE_LEN, DEFAULT_REPLAY_WINDOW_SIZE, MAX_NONCE_LEN,
    MIN_NONCE_LEN,
};
pub use server::{put_entry, BlindServer};
pub use snapshot::{SnapshotMeta, SNAPSHOT_VERSION};
pub use sync::{PinnedEpoch, SyncAck, SyncOffer, SYNC_VERSION};
pub use wire::{
    proof_from_json, proof_to_json, WireAnswer, WireBatchProven, WireDirectory, WireDirectoryEntry,
    WireProvenRow, WireQuery, WireSyncAck, WireSyncOffer, WIRE_VERSION,
};
