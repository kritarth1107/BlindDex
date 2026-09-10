//! # BlindDex
//!
//! Single-server **computational PIR** for opaque catalogs (MCP tool
//! descriptors, skill packs). A client retrieves entry `i` (or a hash-keyed
//! row); with a cryptographic query layer the server learns neither index nor
//! payload.
//!
//! This crate ships a **toy SimplePIR-style matvec** with exact one-hot queries
//! for demos, plus a SHA-256 Merkle commitment over fixed-width rows.
//!
//! ## Honest non-claims
//!
//! - Computational PIR (SimplePIR-style), **not** FHE.
//! - Toy params: `N ≤ 2^12` (4096), row ≤ 256 bytes.
//! - Server sees query **size**; we do not hide that a query happened.
//! - Not production parameters; not ANN / vector search.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod catalog;
pub mod client;
pub mod error;
pub mod params;
pub mod pir;
pub mod server;

pub use catalog::{Catalog, CatalogFile, CatalogFileEntry};
pub use client::BlindClient;
pub use error::{BlindDexError, Result};
pub use params::{
    Params, DEFAULT_MODULUS, DEFAULT_N_ROWS, DEFAULT_ROW_BYTES, MAX_N_ROWS, MAX_ROW_BYTES,
};
pub use pir::{DatabaseMatrix, PirEngine};
pub use server::{put_entry, BlindServer};
