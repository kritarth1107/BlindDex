//! JSON wire codec for host interoperability.
//!
//! Serializes toy PIR queries/answers, Merkle proofs, and directories to/from
//! JSON so a non-Rust host (HTTP later, CLI pipes today) can exchange BlindDex
//! messages without linking the crate.
//!
//! # Honest note
//!
//! The toy query is still an exact one-hot vector on the wire. Encoding it as
//! JSON does **not** add query privacy — see [`crate`] crate docs and
//! `THREAT_MODEL.md`.
//!
//! # Directory on the wire
//!
//! [`WireDirectory`] is the wire representation of a public directory. A server
//! publishes this so clients can resolve keys/hashes to indices locally. The
//! directory reveals which skills exist but (with a real LWE layer) not which
//! one was fetched.

use crate::directory::{Directory, DirectoryEntry, DirectoryParams};
use crate::error::{BlindDexError, Result};
use crate::merkle::MerkleProof;
use crate::params::Params;
use serde::{Deserialize, Serialize};

/// Wire envelope version tag.
pub const WIRE_VERSION: u32 = 1;

/// JSON-friendly PIR query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireQuery {
    /// Codec version.
    pub version: u32,
    /// Catalog / PIR params the query was built for.
    pub params: Params,
    /// Exact (toy) query limbs — length must equal `params.n_rows`.
    pub query: Vec<u64>,
}

/// JSON-friendly PIR answer (matvec limbs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAnswer {
    /// Codec version.
    pub version: u32,
    /// Answer limbs — length must equal `params.limbs_per_row()`.
    pub answer: Vec<u64>,
}

/// Proven retrieval result on the wire: recovered row + inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireProvenRow {
    /// Codec version.
    pub version: u32,
    /// Row index that was retrieved.
    pub index: usize,
    /// Fixed-width row bytes as lowercase hex.
    pub row_hex: String,
    /// Published Merkle root (hex) the proof should open to.
    pub root_hex: String,
    /// Inclusion proof for `index`.
    pub proof: MerkleProof,
}

/// Batch of proven rows (one PIR matvec per index in this slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBatchProven {
    /// Codec version.
    pub version: u32,
    /// Per-index results in request order.
    pub items: Vec<WireProvenRow>,
}

impl WireQuery {
    /// Wrap a raw query vector.
    pub fn new(params: Params, query: Vec<u64>) -> Self {
        Self {
            version: WIRE_VERSION,
            params,
            query,
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

impl WireAnswer {
    /// Wrap answer limbs.
    pub fn new(answer: Vec<u64>) -> Self {
        Self {
            version: WIRE_VERSION,
            answer,
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

impl WireProvenRow {
    /// Build from row bytes + proof + root.
    pub fn new(index: usize, row: &[u8], root: &[u8; 32], proof: MerkleProof) -> Self {
        Self {
            version: WIRE_VERSION,
            index,
            row_hex: hex::encode(row),
            root_hex: hex::encode(root),
            proof,
        }
    }

    /// Decode row bytes from `row_hex`.
    pub fn row_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.row_hex).map_err(|e| BlindDexError::Serde(e.to_string()))
    }

    /// Decode expected root.
    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.root_hex).map_err(|e| BlindDexError::Serde(e.to_string()))?;
        if v.len() != 32 {
            return Err(BlindDexError::Serde(format!(
                "root_hex must be 32 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }

    /// Verify the embedded proof against `root_hex` and that `leaf_hash`
    /// matches `SHA-256(row)`.
    pub fn verify(&self) -> Result<()> {
        use sha2::{Digest, Sha256};
        let root = self.root_bytes()?;
        self.proof.verify(&root)?;
        let row = self.row_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&row);
        let leaf: [u8; 32] = hasher.finalize().into();
        if leaf != self.proof.leaf_hash {
            return Err(BlindDexError::ProofVerificationFailed {
                expected: hex::encode(self.proof.leaf_hash),
                got: hex::encode(leaf),
            });
        }
        Ok(())
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

impl WireBatchProven {
    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Verify every item.
    pub fn verify_all(&self) -> Result<()> {
        for item in &self.items {
            item.verify()?;
        }
        Ok(())
    }
}

/// Encode a [`MerkleProof`] as pretty JSON.
pub fn proof_to_json(proof: &MerkleProof) -> Result<String> {
    Ok(serde_json::to_string_pretty(proof)?)
}

/// Decode a [`MerkleProof`] from JSON.
pub fn proof_from_json(s: &str) -> Result<MerkleProof> {
    Ok(serde_json::from_str(s)?)
}

/// Wire representation of a directory entry.
///
/// Identical to [`DirectoryEntry`] but explicitly versioned for wire compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDirectoryEntry {
    /// Slot index in the catalog.
    pub index: usize,
    /// Optional human-readable key (skill/tool name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Blake3 content hash of the normalized row (lowercase hex, 64 chars).
    pub content_hash: String,
    /// SHA-256 leaf hash for Merkle proof verification (lowercase hex, 64 chars).
    pub leaf_hash: String,
}

impl From<&DirectoryEntry> for WireDirectoryEntry {
    fn from(e: &DirectoryEntry) -> Self {
        Self {
            index: e.index,
            key: e.key.clone(),
            content_hash: e.content_hash.clone(),
            leaf_hash: e.leaf_hash.clone(),
        }
    }
}

impl From<WireDirectoryEntry> for DirectoryEntry {
    fn from(w: WireDirectoryEntry) -> Self {
        Self {
            index: w.index,
            key: w.key,
            content_hash: w.content_hash,
            leaf_hash: w.leaf_hash,
        }
    }
}

/// Wire representation of a public directory.
///
/// A server publishes this so clients can resolve keys/hashes to indices
/// locally before issuing PIR queries.
///
/// # Privacy model
///
/// Publishing a directory reveals which skills exist (keys + hashes).
/// With a future LWE query layer, which skill was *fetched* remains private.
/// See `THREAT_MODEL.md` for full analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDirectory {
    /// Wire codec version.
    pub version: u32,
    /// Number of rows (slots) in the catalog.
    pub n_rows: usize,
    /// Fixed row width in bytes.
    pub row_bytes: usize,
    /// Ring modulus.
    pub modulus: u64,
    /// SHA-256 Merkle root over all catalog slots (lowercase hex).
    pub merkle_root: String,
    /// Directory seal (blake3 fingerprint, lowercase hex).
    pub seal: String,
    /// Directory entries for occupied slots.
    pub entries: Vec<WireDirectoryEntry>,
}

impl WireDirectory {
    /// Build from a [`Directory`].
    pub fn from_directory(dir: &Directory) -> Self {
        Self {
            version: WIRE_VERSION,
            n_rows: dir.params.n_rows,
            row_bytes: dir.params.row_bytes,
            modulus: dir.params.modulus,
            merkle_root: dir.merkle_root.clone(),
            seal: dir.seal_hex(),
            entries: dir.entries.iter().map(WireDirectoryEntry::from).collect(),
        }
    }

    /// Convert to a [`Directory`].
    pub fn to_directory(&self) -> Directory {
        Directory {
            version: crate::directory::DIRECTORY_VERSION,
            params: DirectoryParams {
                n_rows: self.n_rows,
                row_bytes: self.row_bytes,
                modulus: self.modulus,
            },
            merkle_root: self.merkle_root.clone(),
            entries: self.entries.iter().cloned().map(DirectoryEntry::from).collect(),
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Verify that the embedded seal matches the directory content.
    ///
    /// Returns `true` if the seal is valid.
    pub fn verify_seal(&self) -> bool {
        let dir = self.to_directory();
        dir.verify_seal_hex(&self.seal)
    }
}
