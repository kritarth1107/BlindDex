//! JSON wire codec for host interoperability.
//!
//! Serializes toy PIR queries/answers, Merkle proofs, directories, and sync
//! handshakes to/from JSON so a non-Rust host (HTTP later, CLI pipes today)
//! can exchange BlindDex messages without linking the crate.
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
//!
//! # Epoch binding
//!
//! Queries and answers can carry optional epoch fields (`directory_seal` and
//! `merkle_root`) so a server can verify that a query targets the current
//! catalog epoch, and a client can verify that an answer comes from the
//! expected epoch. See [`WireQuery`] and [`WireAnswer`] epoch fields.

use crate::directory::{Directory, DirectoryEntry, DirectoryParams};
use crate::error::{BlindDexError, Result};
use crate::merkle::MerkleProof;
use crate::params::Params;
use crate::snapshot::SnapshotMeta;
use crate::sync::{SyncAck, SyncOffer, SYNC_VERSION};
use serde::{Deserialize, Serialize};

/// Wire envelope version tag.
pub const WIRE_VERSION: u32 = 1;

/// JSON-friendly PIR query.
///
/// # Epoch binding
///
/// Queries can carry optional epoch fields so the server can reject queries
/// targeting a stale or different catalog epoch:
/// - `directory_seal`: blake3 seal of the directory the client expects
/// - `merkle_root`: SHA-256 merkle root of the catalog the client expects
///
/// A server that enforces epoch binding will reject queries where these fields
/// don't match its current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireQuery {
    /// Codec version.
    pub version: u32,
    /// Catalog / PIR params the query was built for.
    pub params: Params,
    /// Exact (toy) query limbs — length must equal `params.n_rows`.
    pub query: Vec<u64>,
    /// Optional directory seal for epoch binding (hex, 64 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_seal: Option<String>,
    /// Optional merkle root for epoch binding (hex, 64 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
}

/// JSON-friendly PIR answer (matvec limbs).
///
/// # Epoch binding
///
/// Answers can carry epoch fields so the client can verify the answer came
/// from the expected catalog epoch:
/// - `directory_seal`: blake3 seal of the server's directory
/// - `merkle_root`: SHA-256 merkle root of the server's catalog
///
/// A client that enforces epoch binding will reject answers where these fields
/// don't match its pinned expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAnswer {
    /// Codec version.
    pub version: u32,
    /// Answer limbs — length must equal `params.limbs_per_row()`.
    pub answer: Vec<u64>,
    /// Optional directory seal for epoch binding (hex, 64 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_seal: Option<String>,
    /// Optional merkle root for epoch binding (hex, 64 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
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
            directory_seal: None,
            merkle_root: None,
        }
    }

    /// Attach epoch binding fields (directory seal and merkle root).
    ///
    /// The server can use these to reject queries targeting a different epoch.
    pub fn with_epoch(mut self, directory_seal: &str, merkle_root: &str) -> Self {
        self.directory_seal = Some(directory_seal.to_string());
        self.merkle_root = Some(merkle_root.to_string());
        self
    }

    /// Check if this query has epoch binding fields.
    pub fn has_epoch(&self) -> bool {
        self.directory_seal.is_some() && self.merkle_root.is_some()
    }

    /// Verify that this query's epoch fields match expected values.
    ///
    /// Returns `Ok(())` if both fields match or are not present.
    /// Returns an error if any field is present but doesn't match.
    pub fn verify_epoch(&self, expected_seal: &str, expected_root: &str) -> Result<()> {
        if let Some(ref seal) = self.directory_seal {
            if seal != expected_seal {
                return Err(BlindDexError::EpochMismatch {
                    field: "directory_seal".to_string(),
                    expected: expected_seal.to_string(),
                    got: seal.clone(),
                });
            }
        }
        if let Some(ref root) = self.merkle_root {
            if root != expected_root {
                return Err(BlindDexError::EpochMismatch {
                    field: "merkle_root".to_string(),
                    expected: expected_root.to_string(),
                    got: root.clone(),
                });
            }
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

impl WireAnswer {
    /// Wrap answer limbs.
    pub fn new(answer: Vec<u64>) -> Self {
        Self {
            version: WIRE_VERSION,
            answer,
            directory_seal: None,
            merkle_root: None,
        }
    }

    /// Attach epoch binding fields (directory seal and merkle root).
    ///
    /// The client can use these to verify the answer came from the expected epoch.
    pub fn with_epoch(mut self, directory_seal: &str, merkle_root: &str) -> Self {
        self.directory_seal = Some(directory_seal.to_string());
        self.merkle_root = Some(merkle_root.to_string());
        self
    }

    /// Check if this answer has epoch binding fields.
    pub fn has_epoch(&self) -> bool {
        self.directory_seal.is_some() && self.merkle_root.is_some()
    }

    /// Verify that this answer's epoch fields match expected values.
    ///
    /// Returns `Ok(())` if both fields match or are not present.
    /// Returns an error if any field is present but doesn't match.
    pub fn verify_epoch(&self, expected_seal: &str, expected_root: &str) -> Result<()> {
        if let Some(ref seal) = self.directory_seal {
            if seal != expected_seal {
                return Err(BlindDexError::EpochMismatch {
                    field: "directory_seal".to_string(),
                    expected: expected_seal.to_string(),
                    got: seal.clone(),
                });
            }
        }
        if let Some(ref root) = self.merkle_root {
            if root != expected_root {
                return Err(BlindDexError::EpochMismatch {
                    field: "merkle_root".to_string(),
                    expected: expected_root.to_string(),
                    got: root.clone(),
                });
            }
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
            entries: self
                .entries
                .iter()
                .cloned()
                .map(DirectoryEntry::from)
                .collect(),
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

/// Wire representation of a sync offer.
///
/// The server sends this to announce its current catalog epoch. Clients
/// verify against a pinned expectation before proceeding with queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSyncOffer {
    /// Protocol version.
    pub version: u32,
    /// Catalog parameters.
    pub params: Params,
    /// Blake3 fingerprint of params (hex, 64 chars).
    pub params_fingerprint: String,
    /// SHA-256 Merkle root over catalog rows (hex, 64 chars).
    pub merkle_root: String,
    /// Blake3 directory seal (hex, 64 chars).
    pub directory_seal: String,
    /// Number of occupied rows.
    pub row_count: usize,
    /// Optional snapshot metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotMeta>,
}

impl WireSyncOffer {
    /// Build from a [`SyncOffer`].
    pub fn from_sync_offer(offer: &SyncOffer) -> Self {
        Self {
            version: WIRE_VERSION,
            params: offer.params,
            params_fingerprint: offer.params_fingerprint.clone(),
            merkle_root: offer.merkle_root.clone(),
            directory_seal: offer.directory_seal.clone(),
            row_count: offer.row_count,
            snapshot: offer.snapshot.clone(),
        }
    }

    /// Convert to a [`SyncOffer`].
    pub fn to_sync_offer(&self) -> SyncOffer {
        SyncOffer {
            version: SYNC_VERSION,
            params: self.params,
            params_fingerprint: self.params_fingerprint.clone(),
            merkle_root: self.merkle_root.clone(),
            directory_seal: self.directory_seal.clone(),
            row_count: self.row_count,
            snapshot: self.snapshot.clone(),
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

/// Wire representation of a sync acknowledgment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSyncAck {
    /// Protocol version.
    pub version: u32,
    /// Whether the client accepts this epoch.
    pub accepted: bool,
    /// Optional reason for rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Echo back the accepted seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_seal: Option<String>,
}

impl WireSyncAck {
    /// Build from a [`SyncAck`].
    pub fn from_sync_ack(ack: &SyncAck) -> Self {
        Self {
            version: WIRE_VERSION,
            accepted: ack.accepted,
            reason: ack.reason.clone(),
            accepted_seal: ack.accepted_seal.clone(),
        }
    }

    /// Convert to a [`SyncAck`].
    pub fn to_sync_ack(&self) -> SyncAck {
        SyncAck {
            version: SYNC_VERSION,
            accepted: self.accepted,
            reason: self.reason.clone(),
            accepted_seal: self.accepted_seal.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    #[test]
    fn wire_query_epoch_fields() {
        let params = Params::preset_tiny();
        let query = vec![1u64; params.n_rows];
        let wq = WireQuery::new(params, query.clone());
        assert!(!wq.has_epoch());

        let wq_epoch = WireQuery::new(params, query)
            .with_epoch("seal123", "root456");
        assert!(wq_epoch.has_epoch());
        assert_eq!(wq_epoch.directory_seal, Some("seal123".to_string()));
        assert_eq!(wq_epoch.merkle_root, Some("root456".to_string()));
    }

    #[test]
    fn wire_query_epoch_roundtrip() {
        let params = Params::preset_tiny();
        let query = vec![1u64; params.n_rows];
        let wq = WireQuery::new(params, query).with_epoch("seal_abc", "root_def");

        let json = wq.to_json().unwrap();
        let wq2 = WireQuery::from_json(&json).unwrap();
        assert_eq!(wq, wq2);
        assert!(wq2.has_epoch());
    }

    #[test]
    fn wire_query_verify_epoch() {
        let params = Params::preset_tiny();
        let query = vec![1u64; params.n_rows];
        let wq = WireQuery::new(params, query).with_epoch("seal_x", "root_y");

        assert!(wq.verify_epoch("seal_x", "root_y").is_ok());
        assert!(wq.verify_epoch("wrong", "root_y").is_err());
        assert!(wq.verify_epoch("seal_x", "wrong").is_err());
    }

    #[test]
    fn wire_answer_epoch_fields() {
        let answer = vec![42u64; 8];
        let wa = WireAnswer::new(answer.clone());
        assert!(!wa.has_epoch());

        let wa_epoch = WireAnswer::new(answer).with_epoch("seal_srv", "root_srv");
        assert!(wa_epoch.has_epoch());
    }

    #[test]
    fn wire_answer_epoch_roundtrip() {
        let answer = vec![42u64; 8];
        let wa = WireAnswer::new(answer).with_epoch("my_seal", "my_root");

        let json = wa.to_json().unwrap();
        let wa2 = WireAnswer::from_json(&json).unwrap();
        assert_eq!(wa, wa2);
    }

    #[test]
    fn wire_answer_verify_epoch() {
        let answer = vec![42u64; 8];
        let wa = WireAnswer::new(answer).with_epoch("seal_a", "root_b");

        assert!(wa.verify_epoch("seal_a", "root_b").is_ok());
        assert!(wa.verify_epoch("other", "root_b").is_err());
    }

    #[test]
    fn wire_sync_offer_roundtrip() {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        cat.insert(Some("test".into()), b"payload").unwrap();

        let offer = SyncOffer::from_catalog(&cat);
        let wire = WireSyncOffer::from_sync_offer(&offer);

        let json = wire.to_json().unwrap();
        let wire2 = WireSyncOffer::from_json(&json).unwrap();
        assert_eq!(wire, wire2);

        let offer2 = wire2.to_sync_offer();
        assert_eq!(offer.merkle_root, offer2.merkle_root);
        assert_eq!(offer.directory_seal, offer2.directory_seal);
        assert_eq!(offer.params, offer2.params);
    }

    #[test]
    fn wire_sync_ack_roundtrip() {
        let ack = SyncAck::accept("seal123");
        let wire = WireSyncAck::from_sync_ack(&ack);

        let json = wire.to_json().unwrap();
        let wire2 = WireSyncAck::from_json(&json).unwrap();
        assert_eq!(wire, wire2);

        let ack2 = wire2.to_sync_ack();
        assert!(ack2.accepted);
        assert_eq!(ack2.accepted_seal, Some("seal123".to_string()));
    }

    #[test]
    fn wire_sync_ack_reject_roundtrip() {
        let ack = SyncAck::reject("epoch mismatch");
        let wire = WireSyncAck::from_sync_ack(&ack);

        let json = wire.to_json().unwrap();
        let wire2 = WireSyncAck::from_json(&json).unwrap();
        let ack2 = wire2.to_sync_ack();

        assert!(!ack2.accepted);
        assert_eq!(ack2.reason, Some("epoch mismatch".to_string()));
    }
}
