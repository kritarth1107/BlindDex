//! Catalog sync handshake for epoch binding.
//!
//! A sync handshake lets a client verify that a server's catalog matches
//! a pinned epoch before issuing PIR queries. The server sends a [`SyncOffer`]
//! containing the catalog fingerprint (merkle root, directory seal, params).
//! The client checks the offer against a pinned expectation and sends a
//! [`SyncAck`] to confirm or reject.
//!
//! # Epoch binding
//!
//! The directory seal + merkle root together form an "epoch" fingerprint.
//! A client that pins these values can detect if the catalog has changed
//! (new entries, modified rows, different params) before trusting any
//! query answers.
//!
//! # Protocol sketch
//!
//! ```text
//! Client                              Server
//!   |                                    |
//!   |  <------ SyncOffer --------------- |  (merkle_root, seal, params, row_count)
//!   |                                    |
//!   |  (verify against pinned epoch)     |
//!   |                                    |
//!   |  ------- SyncAck ----------------> |  (accepted: true/false, reason)
//!   |                                    |
//!   |  (if accepted, proceed with PIR)   |
//! ```
//!
//! # Honest scope
//!
//! This handshake does NOT authenticate the server. It only binds the
//! session to a known catalog state. Server authentication requires
//! transport security (TLS) or signed offers (future work).

use crate::catalog::Catalog;
use crate::directory::Directory;
use crate::error::Result;
use crate::params::Params;
use crate::snapshot::SnapshotMeta;
use serde::{Deserialize, Serialize};

/// Sync protocol version.
pub const SYNC_VERSION: u32 = 1;

/// Server-to-client offer announcing the current catalog epoch.
///
/// The client compares this against a pinned expectation to verify
/// the catalog hasn't changed since a known point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOffer {
    /// Protocol version for forward compatibility.
    pub version: u32,
    /// Catalog parameters (n_rows, row_bytes, modulus).
    pub params: Params,
    /// Blake3 fingerprint of params (hex, 64 chars).
    pub params_fingerprint: String,
    /// SHA-256 Merkle root over catalog rows (hex, 64 chars).
    pub merkle_root: String,
    /// Blake3 directory seal (hex, 64 chars).
    pub directory_seal: String,
    /// Number of occupied rows in the catalog.
    pub row_count: usize,
    /// Optional snapshot metadata (created_at, hint_seed, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotMeta>,
}

/// Client-to-server acknowledgment of a sync offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAck {
    /// Protocol version.
    pub version: u32,
    /// Whether the client accepts this epoch.
    pub accepted: bool,
    /// Optional reason for rejection (for diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Echo back the accepted seal for server-side verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_seal: Option<String>,
}

/// Expected epoch values for offer verification.
///
/// A client constructs this from a previously pinned directory/snapshot
/// and uses it to verify incoming [`SyncOffer`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEpoch {
    /// Expected merkle root (hex).
    pub merkle_root: String,
    /// Expected directory seal (hex).
    pub directory_seal: String,
    /// Expected params fingerprint (hex). Optional for loose matching.
    pub params_fingerprint: Option<String>,
    /// Expected row count. Optional for loose matching.
    pub row_count: Option<usize>,
}

impl SyncOffer {
    /// Build a sync offer from a catalog.
    ///
    /// Computes the directory seal from the catalog's exported directory.
    pub fn from_catalog(catalog: &Catalog) -> Self {
        let dir = catalog.export_directory();
        Self::from_catalog_and_directory(catalog, &dir)
    }

    /// Build a sync offer from a catalog and pre-computed directory.
    ///
    /// Use this when you already have the directory to avoid recomputing it.
    pub fn from_catalog_and_directory(catalog: &Catalog, directory: &Directory) -> Self {
        let params = *catalog.params();
        Self {
            version: SYNC_VERSION,
            params,
            params_fingerprint: Self::compute_params_fingerprint(&params),
            merkle_root: catalog.merkle_root_hex(),
            directory_seal: directory.seal_hex(),
            row_count: catalog.len(),
            snapshot: None,
        }
    }

    /// Build a sync offer with snapshot metadata.
    pub fn with_snapshot(mut self, snapshot: SnapshotMeta) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    /// Compute blake3 fingerprint of params for version binding.
    pub fn compute_params_fingerprint(params: &Params) -> String {
        let json = serde_json::to_string(params).expect("params always serializable");
        hex::encode(blake3::hash(json.as_bytes()).as_bytes())
    }

    /// Verify this offer against a pinned epoch expectation.
    ///
    /// Returns `Ok(())` if all pinned fields match, or an error describing
    /// the mismatch.
    pub fn verify(&self, pinned: &PinnedEpoch) -> Result<()> {
        use crate::error::BlindDexError;

        if self.merkle_root != pinned.merkle_root {
            return Err(BlindDexError::EpochMismatch {
                field: "merkle_root".to_string(),
                expected: pinned.merkle_root.clone(),
                got: self.merkle_root.clone(),
            });
        }

        if self.directory_seal != pinned.directory_seal {
            return Err(BlindDexError::EpochMismatch {
                field: "directory_seal".to_string(),
                expected: pinned.directory_seal.clone(),
                got: self.directory_seal.clone(),
            });
        }

        if let Some(ref expected_fp) = pinned.params_fingerprint {
            if &self.params_fingerprint != expected_fp {
                return Err(BlindDexError::EpochMismatch {
                    field: "params_fingerprint".to_string(),
                    expected: expected_fp.clone(),
                    got: self.params_fingerprint.clone(),
                });
            }
        }

        if let Some(expected_count) = pinned.row_count {
            if self.row_count != expected_count {
                return Err(BlindDexError::EpochMismatch {
                    field: "row_count".to_string(),
                    expected: expected_count.to_string(),
                    got: self.row_count.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Quick check if merkle_root and directory_seal match.
    pub fn matches_epoch(&self, merkle_root: &str, directory_seal: &str) -> bool {
        self.merkle_root == merkle_root && self.directory_seal == directory_seal
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

impl SyncAck {
    /// Create an acceptance ack.
    pub fn accept(seal: &str) -> Self {
        Self {
            version: SYNC_VERSION,
            accepted: true,
            reason: None,
            accepted_seal: Some(seal.to_string()),
        }
    }

    /// Create a rejection ack with reason.
    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            version: SYNC_VERSION,
            accepted: false,
            reason: Some(reason.into()),
            accepted_seal: None,
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

impl PinnedEpoch {
    /// Create from a directory.
    pub fn from_directory(dir: &Directory) -> Self {
        Self {
            merkle_root: dir.merkle_root.clone(),
            directory_seal: dir.seal_hex(),
            params_fingerprint: Some(SyncOffer::compute_params_fingerprint(&Params {
                n_rows: dir.params.n_rows,
                row_bytes: dir.params.row_bytes,
                modulus: dir.params.modulus,
            })),
            row_count: Some(dir.len()),
        }
    }

    /// Create with only merkle_root and seal (loose matching).
    pub fn new(merkle_root: impl Into<String>, directory_seal: impl Into<String>) -> Self {
        Self {
            merkle_root: merkle_root.into(),
            directory_seal: directory_seal.into(),
            params_fingerprint: None,
            row_count: None,
        }
    }

    /// Add expected params fingerprint.
    pub fn with_params_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.params_fingerprint = Some(fp.into());
        self
    }

    /// Add expected row count.
    pub fn with_row_count(mut self, count: usize) -> Self {
        self.row_count = Some(count);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_catalog() -> Catalog {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        cat.insert(Some("skill_a".into()), b"payload a").unwrap();
        cat.insert(Some("skill_b".into()), b"payload b").unwrap();
        cat
    }

    #[test]
    fn sync_offer_from_catalog() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);

        assert_eq!(offer.version, SYNC_VERSION);
        assert_eq!(offer.merkle_root, cat.merkle_root_hex());
        assert_eq!(offer.row_count, cat.len());
        assert_eq!(offer.params, *cat.params());
        assert_eq!(offer.params_fingerprint.len(), 64);
        assert_eq!(offer.directory_seal.len(), 64);
    }

    #[test]
    fn sync_offer_json_roundtrip() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let json = offer.to_json().unwrap();
        let offer2 = SyncOffer::from_json(&json).unwrap();
        assert_eq!(offer, offer2);
    }

    #[test]
    fn sync_ack_accept_reject() {
        let ack = SyncAck::accept("abc123");
        assert!(ack.accepted);
        assert_eq!(ack.accepted_seal, Some("abc123".to_string()));

        let rej = SyncAck::reject("merkle mismatch");
        assert!(!rej.accepted);
        assert_eq!(rej.reason, Some("merkle mismatch".to_string()));
    }

    #[test]
    fn sync_ack_json_roundtrip() {
        let ack = SyncAck::accept("seal123");
        let json = ack.to_json().unwrap();
        let ack2 = SyncAck::from_json(&json).unwrap();
        assert_eq!(ack, ack2);
    }

    #[test]
    fn pinned_epoch_verify_success() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let dir = cat.export_directory();
        let pinned = PinnedEpoch::from_directory(&dir);

        assert!(offer.verify(&pinned).is_ok());
    }

    #[test]
    fn pinned_epoch_verify_merkle_mismatch() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let pinned = PinnedEpoch::new("wrong_root", &offer.directory_seal);

        let err = offer.verify(&pinned).unwrap_err();
        assert!(err.to_string().contains("merkle_root"));
    }

    #[test]
    fn pinned_epoch_verify_seal_mismatch() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let pinned = PinnedEpoch::new(&offer.merkle_root, "wrong_seal");

        let err = offer.verify(&pinned).unwrap_err();
        assert!(err.to_string().contains("directory_seal"));
    }

    #[test]
    fn pinned_epoch_loose_matching() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let dir = cat.export_directory();

        let pinned = PinnedEpoch::new(&dir.merkle_root, &dir.seal_hex());
        assert!(offer.verify(&pinned).is_ok());
    }

    #[test]
    fn matches_epoch_helper() {
        let cat = make_test_catalog();
        let offer = SyncOffer::from_catalog(&cat);
        let dir = cat.export_directory();

        assert!(offer.matches_epoch(&dir.merkle_root, &dir.seal_hex()));
        assert!(!offer.matches_epoch("wrong", &dir.seal_hex()));
        assert!(!offer.matches_epoch(&dir.merkle_root, "wrong"));
    }

    #[test]
    fn params_fingerprint_changes_with_params() {
        let fp1 = SyncOffer::compute_params_fingerprint(&Params::preset_tiny());
        let fp2 = SyncOffer::compute_params_fingerprint(&Params::preset_small());
        assert_ne!(fp1, fp2);

        let fp1_again = SyncOffer::compute_params_fingerprint(&Params::preset_tiny());
        assert_eq!(fp1, fp1_again);
    }

    #[test]
    fn offer_with_snapshot() {
        let cat = make_test_catalog();
        let snap = SnapshotMeta::from_catalog(&cat);
        let offer = SyncOffer::from_catalog(&cat).with_snapshot(snap.clone());

        assert_eq!(offer.snapshot, Some(snap));

        let json = offer.to_json().unwrap();
        let offer2 = SyncOffer::from_json(&json).unwrap();
        assert_eq!(offer, offer2);
    }
}
