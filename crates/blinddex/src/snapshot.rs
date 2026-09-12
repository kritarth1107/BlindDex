//! Catalog snapshot metadata for sealing and verification.
//!
//! A snapshot captures the essential state of a catalog at a point in time:
//! - Parameters (n_rows, row_bytes, modulus)
//! - Merkle root commitment
//! - Row count (occupied slots)
//! - Optional hint seed for offline precomputation
//!
//! This allows a client to verify that a catalog file matches a previously
//! sealed snapshot without re-computing the full Merkle tree.

use crate::catalog::Catalog;
use crate::error::Result;
use crate::params::Params;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Snapshot metadata version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Catalog snapshot metadata for sealing/verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Format version for forward compatibility.
    pub version: u32,
    /// Catalog parameters.
    pub params: Params,
    /// Merkle root as lowercase hex (64 chars).
    pub merkle_root_hex: String,
    /// Number of occupied rows at snapshot time.
    pub row_count: usize,
    /// Optional hint seed (hex) if offline hint was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_seed_hex: Option<String>,
    /// Unix timestamp (seconds) when the snapshot was created.
    pub created_at: u64,
}

impl SnapshotMeta {
    /// Create a snapshot from a catalog.
    pub fn from_catalog(catalog: &Catalog) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            version: SNAPSHOT_VERSION,
            params: *catalog.params(),
            merkle_root_hex: catalog.merkle_root_hex(),
            row_count: catalog.len(),
            hint_seed_hex: None,
            created_at,
        }
    }

    /// Create a snapshot with an associated hint seed.
    pub fn from_catalog_with_hint(catalog: &Catalog, hint_seed: &[u8; 32]) -> Self {
        let mut snap = Self::from_catalog(catalog);
        snap.hint_seed_hex = Some(hex::encode(hint_seed));
        snap
    }

    /// Check if this snapshot matches a catalog's current state.
    ///
    /// Verifies params and merkle root match. Row count is informational
    /// and not strictly enforced (empty slots don't change the root).
    pub fn matches_catalog(&self, catalog: &Catalog) -> bool {
        self.params == *catalog.params() && self.merkle_root_hex == catalog.merkle_root_hex()
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Write snapshot JSON to a file.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Read snapshot from a JSON file.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_json(&text)
    }

    /// Generate the sidecar filename for a catalog path.
    ///
    /// Example: `catalog.json` → `catalog.snapshot.json`
    pub fn sidecar_path(catalog_path: impl AsRef<Path>) -> std::path::PathBuf {
        let p = catalog_path.as_ref();
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("catalog");
        let parent = p.parent().unwrap_or(Path::new("."));
        parent.join(format!("{}.snapshot.json", stem))
    }

    /// Write snapshot as a sidecar file next to the catalog.
    pub fn write_sidecar(&self, catalog_path: impl AsRef<Path>) -> Result<std::path::PathBuf> {
        let sidecar = Self::sidecar_path(&catalog_path);
        self.write_to_file(&sidecar)?;
        Ok(sidecar)
    }

    /// Read snapshot from the sidecar file for a catalog.
    pub fn read_sidecar(catalog_path: impl AsRef<Path>) -> Result<Self> {
        let sidecar = Self::sidecar_path(&catalog_path);
        Self::read_from_file(&sidecar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_from_catalog() {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        cat.insert(Some("test".into()), b"payload").unwrap();

        let snap = SnapshotMeta::from_catalog(&cat);
        assert_eq!(snap.version, SNAPSHOT_VERSION);
        assert_eq!(snap.params, params);
        assert_eq!(snap.row_count, 1);
        assert!(snap.hint_seed_hex.is_none());
        assert!(snap.matches_catalog(&cat));
    }

    #[test]
    fn snapshot_with_hint() {
        let params = Params::preset_tiny();
        let cat = Catalog::new(params).unwrap();
        let seed = [42u8; 32];

        let snap = SnapshotMeta::from_catalog_with_hint(&cat, &seed);
        assert_eq!(snap.hint_seed_hex, Some(hex::encode(seed)));
    }

    #[test]
    fn snapshot_json_roundtrip() {
        let params = Params::preset_small();
        let mut cat = Catalog::new(params).unwrap();
        cat.insert(None, b"data").unwrap();

        let snap = SnapshotMeta::from_catalog(&cat);
        let json = snap.to_json().unwrap();
        let snap2 = SnapshotMeta::from_json(&json).unwrap();
        assert_eq!(snap, snap2);
    }

    #[test]
    fn snapshot_mismatch_after_insert() {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        let snap = SnapshotMeta::from_catalog(&cat);

        assert!(snap.matches_catalog(&cat));

        cat.insert(None, b"new row").unwrap();
        assert!(!snap.matches_catalog(&cat));
    }

    #[test]
    fn sidecar_path_generation() {
        let path = SnapshotMeta::sidecar_path("fixtures/catalog_toy.json");
        assert_eq!(path.to_str().unwrap(), "fixtures/catalog_toy.snapshot.json");

        let path2 = SnapshotMeta::sidecar_path("/tmp/my_catalog.json");
        assert_eq!(path2.to_str().unwrap(), "/tmp/my_catalog.snapshot.json");
    }
}
