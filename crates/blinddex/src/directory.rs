//! Public directory for name→index resolution.
//!
//! A [`Directory`] is a **public** listing of all catalog entries: their indices,
//! optional keys (skill/tool names), content hashes (blake3), and leaf hashes
//! (SHA-256). The directory does NOT include payloads — only metadata needed
//! for a client to resolve a key or hash to an index, then issue a PIR query.
//!
//! # Privacy model
//!
//! Publishing a directory **reveals which skills exist** — the keys and content
//! hashes are public. What remains private (with a future LWE query layer) is
//! **which skill was fetched**. A client downloads the directory, resolves
//! `wire_transfer` → index 3 locally, then issues a blind PIR query for index 3.
//! The server (with cryptographic queries) cannot tell which index was requested.
//!
//! See `THREAT_MODEL.md` for the full analysis.
//!
//! # Sealing
//!
//! [`Directory::seal`] computes a fingerprint (blake3 hash) over the canonical
//! JSON of entries + merkle root. A client can pin this seal to detect if the
//! directory has changed since a known epoch.

use crate::catalog::Catalog;
use crate::error::Result;
use crate::params::Params;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Directory format version tag.
pub const DIRECTORY_VERSION: u32 = 1;

/// A single entry in the public directory.
///
/// Contains the metadata needed for key→index resolution without the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
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

/// Summary of catalog parameters for directory consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryParams {
    /// Number of rows (slots) in the catalog.
    pub n_rows: usize,
    /// Fixed row width in bytes.
    pub row_bytes: usize,
    /// Ring modulus.
    pub modulus: u64,
}

impl From<&Params> for DirectoryParams {
    fn from(p: &Params) -> Self {
        Self {
            n_rows: p.n_rows,
            row_bytes: p.row_bytes,
            modulus: p.modulus,
        }
    }
}

impl From<Params> for DirectoryParams {
    fn from(p: Params) -> Self {
        Self::from(&p)
    }
}

/// A public directory listing catalog entries for key→index resolution.
///
/// # What is revealed
///
/// - All entry indices, keys, content hashes, and leaf hashes.
/// - The Merkle root.
/// - The catalog parameters (n_rows, row_bytes, modulus).
///
/// # What is NOT revealed
///
/// - The actual payload bytes (row contents).
/// - Which entry a client queries (with a real LWE query layer).
///
/// See module docs and `THREAT_MODEL.md` for privacy analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    /// Format version.
    pub version: u32,
    /// Summary of catalog parameters.
    pub params: DirectoryParams,
    /// SHA-256 Merkle root over all catalog slots (lowercase hex).
    pub merkle_root: String,
    /// Directory entries for occupied slots.
    pub entries: Vec<DirectoryEntry>,
}

/// Canonical representation of directory data for seal computation.
///
/// The seal is computed over this structure to ensure deterministic hashing
/// regardless of JSON formatting options.
#[derive(Debug, Clone, Serialize)]
struct SealInput<'a> {
    merkle_root: &'a str,
    entries: &'a [DirectoryEntry],
}

impl Directory {
    /// Build a directory from a catalog.
    ///
    /// Includes all occupied slots (index < `catalog.len()`) that have either:
    /// - A non-zero row, OR
    /// - An assigned key.
    ///
    /// This ensures meaningful entries are exported while excluding unused
    /// capacity slots. Empty rows at the end (beyond `next_free`) are never
    /// included.
    pub fn from_catalog(catalog: &Catalog) -> Self {
        let mut entries = Vec::new();

        for index in 0..catalog.len() {
            let row = catalog.get(index).expect("index within len");
            let key = catalog.get_key(index).expect("index within len");

            let is_nonzero = row.iter().any(|&b| b != 0);
            let has_key = key.is_some();

            if is_nonzero || has_key {
                entries.push(DirectoryEntry {
                    index,
                    key: key.map(String::from),
                    content_hash: Catalog::content_hash(row),
                    leaf_hash: hex::encode(Catalog::leaf_hash(row)),
                });
            }
        }

        Self {
            version: DIRECTORY_VERSION,
            params: DirectoryParams::from(catalog.params()),
            merkle_root: catalog.merkle_root_hex(),
            entries,
        }
    }

    /// Compute a seal (fingerprint) over the directory's canonical content.
    ///
    /// The seal is a blake3 hash of the canonical JSON representation of:
    /// - `merkle_root`
    /// - `entries` (in order, with all fields)
    ///
    /// A client can pin this seal to detect directory changes across epochs.
    /// The seal is stable for the same directory content regardless of JSON
    /// formatting differences (pretty vs compact).
    ///
    /// Returns the seal as a 32-byte array.
    pub fn seal(&self) -> [u8; 32] {
        let input = SealInput {
            merkle_root: &self.merkle_root,
            entries: &self.entries,
        };
        let canonical = serde_json::to_string(&input).expect("seal input is always serializable");
        *blake3::hash(canonical.as_bytes()).as_bytes()
    }

    /// Compute the seal as lowercase hex (64 chars).
    pub fn seal_hex(&self) -> String {
        hex::encode(self.seal())
    }

    /// Verify that this directory matches an expected seal.
    ///
    /// Returns `true` if the computed seal equals the expected seal.
    pub fn verify_seal(&self, expected_seal: &[u8; 32]) -> bool {
        self.seal() == *expected_seal
    }

    /// Verify that this directory matches an expected seal (hex).
    ///
    /// Returns `true` if the computed seal equals the expected seal.
    /// Returns `false` if the hex is invalid or doesn't match.
    pub fn verify_seal_hex(&self, expected_seal_hex: &str) -> bool {
        let Ok(bytes) = hex::decode(expected_seal_hex) else {
            return false;
        };
        if bytes.len() != 32 {
            return false;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        self.verify_seal(&arr)
    }

    /// Number of entries in the directory.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the directory has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by key.
    ///
    /// Returns `Some(&entry)` if a matching key exists, `None` otherwise.
    pub fn get_by_key(&self, key: &str) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| e.key.as_deref() == Some(key))
    }

    /// Look up an entry by content hash (blake3 hex).
    ///
    /// Returns `Some(&entry)` if a matching hash exists, `None` otherwise.
    pub fn get_by_hash(&self, hash: &str) -> Option<&DirectoryEntry> {
        let hash_lower = hash.to_lowercase();
        self.entries.iter().find(|e| e.content_hash == hash_lower)
    }

    /// Resolve a key to an index.
    ///
    /// Returns `Some(index)` if the key exists, `None` otherwise.
    pub fn resolve_key(&self, key: &str) -> Option<usize> {
        self.get_by_key(key).map(|e| e.index)
    }

    /// Resolve a content hash to an index.
    ///
    /// Returns `Some(index)` if the hash exists, `None` otherwise.
    pub fn resolve_hash(&self, hash: &str) -> Option<usize> {
        self.get_by_hash(hash).map(|e| e.index)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Save directory to a JSON file.
    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let text = self.to_json()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Load directory from a JSON file.
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_json(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Params;

    fn make_test_catalog() -> Catalog {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        cat.insert(Some("wire_transfer".into()), b"skill bytes")
            .unwrap();
        cat.insert(Some("calendar".into()), b"calendar sync")
            .unwrap();
        cat.insert(None, b"no-key payload").unwrap();
        cat
    }

    #[test]
    fn from_catalog_includes_occupied_slots() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);

        assert_eq!(dir.len(), 3);
        assert_eq!(dir.version, DIRECTORY_VERSION);
        assert_eq!(dir.merkle_root, cat.merkle_root_hex());

        assert!(dir.get_by_key("wire_transfer").is_some());
        assert!(dir.get_by_key("calendar").is_some());
        assert!(dir.get_by_key("nonexistent").is_none());
    }

    #[test]
    fn resolve_key_works() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);

        assert_eq!(dir.resolve_key("wire_transfer"), Some(0));
        assert_eq!(dir.resolve_key("calendar"), Some(1));
        assert_eq!(dir.resolve_key("missing"), None);
    }

    #[test]
    fn resolve_hash_works() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);

        let row0 = cat.get(0).unwrap();
        let hash0 = Catalog::content_hash(row0);
        assert_eq!(dir.resolve_hash(&hash0), Some(0));
        assert_eq!(dir.resolve_hash("0000000000000000000000000000000000000000000000000000000000000000"), None);
    }

    #[test]
    fn json_roundtrip() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);

        let json = dir.to_json().unwrap();
        let dir2 = Directory::from_json(&json).unwrap();
        assert_eq!(dir, dir2);
    }

    #[test]
    fn params_summary_matches_catalog() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);

        assert_eq!(dir.params.n_rows, cat.params().n_rows);
        assert_eq!(dir.params.row_bytes, cat.params().row_bytes);
        assert_eq!(dir.params.modulus, cat.params().modulus);
    }

    #[test]
    fn seal_is_stable() {
        let cat = make_test_catalog();
        let dir1 = Directory::from_catalog(&cat);
        let dir2 = Directory::from_catalog(&cat);

        assert_eq!(dir1.seal(), dir2.seal());
        assert_eq!(dir1.seal_hex(), dir2.seal_hex());
        assert_eq!(dir1.seal_hex().len(), 64);
    }

    #[test]
    fn seal_changes_with_content() {
        let params = Params::preset_tiny();
        let mut cat1 = Catalog::new(params).unwrap();
        cat1.insert(Some("skill_a".into()), b"payload a").unwrap();
        let dir1 = Directory::from_catalog(&cat1);

        let mut cat2 = Catalog::new(params).unwrap();
        cat2.insert(Some("skill_b".into()), b"payload b").unwrap();
        let dir2 = Directory::from_catalog(&cat2);

        assert_ne!(dir1.seal(), dir2.seal());
    }

    #[test]
    fn verify_seal_works() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);
        let seal = dir.seal();
        let seal_hex = dir.seal_hex();

        assert!(dir.verify_seal(&seal));
        assert!(dir.verify_seal_hex(&seal_hex));

        let wrong_seal = [0u8; 32];
        assert!(!dir.verify_seal(&wrong_seal));
        assert!(!dir.verify_seal_hex("invalid_hex"));
        assert!(!dir.verify_seal_hex(&hex::encode([0u8; 32])));
    }

    #[test]
    fn seal_survives_json_roundtrip() {
        let cat = make_test_catalog();
        let dir = Directory::from_catalog(&cat);
        let original_seal = dir.seal();

        let json = dir.to_json().unwrap();
        let dir2 = Directory::from_json(&json).unwrap();

        assert_eq!(dir2.seal(), original_seal);
        assert!(dir2.verify_seal(&original_seal));
    }
}
