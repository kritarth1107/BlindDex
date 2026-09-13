//! Fixed-width opaque catalog with SHA-256 Merkle commitment.
//!
//! Rows are padded / truncated to `params.row_bytes`. Empty slots are all-zero
//! rows. The Merkle root commits to the leaf hashes `SHA-256(row_bytes)` for
//! every slot `0..n_rows` (including empty ones), so the commitment covers the
//! full capacity.

use crate::directory::Directory;
use crate::error::{BlindDexError, Result};
use crate::merkle::{prove_from_leaves, MerkleProof};
use crate::params::Params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// On-disk / JSON representation of a catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogFile {
    /// Catalog parameters.
    pub params: Params,
    /// Occupied slots.
    pub entries: Vec<CatalogFileEntry>,
}

/// One serialized slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogFileEntry {
    /// Slot index.
    pub index: usize,
    /// Optional human key (skill / tool name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Payload as UTF-8 string, or `hex:...` for binary.
    pub payload: String,
}

/// In-memory fixed-width catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    params: Params,
    /// Packed rows: length == `n_rows`, each exactly `row_bytes`.
    rows: Vec<Vec<u8>>,
    /// Optional keys per slot.
    keys: Vec<Option<String>>,
    /// Content-address map: blake3 hex → index.
    by_hash: HashMap<String, usize>,
    /// Key → index.
    by_key: HashMap<String, usize>,
    /// Next free slot for append-style insert.
    next_free: usize,
}

impl Catalog {
    /// Empty catalog with validated params (all rows zeroed).
    pub fn new(params: Params) -> Result<Self> {
        params.validate()?;
        let n = params.n_rows;
        let w = params.row_bytes;
        Ok(Self {
            params,
            rows: vec![vec![0u8; w]; n],
            keys: vec![None; n],
            by_hash: HashMap::new(),
            by_key: HashMap::new(),
            next_free: 0,
        })
    }

    /// Parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Number of occupied slots (highest insert watermark).
    pub fn len(&self) -> usize {
        self.next_free
    }

    /// True when no inserts have occurred.
    pub fn is_empty(&self) -> bool {
        self.next_free == 0
    }

    /// Pad or truncate payload to `row_bytes`.
    pub fn normalize_row(&self, payload: &[u8]) -> Vec<u8> {
        let w = self.params.row_bytes;
        let mut row = vec![0u8; w];
        let n = payload.len().min(w);
        row[..n].copy_from_slice(&payload[..n]);
        row
    }

    /// Blake3 content hash of a normalized row (hex).
    pub fn content_hash(row: &[u8]) -> String {
        let h = blake3::hash(row);
        hex::encode(h.as_bytes())
    }

    /// SHA-256 leaf hash of a row.
    pub fn leaf_hash(row: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(row);
        hasher.finalize().into()
    }

    /// Merkle root over all `n_rows` leaf hashes (pairwise SHA-256).
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = self.rows.iter().map(|r| Self::leaf_hash(r)).collect();
        debug_assert!(level.len().is_power_of_two());
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                next.push(hasher.finalize().into());
            }
            level = next;
        }
        level[0]
    }

    /// Merkle root as lowercase hex.
    pub fn merkle_root_hex(&self) -> String {
        hex::encode(self.merkle_root())
    }

    /// SHA-256 leaf hash at `index` (opens the committed leaf without the row).
    pub fn open_leaf_hash(&self, index: usize) -> Result<[u8; 32]> {
        let row = self.get(index)?;
        Ok(Self::leaf_hash(row))
    }

    /// Leaf hash at `index` as lowercase hex.
    pub fn open_leaf_hash_hex(&self, index: usize) -> Result<String> {
        Ok(hex::encode(self.open_leaf_hash(index)?))
    }

    /// Merkle inclusion proof for `index` against [`Self::merkle_root`].
    pub fn prove(&self, index: usize) -> Result<MerkleProof> {
        let leaves: Vec<[u8; 32]> = self.rows.iter().map(|r| Self::leaf_hash(r)).collect();
        prove_from_leaves(&leaves, index)
    }

    /// Insert at the next free index. Returns the index.
    pub fn insert(&mut self, key: Option<String>, payload: &[u8]) -> Result<usize> {
        if self.next_free >= self.params.n_rows {
            return Err(BlindDexError::CatalogTooLarge {
                got: self.next_free + 1,
                max: self.params.n_rows,
            });
        }
        let index = self.next_free;
        self.set_at(index, key, payload)?;
        // `set_at` advances `next_free` to index + 1 when needed.
        Ok(index)
    }

    /// Overwrite a specific index (used when loading from file).
    pub fn set_at(&mut self, index: usize, key: Option<String>, payload: &[u8]) -> Result<()> {
        if index >= self.params.n_rows {
            return Err(BlindDexError::IndexOutOfRange {
                index,
                n_rows: self.params.n_rows,
            });
        }
        if let Some(old_key) = self.keys[index].take() {
            self.by_key.remove(&old_key);
        }
        let was_nonzero = self.rows[index].iter().any(|&b| b != 0);
        if was_nonzero {
            let old_hash = Self::content_hash(&self.rows[index]);
            if self.by_hash.get(&old_hash) == Some(&index) {
                self.by_hash.remove(&old_hash);
            }
        }

        let row = self.normalize_row(payload);
        let hash = Self::content_hash(&row);
        self.rows[index] = row;
        if let Some(ref k) = key {
            self.by_key.insert(k.clone(), index);
        }
        self.keys[index] = key;
        self.by_hash.insert(hash, index);
        if index >= self.next_free {
            self.next_free = index + 1;
        }
        Ok(())
    }

    /// Get row by index (exact fixed-width bytes).
    pub fn get(&self, index: usize) -> Result<&[u8]> {
        self.rows
            .get(index)
            .map(Vec::as_slice)
            .ok_or(BlindDexError::IndexOutOfRange {
                index,
                n_rows: self.params.n_rows,
            })
    }

    /// Get optional key at index.
    pub fn get_key(&self, index: usize) -> Result<Option<&str>> {
        self.keys
            .get(index)
            .map(Option::as_deref)
            .ok_or(BlindDexError::IndexOutOfRange {
                index,
                n_rows: self.params.n_rows,
            })
    }

    /// Lookup by blake3 content hash (hex).
    pub fn get_by_hash(&self, hash: &str) -> Result<(usize, &[u8])> {
        let index = *self
            .by_hash
            .get(hash)
            .ok_or_else(|| BlindDexError::HashNotFound {
                hash: hash.to_string(),
            })?;
        Ok((index, &self.rows[index]))
    }

    /// Lookup by string key.
    pub fn get_by_key(&self, key: &str) -> Result<(usize, &[u8])> {
        let index = *self
            .by_key
            .get(key)
            .ok_or_else(|| BlindDexError::KeyNotFound {
                key: key.to_string(),
            })?;
        Ok((index, &self.rows[index]))
    }

    /// Borrow all packed rows (for PIR matrix encoding).
    pub fn rows(&self) -> &[Vec<u8>] {
        &self.rows
    }

    /// Build from params + file entries; rejects oversized entry lists.
    pub fn from_file_data(params: Params, entries: &[CatalogFileEntry]) -> Result<Self> {
        params.validate()?;
        if entries.len() > params.n_rows {
            return Err(BlindDexError::CatalogTooLarge {
                got: entries.len(),
                max: params.n_rows,
            });
        }
        let mut cat = Self::new(params)?;
        for e in entries {
            let payload = decode_payload_string(&e.payload);
            cat.set_at(e.index, e.key.clone(), &payload)?;
        }
        Ok(cat)
    }

    /// Load from JSON path.
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let file: CatalogFile = serde_json::from_str(&text)?;
        Self::from_file_data(file.params, &file.entries)
    }

    /// Serialize to [`CatalogFile`].
    pub fn to_file(&self) -> CatalogFile {
        let mut entries = Vec::new();
        for i in 0..self.next_free {
            let row = &self.rows[i];
            let payload = match std::str::from_utf8(row) {
                Ok(s) => s.trim_end_matches('\0').to_string(),
                Err(_) => format!("hex:{}", hex::encode(row)),
            };
            entries.push(CatalogFileEntry {
                index: i,
                key: self.keys[i].clone(),
                payload,
            });
        }
        CatalogFile {
            params: self.params,
            entries,
        }
    }

    /// Save JSON to path.
    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = self.to_file();
        let text = serde_json::to_string_pretty(&file)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Export a public directory for name→index resolution.
    ///
    /// The directory contains entry metadata (index, key, content_hash, leaf_hash)
    /// but NOT the actual payloads. A client downloads this directory, resolves
    /// a key or hash to an index locally, then issues a PIR query by index.
    ///
    /// See [`Directory`] and `THREAT_MODEL.md` for the privacy model.
    pub fn export_directory(&self) -> Directory {
        Directory::from_catalog(self)
    }
}

fn decode_payload_string(s: &str) -> Vec<u8> {
    if let Some(rest) = s.strip_prefix("hex:") {
        hex::decode(rest).unwrap_or_else(|_| s.as_bytes().to_vec())
    } else {
        s.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pads_and_truncates() {
        let cat = Catalog::new(Params::default()).unwrap();
        let short = cat.normalize_row(b"hi");
        assert_eq!(short.len(), 64);
        assert_eq!(&short[..2], b"hi");
        let long = cat.normalize_row(&[1u8; 200]);
        assert_eq!(long.len(), 64);
    }
}
