//! Merkle inclusion proofs over BlindDex catalog leaves.
//!
//! Leaves are `SHA-256(row_bytes)` for every slot `0..n_rows`. Interior nodes
//! are `SHA-256(left || right)` with the left child always the even-indexed
//! sibling (same layout as [`crate::catalog::Catalog::merkle_root`]).

use crate::error::{BlindDexError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sibling direction relative to the current node on the path to the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiblingSide {
    /// Sibling sits to the left of the current hash (`hash(sib || cur)`).
    Left,
    /// Sibling sits to the right of the current hash (`hash(cur || sib)`).
    Right,
}

/// One level of an inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// Sibling hash (32 bytes).
    #[serde(with = "hex_array32")]
    pub sibling: [u8; 32],
    /// Where the sibling sits relative to the running hash.
    pub side: SiblingSide,
}

/// Merkle inclusion proof for a single catalog index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Leaf index in `0..n_rows`.
    pub index: usize,
    /// `SHA-256` of the fixed-width row bytes at `index`.
    #[serde(with = "hex_array32")]
    pub leaf_hash: [u8; 32],
    /// Sibling path from the leaf toward the root (bottom → top).
    pub path: Vec<ProofStep>,
}

impl MerkleProof {
    /// Recompute the root implied by this proof.
    pub fn compute_root(&self) -> [u8; 32] {
        let mut cur = self.leaf_hash;
        for step in &self.path {
            let mut hasher = Sha256::new();
            match step.side {
                SiblingSide::Left => {
                    hasher.update(step.sibling);
                    hasher.update(cur);
                }
                SiblingSide::Right => {
                    hasher.update(cur);
                    hasher.update(step.sibling);
                }
            }
            cur = hasher.finalize().into();
        }
        cur
    }

    /// Verify that this proof opens to `expected_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> Result<()> {
        let got = self.compute_root();
        if &got == expected_root {
            Ok(())
        } else {
            Err(BlindDexError::ProofVerificationFailed {
                expected: hex::encode(expected_root),
                got: hex::encode(got),
            })
        }
    }

    /// Leaf hash as lowercase hex.
    pub fn leaf_hash_hex(&self) -> String {
        hex::encode(self.leaf_hash)
    }
}

/// Build an inclusion proof for `index` given the full leaf layer.
pub fn prove_from_leaves(leaves: &[[u8; 32]], index: usize) -> Result<MerkleProof> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(BlindDexError::InvalidNRows {
            n: leaves.len(),
            max: crate::params::MAX_N_ROWS,
        });
    }
    if index >= leaves.len() {
        return Err(BlindDexError::IndexOutOfRange {
            index,
            n_rows: leaves.len(),
        });
    }

    let leaf_hash = leaves[index];
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    let mut path = Vec::new();

    while level.len() > 1 {
        let sibling_idx = idx ^ 1;
        let side = if sibling_idx < idx {
            SiblingSide::Left
        } else {
            SiblingSide::Right
        };
        path.push(ProofStep {
            sibling: level[sibling_idx],
            side,
        });

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next.push(hasher.finalize().into());
        }
        level = next;
        idx /= 2;
    }

    Ok(MerkleProof {
        index,
        leaf_hash,
        path,
    })
}

mod hex_array32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn leaf(b: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([b]);
        h.finalize().into()
    }

    #[test]
    fn proof_verifies_against_manual_root() {
        let leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
        let proof = prove_from_leaves(&leaves, 2).unwrap();
        let mut l1_01 = Sha256::new();
        l1_01.update(leaves[0]);
        l1_01.update(leaves[1]);
        let n01: [u8; 32] = l1_01.finalize().into();
        let mut l1_23 = Sha256::new();
        l1_23.update(leaves[2]);
        l1_23.update(leaves[3]);
        let n23: [u8; 32] = l1_23.finalize().into();
        let mut root_h = Sha256::new();
        root_h.update(n01);
        root_h.update(n23);
        let root: [u8; 32] = root_h.finalize().into();
        proof.verify(&root).unwrap();
    }
}
