//! Thin server wrapper: hold catalog matrix and answer PIR queries.

use crate::catalog::Catalog;
use crate::error::Result;
use crate::merkle::MerkleProof;
use crate::pir::DatabaseMatrix;

/// Server holding an encoded catalog. Sees query **size**, not (in the real
/// cryptographic setting) the index. This toy answers cleartext matvecs.
#[derive(Debug, Clone)]
pub struct BlindServer {
    catalog: Catalog,
    matrix: DatabaseMatrix,
    merkle_root: [u8; 32],
}

impl BlindServer {
    /// Build server state from a catalog.
    pub fn from_catalog(catalog: &Catalog) -> Result<Self> {
        let matrix = DatabaseMatrix::from_rows(*catalog.params(), catalog.rows())?;
        Ok(Self {
            catalog: catalog.clone(),
            matrix,
            merkle_root: catalog.merkle_root(),
        })
    }

    /// Published Merkle commitment over the catalog rows.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    /// Merkle root as lowercase hex.
    pub fn merkle_root_hex(&self) -> String {
        hex::encode(self.merkle_root)
    }

    /// Answer a PIR query (matvec). Query length must equal `n_rows`.
    pub fn answer(&self, query: &[u64]) -> Result<Vec<u64>> {
        self.matrix.matvec(query)
    }

    /// Inclusion proof for `index` (server-side open of the committed leaf).
    pub fn prove(&self, index: usize) -> Result<MerkleProof> {
        self.catalog.prove(index)
    }

    /// Answer a PIR query and attach a Merkle inclusion proof for `index`.
    ///
    /// The index is still visible in the cleartext toy query; the proof only
    /// authenticates the recovered row against the published root.
    pub fn answer_proven(&self, query: &[u64], index: usize) -> Result<(Vec<u64>, MerkleProof)> {
        let answer = self.answer(query)?;
        let proof = self.prove(index)?;
        Ok((answer, proof))
    }

    /// Borrow the encoded database matrix.
    pub fn matrix(&self) -> &DatabaseMatrix {
        &self.matrix
    }

    /// Borrow the held catalog (for proofs / local inspection).
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
}

/// Insert helper used by CLI `put` — mutates a catalog then can rebuild server.
pub fn put_entry(catalog: &mut Catalog, key: Option<String>, payload: &[u8]) -> Result<usize> {
    catalog.insert(key, payload)
}
