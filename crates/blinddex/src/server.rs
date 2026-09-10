//! Thin server wrapper: hold catalog matrix and answer PIR queries.

use crate::catalog::Catalog;
use crate::error::Result;
use crate::pir::DatabaseMatrix;

/// Server holding an encoded catalog. Sees query **size**, not (in the real
/// cryptographic setting) the index. This toy answers cleartext matvecs.
#[derive(Debug, Clone)]
pub struct BlindServer {
    matrix: DatabaseMatrix,
    merkle_root: [u8; 32],
}

impl BlindServer {
    /// Build server state from a catalog.
    pub fn from_catalog(catalog: &Catalog) -> Result<Self> {
        let matrix = DatabaseMatrix::from_rows(*catalog.params(), catalog.rows())?;
        Ok(Self {
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

    /// Borrow the encoded database matrix.
    pub fn matrix(&self) -> &DatabaseMatrix {
        &self.matrix
    }
}

/// Insert helper used by CLI `put` — mutates a catalog then can rebuild server.
pub fn put_entry(catalog: &mut Catalog, key: Option<String>, payload: &[u8]) -> Result<usize> {
    catalog.insert(key, payload)
}
