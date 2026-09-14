//! Thin server wrapper: hold catalog matrix and answer PIR queries.
//!
//! # Epoch binding
//!
//! The server can enforce epoch binding by checking incoming queries' epoch
//! fields against its current state. Use [`BlindServer::verify_query_epoch`]
//! to reject queries targeting a different catalog epoch.

use crate::catalog::Catalog;
use crate::directory::Directory;
use crate::error::Result;
use crate::merkle::MerkleProof;
use crate::pir::DatabaseMatrix;
use crate::sync::SyncOffer;
use crate::wire::WireQuery;

/// Server holding an encoded catalog. Sees query **size**, not (in the real
/// cryptographic setting) the index. This toy answers cleartext matvecs.
///
/// # Epoch binding
///
/// The server tracks its catalog epoch (merkle root + directory seal) and
/// can verify incoming queries target the current epoch. Call
/// [`Self::verify_query_epoch`] before answering to reject stale queries.
#[derive(Debug, Clone)]
pub struct BlindServer {
    catalog: Catalog,
    matrix: DatabaseMatrix,
    merkle_root: [u8; 32],
    directory_seal: [u8; 32],
}

impl BlindServer {
    /// Build server state from a catalog.
    ///
    /// Computes and caches the merkle root and directory seal for epoch binding.
    pub fn from_catalog(catalog: &Catalog) -> Result<Self> {
        let matrix = DatabaseMatrix::from_rows(*catalog.params(), catalog.rows())?;
        let directory = catalog.export_directory();
        Ok(Self {
            catalog: catalog.clone(),
            matrix,
            merkle_root: catalog.merkle_root(),
            directory_seal: directory.seal(),
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

    /// Directory seal as bytes.
    pub fn directory_seal(&self) -> [u8; 32] {
        self.directory_seal
    }

    /// Directory seal as lowercase hex.
    pub fn directory_seal_hex(&self) -> String {
        hex::encode(self.directory_seal)
    }

    /// Export the public directory.
    pub fn export_directory(&self) -> Directory {
        self.catalog.export_directory()
    }

    /// Build a sync offer for this server's current epoch.
    pub fn sync_offer(&self) -> SyncOffer {
        SyncOffer::from_catalog(&self.catalog)
    }

    /// Verify that a wire query's epoch fields match this server's state.
    ///
    /// Returns `Ok(())` if the query has no epoch fields or they match.
    /// Returns [`BlindDexError::EpochMismatch`] if any field doesn't match.
    ///
    /// # Usage
    ///
    /// Call this before [`Self::answer`] to reject queries targeting a
    /// different catalog epoch:
    ///
    /// ```ignore
    /// server.verify_query_epoch(&wire_query)?;
    /// let answer = server.answer(&wire_query.query)?;
    /// ```
    pub fn verify_query_epoch(&self, query: &WireQuery) -> Result<()> {
        query.verify_epoch(&self.directory_seal_hex(), &self.merkle_root_hex())
    }

    /// Answer a wire query with epoch verification.
    ///
    /// First verifies epoch fields (if present), then computes the answer.
    /// The answer includes the server's epoch fields so the client can verify.
    pub fn answer_wire(&self, query: &WireQuery) -> Result<crate::wire::WireAnswer> {
        self.verify_query_epoch(query)?;
        let answer = self.answer(&query.query)?;
        Ok(crate::wire::WireAnswer::new(answer)
            .with_epoch(&self.directory_seal_hex(), &self.merkle_root_hex()))
    }

    /// Answer a wire query with epoch verification and Merkle proof.
    ///
    /// This combines epoch verification, PIR answer, and proof generation.
    pub fn answer_wire_proven(
        &self,
        query: &WireQuery,
        index: usize,
    ) -> Result<(crate::wire::WireAnswer, MerkleProof)> {
        self.verify_query_epoch(query)?;
        let (answer, proof) = self.answer_proven(&query.query, index)?;
        let wire_answer = crate::wire::WireAnswer::new(answer)
            .with_epoch(&self.directory_seal_hex(), &self.merkle_root_hex());
        Ok((wire_answer, proof))
    }
}

/// Insert helper used by CLI `put` — mutates a catalog then can rebuild server.
pub fn put_entry(catalog: &mut Catalog, key: Option<String>, payload: &[u8]) -> Result<usize> {
    catalog.insert(key, payload)
}
