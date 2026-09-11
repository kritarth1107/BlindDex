//! Thin client wrapper: build PIR queries and recover rows.

use crate::catalog::Catalog;
use crate::error::{BlindDexError, Result};
use crate::merkle::MerkleProof;
use crate::pir::{DatabaseMatrix, PirEngine};
use crate::server::BlindServer;

/// Maximum indices accepted by [`BlindClient::get_blind_batch`] in this toy slice.
pub const MAX_BATCH_SIZE: usize = 16;

/// Row recovered via toy PIR together with a verified Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenRow {
    /// Catalog index that was retrieved.
    pub index: usize,
    /// Fixed-width row bytes.
    pub row: Vec<u8>,
    /// Inclusion proof that verified against the server root.
    pub proof: MerkleProof,
}

/// Client that talks to a [`BlindServer`] (in-process for this slice).
#[derive(Debug, Clone)]
pub struct BlindClient {
    engine: PirEngine,
}

impl BlindClient {
    /// Construct from catalog params.
    pub fn new(catalog: &Catalog) -> Result<Self> {
        Ok(Self {
            engine: PirEngine::new(*catalog.params())?,
        })
    }

    /// Construct from an explicit engine.
    pub fn from_engine(engine: PirEngine) -> Self {
        Self { engine }
    }

    /// Blind retrieval by row index.
    ///
    /// The server learns neither the index nor the payload **when** the query
    /// is cryptographically protected. This toy slice sends an exact one-hot
    /// vector; see `pir` module docs.
    pub fn get_blind(&self, server: &BlindServer, index: usize) -> Result<Vec<u8>> {
        let query = self.engine.query_exact(index)?;
        let answer = server.answer(&query)?;
        self.engine.recover_row(&answer)
    }

    /// Blind retrieval that also fetches and verifies a Merkle inclusion proof.
    ///
    /// Returns the recovered row only if the proof opens to the server's
    /// published Merkle root and the leaf hash matches `SHA-256(row)`.
    pub fn get_blind_proven(&self, server: &BlindServer, index: usize) -> Result<ProvenRow> {
        let query = self.engine.query_exact(index)?;
        let (answer, proof) = server.answer_proven(&query, index)?;
        let row = self.engine.recover_row(&answer)?;
        let root = server.merkle_root();
        proof.verify(&root)?;
        let leaf = Catalog::leaf_hash(&row);
        if leaf != proof.leaf_hash {
            return Err(BlindDexError::ProofVerificationFailed {
                expected: hex::encode(proof.leaf_hash),
                got: hex::encode(leaf),
            });
        }
        if proof.index != index {
            return Err(BlindDexError::ProofVerificationFailed {
                expected: format!("index {index}"),
                got: format!("index {}", proof.index),
            });
        }
        Ok(ProvenRow { index, row, proof })
    }

    /// Batch blind retrieval for a small set of indices.
    ///
    /// # Honesty
    ///
    /// This slice issues **one independent matvec per index** (sequential
    /// `get_blind_proven` calls). It does **not** pack multiple queries into a
    /// single ciphertext or shared matrix multiply. A packed multi-query API
    /// is future work once a real LWE query layer exists.
    pub fn get_blind_batch(
        &self,
        server: &BlindServer,
        indices: &[usize],
    ) -> Result<Vec<ProvenRow>> {
        if indices.is_empty() || indices.len() > MAX_BATCH_SIZE {
            return Err(BlindDexError::InvalidBatchSize {
                got: indices.len(),
                max: MAX_BATCH_SIZE,
            });
        }
        let mut out = Vec::with_capacity(indices.len());
        for &index in indices {
            out.push(self.get_blind_proven(server, index)?);
        }
        Ok(out)
    }

    /// Resolve a content hash to an index via a local catalog view, then PIR.
    ///
    /// Hash→index resolution uses the client's committed catalog copy; the
    /// blind fetch still goes through PIR.
    pub fn get_blind_by_hash(
        &self,
        local: &Catalog,
        server: &BlindServer,
        hash: &str,
    ) -> Result<Vec<u8>> {
        let (index, _) = local.get_by_hash(hash)?;
        self.get_blind(server, index)
    }

    /// Local (non-network) retrieve against a matrix — used by tests.
    pub fn retrieve_local(&self, db: &DatabaseMatrix, index: usize) -> Result<Vec<u8>> {
        self.engine.retrieve(db, index)
    }

    /// Borrow the underlying PIR engine.
    pub fn engine(&self) -> &PirEngine {
        &self.engine
    }
}
