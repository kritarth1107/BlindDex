//! Thin server wrapper: hold catalog matrix and answer PIR queries.
//!
//! # Epoch binding
//!
//! The server can enforce epoch binding by checking incoming queries' epoch
//! fields against its current state. Use [`BlindServer::verify_query_epoch`]
//! to reject queries targeting a different catalog epoch.
//!
//! # Query receipts and replay protection (v0.6)
//!
//! The server can track recent nonces to detect replay attacks. Enable with
//! [`BlindServer::with_replay_protection`]. When enabled, the server rejects
//! queries with previously seen nonces.
//!
//! **Honest limitation**: The replay window is demo-only, not distributed,
//! and not authenticated. See `THREAT_MODEL.md`.
//!
//! # Query budget (v0.7)
//!
//! The server can enforce a per-epoch query budget using a token bucket. Enable
//! with [`BlindServer::with_query_budget`]. When enabled, each query consumes
//! one token; queries are rejected when the budget is exhausted.
//!
//! **Honest limitation**: The budget is demo fairness/anti-spam only, not
//! authentication. See `THREAT_MODEL.md`.

use crate::budget::QueryBudget;
use crate::catalog::Catalog;
use crate::directory::Directory;
use crate::error::Result;
use crate::merkle::MerkleProof;
use crate::pir::DatabaseMatrix;
use crate::receipt::ReplayWindow;
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
///
/// # Replay protection (v0.6)
///
/// Optionally tracks recent nonces to reject duplicate queries. Enable with
/// [`Self::with_replay_protection`]. This is demo anti-replay only:
/// - Not distributed (multiple servers don't share state)
/// - Not authenticated (a MITM could strip nonces)
/// - Memory-bounded (old nonces are evicted)
///
/// # Query budget (v0.7)
///
/// Optionally enforces a per-epoch query budget. Enable with
/// [`Self::with_query_budget`]. Each query consumes one token; excess queries
/// are rejected with [`BlindDexError::BudgetExceeded`]. This is demo
/// fairness/anti-spam only:
/// - Not authenticated (no per-client tracking)
/// - Not persistent (state lost on restart)
/// - Per-epoch (different epochs have independent budgets)
#[derive(Debug, Clone)]
pub struct BlindServer {
    catalog: Catalog,
    matrix: DatabaseMatrix,
    merkle_root: [u8; 32],
    directory_seal: [u8; 32],
    replay_window: Option<ReplayWindow>,
    padding_target: Option<usize>,
    query_budget: Option<QueryBudget>,
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
            replay_window: None,
            padding_target: None,
            query_budget: None,
        })
    }

    /// Enable replay protection with the specified window capacity.
    ///
    /// When enabled, the server tracks recent nonces and rejects duplicates.
    /// This is demo anti-replay only — see module docs.
    pub fn with_replay_protection(mut self, capacity: usize) -> Self {
        self.replay_window = Some(ReplayWindow::new(capacity));
        self
    }

    /// Enable replay protection with the default window size (256 nonces).
    pub fn with_default_replay_protection(self) -> Self {
        self.with_replay_protection(crate::receipt::DEFAULT_REPLAY_WINDOW_SIZE)
    }

    /// Enable answer padding to a fixed size.
    ///
    /// When set, all `answer_wire` and `answer_wire_proven` responses include
    /// padding to reach `total_bytes` in the padded answer field.
    ///
    /// This hides payload length variation but does NOT hide JSON structure,
    /// query patterns, or provide real privacy. See `THREAT_MODEL.md`.
    pub fn with_answer_padding(mut self, total_bytes: usize) -> Self {
        self.padding_target = Some(total_bytes);
        self
    }

    /// Check if replay protection is enabled.
    pub fn has_replay_protection(&self) -> bool {
        self.replay_window.is_some()
    }

    /// Check if answer padding is enabled.
    pub fn has_answer_padding(&self) -> bool {
        self.padding_target.is_some()
    }

    /// Get the configured padding target (if any).
    pub fn padding_target(&self) -> Option<usize> {
        self.padding_target
    }

    /// Enable query budget with the specified capacity per epoch.
    ///
    /// When enabled, each query consumes one token from the epoch's budget.
    /// Queries are rejected with [`BlindDexError::BudgetExceeded`] when
    /// tokens are exhausted.
    ///
    /// The epoch key is the merkle root hex. Different catalog epochs have
    /// independent budgets.
    ///
    /// This is demo fairness/anti-spam only — see module docs.
    pub fn with_query_budget(mut self, capacity: usize) -> Self {
        self.query_budget = Some(QueryBudget::new(capacity));
        self
    }

    /// Check if query budget is enabled.
    pub fn has_query_budget(&self) -> bool {
        self.query_budget.is_some()
    }

    /// Get the configured budget capacity (if any).
    pub fn budget_capacity(&self) -> Option<usize> {
        self.query_budget.as_ref().map(|b| b.capacity())
    }

    /// Get remaining budget for the current epoch.
    ///
    /// Returns `None` if budget is not enabled.
    pub fn budget_remaining(&self) -> Option<usize> {
        self.query_budget
            .as_ref()
            .map(|b| b.remaining(&self.merkle_root_hex()))
    }

    /// Access the query budget (if enabled).
    pub fn query_budget(&self) -> Option<&QueryBudget> {
        self.query_budget.as_ref()
    }

    /// Access the replay window (if enabled).
    pub fn replay_window(&self) -> Option<&ReplayWindow> {
        self.replay_window.as_ref()
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
    ///
    /// If replay protection is enabled, checks the nonce against the replay
    /// window and rejects duplicates. If padding is enabled, adds padding to
    /// the answer. If query budget is enabled, consumes one token and includes
    /// remaining budget in the answer.
    pub fn answer_wire(&self, query: &WireQuery) -> Result<crate::wire::WireAnswer> {
        self.verify_query_epoch(query)?;

        if let Some(ref window) = self.replay_window {
            if let Some(ref nonce) = query.client_nonce {
                window.check_and_record(nonce)?;
            }
        }

        let epoch_key = self.merkle_root_hex();
        if let Some(ref budget) = self.query_budget {
            budget.try_consume_one(&epoch_key)?;
        }

        let answer = self.answer(&query.query)?;
        let mut wire_answer = crate::wire::WireAnswer::new(answer)
            .with_epoch(&self.directory_seal_hex(), &epoch_key)
            .echo_nonce_from(query);

        if let Some(ref budget) = self.query_budget {
            wire_answer = wire_answer.with_budget_status(budget.remaining(&epoch_key), &epoch_key);
        }

        if let Some(target) = self.padding_target {
            wire_answer = wire_answer.with_padding(target)?;
        }

        Ok(wire_answer)
    }

    /// Answer a wire query with epoch verification and Merkle proof.
    ///
    /// This combines epoch verification, PIR answer, and proof generation.
    ///
    /// If replay protection is enabled, checks the nonce against the replay
    /// window and rejects duplicates. If padding is enabled, adds padding to
    /// the answer. If query budget is enabled, consumes one token and includes
    /// remaining budget in the answer.
    pub fn answer_wire_proven(
        &self,
        query: &WireQuery,
        index: usize,
    ) -> Result<(crate::wire::WireAnswer, MerkleProof)> {
        self.verify_query_epoch(query)?;

        if let Some(ref window) = self.replay_window {
            if let Some(ref nonce) = query.client_nonce {
                window.check_and_record(nonce)?;
            }
        }

        let epoch_key = self.merkle_root_hex();
        if let Some(ref budget) = self.query_budget {
            budget.try_consume_one(&epoch_key)?;
        }

        let (answer, proof) = self.answer_proven(&query.query, index)?;
        let mut wire_answer = crate::wire::WireAnswer::new(answer)
            .with_epoch(&self.directory_seal_hex(), &epoch_key)
            .echo_nonce_from(query);

        if let Some(ref budget) = self.query_budget {
            wire_answer = wire_answer.with_budget_status(budget.remaining(&epoch_key), &epoch_key);
        }

        if let Some(target) = self.padding_target {
            wire_answer = wire_answer.with_padding(target)?;
        }

        Ok((wire_answer, proof))
    }
}

/// Insert helper used by CLI `put` — mutates a catalog then can rebuild server.
pub fn put_entry(catalog: &mut Catalog, key: Option<String>, payload: &[u8]) -> Result<usize> {
    catalog.insert(key, payload)
}
