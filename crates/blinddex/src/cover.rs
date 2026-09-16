//! Cover traffic / decoy query helpers.
//!
//! This module provides scaffolding for **cover traffic** — a set of decoy
//! queries issued alongside a real query to dilute which of several matvecs
//! is the actual retrieval.
//!
//! # Honest non-claims
//!
//! - Cover traffic does **NOT** hide that queries happened; the server (and
//!   observers) see that multiple queries occurred.
//! - Cover traffic only dilutes **which** of the queries in a batch is the
//!   real one, assuming the observer cannot distinguish real from decoy.
//! - On the toy one-hot query path, the server sees the exact indices in each
//!   query. Cover traffic does NOT provide real PIR privacy without an LWE
//!   query layer.
//! - Decoy selection is deterministic from the seed for reproducibility.
//!
//! # Intended use
//!
//! Cover traffic is useful for:
//! - Demonstrating the API shape for batched / cover queries.
//! - Testing infrastructure that handles multiple concurrent queries.
//! - Future integration with LWE queries where decoys provide real privacy.
//!
//! For production privacy, combine with LWE queries and proper traffic shaping.

use crate::client::{BlindClient, ProvenRow, MAX_BATCH_SIZE};
use crate::error::{BlindDexError, Result};
use crate::server::BlindServer;

/// Maximum number of decoy queries supported.
pub const MAX_DECOYS: usize = MAX_BATCH_SIZE - 1;

/// A plan for issuing cover traffic alongside a real query.
///
/// Given a real index, decoy count, and seed, this produces a deterministic
/// set of distinct indices (including the real one) to query. The real index
/// is placed at a seeded position in the list.
///
/// # Example
///
/// ```
/// use blinddex::cover::CoverPlan;
///
/// let plan = CoverPlan::new(42, 4, 256, [1u8; 32]).unwrap();
/// assert_eq!(plan.indices().len(), 5); // 1 real + 4 decoys
/// assert!(plan.indices().contains(&42));
/// assert_eq!(plan.real_position(), plan.indices().iter().position(|&i| i == 42).unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverPlan {
    indices: Vec<usize>,
    real_index: usize,
    real_position: usize,
    seed: [u8; 32],
}

impl CoverPlan {
    /// Create a new cover plan.
    ///
    /// # Arguments
    ///
    /// * `real_index` - The index of the row to actually retrieve.
    /// * `decoy_count` - Number of decoy indices to add (0 to MAX_DECOYS).
    /// * `n_rows` - Total number of rows in the catalog.
    /// * `seed` - 32-byte seed for deterministic decoy selection.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `real_index >= n_rows`
    /// - `decoy_count > MAX_DECOYS`
    /// - `decoy_count >= n_rows` (not enough distinct indices available)
    pub fn new(
        real_index: usize,
        decoy_count: usize,
        n_rows: usize,
        seed: [u8; 32],
    ) -> Result<Self> {
        if real_index >= n_rows {
            return Err(BlindDexError::IndexOutOfRange {
                index: real_index,
                n_rows,
            });
        }
        if decoy_count > MAX_DECOYS {
            return Err(BlindDexError::InvalidBatchSize {
                got: decoy_count + 1,
                max: MAX_BATCH_SIZE,
            });
        }
        if decoy_count >= n_rows {
            return Err(BlindDexError::InvalidBatchSize {
                got: decoy_count + 1,
                max: n_rows,
            });
        }

        let decoys = Self::pick_decoys(real_index, decoy_count, n_rows, &seed);
        let real_position = Self::pick_position(decoy_count + 1, &seed);

        let mut indices = Vec::with_capacity(decoy_count + 1);
        let mut decoy_iter = decoys.into_iter();
        for i in 0..(decoy_count + 1) {
            if i == real_position {
                indices.push(real_index);
            } else {
                indices.push(decoy_iter.next().unwrap());
            }
        }

        Ok(Self {
            indices,
            real_index,
            real_position,
            seed,
        })
    }

    /// Pick distinct decoy indices (excluding real_index).
    fn pick_decoys(real_index: usize, count: usize, n_rows: usize, seed: &[u8; 32]) -> Vec<usize> {
        let mut decoys = Vec::with_capacity(count);
        let mut counter = 0u64;

        while decoys.len() < count {
            let mut hasher = blake3::Hasher::new_keyed(seed);
            hasher.update(b"decoy");
            hasher.update(&counter.to_le_bytes());
            let hash = hasher.finalize();
            let bytes = hash.as_bytes();

            for chunk in bytes.chunks(8) {
                if decoys.len() >= count {
                    break;
                }
                let mut arr = [0u8; 8];
                arr[..chunk.len()].copy_from_slice(chunk);
                let candidate = (u64::from_le_bytes(arr) as usize) % n_rows;

                if candidate != real_index && !decoys.contains(&candidate) {
                    decoys.push(candidate);
                }
            }
            counter += 1;
        }

        decoys.sort_unstable();
        decoys
    }

    /// Pick the position for the real index in the shuffled list.
    fn pick_position(total: usize, seed: &[u8; 32]) -> usize {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(b"position");
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[..8]);
        (u64::from_le_bytes(arr) as usize) % total
    }

    /// The ordered list of indices to query (decoys + real).
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    /// The index of the real row.
    pub fn real_index(&self) -> usize {
        self.real_index
    }

    /// The position of the real index in `indices()`.
    pub fn real_position(&self) -> usize {
        self.real_position
    }

    /// The seed used for deterministic selection.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Number of decoy queries.
    pub fn decoy_count(&self) -> usize {
        self.indices.len() - 1
    }

    /// Total number of queries (real + decoys).
    pub fn total_queries(&self) -> usize {
        self.indices.len()
    }
}

/// Execute a cover plan and retrieve only the real row.
///
/// This issues independent matvec queries for all indices in the plan,
/// then returns only the recovered real row.
///
/// # Arguments
///
/// * `client` - The BlindClient to use for queries.
/// * `server` - The BlindServer to query.
/// * `plan` - The cover plan specifying indices.
///
/// # Honest note
///
/// On the toy one-hot path, the server sees all query indices. Cover traffic
/// dilutes which query was "real" only from an observer's perspective who
/// cannot inspect query content.
pub fn execute_cover_plan(
    client: &BlindClient,
    server: &BlindServer,
    plan: &CoverPlan,
) -> Result<Vec<u8>> {
    let results = execute_cover_plan_all(client, server, plan)?;
    Ok(results[plan.real_position()].row.clone())
}

/// Execute a cover plan and retrieve all rows (for testing / inspection).
///
/// Returns all retrieved rows in the same order as `plan.indices()`.
pub fn execute_cover_plan_all(
    client: &BlindClient,
    server: &BlindServer,
    plan: &CoverPlan,
) -> Result<Vec<ProvenRow>> {
    client.get_blind_batch(server, plan.indices())
}

/// Execute a cover plan returning only the real proven row.
pub fn execute_cover_plan_proven(
    client: &BlindClient,
    server: &BlindServer,
    plan: &CoverPlan,
) -> Result<ProvenRow> {
    let results = execute_cover_plan_all(client, server, plan)?;
    Ok(results[plan.real_position()].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Catalog, Params};

    #[test]
    fn cover_plan_basic() {
        let plan = CoverPlan::new(5, 3, 256, [1u8; 32]).unwrap();
        assert_eq!(plan.total_queries(), 4);
        assert_eq!(plan.decoy_count(), 3);
        assert!(plan.indices().contains(&5));
        assert_eq!(plan.indices()[plan.real_position()], 5);
    }

    #[test]
    fn cover_plan_distinct_indices() {
        let plan = CoverPlan::new(10, 8, 256, [2u8; 32]).unwrap();
        let mut sorted = plan.indices().to_vec();
        sorted.sort();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted.len(), deduped.len(), "indices should be distinct");
    }

    #[test]
    fn cover_plan_deterministic() {
        let seed = [42u8; 32];
        let plan1 = CoverPlan::new(7, 5, 100, seed).unwrap();
        let plan2 = CoverPlan::new(7, 5, 100, seed).unwrap();
        assert_eq!(plan1.indices(), plan2.indices());
        assert_eq!(plan1.real_position(), plan2.real_position());
    }

    #[test]
    fn cover_plan_different_seeds() {
        let plan1 = CoverPlan::new(7, 5, 100, [1u8; 32]).unwrap();
        let plan2 = CoverPlan::new(7, 5, 100, [2u8; 32]).unwrap();
        assert_ne!(plan1.indices(), plan2.indices());
    }

    #[test]
    fn cover_plan_real_index_out_of_range() {
        let result = CoverPlan::new(256, 3, 256, [1u8; 32]);
        assert!(matches!(result, Err(BlindDexError::IndexOutOfRange { .. })));
    }

    #[test]
    fn cover_plan_too_many_decoys() {
        let result = CoverPlan::new(0, MAX_DECOYS + 1, 256, [1u8; 32]);
        assert!(matches!(
            result,
            Err(BlindDexError::InvalidBatchSize { .. })
        ));
    }

    #[test]
    fn cover_plan_not_enough_rows() {
        let result = CoverPlan::new(0, 5, 4, [1u8; 32]);
        assert!(matches!(
            result,
            Err(BlindDexError::InvalidBatchSize { .. })
        ));
    }

    #[test]
    fn cover_plan_zero_decoys() {
        let plan = CoverPlan::new(5, 0, 256, [1u8; 32]).unwrap();
        assert_eq!(plan.total_queries(), 1);
        assert_eq!(plan.indices(), &[5]);
        assert_eq!(plan.real_position(), 0);
    }

    #[test]
    fn execute_cover_plan_roundtrip() {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        for i in 0..8 {
            cat.insert(
                Some(format!("key{}", i)),
                format!("payload {}", i).as_bytes(),
            )
            .unwrap();
        }

        let server = BlindServer::from_catalog(&cat).unwrap();
        let client = BlindClient::new(&cat).unwrap();

        let real_index = 3;
        let plan = CoverPlan::new(real_index, 4, params.n_rows, [99u8; 32]).unwrap();

        let row = execute_cover_plan(&client, &server, &plan).unwrap();
        let text = String::from_utf8_lossy(&row);
        let trimmed = text.trim_end_matches('\0');
        assert_eq!(trimmed, "payload 3");
    }

    #[test]
    fn execute_cover_plan_all_roundtrip() {
        let params = Params::preset_tiny();
        let mut cat = Catalog::new(params).unwrap();
        for i in 0..8 {
            cat.insert(Some(format!("key{}", i)), format!("row{}", i).as_bytes())
                .unwrap();
        }

        let server = BlindServer::from_catalog(&cat).unwrap();
        let client = BlindClient::new(&cat).unwrap();

        let plan = CoverPlan::new(2, 3, params.n_rows, [77u8; 32]).unwrap();
        let results = execute_cover_plan_all(&client, &server, &plan).unwrap();

        assert_eq!(results.len(), plan.total_queries());
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.index, plan.indices()[i]);
        }

        let real = &results[plan.real_position()];
        let text = String::from_utf8_lossy(&real.row);
        assert!(text.starts_with("row2"));
    }
}
