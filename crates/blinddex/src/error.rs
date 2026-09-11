//! Error types for BlindDex.

use thiserror::Error;

/// Errors returned by BlindDex catalog and PIR operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BlindDexError {
    /// Catalog exceeds the configured `n_rows` capacity.
    #[error("catalog too large: {got} rows, max {max}")]
    CatalogTooLarge {
        /// Observed size.
        got: usize,
        /// Configured maximum.
        max: usize,
    },

    /// `n_rows` must be a power of two within the toy bound.
    #[error("invalid n_rows={n}: must be a power of two and ≤ {max}")]
    InvalidNRows {
        /// Provided value.
        n: usize,
        /// Allowed maximum.
        max: usize,
    },

    /// Row width exceeds the toy bound.
    #[error("invalid row_bytes={got}: must be > 0 and ≤ {max}")]
    InvalidRowBytes {
        /// Provided value.
        got: usize,
        /// Allowed maximum.
        max: usize,
    },

    /// Modulus must be at least 2.
    #[error("invalid modulus={got}: must be ≥ 2")]
    InvalidModulus {
        /// Provided modulus.
        got: u64,
    },

    /// Requested index is out of range for the catalog capacity.
    #[error("index {index} out of range (n_rows={n_rows})")]
    IndexOutOfRange {
        /// Requested index.
        index: usize,
        /// Catalog height.
        n_rows: usize,
    },

    /// No row matches the given content hash.
    #[error("no entry with hash {hash}")]
    HashNotFound {
        /// Requested hash hex.
        hash: String,
    },

    /// Key not found in the catalog index.
    #[error("no entry with key {key}")]
    KeyNotFound {
        /// Requested key.
        key: String,
    },

    /// PIR query length does not match `n_rows`.
    #[error("query length {got} does not match n_rows={expected}")]
    BadQueryLength {
        /// Actual length.
        got: usize,
        /// Expected length.
        expected: usize,
    },

    /// Answer limb count does not match the expected row packing.
    #[error("answer length {got} does not match expected limbs={expected}")]
    BadAnswerLength {
        /// Actual length.
        got: usize,
        /// Expected limb count.
        expected: usize,
    },

    /// Merkle inclusion proof does not open to the expected root.
    #[error("merkle proof verification failed: expected root {expected}, got {got}")]
    ProofVerificationFailed {
        /// Expected root hex.
        expected: String,
        /// Recomputed root hex.
        got: String,
    },

    /// Batch request was empty or exceeded the toy batch cap.
    #[error("invalid batch size {got}: must be 1..={max}")]
    InvalidBatchSize {
        /// Requested batch length.
        got: usize,
        /// Allowed maximum.
        max: usize,
    },

    /// JSON (de)serialization failure.
    #[error("serde error: {0}")]
    Serde(String),

    /// I/O failure when loading or saving a catalog file.
    #[error("io error: {0}")]
    Io(String),
}

impl From<serde_json::Error> for BlindDexError {
    fn from(e: serde_json::Error) -> Self {
        BlindDexError::Serde(e.to_string())
    }
}

impl From<std::io::Error> for BlindDexError {
    fn from(e: std::io::Error) -> Self {
        BlindDexError::Io(e.to_string())
    }
}

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, BlindDexError>;
