//! Offline hint scaffolding for SimplePIR-style precomputation.
//!
//! # Overview
//!
//! In SimplePIR, the client can precompute a "hint" from a public seed and
//! cached database parameters. This module provides a **toy scaffolding** for
//! that offline phase: a seeded PRNG expands a 32-byte seed into a reusable
//! blob the client can cache between queries.
//!
//! # Honest scope
//!
//! **This hint does NOT provide query privacy by itself.** The current BlindDex
//! slice still uses exact one-hot queries that reveal the index. The hint is
//! scaffolding toward a future LWE/SimplePIR layer where:
//!
//! 1. The server publishes `(seed, params)` for a database epoch.
//! 2. The client expands the seed into a hint matrix offline.
//! 3. Online queries use the precomputed hint to reduce round-trip latency.
//!
//! Until the LWE query layer is added, this module only demonstrates the API
//! shape and serialization format.
//!
//! # Wire format
//!
//! The hint is serializable via serde (JSON or binary) and includes:
//! - A version tag for forward compatibility.
//! - The 32-byte seed.
//! - A fingerprint of the params it was built for.
//! - Timestamp of generation.

use crate::error::{BlindDexError, Result};
use crate::params::Params;
use serde::{Deserialize, Serialize};

/// Hint format version.
pub const HINT_VERSION: u32 = 1;

/// Offline hint for SimplePIR-style precomputation (toy scaffolding).
///
/// # Honest scope
///
/// This hint is **not** a privacy boundary. It is scaffolding for a future
/// offline phase where the client caches expanded seed data between queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    /// Format version for forward compatibility.
    pub version: u32,
    /// 32-byte seed used to expand the hint.
    #[serde(with = "hex_array32")]
    pub seed: [u8; 32],
    /// Blake3 fingerprint of the params (for mismatch detection).
    #[serde(with = "hex_array32")]
    pub params_fingerprint: [u8; 32],
    /// Unix timestamp (seconds) when the hint was generated.
    pub created_at: u64,
    /// Number of u64 limbs in the expanded hint data.
    pub hint_len: usize,
    /// Expanded hint data (for demo purposes, just the seed expansion).
    ///
    /// In a real SimplePIR implementation, this would be the client's share of
    /// the offline matrix. Here it's a deterministic expansion for API shape.
    pub data: Vec<u64>,
}

impl Hint {
    /// Generate a hint from params and a seed.
    ///
    /// The hint expansion uses blake3 in counter mode to produce a
    /// deterministic stream from the seed.
    ///
    /// # Arguments
    ///
    /// * `params` - The PIR parameters this hint is built for.
    /// * `seed` - A 32-byte seed (use random bytes in production).
    ///
    /// # Honest scope
    ///
    /// This does **not** provide query privacy. It demonstrates the offline
    /// hint API shape for a future SimplePIR layer.
    pub fn generate(params: &Params, seed: [u8; 32]) -> Result<Self> {
        params.validate()?;

        let params_fingerprint = Self::compute_params_fingerprint(params);
        let hint_len = params.n_rows * params.limbs_per_row();
        let data = expand_seed(&seed, hint_len);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            version: HINT_VERSION,
            seed,
            params_fingerprint,
            created_at,
            hint_len,
            data,
        })
    }

    /// Compute a fingerprint of the params for mismatch detection.
    pub fn compute_params_fingerprint(params: &Params) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&params.n_rows.to_le_bytes());
        hasher.update(&params.row_bytes.to_le_bytes());
        hasher.update(&params.modulus.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check that this hint matches the given params.
    pub fn matches_params(&self, params: &Params) -> bool {
        self.params_fingerprint == Self::compute_params_fingerprint(params)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize to bytes (JSON for now; could be binary later).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BlindDexError::Serde(e.to_string()))
    }

    /// Seed as lowercase hex.
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed)
    }

    /// Params fingerprint as lowercase hex.
    pub fn params_fingerprint_hex(&self) -> String {
        hex::encode(self.params_fingerprint)
    }
}

/// Expand a seed into `len` u64 values using blake3 counter mode.
fn expand_seed(seed: &[u8; 32], len: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;

    while out.len() < len {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();

        for chunk in bytes.chunks(8) {
            if out.len() >= len {
                break;
            }
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            out.push(u64::from_le_bytes(arr));
        }
        counter += 1;
    }

    out
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

    #[test]
    fn hint_generate_and_roundtrip() {
        let params = Params::preset_small();
        let seed = [42u8; 32];
        let hint = Hint::generate(&params, seed).unwrap();

        assert_eq!(hint.version, HINT_VERSION);
        assert_eq!(hint.seed, seed);
        assert!(hint.matches_params(&params));
        assert_eq!(hint.hint_len, params.n_rows * params.limbs_per_row());
        assert_eq!(hint.data.len(), hint.hint_len);
    }

    #[test]
    fn hint_json_roundtrip() {
        let params = Params::preset_tiny();
        let seed = [1u8; 32];
        let hint = Hint::generate(&params, seed).unwrap();

        let json = hint.to_json().unwrap();
        let hint2 = Hint::from_json(&json).unwrap();
        assert_eq!(hint, hint2);
    }

    #[test]
    fn hint_bytes_roundtrip() {
        let params = Params::preset_tiny();
        let seed = [99u8; 32];
        let hint = Hint::generate(&params, seed).unwrap();

        let bytes = hint.to_bytes().unwrap();
        let hint2 = Hint::from_bytes(&bytes).unwrap();
        assert_eq!(hint, hint2);
    }

    #[test]
    fn hint_params_mismatch() {
        let params1 = Params::preset_tiny();
        let params2 = Params::preset_small();
        let seed = [7u8; 32];

        let hint = Hint::generate(&params1, seed).unwrap();
        assert!(hint.matches_params(&params1));
        assert!(!hint.matches_params(&params2));
    }

    #[test]
    fn expand_seed_deterministic() {
        let seed = [123u8; 32];
        let a = expand_seed(&seed, 100);
        let b = expand_seed(&seed, 100);
        assert_eq!(a, b);

        let c = expand_seed(&seed, 50);
        assert_eq!(&a[..50], &c[..]);
    }
}
