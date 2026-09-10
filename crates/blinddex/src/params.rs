//! Toy parameter set for BlindDex computational PIR.
//!
//! # Honest scope
//!
//! These are **demo** parameters, not production SimplePIR parameters.
//! - `n_rows` ≤ [`MAX_N_ROWS`] (4096) and must be a power of two.
//! - `row_bytes` ≤ [`MAX_ROW_BYTES`] (256).
//! - `modulus` defaults to `2^32` (`1 << 32`). With exact one-hot queries the
//!   modular reduction is irrelevant for correctness of the toy path; a real
//!   SimplePIR deployment would choose `q` to support LWE noise and packing.

use crate::error::{BlindDexError, Result};
use serde::{Deserialize, Serialize};

/// Hard cap on catalog height for this public slice.
pub const MAX_N_ROWS: usize = 4096;

/// Hard cap on fixed row width (bytes).
pub const MAX_ROW_BYTES: usize = 256;

/// Default catalog height (power of two).
pub const DEFAULT_N_ROWS: usize = 256;

/// Default fixed row width.
pub const DEFAULT_ROW_BYTES: usize = 64;

/// Default modulus `q = 2^32`. Documented as a toy ring; not an LWE-secure modulus.
pub const DEFAULT_MODULUS: u64 = 1u64 << 32;

/// PIR / catalog parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Number of rows (slots). Must be a power of two, ≤ [`MAX_N_ROWS`].
    pub n_rows: usize,
    /// Fixed width of each row in bytes, ≤ [`MAX_ROW_BYTES`].
    pub row_bytes: usize,
    /// Ring modulus `q`. Default `2^32`.
    pub modulus: u64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            n_rows: DEFAULT_N_ROWS,
            row_bytes: DEFAULT_ROW_BYTES,
            modulus: DEFAULT_MODULUS,
        }
    }
}

impl Params {
    /// Construct and validate parameters.
    pub fn new(n_rows: usize, row_bytes: usize, modulus: u64) -> Result<Self> {
        let p = Self {
            n_rows,
            row_bytes,
            modulus,
        };
        p.validate()?;
        Ok(p)
    }

    /// Validate toy bounds and power-of-two height.
    pub fn validate(&self) -> Result<()> {
        if self.n_rows == 0 || self.n_rows > MAX_N_ROWS || !self.n_rows.is_power_of_two() {
            return Err(BlindDexError::InvalidNRows {
                n: self.n_rows,
                max: MAX_N_ROWS,
            });
        }
        if self.row_bytes == 0 || self.row_bytes > MAX_ROW_BYTES {
            return Err(BlindDexError::InvalidRowBytes {
                got: self.row_bytes,
                max: MAX_ROW_BYTES,
            });
        }
        if self.modulus < 2 {
            return Err(BlindDexError::InvalidModulus { got: self.modulus });
        }
        Ok(())
    }

    /// Number of `u32` limbs needed to pack one row.
    pub fn limbs_per_row(&self) -> usize {
        self.row_bytes.div_ceil(4)
    }
}
