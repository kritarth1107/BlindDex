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

    /// Tiny preset: 16 rows × 32 bytes (quick tests, minimal memory).
    ///
    /// # Honest scope
    ///
    /// These are **demo** parameters, not production LWE params.
    /// Do not use for real privacy applications.
    pub fn preset_tiny() -> Self {
        Self {
            n_rows: 16,
            row_bytes: 32,
            modulus: DEFAULT_MODULUS,
        }
    }

    /// Small preset: 64 rows × 64 bytes (good for examples/benches).
    ///
    /// # Honest scope
    ///
    /// These are **demo** parameters, not production LWE params.
    /// Do not use for real privacy applications.
    pub fn preset_small() -> Self {
        Self {
            n_rows: 64,
            row_bytes: 64,
            modulus: DEFAULT_MODULUS,
        }
    }

    /// Medium preset: 256 rows × 128 bytes (typical toy catalog).
    ///
    /// # Honest scope
    ///
    /// These are **demo** parameters, not production LWE params.
    /// Do not use for real privacy applications.
    pub fn preset_medium() -> Self {
        Self {
            n_rows: 256,
            row_bytes: 128,
            modulus: DEFAULT_MODULUS,
        }
    }

    /// Demo preset: matches `Default::default()` (256 rows × 64 bytes).
    ///
    /// Provided for API symmetry with other presets.
    ///
    /// # Honest scope
    ///
    /// These are **demo** parameters, not production LWE params.
    /// Do not use for real privacy applications.
    pub fn preset_demo() -> Self {
        Self::default()
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

    /// List all available preset names for CLI / docs.
    pub fn preset_names() -> &'static [&'static str] {
        &["tiny", "small", "medium", "demo"]
    }

    /// Get a preset by name (case-insensitive).
    pub fn from_preset_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "tiny" => Some(Self::preset_tiny()),
            "small" => Some(Self::preset_small()),
            "medium" => Some(Self::preset_medium()),
            "demo" => Some(Self::preset_demo()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_validate() {
        Params::preset_tiny().validate().unwrap();
        Params::preset_small().validate().unwrap();
        Params::preset_medium().validate().unwrap();
        Params::preset_demo().validate().unwrap();
    }

    #[test]
    fn preset_demo_matches_default() {
        assert_eq!(Params::preset_demo(), Params::default());
    }

    #[test]
    fn preset_names_roundtrip() {
        for name in Params::preset_names() {
            let p = Params::from_preset_name(name).unwrap();
            p.validate().unwrap();
        }
    }

    #[test]
    fn preset_sizes_are_correct() {
        let tiny = Params::preset_tiny();
        assert_eq!(tiny.n_rows, 16);
        assert_eq!(tiny.row_bytes, 32);

        let small = Params::preset_small();
        assert_eq!(small.n_rows, 64);
        assert_eq!(small.row_bytes, 64);

        let medium = Params::preset_medium();
        assert_eq!(medium.n_rows, 256);
        assert_eq!(medium.row_bytes, 128);
    }
}
