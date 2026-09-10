//! SimplePIR-style matrix–vector PIR (toy, exact recovery).
//!
//! # Model
//!
//! The database is encoded as a matrix `Db` over `Z_q` whose rows are the
//! packed limbs of each catalog row. A query is a column vector `q` of length
//! `n_rows`. The server returns the matvec `a = Dbᵀ · q` wait — we treat `Db`
//! as `n_rows × L` (row-major) and compute
//!
//! ```text
//! answer[ℓ] = Σ_i  Db[i][ℓ] * q[i]   (mod q)
//! ```
//!
//! so `answer` reconstructs row `i*` when `q = e_{i*}` (the standard basis).
//!
//! # Toy vs production
//!
//! This public slice uses an **exact one-hot** query (`q[i*] = 1`, else `0`)
//! so demos always recover the row with no decoding failure. Real SimplePIR
//! encrypts `q` under LWE, adds noise, and packs multiple database rows into
//! ciphertext coefficients. Do **not** treat this toy path as hiding the index
//! from a malicious server that can read `q` in the clear — the wire protocol
//! here is educational. Index privacy requires the cryptographic query layer
//! (out of scope for this slice).

use crate::error::{BlindDexError, Result};
use crate::params::Params;

/// Database matrix: `n_rows` vectors of `limbs_per_row` limbs in `Z_q`.
#[derive(Debug, Clone)]
pub struct DatabaseMatrix {
    params: Params,
    /// Flat row-major: `rows[i * L + ℓ]`.
    data: Vec<u64>,
}

impl DatabaseMatrix {
    /// Encode fixed-width catalog rows into limb matrix.
    pub fn from_rows(params: Params, rows: &[Vec<u8>]) -> Result<Self> {
        params.validate()?;
        if rows.len() != params.n_rows {
            return Err(BlindDexError::CatalogTooLarge {
                got: rows.len(),
                max: params.n_rows,
            });
        }
        let l = params.limbs_per_row();
        let mut data = vec![0u64; params.n_rows * l];
        for (i, row) in rows.iter().enumerate() {
            if row.len() != params.row_bytes {
                return Err(BlindDexError::InvalidRowBytes {
                    got: row.len(),
                    max: params.row_bytes,
                });
            }
            pack_row_into(row, &mut data[i * l..(i + 1) * l], params.modulus);
        }
        Ok(Self { params, data })
    }

    /// Parameters used to encode this matrix.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Number of limbs per database row.
    pub fn limbs_per_row(&self) -> usize {
        self.params.limbs_per_row()
    }

    /// Server matvec: `answer[ℓ] = Σ_i Db[i][ℓ] * q[i] mod q`.
    pub fn matvec(&self, query: &[u64]) -> Result<Vec<u64>> {
        if query.len() != self.params.n_rows {
            return Err(BlindDexError::BadQueryLength {
                got: query.len(),
                expected: self.params.n_rows,
            });
        }
        let l = self.limbs_per_row();
        let qmod = self.params.modulus;
        let mut answer = vec![0u64; l];
        for (i, &qi) in query.iter().enumerate() {
            if qi == 0 {
                continue;
            }
            let row = &self.data[i * l..(i + 1) * l];
            for limb_idx in 0..l {
                // wrapping mul/add then reduce; for qi ∈ {0,1} this is exact.
                let prod = mul_mod(row[limb_idx], qi, qmod);
                answer[limb_idx] = add_mod(answer[limb_idx], prod, qmod);
            }
        }
        Ok(answer)
    }
}

/// Client-side PIR helpers (toy exact path).
#[derive(Debug, Clone)]
pub struct PirEngine {
    params: Params,
}

impl PirEngine {
    /// Create a PIR engine for the given params.
    pub fn new(params: Params) -> Result<Self> {
        params.validate()?;
        Ok(Self { params })
    }

    /// Borrow the engine parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Build an exact standard-basis query for `index`.
    ///
    /// Note: production SimplePIR would sample LWE noise around `e_index`.
    pub fn query_exact(&self, index: usize) -> Result<Vec<u64>> {
        if index >= self.params.n_rows {
            return Err(BlindDexError::IndexOutOfRange {
                index,
                n_rows: self.params.n_rows,
            });
        }
        let mut q = vec![0u64; self.params.n_rows];
        q[index] = 1;
        Ok(q)
    }

    /// Recover fixed-width row bytes from a matvec answer (exact path).
    pub fn recover_row(&self, answer: &[u64]) -> Result<Vec<u8>> {
        let l = self.params.limbs_per_row();
        if answer.len() != l {
            return Err(BlindDexError::BadAnswerLength {
                got: answer.len(),
                expected: l,
            });
        }
        Ok(unpack_row(
            answer,
            self.params.row_bytes,
            self.params.modulus,
        ))
    }

    /// Full client round-trip helper against a matrix (for tests / local demo).
    pub fn retrieve(&self, db: &DatabaseMatrix, index: usize) -> Result<Vec<u8>> {
        let q = self.query_exact(index)?;
        let ans = db.matvec(&q)?;
        self.recover_row(&ans)
    }
}

fn pack_row_into(row: &[u8], out: &mut [u64], modulus: u64) {
    for (i, slot) in out.iter_mut().enumerate() {
        let base = i * 4;
        let mut limb: u32 = 0;
        for b in 0..4 {
            if base + b < row.len() {
                limb |= u32::from(row[base + b]) << (8 * b);
            }
        }
        *slot = u64::from(limb) % modulus;
    }
}

fn unpack_row(limbs: &[u64], row_bytes: usize, _modulus: u64) -> Vec<u8> {
    let mut row = vec![0u8; row_bytes];
    for (i, &limb) in limbs.iter().enumerate() {
        let base = i * 4;
        let v = limb as u32;
        for b in 0..4 {
            let idx = base + b;
            if idx < row_bytes {
                row[idx] = ((v >> (8 * b)) & 0xff) as u8;
            }
        }
    }
    row
}

fn add_mod(a: u64, b: u64, q: u64) -> u64 {
    if q == 0 {
        return a.wrapping_add(b);
    }
    // q may be 2^32; keep intermediates in u128.
    ((u128::from(a) + u128::from(b)) % u128::from(q)) as u64
}

fn mul_mod(a: u64, b: u64, q: u64) -> u64 {
    if q == 0 {
        return a.wrapping_mul(b);
    }
    ((u128::from(a) * u128::from(b)) % u128::from(q)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let params = Params::new(4, 8, 1u64 << 32).unwrap();
        let row = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let l = params.limbs_per_row();
        let mut limbs = vec![0u64; l];
        pack_row_into(&row, &mut limbs, params.modulus);
        let back = unpack_row(&limbs, params.row_bytes, params.modulus);
        assert_eq!(back, row);
    }
}
