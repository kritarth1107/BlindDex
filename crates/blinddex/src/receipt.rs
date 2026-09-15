//! Query receipts: client nonces and server replay protection.
//!
//! This module provides scaffolding for demo anti-replay:
//!
//! - **Client nonces**: A client generates a random 16–32 byte nonce and attaches
//!   it to a query. The server echoes the nonce in the answer. The client verifies
//!   the echo to detect answer substitution.
//!
//! - **Replay window**: The server tracks recently seen nonces (bounded LRU) and
//!   rejects duplicates. This prevents trivial replay attacks in a single-server
//!   demo setting.
//!
//! # Honest non-claims
//!
//! - This is **demo anti-replay**, not production crypto.
//! - The replay window is **not distributed** — multiple servers do not share state.
//! - Nonces are **not authenticated** — a MITM could strip or forge them.
//! - The nonce does not bind to query content; it only detects answer substitution.
//!
//! For production use, combine with TLS client certificates, signed requests,
//! or a proper challenge-response protocol.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};

use crate::error::{BlindDexError, Result};

/// Default nonce length in bytes.
pub const DEFAULT_NONCE_LEN: usize = 16;

/// Minimum nonce length in bytes.
pub const MIN_NONCE_LEN: usize = 16;

/// Maximum nonce length in bytes.
pub const MAX_NONCE_LEN: usize = 32;

/// Default replay window capacity (number of nonces to remember).
pub const DEFAULT_REPLAY_WINDOW_SIZE: usize = 256;

/// Generate a random nonce of the specified length.
///
/// Uses a simple entropy source (system time + counter) hashed with blake3.
/// For production, use a proper CSPRNG.
///
/// # Panics
///
/// Panics if `len` is outside `MIN_NONCE_LEN..=MAX_NONCE_LEN`.
pub fn generate_nonce(len: usize) -> Vec<u8> {
    assert!(
        (MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&len),
        "nonce length must be {MIN_NONCE_LEN}..={MAX_NONCE_LEN}, got {len}"
    );

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&nanos.to_le_bytes());
    seed[8..].copy_from_slice(&count.to_le_bytes());

    let hash = blake3::hash(&seed);
    hash.as_bytes()[..len].to_vec()
}

/// Generate a default-length nonce (16 bytes).
pub fn generate_nonce_default() -> Vec<u8> {
    generate_nonce(DEFAULT_NONCE_LEN)
}

/// Generate a nonce and return it as lowercase hex.
pub fn generate_nonce_hex(len: usize) -> String {
    hex::encode(generate_nonce(len))
}

/// Generate a default-length nonce as lowercase hex.
pub fn generate_nonce_hex_default() -> String {
    hex::encode(generate_nonce_default())
}

/// Verify that an echoed nonce matches the expected nonce.
///
/// # Arguments
///
/// * `expected` - The nonce the client sent (hex string).
/// * `got` - The nonce the server echoed back (hex string, or `None` if missing).
///
/// # Errors
///
/// Returns [`BlindDexError::ReceiptMismatch`] if the nonces don't match.
pub fn verify_nonce_echo(expected: &str, got: Option<&str>) -> Result<()> {
    match got {
        Some(echoed) if echoed == expected => Ok(()),
        Some(echoed) => Err(BlindDexError::ReceiptMismatch {
            expected: expected.to_string(),
            got: echoed.to_string(),
        }),
        None => Err(BlindDexError::ReceiptMismatch {
            expected: expected.to_string(),
            got: "(missing)".to_string(),
        }),
    }
}

/// A bounded replay window for tracking recently seen nonces.
///
/// This is a simple demo implementation using a `HashSet` with LRU-style eviction.
/// When the window is full, the oldest entries are evicted to make room.
///
/// # Thread safety
///
/// The replay window uses interior mutability (`Mutex`) so it can be used
/// from a shared `&BlindServer` reference without external synchronization.
///
/// # Honest limitations
///
/// - **Not distributed**: Only tracks nonces on this server instance.
/// - **Memory-bounded**: Evicts old nonces; very old replays may succeed.
/// - **No persistence**: State is lost on restart.
#[derive(Debug)]
pub struct ReplayWindow {
    inner: Mutex<ReplayWindowInner>,
}

#[derive(Debug)]
struct ReplayWindowInner {
    seen: HashSet<String>,
    order: Vec<String>,
    capacity: usize,
}

impl ReplayWindow {
    /// Create a new replay window with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(ReplayWindowInner {
                seen: HashSet::with_capacity(capacity),
                order: Vec::with_capacity(capacity),
                capacity,
            }),
        }
    }

    /// Create a new replay window with the default capacity (256).
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SIZE)
    }

    fn lock(&self) -> MutexGuard<'_, ReplayWindowInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check if a nonce has been seen before, and if not, record it.
    ///
    /// Returns `Ok(())` if the nonce is fresh (not seen before).
    /// Returns [`BlindDexError::ReplayDetected`] if the nonce was already seen.
    pub fn check_and_record(&self, nonce: &str) -> Result<()> {
        let mut inner = self.lock();

        if inner.seen.contains(nonce) {
            return Err(BlindDexError::ReplayDetected {
                nonce: nonce.to_string(),
            });
        }

        if inner.order.len() >= inner.capacity {
            if let Some(oldest) = inner.order.first().cloned() {
                inner.seen.remove(&oldest);
                inner.order.remove(0);
            }
        }

        inner.seen.insert(nonce.to_string());
        inner.order.push(nonce.to_string());

        Ok(())
    }

    /// Check if a nonce has been seen before (without recording).
    pub fn contains(&self, nonce: &str) -> bool {
        self.lock().seen.contains(nonce)
    }

    /// Current number of tracked nonces.
    pub fn len(&self) -> usize {
        self.lock().seen.len()
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().seen.is_empty()
    }

    /// The configured capacity.
    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Clear all tracked nonces.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.seen.clear();
        inner.order.clear();
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

impl Clone for ReplayWindow {
    fn clone(&self) -> Self {
        let inner = self.lock();
        Self {
            inner: Mutex::new(ReplayWindowInner {
                seen: inner.seen.clone(),
                order: inner.order.clone(),
                capacity: inner.capacity,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_nonce_length() {
        let n16 = generate_nonce(16);
        assert_eq!(n16.len(), 16);

        let n32 = generate_nonce(32);
        assert_eq!(n32.len(), 32);
    }

    #[test]
    fn generate_nonce_uniqueness() {
        let a = generate_nonce_default();
        let b = generate_nonce_default();
        assert_ne!(a, b);
    }

    #[test]
    fn generate_nonce_hex_format() {
        let hex = generate_nonce_hex(16);
        assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_nonce_echo_match() {
        let nonce = "abc123";
        assert!(verify_nonce_echo(nonce, Some(nonce)).is_ok());
    }

    #[test]
    fn verify_nonce_echo_mismatch() {
        let result = verify_nonce_echo("abc123", Some("xyz789"));
        assert!(matches!(result, Err(BlindDexError::ReceiptMismatch { .. })));
    }

    #[test]
    fn verify_nonce_echo_missing() {
        let result = verify_nonce_echo("abc123", None);
        assert!(matches!(result, Err(BlindDexError::ReceiptMismatch { .. })));
    }

    #[test]
    fn replay_window_fresh_nonce() {
        let window = ReplayWindow::new(10);
        assert!(window.check_and_record("nonce1").is_ok());
        assert!(window.contains("nonce1"));
    }

    #[test]
    fn replay_window_duplicate_nonce() {
        let window = ReplayWindow::new(10);
        assert!(window.check_and_record("nonce1").is_ok());
        let result = window.check_and_record("nonce1");
        assert!(matches!(result, Err(BlindDexError::ReplayDetected { .. })));
    }

    #[test]
    fn replay_window_eviction() {
        let window = ReplayWindow::new(3);
        assert!(window.check_and_record("a").is_ok());
        assert!(window.check_and_record("b").is_ok());
        assert!(window.check_and_record("c").is_ok());
        assert_eq!(window.len(), 3);

        assert!(window.check_and_record("d").is_ok());
        assert_eq!(window.len(), 3);
        assert!(!window.contains("a"));
        assert!(window.contains("b"));
        assert!(window.contains("c"));
        assert!(window.contains("d"));
    }

    #[test]
    fn replay_window_clear() {
        let window = ReplayWindow::new(10);
        window.check_and_record("a").unwrap();
        window.check_and_record("b").unwrap();
        assert_eq!(window.len(), 2);

        window.clear();
        assert!(window.is_empty());
        assert!(window.check_and_record("a").is_ok());
    }
}
