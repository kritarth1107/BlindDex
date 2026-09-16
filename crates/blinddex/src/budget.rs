//! Server-side query budget / rate limiting.
//!
//! This module provides a simple **token bucket** for limiting the number of
//! queries a server will answer per epoch. Each epoch (identified by merkle
//! root or directory seal) has an independent budget.
//!
//! # Honest non-claims
//!
//! - This is a **demo fairness / anti-spam knob**, not authentication.
//! - The budget does NOT authenticate clients or prevent Sybil attacks.
//! - There is no persistent storage; budget state is lost on restart.
//! - The epoch key is just a string; clients can craft queries for different
//!   epochs if the server accepts multiple.
//!
//! # Intended use
//!
//! Query budgets are useful for:
//! - Demonstrating rate-limiting API shape for catalog servers.
//! - Preventing trivial denial-of-service in demo scenarios.
//! - Testing budget exhaustion handling in client code.
//!
//! For production, combine with proper authentication, persistent rate-limit
//! storage (e.g., Redis), and per-client tracking.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::error::{BlindDexError, Result};

/// A per-epoch query budget with token bucket semantics.
///
/// Each epoch (identified by a string key, typically merkle root hex or
/// directory seal) has an independent token count. Queries consume tokens;
/// when tokens are exhausted, further queries are rejected until the epoch
/// changes or tokens are manually refilled.
///
/// # Thread safety
///
/// Uses interior mutability (`Mutex`) for shared server access.
///
/// # Example
///
/// ```
/// use blinddex::budget::QueryBudget;
///
/// let budget = QueryBudget::new(10);
///
/// // Consume 3 tokens for epoch "abc123"
/// assert!(budget.try_consume("abc123", 3).is_ok());
/// assert_eq!(budget.remaining("abc123"), 7);
///
/// // Try to consume more than remaining
/// let result = budget.try_consume("abc123", 10);
/// assert!(result.is_err());
/// ```
#[derive(Debug)]
pub struct QueryBudget {
    inner: Mutex<QueryBudgetInner>,
}

#[derive(Debug)]
struct QueryBudgetInner {
    capacity: usize,
    buckets: HashMap<String, usize>,
}

impl QueryBudget {
    /// Create a new query budget with the specified capacity per epoch.
    ///
    /// Each epoch starts with `capacity` tokens. Tokens do not automatically
    /// refill; call [`Self::refill`] to reset an epoch's budget.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(QueryBudgetInner {
                capacity,
                buckets: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, QueryBudgetInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The configured capacity per epoch.
    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Get the remaining tokens for an epoch.
    ///
    /// Returns `capacity` for epochs that haven't been seen yet.
    pub fn remaining(&self, epoch_key: &str) -> usize {
        let inner = self.lock();
        *inner.buckets.get(epoch_key).unwrap_or(&inner.capacity)
    }

    /// Try to consume `n` tokens from an epoch's budget.
    ///
    /// # Errors
    ///
    /// Returns [`BlindDexError::BudgetExceeded`] if there are not enough tokens.
    pub fn try_consume(&self, epoch_key: &str, n: usize) -> Result<()> {
        let mut inner = self.lock();
        let remaining = *inner.buckets.get(epoch_key).unwrap_or(&inner.capacity);

        if n > remaining {
            return Err(BlindDexError::BudgetExceeded {
                requested: n,
                remaining,
                epoch_key: epoch_key.to_string(),
            });
        }

        inner.buckets.insert(epoch_key.to_string(), remaining - n);
        Ok(())
    }

    /// Consume 1 token from an epoch's budget.
    ///
    /// Convenience wrapper for `try_consume(epoch_key, 1)`.
    pub fn try_consume_one(&self, epoch_key: &str) -> Result<()> {
        self.try_consume(epoch_key, 1)
    }

    /// Refill an epoch's budget to full capacity.
    pub fn refill(&self, epoch_key: &str) {
        let mut inner = self.lock();
        inner.buckets.remove(epoch_key);
    }

    /// Refill all epochs to full capacity.
    pub fn refill_all(&self) {
        self.lock().buckets.clear();
    }

    /// Check if an epoch's budget is exhausted (0 tokens remaining).
    pub fn is_exhausted(&self, epoch_key: &str) -> bool {
        self.remaining(epoch_key) == 0
    }

    /// Get the number of tracked epochs (those with consumed tokens).
    pub fn tracked_epochs(&self) -> usize {
        self.lock().buckets.len()
    }
}

impl Clone for QueryBudget {
    fn clone(&self) -> Self {
        let inner = self.lock();
        Self {
            inner: Mutex::new(QueryBudgetInner {
                capacity: inner.capacity,
                buckets: inner.buckets.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_initial_capacity() {
        let budget = QueryBudget::new(100);
        assert_eq!(budget.capacity(), 100);
        assert_eq!(budget.remaining("any_epoch"), 100);
    }

    #[test]
    fn budget_consume_basic() {
        let budget = QueryBudget::new(10);
        assert!(budget.try_consume("epoch1", 3).is_ok());
        assert_eq!(budget.remaining("epoch1"), 7);
    }

    #[test]
    fn budget_consume_multiple() {
        let budget = QueryBudget::new(10);
        budget.try_consume("e1", 2).unwrap();
        budget.try_consume("e1", 3).unwrap();
        assert_eq!(budget.remaining("e1"), 5);
    }

    #[test]
    fn budget_exceed_fails() {
        let budget = QueryBudget::new(5);
        budget.try_consume("e", 3).unwrap();
        let result = budget.try_consume("e", 5);
        assert!(matches!(result, Err(BlindDexError::BudgetExceeded { .. })));
        assert_eq!(budget.remaining("e"), 2);
    }

    #[test]
    fn budget_exact_exhaust() {
        let budget = QueryBudget::new(5);
        budget.try_consume("e", 5).unwrap();
        assert!(budget.is_exhausted("e"));
        assert!(budget.try_consume_one("e").is_err());
    }

    #[test]
    fn budget_independent_epochs() {
        let budget = QueryBudget::new(10);
        budget.try_consume("a", 7).unwrap();
        budget.try_consume("b", 3).unwrap();
        assert_eq!(budget.remaining("a"), 3);
        assert_eq!(budget.remaining("b"), 7);
        assert_eq!(budget.remaining("c"), 10);
    }

    #[test]
    fn budget_refill_epoch() {
        let budget = QueryBudget::new(10);
        budget.try_consume("e", 10).unwrap();
        assert!(budget.is_exhausted("e"));
        budget.refill("e");
        assert_eq!(budget.remaining("e"), 10);
        assert!(!budget.is_exhausted("e"));
    }

    #[test]
    fn budget_refill_all() {
        let budget = QueryBudget::new(10);
        budget.try_consume("a", 5).unwrap();
        budget.try_consume("b", 5).unwrap();
        budget.refill_all();
        assert_eq!(budget.remaining("a"), 10);
        assert_eq!(budget.remaining("b"), 10);
        assert_eq!(budget.tracked_epochs(), 0);
    }

    #[test]
    fn budget_clone() {
        let budget = QueryBudget::new(10);
        budget.try_consume("e", 3).unwrap();
        let cloned = budget.clone();
        assert_eq!(cloned.remaining("e"), 7);
        budget.try_consume("e", 2).unwrap();
        assert_eq!(cloned.remaining("e"), 7);
    }

    #[test]
    fn budget_consume_one() {
        let budget = QueryBudget::new(3);
        budget.try_consume_one("e").unwrap();
        budget.try_consume_one("e").unwrap();
        budget.try_consume_one("e").unwrap();
        assert!(budget.try_consume_one("e").is_err());
    }
}
