//! Retry, error-detail, and restart-recovery primitives for verification.

use crate::cross_chain::{CrossChainError, CrossChainResult, VerificationSession};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationErrorCategory {
    Timeout,
    InvalidProof,
    NotFound,
    Communication,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationErrorDetail {
    pub category: VerificationErrorCategory,
    pub reason: String,
    pub peer_id: Option<String>,
    pub timestamp: u64,
    pub retry_count: u32,
}

impl VerificationErrorDetail {
    pub fn from_error(
        error: &CrossChainError,
        peer_id: Option<String>,
        timestamp: u64,
        retry_count: u32,
    ) -> Self {
        let category = match error {
            CrossChainError::Timeout => VerificationErrorCategory::Timeout,
            CrossChainError::InvalidMerkleProof
            | CrossChainError::InvalidConsensusProof(_)
            | CrossChainError::InvalidSignature => VerificationErrorCategory::InvalidProof,
            CrossChainError::TransactionNotFound(_) | CrossChainError::ProofNotFound(_) => {
                VerificationErrorCategory::NotFound
            }
            CrossChainError::CommunicationError(_) => VerificationErrorCategory::Communication,
            _ => VerificationErrorCategory::Internal,
        };
        Self {
            category,
            reason: error.to_string(),
            peer_id,
            timestamp,
            retry_count,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_retries: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(300),
            max_retries: 5,
        }
    }
}

impl RetryPolicy {
    pub fn backoff(&self, retry_count: u32) -> Option<Duration> {
        if retry_count >= self.max_retries {
            return None;
        }
        let multiplier = 1u32.checked_shl(retry_count).unwrap_or(u32::MAX);
        Some(std::cmp::min(
            self.initial_backoff.saturating_mul(multiplier),
            self.max_backoff,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryState {
    pub attempts: u32,
    pub next_retry_at: Option<u64>,
}

impl RetryState {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            next_retry_at: None,
        }
    }

    pub fn schedule(&mut self, policy: RetryPolicy, now_millis: u64) -> bool {
        let Some(delay) = policy.backoff(self.attempts) else {
            return false;
        };
        self.attempts += 1;
        self.next_retry_at = Some(now_millis.saturating_add(delay.as_millis() as u64));
        true
    }
}

/// A small durable journal for pending sessions. Callers can atomically
/// replace the journal file using their own temp-file policy before rename.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SessionJournal {
    pub sessions: Vec<VerificationSession>,
}

/// Durable-friendly audit record for verification decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAuditEvent {
    pub transaction_hash: oxydome_crypto::Hash,
    pub session_id: oxydome_crypto::Hash,
    pub result_status: String,
    pub proof_count: usize,
    pub node_responses: usize,
    pub completion_timestamp: u64,
    pub event_type: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub events: Vec<VerificationAuditEvent>,
}

impl AuditLog {
    pub fn record(&mut self, event: VerificationAuditEvent) {
        self.events.push(event);
    }

    pub fn save(&self, path: impl AsRef<Path>) -> CrossChainResult<()> {
        let bytes =
            bincode::serialize(self).map_err(|e| CrossChainError::StorageError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| CrossChainError::StorageError(e.to_string()))
    }

    pub fn load(path: impl AsRef<Path>) -> CrossChainResult<Self> {
        let bytes = fs::read(path).map_err(|e| CrossChainError::StorageError(e.to_string()))?;
        bincode::deserialize(&bytes).map_err(|e| CrossChainError::StorageError(e.to_string()))
    }
}

impl SessionJournal {
    pub fn save(&self, path: impl AsRef<Path>) -> CrossChainResult<()> {
        let bytes =
            bincode::serialize(self).map_err(|e| CrossChainError::StorageError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| CrossChainError::StorageError(e.to_string()))
    }

    pub fn load(path: impl AsRef<Path>) -> CrossChainResult<Self> {
        let bytes = fs::read(path).map_err(|e| CrossChainError::StorageError(e.to_string()))?;
        bincode::deserialize(&bytes).map_err(|e| CrossChainError::StorageError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_bounded_and_exhausts() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff(0), Some(Duration::from_secs(30)));
        assert_eq!(policy.backoff(4), Some(Duration::from_secs(300)));
        assert_eq!(policy.backoff(5), None);
    }

    #[test]
    fn retry_state_schedules_absolute_time() {
        let mut state = RetryState::new();
        assert!(state.schedule(RetryPolicy::default(), 1_000));
        assert_eq!(state.next_retry_at, Some(31_000));
        assert_eq!(state.attempts, 1);
    }
}
