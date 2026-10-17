//! Cross-chain verification error types.

use oxydome_crypto::Hash;
use thiserror::Error;

/// Error type for cross-chain verification operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CrossChainError {
    #[error("transaction expired at timestamp {0}")]
    Expired(u64),
    #[error("proof validation failed: {0}")]
    ProofValidationFailed(String),
    #[error("merkle proof verification failed")]
    InvalidMerkleProof,
    #[error("consensus proof verification failed: {0}")]
    InvalidConsensusProof(String),
    #[error("peer signature verification failed")]
    InvalidSignature,
    #[error("block header validation failed: {0}")]
    InvalidBlockHeader(String),
    #[error("source chain synchronization lag exceeds threshold: {0} blocks")]
    ChainSyncLag(u64),
    #[error("block header age {0} exceeds maximum {1}")]
    BlockTooOld(u64, u64),
    #[error("block header timestamp {0} is in the future")]
    BlockFromFuture(u64),
    #[error("transaction {0} not found on source chain")]
    TransactionNotFound(Hash),
    #[error("insufficient peers for quorum: required {0}, available {1}")]
    InsufficientPeers(usize, usize),
    #[error("verification quorum not achieved: required {0}, got {1}")]
    QuorumNotAchieved(usize, usize),
    #[error("verification request timed out")]
    Timeout,
    #[error("communication error: {0}")]
    CommunicationError(String),
    #[error("encryption algorithm not supported")]
    UnsupportedEncryptionAlgorithm,
    #[error("encryption error")]
    EncryptionError,
    #[error("decryption error")]
    DecryptionError,
    #[error("key exchange error")]
    KeyExchangeError(String),
    #[error("proof storage error: {0}")]
    StorageError(String),
    #[error("proof not found for transaction {0}")]
    ProofNotFound(Hash),
    #[error("proof expired")]
    ProofExpired,
    #[error("invalid proof ID")]
    InvalidProofId,
    #[error("invalid request format")]
    InvalidRequest,
    #[error("peer reputation too low")]
    ReputationTooLow,
    #[error("insufficient geographic diversity")]
    InsufficientDiversity,
    #[error("verification session error")]
    SessionError,
    #[error("serialization error")]
    SerializationError,
    #[error("concurrency limit exceeded")]
    ConcurrencyLimitExceeded(usize),
    #[error("resource limit exceeded")]
    ResourceLimitExceeded,
    #[error("ephemeral verification key validation failed: {0}")]
    EphemeralVerification(String),
}

impl CrossChainError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::CommunicationError(_)
                | Self::ChainSyncLag(_)
                | Self::QuorumNotAchieved(_, _)
                | Self::InsufficientPeers(_, _)
        )
    }
}

/// Result type for cross-chain operations.
pub type CrossChainResult<T> = Result<T, CrossChainError>;
