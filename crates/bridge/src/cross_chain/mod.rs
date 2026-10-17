//! Cross-chain transaction verification module.
//!
//! This module provides the core infrastructure for verifying cross-chain
//! transactions during block verification. It includes types for cross-chain
//! transactions, proofs, verification requests/responses, and the main
//! verification coordinator.
//!
//! ## Architecture
//!
//! The cross-chain verification system consists of several components:
//!
//! - **Types**: Core data structures for cross-chain operations
//! - **Coordinator**: Manages verification sessions and coordination
//! - **ProofManager**: Handles proof creation, validation, and storage
//! - **SecureCommunicationLayer**: Handles encrypted peer communication
//! - **CryptoUtils**: Cryptographic utilities for encryption and proofs
//! - **Errors**: Error types for cross-chain operations
//!
//! ## Usage
//!
//! To use the cross-chain verification system, create a coordinator and
//! call the appropriate verification methods:
//!
//! ```ignore
//! use crate::cross_chain::{
//!     DefaultCrossChainVerificationCoordinator, PeerId, EncryptionConfig,
//!     CoordinatorConfig,
//! };
//!
//! let local_peer = PeerId::new(hash);
//! let coordinator = DefaultCrossChainVerificationCoordinator::with_defaults(local_peer);
//! ```

pub mod communication;
pub mod coordinator;
pub mod crypto_utils;
pub mod errors;
pub mod limits;
pub mod proof_manager;
pub mod recovery;
pub mod sync;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export commonly used types from types module
pub use types::{
    ChainId, ConsensusProof, CrossChainOperation, CrossChainProof, CrossChainTransaction,
    CrossChainVerificationResult, EncryptionAlgorithm, EncryptionConfig, PeerId, PeerInfo, Region,
    ReputationScore, Timestamp, TransactionVerificationResult, ValidationResult, ValidatorSet,
    VerificationRequest, VerificationResponse, VerificationResult, VerificationStatus,
};

// Re-export from errors module
pub use errors::CrossChainError;

// Re-export CrossChainResult from errors
pub use errors::CrossChainResult;
pub use limits::{LoadSnapshot, ResourceLimits, VerificationJob, VerificationScheduler};
pub use recovery::{
    AuditLog, RetryPolicy, RetryState, SessionJournal, VerificationAuditEvent,
    VerificationErrorCategory, VerificationErrorDetail,
};
pub use sync::{validate_expiration, validate_header_timestamp, validate_sync_lag};

// Re-export from coordinator module
pub use coordinator::{
    ConsensusVerificationHook, CoordinatorConfig, CrossChainVerificationCoordinator,
    DefaultCrossChainVerificationCoordinator, VerificationSession, VerificationSessionState,
};

// Re-export from proof_manager module
pub use proof_manager::{DefaultProofManager, ProofCache, ProofManager, ProofStorage, StoredProof};

// Re-export from communication module
pub use communication::{
    ChannelBinding, ConnectionPool, DefaultSecureCommunicationLayer, EncryptedMessage,
    LocalVerificationHandler, SecureChannel, SecureChannelState, SecureCommunicationLayer,
    VerificationPeerHandler,
};

// Re-export from crypto_utils module
pub use crypto_utils::{
    Aes256GcmEncryptor, ChaCha20Poly1305Encryptor, SecureChannelBinding, X25519KeyPair,
};
