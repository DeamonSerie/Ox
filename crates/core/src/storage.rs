//! Storage labeling and auditing types for the network capacity system.
//!
//! This module also defines the EVFS (Ephemeral Verification File System) types:
//! [`FileEvkLabel`] (re-exported from `oxydome_crypto::evk`), [`FileAccessRecord`], and the
//! v2 storage-label commitment that folds file metadata into the on-chain storage label.

use crate::PublicKey;
use oxydome_crypto::{Hash, Sig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Errors specific to file label validation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FileEvkLabelError {
    #[error("file label signature is invalid")]
    BadSignature,
    #[error("file key chain commitment does not match computation")]
    BadChainCommitment,
    #[error("file label previous_commitment does not match chain tip")]
    BadChainLink,
    #[error("file size {0} exceeds maximum {1}")]
    FileTooLarge(u64, u64),
    #[error("file is already stored")]
    DuplicateFile,
    #[error("node is not an authorized network participant")]
    UnauthorizedNode,
    #[error("node file count exceeds maximum {0}")]
    NodeFileCountExceeded(u64),
    #[error("file operations are not yet active at this height")]
    NotActive,
}

/// A self-signed label describing a peer node's available storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLabel {
    pub node: PublicKey,
    pub height: u64,
    /// Declared total capacity in bytes.
    pub capacity_bytes: u64,
    /// Measured used storage in bytes.
    pub used_bytes: u64,
    /// Available storage in bytes (capacity - used).
    pub available_bytes: u64,
    pub timestamp: u64,
    pub signature: Sig,
    #[serde(default)]
    pub file_root: Option<Hash>,
    #[serde(default)]
    pub file_count: u64,
    #[serde(default)]
    pub file_storage_bytes: u64,
}

impl StorageLabel {
    /// Verify the label's signature and internal consistency, including the file-system
    /// fields when present.
    ///
    /// Tries the v2 commitment (which includes file fields) first, then falls back to the
    /// legacy v1 commitment so pre-activation labels remain valid.
    pub fn is_valid(&self) -> bool {
        if self.used_bytes > self.capacity_bytes {
            return false;
        }
        if self.available_bytes != self.capacity_bytes.saturating_sub(self.used_bytes) {
            return false;
        }
        if self.file_storage_bytes > self.available_bytes {
            return false;
        }
        if self.file_count > 0 && self.file_root.is_none() {
            return false;
        }
        let commit_v2 = evfs_label_commitment_v2(self);
        if oxydome_crypto::verify(&self.node, &commit_v2.0, &self.signature) {
            return true;
        }
        let commit_v1 = label_commitment(
            self.node,
            self.height,
            self.capacity_bytes,
            self.used_bytes,
            self.available_bytes,
            self.timestamp,
        );
        oxydome_crypto::verify(&self.node, &commit_v1.0, &self.signature)
    }

    /// Check if the label is within the allowed deviation (in basis points).
    /// `other` is the auditor's measured value for comparison.
    pub fn within_deviation(&self, other_available: u64, deviation_bps: u32) -> bool {
        if deviation_bps == 0 {
            return self.available_bytes == other_available;
        }
        let allowed = ((other_available as u128) * (deviation_bps as u128) / 10_000) as u128;
        let diff = ((self.available_bytes as u128) as i128 - (other_available as u128) as i128)
            .abs() as u128;
        diff <= allowed
    }
}

/// Compute the commitment that nodes sign for their storage label.
pub fn label_commitment(
    node: PublicKey,
    height: u64,
    capacity_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    timestamp: u64,
) -> Hash {
    oxydome_crypto::hash_value(&(
        "oxydome-storage-label-v1",
        node,
        height,
        capacity_bytes,
        used_bytes,
        available_bytes,
        timestamp,
    ))
}

/// v2 storage-label commitment that includes the EVFS file-system fields.
pub fn evfs_label_commitment_v2(label: &StorageLabel) -> Hash {
    oxydome_crypto::hash_value(&(
        "oxydome-storage-label-v2",
        label.node,
        label.height,
        label.capacity_bytes,
        label.used_bytes,
        label.available_bytes,
        label.timestamp,
        label.file_root,
        label.file_count,
        label.file_storage_bytes,
    ))
}

/// A record of a single file access, stored in the on-chain access log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccessRecord {
    pub accessor: PublicKey,
    pub file_id: Hash,
    pub content_hash: Hash,
    pub height: u64,
    pub timestamp: u64,
}

/// Per-epoch storage audit result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAuditResult {
    pub epoch: u64,
    pub per_node: BTreeMap<PublicKey, bool>, // true if compliant
    pub network_available: u64,
    pub expected_network_storage: u64,
    pub compliant: bool,
}
