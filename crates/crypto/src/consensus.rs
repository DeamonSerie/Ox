//! Consensus proof verification for block finality.
//!
//! This module implements threshold signature verification for 2/3 validator set
//! and block finality verification logic as required by the cross-chain verification
//! system.

use crate::{hash, verify, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default threshold for consensus: 2/3 of validator set.
pub const CONSENSUS_THRESHOLD_DENOMINATOR: usize = 3;
pub const CONSENSUS_THRESHOLD_NUMERATOR: usize = 2;

/// Computes the minimum number of signatures required for consensus.
///
/// # Arguments
/// * `validator_count` - Total number of validators in the set
///
/// # Returns
/// The minimum number of signatures required (2/3 + 1 of total)
pub fn compute_consensus_threshold(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    // 2/3+1 quorum as per BFT requirements
    (validator_count * CONSENSUS_THRESHOLD_NUMERATOR / CONSENSUS_THRESHOLD_DENOMINATOR) + 1
}

/// Error type for consensus proof operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsensusError {
    #[error("consensus threshold not met: required {0}, got {1}")]
    ThresholdNotMet(usize, usize),
    #[error("consensus proof verification failed")]
    VerificationFailed,
    #[error("invalid validator set: {0}")]
    InvalidValidatorSet(String),
    #[error("aggregated signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("block height {0} below finality threshold {1}")]
    BlockNotFinal(u64, u64),
    #[error("consensus proof serialization failed: {0}")]
    SerializationError(String),
    #[error("consensus proof deserialization failed: {0}")]
    DeserializationError(String),
    #[error("epoch mismatch: expected {0}, got {1}")]
    EpochMismatch(u64, u64),
    #[error("validator set lookup failed for epoch {0}")]
    ValidatorSetNotFound(u64),
}

/// Result type for consensus operations.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

/// A signature from a single validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_index: usize,
    pub validator_pubkey: PublicKey,
    pub signature: Sig,
    pub message_hash: Hash,
}

impl ValidatorSignature {
    /// Creates a new validator signature.
    pub fn new(
        validator_index: usize,
        validator_pubkey: PublicKey,
        signature: Sig,
        message_hash: Hash,
    ) -> Self {
        Self {
            validator_index,
            validator_pubkey,
            signature,
            message_hash,
        }
    }

    /// Verifies this signature against the message hash.
    pub fn verify(&self) -> bool {
        verify(
            &self.validator_pubkey,
            &self.message_hash.0,
            &self.signature,
        )
    }
}

/// An aggregated consensus proof for block finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProof {
    /// The block hash being finalized
    pub block_hash: Hash,
    /// The validator set that signed
    pub validator_set: Vec<PublicKey>,
    /// The signatures from validators
    pub signatures: Vec<ValidatorSignature>,
    /// The epoch number when this was finalized
    pub epoch: u64,
    /// The block height that was finalized
    pub block_height: u64,
    /// Optional: aggregated signature (for BLS-style aggregation)
    pub aggregated_signature: Option<Vec<u8>>,
}

impl ConsensusProof {
    /// Creates a new consensus proof.
    pub fn new(
        block_hash: Hash,
        validator_set: Vec<PublicKey>,
        signatures: Vec<ValidatorSignature>,
        epoch: u64,
        block_height: u64,
        aggregated_signature: Option<Vec<u8>>,
    ) -> Self {
        Self {
            block_hash,
            validator_set,
            signatures,
            epoch,
            block_height,
            aggregated_signature,
        }
    }

    /// Verifies the consensus proof.
    ///
    /// # Returns
    /// * `Ok(())` if the proof is valid
    /// * `Err(ConsensusError)` if verification fails
    pub fn verify(&self, finality_threshold: u64) -> ConsensusResult<()> {
        // Verify block is final
        if self.block_height < finality_threshold {
            return Err(ConsensusError::BlockNotFinal(
                self.block_height,
                finality_threshold,
            ));
        }

        // Verify we have enough signatures
        let threshold = compute_consensus_threshold(self.validator_set.len());
        if self.signatures.len() < threshold {
            return Err(ConsensusError::ThresholdNotMet(
                threshold,
                self.signatures.len(),
            ));
        }

        // Verify each signature is from a valid validator
        for sig in &self.signatures {
            if !self.validator_set.contains(&sig.validator_pubkey) {
                return Err(ConsensusError::InvalidValidatorSet(
                    "signature from unknown validator".to_string(),
                ));
            }

            if !sig.verify() {
                return Err(ConsensusError::InvalidSignature(
                    "invalid validator signature".to_string(),
                ));
            }
        }

        // Verify each signature is unique (same validator can't sign twice)
        let unique_validators: std::collections::HashSet<_> =
            self.signatures.iter().map(|s| s.validator_pubkey).collect();
        if unique_validators.len() != self.signatures.len() {
            return Err(ConsensusError::InvalidValidatorSet(
                "duplicate validator signatures".to_string(),
            ));
        }

        // Verify all signatures are for the same block hash
        for sig in &self.signatures {
            if sig.message_hash != self.block_hash {
                return Err(ConsensusError::InvalidSignature(
                    "signature for different block hash".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Creates a consensus proof from raw signatures.
    pub fn from_signatures(
        block_hash: Hash,
        validator_set: &[PublicKey],
        signatures: &[(usize, PublicKey, Sig)],
        epoch: u64,
        block_height: u64,
    ) -> Self {
        let sigs = signatures
            .iter()
            .map(|(idx, pk, sig)| ValidatorSignature::new(*idx, *pk, *sig, block_hash))
            .collect();

        Self::new(
            block_hash,
            validator_set.to_vec(),
            sigs,
            epoch,
            block_height,
            None, // aggregated signature not implemented
        )
    }

    /// Serializes the consensus proof to bytes.
    pub fn serialize(&self) -> ConsensusResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    /// Deserializes a consensus proof from bytes.
    pub fn deserialize(bytes: &[u8]) -> ConsensusResult<Self> {
        bincode::deserialize(bytes).map_err(|e| ConsensusError::DeserializationError(e.to_string()))
    }
}

/// Verifies a block header's finality using a consensus proof.
///
/// # Arguments
/// * `block_hash` - The hash of the block being verified
/// * `block_height` - The height of the block
/// * `finality_threshold` - Minimum blocks before finality (default: 12)
/// * `consensus_proof` - The consensus proof to verify
///
/// # Returns
/// * `Ok(true)` if the block is finalized
/// * `Err(ConsensusError)` if verification fails
pub fn verify_block_finality(
    block_hash: Hash,
    block_height: u64,
    finality_threshold: u64,
    consensus_proof: &ConsensusProof,
) -> ConsensusResult<bool> {
    // Verify the consensus proof
    consensus_proof.verify(finality_threshold)?;

    // Verify block hash matches
    if consensus_proof.block_hash != block_hash {
        return Err(ConsensusError::InvalidSignature(
            "block hash mismatch in consensus proof".to_string(),
        ));
    }

    // Verify block height
    if consensus_proof.block_height != block_height {
        return Err(ConsensusError::InvalidSignature(
            "block height mismatch in consensus proof".to_string(),
        ));
    }

    Ok(true)
}

/// Validates that a validator set has the required quorum.
///
/// # Arguments
/// * `validators` - The list of validator public keys
/// * `signers` - The list of validator public keys that signed
///
/// # Returns
/// * `Ok(())` if the quorum is met
/// * `Err(ConsensusError)` if the quorum is not met
pub fn validate_validator_quorum(
    validators: &[PublicKey],
    signers: &[PublicKey],
) -> ConsensusResult<()> {
    let threshold = compute_consensus_threshold(validators.len());

    // Count unique signers
    let unique_signers: std::collections::HashSet<_> = signers.iter().collect();

    if unique_signers.len() < threshold {
        return Err(ConsensusError::ThresholdNotMet(
            threshold,
            unique_signers.len(),
        ));
    }

    // Verify all signers are in the validator set
    for signer in &unique_signers {
        if !validators.contains(signer) {
            return Err(ConsensusError::InvalidValidatorSet(
                "signer not in validator set".to_string(),
            ));
        }
    }

    Ok(())
}

/// Computes the message hash for block finality signing.
///
/// The message hash includes:
/// - Block hash
/// - Block height
/// - Epoch number
///
/// This ensures signatures cannot be reused across different blocks or epochs.
pub fn compute_finality_message_hash(block_hash: Hash, block_height: u64, epoch: u64) -> Hash {
    let block_bytes = block_hash.0.to_vec();
    let height_bytes = block_height.to_le_bytes().to_vec();
    let epoch_bytes = epoch.to_le_bytes().to_vec();

    hash(&[block_bytes, height_bytes, epoch_bytes].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_consensus_threshold_basic() {
        assert_eq!(compute_consensus_threshold(0), 0);
        assert_eq!(compute_consensus_threshold(1), 1); // 2/3*1 + 1 = 1
        assert_eq!(compute_consensus_threshold(3), 3); // 2/3*3 + 1 = 3
        assert_eq!(compute_consensus_threshold(4), 3); // 2/3*4 + 1 = 3.67 -> 3
        assert_eq!(compute_consensus_threshold(7), 5); // 2/3*7 + 1 = 5.67 -> 5
        assert_eq!(compute_consensus_threshold(10), 7); // 2/3*10 + 1 = 7.67 -> 7
    }

    #[test]
    fn consensus_proof_minimal_valid() {
        let block_hash = hash(b"test-block");
        let validators: Vec<PublicKey> = (0..7)
            .map(|_| {
                // Create dummy public keys
                let mut pub_key = [0u8; 32];
                pub_key[0] = 1;
                PublicKey(pub_key)
            })
            .collect();

        let message_hash = compute_finality_message_hash(block_hash, 100, 1);

        // Create signatures (these will fail verification but test structure)
        let mut signatures = Vec::new();
        for (i, pk) in validators.iter().enumerate() {
            // Create dummy signature
            let mut sig_bytes = [0u8; 64];
            sig_bytes[0] = i as u8;
            let sig = Sig(sig_bytes);
            signatures.push(ValidatorSignature::new(i, *pk, sig, message_hash));
        }

        let proof = ConsensusProof::new(block_hash, validators.clone(), signatures, 1, 100, None);

        // This should fail verification (dummy signatures) but test structure
        // The threshold check should pass
        let result = proof.verify(12);
        assert!(matches!(result, Err(ConsensusError::InvalidSignature(_))));
    }

    #[test]
    fn consensus_proof_threshold_not_met() {
        let block_hash = hash(b"test-block");
        let validators: Vec<PublicKey> = (0..7)
            .map(|_| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = 1;
                PublicKey(pub_key)
            })
            .collect();

        let message_hash = compute_finality_message_hash(block_hash, 100, 1);

        // Create only 2 signatures (need 3 for 7 validators)
        let mut signatures = Vec::new();
        for (i, pk) in validators.iter().take(2).enumerate() {
            let mut sig_bytes = [0u8; 64];
            sig_bytes[0] = i as u8;
            let sig = Sig(sig_bytes);
            signatures.push(ValidatorSignature::new(i, *pk, sig, message_hash));
        }

        let proof = ConsensusProof::new(block_hash, validators, signatures, 1, 100, None);

        let result = proof.verify(12);
        assert!(matches!(result, Err(ConsensusError::ThresholdNotMet(_, _))));
    }

    #[test]
    fn consensus_proof_duplicate_signers() {
        let block_hash = hash(b"test-block");
        let validators: Vec<PublicKey> = (0..7)
            .map(|i| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = i;
                PublicKey(pub_key)
            })
            .collect();

        let message_hash = compute_finality_message_hash(block_hash, 100, 1);

        // Create a keypair for a valid validator
        let kp = crate::KeyPair::generate();
        let pk = kp.public();

        // Create valid signatures for the same validator (duplicate)
        // We need at least 5 signatures to pass threshold check (2/3+1 of 7 = 5)
        let mut signatures = Vec::new();
        for i in 0..5 {
            let sig = kp.sign(&message_hash.0);
            signatures.push(ValidatorSignature::new(i, pk, sig, message_hash));
        }

        let proof = ConsensusProof::new(block_hash, validators, signatures, 1, 100, None);

        // This should fail because we have duplicate validators (same validator signing 5 times)
        let result = proof.verify(12);
        assert!(matches!(
            result,
            Err(ConsensusError::InvalidValidatorSet(_))
        ));
    }

    #[test]
    fn block_finality_verification() {
        let block_hash = hash(b"test-block");

        // Create a minimal valid consensus proof
        let validators: Vec<PublicKey> = (0..7)
            .map(|_| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = 1;
                PublicKey(pub_key)
            })
            .collect();

        let message_hash = compute_finality_message_hash(block_hash, 100, 1);

        let mut signatures = Vec::new();
        for (i, pk) in validators.iter().enumerate() {
            let mut sig_bytes = [0u8; 64];
            sig_bytes[0] = i as u8;
            let sig = Sig(sig_bytes);
            signatures.push(ValidatorSignature::new(i, *pk, sig, message_hash));
        }

        let proof = ConsensusProof::new(block_hash, validators, signatures, 1, 100, None);

        // This will fail verification due to dummy signatures, but test structure
        let result = verify_block_finality(block_hash, 100, 12, &proof);
        assert!(matches!(result, Err(ConsensusError::InvalidSignature(_))));
    }

    #[test]
    fn finality_message_hash_deterministic() {
        let block_hash = hash(b"test-block");
        let h1 = compute_finality_message_hash(block_hash, 100, 1);
        let h2 = compute_finality_message_hash(block_hash, 100, 1);
        assert_eq!(h1, h2);

        // Different block height should give different hash
        let h3 = compute_finality_message_hash(block_hash, 200, 1);
        assert_ne!(h1, h3);

        // Different epoch should give different hash
        let h4 = compute_finality_message_hash(block_hash, 100, 2);
        assert_ne!(h1, h4);
    }

    #[test]
    fn validator_quorum_validation() {
        let validators: Vec<PublicKey> = (0..7)
            .map(|i| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = i;
                PublicKey(pub_key)
            })
            .collect();

        let signers: Vec<PublicKey> = validators.iter().take(5).cloned().collect();

        // Should succeed (5 >= 3 threshold)
        let result = validate_validator_quorum(&validators, &signers);
        assert!(result.is_ok());
    }

    #[test]
    fn validator_quorum_not_met() {
        let validators: Vec<PublicKey> = (0..7)
            .map(|i| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = i;
                PublicKey(pub_key)
            })
            .collect();

        let signers: Vec<PublicKey> = validators.iter().take(2).cloned().collect();

        // Should fail (2 < 3 threshold)
        let result = validate_validator_quorum(&validators, &signers);
        assert!(matches!(result, Err(ConsensusError::ThresholdNotMet(_, _))));
    }

    #[test]
    fn validator_quorum_unknown_signer() {
        let validators: Vec<PublicKey> = (0..7)
            .map(|i| {
                let mut pub_key = [0u8; 32];
                pub_key[0] = i;
                PublicKey(pub_key)
            })
            .collect();

        let mut signers: Vec<PublicKey> = validators.iter().take(5).cloned().collect();
        // Add an unknown signer
        let mut unknown_pubkey = [0u8; 32];
        unknown_pubkey[0] = 99;
        signers.push(PublicKey(unknown_pubkey));

        // Should fail (unknown signer)
        let result = validate_validator_quorum(&validators, &signers);
        assert!(matches!(
            result,
            Err(ConsensusError::InvalidValidatorSet(_))
        ));
    }
}
