//! Cross-chain transaction and proof types.

use oxydome_core::{Amount, BlockHeader, Transaction};
use oxydome_crypto::{Hash, MerkleProof};
use serde::{Deserialize, Serialize};

/// A chain identifier for cross-chain operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chain({})", self.0)
    }
}

/// The type of cross-chain operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossChainOperation {
    Transfer,
    Withdrawal,
    Deposit,
    Message,
    AtomicSwap,
    ContractCall,
    ContractDeployment,
    Recover,
}

/// A cross-chain transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainTransaction {
    pub base: Transaction,
    pub source_chain: ChainId,
    pub destination_chain: ChainId,
    pub operation: CrossChainOperation,
    pub source_txid: Hash,
    pub source_proof: MerkleProof,
    pub source_block_height: u64,
    pub destination_address: Hash,
    pub amount: Amount,
    pub nonce: u64,
    pub expiration: u64,
}

impl CrossChainTransaction {
    pub fn new(
        base: Transaction,
        source_chain: ChainId,
        destination_chain: ChainId,
        operation: CrossChainOperation,
        source_txid: Hash,
        source_proof: MerkleProof,
        source_block_height: u64,
        destination_address: Hash,
        amount: Amount,
        nonce: u64,
        expiration: u64,
    ) -> Self {
        Self {
            base,
            source_chain,
            destination_chain,
            operation,
            source_txid,
            source_proof,
            source_block_height,
            destination_address,
            amount,
            nonce,
            expiration,
        }
    }

    pub fn txid(&self) -> Hash {
        self.base.txid()
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expiration
    }
}

/// Consensus proof for block finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProof {
    pub validator_set: ValidatorSet,
    pub signers_count: usize,
    pub threshold: usize,
    pub aggregated_signature: Vec<u8>,
    pub epoch: u64,
}

/// Validator set for consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<oxydome_crypto::PublicKey>,
    pub total: usize,
    pub quorum: usize,
}

/// Encryption algorithm for secure communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl EncryptionAlgorithm {
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::ChaCha20Poly1305)
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
            Self::Aes128Cbc => 16,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::ChaCha20Poly1305 => 12,
            Self::Aes128Cbc => 16,
        }
    }
}

/// Encryption configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub algorithm: EncryptionAlgorithm,
    pub use_hardware_acceleration: bool,
    pub max_message_size: usize,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::default(),
            use_hardware_acceleration: true,
            max_message_size: 1024 * 1024,
        }
    }
}

/// A cross-chain proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainProof {
    pub proof_id: Hash,
    pub transaction: CrossChainTransaction,
    pub source_block_header: BlockHeader,
    pub merkle_proof: MerkleProof,
    pub consensus_proof: ConsensusProof,
    pub prover_peer: PeerId,
    /// Public key used to authenticate the proof signature.
    pub prover_public_key: oxydome_crypto::PublicKey,
    pub created_at: u64,
    pub signature: oxydome_crypto::Sig,
    /// Optional destination-chain EVK reference. Legacy proofs remain valid during migration.
    #[serde(default)]
    pub destination_ephemeral_key: Option<oxydome_crypto::PublicKey>,
    #[serde(default)]
    pub destination_verification_commitment: Option<Hash>,
}

impl CrossChainProof {
    /// Associates a proof with the destination chain's current verification state.
    pub fn attach_destination_ephemeral_key(
        &mut self,
        key: &oxydome_crypto::evk::EphemeralVerificationKey,
    ) {
        self.destination_ephemeral_key = Some(key.public_key);
        self.destination_verification_commitment = Some(oxydome_crypto::hash_many(&[
            b"CROSS_CHAIN_EVK",
            key.public_key.as_bytes(),
            key.key_chain_commitment.as_bytes(),
        ]));
    }

    pub fn validate_destination_ephemeral_key(
        &self,
        key: &oxydome_crypto::evk::EphemeralVerificationKey,
    ) -> bool {
        self.destination_ephemeral_key == Some(key.public_key)
            && self.destination_verification_commitment
                == Some(oxydome_crypto::hash_many(&[
                    b"CROSS_CHAIN_EVK",
                    key.public_key.as_bytes(),
                    key.key_chain_commitment.as_bytes(),
                ]))
    }

    /// Returns the canonical payload covered by `signature`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature = oxydome_crypto::Sig([0u8; 64]);
        oxydome_crypto::encode(&unsigned)
    }
}

impl CrossChainProof {
    pub fn new(
        proof_id: Hash,
        transaction: CrossChainTransaction,
        source_block_header: BlockHeader,
        merkle_proof: MerkleProof,
        consensus_proof: ConsensusProof,
        prover_peer: PeerId,
        created_at: u64,
        signature: oxydome_crypto::Sig,
    ) -> Self {
        Self {
            proof_id,
            transaction,
            source_block_header,
            merkle_proof,
            consensus_proof,
            prover_peer,
            prover_public_key: oxydome_crypto::PublicKey([0u8; 32]),
            created_at,
            signature,
            destination_ephemeral_key: None,
            destination_verification_commitment: None,
        }
    }
}

/// A peer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Hash);

impl PeerId {
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Peer({})", hex::encode(&self.0 .0[..8]))
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self(Hash::zero())
    }
}

/// Timestamp for cross-chain operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn new(ms: u64) -> Self {
        Self(ms)
    }

    pub fn milliseconds(&self) -> u64 {
        self.0
    }

    pub fn seconds(&self) -> u64 {
        self.0 / 1000
    }
}

/// Verification request sent to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub request_id: Hash,
    pub transaction: CrossChainTransaction,
    pub source_block_header: BlockHeader,
    pub merkle_proof: MerkleProof,
    pub required_quorum: usize,
    pub requestor: PeerId,
    pub timestamp: Timestamp,
    pub encryption_algorithm: EncryptionAlgorithm,
}

impl VerificationRequest {
    pub fn new(
        request_id: Hash,
        transaction: CrossChainTransaction,
        source_block_header: BlockHeader,
        merkle_proof: MerkleProof,
        required_quorum: usize,
        requestor: PeerId,
        timestamp: Timestamp,
        encryption_algorithm: EncryptionAlgorithm,
    ) -> Self {
        Self {
            request_id,
            transaction,
            source_block_header,
            merkle_proof,
            required_quorum,
            requestor,
            timestamp,
            encryption_algorithm,
        }
    }
}

/// The result of verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    Verified,
    Failed,
    Pending,
    Timeout,
    Error,
}

/// Verification response from peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResponse {
    pub request_id: Hash,
    pub result: VerificationResult,
    pub proof: Option<CrossChainProof>,
    pub error_message: Option<String>,
    pub responder: PeerId,
    pub signature: oxydome_crypto::Sig,
}

impl VerificationResponse {
    pub fn success(
        request_id: Hash,
        proof: CrossChainProof,
        responder: PeerId,
        signature: oxydome_crypto::Sig,
    ) -> Self {
        Self {
            request_id,
            result: VerificationResult::Verified,
            proof: Some(proof),
            error_message: None,
            responder,
            signature,
        }
    }

    pub fn failure(
        request_id: Hash,
        error_message: String,
        responder: PeerId,
        signature: oxydome_crypto::Sig,
    ) -> Self {
        Self {
            request_id,
            result: VerificationResult::Failed,
            proof: None,
            error_message: Some(error_message),
            responder,
            signature,
        }
    }
}

/// Block verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainVerificationResult {
    pub verified_count: usize,
    pub failed_count: usize,
    pub pending_count: usize,
    pub transaction_results: Vec<TransactionVerificationResult>,
}

/// Individual transaction verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionVerificationResult {
    pub txid: Hash,
    pub status: VerificationStatus,
    pub proof_count: usize,
    pub required_quorum: usize,
    pub error_message: Option<String>,
}

/// Status of verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Pending,
    InProgress,
    Verified,
    Failed,
    TimedOut,
    Skipped,
}

/// Peer reputation score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationScore(pub u64);

impl ReputationScore {
    pub fn new(score: u64) -> Self {
        Self(score.clamp(0, 100))
    }

    pub fn score(&self) -> u64 {
        self.0
    }

    pub fn meets_threshold(&self, threshold: u64) -> bool {
        self.0 >= threshold
    }
}

/// Geographic region for peer diversity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Region {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Asia,
    Africa,
    Oceania,
    Unknown,
}

/// Peer information for selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub reputation: ReputationScore,
    pub region: Region,
    pub supports_cross_chain: bool,
    pub latency_ms: u64,
}

impl PeerInfo {
    pub fn new(
        peer_id: PeerId,
        reputation: ReputationScore,
        region: Region,
        supports_cross_chain: bool,
        latency_ms: u64,
    ) -> Self {
        Self {
            peer_id,
            reputation,
            region,
            supports_cross_chain,
            latency_ms,
        }
    }
}

/// Result of validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult<T> {
    pub is_valid: bool,
    pub data: Option<T>,
    pub error_message: Option<String>,
}

impl<T> ValidationResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            is_valid: true,
            data: Some(data),
            error_message: None,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            is_valid: false,
            data: None,
            error_message: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_algorithm_defaults() {
        assert_eq!(
            EncryptionAlgorithm::default(),
            EncryptionAlgorithm::Aes256Gcm
        );
    }

    #[test]
    fn encryption_algorithm_properties() {
        let aes = EncryptionAlgorithm::Aes256Gcm;
        assert!(aes.is_secure());
        assert_eq!(aes.key_size(), 32);
        assert_eq!(aes.nonce_size(), 12);
    }

    #[test]
    fn reputation_score_clamping() {
        let high = ReputationScore::new(150);
        assert_eq!(high.score(), 100);
        let low = ReputationScore::new(0);
        assert_eq!(low.score(), 0);
    }

    #[test]
    fn timestamp_conversion() {
        let ts = Timestamp::new(1700000000000);
        assert_eq!(ts.milliseconds(), 1700000000000);
        assert_eq!(ts.seconds(), 1700000000);
    }
}
