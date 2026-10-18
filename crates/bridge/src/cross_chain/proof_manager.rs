//! Proof manager trait and implementation for cross-chain proof lifecycle.

use crate::cross_chain::crypto_utils;
use crate::cross_chain::sync::validate_header_timestamp;
use crate::cross_chain::{
    ChainId, ConsensusProof, CrossChainError, CrossChainOperation, CrossChainProof,
    CrossChainResult, CrossChainTransaction, PeerId, ValidatorSet,
};
use lru::LruCache;
use oxydome_core::{Block, BlockHeader, PublicKey, Transaction, ValueIndex};
use oxydome_crypto::{Hash, KeyPair, MerkleProof, Sig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Trait for managing cross-chain proof lifecycle.
pub trait ProofManager: Send + Sync {
    fn create_proof(
        &self,
        transaction: &Transaction,
        source_block: &Block,
    ) -> CrossChainResult<CrossChainProof>;
    fn validate_proof(&self, proof: &CrossChainProof) -> CrossChainResult<ProofValidationResult>;
    fn store_proof(&self, proof: &CrossChainProof) -> CrossChainResult<()>;
    fn get_proof(&self, txid: &Hash) -> Option<CrossChainProof>;

    /// Creates a proof and binds it to the destination chain's EVK state.
    fn create_proof_with_ephemeral_key(
        &self,
        transaction: &Transaction,
        source_block: &Block,
        key: &oxydome_crypto::evk::EphemeralVerificationKey,
    ) -> CrossChainResult<CrossChainProof> {
        let mut proof = self.create_proof(transaction, source_block)?;
        proof.attach_destination_ephemeral_key(key);
        Ok(proof)
    }
}

/// Result of proof validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofValidationResult {
    pub is_valid: bool,
    pub error_message: Option<String>,
    pub txid: Hash,
}

/// Persistent proof storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStorage {
    proofs: BTreeMap<Hash, StoredProof>,
    max_proofs: usize,
    ttl_seconds: u64,
    last_clean: u64,
}

impl ProofStorage {
    pub fn new(max_proofs: usize, ttl_seconds: u64) -> Self {
        Self {
            proofs: BTreeMap::new(),
            max_proofs,
            ttl_seconds,
            last_clean: 0,
        }
    }

    pub fn insert(&mut self, proof: StoredProof) -> Option<StoredProof> {
        self.clean_expired();
        if self.proofs.len() >= self.max_proofs {
            if let Some(oldest_key) = self.proofs.keys().next().copied() {
                self.proofs.remove(&oldest_key);
            }
        }
        self.proofs.insert(proof.txid, proof)
    }

    pub fn get(&mut self, txid: &Hash) -> Option<&StoredProof> {
        self.clean_expired();
        self.proofs.get(txid)
    }

    pub fn clean_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.proofs
            .retain(|_, proof| !proof.is_expired(now, self.ttl_seconds));
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

/// A stored proof with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProof {
    pub txid: Hash,
    pub proof: CrossChainProof,
    pub stored_at: u64,
    pub last_access: u64,
    pub access_count: u64,
}

impl StoredProof {
    pub fn new(txid: Hash, proof: CrossChainProof) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            txid,
            proof,
            stored_at: now,
            last_access: now,
            access_count: 0,
        }
    }

    pub fn touch(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.last_access = now;
        self.access_count += 1;
    }

    pub fn is_expired(&self, now: u64, ttl_seconds: u64) -> bool {
        now > self.stored_at + ttl_seconds
    }
}

/// In-memory proof cache with TTL and LRU eviction.
#[derive(Debug, Clone)]
pub struct ProofCache {
    cache: Arc<std::sync::Mutex<LruCache<Hash, StoredProof>>>,
    max_entries: usize,
    ttl_seconds: u64,
}

impl ProofCache {
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(std::sync::Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(max_entries).unwrap(),
            ))),
            max_entries,
            ttl_seconds,
        }
    }

    pub fn insert(&self, txid: Hash, proof: CrossChainProof) {
        let mut cache = self.cache.lock().unwrap();
        let stored = StoredProof::new(txid, proof);
        cache.push(txid, stored);
    }

    pub fn get(&self, txid: &Hash) -> Option<StoredProof> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(stored) = cache.pop(txid) {
            let mut accessed = stored.clone();
            accessed.touch();
            cache.push(*txid, accessed.clone());
            Some(accessed)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.lock().unwrap().is_empty()
    }
}

/// Default implementation of the proof manager.
#[derive(Debug)]
pub struct DefaultProofManager {
    cache: ProofCache,
    storage: Arc<std::sync::Mutex<ProofStorage>>,
    local_peer_id: PeerId,
    signing_key: KeyPair,
    max_merkle_depth: usize,
}

impl DefaultProofManager {
    pub fn new(
        local_peer_id: PeerId,
        cache_size: usize,
        storage_size: usize,
        ttl_seconds: u64,
    ) -> Self {
        let signing_key = KeyPair::generate();
        Self {
            cache: ProofCache::new(cache_size, ttl_seconds),
            storage: Arc::new(std::sync::Mutex::new(ProofStorage::new(
                storage_size,
                ttl_seconds,
            ))),
            local_peer_id,
            signing_key,
            max_merkle_depth: 64,
        }
    }

    pub fn with_defaults(local_peer_id: PeerId) -> Self {
        Self::new(local_peer_id, 10_000, 50_000, 86_400)
    }
}

#[async_trait::async_trait]
impl ProofManager for Arc<DefaultProofManager> {
    fn create_proof(
        &self,
        transaction: &Transaction,
        source_block: &Block,
    ) -> CrossChainResult<CrossChainProof> {
        let txid = transaction.txid();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let merkle_proof = {
            let leaves: Vec<Hash> = source_block.transactions.iter().map(|t| t.txid()).collect();
            let index = source_block
                .transactions
                .iter()
                .position(|t| t.txid() == txid)
                .ok_or_else(|| CrossChainError::TransactionNotFound(txid))?;
            oxydome_crypto::merkle_proof(&leaves, index)
        };

        let block_hash = oxydome_crypto::hash_value(&source_block.header);
        let public_key = self.signing_key.public();
        let consensus_proof = ConsensusProof {
            validator_set: ValidatorSet {
                validators: vec![public_key],
                total: 1,
                quorum: 1,
            },
            signers_count: 1,
            threshold: 1,
            aggregated_signature: self.signing_key.sign(&block_hash.0).0.to_vec(),
            epoch: source_block.header.epoch,
        };

        let proof = CrossChainProof {
            proof_id: txid,
            transaction: CrossChainTransaction::new(
                Transaction {
                    inputs: transaction.inputs.clone(),
                    outputs: transaction.outputs.clone(),
                    fee: transaction.fee,
                    ovm_action: transaction.ovm_action.clone(),
                    ohm_context: transaction.ohm_context.clone(),
                    position_hash: transaction.position_hash,
                },
                ChainId::new(1),
                ChainId::new(2),
                CrossChainOperation::Transfer,
                txid,
                merkle_proof.clone(),
                source_block.header.height,
                Hash::zero(),
                0,
                0,
                0,
            ),
            source_block_header: source_block.header.clone(),
            merkle_proof,
            consensus_proof,
            prover_peer: self.local_peer_id,
            prover_public_key: public_key,
            created_at: now,
            signature: Sig([0u8; 64]),
            destination_ephemeral_key: None,
            destination_verification_commitment: None,
        };

        let mut proof = proof;
        proof.signature = self.signing_key.sign(&proof.signing_bytes());

        Ok(proof)
    }

    fn validate_proof(&self, proof: &CrossChainProof) -> CrossChainResult<ProofValidationResult> {
        let txid = proof.transaction.txid();
        if proof.proof_id != txid || proof.transaction.source_txid != txid {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("proof transaction identifier mismatch".to_string()),
                txid,
            });
        }
        if proof.transaction.source_block_height != proof.source_block_header.height {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("proof block height mismatch".to_string()),
                txid,
            });
        }
        if proof.prover_public_key == PublicKey([0u8; 32]) {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("missing prover public key".to_string()),
                txid,
            });
        }
        if !oxydome_crypto::verify(
            &proof.prover_public_key,
            &proof.signing_bytes(),
            &proof.signature,
        ) {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("proof signature verification failed".to_string()),
                txid,
            });
        }
        let consensus = &proof.consensus_proof;
        if consensus.validator_set.total != consensus.validator_set.validators.len()
            || consensus.validator_set.quorum == 0
            || consensus.threshold < consensus.validator_set.quorum
            || consensus.signers_count < consensus.threshold
            || consensus.signers_count > consensus.validator_set.total
            || consensus.aggregated_signature.len() != 64
            || !consensus
                .validator_set
                .validators
                .contains(&proof.prover_public_key)
        {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("invalid consensus proof metadata".to_string()),
                txid,
            });
        }
        let consensus_signature =
            Sig::from_slice(&consensus.aggregated_signature).ok_or_else(|| {
                CrossChainError::InvalidConsensusProof(
                    "invalid consensus signature length".to_string(),
                )
            })?;
        let source_block_hash = oxydome_crypto::hash_value(&proof.source_block_header);
        if !oxydome_crypto::verify(
            &proof.prover_public_key,
            &source_block_hash.0,
            &consensus_signature,
        ) {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("consensus signature verification failed".to_string()),
                txid,
            });
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if now > proof.created_at.saturating_add(300) || proof.created_at > now.saturating_add(60) {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("proof is stale or from the future".to_string()),
                txid,
            });
        }
        validate_header_timestamp(&proof.source_block_header, now)?;
        if proof.transaction.expiration != 0 && now > proof.transaction.expiration {
            return Err(CrossChainError::Expired(proof.transaction.expiration));
        }
        let merkle_valid = crypto_utils::verify_merkle_inclusion(
            &txid,
            &proof.merkle_proof,
            &proof.source_block_header.tx_root,
            self.max_merkle_depth,
        )?;

        if !merkle_valid {
            return Ok(ProofValidationResult {
                is_valid: false,
                error_message: Some("Merkle proof verification failed".to_string()),
                txid,
            });
        }

        Ok(ProofValidationResult {
            is_valid: true,
            error_message: None,
            txid,
        })
    }

    fn store_proof(&self, proof: &CrossChainProof) -> CrossChainResult<()> {
        let txid = proof.transaction.txid();
        self.cache.insert(txid, proof.clone());
        let mut storage = self.storage.lock().unwrap();
        let stored = StoredProof::new(txid, proof.clone());
        storage.insert(stored);
        Ok(())
    }

    fn get_proof(&self, txid: &Hash) -> Option<CrossChainProof> {
        if let Some(stored) = self.cache.get(txid) {
            return Some(stored.proof.clone());
        }
        let mut storage = self.storage.lock().unwrap();
        storage.get(txid).map(|stored| stored.proof.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::{merkle_root, MerkleProof, Sig};

    fn create_test_block() -> Block {
        let header = BlockHeader {
            height: 1000,
            execution_version: 1,
            ovm_activation_height: 0,
            smart_contract_activation_height: 0,
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            operation_root: Hash::zero(),
            ovm_receipt_root: Hash::zero(),
            utxo_root: Hash::zero(),
            state_root: Hash::zero(),
            supply: 1_000_000,
            epoch: 1,
            generation: 1,
            value_index: ValueIndex::from_raw(1_000_000_000_000),
            producer: PublicKey([0u8; 32]),
            timestamp: 1699000000000,
            volume: 1000,
            tx_count: 1,
            exit_amount: 0,
            ephemeral_public_key: None,
            previous_verification_commitment: None,
            verification_state_commitment: None,
            speedometer_minted: 0,
            speedometer_airdrop_amount: 0,
            gas_price: 0,
            total_gas_fees: 0,
            coin_toss_seed: None,
            ordered_tx_root: None,
        };
        Block {
            header,
            transactions: Vec::new(),
            operations: Vec::new(),
            ovm_receipts: Vec::new(),
        }
    }

    #[test]
    fn proof_cache_insert_and_get() {
        let mut cache = ProofCache::new(100, 3600);
        let txid = Hash::zero();
        let proof = CrossChainProof {
            proof_id: txid,
            transaction: CrossChainTransaction::new(
                Transaction {
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    fee: 0,
                    ovm_action: None,
                    ohm_context: None,
                    position_hash: None,
                },
                ChainId::new(1),
                ChainId::new(2),
                CrossChainOperation::Transfer,
                txid,
                MerkleProof {
                    siblings: Vec::new(),
                    index: 0,
                },
                1000,
                Hash::zero(),
                1000,
                0,
                1700000000000,
            ),
            source_block_header: create_test_block().header,
            merkle_proof: MerkleProof {
                siblings: Vec::new(),
                index: 0,
            },
            consensus_proof: ConsensusProof {
                validator_set: ValidatorSet {
                    validators: Vec::new(),
                    total: 0,
                    quorum: 0,
                },
                signers_count: 0,
                threshold: 0,
                aggregated_signature: Vec::new(),
                epoch: 0,
            },
            prover_peer: PeerId::new(Hash::zero()),
            created_at: 1699000000000,
            signature: Sig([0u8; 64]),
            prover_public_key: PublicKey([0u8; 32]),
            destination_ephemeral_key: None,
            destination_verification_commitment: None,
        };
        cache.insert(txid, proof.clone());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn proof_creation_and_validation_rejects_tampering() {
        let tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            ovm_action: None,
            ohm_context: None,
            position_hash: None,
        };
        let mut header = create_test_block().header;
        header.timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        header.tx_root = merkle_root(&[tx.txid()]);
        let block = Block {
            header,
            transactions: vec![tx.clone()],
            operations: Vec::new(),
            ovm_receipts: Vec::new(),
        };
        let manager = Arc::new(DefaultProofManager::with_defaults(
            PeerId::new(Hash::zero()),
        ));
        let proof = manager
            .create_proof(&tx, &block)
            .expect("proof should be constructed");
        assert!(
            manager
                .validate_proof(&proof)
                .expect("validation should run")
                .is_valid
        );

        let mut tampered = proof;
        tampered.transaction.base.fee = 1;
        assert!(
            !manager
                .validate_proof(&tampered)
                .expect("validation should run")
                .is_valid
        );
    }

    #[test]
    fn proof_manager_binds_destination_ephemeral_state() {
        let tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            ovm_action: None,
            ohm_context: None,
            position_hash: None,
        };
        let mut block = create_test_block();
        block.transactions = vec![tx.clone()];
        block.header.tx_root = merkle_root(&[tx.txid()]);
        let manager = Arc::new(DefaultProofManager::with_defaults(
            PeerId::new(Hash::zero()),
        ));
        let evk_manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let key = oxydome_crypto::evk::IEphemeralKeyManager::generate_ephemeral_key(
            &evk_manager,
            block.header.height,
            block.hash(),
            Hash::zero(),
            1,
        )
        .unwrap();
        let proof = manager
            .create_proof_with_ephemeral_key(&tx, &block, &key)
            .unwrap();
        assert!(proof.validate_destination_ephemeral_key(&key));
    }
}
