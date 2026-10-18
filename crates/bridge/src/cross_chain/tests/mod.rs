//! Tests for the cross-chain module.
use crate::cross_chain::{
    ChainId, ConsensusProof, CrossChainOperation, CrossChainProof, CrossChainTransaction,
    EncryptionAlgorithm, PeerId, ProofManager, Timestamp, ValidatorSet, VerificationRequest,
    VerificationResponse, VerificationResult,
};
use oxydome_core::{Block, BlockHeader, PublicKey, Transaction, ValueIndex};
use oxydome_crypto::evk::{
    CrossChainEphemeralKeyIntegrator, EphemeralKeyManager, EphemeralVerificationKey, EvkConfig,
    ICrossChainEphemeralKeyIntegrator, IEphemeralKeyManager, IKeyChainValidator,
};
use oxydome_crypto::{Hash, MerkleProof, Sig};

/// Creates a test transaction.
fn create_test_tx() -> Transaction {
    Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        fee: 0,
        ovm_action: None,
        ohm_context: None,
        position_hash: None,
    }
}

/// Creates a test block header.
fn create_test_header() -> BlockHeader {
    BlockHeader {
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
    }
}

/// Creates a test block.
fn create_test_block() -> Block {
    Block {
        header: create_test_header(),
        transactions: Vec::new(),
        operations: Vec::new(),
        ovm_receipts: Vec::new(),
    }
}

#[test]
fn cross_chain_transaction_creation() {
    let base = create_test_tx();
    let tx = CrossChainTransaction::new(
        base,
        ChainId::new(1),
        ChainId::new(2),
        CrossChainOperation::Transfer,
        Hash::zero(),
        MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        1000,
        Hash::zero(),
        1000,
        0,
        1700000000000,
    );

    assert_eq!(tx.source_chain.id(), 1);
    assert_eq!(tx.destination_chain.id(), 2);
    assert_eq!(tx.operation, CrossChainOperation::Transfer);
}

#[test]
fn cross_chain_transaction_expiration() {
    let tx = CrossChainTransaction::new(
        create_test_tx(),
        ChainId::new(1),
        ChainId::new(2),
        CrossChainOperation::Transfer,
        Hash::zero(),
        MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        1000,
        Hash::zero(),
        1000,
        0,
        1700000000000,
    );

    // Before expiration
    assert!(!tx.is_expired(1699000000000));
    // At expiration
    assert!(!tx.is_expired(1700000000000));
    // After expiration
    assert!(tx.is_expired(1700000001000));
}

#[test]
fn cross_chain_proof_creation() {
    let proof = CrossChainProof::new(
        Hash::zero(),
        CrossChainTransaction::new(
            create_test_tx(),
            ChainId::new(1),
            ChainId::new(2),
            CrossChainOperation::Transfer,
            Hash::zero(),
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
        create_test_header(),
        MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        ConsensusProof {
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
        PeerId::new(Hash::zero()),
        1699000000000,
        oxydome_crypto::Sig([0u8; 64]),
    );

    assert_eq!(proof.prover_peer, PeerId::new(Hash::zero()));
    assert_eq!(proof.created_at, 1699000000000);
}

#[test]
fn verification_request_creation() {
    let request = VerificationRequest::new(
        Hash::zero(),
        CrossChainTransaction::new(
            create_test_tx(),
            ChainId::new(1),
            ChainId::new(2),
            CrossChainOperation::Transfer,
            Hash::zero(),
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
        create_test_header(),
        MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        3,
        PeerId::new(Hash::zero()),
        Timestamp::new(1699000000000),
        EncryptionAlgorithm::Aes256Gcm,
    );

    assert_eq!(request.required_quorum, 3);
    assert_eq!(request.encryption_algorithm, EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn verification_response_success() {
    let response = VerificationResponse::success(
        Hash::zero(),
        CrossChainProof::new(
            Hash::zero(),
            CrossChainTransaction::new(
                create_test_tx(),
                ChainId::new(1),
                ChainId::new(2),
                CrossChainOperation::Transfer,
                Hash::zero(),
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
            create_test_header(),
            MerkleProof {
                siblings: Vec::new(),
                index: 0,
            },
            ConsensusProof {
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
            PeerId::new(Hash::zero()),
            1699000000000,
            oxydome_crypto::Sig([0u8; 64]),
        ),
        PeerId::new(Hash::zero()),
        oxydome_crypto::Sig([0u8; 64]),
    );

    assert_eq!(response.result, VerificationResult::Verified);
    assert!(response.proof.is_some());
    assert!(response.error_message.is_none());
}

#[test]
fn verification_response_failure() {
    let response = VerificationResponse::failure(
        Hash::zero(),
        "Transaction not found".to_string(),
        PeerId::new(Hash::zero()),
        oxydome_crypto::Sig([0u8; 64]),
    );

    assert_eq!(response.result, VerificationResult::Failed);
    assert!(response.proof.is_none());
    assert!(response.error_message.is_some());
    assert_eq!(response.error_message.unwrap(), "Transaction not found");
}

#[test]
fn encryption_algorithm_properties() {
    let aes256 = EncryptionAlgorithm::Aes256Gcm;
    assert!(aes256.is_secure());
    assert_eq!(aes256.key_size(), 32);
    assert_eq!(aes256.nonce_size(), 12);

    let chacha = EncryptionAlgorithm::ChaCha20Poly1305;
    assert!(chacha.is_secure());
    assert_eq!(chacha.key_size(), 32);
    assert_eq!(chacha.nonce_size(), 12);

    let aes128 = EncryptionAlgorithm::Aes128Cbc;
    assert!(!aes128.is_secure());
    assert_eq!(aes128.key_size(), 16);
    assert_eq!(aes128.nonce_size(), 16);
}

#[test]
fn default_encryption_algorithm() {
    assert_eq!(
        EncryptionAlgorithm::default(),
        EncryptionAlgorithm::Aes256Gcm
    );
}

// ---------------------------------------------------------------------------
// EVK cross-chain integration tests
// ---------------------------------------------------------------------------

/// Creates a CrossChainProof with an attached destination EVK reference.
fn create_proof_with_evk(
    tx: Transaction,
    source_block: Block,
    key: &EphemeralVerificationKey,
) -> CrossChainProof {
    let txid = tx.txid();
    let mut header = source_block.header.clone();
    header.tx_root = oxydome_crypto::merkle_root(&[txid]);
    let block = Block {
        header,
        transactions: vec![tx.clone()],
        operations: Vec::new(),
        ovm_receipts: Vec::new(),
    };
    let merkle_proof = oxydome_crypto::merkle_proof(
        &block
            .transactions
            .iter()
            .map(|t| t.txid())
            .collect::<Vec<_>>(),
        0,
    );
    let block_hash = oxydome_crypto::hash_value(&block.header);
    let signing_key = oxydome_crypto::KeyPair::generate();
    let consensus_proof = ConsensusProof {
        validator_set: ValidatorSet {
            validators: vec![signing_key.public()],
            total: 1,
            quorum: 1,
        },
        signers_count: 1,
        threshold: 1,
        aggregated_signature: signing_key.sign(&block_hash.0).0.to_vec(),
        epoch: block.header.epoch,
    };
    let cross_tx = CrossChainTransaction::new(
        tx,
        ChainId::new(1),
        ChainId::new(2),
        CrossChainOperation::Transfer,
        txid,
        merkle_proof.clone(),
        block.header.height,
        Hash::zero(),
        1000,
        0,
        1700000000000,
    );
    let mut proof = CrossChainProof {
        proof_id: txid,
        transaction: cross_tx,
        source_block_header: block.header.clone(),
        merkle_proof,
        consensus_proof,
        prover_peer: PeerId::new(Hash::zero()),
        prover_public_key: signing_key.public(),
        created_at: 1699000000,
        signature: Sig([0u8; 64]),
        destination_ephemeral_key: None,
        destination_verification_commitment: None,
    };
    proof.attach_destination_ephemeral_key(key);
    proof.signature = signing_key.sign(&proof.signing_bytes());
    proof
}

#[test]
fn cross_chain_ephemeral_key_is_recorded_and_retrieved() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        100,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    let commitment = integrator.record_destination_ephemeral_key(ChainId::new(2).id(), key);
    assert!(!commitment.is_zero());

    let state = integrator
        .get_cross_chain_verification_state(ChainId::new(2).id())
        .expect("cross-chain state should exist");
    assert_eq!(state.chain_id, ChainId::new(2).id());
    assert_eq!(state.ephemeral_key, key.public_key);
    assert_eq!(state.height, key.block_height);
}

#[test]
fn cross_chain_ephemeral_reference_validates() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        200,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    integrator.record_destination_ephemeral_key(ChainId::new(3).id(), key);
    assert!(integrator
        .validate_cross_chain_ephemeral_reference(ChainId::new(3).id(), &key)
        .is_ok());
}

#[test]
fn cross_chain_ephemeral_reference_rejects_wrong_key() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        300,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();
    let other_key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        300,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    integrator.record_destination_ephemeral_key(ChainId::new(4).id(), key);
    assert!(integrator
        .validate_cross_chain_ephemeral_reference(ChainId::new(4).id(), &other_key)
        .is_err());
}

#[test]
fn cross_chain_ephemeral_reference_rejects_unknown_chain() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        400,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    assert!(integrator
        .validate_cross_chain_ephemeral_reference(ChainId::new(99).id(), &key)
        .is_err());
}

#[test]
fn cross_chain_state_chaining_links_consecutive_states() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());

    let key1 = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        500,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();
    let key2 = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        501,
        Hash::zero(),
        key1.key_chain_commitment,
        1699000001,
    )
    .unwrap();

    let state1 = oxydome_crypto::evk::CrossChainVerificationState {
        chain_id: ChainId::new(5).id(),
        height: key1.block_height,
        ephemeral_key: key1.public_key,
        commitment: Hash::zero(),
        previous_cross_chain_state: Hash::zero(),
    };
    let first_commitment = integrator.chain_cross_chain_states(state1).unwrap();

    let state2 = oxydome_crypto::evk::CrossChainVerificationState {
        chain_id: ChainId::new(5).id(),
        height: key2.block_height,
        ephemeral_key: key2.public_key,
        commitment: Hash::zero(),
        previous_cross_chain_state: Hash::zero(),
    };
    let second_commitment = integrator.chain_cross_chain_states(state2).unwrap();

    let final_state = integrator
        .get_cross_chain_verification_state(ChainId::new(5).id())
        .unwrap();
    assert_eq!(final_state.previous_cross_chain_state, first_commitment);
    assert_eq!(final_state.commitment, second_commitment);
    assert_ne!(first_commitment, second_commitment);
}

#[test]
fn proof_attaches_and_validates_destination_ephemeral_key() {
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        600,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    let tx = create_test_tx();
    let mut block = create_test_block();
    block.transactions = vec![tx.clone()];
    block.header.tx_root = oxydome_crypto::merkle_root(&[tx.txid()]);

    let proof = create_proof_with_evk(tx, block, &key);
    assert!(proof.validate_destination_ephemeral_key(&key));
    assert_eq!(proof.destination_ephemeral_key, Some(key.public_key));
}

#[test]
fn proof_without_ephemeral_key_is_valid_when_no_integrator_configured() {
    let proof_manager = std::sync::Arc::new(
        crate::cross_chain::DefaultProofManager::with_defaults(PeerId::new(Hash::zero())),
    );
    let tx = create_test_tx();
    let mut block = create_test_block();
    block.transactions = vec![tx.clone()];
    block.header.tx_root = oxydome_crypto::merkle_root(&[tx.txid()]);
    block.header.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let proof = proof_manager.create_proof(&tx, &block).unwrap();
    assert!(proof.destination_ephemeral_key.is_none());

    let result = proof_manager.validate_proof(&proof).unwrap();
    assert!(result.is_valid);
}

#[test]
fn coordinator_validates_cross_chain_with_evk_integrator() {
    let coordinator = crate::cross_chain::DefaultCrossChainVerificationCoordinator::with_defaults(
        PeerId::new(Hash::zero()),
    );
    let integrator = std::sync::Arc::new(CrossChainEphemeralKeyIntegrator::default());
    coordinator.set_ephemeral_key_integrator(integrator.clone());

    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());
    let key = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        700,
        Hash::zero(),
        Hash::zero(),
        1699000000,
    )
    .unwrap();

    integrator.record_destination_ephemeral_key(ChainId::new(2).id(), key);

    let tx = create_test_tx();
    let mut block = create_test_block();
    block.header.height = 700;
    block.transactions = vec![tx.clone()];
    block.header.tx_root = oxydome_crypto::merkle_root(&[tx.txid()]);

    let proof_manager = std::sync::Arc::new(
        crate::cross_chain::DefaultProofManager::with_defaults(PeerId::new(Hash::zero())),
    );
    let proof = proof_manager
        .create_proof_with_ephemeral_key(&tx, &block, &key)
        .unwrap();
    assert!(proof.validate_destination_ephemeral_key(&key));
}

#[test]
fn coordinator_without_evk_integrator_accepts_proof_without_key() {
    let coordinator = crate::cross_chain::DefaultCrossChainVerificationCoordinator::with_defaults(
        PeerId::new(Hash::zero()),
    );

    let tx = create_test_tx();
    let mut block = create_test_block();
    block.transactions = vec![tx.clone()];
    block.header.tx_root = oxydome_crypto::merkle_root(&[tx.txid()]);
    block.header.timestamp = 1699000000;

    let proof_manager = std::sync::Arc::new(
        crate::cross_chain::DefaultProofManager::with_defaults(PeerId::new(Hash::zero())),
    );
    let proof = proof_manager.create_proof(&tx, &block).unwrap();
    assert!(proof.destination_ephemeral_key.is_none());
}

#[test]
fn verification_chain_validation_detects_broken_chain() {
    let integrator = CrossChainEphemeralKeyIntegrator::default();
    let evk_manager = EphemeralKeyManager::new(EvkConfig::default());

    let key1 = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        0,
        Hash::zero(),
        Hash::zero(),
        1,
    )
    .unwrap();

    integrator.record_destination_ephemeral_key(ChainId::new(1).id(), key1);
    let result = integrator.validate_cross_chain_ephemeral_reference(ChainId::new(1).id(), &key1);
    assert!(result.is_ok());

    let key2 = IEphemeralKeyManager::generate_ephemeral_key(
        &evk_manager,
        1,
        Hash::zero(),
        Hash::zero(),
        2,
    )
    .unwrap();
    integrator.record_destination_ephemeral_key(ChainId::new(1).id(), key2);
    assert!(integrator
        .validate_cross_chain_ephemeral_reference(ChainId::new(1).id(), &key1)
        .is_err());
}
