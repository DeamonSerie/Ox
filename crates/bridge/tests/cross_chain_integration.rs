use async_trait::async_trait;
use oxydome_bridge::cross_chain::*;
use oxydome_core::{Block, BlockHeader, PublicKey, Transaction, ValueIndex};
use oxydome_crypto::{hash_value, merkle_root, Hash, MerkleProof, Sig};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn source_block() -> (Transaction, Block) {
    let transaction = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        fee: 0,
        ovm_action: None,
        ohm_context: None,
    };
    let mut header = BlockHeader {
        height: 42,
        execution_version: 1,
        ovm_activation_height: 0,
        smart_contract_activation_height: 0,
        prev_hash: Hash::zero(),
        tx_root: Hash::zero(),
        operation_root: Hash::zero(),
        ovm_receipt_root: Hash::zero(),
        utxo_root: Hash::zero(),
        state_root: Hash::zero(),
        supply: 0,
        epoch: 1,
        generation: 1,
        value_index: ValueIndex::from_raw(0),
        producer: PublicKey([0; 32]),
        timestamp: now_ms(),
        volume: 0,
        tx_count: 1,
        exit_amount: 0,
        ephemeral_public_key: None,
        previous_verification_commitment: None,
        verification_state_commitment: None,
        speedometer_minted: 0,
        speedometer_airdrop_amount: 0,
        gas_price: 0,
        total_gas_fees: 0,
    };
    header.tx_root = merkle_root(&[transaction.txid()]);
    (
        transaction.clone(),
        Block {
            header,
            transactions: vec![transaction],
            operations: Vec::new(),
            ovm_receipts: Vec::new(),
        },
    )
}

struct MockCommunication {
    proof: CrossChainProof,
}

struct HandshakePeer {
    key: X25519KeyPair,
}

#[async_trait]
impl VerificationPeerHandler for HandshakePeer {
    async fn establish_channel(
        &self,
        initiator_public_key: [u8; 32],
    ) -> CrossChainResult<[u8; 32]> {
        Ok(self
            .key
            .derive_shared_secret(&x25519_dalek::PublicKey::from(initiator_public_key)))
    }

    async fn handle_verification_request(
        &self,
        _request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse> {
        Err(CrossChainError::InvalidRequest)
    }
}

#[async_trait]
impl SecureCommunicationLayer for MockCommunication {
    async fn request_verification(
        &self,
        peer: &PeerId,
        request: &VerificationRequest,
        _timeout: Duration,
    ) -> CrossChainResult<VerificationResponse> {
        Ok(VerificationResponse::success(
            request.request_id,
            self.proof.clone(),
            *peer,
            Sig([0; 64]),
        ))
    }

    async fn broadcast_verification_request(
        &self,
        request: &VerificationRequest,
        peers: &[PeerId],
        quorum: usize,
        _timeout: Duration,
    ) -> CrossChainResult<Vec<VerificationResponse>> {
        if peers.len() < quorum {
            return Err(CrossChainError::QuorumNotAchieved(quorum, peers.len()));
        }
        Ok(peers
            .iter()
            .map(|peer| {
                VerificationResponse::success(
                    request.request_id,
                    self.proof.clone(),
                    *peer,
                    Sig([0; 64]),
                )
            })
            .collect())
    }

    async fn handle_verification_request(
        &self,
        _request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse> {
        Err(CrossChainError::InvalidRequest)
    }
    async fn establish_secure_channel(&self, _peer: &PeerId) -> CrossChainResult<ChannelBinding> {
        Ok(ChannelBinding::new([1; 32]))
    }
    async fn close_secure_channel(&self, _peer: &PeerId) -> CrossChainResult<()> {
        Ok(())
    }
}

fn peers() -> Vec<PeerInfo> {
    [
        Region::NorthAmerica,
        Region::Europe,
        Region::Asia,
        Region::Africa,
        Region::Oceania,
        Region::SouthAmerica,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, region)| {
        PeerInfo::new(
            PeerId::new(Hash::from([(i + 1) as u8; 64])),
            ReputationScore::new(90),
            region,
            true,
            i as u64,
        )
    })
    .collect()
}

#[tokio::test]
async fn complete_verification_flow_reaches_quorum() {
    let (transaction, block) = source_block();
    let manager = Arc::new(DefaultProofManager::with_defaults(
        PeerId::new(Hash::zero()),
    ));
    let proof = manager.create_proof(&transaction, &block).unwrap();
    let coordinator = Arc::new({
        let mut coordinator =
            DefaultCrossChainVerificationCoordinator::with_defaults(PeerId::new(Hash::zero()));
        coordinator.set_peers(peers());
        coordinator
    });
    let communication = MockCommunication {
        proof: proof.clone(),
    };
    let status = coordinator
        .verify_cross_chain_transaction(
            proof.transaction.clone(),
            block.header.clone(),
            proof.merkle_proof.clone(),
            &communication,
            &manager,
        )
        .await
        .unwrap();
    assert_eq!(status, VerificationStatus::Verified);
    assert_eq!(
        coordinator.get_verification_status(&transaction.txid()),
        Some(VerificationStatus::Verified)
    );
    assert_eq!(coordinator.audit_log().unwrap().events.len(), 1);
}

#[test]
fn session_persistence_and_retry_recovery_are_restart_safe() {
    let mut coordinator_value =
        DefaultCrossChainVerificationCoordinator::with_defaults(PeerId::new(Hash::zero()));
    let (transaction, _) = source_block();
    coordinator_value.set_peers(peers());
    let coordinator = Arc::new(coordinator_value);
    coordinator
        .verify_transaction(
            &CrossChainTransaction::new(
                transaction,
                ChainId::new(1),
                ChainId::new(2),
                CrossChainOperation::Transfer,
                Hash::zero(),
                MerkleProof {
                    siblings: Vec::new(),
                    index: 0,
                },
                42,
                Hash::zero(),
                0,
                0,
                now_ms() + 60_000,
            ),
            42,
        )
        .unwrap();
    let path = std::env::temp_dir().join(format!("oxydome-cross-chain-{}.journal", now_ms()));
    coordinator.save_sessions(&path).unwrap();
    let restored =
        DefaultCrossChainVerificationCoordinator::with_defaults(PeerId::new(Hash::zero()));
    restored.load_sessions(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let txid = hash_value(&"retry-target");
    assert!(restored.schedule_retry(txid, 1_000).unwrap());
    assert!(!restored.retry_due(&txid, 1_000).unwrap());
}

#[test]
fn consensus_hook_receives_failure_for_block_rejection() {
    struct Hook(std::sync::Mutex<Vec<VerificationStatus>>);
    impl ConsensusVerificationHook for Hook {
        fn on_cross_chain_result(
            &self,
            _transaction: &CrossChainTransaction,
            status: VerificationStatus,
        ) -> Result<(), String> {
            self.0.lock().unwrap().push(status);
            Ok(())
        }
    }
    let (transaction, _) = source_block();
    let cross = CrossChainTransaction::new(
        transaction,
        ChainId::new(1),
        ChainId::new(2),
        CrossChainOperation::Transfer,
        Hash::zero(),
        MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        42,
        Hash::zero(),
        0,
        0,
        now_ms() + 60_000,
    );
    let coordinator =
        DefaultCrossChainVerificationCoordinator::with_defaults(PeerId::new(Hash::zero()));
    let hook = Hook(std::sync::Mutex::new(Vec::new()));
    coordinator
        .apply_consensus_hook(&cross, VerificationStatus::Failed, &hook)
        .unwrap();
    assert_eq!(*hook.0.lock().unwrap(), vec![VerificationStatus::Failed]);
}

#[tokio::test]
async fn secure_communication_reuses_handshake_and_authenticated_encryption() {
    let local = PeerId::new(Hash::from([9; 64]));
    let peer = PeerId::new(Hash::from([8; 64]));
    let communication = Arc::new(DefaultSecureCommunicationLayer::with_defaults(local));
    communication
        .register_peer_handler(
            peer,
            Arc::new(HandshakePeer {
                key: X25519KeyPair::generate(),
            }),
        )
        .unwrap();
    let first = communication.establish_secure_channel(&peer).await.unwrap();
    let second = communication.establish_secure_channel(&peer).await.unwrap();
    assert_eq!(first, second);
    let encrypted = communication
        .encrypt_message(&peer, b"authenticated cross-chain message")
        .unwrap();
    assert_eq!(encrypted.to, peer);
    assert_ne!(encrypted.payload, b"authenticated cross-chain message");
}
