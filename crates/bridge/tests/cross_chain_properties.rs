use oxydome_bridge::cross_chain::{
    Aes256GcmEncryptor, PeerId, VerificationResponse, VerificationSession,
};
use oxydome_crypto::merkle::{
    build_merkle_proof_with_limit, compute_merkle_root_with_limit, verify_merkle_proof,
};
use oxydome_crypto::{hash, Hash, Sig};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn merkle_proofs_round_trip(leaves in prop::collection::vec(any::<u8>(), 1..32)) {
        let hashes: Vec<Hash> = leaves.iter().map(|value| hash(&[*value])).collect();
        let root = compute_merkle_root_with_limit(&hashes, None).unwrap();
        for index in 0..hashes.len() {
            let proof = build_merkle_proof_with_limit(&hashes, index, None).unwrap();
            prop_assert_eq!(verify_merkle_proof(&root, &hashes[index], &proof, None).unwrap(), true);
        }
    }

    #[test]
    fn merkle_proofs_reject_changed_leaves(leaves in prop::collection::vec(any::<u8>(), 1..16)) {
        let hashes: Vec<Hash> = leaves.iter().map(|value| hash(&[*value])).collect();
        let root = compute_merkle_root_with_limit(&hashes, None).unwrap();
        let proof = build_merkle_proof_with_limit(&hashes, 0, None).unwrap();
        prop_assert!(verify_merkle_proof(&root, &hash(&[leaves[0].wrapping_add(1)]), &proof, None).is_err());
    }
}

#[test]
fn proof_and_message_serialization_round_trip() {
    let proof = oxydome_crypto::MerkleProof {
        siblings: vec![Hash::from([3; 64])],
        index: 1,
    };
    let encoded = bincode::serialize(&proof).unwrap();
    assert_eq!(
        bincode::deserialize::<oxydome_crypto::MerkleProof>(&encoded).unwrap(),
        proof
    );
    let response = VerificationResponse::failure(
        Hash::from([4; 64]),
        "not found".into(),
        PeerId::default(),
        Sig([0; 64]),
    );
    let encoded = bincode::serialize(&response).unwrap();
    assert_eq!(
        bincode::deserialize::<VerificationResponse>(&encoded).unwrap(),
        response
    );
}

#[test]
fn verification_is_idempotent_and_quorum_is_subset_invariant() {
    let transaction = oxydome_bridge::cross_chain::CrossChainTransaction::new(
        oxydome_core::Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            ovm_action: None,
            ohm_context: None,
        },
        oxydome_bridge::cross_chain::ChainId::new(1),
        oxydome_bridge::cross_chain::ChainId::new(2),
        oxydome_bridge::cross_chain::CrossChainOperation::Transfer,
        Hash::zero(),
        oxydome_crypto::MerkleProof {
            siblings: Vec::new(),
            index: 0,
        },
        1,
        Hash::zero(),
        0,
        0,
        0,
    );
    let mut session =
        VerificationSession::new(transaction, 3, 0, std::time::Duration::from_secs(30));
    for id in 1..=3 {
        session.add_response(VerificationResponse::failure(
            Hash::zero(),
            "invalid".into(),
            PeerId::new(Hash::from([id; 64])),
            Sig([0; 64]),
        ));
    }
    assert_eq!(session.responses.len(), 3);
    assert_eq!(
        session.state,
        oxydome_bridge::cross_chain::VerificationSessionState::InProgress
    );
    let duplicate = session.responses[0].clone();
    session.add_response(duplicate);
    assert_eq!(session.responses.len(), 3);
}

#[test]
fn encryption_round_trip_property_sample() {
    let cipher = Aes256GcmEncryptor::new(&[9; 32]).unwrap();
    let plaintext = b"cross-chain payload";
    let nonce = [7; 12];
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    assert_eq!(cipher.decrypt(&nonce, &ciphertext).unwrap(), plaintext);
}
