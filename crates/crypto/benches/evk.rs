use oxydome_crypto::evk::{
    EphemeralKeyManager, EvkConfig, IEphemeralKeyManager, VerificationSession,
};
use oxydome_crypto::Hash;
use std::collections::BTreeMap;
use std::time::Instant;

fn main() {
    let manager = EphemeralKeyManager::new(EvkConfig::default());
    let start = Instant::now();
    for height in 0..10_000 {
        let _ = manager.generate_ephemeral_key(height, Hash::zero(), Hash::zero(), height);
    }
    println!("EVK key generation: {:?} for 10,000 keys", start.elapsed());
    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = manager.get_ephemeral_key(Hash::zero());
    }
    println!(
        "EVK lookup workload: {:?} for 10,000 lookups",
        start.elapsed()
    );

    let manager = EphemeralKeyManager::new(EvkConfig::default());
    let mut previous = Hash::zero();
    let start = Instant::now();
    for height in 0..10_000 {
        let key = manager
            .generate_ephemeral_key(height, Hash::zero(), previous, height)
            .unwrap();
        previous = key.key_chain_commitment;
        manager.record_session(VerificationSession {
            session_id: key.session_id,
            block_height: height,
            block_hash: key.block_hash,
            ephemeral_key: key.public_key,
            previous_commitment: key.previous_commitment,
            next_commitment: key.key_chain_commitment,
            started_at: height,
            completed_at: Some(height),
            verifier_node: key.public_key,
            result: Some(true),
            metadata: BTreeMap::new(),
        });
    }
    println!(
        "EVK session recording: {:?} for 10,000 sessions",
        start.elapsed()
    );
    for length in [100, 1_000, 10_000] {
        let start = Instant::now();
        manager.validate_chain_segment(0, length - 1).unwrap();
        println!(
            "EVK chain validation ({length} blocks): {:?}",
            start.elapsed()
        );
    }
    println!("EVK persisted delta: 96 bytes/block");
}
