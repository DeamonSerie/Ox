//! Ephemeral verification keys and authenticated node channels.
//!
//! EVK keeps private Ed25519 signing material in memory only for the lifetime of a
//! verification session.  Public state is chained with SHA3-512, so a peer or an
//! administrator can validate a block without receiving private key material.

use crate::{hash, hash_many, hash_value, verify, Hash, KeyPair, PublicKey, Sig};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use zeroize::Zeroize;

pub const EVK_STORAGE_BYTES: usize = 128;
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralVerificationKey {
    pub session_id: Hash,
    pub block_height: u64,
    pub block_hash: Hash,
    pub public_key: PublicKey,
    pub previous_commitment: Hash,
    pub key_chain_commitment: Hash,
    pub generated_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSession {
    pub session_id: Hash,
    pub block_height: u64,
    pub block_hash: Hash,
    pub ephemeral_key: PublicKey,
    pub previous_commitment: Hash,
    pub next_commitment: Hash,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub verifier_node: PublicKey,
    pub result: Option<bool>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProof {
    pub height: u64,
    pub session_id: Hash,
    pub public_key: PublicKey,
    pub previous_commitment: Hash,
    pub commitment: Hash,
}

/// Public verification-key chain used by validators and audit tools.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralKeyChain {
    pub keys: BTreeMap<u64, EphemeralVerificationKey>,
}

impl EphemeralKeyChain {
    pub fn insert(&mut self, key: EphemeralVerificationKey) {
        self.keys.insert(key.block_height, key);
    }
    pub fn get(&self, height: u64) -> Option<&EphemeralVerificationKey> {
        self.keys.get(&height)
    }
    pub fn validate(&self) -> Result<(), EvkError> {
        let mut previous = Hash::zero();
        for (height, key) in &self.keys {
            if key.block_height != *height
                || key.previous_commitment != previous
                || EphemeralKeyManager::compute_chaining_commitment(
                    previous,
                    key.public_key,
                    *height,
                    key.block_hash,
                ) != key.key_chain_commitment
            {
                return Err(EvkError::InvalidChain(*height));
            }
            previous = key.key_chain_commitment;
        }
        Ok(())
    }
}

/// A self-verifying file label that reuses the EVK key-chain commitment mechanism.
///
/// Each file is identified by its `key_chain_commitment`, which chains to the previous
/// file's commitment via [`EphemeralKeyManager::compute_file_key_chain_commitment`].
/// The first file in a chain chains from [`Hash::zero`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvkLabel {
    pub content_hash: Hash,
    pub key_chain_commitment: Hash,
    pub node: PublicKey,
    pub block_height: u64,
    pub block_hash: Hash,
    pub previous_commitment: Hash,
    pub size: u64,
    pub signature: Sig,
}

impl FileEvkLabel {
    /// Verifies the storing node's signature over the label commitment.
    pub fn is_valid(&self) -> bool {
        verify(&self.node, &file_label_commitment(self).0, &self.signature)
    }
}

/// Computes the commitment that the storing node signs for a file label.
pub fn file_label_commitment(label: &FileEvkLabel) -> Hash {
    hash_value(&(
        "oxydome-evfs-file-label-v1",
        label.content_hash,
        label.key_chain_commitment,
        label.node,
        label.block_height,
        label.block_hash,
        label.previous_commitment,
        label.size,
    ))
}

/// A chain of file labels keyed by block height.
///
/// Validation mirrors [`EphemeralKeyChain::validate`]: the first label chains from
/// [`Hash::zero`] and each subsequent label's `previous_commitment` must equal the
/// previous label's `key_chain_commitment`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileKeyChain {
    pub labels: BTreeMap<u64, FileEvkLabel>,
}

impl FileKeyChain {
    pub fn insert(&mut self, label: FileEvkLabel) {
        self.labels.insert(label.block_height, label);
    }
    pub fn get(&self, height: u64) -> Option<&FileEvkLabel> {
        self.labels.get(&height)
    }
    pub fn validate(&self) -> Result<(), EvkError> {
        validate_file_key_chain(Hash::zero(), self)
    }
}

/// Validates a sequence of file labels linked by `key_chain_commitment`, chaining from
/// `genesis_tip` (which is [`Hash::zero`] for the first file in a chain).
pub fn validate_file_key_chain(genesis_tip: Hash, chain: &FileKeyChain) -> Result<(), EvkError> {
    validate_file_key_chain_impl(genesis_tip, &chain.labels)
}

fn validate_file_key_chain_impl(
    genesis_tip: Hash,
    labels: &BTreeMap<u64, FileEvkLabel>,
) -> Result<(), EvkError> {
    let mut previous = genesis_tip;
    for (height, label) in labels {
        if label.block_height != *height
            || label.previous_commitment != previous
            || EphemeralKeyManager::compute_file_key_chain_commitment(
                previous,
                label.content_hash,
                *height,
                label.block_hash,
            ) != label.key_chain_commitment
        {
            return Err(EvkError::InvalidChain(*height));
        }
        previous = label.key_chain_commitment;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainVerificationState {
    pub chain_id: u64,
    pub height: u64,
    pub ephemeral_key: PublicKey,
    pub commitment: Hash,
    pub previous_cross_chain_state: Hash,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvkError {
    #[error("session not found")]
    SessionNotFound,
    #[error("verification key chain is invalid at height {0}")]
    InvalidChain(u64),
    #[error("verification key has expired")]
    Expired,
    #[error("missing chain segment at height {0}")]
    MissingHeight(u64),
    #[error("ephemeral key fields must be supplied together")]
    IncompleteHeader,
    #[error("ephemeral key is required outside migration mode")]
    MissingEphemeralKey,
    #[error("migration transition is not authorized")]
    UnauthorizedMigration,
    #[error("secure channel replay detected")]
    Replay,
    #[error("secure channel authentication failed")]
    Authentication,
    #[error("secure channel payload is too large")]
    PayloadTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvkConfig {
    pub session_timeout_secs: u64,
    pub checkpoint_interval: u64,
    pub migration_threshold_percent: u8,
    pub max_message_size: usize,
}

impl Default for EvkConfig {
    fn default() -> Self {
        Self {
            session_timeout_secs: 300,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            migration_threshold_percent: 90,
            max_message_size: 16 * 1024 * 1024,
        }
    }
}

struct Secret {
    bytes: [u8; 32],
    locked: bool,
}
impl Secret {
    fn new(mut bytes: [u8; 32]) -> Self {
        #[cfg(unix)]
        let locked = unsafe { libc::mlock(bytes.as_mut_ptr().cast(), bytes.len()) == 0 };
        #[cfg(not(unix))]
        let locked = false;
        Self { bytes, locked }
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        rand::rngs::OsRng.fill_bytes(&mut self.bytes);
        self.bytes.zeroize();
        #[cfg(unix)]
        if self.locked {
            unsafe {
                libc::munlock(self.bytes.as_mut_ptr().cast(), self.bytes.len());
            }
        }
    }
}

#[derive(Clone)]
pub struct EphemeralKeyManager {
    inner: Arc<Mutex<ManagerState>>,
    pub config: EvkConfig,
}

struct ManagerState {
    active: BTreeMap<Hash, (EphemeralVerificationKey, Secret)>,
    historical: BTreeMap<u64, EphemeralVerificationKey>,
    sessions: BTreeMap<Hash, VerificationSession>,
    checkpoints: BTreeMap<u64, Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedManagerState {
    historical: BTreeMap<u64, EphemeralVerificationKey>,
    sessions: BTreeMap<Hash, VerificationSession>,
    checkpoints: BTreeMap<u64, Hash>,
}

pub trait IEphemeralKeyManager: Send + Sync {
    fn generate_ephemeral_key(
        &self,
        height: u64,
        block_hash: Hash,
        previous: Hash,
        now: u64,
    ) -> Result<EphemeralVerificationKey, EvkError>;
    fn get_ephemeral_key(&self, session_id: Hash) -> Result<EphemeralVerificationKey, EvkError>;
    fn validate_key_chain(&self, key: &EphemeralVerificationKey, now: u64) -> Result<(), EvkError>;
}

impl EphemeralKeyManager {
    pub fn new(config: EvkConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ManagerState {
                active: BTreeMap::new(),
                historical: BTreeMap::new(),
                sessions: BTreeMap::new(),
                checkpoints: BTreeMap::new(),
            })),
            config,
        }
    }

    pub fn session_id(height: u64, timestamp: u64) -> Hash {
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        hash_many(&[
            b"EVK_SESSION",
            &height.to_le_bytes(),
            &timestamp.to_le_bytes(),
            &random,
        ])
    }

    pub fn compute_chaining_commitment(
        previous: Hash,
        public_key: PublicKey,
        height: u64,
        block_hash: Hash,
    ) -> Hash {
        hash_many(&[
            b"EVK_CHAIN",
            previous.as_bytes(),
            public_key.as_bytes(),
            &height.to_le_bytes(),
            block_hash.as_bytes(),
        ])
    }

    /// Files are chained through EVFS using the same chaining pattern as block EVK keys, but
    /// with a distinct domain separator (`EVFS_FILE_CHAIN`) and the file content hash in place
    /// of the ephemeral public key.
    pub fn compute_file_key_chain_commitment(
        previous: Hash,
        content_hash: Hash,
        height: u64,
        block_hash: Hash,
    ) -> Hash {
        hash_many(&[
            b"EVFS_FILE_CHAIN",
            previous.as_bytes(),
            content_hash.as_bytes(),
            &height.to_le_bytes(),
            block_hash.as_bytes(),
        ])
    }

    pub fn secure_erase(&self, session_id: Hash) -> Result<(), EvkError> {
        self.inner
            .lock()
            .unwrap()
            .active
            .remove(&session_id)
            .map(|_| ())
            .ok_or(EvkError::SessionNotFound)
    }

    pub fn record_session(&self, session: VerificationSession) {
        let mut state = self.inner.lock().unwrap();
        state.historical.insert(
            session.block_height,
            EphemeralVerificationKey {
                session_id: session.session_id,
                block_height: session.block_height,
                block_hash: session.block_hash,
                public_key: session.ephemeral_key,
                previous_commitment: session.previous_commitment,
                key_chain_commitment: session.next_commitment,
                generated_at: session.started_at,
                expires_at: session
                    .started_at
                    .saturating_add(self.config.session_timeout_secs),
            },
        );
        if session
            .block_height
            .is_multiple_of(self.config.checkpoint_interval.max(1))
        {
            state
                .checkpoints
                .insert(session.block_height, session.next_commitment);
        }
        state.sessions.insert(session.session_id, session);
    }

    pub fn get_session(&self, id: Hash) -> Result<VerificationSession, EvkError> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .get(&id)
            .cloned()
            .ok_or(EvkError::SessionNotFound)
    }
    pub fn get_historical_key(&self, height: u64) -> Result<EphemeralVerificationKey, EvkError> {
        self.inner
            .lock()
            .unwrap()
            .historical
            .get(&height)
            .copied()
            .ok_or(EvkError::MissingHeight(height))
    }
    pub fn checkpoint(&self, height: u64) -> Option<Hash> {
        self.inner.lock().unwrap().checkpoints.get(&height).copied()
    }
    /// Exports only public historical state. Active private keys are deliberately excluded.
    pub fn export_state(&self) -> Vec<u8> {
        let state = self.inner.lock().unwrap();
        crate::encode(&PersistedManagerState {
            historical: state.historical.clone(),
            sessions: state.sessions.clone(),
            checkpoints: state.checkpoints.clone(),
        })
    }
    pub fn import_state(&self, encoded: &[u8]) -> Result<(), EvkError> {
        let restored: PersistedManagerState =
            crate::bincode::deserialize(encoded).map_err(|_| EvkError::InvalidChain(0))?;
        let mut state = self.inner.lock().unwrap();
        state.historical = restored.historical;
        state.sessions = restored.sessions;
        state.checkpoints = restored.checkpoints;
        Ok(())
    }
    pub fn query_by_height_range(&self, start: u64, end: u64) -> Vec<VerificationSession> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .values()
            .filter(|s| (start..=end).contains(&s.block_height))
            .cloned()
            .collect()
    }
    pub fn validate_chain_to_height(&self, end: u64) -> Result<(), EvkError> {
        self.validate_chain_segment(0, end)
    }
    pub fn validate_chain_segment(&self, start: u64, end: u64) -> Result<(), EvkError> {
        let state = self.inner.lock().unwrap();
        let mut previous = if start == 0 {
            Hash::zero()
        } else {
            state
                .historical
                .get(&(start - 1))
                .ok_or(EvkError::MissingHeight(start - 1))?
                .key_chain_commitment
        };
        for height in start..=end {
            let key = state
                .historical
                .get(&height)
                .ok_or(EvkError::MissingHeight(height))?;
            if key.previous_commitment != previous
                || Self::compute_chaining_commitment(
                    previous,
                    key.public_key,
                    height,
                    key.block_hash,
                ) != key.key_chain_commitment
            {
                return Err(EvkError::InvalidChain(height));
            }
            previous = key.key_chain_commitment;
        }
        Ok(())
    }
    pub fn get_verification_proof(&self, height: u64) -> Result<VerificationProof, EvkError> {
        let k = self
            .inner
            .lock()
            .unwrap()
            .historical
            .get(&height)
            .copied()
            .ok_or(EvkError::MissingHeight(height))?;
        Ok(VerificationProof {
            height,
            session_id: k.session_id,
            public_key: k.public_key,
            previous_commitment: k.previous_commitment,
            commitment: k.key_chain_commitment,
        })
    }
}

impl IEphemeralKeyManager for EphemeralKeyManager {
    fn generate_ephemeral_key(
        &self,
        height: u64,
        block_hash: Hash,
        previous: Hash,
        now: u64,
    ) -> Result<EphemeralVerificationKey, EvkError> {
        let pair = KeyPair::generate();
        let public_key = pair.public();
        let key = EphemeralVerificationKey {
            session_id: Self::session_id(height, now),
            block_height: height,
            block_hash,
            public_key,
            previous_commitment: previous,
            key_chain_commitment: Self::compute_chaining_commitment(
                previous, public_key, height, block_hash,
            ),
            generated_at: now,
            expires_at: now.saturating_add(self.config.session_timeout_secs),
        };
        self.inner
            .lock()
            .unwrap()
            .active
            .insert(key.session_id, (key, Secret::new(pair.secret_seed())));
        Ok(key)
    }
    fn get_ephemeral_key(&self, session_id: Hash) -> Result<EphemeralVerificationKey, EvkError> {
        self.inner
            .lock()
            .unwrap()
            .active
            .get(&session_id)
            .map(|v| v.0)
            .ok_or(EvkError::SessionNotFound)
    }
    fn validate_key_chain(&self, key: &EphemeralVerificationKey, now: u64) -> Result<(), EvkError> {
        if now > key.expires_at {
            return Err(EvkError::Expired);
        }
        if Self::compute_chaining_commitment(
            key.previous_commitment,
            key.public_key,
            key.block_height,
            key.block_hash,
        ) != key.key_chain_commitment
        {
            return Err(EvkError::InvalidChain(key.block_height));
        }
        Ok(())
    }
}

pub trait IKeyChainValidator {
    fn validate_complete_chain(&self, end: u64) -> Result<(), EvkError>;
    fn validate_chain_segment(&self, start: u64, end: u64) -> Result<(), EvkError>;
    fn get_verification_proof(&self, height: u64) -> Result<VerificationProof, EvkError>;
}
impl IKeyChainValidator for EphemeralKeyManager {
    fn validate_complete_chain(&self, end: u64) -> Result<(), EvkError> {
        self.validate_chain_to_height(end)
    }
    fn validate_chain_segment(&self, start: u64, end: u64) -> Result<(), EvkError> {
        self.validate_chain_segment(start, end)
    }
    fn get_verification_proof(&self, height: u64) -> Result<VerificationProof, EvkError> {
        self.get_verification_proof(height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatus {
    pub migration_mode: bool,
    pub total_blocks: u64,
    pub keyed_blocks: u64,
    pub threshold_percent: u8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationEvent {
    Completed {
        keyed_blocks: u64,
        total_blocks: u64,
    },
    RolledBack,
}
#[derive(Clone)]
pub struct MigrationController {
    manager: EphemeralKeyManager,
    status: Arc<Mutex<MigrationStatus>>,
}
impl MigrationController {
    pub fn new(manager: EphemeralKeyManager) -> Self {
        let threshold = manager.config.migration_threshold_percent;
        Self {
            manager,
            status: Arc::new(Mutex::new(MigrationStatus {
                migration_mode: true,
                total_blocks: 0,
                keyed_blocks: 0,
                threshold_percent: threshold,
            })),
        }
    }
    pub fn observe_block(&self, has_key: bool) {
        let _ = self.observe_block_event(has_key);
    }
    pub fn observe_block_event(&self, has_key: bool) -> Option<MigrationEvent> {
        let mut s = self.status.lock().unwrap();
        let was_migration = s.migration_mode;
        s.total_blocks += 1;
        if has_key {
            s.keyed_blocks += 1;
        }
        if s.total_blocks > 0
            && s.keyed_blocks * 100 >= s.total_blocks * u64::from(s.threshold_percent)
        {
            s.migration_mode = false;
            if was_migration {
                return Some(MigrationEvent::Completed {
                    keyed_blocks: s.keyed_blocks,
                    total_blocks: s.total_blocks,
                });
            }
        }
        None
    }
    pub fn status(&self) -> MigrationStatus {
        *self.status.lock().unwrap()
    }
    pub fn migration_authorization_message(migration_mode: bool) -> Vec<u8> {
        [
            b"EVK_MIGRATION_ADMIN".as_slice(),
            &[u8::from(migration_mode)],
        ]
        .concat()
    }
    pub fn set_mode(
        &self,
        migration_mode: bool,
        authorization: &Sig,
        admin: &PublicKey,
    ) -> Result<(), EvkError> {
        if !verify(
            admin,
            &Self::migration_authorization_message(migration_mode),
            authorization,
        ) {
            return Err(EvkError::UnauthorizedMigration);
        }
        let was_migration = self.status.lock().unwrap().migration_mode;
        self.status.lock().unwrap().migration_mode = migration_mode;
        if !was_migration && migration_mode {
            let _ = MigrationEvent::RolledBack;
        }
        Ok(())
    }
    pub fn validate_header(&self, has_key: bool) -> Result<(), EvkError> {
        if !self.status().migration_mode && !has_key {
            Err(EvkError::MissingEphemeralKey)
        } else {
            Ok(())
        }
    }
    pub fn manager(&self) -> &EphemeralKeyManager {
        &self.manager
    }
}

pub trait IVerificationChainIntegrator {
    fn on_verification_start(
        &self,
        height: u64,
        block_hash: Hash,
        previous: Hash,
        now: u64,
    ) -> Result<EphemeralVerificationKey, EvkError>;
    fn on_verification_complete(&self, session: VerificationSession);
    fn on_verification_failure(&self, session_id: Hash, error: &EvkError);
    fn validate_block_ephemeral_key(
        &self,
        key: &EphemeralVerificationKey,
        now: u64,
    ) -> Result<(), EvkError>;
    fn get_next_block_ephemeral_key(&self) -> Option<PublicKey>;
    fn on_block_finalized(&self, height: u64, block_hash: Hash) -> Result<(), EvkError>;
}
#[derive(Clone)]
pub struct VerificationChainIntegrator {
    pub manager: EphemeralKeyManager,
    pub verifier: PublicKey,
}
impl IVerificationChainIntegrator for VerificationChainIntegrator {
    fn on_verification_start(
        &self,
        h: u64,
        b: Hash,
        p: Hash,
        n: u64,
    ) -> Result<EphemeralVerificationKey, EvkError> {
        self.manager.generate_ephemeral_key(h, b, p, n)
    }
    fn on_verification_complete(&self, s: VerificationSession) {
        self.manager.record_session(s.clone());
        let _ = self.manager.secure_erase(s.session_id);
    }
    fn on_verification_failure(&self, session_id: Hash, _error: &EvkError) {
        let _ = self.manager.secure_erase(session_id);
    }
    fn validate_block_ephemeral_key(
        &self,
        k: &EphemeralVerificationKey,
        n: u64,
    ) -> Result<(), EvkError> {
        self.manager.validate_key_chain(k, n)
    }
    fn get_next_block_ephemeral_key(&self) -> Option<PublicKey> {
        let state = self.manager.inner.lock().unwrap();
        state.historical.last_key_value().map(|(_, v)| v.public_key)
    }
    fn on_block_finalized(&self, _height: u64, _block_hash: Hash) -> Result<(), EvkError> {
        Ok(())
    }
}

pub trait ICrossChainEphemeralKeyIntegrator {
    fn record_destination_ephemeral_key(
        &self,
        chain_id: u64,
        key: EphemeralVerificationKey,
    ) -> Hash;
    fn validate_cross_chain_ephemeral_reference(
        &self,
        chain_id: u64,
        key: &EphemeralVerificationKey,
    ) -> Result<(), EvkError>;
    fn chain_cross_chain_states(
        &self,
        state: CrossChainVerificationState,
    ) -> Result<Hash, EvkError>;
    fn get_cross_chain_verification_state(
        &self,
        chain_id: u64,
    ) -> Option<CrossChainVerificationState>;
}
#[derive(Clone, Debug, Default)]
pub struct CrossChainEphemeralKeyIntegrator {
    states: Arc<Mutex<BTreeMap<u64, CrossChainVerificationState>>>,
}
impl ICrossChainEphemeralKeyIntegrator for CrossChainEphemeralKeyIntegrator {
    fn record_destination_ephemeral_key(
        &self,
        chain_id: u64,
        key: EphemeralVerificationKey,
    ) -> Hash {
        let commitment = hash_many(&[
            b"CROSS_CHAIN_EVK",
            &chain_id.to_le_bytes(),
            key.public_key.as_bytes(),
            key.key_chain_commitment.as_bytes(),
        ]);
        self.states.lock().unwrap().insert(
            chain_id,
            CrossChainVerificationState {
                chain_id,
                height: key.block_height,
                ephemeral_key: key.public_key,
                commitment,
                previous_cross_chain_state: Hash::zero(),
            },
        );
        commitment
    }
    fn validate_cross_chain_ephemeral_reference(
        &self,
        chain_id: u64,
        key: &EphemeralVerificationKey,
    ) -> Result<(), EvkError> {
        let state = self
            .states
            .lock()
            .unwrap()
            .get(&chain_id)
            .copied()
            .ok_or(EvkError::SessionNotFound)?;
        if state.ephemeral_key != key.public_key {
            return Err(EvkError::InvalidChain(key.block_height));
        }
        Ok(())
    }
    fn chain_cross_chain_states(
        &self,
        mut state: CrossChainVerificationState,
    ) -> Result<Hash, EvkError> {
        if let Some(previous) = self.states.lock().unwrap().get(&state.chain_id).copied() {
            state.previous_cross_chain_state = previous.commitment;
        }
        state.commitment = hash_many(&[
            b"CROSS_CHAIN_EVK",
            &state.chain_id.to_le_bytes(),
            state.ephemeral_key.as_bytes(),
            state.previous_cross_chain_state.as_bytes(),
            &state.height.to_le_bytes(),
        ]);
        let commitment = state.commitment;
        self.states.lock().unwrap().insert(state.chain_id, state);
        Ok(commitment)
    }
    fn get_cross_chain_verification_state(
        &self,
        chain_id: u64,
    ) -> Option<CrossChainVerificationState> {
        self.states.lock().unwrap().get(&chain_id).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    Peer,
    Administrator,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureNodeEnvelope {
    pub session_id: Hash,
    pub sequence: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub sender: PublicKey,
    pub role: NodeRole,
}
pub struct SecureNodeChannel {
    key: [u8; 32],
    session_id: Hash,
    sender: PublicKey,
    role: NodeRole,
    next_send: u64,
    received: BTreeSet<u64>,
}
impl SecureNodeChannel {
    pub fn handshake_transcript(
        local_exchange: &[u8; 32],
        peer_exchange: &[u8; 32],
        local_identity: &PublicKey,
        peer_identity: &PublicKey,
        local_role: NodeRole,
        peer_role: NodeRole,
        context: &[u8],
    ) -> Hash {
        let role_byte = |role| match role {
            NodeRole::Peer => 0u8,
            NodeRole::Administrator => 1u8,
        };
        let (first_exchange, second_exchange) = if local_exchange <= peer_exchange {
            (local_exchange, peer_exchange)
        } else {
            (peer_exchange, local_exchange)
        };
        let (first_identity, second_identity) =
            if local_identity.as_bytes() <= peer_identity.as_bytes() {
                (local_identity.as_bytes(), peer_identity.as_bytes())
            } else {
                (peer_identity.as_bytes(), local_identity.as_bytes())
            };
        let roles = if local_identity.as_bytes() <= peer_identity.as_bytes() {
            [role_byte(local_role), role_byte(peer_role)]
        } else {
            [role_byte(peer_role), role_byte(local_role)]
        };
        hash_many(&[
            b"EVK_HANDSHAKE",
            first_exchange,
            second_exchange,
            first_identity,
            second_identity,
            &roles,
            context,
        ])
    }

    pub fn establish(
        local: &KeyPair,
        local_role: NodeRole,
        peer: &PublicKey,
        context: &[u8],
    ) -> Self {
        let local_public = local.public();
        let (first, second) = if local_public.as_bytes() <= peer.as_bytes() {
            (local_public.as_bytes(), peer.as_bytes())
        } else {
            (peer.as_bytes(), local_public.as_bytes())
        };
        let shared = hash_many(&[b"EVK_CHANNEL", first, second, context]);
        let session_id = hash_many(&[b"EVK_SESSION_CHANNEL", shared.as_bytes()]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&shared.as_bytes()[..32]);
        Self {
            key,
            session_id,
            sender: local_public,
            role: local_role,
            next_send: 0,
            received: BTreeSet::new(),
        }
    }
    /// Establishes a channel from an X25519 shared secret and authenticates the
    /// transcript with the long-lived Ed25519 node identity.
    #[allow(clippy::too_many_arguments)]
    pub fn establish_authenticated(
        local: &KeyPair,
        local_role: NodeRole,
        exchange: &crate::x25519::X25519StaticKeyPair,
        peer_exchange: &[u8; 32],
        peer_identity: &PublicKey,
        peer_role: NodeRole,
        context: &[u8],
        peer_signature: &Sig,
    ) -> Result<Self, EvkError> {
        let local_identity = local.public();
        let transcript = Self::handshake_transcript(
            exchange.public().as_bytes(),
            peer_exchange,
            &local_identity,
            peer_identity,
            local_role,
            peer_role,
            context,
        );
        if !verify(peer_identity, transcript.as_bytes(), peer_signature) {
            return Err(EvkError::Authentication);
        }
        let peer = x25519_dalek::PublicKey::from(*peer_exchange);
        let shared = exchange.derive_shared_secret(&peer);
        let (derived, _) =
            crate::x25519::X25519KeyPair::derive_keys(&shared, transcript.as_bytes(), 32)
                .map_err(|_| EvkError::Authentication)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(Self {
            key,
            session_id: hash_many(&[b"EVK_SESSION_CHANNEL", transcript.as_bytes()]),
            sender: local.public(),
            role: local_role,
            next_send: 0,
            received: BTreeSet::new(),
        })
    }
    pub fn encrypt(&mut self, payload: &[u8]) -> Result<SecureNodeEnvelope, EvkError> {
        if payload.len() > 16 * 1024 * 1024 {
            return Err(EvkError::PayloadTooLarge);
        }
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = hash_many(&[
            self.session_id.as_bytes(),
            &self.next_send.to_le_bytes(),
            self.sender.as_bytes(),
        ]);
        let ciphertext = crate::aes256gcm::Aes256GcmCipher::new(&self.key)
            .encrypt(&nonce, payload, aad.as_bytes())
            .map_err(|_| EvkError::Authentication)?;
        let envelope = SecureNodeEnvelope {
            session_id: self.session_id,
            sequence: self.next_send,
            nonce,
            ciphertext,
            sender: self.sender,
            role: self.role,
        };
        self.next_send += 1;
        Ok(envelope)
    }
    pub fn decrypt(&mut self, envelope: &SecureNodeEnvelope) -> Result<Vec<u8>, EvkError> {
        if envelope.session_id != self.session_id || !self.received.insert(envelope.sequence) {
            return Err(EvkError::Replay);
        }
        let aad = hash_many(&[
            envelope.session_id.as_bytes(),
            &envelope.sequence.to_le_bytes(),
            envelope.sender.as_bytes(),
        ]);
        crate::aes256gcm::Aes256GcmCipher::new(&self.key)
            .decrypt(&envelope.nonce, &envelope.ciphertext, aad.as_bytes())
            .map_err(|_| EvkError::Authentication)
    }
    pub fn sender(&self) -> PublicKey {
        self.sender
    }
    pub fn role(&self) -> NodeRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn key_chain_and_erase() {
        let m = EphemeralKeyManager::new(EvkConfig::default());
        let k = m
            .generate_ephemeral_key(0, Hash::zero(), Hash::zero(), 1)
            .unwrap();
        m.validate_key_chain(&k, 2).unwrap();
        assert!(m.secure_erase(k.session_id).is_ok());
        assert!(m.get_ephemeral_key(k.session_id).is_err());
    }
    #[test]
    fn sessions_and_cross_chain() {
        let m = EphemeralKeyManager::new(EvkConfig::default());
        let k = m
            .generate_ephemeral_key(0, Hash::zero(), Hash::zero(), 1)
            .unwrap();
        m.record_session(VerificationSession {
            session_id: k.session_id,
            block_height: 0,
            block_hash: k.block_hash,
            ephemeral_key: k.public_key,
            previous_commitment: k.previous_commitment,
            next_commitment: k.key_chain_commitment,
            started_at: 1,
            completed_at: Some(2),
            verifier_node: KeyPair::generate().public(),
            result: Some(true),
            metadata: BTreeMap::new(),
        });
        m.validate_chain_to_height(0).unwrap();
        let c = CrossChainEphemeralKeyIntegrator::default();
        c.record_destination_ephemeral_key(7, k);
        c.validate_cross_chain_ephemeral_reference(7, &k).unwrap();
    }
    #[test]
    fn public_session_state_is_persistent_without_private_keys() {
        let manager = EphemeralKeyManager::new(EvkConfig::default());
        let key = manager
            .generate_ephemeral_key(0, Hash::zero(), Hash::zero(), 1)
            .unwrap();
        manager.record_session(VerificationSession {
            session_id: key.session_id,
            block_height: 0,
            block_hash: key.block_hash,
            ephemeral_key: key.public_key,
            previous_commitment: key.previous_commitment,
            next_commitment: key.key_chain_commitment,
            started_at: 1,
            completed_at: Some(2),
            verifier_node: KeyPair::generate().public(),
            result: Some(true),
            metadata: BTreeMap::new(),
        });
        let snapshot = manager.export_state();
        let restored = EphemeralKeyManager::new(EvkConfig::default());
        restored.import_state(&snapshot).unwrap();
        assert_eq!(
            restored.get_historical_key(0).unwrap(),
            manager.get_historical_key(0).unwrap()
        );
        assert!(restored.get_ephemeral_key(key.session_id).is_err());
    }
    #[test]
    fn migration_controller_requires_signed_mode_transition() {
        let manager = EphemeralKeyManager::new(EvkConfig::default());
        let controller = MigrationController::new(manager);
        let admin = KeyPair::generate();
        let signature = admin.sign(&MigrationController::migration_authorization_message(false));
        controller
            .set_mode(false, &signature, &admin.public())
            .unwrap();
        assert!(!controller.status().migration_mode);
        let bad = admin.sign(&MigrationController::migration_authorization_message(true));
        assert!(controller.set_mode(false, &bad, &admin.public()).is_err());
    }
    #[test]
    fn channel_authentication_and_replay_protection() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut tx = SecureNodeChannel::establish(&a, NodeRole::Peer, &b.public(), b"admin");
        let mut rx =
            SecureNodeChannel::establish(&b, NodeRole::Administrator, &a.public(), b"admin");
        let envelope = tx.encrypt(b"hello").unwrap();
        assert_eq!(rx.decrypt(&envelope).unwrap(), b"hello");
        assert_eq!(rx.decrypt(&envelope), Err(EvkError::Replay));
    }

    proptest! {
        #[test]
        fn generated_keys_are_unique(height in 0u64..100_000, timestamp in 0u64..u64::MAX) {
            let manager = EphemeralKeyManager::new(EvkConfig::default());
            let first = manager.generate_ephemeral_key(height, Hash::zero(), Hash::zero(), timestamp).unwrap();
            let second = manager.generate_ephemeral_key(height, Hash::zero(), Hash::zero(), timestamp).unwrap();
            prop_assert_ne!(first.public_key, second.public_key);
            prop_assert_ne!(first.session_id, second.session_id);
        }

        #[test]
        fn commitment_recomputation_is_stable(height in 0u64..100_000, timestamp in 0u64..u64::MAX) {
            let manager = EphemeralKeyManager::new(EvkConfig::default());
            let key = manager.generate_ephemeral_key(height, Hash::zero(), Hash::zero(), timestamp).unwrap();
            prop_assert_eq!(key.key_chain_commitment, EphemeralKeyManager::compute_chaining_commitment(key.previous_commitment, key.public_key, key.block_height, key.block_hash));
        }

        #[test]
        fn chain_continuity_across_chain_segment(
            heights in prop::collection::vec(0u64..10_000, 1..50),
            timestamps in prop::collection::vec(1u64..1_000_000, 1..50),
        ) {
            // Sort heights and ensure they are contiguous from 0 upward
            let mut sorted_heights: Vec<u64> = heights.clone();
            sorted_heights.sort();
            sorted_heights.dedup();
            if sorted_heights.first() != Some(&0) {
                sorted_heights.insert(0, 0);
            }
            // Make heights contiguous: 0,1,2,...
            let contiguous: Vec<u64> = (0..sorted_heights.len() as u64).collect();

            let manager = EphemeralKeyManager::new(EvkConfig::default());
            let mut previous = Hash::zero();
            let mut last_height: u64 = 0;
            for (i, &h) in contiguous.iter().enumerate() {
                let ts = timestamps.get(i).copied().unwrap_or(1);
                let key = manager.generate_ephemeral_key(h, Hash::zero(), previous, ts).unwrap();
                previous = key.key_chain_commitment;
                last_height = h;
                manager.record_session(VerificationSession {
                    session_id: key.session_id,
                    block_height: key.block_height,
                    block_hash: key.block_hash,
                    ephemeral_key: key.public_key,
                    previous_commitment: key.previous_commitment,
                    next_commitment: key.key_chain_commitment,
                    started_at: ts,
                    completed_at: Some(ts + 1),
                    verifier_node: KeyPair::generate().public(),
                    result: Some(true),
                    metadata: BTreeMap::new(),
                });
            }
            manager.validate_chain_segment(0, last_height).unwrap();
        }

        #[test]
        fn session_round_trip_preserves_data(
            block_height in 0u64..100_000,
            timestamp in 0u64..u64::MAX,
        ) {
            let manager = EphemeralKeyManager::new(EvkConfig::default());
            let key = manager.generate_ephemeral_key(block_height, Hash::zero(), Hash::zero(), timestamp).unwrap();
            let session = VerificationSession {
                session_id: key.session_id,
                block_height: key.block_height,
                block_hash: key.block_hash,
                ephemeral_key: key.public_key,
                previous_commitment: key.previous_commitment,
                next_commitment: key.key_chain_commitment,
                started_at: timestamp,
                completed_at: Some(timestamp + 1),
                verifier_node: PublicKey([0; 32]),
                result: Some(true),
                metadata: BTreeMap::new(),
            };
            manager.record_session(session.clone());
            let retrieved = manager.get_session(key.session_id).unwrap();
            prop_assert_eq!(session, retrieved);
        }

        #[test]
        fn genesis_commitment_is_deterministic(
            seed in 0u64..1_000_000,
        ) {
            let public_key = {
                let kp = KeyPair::from_seed(&[0u8; 32]);
                kp.public()
            };
            let block_hash = hash_many(&[&seed.to_le_bytes()]);
            let c1 = EphemeralKeyManager::compute_chaining_commitment(Hash::zero(), public_key, seed, block_hash);
            let c2 = EphemeralKeyManager::compute_chaining_commitment(Hash::zero(), public_key, seed, block_hash);
            prop_assert_eq!(c1, c2);
        }
    }

    #[test]
    fn file_key_chain_commitment_uses_distinct_domain() {
        let public_key = KeyPair::from_seed(&[0u8; 32]).public();
        let content_hash = hash(b"file-data");
        let evk = EphemeralKeyManager::compute_chaining_commitment(
            Hash::zero(),
            public_key,
            1,
            Hash::zero(),
        );
        let file = EphemeralKeyManager::compute_file_key_chain_commitment(
            Hash::zero(),
            content_hash,
            1,
            Hash::zero(),
        );
        assert_ne!(evk, file);
    }

    #[test]
    fn file_key_chain_commitment_is_deterministic() {
        let content_hash = hash(b"file-data");
        let previous = Hash::zero();
        let c1 = EphemeralKeyManager::compute_file_key_chain_commitment(
            previous,
            content_hash,
            5,
            Hash::zero(),
        );
        let c2 = EphemeralKeyManager::compute_file_key_chain_commitment(
            previous,
            content_hash,
            5,
            Hash::zero(),
        );
        assert_eq!(c1, c2);
    }

    #[test]
    fn file_key_chain_validates_and_rejects_tampering() {
        let node = KeyPair::from_seed(&[1u8; 32]);
        let block_hash = hash(b"block");
        let content_hash = hash(b"file-content");
        let commitment = EphemeralKeyManager::compute_file_key_chain_commitment(
            Hash::zero(),
            content_hash,
            1,
            block_hash,
        );
        let label = FileEvkLabel {
            content_hash,
            key_chain_commitment: commitment,
            node: node.public(),
            block_height: 1,
            block_hash,
            previous_commitment: Hash::zero(),
            size: 100,
            signature: node.sign(
                &file_label_commitment(&FileEvkLabel {
                    content_hash,
                    key_chain_commitment: commitment,
                    node: node.public(),
                    block_height: 1,
                    block_hash,
                    previous_commitment: Hash::zero(),
                    size: 100,
                    signature: Sig([0u8; 64]),
                })
                .0,
            ),
        };
        assert!(label.is_valid());
        let mut chain = FileKeyChain::default();
        chain.insert(label);
        assert!(chain.validate().is_ok());

        let mut tampered = chain.clone();
        tampered.labels.insert(
            2,
            FileEvkLabel {
                content_hash,
                key_chain_commitment: Hash::zero(),
                node: node.public(),
                block_height: 2,
                block_hash,
                previous_commitment: commitment,
                size: 100,
                signature: Sig([0u8; 64]),
            },
        );
        assert!(tampered.validate().is_err());
    }
}
