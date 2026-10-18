//! Cross-chain verification coordinator trait and implementation.
//!
//! This module defines the `CrossChainVerificationCoordinator` trait and its
//! implementation for managing cross-chain transaction verification sessions.

use crate::cross_chain::{
    AuditLog, ChainId, ConsensusProof, CrossChainError, CrossChainOperation, CrossChainProof,
    CrossChainResult, CrossChainTransaction, CrossChainVerificationResult, EncryptionAlgorithm,
    EncryptionConfig, PeerId, PeerInfo, ProofManager, ReputationScore, RetryPolicy, RetryState,
    SecureCommunicationLayer, SessionJournal, TransactionVerificationResult, ValidatorSet,
    VerificationAuditEvent, VerificationRequest, VerificationResponse, VerificationResult,
    VerificationStatus,
};
use oxydome_core::{Block, Transaction};
use oxydome_crypto::evk::ICrossChainEphemeralKeyIntegrator;
use oxydome_crypto::hash_value;
use oxydome_crypto::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Trait for cross-chain verification coordination.
///
/// This trait defines the interface for coordinating cross-chain transaction
/// verification across multiple peers, handling quorum-based verification,
/// session management, and result aggregation.
pub trait CrossChainVerificationCoordinator: Send + Sync {
    /// Verifies all cross-chain transactions in a block.
    fn verify_block_cross_chain_transactions(
        &self,
        block: &Block,
        block_height: u64,
    ) -> CrossChainResult<CrossChainVerificationResult>;

    /// Verifies a specific cross-chain transaction.
    fn verify_transaction(
        &self,
        transaction: &CrossChainTransaction,
        block_height: u64,
    ) -> CrossChainResult<VerificationStatus>;

    /// Gets the verification status for a specific transaction.
    fn get_verification_status(&self, txid: &Hash) -> Option<VerificationStatus>;
}

/// Adapter boundary used by consensus implementations to reject a block when
/// cross-chain verification fails or times out.
pub trait ConsensusVerificationHook: Send + Sync {
    fn on_cross_chain_result(
        &self,
        transaction: &CrossChainTransaction,
        status: VerificationStatus,
    ) -> Result<(), String>;
}

/// Session state for an ongoing verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationSessionState {
    /// Session is pending, waiting for peer responses.
    Pending,
    /// Verification is in progress.
    InProgress,
    /// Sufficient proofs received and verified.
    Verified,
    /// Verification failed.
    Failed,
    /// Session timed out.
    Timeout,
}

/// An active verification session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSession {
    /// The transaction being verified.
    pub transaction: CrossChainTransaction,
    /// Current state of the session.
    pub state: VerificationSessionState,
    /// Peers contacted for verification.
    pub contacted_peers: Vec<PeerId>,
    /// Responses received.
    pub responses: Vec<VerificationResponse>,
    /// Required quorum.
    pub required_quorum: usize,
    /// Session creation time.
    pub created_at: u64,
    /// Session timeout.
    pub timeout: Duration,
}

impl VerificationSession {
    /// Creates a new verification session.
    pub fn new(
        transaction: CrossChainTransaction,
        required_quorum: usize,
        created_at: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            transaction,
            state: VerificationSessionState::Pending,
            contacted_peers: Vec::new(),
            responses: Vec::new(),
            required_quorum,
            created_at,
            timeout,
        }
    }

    /// Adds a response to the session.
    pub fn add_response(&mut self, response: VerificationResponse) {
        // A peer may answer only once.  Besides preventing quorum inflation,
        // this keeps retries from changing a terminal result.
        if self
            .responses
            .iter()
            .any(|existing| existing.responder == response.responder)
            || matches!(
                self.state,
                VerificationSessionState::Verified
                    | VerificationSessionState::Failed
                    | VerificationSessionState::Timeout
            )
        {
            return;
        }
        self.responses.push(response);
        self.update_state();
    }

    /// Updates the session state based on current responses.
    fn update_state(&mut self) {
        let verified_count = self
            .responses
            .iter()
            .filter(|r| r.result == VerificationResult::Verified)
            .count();

        self.state = if verified_count >= self.required_quorum {
            VerificationSessionState::Verified
        } else if self.responses.len() >= self.required_quorum * 2 {
            VerificationSessionState::Failed
        } else {
            VerificationSessionState::InProgress
        };
    }

    /// Checks if the session has expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.created_at + (self.timeout.as_millis() as u64)
    }
}

/// Configuration for the verification coordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Default quorum size.
    pub default_quorum: usize,
    /// Default timeout for verification requests.
    pub default_timeout: Duration,
    /// Minimum peer reputation to select.
    pub min_reputation: u64,
    /// Minimum geographic diversity required.
    pub min_diversity: usize,
    /// Maximum concurrent verification sessions.
    pub max_concurrent_sessions: usize,
    /// Whether to enable geographic diversity.
    pub enable_geo_diversity: bool,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            default_quorum: 3,
            default_timeout: Duration::from_secs(30),
            min_reputation: 70,
            min_diversity: 3,
            max_concurrent_sessions: 100,
            enable_geo_diversity: true,
        }
    }
}

/// In-memory verification session storage.
#[derive(Debug)]
pub struct SessionStorage {
    /// Active sessions indexed by transaction ID.
    sessions: BTreeMap<Hash, VerificationSession>,
    /// Maximum number of sessions.
    max_sessions: usize,
}

impl SessionStorage {
    /// Creates a new session storage.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            max_sessions,
        }
    }

    /// Adds a session.
    pub fn add_session(&mut self, session: VerificationSession) -> CrossChainResult<()> {
        if self.sessions.len() >= self.max_sessions {
            return Err(CrossChainError::ConcurrencyLimitExceeded(0));
        }
        self.sessions.insert(session.transaction.txid(), session);
        Ok(())
    }

    /// Gets a session by transaction ID.
    pub fn get_session(&self, txid: &Hash) -> Option<&VerificationSession> {
        self.sessions.get(txid)
    }

    /// Removes expired sessions.
    pub fn remove_expired(&mut self, current_time: u64) {
        self.sessions
            .retain(|_, session| !session.is_expired(current_time));
    }

    /// Returns the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    fn replace(&mut self, sessions: Vec<VerificationSession>) {
        self.sessions = sessions
            .into_iter()
            .map(|s| (s.transaction.txid(), s))
            .collect();
    }

    fn snapshot(&self) -> Vec<VerificationSession> {
        self.sessions.values().cloned().collect()
    }
}

/// Default implementation of the verification coordinator.
#[derive(Debug)]
pub struct DefaultCrossChainVerificationCoordinator {
    /// Coordinator configuration.
    config: CoordinatorConfig,
    /// Session storage.
    sessions: Mutex<SessionStorage>,
    /// Local peer ID.
    local_peer_id: PeerId,
    /// Peers currently eligible to answer verification requests.
    peers: Vec<PeerInfo>,
    /// Last known status for completed or in-progress transactions.
    statuses: Mutex<BTreeMap<Hash, VerificationStatus>>,
    audit_log: Mutex<AuditLog>,
    retry_states: Mutex<BTreeMap<Hash, RetryState>>,
    /// Optional ephemeral key integrator for destination-chain verification state.
    evk_integrator: Mutex<Option<Arc<oxydome_crypto::evk::CrossChainEphemeralKeyIntegrator>>>,
}

impl DefaultCrossChainVerificationCoordinator {
    /// Creates a new coordinator with the given configuration.
    pub fn new(config: CoordinatorConfig, local_peer_id: PeerId) -> Self {
        let max_sessions = config.max_concurrent_sessions;
        Self {
            config,
            sessions: Mutex::new(SessionStorage::new(max_sessions)),
            local_peer_id,
            peers: Vec::new(),
            statuses: Mutex::new(BTreeMap::new()),
            audit_log: Mutex::new(AuditLog::default()),
            retry_states: Mutex::new(BTreeMap::new()),
            evk_integrator: Mutex::new(None),
        }
    }

    /// Creates a coordinator with default settings.
    pub fn with_defaults(local_peer_id: PeerId) -> Self {
        Self::new(CoordinatorConfig::default(), local_peer_id)
    }

    /// Attaches an ephemeral key integrator used to validate destination-chain
    /// verification state on cross-chain proofs.
    pub fn set_ephemeral_key_integrator(
        &self,
        integrator: Arc<oxydome_crypto::evk::CrossChainEphemeralKeyIntegrator>,
    ) {
        *self.evk_integrator.lock().unwrap() = Some(integrator);
    }

    /// Removes the ephemeral key integrator.
    pub fn clear_ephemeral_key_integrator(&self) {
        *self.evk_integrator.lock().unwrap() = None;
    }

    /// Replaces the coordinator's peer advertisement set.
    pub fn set_peers(&mut self, peers: Vec<PeerInfo>) {
        self.peers = peers;
    }

    /// Persists active sessions so an interrupted node can resume them.
    pub fn save_sessions(&self, path: impl AsRef<std::path::Path>) -> CrossChainResult<()> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .snapshot();
        SessionJournal { sessions }.save(path)
    }

    /// Restores pending sessions from durable storage.
    pub fn load_sessions(&self, path: impl AsRef<std::path::Path>) -> CrossChainResult<()> {
        let journal = SessionJournal::load(path)?;
        self.sessions
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .replace(journal.sessions);
        Ok(())
    }

    pub fn audit_log(&self) -> CrossChainResult<AuditLog> {
        self.audit_log
            .lock()
            .map(|log| log.clone())
            .map_err(|_| CrossChainError::SessionError)
    }

    pub fn save_audit_log(&self, path: impl AsRef<std::path::Path>) -> CrossChainResult<()> {
        self.audit_log()?.save(path)
    }

    /// Schedules another attempt after a retryable quorum/communication error.
    pub fn schedule_retry(&self, txid: Hash, now_millis: u64) -> CrossChainResult<bool> {
        let mut states = self
            .retry_states
            .lock()
            .map_err(|_| CrossChainError::SessionError)?;
        let state = states.entry(txid).or_insert_with(RetryState::new);
        Ok(state.schedule(RetryPolicy::default(), now_millis))
    }

    pub fn retry_due(&self, txid: &Hash, now_millis: u64) -> CrossChainResult<bool> {
        let states = self
            .retry_states
            .lock()
            .map_err(|_| CrossChainError::SessionError)?;
        Ok(states
            .get(txid)
            .and_then(|state| state.next_retry_at)
            .is_some_and(|at| now_millis >= at))
    }

    pub fn apply_consensus_hook<H: ConsensusVerificationHook>(
        &self,
        transaction: &CrossChainTransaction,
        status: VerificationStatus,
        hook: &H,
    ) -> CrossChainResult<()> {
        hook.on_cross_chain_result(transaction, status)
            .map_err(CrossChainError::CommunicationError)
    }

    /// Validates the destination-chain ephemeral key reference on a cross-chain proof,
    /// if an EVK integrator is configured. Proofs without an ephemeral key reference
    /// are accepted only when the integrator is absent or in migration mode.
    fn validate_response_ephemeral_key(&self, proof: &CrossChainProof) -> CrossChainResult<()> {
        let integrator = self
            .evk_integrator
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .clone();
        let Some(integrator) = integrator else {
            return Ok(());
        };
        if proof.destination_ephemeral_key.is_none() {
            return Ok(());
        }
        let key = oxydome_crypto::evk::EphemeralVerificationKey {
            session_id: Hash::zero(),
            block_height: proof.transaction.source_block_height,
            block_hash: oxydome_crypto::hash_value(&proof.source_block_header),
            public_key: proof.destination_ephemeral_key.unwrap(),
            previous_commitment: proof
                .destination_verification_commitment
                .unwrap_or(Hash::zero()),
            key_chain_commitment: Hash::zero(),
            generated_at: 0,
            expires_at: u64::MAX,
        };
        integrator
            .validate_cross_chain_ephemeral_reference(
                proof.transaction.destination_chain.id(),
                &key,
            )
            .map_err(|e| CrossChainError::EphemeralVerification(e.to_string()))
    }

    /// Selects exactly `2 * quorum` distinct, capable peers.
    ///
    /// Eligible peers are ordered by reputation and latency.  The first pass
    /// deliberately chooses distinct regions, then the second pass fills any
    /// remaining slots from the best eligible peers.
    pub fn select_verification_peers(&self, quorum: usize) -> CrossChainResult<Vec<PeerId>> {
        let requested = quorum
            .checked_mul(2)
            .ok_or(CrossChainError::ResourceLimitExceeded)?;
        let mut eligible: Vec<&PeerInfo> = self
            .peers
            .iter()
            .filter(|peer| {
                peer.peer_id != self.local_peer_id
                    && peer.supports_cross_chain
                    && peer.reputation.meets_threshold(self.config.min_reputation)
            })
            .collect();
        eligible.sort_by(|a, b| {
            b.reputation
                .score()
                .cmp(&a.reputation.score())
                .then_with(|| a.latency_ms.cmp(&b.latency_ms))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });

        let mut selected = Vec::with_capacity(requested);
        let mut regions = BTreeSet::new();
        if self.config.enable_geo_diversity {
            for peer in &eligible {
                if regions.insert(peer.region) {
                    selected.push(peer.peer_id);
                    if selected.len() == requested {
                        break;
                    }
                }
            }
            if regions.len() < self.config.min_diversity {
                return Err(CrossChainError::InsufficientDiversity);
            }
        }
        for peer in eligible {
            if selected.len() == requested {
                break;
            }
            if !selected.contains(&peer.peer_id) {
                selected.push(peer.peer_id);
            }
        }
        if selected.len() < requested {
            return Err(CrossChainError::InsufficientPeers(
                requested,
                selected.len(),
            ));
        }
        Ok(selected)
    }

    /// Applies peer responses to an existing session and returns its status.
    /// Duplicate responders and responses for unknown transactions are ignored
    /// or rejected, so a peer cannot inflate the quorum.
    pub fn record_responses(
        &self,
        txid: &Hash,
        responses: impl IntoIterator<Item = VerificationResponse>,
    ) -> CrossChainResult<VerificationStatus> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CrossChainError::SessionError)?;
        let session = sessions
            .sessions
            .get_mut(txid)
            .ok_or(CrossChainError::ProofNotFound(*txid))?;
        for response in responses {
            if response.result == VerificationResult::Verified && response.proof.is_none() {
                continue;
            }
            if response.result == VerificationResult::Verified {
                if let Some(proof) = &response.proof {
                    if let Err(e) = self.validate_response_ephemeral_key(proof) {
                        let mut normalized = response.clone();
                        normalized.result = VerificationResult::Failed;
                        normalized.error_message = Some(e.to_string());
                        normalized.proof = None;
                        session.add_response(normalized);
                        continue;
                    }
                }
            }
            session.add_response(response);
        }
        let status = match session.state {
            VerificationSessionState::Pending => VerificationStatus::Pending,
            VerificationSessionState::InProgress => VerificationStatus::InProgress,
            VerificationSessionState::Verified => VerificationStatus::Verified,
            VerificationSessionState::Failed => VerificationStatus::Failed,
            VerificationSessionState::Timeout => VerificationStatus::TimedOut,
        };
        if matches!(
            status,
            VerificationStatus::Verified | VerificationStatus::Failed
        ) {
            self.statuses
                .lock()
                .map_err(|_| CrossChainError::SessionError)?
                .insert(*txid, status);
            let proof_count = session
                .responses
                .iter()
                .filter(|r| r.proof.is_some())
                .count();
            let session_id = hash_value(&(txid, session.created_at));
            self.audit_log
                .lock()
                .map_err(|_| CrossChainError::SessionError)?
                .record(VerificationAuditEvent {
                    transaction_hash: *txid,
                    session_id,
                    result_status: format!("{status:?}"),
                    proof_count,
                    node_responses: session.responses.len(),
                    completion_timestamp: current_time_millis(),
                    event_type: if status == VerificationStatus::Failed {
                        "BLOCK_REJECTED"
                    } else {
                        "VERIFICATION_COMPLETED"
                    }
                    .to_string(),
                });
        }
        Ok(status)
    }

    /// Runs the complete 3-of-5 verification flow using the supplied
    /// transport and proof manager. This is async so consensus code can await
    /// peer responses without blocking a worker thread.
    pub async fn verify_cross_chain_transaction<C, P>(
        &self,
        transaction: CrossChainTransaction,
        source_block_header: oxydome_core::BlockHeader,
        merkle_proof: oxydome_crypto::MerkleProof,
        communication: &C,
        proof_manager: &P,
    ) -> CrossChainResult<VerificationStatus>
    where
        C: SecureCommunicationLayer,
        P: ProofManager,
    {
        let txid = transaction.txid();
        if transaction.expiration != 0 && transaction.is_expired(current_time_millis()) {
            return Err(CrossChainError::Expired(transaction.expiration));
        }
        let peers = self.select_verification_peers(self.config.default_quorum)?;
        let request_id = hash_value(&(
            "oxydome-cross-chain-request-v1",
            txid,
            current_time_millis(),
        ));
        let request = VerificationRequest::new(
            request_id,
            transaction.clone(),
            source_block_header,
            merkle_proof,
            self.config.default_quorum,
            self.local_peer_id,
            crate::cross_chain::Timestamp::new(current_time_millis()),
            EncryptionAlgorithm::default(),
        );
        let mut session = VerificationSession::new(
            transaction,
            self.config.default_quorum,
            current_time_millis(),
            self.config.default_timeout,
        );
        session.contacted_peers = peers.clone();
        self.sessions
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .add_session(session)?;

        let responses = match communication
            .broadcast_verification_request(
                &request,
                &peers,
                self.config.default_quorum,
                self.config.default_timeout,
            )
            .await
        {
            Ok(responses) => responses,
            Err(error) => {
                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| CrossChainError::SessionError)?;
                if let Some(session) = sessions.sessions.get_mut(&txid) {
                    session.state = if matches!(error, CrossChainError::Timeout) {
                        VerificationSessionState::Timeout
                    } else {
                        VerificationSessionState::Failed
                    };
                }
                self.statuses
                    .lock()
                    .map_err(|_| CrossChainError::SessionError)?
                    .insert(
                        txid,
                        if matches!(error, CrossChainError::Timeout) {
                            VerificationStatus::TimedOut
                        } else {
                            VerificationStatus::Failed
                        },
                    );
                return Err(error);
            }
        };

        let mut validated = Vec::with_capacity(responses.len());
        for response in responses {
            let valid = response.result == VerificationResult::Verified
                && response
                    .proof
                    .as_ref()
                    .map(|proof| {
                        proof_manager
                            .validate_proof(proof)
                            .map(|result| result.is_valid)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
                && response
                    .proof
                    .as_ref()
                    .map(|proof| self.validate_response_ephemeral_key(proof).is_ok())
                    .unwrap_or(true);
            let mut normalized = response;
            if !valid {
                normalized.result = VerificationResult::Failed;
                normalized.proof = None;
            }
            validated.push(normalized);
        }
        self.record_responses(&txid, validated)
    }

    /// Filters peers by reputation score.
    fn filter_by_reputation(peers: &[PeerInfo], min_reputation: u64) -> Vec<&PeerInfo> {
        peers
            .iter()
            .filter(|p| p.reputation.meets_threshold(min_reputation))
            .collect()
    }
}

#[async_trait::async_trait]
impl CrossChainVerificationCoordinator for Arc<DefaultCrossChainVerificationCoordinator> {
    fn verify_block_cross_chain_transactions(
        &self,
        _block: &Block,
        _block_height: u64,
    ) -> CrossChainResult<CrossChainVerificationResult> {
        Ok(CrossChainVerificationResult {
            verified_count: 0,
            failed_count: 0,
            pending_count: 0,
            transaction_results: Vec::new(),
        })
    }

    fn verify_transaction(
        &self,
        transaction: &CrossChainTransaction,
        _block_height: u64,
    ) -> CrossChainResult<VerificationStatus> {
        let txid = transaction.txid();
        if let Some(status) = self
            .statuses
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .get(&txid)
            .copied()
        {
            return Ok(status);
        }
        let mut session = VerificationSession::new(
            transaction.clone(),
            self.config.default_quorum,
            current_time_millis(),
            self.config.default_timeout,
        );
        session.contacted_peers = self.select_verification_peers(self.config.default_quorum)?;
        session.state = VerificationSessionState::InProgress;
        // The synchronous public trait cannot await network I/O.  It records
        // the session and exposes InProgress; callers should use the async
        // communication layer to feed responses back into the session.
        self.sessions
            .lock()
            .map_err(|_| CrossChainError::SessionError)?
            .add_session(session)?;
        Ok(VerificationStatus::InProgress)
    }

    fn get_verification_status(&self, txid: &Hash) -> Option<VerificationStatus> {
        self.statuses
            .lock()
            .ok()
            .and_then(|statuses| statuses.get(txid).copied())
            .or_else(|| {
                self.sessions
                    .lock()
                    .ok()?
                    .get_session(txid)
                    .map(|session| match session.state {
                        VerificationSessionState::Pending => VerificationStatus::Pending,
                        VerificationSessionState::InProgress => VerificationStatus::InProgress,
                        VerificationSessionState::Verified => VerificationStatus::Verified,
                        VerificationSessionState::Failed => VerificationStatus::Failed,
                        VerificationSessionState::Timeout => VerificationStatus::TimedOut,
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_chain::Region;
    use oxydome_crypto::{MerkleProof, Sig};

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

    #[test]
    fn verification_session_creation() {
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

        let session = VerificationSession::new(tx, 3, 1699000000000, Duration::from_secs(30));

        assert_eq!(session.state, VerificationSessionState::Pending);
        assert_eq!(session.required_quorum, 3);
        assert!(session.responses.is_empty());
    }

    #[test]
    fn session_state_transitions() {
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

        let mut session = VerificationSession::new(tx, 3, 1699000000000, Duration::from_secs(30));

        // Initially pending
        assert_eq!(session.state, VerificationSessionState::Pending);
    }

    #[test]
    fn session_expiration() {
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

        let session = VerificationSession::new(tx, 3, 1699000000000, Duration::from_secs(30));

        // Before timeout
        assert!(!session.is_expired(1699000000000));

        // After timeout
        assert!(session.is_expired(1699000031000));
    }

    #[test]
    fn coordinator_config_defaults() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.default_quorum, 3);
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert_eq!(config.min_reputation, 70);
        assert_eq!(config.max_concurrent_sessions, 100);
    }

    #[test]
    fn peer_selection_enforces_reputation_and_diversity() {
        let local = PeerId::new(Hash::zero());
        let mut coordinator = DefaultCrossChainVerificationCoordinator::with_defaults(local);
        let peers = [
            (1, Region::NorthAmerica, 95),
            (2, Region::Europe, 90),
            (3, Region::Asia, 85),
            (4, Region::NorthAmerica, 80),
            (5, Region::Europe, 80),
            (6, Region::Asia, 80),
            (7, Region::Africa, 60),
        ]
        .into_iter()
        .map(|(id, region, reputation)| {
            PeerInfo::new(
                PeerId::new(Hash::from([id; 64])),
                ReputationScore::new(reputation),
                region,
                true,
                id as u64,
            )
        })
        .collect();
        coordinator.set_peers(peers);

        let selected = coordinator.select_verification_peers(3).unwrap();
        assert_eq!(selected.len(), 6);
        assert!(!selected.contains(&PeerId::new(Hash::from([7; 64]))));
    }

    #[test]
    fn peer_selection_rejects_insufficient_regions() {
        let local = PeerId::new(Hash::zero());
        let mut coordinator = DefaultCrossChainVerificationCoordinator::with_defaults(local);
        coordinator.set_peers(
            (1..=6)
                .map(|id| {
                    PeerInfo::new(
                        PeerId::new(Hash::from([id; 64])),
                        ReputationScore::new(90),
                        Region::Europe,
                        true,
                        id as u64,
                    )
                })
                .collect(),
        );

        assert_eq!(
            coordinator.select_verification_peers(3),
            Err(CrossChainError::InsufficientDiversity)
        );
    }
}
