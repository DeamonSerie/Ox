//! Secure communication layer for cross-chain verification.
//!
//! This module defines the `SecureCommunicationLayer` trait and its
//! implementation for encrypted peer-to-peer verification requests.

use crate::cross_chain::crypto_utils;
use crate::cross_chain::ProofManager;
use crate::cross_chain::{
    ConsensusProof, CrossChainError, CrossChainOperation, CrossChainProof, CrossChainResult,
    CrossChainTransaction, EncryptionAlgorithm, EncryptionConfig, PeerId, ValidatorSet,
    VerificationRequest, VerificationResponse,
};
use async_trait::async_trait;
use futures_util::future::join_all;
use oxydome_core::{Block, Transaction};
use oxydome_crypto::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Transport-independent endpoint for verification requests.
#[async_trait]
pub trait VerificationPeerHandler: Send + Sync {
    /// Completes the peer side of the X25519 handshake. The returned value is
    /// the raw shared secret and must never be persisted by the handler.
    async fn establish_channel(
        &self,
        _initiator_public_key: [u8; 32],
    ) -> CrossChainResult<[u8; 32]> {
        Err(CrossChainError::KeyExchangeError(
            "peer does not support secure-channel handshakes".into(),
        ))
    }

    async fn handle_verification_request(
        &self,
        request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse>;
}

/// Local-chain request handler used by a node receiving a verification request.
/// Blocks are indexed by source transaction ID, so a missing transaction returns
/// an explicit failure response instead of silently voting against the request.
pub struct LocalVerificationHandler<P: ProofManager> {
    responder: PeerId,
    proof_manager: Arc<P>,
    blocks: std::sync::Mutex<BTreeMap<Hash, Block>>,
}

impl<P: ProofManager> LocalVerificationHandler<P> {
    pub fn new(responder: PeerId, proof_manager: Arc<P>) -> Self {
        Self {
            responder,
            proof_manager,
            blocks: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    pub fn index_block(&self, block: Block) {
        if let Ok(mut blocks) = self.blocks.lock() {
            for transaction in &block.transactions {
                blocks.insert(transaction.txid(), block.clone());
            }
        }
    }
}

#[async_trait]
impl<P: ProofManager> VerificationPeerHandler for LocalVerificationHandler<P> {
    async fn handle_verification_request(
        &self,
        request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse> {
        let source_txid = request.transaction.source_txid;
        let block = self
            .blocks
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("local block index poisoned".into()))?
            .get(&source_txid)
            .cloned();
        let Some(block) = block else {
            return Ok(VerificationResponse::failure(
                request.request_id,
                "source transaction not found on local chain".into(),
                self.responder,
                oxydome_crypto::Sig([0; 64]),
            ));
        };
        let transaction: Transaction = block
            .transactions
            .iter()
            .find(|transaction| transaction.txid() == source_txid)
            .cloned()
            .ok_or(CrossChainError::TransactionNotFound(source_txid))?;
        let proof = self.proof_manager.create_proof(&transaction, &block)?;
        Ok(VerificationResponse::success(
            request.request_id,
            proof,
            self.responder,
            oxydome_crypto::Sig([0; 64]),
        ))
    }
}

/// A channel binding ID for encrypting messages bound to a specific session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelBinding(pub [u8; 32]);

impl ChannelBinding {
    /// Creates a new channel binding.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Trait for secure peer-to-peer communication.
///
/// This trait defines the interface for encrypted communication with peers
/// during cross-chain verification, including key exchange, message encryption,
/// and request/response handling.
#[async_trait]
pub trait SecureCommunicationLayer: Send + Sync {
    /// Requests verification from a single peer.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to request verification from.
    /// * `request` - The verification request.
    /// * `timeout` - The timeout for the request.
    ///
    /// # Returns
    ///
    /// The verification response or an error.
    async fn request_verification(
        &self,
        peer: &PeerId,
        request: &VerificationRequest,
        timeout: Duration,
    ) -> CrossChainResult<VerificationResponse>;

    /// Broadcasts a verification request to multiple peers.
    ///
    /// # Arguments
    ///
    /// * `request` - The verification request.
    /// * `peers` - The peers to send the request to.
    /// * `quorum` - The number of responses needed.
    /// * `timeout` - The timeout for the broadcast.
    ///
    /// # Returns
    ///
    /// A vector of responses from peers.
    async fn broadcast_verification_request(
        &self,
        request: &VerificationRequest,
        peers: &[PeerId],
        quorum: usize,
        timeout: Duration,
    ) -> CrossChainResult<Vec<VerificationResponse>>;

    /// Handles an incoming verification request.
    ///
    /// # Arguments
    ///
    /// * `request` - The incoming verification request.
    ///
    /// # Returns
    ///
    /// The verification response.
    async fn handle_verification_request(
        &self,
        request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse>;

    /// Establishes a secure channel with a peer.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to establish a channel with.
    ///
    /// # Returns
    ///
    /// The channel binding ID or an error.
    async fn establish_secure_channel(&self, peer: &PeerId) -> CrossChainResult<ChannelBinding>;

    /// Closes a secure channel with a peer.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to close the channel with.
    async fn close_secure_channel(&self, peer: &PeerId) -> CrossChainResult<()>;
}

/// Secure channel state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureChannelState {
    /// Channel is being established.
    Establishing,
    /// Channel is ready for communication.
    Ready,
    /// Channel is closing.
    Closing,
    /// Channel has been closed.
    Closed,
}

/// Information about an established secure channel.
#[derive(Debug, Clone, PartialEq)]
pub struct SecureChannel {
    /// The peer this channel connects to.
    pub peer: PeerId,
    /// Current state of the channel.
    pub state: SecureChannelState,
    /// Encryption algorithm for this channel.
    pub algorithm: EncryptionAlgorithm,
    /// Channel binding ID.
    pub binding: ChannelBinding,
    /// Last activity timestamp.
    pub last_activity: u64,
    /// Number of messages sent.
    pub messages_sent: u64,
    /// Number of messages received.
    pub messages_received: u64,
}

impl SecureChannel {
    /// Creates a new secure channel.
    pub fn new(peer: PeerId, algorithm: EncryptionAlgorithm, binding: ChannelBinding) -> Self {
        Self {
            peer,
            state: SecureChannelState::Ready,
            algorithm,
            binding,
            last_activity: 0,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// Marks the channel as active.
    pub fn mark_active(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.messages_sent += 1;
    }

    /// Marks a message as received.
    pub fn mark_received(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.messages_received += 1;
    }
}

/// Secure channel storage and management.
#[derive(Debug, Default)]
pub struct ChannelStorage {
    /// Active channels indexed by peer ID.
    channels: BTreeMap<PeerId, SecureChannel>,
    /// Maximum number of channels.
    max_channels: usize,
}

/// Reusable peer connection registry. The secure layer keeps channels alive in
/// this pool, avoiding a new handshake for every verification request.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    connections: BTreeMap<PeerId, ChannelBinding>,
    unhealthy: BTreeMap<PeerId, u64>,
    max_connections: usize,
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn connection_pool_reuses_and_health_checks_bindings() {
        let peer = PeerId::new(oxydome_crypto::Hash::zero());
        let binding = ChannelBinding::new([7; 32]);
        let mut pool = ConnectionPool::new(1);
        pool.insert(peer, binding).unwrap();
        assert_eq!(pool.get(&peer), Some(binding));
        pool.mark_unhealthy(peer, 10);
        assert_eq!(pool.get(&peer), None);
        pool.insert(peer, binding).unwrap();
        assert_eq!(pool.get(&peer), Some(binding));
    }
}

impl ConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: BTreeMap::new(),
            unhealthy: BTreeMap::new(),
            max_connections,
        }
    }

    pub fn insert(&mut self, peer: PeerId, binding: ChannelBinding) -> CrossChainResult<()> {
        if !self.connections.contains_key(&peer) && self.connections.len() >= self.max_connections {
            return Err(CrossChainError::ConcurrencyLimitExceeded(
                self.max_connections,
            ));
        }
        self.unhealthy.remove(&peer);
        self.connections.insert(peer, binding);
        Ok(())
    }

    pub fn get(&self, peer: &PeerId) -> Option<ChannelBinding> {
        self.connections
            .get(peer)
            .copied()
            .filter(|_| !self.unhealthy.contains_key(peer))
    }

    pub fn mark_unhealthy(&mut self, peer: PeerId, timestamp: u64) {
        self.unhealthy.insert(peer, timestamp);
    }

    pub fn remove(&mut self, peer: &PeerId) {
        self.connections.remove(peer);
        self.unhealthy.remove(peer);
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }
}

impl ChannelStorage {
    /// Creates a new channel storage.
    pub fn new(max_channels: usize) -> Self {
        Self {
            channels: BTreeMap::new(),
            max_channels,
        }
    }

    /// Gets a channel for a peer.
    pub fn get(&self, peer: &PeerId) -> Option<&SecureChannel> {
        self.channels.get(peer)
    }

    /// Gets a mutable channel for a peer.
    pub fn get_mut(&mut self, peer: &PeerId) -> Option<&mut SecureChannel> {
        self.channels.get_mut(peer)
    }

    /// Adds a channel.
    pub fn add(&mut self, channel: SecureChannel) -> CrossChainResult<()> {
        if self.channels.len() >= self.max_channels {
            return Err(CrossChainError::ConcurrencyLimitExceeded(
                self.channels.len(),
            ));
        }
        self.channels.insert(channel.peer, channel);
        Ok(())
    }

    /// Removes a channel.
    pub fn remove(&mut self, peer: &PeerId) -> Option<SecureChannel> {
        self.channels.remove(peer)
    }

    /// Returns the number of active channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Returns true if there are no active channels.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

/// Message envelope for encrypted communication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The peer this message is from.
    pub from: PeerId,
    /// The peer this message is to.
    pub to: PeerId,
    /// The encrypted payload.
    pub payload: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: Vec<u8>,
    /// The encryption algorithm used.
    pub algorithm: EncryptionAlgorithm,
    /// Channel binding for this message.
    pub channel_binding: ChannelBinding,
}

/// Default implementation of the secure communication layer.
#[derive(Default)]
pub struct DefaultSecureCommunicationLayer {
    /// Channel storage.
    channels: Arc<std::sync::Mutex<ChannelStorage>>,
    connection_pool: Arc<std::sync::Mutex<ConnectionPool>>,
    /// Encryption configuration.
    config: EncryptionConfig,
    /// Local peer ID.
    local_peer_id: PeerId,
    /// Algorithm preferences (ordered).
    algorithm_preferences: Vec<EncryptionAlgorithm>,
    handlers: Arc<std::sync::Mutex<BTreeMap<PeerId, Arc<dyn VerificationPeerHandler>>>>,
    channel_keys: Arc<std::sync::Mutex<BTreeMap<PeerId, [u8; 32]>>>,
}

impl std::fmt::Debug for DefaultSecureCommunicationLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DefaultSecureCommunicationLayer")
            .field("config", &self.config)
            .field("local_peer_id", &self.local_peer_id)
            .field("algorithm_preferences", &self.algorithm_preferences)
            .finish_non_exhaustive()
    }
}

impl DefaultSecureCommunicationLayer {
    /// Creates a new communication layer.
    pub fn new(local_peer_id: PeerId, config: EncryptionConfig, max_channels: usize) -> Self {
        Self {
            channels: Arc::new(std::sync::Mutex::new(ChannelStorage::new(max_channels))),
            connection_pool: Arc::new(std::sync::Mutex::new(ConnectionPool::new(max_channels))),
            config,
            local_peer_id,
            algorithm_preferences: vec![
                EncryptionAlgorithm::Aes256Gcm,
                EncryptionAlgorithm::ChaCha20Poly1305,
                EncryptionAlgorithm::Aes128Cbc,
            ],
            handlers: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            channel_keys: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    /// Creates a communication layer with default settings.
    pub fn with_defaults(local_peer_id: PeerId) -> Self {
        Self::new(local_peer_id, EncryptionConfig::default(), 100)
    }

    /// Negotiates an encryption algorithm with a peer.
    fn negotiate_algorithm(&self, peer_preferences: &[EncryptionAlgorithm]) -> EncryptionAlgorithm {
        for our_alg in &self.algorithm_preferences {
            // CBC is retained for capability negotiation compatibility, but is
            // not acceptable for new verification channels because it does not
            // provide authenticated encryption.
            if our_alg.is_secure() && peer_preferences.contains(our_alg) {
                return *our_alg;
            }
        }
        // Fall back to default if no common algorithm
        EncryptionAlgorithm::default()
    }

    /// Gets the algorithm preferences for outgoing requests.
    pub fn algorithm_preferences(&self) -> &[EncryptionAlgorithm] {
        &self.algorithm_preferences
    }

    pub fn register_peer_handler(
        &self,
        peer: PeerId,
        handler: Arc<dyn VerificationPeerHandler>,
    ) -> CrossChainResult<()> {
        self.handlers
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("handler registry poisoned".into()))?
            .insert(peer, handler);
        Ok(())
    }

    pub fn unregister_peer_handler(&self, peer: &PeerId) -> CrossChainResult<()> {
        self.handlers
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("handler registry poisoned".into()))?
            .remove(peer);
        Ok(())
    }

    /// Encrypts a payload using the authenticated session key established for
    /// `peer`. AES-256-GCM is the default wire algorithm and binds ciphertext
    /// to the channel and both peer identities through associated data.
    pub fn encrypt_message(
        &self,
        peer: &PeerId,
        plaintext: &[u8],
    ) -> CrossChainResult<EncryptedMessage> {
        let (binding, key) = self.channel_material(peer)?;
        if self.config.algorithm != EncryptionAlgorithm::Aes256Gcm {
            return Err(CrossChainError::UnsupportedEncryptionAlgorithm);
        }
        let nonce = crypto_utils::generate_nonce(EncryptionAlgorithm::Aes256Gcm);
        let encryptor = crypto_utils::Aes256GcmEncryptor::new(&key)
            .map_err(|_| CrossChainError::EncryptionError)?;
        let aad = channel_aad(&binding, &self.local_peer_id, peer);
        let payload = encryptor
            .encrypt_with_aad(&nonce, plaintext, &aad)
            .map_err(|_| CrossChainError::EncryptionError)?;
        Ok(EncryptedMessage {
            from: self.local_peer_id,
            to: *peer,
            payload,
            nonce,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            channel_binding: binding,
        })
    }

    pub fn decrypt_message(
        &self,
        peer: &PeerId,
        message: &EncryptedMessage,
    ) -> CrossChainResult<Vec<u8>> {
        let (binding, key) = self.channel_material(peer)?;
        if message.from != *peer
            || message.to != self.local_peer_id
            || message.algorithm != EncryptionAlgorithm::Aes256Gcm
            || message.channel_binding != binding
        {
            return Err(CrossChainError::InvalidRequest);
        }
        let decryptor = crypto_utils::Aes256GcmEncryptor::new(&key)
            .map_err(|_| CrossChainError::DecryptionError)?;
        decryptor
            .decrypt_with_aad(
                &message.nonce,
                &message.payload,
                &channel_aad(&binding, &message.from, &message.to),
            )
            .map_err(|_| CrossChainError::DecryptionError)
    }

    fn channel_material(&self, peer: &PeerId) -> CrossChainResult<(ChannelBinding, [u8; 32])> {
        let binding = self
            .channels
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("channel registry poisoned".into()))?
            .get(peer)
            .map(|channel| channel.binding)
            .ok_or(CrossChainError::CommunicationError(
                "secure channel unavailable".into(),
            ))?;
        let key = self
            .channel_keys
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("key registry poisoned".into()))?
            .get(peer)
            .copied()
            .ok_or(CrossChainError::KeyExchangeError(
                "session key unavailable".into(),
            ))?;
        Ok((binding, key))
    }
}

fn channel_aad(binding: &ChannelBinding, from: &PeerId, to: &PeerId) -> Vec<u8> {
    [binding.0.as_slice(), from.0.as_bytes(), to.0.as_bytes()].concat()
}

#[async_trait]
impl SecureCommunicationLayer for Arc<DefaultSecureCommunicationLayer> {
    async fn request_verification(
        &self,
        peer: &PeerId,
        request: &VerificationRequest,
        timeout: Duration,
    ) -> CrossChainResult<VerificationResponse> {
        if timeout.is_zero() || request.required_quorum == 0 {
            return Err(CrossChainError::InvalidRequest);
        }
        self.establish_secure_channel(peer).await?;
        let handler = self
            .handlers
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("handler registry poisoned".into()))?
            .get(peer)
            .cloned()
            .ok_or_else(|| {
                CrossChainError::CommunicationError("peer transport unavailable".into())
            })?;
        let response = tokio::time::timeout(timeout, handler.handle_verification_request(request))
            .await
            .map_err(|_| CrossChainError::Timeout)??;
        if response.request_id != request.request_id || response.responder != *peer {
            return Err(CrossChainError::InvalidRequest);
        }
        if let Ok(mut channels) = self.channels.lock() {
            if let Some(channel) = channels.get_mut(peer) {
                channel.mark_active();
                channel.mark_received();
            }
        }
        Ok(response)
    }

    async fn broadcast_verification_request(
        &self,
        request: &VerificationRequest,
        peers: &[PeerId],
        quorum: usize,
        timeout: Duration,
    ) -> CrossChainResult<Vec<VerificationResponse>> {
        if peers.is_empty() || quorum == 0 {
            return Err(CrossChainError::InvalidRequest);
        }
        let futures = peers.iter().map(|peer| async move {
            tokio::time::timeout(timeout, self.request_verification(peer, request, timeout))
                .await
                .ok()
                .and_then(Result::ok)
        });
        let responses: Vec<_> = join_all(futures).await.into_iter().flatten().collect();
        if responses.len() < quorum {
            return Err(CrossChainError::QuorumNotAchieved(quorum, responses.len()));
        }
        Ok(responses)
    }

    async fn handle_verification_request(
        &self,
        request: &VerificationRequest,
    ) -> CrossChainResult<VerificationResponse> {
        let handler = self
            .handlers
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("handler registry poisoned".into()))?
            .get(&self.local_peer_id)
            .cloned()
            .ok_or_else(|| {
                CrossChainError::CommunicationError("local verifier unavailable".into())
            })?;
        handler.handle_verification_request(request).await
    }

    async fn establish_secure_channel(&self, peer: &PeerId) -> CrossChainResult<ChannelBinding> {
        if peer == &self.local_peer_id {
            return Err(CrossChainError::InvalidRequest);
        }
        if let Some(binding) = self
            .connection_pool
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("connection pool poisoned".into()))?
            .get(peer)
        {
            return Ok(binding);
        }
        let handler = self
            .handlers
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("handler registry poisoned".into()))?
            .get(peer)
            .cloned()
            .ok_or_else(|| {
                CrossChainError::CommunicationError("peer transport unavailable".into())
            })?;
        let local_key = crate::cross_chain::crypto_utils::X25519KeyPair::generate();
        let shared_secret = handler
            .establish_channel(*local_key.public().as_bytes())
            .await?;
        let (encryption_key, _) = crate::cross_chain::crypto_utils::derive_keys_from_shared_secret(
            &shared_secret,
            self.config.algorithm,
            b"oxydome-cross-chain-channel-v1",
        )?;
        if encryption_key.len() != 32 {
            return Err(CrossChainError::KeyExchangeError(
                "secure channel requires a 256-bit encryption key".into(),
            ));
        }
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&encryption_key);
        self.channel_keys
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("key registry poisoned".into()))?
            .insert(*peer, session_key);
        let digest = oxydome_crypto::hash_many(&[
            self.local_peer_id.0.as_bytes(),
            peer.0.as_bytes(),
            &shared_secret,
            b"oxydome-cross-chain-channel-v1",
        ]);
        let mut binding_bytes = [0u8; 32];
        binding_bytes.copy_from_slice(&digest.as_bytes()[..32]);
        let binding = ChannelBinding::new(binding_bytes);
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("channel registry poisoned".into()))?;
        if channels.get(peer).is_none() {
            channels.add(SecureChannel::new(*peer, self.config.algorithm, binding))?;
        }
        self.connection_pool
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("connection pool poisoned".into()))?
            .insert(*peer, binding)?;
        Ok(binding)
    }

    async fn close_secure_channel(&self, peer: &PeerId) -> CrossChainResult<()> {
        self.channels
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("channel registry poisoned".into()))?
            .remove(peer);
        self.connection_pool
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("connection pool poisoned".into()))?
            .remove(peer);
        self.channel_keys
            .lock()
            .map_err(|_| CrossChainError::CommunicationError("key registry poisoned".into()))?
            .remove(peer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_storage_operations() {
        let mut storage = ChannelStorage::new(10);

        // Initially empty
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);

        // Add a channel
        let channel = SecureChannel::new(
            PeerId::new(oxydome_crypto::Hash::zero()),
            EncryptionAlgorithm::Aes256Gcm,
            ChannelBinding::new([0u8; 32]),
        );
        storage.add(channel.clone()).unwrap();

        // Now has one channel
        assert!(!storage.is_empty());
        assert_eq!(storage.len(), 1);

        // Can retrieve the channel
        let retrieved = storage
            .get(&PeerId::new(oxydome_crypto::Hash::zero()))
            .unwrap();
        assert_eq!(retrieved.state, SecureChannelState::Ready);

        // Remove the channel
        let removed = storage
            .remove(&PeerId::new(oxydome_crypto::Hash::zero()))
            .unwrap();
        assert_eq!(removed, channel);

        // Back to empty
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn secure_channel_activity() {
        let peer = PeerId::new(oxydome_crypto::Hash::zero());
        let mut channel = SecureChannel::new(
            peer,
            EncryptionAlgorithm::Aes256Gcm,
            ChannelBinding::new([0u8; 32]),
        );

        // Initially zero activity
        assert_eq!(channel.messages_sent, 0);
        assert_eq!(channel.messages_received, 0);

        // Mark activity
        channel.mark_active();
        assert_eq!(channel.messages_sent, 1);

        // Mark received
        channel.mark_received();
        assert_eq!(channel.messages_received, 1);
    }

    #[test]
    fn algorithm_negotiation() {
        let comms = DefaultSecureCommunicationLayer::with_defaults(PeerId::new(
            oxydome_crypto::Hash::zero(),
        ));

        // Common algorithm
        let result = comms.negotiate_algorithm(&[EncryptionAlgorithm::Aes256Gcm]);
        assert_eq!(result, EncryptionAlgorithm::Aes256Gcm);

        // No common algorithm - should fall back to default
        let result = comms.negotiate_algorithm(&[EncryptionAlgorithm::Aes128Cbc]);
        assert_eq!(result, EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn concurrency_limit() {
        let mut storage = ChannelStorage::new(2);

        // Add two channels
        let channel1 = SecureChannel::new(
            PeerId::new(oxydome_crypto::Hash::zero()),
            EncryptionAlgorithm::Aes256Gcm,
            ChannelBinding::new([0u8; 32]),
        );
        storage.add(channel1).unwrap();

        let channel2 = SecureChannel::new(
            PeerId::new(oxydome_crypto::Hash::from([1u8; 64])),
            EncryptionAlgorithm::ChaCha20Poly1305,
            ChannelBinding::new([1u8; 32]),
        );
        storage.add(channel2).unwrap();

        // Should be at capacity
        assert_eq!(storage.len(), 2);

        // Third channel should fail
        let channel3 = SecureChannel::new(
            PeerId::new(oxydome_crypto::Hash::from([2u8; 64])),
            EncryptionAlgorithm::Aes128Cbc,
            ChannelBinding::new([2u8; 32]),
        );
        assert!(storage.add(channel3).is_err());
    }
}
