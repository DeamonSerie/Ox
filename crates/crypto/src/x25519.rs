//! X25519 key exchange utilities for secure communication.
//!
//! This module implements:
//! - Ephemeral key pair generation
//! - Shared secret derivation using X25519
//! - HKDF key derivation for encryption/MAC keys
//! - Secure memory clearing after use

use hkdf::Hkdf;
use rand::RngCore;
use rand::SeedableRng;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

/// Length of X25519 shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// Length of X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Error type for X25519 operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum X25519Error {
    #[error("key exchange failed: {0}")]
    KeyExchangeError(String),
    #[error("key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("invalid key length: expected {0}, got {1}")]
    InvalidKeyLength(usize, usize),
    #[error("invalid nonce length: expected {0}, got {1}")]
    InvalidNonceLength(usize, usize),
    #[error("secure memory clearing failed")]
    MemoryClearingError,
}

/// Result type for X25519 operations.
pub type X25519Result<T> = Result<T, X25519Error>;

/// An ephemeral X25519 key pair for key exchange.
pub struct X25519KeyPair {
    secret: [u8; 32],
    public: PublicKey,
}

impl X25519KeyPair {
    /// Generates a new ephemeral key pair from cryptographically secure randomness.
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);

        // Create an ephemeral secret from a ChaChaRng seeded with our random bytes
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_seed(secret_bytes);
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        Self {
            secret: secret_bytes,
            public,
        }
    }

    /// Returns the public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Derives a shared secret with the peer's public key.
    pub fn derive_shared_secret(&self, peer_public: &PublicKey) -> [u8; SHARED_SECRET_LEN] {
        // Create a new secret from stored bytes
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.secret);
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let shared = secret.diffie_hellman(peer_public);
        let mut result = [0u8; SHARED_SECRET_LEN];
        result.copy_from_slice(shared.as_bytes());
        result
    }

    /// Derives encryption and MAC keys from a shared secret using HKDF.
    ///
    /// # Arguments
    /// * `shared_secret` - The X25519 shared secret
    /// * `info` - Optional context/application-specific information
    /// * `key_length` - Length of each derived key (default: 32 bytes)
    ///
    /// # Returns
    /// A tuple of (encryption_key, mac_key)
    pub fn derive_keys(
        shared_secret: &[u8; SHARED_SECRET_LEN],
        info: &[u8],
        key_length: usize,
    ) -> X25519Result<(Vec<u8>, Vec<u8>)> {
        if shared_secret.len() != SHARED_SECRET_LEN {
            return Err(X25519Error::InvalidKeyLength(
                SHARED_SECRET_LEN,
                shared_secret.len(),
            ));
        }

        let hkdf = Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);

        let mut encryption_key = vec![0u8; key_length];
        let mut mac_key = vec![0u8; key_length];

        hkdf.expand(b"encryption", &mut encryption_key)
            .map_err(|e| X25519Error::KeyDerivationError(e.to_string()))?;

        hkdf.expand(b"mac", &mut mac_key)
            .map_err(|e| X25519Error::KeyDerivationError(e.to_string()))?;

        Ok((encryption_key, mac_key))
    }

    /// Clears sensitive key material from memory.
    pub fn clear_memory(bytes: &mut [u8]) {
        bytes.zeroize();
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// A static X25519 key pair (for long-term keys, not ephemeral).
pub struct X25519StaticKeyPair {
    secret: [u8; 32],
    public: PublicKey,
}

impl X25519StaticKeyPair {
    /// Generates a new static key pair.
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);

        let mut rng = rand_chacha::ChaCha20Rng::from_seed(secret_bytes);
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        Self {
            secret: secret_bytes,
            public,
        }
    }

    /// Returns the public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Derives a shared secret with the peer's public key.
    pub fn derive_shared_secret(&self, peer_public: &PublicKey) -> [u8; SHARED_SECRET_LEN] {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(self.secret);
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let shared = secret.diffie_hellman(peer_public);
        let mut result = [0u8; SHARED_SECRET_LEN];
        result.copy_from_slice(shared.as_bytes());
        result
    }

    /// Clears the secret key material.
    pub fn clear(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for X25519StaticKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Securely clears a buffer by overwriting with zeros.
pub fn secure_clear(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Securely clears and returns a vector to its original capacity.
pub fn secure_clear_vec(vec: &mut Vec<u8>) {
    vec.zeroize();
}

/// Derives an AES-256 key from a shared secret using HKDF.
///
/// # Arguments
/// * `shared_secret` - The X25519 shared secret (32 bytes)
/// * `info` - Optional context/application-specific information
///
/// # Returns
/// A 32-byte key for AES-256 encryption
pub fn derive_aes256_key(
    shared_secret: &[u8; SHARED_SECRET_LEN],
    info: &[u8],
) -> X25519Result<[u8; 32]> {
    let hkdf = Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);

    let mut key = [0u8; 32];
    hkdf.expand(b"aes256-key", &mut key)
        .map_err(|e| X25519Error::KeyDerivationError(e.to_string()))?;

    Ok(key)
}

/// Derives a nonce for AES-GCM encryption.
///
/// For AES-GCM, we need a 12-byte nonce. We derive it from the shared secret
/// using HKDF with a specific context.
pub fn derive_nonce(
    shared_secret: &[u8; SHARED_SECRET_LEN],
    info: &[u8],
) -> X25519Result<[u8; 12]> {
    let hkdf = Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);

    let mut nonce = [0u8; 12];
    hkdf.expand(b"gcm-nonce", &mut nonce)
        .map_err(|e| X25519Error::KeyDerivationError(e.to_string()))?;

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pair_generation() {
        let keypair = X25519KeyPair::generate();
        let public = keypair.public();

        // Public key should be 32 bytes
        assert_eq!(public.as_bytes().len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn shared_secret_derivation() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        // Both should derive the same shared secret
        let alice_secret = alice.derive_shared_secret(bob.public());
        let bob_secret = bob.derive_shared_secret(alice.public());

        assert_eq!(&alice_secret[..], &bob_secret[..]);
    }

    #[test]
    fn key_derivation() {
        let shared_secret = [1u8; SHARED_SECRET_LEN];
        let info = b"test-info";

        let (enc_key, mac_key) = X25519KeyPair::derive_keys(&shared_secret, info, 32).unwrap();

        assert_eq!(enc_key.len(), 32);
        assert_eq!(mac_key.len(), 32);
        assert_ne!(&enc_key[..], &mac_key[..]);
    }

    #[test]
    fn aes256_key_derivation() {
        let shared_secret = [1u8; SHARED_SECRET_LEN];
        let info = b"test-info";

        let key = derive_aes256_key(&shared_secret, info).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn nonce_derivation() {
        let shared_secret = [1u8; SHARED_SECRET_LEN];
        let info = b"test-info";

        let nonce = derive_nonce(&shared_secret, info).unwrap();

        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_secure_clear() {
        let mut data = [1u8; 32];
        secure_clear(&mut data);

        // After clearing, all bytes should be zero
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_clear_vec() {
        let mut data = vec![1u8; 32];
        secure_clear_vec(&mut data);

        // After clearing, all bytes should be zero
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn static_key_pair_generation() {
        let keypair = X25519StaticKeyPair::generate();
        let public = keypair.public();

        assert_eq!(public.as_bytes().len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn static_key_shared_secret() {
        let alice = X25519StaticKeyPair::generate();
        let bob = X25519StaticKeyPair::generate();

        let alice_secret = alice.derive_shared_secret(bob.public());
        let bob_secret = bob.derive_shared_secret(alice.public());

        assert_eq!(&alice_secret[..], &bob_secret[..]);
    }

    #[test]
    fn key_clearing() {
        let mut keypair = X25519StaticKeyPair::generate();

        // Clear the key
        keypair.clear();

        // After clearing, all bytes should be zero
        assert!(keypair.secret.iter().all(|&b| b == 0));
    }
}
