//! Cryptographic utilities for cross-chain verification.

use crate::cross_chain::{CrossChainError, CrossChainResult, EncryptionAlgorithm};
use aes_gcm::aead::{Aead as AesAead, KeyInit as AesKeyInit};
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit};
use oxydome_crypto::zeroize::Zeroize;
use rand::RngCore;

/// X25519 key pair for key exchange.
pub struct X25519KeyPair {
    secret: [u8; 32],
    public: x25519_dalek::PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        Self { secret, public }
    }

    pub fn public(&self) -> x25519_dalek::PublicKey {
        self.public
    }

    pub fn derive_shared_secret(&self, peer_public: &x25519_dalek::PublicKey) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(self.secret);
        *secret.diffie_hellman(peer_public).as_bytes()
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Derives encryption keys from a shared secret using HKDF.
pub fn derive_keys_from_shared_secret(
    shared_secret: &[u8; 32],
    algorithm: EncryptionAlgorithm,
    info: &[u8],
) -> CrossChainResult<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let hkdf = hkdf::Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);
            let mut encryption_key = vec![0u8; 32];
            let mut mac_key = vec![0u8; 32];
            hkdf.expand(b"encryption", &mut encryption_key)
                .map_err(|e| CrossChainError::KeyExchangeError(e.to_string()))?;
            hkdf.expand(b"mac", &mut mac_key)
                .map_err(|e| CrossChainError::KeyExchangeError(e.to_string()))?;
            Ok((encryption_key, mac_key))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let hkdf = hkdf::Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);
            let mut encryption_key = vec![0u8; 32];
            hkdf.expand(b"encryption", &mut encryption_key)
                .map_err(|e| CrossChainError::KeyExchangeError(e.to_string()))?;
            Ok((encryption_key, Vec::new()))
        }
        EncryptionAlgorithm::Aes128Cbc => {
            let hkdf = hkdf::Hkdf::<sha3::Sha3_256>::new(Some(info), shared_secret);
            let mut encryption_key = vec![0u8; 16];
            let mut iv = vec![0u8; 16];
            hkdf.expand(b"encryption", &mut encryption_key)
                .map_err(|e| CrossChainError::KeyExchangeError(e.to_string()))?;
            hkdf.expand(b"iv", &mut iv)
                .map_err(|e| CrossChainError::KeyExchangeError(e.to_string()))?;
            Ok((encryption_key, iv))
        }
    }
}

/// AES-256-GCM encryption helper.
pub struct Aes256GcmEncryptor {
    key: [u8; 32],
}

impl Aes256GcmEncryptor {
    pub fn new(key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if key.len() != 32 {
            return Err("invalid key size for AES-256-GCM".into());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Ok(Self { key: key_array })
    }

    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.encrypt_with_aad(nonce, plaintext, &[])
    }

    pub fn encrypt_with_aad(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if nonce.len() != 12 {
            return Err("invalid nonce size for AES-256-GCM".into());
        }
        let nonce_array: [u8; 12] = nonce.try_into()?;
        let cipher = aes_gcm::Aes256Gcm::new(&self.key.into());
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        cipher
            .encrypt(&nonce_array.into(), payload)
            .map_err(|_| "AES-256-GCM encryption failed".into())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.decrypt_with_aad(nonce, ciphertext, &[])
    }

    pub fn decrypt_with_aad(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if nonce.len() != 12 {
            return Err("invalid nonce size for AES-256-GCM".into());
        }
        let nonce_array: [u8; 12] = nonce.try_into()?;
        let cipher = aes_gcm::Aes256Gcm::new(&self.key.into());
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        cipher
            .decrypt(&nonce_array.into(), payload)
            .map_err(|_| "AES-256-GCM authentication failed".into())
    }
}

/// ChaCha20-Poly1305 encryption helper.
pub struct ChaCha20Poly1305Encryptor {
    key: [u8; 32],
}

impl ChaCha20Poly1305Encryptor {
    pub fn new(key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if key.len() != 32 {
            return Err("invalid key size for ChaCha20-Poly1305".into());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Ok(Self { key: key_array })
    }

    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if nonce.len() != 12 && nonce.len() != 24 {
            return Err("invalid nonce size for ChaCha20-Poly1305".into());
        }
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&self.key.into());
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &[],
        };
        cipher
            .encrypt(nonce.into(), payload)
            .map_err(|_| "ChaCha20-Poly1305 encryption failed".into())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if nonce.len() != 12 && nonce.len() != 24 {
            return Err("invalid nonce size for ChaCha20-Poly1305".into());
        }
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&self.key.into());
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: &[],
        };
        cipher
            .decrypt(nonce.into(), payload)
            .map_err(|_| "ChaCha20-Poly1305 authentication failed".into())
    }
}

/// Generates a cryptographically secure nonce.
pub fn generate_nonce(algorithm: EncryptionAlgorithm) -> Vec<u8> {
    let mut nonce = vec![0u8; algorithm.nonce_size()];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Verifies a Merkle inclusion proof.
pub fn verify_merkle_inclusion(
    leaf: &oxydome_crypto::Hash,
    proof: &oxydome_crypto::MerkleProof,
    root: &oxydome_crypto::Hash,
    max_depth: usize,
) -> CrossChainResult<bool> {
    if proof.siblings.len() > max_depth {
        return Err(CrossChainError::InvalidMerkleProof);
    }
    let valid = oxydome_crypto::merkle_verify(root, leaf, proof);
    Ok(valid)
}

/// Builds a Merkle proof for a leaf at the given index.
pub fn build_merkle_proof(
    leaves: &[oxydome_crypto::Hash],
    index: usize,
) -> oxydome_crypto::MerkleProof {
    oxydome_crypto::merkle_proof(leaves, index)
}

/// Computes the Merkle root from a list of leaves.
pub fn compute_merkle_root(leaves: &[oxydome_crypto::Hash]) -> oxydome_crypto::Hash {
    oxydome_crypto::merkle_root(leaves)
}

/// Channel binding ID for encrypting messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureChannelBinding(pub [u8; 32]);

impl SecureChannelBinding {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_key_generation() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        // Use a fresh secret for each derivation to avoid ownership issues
        let alice_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let alice_pub = x25519_dalek::PublicKey::from(&alice_secret);
        let bob_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bob_pub = x25519_dalek::PublicKey::from(&bob_secret);
        let alice_shared = alice_secret.diffie_hellman(&bob_pub);
        let bob_shared = bob_secret.diffie_hellman(&alice_pub);
        let mut alice_result = [0u8; 32];
        let mut bob_result = [0u8; 32];
        alice_result.copy_from_slice(alice_shared.as_bytes());
        bob_result.copy_from_slice(bob_shared.as_bytes());
        assert_eq!(alice_result, bob_result);
    }

    #[test]
    fn aes256_gcm_encryption_roundtrip() {
        let key = [1u8; 32];
        let plaintext = b"Hello, Cross-Chain World!";
        let nonce = generate_nonce(EncryptionAlgorithm::Aes256Gcm);
        let encryptor = Aes256GcmEncryptor::new(&key).unwrap();
        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        let decryptor = Aes256GcmEncryptor::new(&key).unwrap();
        let decrypted = decryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
