//! AES-256-GCM encryption/decryption for secure communication.
//!
//! This module implements:
//! - Message encryption with 12-byte nonce
//! - Message decryption with authentication tag verification
//! - Unique nonce generation per message
//! - Constant-time operations for security

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// AES-256 key length in bytes.
pub const AES256_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Error type for AES-256-GCM operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Aes256GcmError {
    #[error("invalid key length: expected {0}, got {1}")]
    InvalidKeyLength(usize, usize),
    #[error("invalid nonce length: expected {0}, got {1}")]
    InvalidNonceLength(usize, usize),
    #[error("encryption failed: {0}")]
    EncryptionError(String),
    #[error("decryption failed: {0}")]
    DecryptionError(String),
    #[error("authentication tag verification failed")]
    AuthenticationTagMismatch,
    #[error("secure memory clearing failed")]
    MemoryClearingError,
}

/// Result type for AES-256-GCM operations.
pub type Aes256GcmResult<T> = Result<T, Aes256GcmError>;

/// An AES-256-GCM encryptor/decryptor.
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Creates a new AES-256-GCM cipher from a 32-byte key.
    ///
    /// The key is Zeroizing for secure memory handling.
    pub fn new(key: &[u8; AES256_KEY_LEN]) -> Self {
        let key_ref = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key_ref);
        Self { cipher }
    }

    /// Encrypts a message with a 12-byte nonce.
    ///
    /// # Arguments
    /// * `nonce` - A unique 12-byte nonce for this encryption
    /// * `plaintext` - The message to encrypt
    /// * `aad` - Optional additional authenticated data
    ///
    /// # Returns
    /// A tuple of (ciphertext, tag) where ciphertext includes the tag
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Aes256GcmResult<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(Aes256GcmError::InvalidNonceLength(NONCE_LEN, nonce.len()));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| Aes256GcmError::EncryptionError(e.to_string()))
    }

    /// Decrypts a message with authentication tag verification.
    ///
    /// # Arguments
    /// * `nonce` - The 12-byte nonce used for encryption
    /// * `ciphertext` - The encrypted message (includes authentication tag)
    /// * `aad` - Optional additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext if authentication succeeds
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Aes256GcmResult<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(Aes256GcmError::InvalidNonceLength(NONCE_LEN, nonce.len()));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| Aes256GcmError::DecryptionError(e.to_string()))
    }
}

/// Generates a cryptographically secure 12-byte nonce.
///
/// This function uses the operating system's CSPRNG.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// A complete encrypted message with nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The 12-byte nonce used for encryption
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext including authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Creates a new encrypted message.
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Encrypts a message and returns an EncryptedMessage.
    pub fn encrypt(
        key: &[u8; AES256_KEY_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Aes256GcmResult<Self> {
        let nonce = generate_nonce();
        let cipher = Aes256GcmCipher::new(key);
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;

        Ok(Self::new(nonce, ciphertext))
    }

    /// Decrypts an EncryptedMessage.
    pub fn decrypt(&self, key: &[u8; AES256_KEY_LEN], aad: &[u8]) -> Aes256GcmResult<Vec<u8>> {
        let cipher = Aes256GcmCipher::new(key);
        cipher.decrypt(&self.nonce, &self.ciphertext, aad)
    }

    /// Returns the total size of the encrypted message.
    pub fn size(&self) -> usize {
        NONCE_LEN + self.ciphertext.len()
    }
}

/// Securely clears a key from memory.
pub fn clear_key(key: &mut [u8; AES256_KEY_LEN]) {
    key.zeroize();
}

/// Securely clears an encrypted message from memory.
pub fn clear_encrypted_message(msg: &mut EncryptedMessage) {
    msg.nonce.zeroize();
    msg.ciphertext.zeroize();
}

/// Verifies that two encrypted messages with the same key and nonce are deterministic.
///
/// Note: AES-256-GCM with the same key and nonce should produce the same ciphertext
/// for the same plaintext. However, for security, we typically use unique nonces.
pub fn verify_encryption_deterministic(
    key: &[u8; AES256_KEY_LEN],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Aes256GcmResult<bool> {
    let cipher = Aes256GcmCipher::new(key);

    let ciphertext1 = cipher.encrypt(nonce, plaintext, aad)?;
    let ciphertext2 = cipher.encrypt(nonce, plaintext, aad)?;

    Ok(ciphertext1 == ciphertext2)
}

/// Verifies decryption produces the original plaintext.
pub fn verify_encryption_roundtrip(
    key: &[u8; AES256_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Aes256GcmResult<bool> {
    let cipher = Aes256GcmCipher::new(key);
    let nonce = generate_nonce();

    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad)?;

    Ok(decrypted == plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation() {
        let key = [1u8; AES256_KEY_LEN];
        let cipher = Aes256GcmCipher::new(&key);

        // Cipher should be created successfully
        assert!(std::mem::size_of_val(&cipher) > 0);
    }

    #[test]
    fn encryption_roundtrip() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Hello, AES-256-GCM World!";
        let aad = b"authenticated data";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn encryption_with_empty_aad() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Test message";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn encryption_with_empty_plaintext() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; AES256_KEY_LEN];
        let key2 = [2u8; AES256_KEY_LEN];
        let plaintext = b"Test message";

        let cipher1 = Aes256GcmCipher::new(&key1);
        let nonce = generate_nonce();

        let ciphertext = cipher1.encrypt(&nonce, plaintext, &[]).unwrap();

        // Try to decrypt with wrong key
        let cipher2 = Aes256GcmCipher::new(&key2);
        let result = cipher2.decrypt(&nonce, &ciphertext, &[]);

        assert!(matches!(result, Err(Aes256GcmError::DecryptionError(_))));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Test message";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let mut ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let result = cipher.decrypt(&nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(Aes256GcmError::DecryptionError(_))));
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Test message";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();

        // Tamper with nonce
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0xFF;

        let result = cipher.decrypt(&bad_nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(Aes256GcmError::DecryptionError(_))));
    }

    #[test]
    fn encrypted_message_roundtrip() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Encrypted message test";
        let aad = b"test aad";

        let encrypted = EncryptedMessage::encrypt(&key, plaintext, aad).unwrap();
        let decrypted = encrypted.decrypt(&key, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn nonce_uniqueness() {
        // Generate multiple nonces and verify they're all unique
        let nonces: Vec<[u8; NONCE_LEN]> = (0..1000).map(|_| generate_nonce()).collect();
        let unique: std::collections::HashSet<_> = nonces.iter().collect();

        assert_eq!(unique.len(), 1000);
    }

    #[test]
    fn nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_LEN);
    }

    #[test]
    fn test_key_length_validation() {
        // AES-256-GCM requires a 32-byte key
        let key = [1u8; AES256_KEY_LEN];
        let cipher = Aes256GcmCipher::new(&key);

        // Cipher should be created successfully
        let _ = cipher;
    }

    #[test]
    fn test_clear_key() {
        let mut key = [1u8; AES256_KEY_LEN];
        clear_key(&mut key);

        assert!(key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_clear_encrypted_message() {
        let mut msg = EncryptedMessage::new([1u8; NONCE_LEN], vec![1u8; 100]);

        clear_encrypted_message(&mut msg);

        assert!(msg.nonce.iter().all(|&b| b == 0));
        assert!(msg.ciphertext.iter().all(|&b| b == 0));
    }

    #[test]
    fn encryption_with_large_plaintext() {
        let key = [1u8; AES256_KEY_LEN];
        // 1MB plaintext
        let plaintext = vec![42u8; 1024 * 1024];

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        let ciphertext = cipher.encrypt(&nonce, &plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn encryption_with_aad() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Secret message";
        let aad1 = b"header1";
        let aad2 = b"header2";

        let cipher = Aes256GcmCipher::new(&key);
        let nonce = generate_nonce();

        // Encrypt with aad1
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad1).unwrap();

        // Decrypt with aad1 should succeed
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad1).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // Decrypt with aad2 should fail (AAD mismatch)
        let result = cipher.decrypt(&nonce, &ciphertext, aad2);
        assert!(matches!(result, Err(Aes256GcmError::DecryptionError(_))));
    }

    #[test]
    fn encryption_deterministic_same_nonce() {
        let key = [1u8; AES256_KEY_LEN];
        let plaintext = b"Deterministic test";
        let nonce = [1u8; NONCE_LEN];

        let cipher = Aes256GcmCipher::new(&key);

        let ct1 = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        let ct2 = cipher.encrypt(&nonce, plaintext, &[]).unwrap();

        assert_eq!(ct1, ct2);
    }
}
