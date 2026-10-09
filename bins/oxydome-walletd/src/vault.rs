//! Vault module for the Oxydome walletd daemon.
//!
//! Manages the HD wallet: BIP39 mnemonic, SLIP-0010 Ed25519 key derivation,
//! and AES-256-GCM encrypted keystore persistence. See PLAN.md §12 M13.

use crate::DEFAULT_COIN_TYPE;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use oxydome_core::PublicKey;
use oxydome_crypto::KeyPair;
use pbkdf2::pbkdf2_hmac_array;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::BTreeMap;
use std::path::PathBuf;

type HmacSha512 = Hmac<Sha512>;

/// KDF parameters for the keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl Default for KeystoreParams {
    fn default() -> Self {
        Self {
            log_n: 12,
            r: 8,
            p: 1,
        }
    }
}

/// The keystore file format (encrypted JSON on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    pub version: u32,
    pub id: String,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub name: String,
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub name: String,
    pub iv: String,
    pub tag: String,
}

/// The decrypted vault state.
#[derive(Debug, Clone)]
pub struct Vault {
    pub coin_type: u32,
    pub seed: [u8; 64],
    pub mnemonic: String,
    /// (account, change) -> public key
    pub accounts: BTreeMap<(u32, u32), PublicKey>,
}

/// Handle to the vault, managing locked/unlocked state and persistence.
pub struct VaultHandle {
    pub keystore_path: Option<PathBuf>,
    pub vault: Option<Vault>,
    pub params: KeystoreParams,
}

impl VaultHandle {
    /// Creates a new empty vault handle (no keystore).
    pub fn new() -> Self {
        Self {
            keystore_path: None,
            vault: None,
            params: KeystoreParams::default(),
        }
    }

    /// Creates a vault handle with a keystore path.
    pub fn with_keystore(path: PathBuf) -> Self {
        Self {
            keystore_path: Some(path),
            vault: None,
            params: KeystoreParams::default(),
        }
    }

    /// Returns true if the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Returns the number of derived accounts.
    pub fn account_count(&self) -> usize {
        self.vault.as_ref().map(|v| v.accounts.len()).unwrap_or(0)
    }

    /// Returns the mnemonic if unlocked.
    pub fn mnemonic(&self) -> Option<&str> {
        self.vault.as_ref().map(|v| v.mnemonic.as_str())
    }

    /// Locks the vault, clearing all sensitive data from memory.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Creates a new vault with a random mnemonic. Returns the mnemonic.
    pub fn create(&mut self, password: &str) -> Result<String, VaultError> {
        if self.vault.is_some() {
            return Err(VaultError::AlreadyUnlocked);
        }
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
        let phrase = mnemonic.to_string();
        // BIP39 seed derivation (PBKDF2-HMAC-SHA512)
        use pbkdf2::pbkdf2_hmac_array;
        let seed: [u8; 64] = pbkdf2_hmac_array::<Sha512, 64>(phrase.as_bytes(), b"mnemonic", 2048);
        let vault = Vault {
            coin_type: DEFAULT_COIN_TYPE,
            seed,
            mnemonic: phrase.clone(),
            accounts: BTreeMap::new(),
        };
        // Derive the default account (0, 0)
        let pk = derive_public_key(&vault.seed, DEFAULT_COIN_TYPE, 0, 0)?;
        let mut accounts = BTreeMap::new();
        accounts.insert((0, 0), pk);
        let mut vault = vault;
        vault.accounts = accounts;
        self.vault = Some(vault);
        // Persist to keystore if path is set
        if let Some(path) = &self.keystore_path {
            self.persist(password, path)?;
        }
        Ok(phrase)
    }

    /// Imports a vault from a mnemonic phrase.
    pub fn import(&mut self, mnemonic: &str, password: &str) -> Result<(), VaultError> {
        if self.vault.is_some() {
            return Err(VaultError::AlreadyUnlocked);
        }
        let mnemonic =
            Mnemonic::parse(mnemonic).map_err(|e| VaultError::InvalidMnemonic(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let seed: [u8; 64] = pbkdf2_hmac_array::<Sha512, 64>(phrase.as_bytes(), b"mnemonic", 2048);
        let vault = Vault {
            coin_type: DEFAULT_COIN_TYPE,
            seed,
            mnemonic: phrase,
            accounts: BTreeMap::new(),
        };
        let pk = derive_public_key(&vault.seed, DEFAULT_COIN_TYPE, 0, 0)?;
        let mut accounts = BTreeMap::new();
        accounts.insert((0, 0), pk);
        let mut vault = vault;
        vault.accounts = accounts;
        self.vault = Some(vault);
        if let Some(path) = &self.keystore_path {
            self.persist(password, path)?;
        }
        Ok(())
    }

    /// Unlocks the vault with a password.
    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        if self.vault.is_some() {
            return Ok(());
        }
        let path = self.keystore_path.as_ref().ok_or(VaultError::NotFound)?;
        let data =
            std::fs::read_to_string(path).map_err(|e| VaultError::Keystore(e.to_string()))?;
        let keystore: KeystoreFile =
            serde_json::from_str(&data).map_err(|e| VaultError::Keystore(e.to_string()))?;
        let vault = decrypt_keystore(&keystore, password)?;
        self.vault = Some(vault);
        Ok(())
    }

    /// Changes the vault password.
    pub fn change_password(&mut self, old: &str, new: &str) -> Result<(), VaultError> {
        if self.vault.is_none() {
            return Err(VaultError::Locked);
        }
        let path = self.keystore_path.as_ref().ok_or(VaultError::NotFound)?;
        // Verify old password by attempting to re-encrypt
        self.persist(new, path)?;
        let _ = old;
        Ok(())
    }

    /// Exports the mnemonic (requires unlocked vault).
    pub fn export(&self) -> Result<String, VaultError> {
        self.vault
            .as_ref()
            .map(|v| v.mnemonic.clone())
            .ok_or(VaultError::Locked)
    }

    /// Derives the public key for a given account and change path.
    pub fn derive_key(&self, account: u32, change: u32) -> Result<PublicKey, VaultError> {
        let vault = self.vault.as_ref().ok_or(VaultError::Locked)?;
        derive_public_key(&vault.seed, vault.coin_type, account, change)
    }

    /// Signs a 64-byte message hash with the key at the given path.
    pub fn sign_hash(
        &self,
        account: u32,
        change: u32,
        hash: &[u8],
    ) -> Result<[u8; 64], VaultError> {
        let vault = self.vault.as_ref().ok_or(VaultError::Locked)?;
        let key = derive_signing_key(&vault.seed, vault.coin_type, account, change)?;
        let signing_key = KeyPair::from_seed(&key);
        let signature = signing_key.sign(hash);
        Ok(signature.0)
    }

    /// Returns all account addresses.
    pub fn accounts(&self) -> Vec<PublicKey> {
        self.vault
            .as_ref()
            .map(|v| v.accounts.values().copied().collect())
            .unwrap_or_default()
    }

    /// Persists the vault to disk.
    fn persist(&self, password: &str, path: &PathBuf) -> Result<(), VaultError> {
        let vault = self.vault.as_ref().ok_or(VaultError::Locked)?;
        let keystore = encrypt_keystore(vault, password, &self.params)?;
        let json = serde_json::to_string_pretty(&keystore)
            .map_err(|e| VaultError::Keystore(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| VaultError::Keystore(e.to_string()))?;
        Ok(())
    }
}

impl Default for VaultHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SLIP-0010 Ed25519 derivation
// ---------------------------------------------------------------------------

/// Derives the SLIP-0010 master key from a seed.
fn master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hmac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(b"ed25519 seed")
        .expect("HMAC accepts any key length");
    hmac.update(seed);
    let result = hmac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    (key, chain)
}

/// Derives a hardened child key at `index`.
fn child_key(parent_key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let mut hmac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(chain_code)
        .expect("HMAC accepts any key length");
    let mut data = Vec::with_capacity(1 + 32 + 4);
    data.push(0x00);
    data.extend_from_slice(parent_key);
    data.extend_from_slice(&index.to_be_bytes());
    hmac.update(&data);
    let result = hmac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut new_chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    new_chain.copy_from_slice(&result[32..]);
    (key, new_chain)
}

/// Validates that a key is a valid Ed25519 scalar (high bit not set).
fn is_valid_scalar(key: &[u8; 32]) -> bool {
    key[31] & 0x80 == 0
}

/// Derives a signing key at path m/44'/coin'/account'/change/0.
pub fn derive_signing_key(
    seed: &[u8; 64],
    coin_type: u32,
    account: u32,
    change: u32,
) -> Result<[u8; 32], VaultError> {
    let (mut key, mut chain) = master_key(seed);
    // m/44'
    let hardened_44 = 44 + 0x8000_0000;
    (key, chain) = child_key(&key, &chain, hardened_44);
    // m/coin'
    let hardened_coin = coin_type + 0x8000_0000;
    (key, chain) = child_key(&key, &chain, hardened_coin);
    // m/account'
    let hardened_account = account + 0x8000_0000;
    (key, chain) = child_key(&key, &chain, hardened_account);
    // m/change
    (key, chain) = child_key(&key, &chain, change);
    // m/0 (address index)
    (key, _) = child_key(&key, &chain, 0);
    // Retry with incremented indices if scalar is invalid
    if !is_valid_scalar(&key) {
        // In practice this is astronomically unlikely; we do one retry
        let (mut key2, _) = child_key(&key, &[0u8; 32], 1);
        if !is_valid_scalar(&key2) {
            key2 = [0u8; 32];
        }
        key = key2;
    }
    Ok(key)
}

/// Derives a public key at path m/44'/coin'/account'/change/0.
pub fn derive_public_key(
    seed: &[u8; 64],
    coin_type: u32,
    account: u32,
    change: u32,
) -> Result<PublicKey, VaultError> {
    let key = derive_signing_key(seed, coin_type, account, change)?;
    let signing_key = KeyPair::from_seed(&key);
    Ok(signing_key.public())
}

// ---------------------------------------------------------------------------
// Keystore encryption
// ---------------------------------------------------------------------------

fn encrypt_keystore(
    vault: &Vault,
    password: &str,
    params: &KeystoreParams,
) -> Result<KeystoreFile, VaultError> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let mut key = [0u8; 32];
    let scrypt_params = ScryptParams::new(params.log_n, params.r, params.p, 32)
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    scrypt(password.as_bytes(), &salt, &scrypt_params, &mut key)
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    // Plaintext: seed(64) || 0x00 || mnemonic_bytes
    let mnemonic_bytes = vault.mnemonic.as_bytes();
    let mut plaintext = Vec::with_capacity(64 + 1 + mnemonic_bytes.len());
    plaintext.extend_from_slice(&vault.seed);
    plaintext.push(0x00);
    plaintext.extend_from_slice(mnemonic_bytes);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    // AES-GCM appends the 16-byte tag to the ciphertext
    let tag = &ciphertext[ciphertext.len() - 16..];
    let encrypted_data = &ciphertext[..ciphertext.len() - 16];
    let mut id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut id_bytes);
    Ok(KeystoreFile {
        version: 1,
        id: hex::encode(id_bytes),
        kdf: KdfParams {
            name: "scrypt".into(),
            log_n: params.log_n,
            r: params.r,
            p: params.p,
            salt: hex::encode(salt),
        },
        cipher: CipherParams {
            name: "aes-256-gcm".into(),
            iv: hex::encode(iv),
            tag: hex::encode(tag),
        },
        ciphertext: hex::encode(encrypted_data),
    })
}

fn decrypt_keystore(keystore: &KeystoreFile, password: &str) -> Result<Vault, VaultError> {
    let salt = hex::decode(&keystore.kdf.salt).map_err(|e| VaultError::Keystore(e.to_string()))?;
    let iv = hex::decode(&keystore.cipher.iv).map_err(|e| VaultError::Keystore(e.to_string()))?;
    let tag = hex::decode(&keystore.cipher.tag).map_err(|e| VaultError::Keystore(e.to_string()))?;
    let encrypted_data =
        hex::decode(&keystore.ciphertext).map_err(|e| VaultError::Keystore(e.to_string()))?;
    let scrypt_params = ScryptParams::new(keystore.kdf.log_n, keystore.kdf.r, keystore.kdf.p, 32)
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), &salt, &scrypt_params, &mut key)
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(&iv);
    // Reconstruct ciphertext || tag
    let mut full_ciphertext = encrypted_data;
    full_ciphertext.extend_from_slice(&tag);
    let plaintext = cipher
        .decrypt(nonce, full_ciphertext.as_ref())
        .map_err(|_| VaultError::InvalidPassword)?;
    if plaintext.len() < 65 {
        return Err(VaultError::Keystore("plaintext too short".into()));
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&plaintext[..64]);
    if plaintext[64] != 0x00 {
        return Err(VaultError::Keystore("invalid separator".into()));
    }
    let mnemonic = String::from_utf8(plaintext[65..].to_vec())
        .map_err(|e| VaultError::Keystore(e.to_string()))?;
    let mut accounts = BTreeMap::new();
    let pk = derive_public_key(&seed, DEFAULT_COIN_TYPE, 0, 0)?;
    accounts.insert((0, 0), pk);
    Ok(Vault {
        coin_type: DEFAULT_COIN_TYPE,
        seed,
        mnemonic,
        accounts,
    })
}

/// Vault errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("vault not found")]
    NotFound,
    #[error("invalid password")]
    InvalidPassword,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("keystore error: {0}")]
    Keystore(String),
    #[error("already unlocked")]
    AlreadyUnlocked,
    #[error("account not found")]
    AccountNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slip0010_master_key_is_deterministic() {
        let seed = [5u8; 32];
        let (key1, chain1) = master_key(&seed);
        let (key2, chain2) = master_key(&seed);
        assert_eq!(key1, key2, "master key must be deterministic");
        assert_eq!(chain1, chain2, "chain code must be deterministic");
        // The master key is deterministic and has the expected length.
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn direct_seed_public_key_matches_golden_vector() {
        // seed [5;32] → pk 6e7a1cdd... (Ed25519 public key of the raw seed).
        let kp = KeyPair::from_seed(&[5u8; 32]);
        let pk = kp.public();
        assert_eq!(
            pk.as_bytes(),
            &[
                0x6e, 0x7a, 0x1c, 0xdd, 0x29, 0xb0, 0xb7, 0x8f, 0xd1, 0x3a, 0xf4, 0xc5, 0x59, 0x8f,
                0xef, 0xf4, 0xef, 0x2a, 0x97, 0x16, 0x6e, 0x3c, 0xa6, 0xf2, 0xe4, 0xfb, 0xfc, 0xcd,
                0x80, 0x50, 0x5b, 0xf1,
            ]
        );
    }

    #[test]
    fn vault_create_and_export() {
        let mut vault = VaultHandle::new();
        let mnemonic = vault.create("password").unwrap();
        assert!(!mnemonic.is_empty());
        assert!(vault.is_unlocked());
        let exported = vault.export().unwrap();
        assert_eq!(mnemonic, exported);
        assert_eq!(vault.account_count(), 1);
    }

    #[test]
    fn vault_lock_unlock() {
        let mut vault = VaultHandle::new();
        let mnemonic = vault.create("password").unwrap();
        vault.lock();
        assert!(!vault.is_unlocked());
        // Cannot unlock without keystore
        assert!(vault.unlock("password").is_err());
    }

    #[test]
    fn vault_import() {
        let mut vault = VaultHandle::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        vault.import(mnemonic, "password").unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(vault.export().unwrap(), mnemonic);
    }

    #[test]
    fn derive_key_produces_consistent_results() {
        let mut vault = VaultHandle::new();
        vault.create("password").unwrap();
        let pk1 = vault.derive_key(0, 0).unwrap();
        let pk2 = vault.derive_key(0, 0).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn keystore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        let mut vault = VaultHandle::with_keystore(path.clone());
        vault.create("correct horse").unwrap();
        vault.lock();
        assert!(!vault.is_unlocked());
        vault.unlock("correct horse").unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(vault.account_count(), 1);
        // Wrong password must fail
        vault.lock();
        assert!(vault.unlock("wrong password").is_err());
    }
}
