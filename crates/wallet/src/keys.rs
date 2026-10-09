//! The signing abstraction used across the wallet core.

use oxydome_crypto::{Hash, KeyPair, PublicKey, Sig};

/// Anything that can produce Ed25519 signatures for one public key.
///
/// Wallet apps supply their own implementation:
/// * a local keypair ([`LocalSigner`]),
/// * a remote signer (e.g. the browser holding the seed phrase),
/// * the optional vault (implemented in M13).
///
/// Signing is always over a 64-byte digest; [`Signer::sign`] hands the caller the raw bytes.
pub trait Signer {
    /// The public key this signer controls.
    fn public(&self) -> PublicKey;

    /// Signs an arbitrary message bytestring.
    fn sign(&self, message: &[u8]) -> Sig;

    /// Signs a 64-byte hash digest directly. Used by the message-signing scheme and by
    /// transaction input signing (`Transaction::signing_hash`).
    fn sign_hash(&self, digest: &Hash) -> Sig {
        self.sign(&digest.0)
    }
}

/// A signer backed by an in-memory [`KeyPair`].
pub struct LocalSigner {
    pub key: KeyPair,
}

impl LocalSigner {
    pub fn new(key: KeyPair) -> Self {
        Self { key }
    }
}

impl Signer for LocalSigner {
    fn public(&self) -> PublicKey {
        self.key.public()
    }

    fn sign(&self, message: &[u8]) -> Sig {
        self.key.sign(message)
    }

    fn sign_hash(&self, digest: &Hash) -> Sig {
        self.key.sign(&digest.0)
    }
}

/// Convenience blanket impl so a raw keypair can be used anywhere a signer is expected.
impl Signer for KeyPair {
    fn public(&self) -> PublicKey {
        KeyPair::public(self)
    }

    fn sign(&self, message: &[u8]) -> Sig {
        KeyPair::sign(self, message)
    }

    fn sign_hash(&self, digest: &Hash) -> Sig {
        self.sign(&digest.0)
    }
}
