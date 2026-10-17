//! Speedometer: an account-based currency that stabilizes pool price movements.
//!
//! Speedometer is created automatically from transaction activity: for every
//! transaction with non-zero `output_total`, `stabilization_bps` basis points of the
//! transaction value is minted to liquidity providers. The network also airdrops
//! fresh Speedometer on a fixed cadence, sized from the block's highest transaction
//! value and an on-chain Ox price oracle.
//!
//! Speedometer uses an account-balance ledger (not a UTXO set). It is fully derived
//! from committed block data but is deliberately not committed into the block header
//! or `state_root`, mirroring GAS.

use crate::{Amount, PublicKey, Sig};
use oxydome_crypto::{hash_value, verify, Hash};
use serde::{Deserialize, Serialize};

/// An account's Speedometer balance plus the expected operation nonce (replay protection).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedometerAccount {
    /// Circulating Speedometer balance.
    pub balance: Amount,
    /// Next expected transfer nonce.
    pub nonce: u64,
}

impl SpeedometerAccount {
    pub fn new(balance: Amount) -> Self {
        Self { balance, nonce: 0 }
    }
}

/// A Speedometer action: owner-signed transfers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeedometerAction {
    /// Transfers Speedometer from `actor` to `to`.
    Transfer {
        /// Recipient address.
        to: PublicKey,
        /// Amount of Speedometer to move.
        amount: Amount,
    },
}

impl SpeedometerAction {
    /// Validates the action shape independently of any signatures.
    pub fn is_valid_shape(&self) -> bool {
        match self {
            SpeedometerAction::Transfer { amount, .. } => *amount > 0,
        }
    }
}

/// A signed Speedometer operation for user-initiated transfers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedometerOperation {
    /// Actor (signer) of this operation.
    pub actor: PublicKey,
    /// Sender nonce; must equal the account's next expected nonce.
    pub nonce: u64,
    /// The Speedometer action.
    pub action: SpeedometerAction,
    /// Signature over `(actor, nonce, action)`.
    pub signature: Sig,
}

#[derive(Serialize)]
struct SpeedometerSigningData<'a> {
    actor: PublicKey,
    nonce: u64,
    action: &'a SpeedometerAction,
}

impl SpeedometerOperation {
    /// Creates an unsigned Speedometer operation.
    pub fn new_unsigned(actor: PublicKey, nonce: u64, action: SpeedometerAction) -> Self {
        Self {
            actor,
            nonce,
            action,
            signature: Sig([0u8; 64]),
        }
    }

    /// The hash signed by the actor.
    pub fn signing_hash(&self) -> Hash {
        hash_value(&SpeedometerSigningData {
            actor: self.actor,
            nonce: self.nonce,
            action: &self.action,
        })
    }

    /// Signs the operation, setting the actor from the key.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.actor = key.public();
        self.signature = key.sign(&self.signing_hash().0);
    }

    /// Verifies only the actor signature.
    pub fn is_signature_valid(&self) -> bool {
        verify(&self.actor, &self.signing_hash().0, &self.signature)
    }

    /// Verifies the operation (shape, plus signature for transfers).
    pub fn is_valid(&self) -> bool {
        if !self.action.is_valid_shape() {
            return false;
        }
        match &self.action {
            SpeedometerAction::Transfer { .. } => self.is_signature_valid(),
        }
    }

    /// The operation id.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_signs_and_verifies() {
        let key = oxydome_crypto::KeyPair::from_seed(&[5u8; 32]);
        let dest = oxydome_crypto::KeyPair::from_seed(&[6u8; 32]);
        let mut op = SpeedometerOperation::new_unsigned(
            key.public(),
            0,
            SpeedometerAction::Transfer {
                to: dest.public(),
                amount: 10,
            },
        );
        op.sign(&key);
        assert!(op.is_valid());
        assert!(op.is_signature_valid());
    }

    #[test]
    fn transfer_tamper_fails() {
        let key = oxydome_crypto::KeyPair::from_seed(&[5u8; 32]);
        let dest = oxydome_crypto::KeyPair::from_seed(&[6u8; 32]);
        let mut op = SpeedometerOperation::new_unsigned(
            key.public(),
            0,
            SpeedometerAction::Transfer {
                to: dest.public(),
                amount: 10,
            },
        );
        op.sign(&key);
        if let SpeedometerAction::Transfer { amount, .. } = &mut op.action {
            *amount = 11;
        }
        assert!(!op.is_valid());
    }
}
