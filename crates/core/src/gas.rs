//! GAS: the Ox network's fuel currency for uploading and running programs.
//!
//! GAS is created automatically by the server nodes out of the fees they earn: for every
//! node reward, [`GAS_SERVER_FEE_BPS`] basis points of the Ox value is burned and an equal
//! amount of GAS is minted to that node. GAS is later burned from circulation whenever a
//! program is uploaded or executed. The network also airdrops fresh GAS on a fixed cadence,
//! sized from the current GAS supply and an on-chain Ox price oracle.
//!
//! GAS uses an account-balance ledger (not a UTXO set). It is fully derived from committed
//! block data but is deliberately not committed into the block header or `state_root`.

use crate::operation::MasterApproval;
use crate::{Amount, PublicKey, Sig};
use oxydome_crypto::{hash_value, verify, Hash};
use serde::{Deserialize, Serialize};

/// Share of every server-node reward converted (burned Ox, minted GAS) into GAS, in basis
/// points (`2000` = 20%).
pub const GAS_SERVER_FEE_BPS: u32 = 2000;
/// Basis points denominator.
pub const GAS_BPS_DENOMINATOR: Amount = 10_000;

/// An account's GAS balance plus the expected operation nonce (replay protection).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasAccount {
    /// Circulating GAS balance.
    pub balance: Amount,
    /// Next expected transfer nonce.
    pub nonce: u64,
}

impl GasAccount {
    pub fn new(balance: Amount) -> Self {
        Self { balance, nonce: 0 }
    }
}

/// A GAS operation: either a master-governed price update or an owner-signed transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GasAction {
    /// Sets the on-chain Ox price used to size airdrops. Requires master super-majority.
    SetOxPrice {
        /// The new Ox price (arbitrary on-chain units).
        price: Amount,
    },
    /// Transfers GAS from `actor` to `to`.
    Transfer {
        /// Recipient address.
        to: PublicKey,
        /// Amount of GAS to move.
        amount: Amount,
    },
}

impl GasAction {
    /// Validates the action shape independently of any signatures.
    pub fn is_valid_shape(&self) -> bool {
        match self {
            GasAction::SetOxPrice { price } => *price > 0,
            GasAction::Transfer { amount, .. } => *amount > 0,
        }
    }
}

/// A signed GAS operation, matching the wrapper pattern of `OhmOperation`/`DaoOperation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasOperation {
    /// Actor (signer / affected account) of this operation.
    pub actor: PublicKey,
    /// Sender nonce; must equal the account's next expected nonce for transfers.
    pub nonce: u64,
    /// The GAS action.
    pub action: GasAction,
    /// Signature over `(actor, nonce, action)`.
    pub signature: Sig,
    /// Master approvals (used by [`GasAction::SetOxPrice`]).
    pub approvals: Vec<MasterApproval>,
}

#[derive(Serialize)]
struct GasSigningData<'a> {
    actor: PublicKey,
    nonce: u64,
    action: &'a GasAction,
}

impl GasOperation {
    /// Creates an unsigned GAS operation.
    pub fn new_unsigned(actor: PublicKey, nonce: u64, action: GasAction) -> Self {
        Self {
            actor,
            nonce,
            action,
            signature: Sig([0u8; 64]),
            approvals: Vec::new(),
        }
    }

    /// The hash signed by the actor.
    pub fn signing_hash(&self) -> Hash {
        hash_value(&GasSigningData {
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
            GasAction::SetOxPrice { .. } => true,
            GasAction::Transfer { .. } => self.is_signature_valid(),
        }
    }

    /// The operation id.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}

/// Computes the GAS conversion split of a node reward using [`GAS_SERVER_FEE_BPS`].
///
/// Returns `(ox_kept, gas_minted)`. The rounding remainder stays with the node as Ox, so
/// `ox_kept + gas_minted == reward` exactly.
pub fn conversion_split(reward: Amount) -> (Amount, Amount) {
    conversion_split_with_bps(reward, GAS_SERVER_FEE_BPS)
}

/// Computes the GAS conversion split of a node reward using an explicit basis-point share.
pub fn conversion_split_with_bps(reward: Amount, bps: u32) -> (Amount, Amount) {
    let gas_minted = reward.saturating_mul(bps as u128) / GAS_BPS_DENOMINATOR;
    let ox_kept = reward.saturating_sub(gas_minted);
    (ox_kept, gas_minted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_is_twenty_percent() {
        let (ox, gas) = conversion_split(1_000);
        assert_eq!(gas, 200);
        assert_eq!(ox, 800);
    }

    #[test]
    fn conversion_conserves_value() {
        for reward in [0u128, 1, 2, 7, 99, 100, 999, 12_345] {
            let (ox, gas) = conversion_split(reward);
            assert_eq!(ox + gas, reward);
            assert_eq!(gas, reward * GAS_SERVER_FEE_BPS as u128 / GAS_BPS_DENOMINATOR);
        }
    }

    #[test]
    fn transfer_signs_and_verifies() {
        let key = oxydome_crypto::KeyPair::from_seed(&[5u8; 32]);
        let dest = oxydome_crypto::KeyPair::from_seed(&[6u8; 32]);
        let mut op = GasOperation::new_unsigned(
            key.public(),
            0,
            GasAction::Transfer {
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
        let mut op = GasOperation::new_unsigned(
            key.public(),
            0,
            GasAction::Transfer {
                to: dest.public(),
                amount: 10,
            },
        );
        op.sign(&key);
        if let GasAction::Transfer { amount, .. } = &mut op.action {
            *amount = 11;
        }
        assert!(!op.is_valid());
    }

    #[test]
    fn oracle_price_shape() {
        let key = oxydome_crypto::KeyPair::from_seed(&[5u8; 32]);
        let op = GasOperation::new_unsigned(key.public(), 0, GasAction::SetOxPrice { price: 300 });
        assert!(op.is_valid());
        let zero = GasOperation::new_unsigned(key.public(), 0, GasAction::SetOxPrice { price: 0 });
        assert!(!zero.is_valid());
    }
}
