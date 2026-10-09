//! Transactions and the UTXO primitive types.

use crate::{Amount, CoreError};
use oxydome_crypto::{hash_value, verify, Hash, KeyPair, PublicKey, Sig};
use serde::{Deserialize, Serialize};

/// Reference to a specific output of a previous transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Hash,
    pub index: u32,
}

impl OutPoint {
    pub fn new(txid: Hash, index: u32) -> Self {
        Self { txid, index }
    }

    /// The unique key used by the state accumulator.
    pub fn key(&self) -> Hash {
        hash_value(self)
    }
}

/// The semantic class of a transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputKind {
    /// Ordinary spendable Ox.
    Spendable,
    /// Node/master fee earnings. On-chain and counted in supply, but only unlockable by an
    /// approved [`crate::WithdrawRequest`].
    LockedReward,
    /// Ox deposited into the Exit/Reserve sink. This applies downward pressure on the value
    /// index and is refunded (tagged) when a rebound occurs.
    ExitReserve { generation: u64 },
}

impl OutputKind {
    pub fn is_spendable(&self) -> bool {
        matches!(self, OutputKind::Spendable)
    }

    pub fn is_locked_reward(&self) -> bool {
        matches!(self, OutputKind::LockedReward)
    }

    pub fn is_exit(&self) -> bool {
        matches!(self, OutputKind::ExitReserve { .. })
    }
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: Amount,
    pub recipient: PublicKey,
    pub kind: OutputKind,
    /// Set when this output was minted by a rebound event; such outputs are maturity-locked.
    pub rebound_gen: Option<u64>,
}

impl TxOutput {
    pub fn spendable(amount: Amount, recipient: PublicKey) -> Self {
        Self {
            amount,
            recipient,
            kind: OutputKind::Spendable,
            rebound_gen: None,
        }
    }

    pub fn locked_reward(amount: Amount, recipient: PublicKey) -> Self {
        Self {
            amount,
            recipient,
            kind: OutputKind::LockedReward,
            rebound_gen: None,
        }
    }

    pub fn exit(amount: Amount, recipient: PublicKey, generation: u64) -> Self {
        Self {
            amount,
            recipient,
            kind: OutputKind::ExitReserve { generation },
            rebound_gen: None,
        }
    }

    pub fn is_rebound_credit(&self) -> bool {
        self.rebound_gen.is_some()
    }
}

/// A transaction input: a reference to a previous output plus the owner's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_out: OutPoint,
    pub owner: PublicKey,
    pub signature: Sig,
}

/// A value-transfer transaction.
///
/// Conservation (checked by the `state` crate against the live UTXO set) requires
/// `sum(input values) == sum(output amounts) + fee`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: Amount,
}

/// The canonical value that an input signature commits to. Excludes all signatures so that
/// signing is not self-referential.
#[derive(Serialize)]
struct TxSigningData<'a> {
    prev_outs: Vec<OutPoint>,
    owners: Vec<PublicKey>,
    outputs: &'a [TxOutput],
    fee: Amount,
    input_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("transaction has {0} bytes, exceeding the {1} byte limit")]
    TooLarge(usize, usize),
    #[error("duplicate input {0:?}")]
    DuplicateInput(OutPoint),
    #[error("output amount is zero")]
    ZeroOutput,
    #[error("fee must be non-zero")]
    ZeroFee,
    #[error("input {0} has an invalid signature")]
    BadSignature(usize),
    #[error("input {index} owner {owner:?} does not match signature")]
    OwnerMismatch { index: usize, owner: PublicKey },
    #[error("transaction mixes Exit/Reserve deposits with rebound credits (bunny-hop BH3)")]
    ExitAndReboundMix,
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Maximum serialized transaction size in bytes.
pub const MAX_TX_BYTES: usize = 256 * 1024;
/// Maximum number of inputs or outputs in one transaction.
pub const MAX_TX_ITEMS: usize = 4096;

impl Transaction {
    /// The canonical signing hash for `input_index`.
    pub fn signing_hash(&self, input_index: usize) -> Hash {
        let data = TxSigningData {
            prev_outs: self.inputs.iter().map(|i| i.prev_out).collect(),
            owners: self.inputs.iter().map(|i| i.owner).collect(),
            outputs: &self.outputs,
            fee: self.fee,
            input_index: input_index as u32,
        };
        hash_value(&data)
    }

    /// The transaction id (SHA3-512 over the whole transaction).
    pub fn txid(&self) -> Hash {
        hash_value(self)
    }

    /// Builds a transaction with placeholder (all-zero) signatures.
    pub fn new_unsigned(
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<TxOutput>,
        fee: Amount,
    ) -> Self {
        Self {
            inputs: inputs
                .into_iter()
                .map(|(prev_out, owner)| TxInput {
                    prev_out,
                    owner,
                    signature: Sig([0u8; 64]),
                })
                .collect(),
            outputs,
            fee,
        }
    }

    /// Signs input `index` with `key`.
    pub fn sign_input(&mut self, index: usize, key: &KeyPair) {
        let msg = self.signing_hash(index);
        self.inputs[index].signature = key.sign(&msg.0);
    }

    /// Signs every input owned by `key`.
    pub fn sign_owned_inputs(&mut self, key: &KeyPair) {
        let owner = key.public();
        for i in 0..self.inputs.len() {
            if self.inputs[i].owner == owner {
                self.sign_input(i, key);
            }
        }
    }

    pub fn output_total(&self) -> Result<Amount, CoreError> {
        let mut total: Amount = 0;
        for out in &self.outputs {
            total = total.checked_add(out.amount).ok_or(CoreError::Overflow)?;
        }
        Ok(total)
    }

    pub fn has_exit_output(&self) -> bool {
        self.outputs.iter().any(|o| o.kind.is_exit())
    }

    pub fn has_rebound_output(&self) -> bool {
        self.outputs.iter().any(|o| o.is_rebound_credit())
    }

    /// Performs all stateless validation and signature verification.
    pub fn validate_structure(&self) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxError::NoOutputs);
        }
        if self.inputs.len() > MAX_TX_ITEMS || self.outputs.len() > MAX_TX_ITEMS {
            return Err(TxError::TooLarge(
                self.inputs.len() + self.outputs.len(),
                MAX_TX_ITEMS,
            ));
        }
        if self.fee == 0 {
            return Err(TxError::ZeroFee);
        }
        for out in &self.outputs {
            if out.amount == 0 {
                return Err(TxError::ZeroOutput);
            }
        }
        // Reject duplicate inputs.
        let mut seen = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if !seen.insert(input.prev_out) {
                return Err(TxError::DuplicateInput(input.prev_out));
            }
        }
        // Bunny-hop BH3: a single transaction may not both exit and receive rebound credits.
        if self.has_exit_output() && self.has_rebound_output() {
            return Err(TxError::ExitAndReboundMix);
        }
        // Verify signatures.
        for (idx, input) in self.inputs.iter().enumerate() {
            let msg = self.signing_hash(idx);
            if !verify(&input.owner, &msg.0, &input.signature) {
                return Err(TxError::BadSignature(idx));
            }
        }
        let size = bincode::serialize(self)
            .map(|b| b.len())
            .map_err(|e| TxError::Serialization(e.to_string()))?;
        if size > MAX_TX_BYTES {
            return Err(TxError::TooLarge(size, MAX_TX_BYTES));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;

    fn signed_tx(seed: u8, fee: Amount) -> (Transaction, PublicKey) {
        let kp = KeyPair::from_seed(&[seed; 32]);
        let owner = kp.public();
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_out: OutPoint::new(Hash::zero(), 0),
                owner,
                signature: Sig([0u8; 64]),
            }],
            outputs: vec![TxOutput::spendable(100, owner)],
            fee,
        };
        let msg = tx.signing_hash(0);
        tx.inputs[0].signature = kp.sign(&msg.0);
        (tx, owner)
    }

    #[test]
    fn valid_tx_passes() {
        let (tx, _) = signed_tx(1, 5);
        assert!(tx.validate_structure().is_ok());
    }

    #[test]
    fn tampered_tx_fails_signature() {
        let (mut tx, _) = signed_tx(1, 5);
        tx.outputs[0].amount = 999;
        assert!(matches!(
            tx.validate_structure(),
            Err(TxError::BadSignature(0))
        ));
    }

    #[test]
    fn bh3_mix_rejected() {
        let (mut tx, owner) = signed_tx(1, 5);
        tx.outputs = vec![
            TxOutput::exit(1, owner, 0),
            TxOutput {
                rebound_gen: Some(1),
                ..TxOutput::spendable(1, owner)
            },
        ];
        assert_eq!(tx.validate_structure(), Err(TxError::ExitAndReboundMix));
    }

    #[test]
    fn duplicate_inputs_rejected() {
        let (mut tx, owner) = signed_tx(1, 5);
        let dup = tx.inputs[0].clone();
        tx.inputs.push(dup);
        assert!(matches!(
            tx.validate_structure(),
            Err(TxError::DuplicateInput(_))
        ));
        let _ = owner;
    }
}
