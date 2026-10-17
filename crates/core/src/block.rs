//! Blocks and block headers.

use crate::operation::Operation;
use crate::tx::Transaction;
use crate::Amount;
use oxydome_crypto::{hash_value, merkle_root, Hash, PublicKey};
use serde::{Deserialize, Serialize};

/// Fixed-point scale for the Ox value index: `1.000 == 1_000_000_000_000`.
pub const VALUE_SCALE: u128 = 1_000_000_000_000;
pub const LEGACY_EXECUTION_VERSION: u32 = 1;
pub const OVM_EXECUTION_VERSION: u32 = 2;
pub const SMART_CONTRACT_EXECUTION_VERSION: u32 = 4;

/// The Ox value index, encoded as a fixed-point `u128` with [`VALUE_SCALE`] precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValueIndex(pub u128);

impl ValueIndex {
    pub const ONE: ValueIndex = ValueIndex(VALUE_SCALE);

    pub fn from_raw(raw: u128) -> Self {
        ValueIndex(raw)
    }

    pub fn raw(&self) -> u128 {
        self.0
    }

    /// Human-readable decimal with 6 fractional digits.
    pub fn to_display(&self) -> String {
        let whole = self.0 / VALUE_SCALE;
        let frac = self.0 % VALUE_SCALE / 1_000_000;
        format!("{whole}.{frac:06}")
    }

    pub fn is_non_positive(&self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for ValueIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_display())
    }
}

/// The immutable header of a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    /// Commits the execution rules used to validate this block.
    pub execution_version: u32,
    /// Commits the network's OVM activation configuration.
    pub ovm_activation_height: u64,
    /// Commits activation of multi-entry-point Solid contract artifacts.
    pub smart_contract_activation_height: u64,
    pub prev_hash: Hash,
    pub tx_root: Hash,
    pub operation_root: Hash,
    pub ovm_receipt_root: Hash,
    /// Commits the UTXO tree separately so header-only input proofs remain verifiable when
    /// `state_root` also commits to contract code and storage.
    pub utxo_root: Hash,
    pub state_root: Hash,
    pub supply: Amount,
    pub epoch: u64,
    pub generation: u64,
    pub value_index: ValueIndex,
    pub producer: PublicKey,
    pub timestamp: u64,
    /// Total Ox transacted in this block (window statistics, committed so that masters can
    /// verify the value index from headers alone).
    pub volume: Amount,
    /// Number of transactions in this block.
    pub tx_count: u64,
    /// Ox deposited into the Exit/Reserve sink this block.
    pub exit_amount: Amount,
    /// Optional per-block verification key. Legacy headers omit these fields during migration.
    #[serde(default)]
    pub ephemeral_public_key: Option<PublicKey>,
    #[serde(default)]
    pub previous_verification_commitment: Option<Hash>,
    #[serde(default)]
    pub verification_state_commitment: Option<Hash>,
    /// Total Speedometer minted from per-transaction stabilization this block.
    #[serde(default)]
    pub speedometer_minted: Amount,
    /// Airdrop amount distributed this block (if a Speedometer airdrop occurred).
    #[serde(default)]
    pub speedometer_airdrop_amount: Amount,
    /// Gas price used for OVM execution in this block (derived from pegged bounds).
    #[serde(default)]
    pub gas_price: Amount,
    /// Total GAS fees collected from OVM execution in this block.
    #[serde(default)]
    pub total_gas_fees: Amount,
}

impl BlockHeader {
    pub fn set_ephemeral_verification_key(
        &mut self,
        key: &oxydome_crypto::evk::EphemeralVerificationKey,
    ) {
        self.ephemeral_public_key = Some(key.public_key);
        self.previous_verification_commitment = Some(key.previous_commitment);
        // The state commitment is derived during validation and is intentionally not
        // persisted; this keeps the EVK header delta at 32 + 64 = 96 bytes.
        self.verification_state_commitment = None;
    }
    /// Validates the EVK extension while preserving legacy-header compatibility in migration mode.
    pub fn validate_ephemeral_keys(&self, migration_mode: bool) -> Result<(), String> {
        let present = self.ephemeral_public_key.is_some();
        if !migration_mode && !present {
            return Err("missing ephemeral verification key".into());
        }
        if !present {
            return Ok(());
        }
        let previous = self
            .previous_verification_commitment
            .ok_or("missing previous verification commitment")?;
        let expected = oxydome_crypto::hash_many(&[
            b"EVK_STATE",
            self.ephemeral_public_key.unwrap().as_bytes(),
            previous.as_bytes(),
            &self.height.to_le_bytes(),
            &self.timestamp.to_le_bytes(),
        ]);
        if let Some(actual) = self.verification_state_commitment {
            if actual != expected {
                return Err("invalid verification state commitment".into());
            }
        }
        Ok(())
    }

    pub fn ephemeral_storage_bytes(&self) -> usize {
        usize::from(self.ephemeral_public_key.is_some()) * 32
            + usize::from(self.previous_verification_commitment.is_some()) * 64
    }
}

/// A full block: header plus the transactions and operations it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub operations: Vec<Operation>,
    pub ovm_receipts: Vec<crate::OvmReceipt>,
}

impl Block {
    /// Builds a normal header and attaches the public portion of an EVK session.
    pub fn build_header_with_ephemeral_key(
        mut block: Block,
        key: &oxydome_crypto::evk::EphemeralVerificationKey,
    ) -> Block {
        block.header.set_ephemeral_verification_key(key);
        block
    }
    pub fn hash(&self) -> Hash {
        hash_value(&self.header)
    }

    pub fn tx_root(&self) -> Hash {
        let leaves: Vec<Hash> = self.transactions.iter().map(|t| t.txid()).collect();
        merkle_root(&leaves)
    }

    pub fn operation_root(&self) -> Hash {
        let leaves: Vec<Hash> = self.operations.iter().map(|o| o.id()).collect();
        merkle_root(&leaves)
    }

    pub fn ovm_receipt_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .ovm_receipts
            .iter()
            .map(oxydome_crypto::hash_value)
            .collect();
        merkle_root(&leaves)
    }

    /// Total settled fees. OVM execution is paid in GAS (burned from the caller's balance), so
    /// the Ox fee is simply the transfer fee and no gas escrow is re-derived here.
    pub fn fee_total(&self) -> Amount {
        self.transactions
            .iter()
            .map(|tx| tx.fee)
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    /// Checks that the header's commitments match the block body.
    pub fn roots_match(&self) -> bool {
        self.header.tx_root == self.tx_root()
            && self.header.operation_root == self.operation_root()
            && self.header.ovm_receipt_root == self.ovm_receipt_root()
    }

    /// Constructs a block header with the roots filled in from the body.
    pub fn build_header(
        height: u64,
        execution_version: u32,
        ovm_activation_height: u64,
        smart_contract_activation_height: u64,
        prev_hash: Hash,
        utxo_root: Hash,
        state_root: Hash,
        supply: Amount,
        epoch: u64,
        generation: u64,
        value_index: ValueIndex,
        producer: PublicKey,
        timestamp: u64,
        transactions: Vec<Transaction>,
        operations: Vec<Operation>,
    ) -> Block {
        let tx_root = {
            let leaves: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
            merkle_root(&leaves)
        };
        let operation_root = {
            let leaves: Vec<Hash> = operations.iter().map(|o| o.id()).collect();
            merkle_root(&leaves)
        };
        let volume: Amount = transactions
            .iter()
            .map(|t| t.output_total().unwrap_or(0))
            .fold(0u128, |a, b| a.saturating_add(b));
        let exit_amount: Amount = transactions
            .iter()
            .flat_map(|t| t.outputs.iter())
            .filter(|o| o.kind.is_exit())
            .map(|o| o.amount)
            .fold(0u128, |a, b| a.saturating_add(b));
        let tx_count = transactions.len() as u64;
        Block {
            header: BlockHeader {
                height,
                execution_version,
                ovm_activation_height,
                smart_contract_activation_height,
                prev_hash,
                tx_root,
                operation_root,
                ovm_receipt_root: merkle_root(&[]),
                utxo_root,
                state_root,
                supply,
                epoch,
                generation,
                value_index,
                producer,
                timestamp,
                volume,
                tx_count,
                exit_amount,
                ephemeral_public_key: None,
                previous_verification_commitment: None,
                verification_state_commitment: None,
                speedometer_minted: 0,
                speedometer_airdrop_amount: 0,
                gas_price: 0,
                total_gas_fees: 0,
            },
            transactions,
            operations,
            ovm_receipts: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::evk::{EphemeralKeyManager, EvkConfig, IEphemeralKeyManager};

    #[test]
    fn evk_headers_support_migration_and_production_validation() {
        let manager = EphemeralKeyManager::new(EvkConfig::default());
        let key = manager
            .generate_ephemeral_key(1, Hash::zero(), Hash::zero(), 10)
            .unwrap();
        let mut header = Block::build_header(
            1,
            1,
            0,
            0,
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            0,
            0,
            0,
            ValueIndex::from_raw(0),
            PublicKey([0; 32]),
            10,
            Vec::new(),
            Vec::new(),
        )
        .header;
        assert!(header.validate_ephemeral_keys(true).is_ok());
        assert!(header.validate_ephemeral_keys(false).is_err());
        header.set_ephemeral_verification_key(&key);
        assert!(header.validate_ephemeral_keys(false).is_ok());
        assert_eq!(header.ephemeral_storage_bytes(), 96);
    }

    #[test]
    fn evk_optional_fields_round_trip_through_bincode() {
        let header = Block::build_header(
            1,
            1,
            0,
            0,
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            0,
            0,
            0,
            ValueIndex::from_raw(0),
            PublicKey([0; 32]),
            10,
            Vec::new(),
            Vec::new(),
        )
        .header;
        let encoded = bincode::serialize(&header).unwrap();
        let decoded: BlockHeader = bincode::deserialize(&encoded).unwrap();
        assert_eq!(header, decoded);
    }
}
