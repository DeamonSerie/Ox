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
            },
            transactions,
            operations,
            ovm_receipts: Vec::new(),
        }
    }
}
