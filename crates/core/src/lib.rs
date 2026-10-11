//! Core Oxydome data types: amounts, transactions, operations, blocks and chain parameters.
//!
//! This crate is intentionally free of I/O and consensus logic; it defines the wire-level
//! vocabulary that every other crate shares.

pub mod block;
pub mod config;
pub mod dao;
pub mod gas;
pub mod genesis;
pub mod governance;
pub mod ohm;
pub mod operation;
pub mod params;
pub mod tx;

pub use block::{
    Block, BlockHeader, ValueIndex, LEGACY_EXECUTION_VERSION, OVM_EXECUTION_VERSION,
    SMART_CONTRACT_EXECUTION_VERSION, VALUE_SCALE,
};
pub use config::{AllocationConfig, AppConfig, ConfigError, EndpointConfig};
pub use dao::{
    DaoAction, DaoCurrency, DaoOperation, DaoPeg, DaoPolicy, DaoProposal, DaoProposalAction,
    DaoProposalStatus, DaoState, DaoWindowStats, DAO_POLICY_VERSION, MAX_DAO_CURRENCY_SYMBOL_BYTES,
    MAX_DAO_HOLDERS, MAX_DAO_MAKERS, MAX_DAO_PROPOSALS, MAX_DAO_PROPOSAL_HEIGHTS,
};
pub use gas::{
    conversion_split, conversion_split_with_bps, GasAccount, GasAction, GasOperation,
    GAS_BPS_DENOMINATOR, GAS_SERVER_FEE_BPS,
};
pub use genesis::{GenesisAllocation, GenesisConfig};
pub use governance::GovernanceSet;
pub use operation::{
    MasterApproval, NodeApproval, Operation, RewardDistribution, TreasuryBurn, TreasuryMint,
    WithdrawRequest,
};
pub use ohm::{
    build_ohm_server_outputs, compute_ohm_fee_split, hash_words, ohm_cross_msg_id,
    ohm_genesis_hash, ohm_inbox_root, ohm_outbox_root, ohm_state_root, ohm_state_root_full,
    ohm_treasury_outpoint, ohm_utxo_root, reply_arguments, CrossRecvCall, CrossSendCall,
    InboundReceipt, OhmAction, OhmBlock, OhmBlockHeader, OhmContext, OhmContract, OhmInput,
    OhmOperation, OhmOutput, OhmPolicy, OhmState, OhmTransaction, OhmUtxoEntry, OutboundMessage,
    MAX_CROSS_MESSAGE_ARGS, MAX_CROSS_MESSAGE_ENTRY_BYTES, MAX_OHM_BLOCK_TXS, MAX_OHM_NAME_BYTES,
    MAX_OHM_REASON_BYTES, MAX_OHM_TX_ITEMS, OHM_POLICY_MAGIC, OHM_POLICY_VERSION,
    OHM_SERVER_FEE_BPS,
};
pub use oxydome_crypto::{Hash, PublicKey, Sig};
pub use params::ChainParams;
pub use tx::{
    transfer_fee, transfer_fee_for_amount, OutPoint, OutputKind, OvmAction, OvmFailureCode, OvmLog,
    OvmReceipt, Transaction, TxError, TxInput, TxOutput, MAX_OVM_ARGUMENTS,
    MAX_OVM_BLOCK_GAS_LIMIT, MAX_OVM_GAS_LIMIT,
};

/// The Ox amount type. `u128` is used everywhere internally to make overflow practically
/// impossible while still allowing very large supplies.
pub type Amount = u128;

/// Returns the quorum size for `n` voters at a `num/den` super-majority, plus one.
///
/// For example `2/3` of 4 is `4*2/3 + 1 = 3`.
pub fn quorum(n: usize, num: usize, den: usize) -> usize {
    if den == 0 {
        return n;
    }
    (n * num) / den + 1
}

/// Error type shared across core validation helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("malformed value: {0}")]
    Malformed(String),
    #[error("amount overflow")]
    Overflow,
    #[error("amount underflow")]
    Underflow,
}
