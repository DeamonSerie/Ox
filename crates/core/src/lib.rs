//! Core Oxydome data types: amounts, transactions, operations, blocks and chain parameters.
//!
//! This crate is intentionally free of I/O and consensus logic; it defines the wire-level
//! vocabulary that every other crate shares.

pub mod block;
pub mod coin_toss;
pub mod config;
pub mod dao;
pub mod express_bus;
pub mod gas;
pub mod genesis;
pub mod governance;
pub mod ohm;
pub mod operation;
pub mod params;
pub mod pricing;
pub mod speedometer;
pub mod storage;
pub mod timer;
pub mod tx;

pub use block::{
    Block, BlockHeader, ValueIndex, LEGACY_EXECUTION_VERSION, OVM_EXECUTION_VERSION,
    SMART_CONTRACT_EXECUTION_VERSION, VALUE_SCALE,
};
pub use coin_toss::{aggregate_seed, ordered_root, ordered_transactions};
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
pub use operation::{
    BlockRewardDistribution, DepartureEarningsDistribution, DepartureType, MasterApproval,
    NodeApproval, NodeKind, NodeLeaveRequest, Operation, RewardDistribution, TokenAmount,
    TreasuryBurn, TreasuryMint, WithdrawRequest,
};
pub use operation::{FileAccessOperation, FileDeleteOperation, FileStoreOperation, LiquidityPoolAction, LiquidityPoolOperation};
pub use operation::{StorageAuditOperation, StorageLabelOperation};
pub use oxydome_crypto::evk::{FileEvkLabel, FileKeyChain};
pub use oxydome_crypto::{Hash, PublicKey, Sig};
pub use params::ChainParams;
pub use pricing::{
    compute_gas_price, compute_gas_price_premium, compute_price_bounds,
    default_liquidity_pool_activation_height, default_liquidity_pool_fee_bps,
    default_max_liquidity_pools, default_pegged_currency_activation_height,
    default_pegged_spread_bps, default_pegged_window_blocks, is_in_upper_half, pack_pool_state,
    pegged_convert, pool_swap, scale_to_u64, LiquidityPoolConfig, LiquidityPoolState,
    PeggedCurrencyConfig, PeggedCurrencyState, PoolKParams, PoolStatePacked, PriceAsset,
    PriceBounds, PriceSample, LIQUIDITY_POOL_SCALE,
};
pub use speedometer::{SpeedometerAccount, SpeedometerAction, SpeedometerOperation};
pub use storage::{
    evfs_label_commitment_v2, label_commitment, FileAccessRecord, FileEvkLabelError,
    StorageAuditResult, StorageLabel,
};
pub use timer::{
    accumulated_track, actual_direction, reward_for_bet, timer_burn_outpoint, Timer, TimerAction,
    TimerAsset, TimerBet, TimerConfig, TimerDirection, TimerOperation, TimerSample, MAX_TIMERS,
    MAX_TIMER_BETS, MAX_TIMER_BET_DIGITS, MAX_TIMER_DURATION_BLOCKS, MAX_TIMER_REASON_BYTES,
};
pub use express_bus::{
    bus_flow_delta, is_ox_asset, BusSample, ExpressBusDeposit, ExpressBusTracker,
    ExpressBusWithdraw, FP as EXPRESS_FP, MAX_EXPRESS_BUSES,
};
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
