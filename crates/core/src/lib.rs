//! Core Oxydome data types: amounts, transactions, operations, blocks and chain parameters.
//!
//! This crate is intentionally free of I/O and consensus logic; it defines the wire-level
//! vocabulary that every other crate shares.

pub mod block;
pub mod config;
pub mod genesis;
pub mod governance;
pub mod operation;
pub mod params;
pub mod tx;

pub use block::{Block, BlockHeader, ValueIndex, VALUE_SCALE};
pub use config::{AllocationConfig, AppConfig, ConfigError, EndpointConfig};
pub use genesis::{GenesisAllocation, GenesisConfig};
pub use governance::GovernanceSet;
pub use operation::{
    MasterApproval, NodeApproval, Operation, RewardDistribution, TreasuryBurn, TreasuryMint,
    WithdrawRequest,
};
pub use oxydome_crypto::{Hash, PublicKey, Sig};
pub use params::ChainParams;
pub use tx::{OutPoint, OutputKind, Transaction, TxError, TxInput, TxOutput};

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
