//! Genesis configuration: initial supply distribution and the founding master/node sets.

use crate::params::ChainParams;
use crate::{Amount, PublicKey};
use serde::{Deserialize, Serialize};

/// A single genesis account allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub recipient: PublicKey,
    pub amount: Amount,
}

/// Everything needed to bootstrap a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub params: ChainParams,
    /// Initial balances. The sum must equal `params.genesis_supply`.
    pub allocations: Vec<GenesisAllocation>,
    /// Founding masters. Exactly one at launch.
    pub masters: Vec<PublicKey>,
    /// Founding server nodes.
    pub nodes: Vec<PublicKey>,
    /// UNIX timestamp recorded in the genesis header.
    pub timestamp: u64,
}

impl GenesisConfig {
    pub fn allocated_supply(&self) -> Amount {
        self.allocations
            .iter()
            .map(|a| a.amount)
            .fold(0u128, |x, y| x.saturating_add(y))
    }
}
