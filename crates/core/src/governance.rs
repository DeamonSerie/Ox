//! Governance membership: the current master set and server-node set, plus quorum helpers.

use crate::params::ChainParams;
use crate::{quorum, PublicKey};
use serde::{Deserialize, Serialize};

/// The set of active masters and server nodes for the current epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSet {
    pub masters: Vec<PublicKey>,
    pub nodes: Vec<PublicKey>,
}

impl GovernanceSet {
    pub fn new(masters: Vec<PublicKey>, nodes: Vec<PublicKey>) -> Self {
        Self { masters, nodes }
    }

    pub fn contains_master(&self, key: &PublicKey) -> bool {
        self.masters.iter().any(|m| m == key)
    }

    pub fn contains_node(&self, key: &PublicKey) -> bool {
        self.nodes.iter().any(|n| n == key)
    }

    /// Number of master approvals required for a governance operation.
    pub fn master_threshold(&self, params: &ChainParams) -> usize {
        quorum(
            self.masters.len(),
            params.master_approval_num,
            params.master_approval_den,
        )
    }

    /// Number of server-node approvals required for a withdrawal.
    pub fn node_threshold(&self, params: &ChainParams) -> usize {
        quorum(
            self.nodes.len(),
            params.node_approval_num,
            params.node_approval_den,
        )
    }
}
