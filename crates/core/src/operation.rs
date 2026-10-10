//! Block-level operations: treasury mint/burn, node withdrawals and fee rewards.
//!
//! Operations are distinct from ordinary transactions because they change the *supply* or the
//! *lock state* of Ox and therefore require governance approval (masters for mint/burn, server
//! nodes for withdrawals). Fee rewards are validated against the block's collected fees.

use crate::tx::TxOutput;
use crate::{Amount, DaoAction, DaoOperation, GasAction, GasOperation, OhmAction, OhmOperation, OutPoint};
use oxydome_crypto::{hash_value, verify, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};

/// A master's signature approving a governance operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterApproval {
    pub master: PublicKey,
    pub proposal: Hash,
    pub signature: Sig,
}

/// A server-node signature approving a withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeApproval {
    pub node: PublicKey,
    pub proposal: Hash,
    pub signature: Sig,
}

impl MasterApproval {
    pub fn is_valid(&self, proposal: &Hash) -> bool {
        self.proposal == *proposal && verify(&self.master, &proposal.0, &self.signature)
    }
}

impl NodeApproval {
    pub fn is_valid(&self, proposal: &Hash) -> bool {
        self.proposal == *proposal && verify(&self.node, &proposal.0, &self.signature)
    }
}

/// A proposal to mint new Ox. Requires master super-majority approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryMint {
    pub amount: Amount,
    pub recipient: PublicKey,
    pub approvals: Vec<MasterApproval>,
}

/// A proposal to burn existing Ox held in `source`. Requires master super-majority approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryBurn {
    pub source: OutPoint,
    pub owner: PublicKey,
    pub owner_signature: Sig,
    pub amount: Amount,
    pub approvals: Vec<MasterApproval>,
}

/// A node's request to unlock `amount` of its on-chain fee earnings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub node: PublicKey,
    pub inputs: Vec<OutPoint>,
    pub amount: Amount,
    pub node_signature: Sig,
    pub approvals: Vec<NodeApproval>,
}

/// Distribution of a block's fees. `master_outputs` must sum to exactly the master share
/// (`fee_master_bps` of the block's fees) and `node_outputs` to the remainder. Together they
/// must equal the sum of transaction fees in the block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub master_outputs: Vec<TxOutput>,
    pub node_outputs: Vec<TxOutput>,
}

impl RewardDistribution {
    pub fn master_total(&self) -> Amount {
        self.master_outputs
            .iter()
            .map(|o| o.amount)
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    pub fn node_total(&self) -> Amount {
        self.node_outputs
            .iter()
            .map(|o| o.amount)
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    pub fn total(&self) -> Amount {
        self.master_total().saturating_add(self.node_total())
    }

    pub fn all_outputs(&self) -> impl Iterator<Item = &TxOutput> {
        self.master_outputs.iter().chain(self.node_outputs.iter())
    }
}

/// The canonical, signature-free data a governance proposal commits to.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SignableOperation {
    Mint {
        amount: Amount,
        recipient: PublicKey,
    },
    Burn {
        source: OutPoint,
        owner: PublicKey,
        amount: Amount,
    },
    Withdraw {
        node: PublicKey,
        inputs: Vec<OutPoint>,
        amount: Amount,
    },
    Rewards {
        master_outputs: Vec<TxOutput>,
        node_outputs: Vec<TxOutput>,
    },
    Dao {
        actor: PublicKey,
        action: DaoAction,
    },
    Ohm {
        actor: PublicKey,
        action: OhmAction,
    },
    Gas {
        actor: PublicKey,
        nonce: u64,
        action: GasAction,
    },
}

/// A block operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Mint(TreasuryMint),
    Burn(TreasuryBurn),
    Withdraw(WithdrawRequest),
    Rewards(RewardDistribution),
    Dao(DaoOperation),
    Ohm(OhmOperation),
    Gas(GasOperation),
}

impl Operation {
    /// The hash that approvals sign and that ties an operation to its governance record.
    pub fn proposal_id(&self) -> Hash {
        let signable = match self {
            Operation::Mint(m) => SignableOperation::Mint {
                amount: m.amount,
                recipient: m.recipient,
            },
            Operation::Burn(b) => SignableOperation::Burn {
                source: b.source,
                owner: b.owner,
                amount: b.amount,
            },
            Operation::Withdraw(w) => SignableOperation::Withdraw {
                node: w.node,
                inputs: w.inputs.clone(),
                amount: w.amount,
            },
            Operation::Rewards(r) => SignableOperation::Rewards {
                master_outputs: r.master_outputs.clone(),
                node_outputs: r.node_outputs.clone(),
            },
            Operation::Dao(op) => SignableOperation::Dao {
                actor: op.actor,
                action: op.action.clone(),
            },
            Operation::Ohm(op) => SignableOperation::Ohm {
                actor: op.actor,
                action: op.action.clone(),
            },
            Operation::Gas(op) => SignableOperation::Gas {
                actor: op.actor,
                nonce: op.nonce,
                action: op.action.clone(),
            },
        };
        hash_value(&signable)
    }

    pub fn master_approvals(&self) -> &[MasterApproval] {
        match self {
            Operation::Mint(m) => &m.approvals,
            Operation::Burn(b) => &b.approvals,
            Operation::Gas(g) => &g.approvals,
            _ => &[],
        }
    }

    pub fn node_approvals(&self) -> &[NodeApproval] {
        match self {
            Operation::Withdraw(w) => &w.approvals,
            _ => &[],
        }
    }

    /// Counts distinct, valid master approvals for this operation's proposal id.
    pub fn valid_master_approvals(&self) -> usize {
        let id = self.proposal_id();
        let mut seen = std::collections::BTreeSet::new();
        self.master_approvals()
            .iter()
            .filter(|a| a.is_valid(&id) && seen.insert(a.master))
            .count()
    }

    /// Counts distinct, valid node approvals for this operation's proposal id.
    pub fn valid_node_approvals(&self) -> usize {
        let id = self.proposal_id();
        let mut seen = std::collections::BTreeSet::new();
        self.node_approvals()
            .iter()
            .filter(|a| a.is_valid(&id) && seen.insert(a.node))
            .count()
    }

    pub fn is_governance(&self) -> bool {
        matches!(
            self,
            Operation::Mint(_)
                | Operation::Burn(_)
                | Operation::Withdraw(_)
                | Operation::Dao(_)
                | Operation::Ohm(_)
                | Operation::Gas(_)
        )
    }

    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}
