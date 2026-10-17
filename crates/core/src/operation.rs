//! Block-level operations: treasury mint/burn, node withdrawals and fee rewards.
//!
//! Operations are distinct from ordinary transactions because they change the *supply* or the
//! *lock state* of Ox and therefore require governance approval (masters for mint/burn, server
//! nodes for withdrawals). Fee rewards are validated against the block's collected fees.

use crate::tx::TxOutput;
use crate::{
    Amount, DaoAction, DaoOperation, ExpressBusDeposit, ExpressBusWithdraw, GasAction,
    GasOperation, OhmAction, OhmOperation, PriceAsset, OutPoint,
};
use oxydome_crypto::{hash_value, verify, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};

/// The role of a node in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum NodeKind {
    Server,
    Master,
}

/// An amount of a specific asset/token held by a node.
/// `asset_id` of `None` refers to the native Ox unit-of-account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAmount {
    pub asset_id: Option<Hash>,
    pub amount: Amount,
}

/// Records the redistribution of held earnings when a node departs.
/// Half of the departed node's held earnings are distributed equally to the
/// connected members of both the server and master node groups. The remainder
/// of the held earnings is retained by the departing node for a cooling-off
/// period (and may be claimed later through the standard withdrawal path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepartureEarningsDistribution {
    /// Public keys of the departing node(s).
    pub departed_nodes: Vec<PublicKey>,
    /// Total earnings held by the departed nodes before redistribution.
    pub total_held: Vec<TokenAmount>,
    /// Amount distributed (half of held) across all tokens.
    pub distributed: Vec<TokenAmount>,
    /// Per-recipient distribution to connected server nodes: (recipient, tokens).
    pub server_distributions: Vec<(PublicKey, Vec<TokenAmount>)>,
    /// Per-recipient distribution to connected master nodes: (recipient, tokens).
    pub master_distributions: Vec<(PublicKey, Vec<TokenAmount>)>,
    /// Block height at which this distribution was recorded.
    pub block_height: u64,
    /// Whether this departure was a voluntary leave or a liveness-triggered eviction.
    pub departure_type: DepartureType,
}

/// How a node departed the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepartureType {
    Graceful,
    LivenessTriggered,
}

/// A withdrawal request for earnings held by a departing node.
///
/// `take_fraction` is basis points of the held earnings to confiscate and
/// redistribute (default `5000` = 50%). The remainder stays locked for the
/// departing node and is handled via the standard withdrawal flow after the
/// cooling-off period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepartureWithdrawRequest {
    pub node: PublicKey,
    pub node_kind: NodeKind,
    pub inputs: Vec<OutPoint>,
    /// Sum of input amounts being withdrawn (must match sum of inputs).
    pub amount: Amount,
    /// The fraction of the held earnings being confiscated/redistributed.
    pub take_fraction_bps: u32,
    pub node_signature: Sig,
    pub approvals: Vec<NodeApproval>,
    pub master_approvals: Vec<MasterApproval>,
}

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
///
/// `nonce` makes each proposal (and its derived proposal id and minted outpoint) unique. It is
/// part of the signed payload, so a previously approved proposal cannot be replayed to mint the
/// same amount again without fresh approvals for a new nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryMint {
    pub amount: Amount,
    pub recipient: PublicKey,
    pub nonce: u64,
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

/// A proposal to change the GAS price oracle value. Requires master super-majority approval,
/// followed by server consensus with change limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryPriceChange {
    /// The new Ox price oracle value (same scale as ox_price_reference).
    pub new_price: Amount,
    /// Basis points of master approvals collected.
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

/// Distribution of minted block rewards (separate from fee-based rewards).
/// Server nodes receive validation rewards based on participation and GAS price derivatives.
/// Master nodes receive initiation rewards based on server reward derivatives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRewardDistribution {
    pub server_outputs: Vec<TxOutput>,
    pub master_outputs: Vec<TxOutput>,
}

impl BlockRewardDistribution {
    pub fn server_total(&self) -> Amount {
        self.server_outputs
            .iter()
            .map(|o| o.amount)
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    pub fn master_total(&self) -> Amount {
        self.master_outputs
            .iter()
            .map(|o| o.amount)
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    pub fn total(&self) -> Amount {
        self.server_total().saturating_add(self.master_total())
    }

    pub fn all_outputs(&self) -> impl Iterator<Item = &TxOutput> {
        self.server_outputs.iter().chain(self.master_outputs.iter())
    }
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
        nonce: u64,
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
    BlockRewards {
        server_outputs: Vec<TxOutput>,
        master_outputs: Vec<TxOutput>,
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
    PriceChange {
        new_price: Amount,
    },
    StorageLabel {
        node: PublicKey,
        height: u64,
        capacity_bytes: u64,
        used_bytes: u64,
        available_bytes: u64,
        timestamp: u64,
    },
    StorageAudit {
        epoch: u64,
        network_available: u64,
        expected_network_storage: u64,
        compliant: bool,
    },
    NodeLeave {
        node: PublicKey,
        node_kind: NodeKind,
    },
    DepartureEarnings {
        departed_nodes: Vec<PublicKey>,
        total_held: Vec<TokenAmount>,
        distributed: Vec<TokenAmount>,
        block_height: u64,
        departure_type: DepartureType,
    },
    Timer {
        actor: PublicKey,
        nonce: u64,
        action: crate::timer::TimerAction,
    },
    Speedometer {
        actor: PublicKey,
        nonce: u64,
        action: crate::speedometer::SpeedometerAction,
    },
    FileStore {
        file_label: oxydome_crypto::evk::FileEvkLabel,
    },
    FileAccess {
        accessor: PublicKey,
        file_id: Hash,
        content_hash: Hash,
        timestamp: u64,
    },
    FileDelete {
        deleter: PublicKey,
        file_id: Hash,
        content_hash: Hash,
    },
    LiquidityPool {
        actor: PublicKey,
        nonce: u64,
        action: LiquidityPoolAction,
    },
    ExpressBusDeposit {
        bus_id: Hash,
        asset: PriceAsset,
        depositor: PublicKey,
        inputs: Vec<OutPoint>,
        amount: Amount,
        nonce: u64,
    },
    ExpressBusWithdraw {
        bus_id: Hash,
        asset: PriceAsset,
        owner: PublicKey,
        inputs: Vec<OutPoint>,
        amount: Amount,
        nonce: u64,
    },
}


/// A node's request to leave the network.
///
/// Servers require `2/3+1` server-node approvals; masters require `2/3+1`
/// master approvals. On approval, half of the node's held earnings are
/// redistributed to the connected members of both node groups, and the
/// departure is recorded on-chain as `DepartureEarnings` distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLeaveRequest {
    pub node: PublicKey,
    pub node_kind: NodeKind,
    pub node_signature: Sig,
    pub approvals: Vec<NodeApproval>,
    pub master_approvals: Vec<MasterApproval>,
}

/// A proposal to set a node's storage label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLabelOperation {
    pub label: crate::storage::StorageLabel,
    pub approvals: Vec<NodeApproval>,
}

/// An epoch storage audit result recorded on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAuditOperation {
    pub result: crate::storage::StorageAuditResult,
    pub approvals: Vec<MasterApproval>,
}

/// A file store operation, recording a file label on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStoreOperation {
    pub file_label: oxydome_crypto::evk::FileEvkLabel,
    pub approvals: Vec<NodeApproval>,
}

/// A file access record operation, recording a FileAccessRecord on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccessOperation {
    pub accessor: PublicKey,
    pub file_id: Hash,
    pub content_hash: Hash,
    pub timestamp: u64,
    pub signature: Sig,
}

/// A file deletion operation, removing a file label from the on-chain record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeleteOperation {
    pub deleter: PublicKey,
    pub file_id: Hash,
    pub content_hash: Hash,
    pub signature: Sig,
}

/// Actions performable through LiquidityPool operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiquidityPoolAction {
    /// Create a new liquidity pool for the given currencies.
    Create { currencies: Vec<PriceAsset> },
    /// Provide liquidity to an existing pool.
    Provide { amounts: std::collections::BTreeMap<PriceAsset, Amount> },
    /// Remove liquidity from a pool.
    RemoveLiquidity { amounts: std::collections::BTreeMap<PriceAsset, Amount> },
    /// Swap one asset for another through the pool.
    Swap {
        input_asset: PriceAsset,
        input_amount: Amount,
        min_output: Amount,
    },
}

/// A signed liquidity pool operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPoolOperation {
    /// Actor (signer) of this operation.
    pub actor: PublicKey,
    /// The liquidity pool action.
    pub action: LiquidityPoolAction,
    /// Nonce to prevent replay.
    pub nonce: u64,
    /// Signature over the signing payload.
    pub signature: Sig,
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
    PriceChange(TreasuryPriceChange),
    BlockRewards(BlockRewardDistribution),
    StorageLabel(StorageLabelOperation),
    StorageAudit(StorageAuditOperation),
    Timer(crate::timer::TimerOperation),
    Speedometer(crate::speedometer::SpeedometerOperation),
    FileStore(FileStoreOperation),
    FileAccess(FileAccessOperation),
    FileDelete(FileDeleteOperation),
    LiquidityPool(LiquidityPoolOperation),
    /// A master-approved deposit into an Express Bus route (tags UTXOs as BusReceipt).
    ExpressBusDeposit(ExpressBusDeposit),
    /// A node-approved, owner-signed withdrawal from an Express Bus route
    /// (spends BusReceipt UTXOs).
    ExpressBusWithdraw(ExpressBusWithdraw),
    /// A node departing the network (graceful leave).
    NodeLeave(NodeLeaveRequest),
    /// Earnings redistribution from a departing node, recorded on-chain.
    DepartureEarnings(DepartureEarningsDistribution),
}

impl Operation {
    /// The hash that approvals sign and that ties an operation to its governance record.
    pub fn proposal_id(&self) -> Hash {
        let signable = match self {
            Operation::Mint(m) => SignableOperation::Mint {
                amount: m.amount,
                recipient: m.recipient,
                nonce: m.nonce,
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
            Operation::PriceChange(tp) => SignableOperation::PriceChange {
                new_price: tp.new_price,
            },
            Operation::BlockRewards(b) => SignableOperation::BlockRewards {
                server_outputs: b.server_outputs.clone(),
                master_outputs: b.master_outputs.clone(),
            },
            Operation::StorageLabel(op) => SignableOperation::StorageLabel {
                node: op.label.node,
                height: op.label.height,
                capacity_bytes: op.label.capacity_bytes,
                used_bytes: op.label.used_bytes,
                available_bytes: op.label.available_bytes,
                timestamp: op.label.timestamp,
            },
            Operation::StorageAudit(op) => SignableOperation::StorageAudit {
                epoch: op.result.epoch,
                network_available: op.result.network_available,
                expected_network_storage: op.result.expected_network_storage,
                compliant: op.result.compliant,
            },
            Operation::NodeLeave(l) => SignableOperation::NodeLeave {
                node: l.node,
                node_kind: l.node_kind,
            },
            Operation::DepartureEarnings(d) => SignableOperation::DepartureEarnings {
                departed_nodes: d.departed_nodes.clone(),
                total_held: d.total_held.clone(),
                distributed: d.distributed.clone(),
                block_height: d.block_height,
                departure_type: d.departure_type,
            },
            Operation::Timer(op) => SignableOperation::Timer {
                actor: op.actor,
                nonce: op.nonce,
                action: op.action.clone(),
            },
            Operation::Speedometer(op) => SignableOperation::Speedometer {
                actor: op.actor,
                nonce: op.nonce,
                action: op.action.clone(),
            },
            Operation::FileStore(op) => SignableOperation::FileStore {
                file_label: op.file_label.clone(),
            },
            Operation::FileAccess(op) => SignableOperation::FileAccess {
                accessor: op.accessor,
                file_id: op.file_id,
                content_hash: op.content_hash,
                timestamp: op.timestamp,
            },
            Operation::FileDelete(op) => SignableOperation::FileDelete {
                deleter: op.deleter,
                file_id: op.file_id,
                content_hash: op.content_hash,
            },
            Operation::LiquidityPool(op) => SignableOperation::LiquidityPool {
                actor: op.actor,
                nonce: op.nonce,
                action: op.action.clone(),
            },
            Operation::ExpressBusDeposit(op) => SignableOperation::ExpressBusDeposit {
                bus_id: op.bus_id,
                asset: op.asset,
                depositor: op.depositor,
                inputs: op.inputs.clone(),
                amount: op.amount,
                nonce: op.nonce,
            },
            Operation::ExpressBusWithdraw(op) => SignableOperation::ExpressBusWithdraw {
                bus_id: op.bus_id,
                asset: op.asset,
                owner: op.owner,
                inputs: op.inputs.clone(),
                amount: op.amount,
                nonce: op.nonce,
            },
        };
        hash_value(&signable)
    }

    pub fn master_approvals(&self) -> &[MasterApproval] {
        match self {
            Operation::Mint(m) => &m.approvals,
            Operation::Burn(b) => &b.approvals,
            Operation::Gas(g) => &g.approvals,
            Operation::PriceChange(p) => &p.approvals,
            Operation::StorageAudit(a) => &a.approvals,
            Operation::NodeLeave(l) => &l.master_approvals,
            Operation::Timer(t) => &t.approvals,
            Operation::ExpressBusDeposit(d) => &d.approvals,
            Operation::LiquidityPool(_) => &[],
            Operation::BlockRewards(_) | Operation::StorageLabel(_) => &[],
            _ => &[],
        }
    }

    pub fn node_approvals(&self) -> &[NodeApproval] {
        match self {
            Operation::Withdraw(w) => &w.approvals,
            Operation::StorageLabel(l) => &l.approvals,
            Operation::NodeLeave(l) => &l.approvals,
            Operation::ExpressBusWithdraw(w) => &w.approvals,
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
                | Operation::StorageLabel(_)
                | Operation::StorageAudit(_)
                | Operation::LiquidityPool(_)
                | Operation::NodeLeave(_)
                | Operation::DepartureEarnings(_)
                | Operation::ExpressBusDeposit(_)
                | Operation::ExpressBusWithdraw(_)
        )
    }

    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}
