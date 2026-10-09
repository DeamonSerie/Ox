//! Fee rewards and node withdrawals.
//!
//! Block fees are split 4/96 between masters and server nodes by default. Master shares are
//! divided equally; server shares are participation-weighted (the block proposer earns a
//! bonus). All earnings are `LockedReward` outputs, unlockable only through an approved
//! withdrawal.

use oxydome_core::{
    Amount, ChainParams, NodeApproval, Operation, OutPoint, PublicKey, RewardDistribution,
    TxOutput, WithdrawRequest,
};
use oxydome_crypto::{KeyPair, Sig};
use oxydome_currency::withdraw_cap;

/// Splits a pool among `recipients` weighted by the second tuple element. Remainder (from
/// integer division) is given to the first recipient. Zero-weight pools split equally.
fn split_pool(pool: Amount, recipients: &[(PublicKey, u128)]) -> Vec<TxOutput> {
    if pool == 0 || recipients.is_empty() {
        return Vec::new();
    }
    let total_weight: u128 = recipients.iter().map(|(_, w)| *w).sum();
    let mut outputs = Vec::new();
    let mut assigned: Amount = 0;
    if total_weight == 0 {
        let base = pool / recipients.len() as u128;
        for (i, (key, _)) in recipients.iter().enumerate() {
            let amount = if i == 0 {
                pool - base * (recipients.len() as u128 - 1)
            } else {
                base
            };
            if amount > 0 {
                outputs.push(TxOutput::locked_reward(amount, *key));
                assigned = assigned.saturating_add(amount);
            }
        }
        let _ = assigned;
        return outputs;
    }
    for (i, (key, weight)) in recipients.iter().enumerate() {
        let amount = if i == 0 {
            // First recipient absorbs the rounding remainder.
            let rest: Amount = recipients
                .iter()
                .skip(1)
                .map(|(_, w)| pool.saturating_mul(*w) / total_weight)
                .fold(0u128, |a, b| a.saturating_add(b));
            pool.saturating_sub(rest)
        } else {
            pool.saturating_mul(*weight) / total_weight
        };
        if amount > 0 {
            outputs.push(TxOutput::locked_reward(amount, *key));
        }
    }
    outputs
}

/// Builds the reward distribution for a block given its total fees, the master set and the
/// participation weights of the server nodes.
pub fn split_fees(
    total_fees: Amount,
    params: &ChainParams,
    masters: &[PublicKey],
    node_weights: &[(PublicKey, u128)],
) -> RewardDistribution {
    if total_fees == 0 {
        return RewardDistribution {
            master_outputs: Vec::new(),
            node_outputs: Vec::new(),
        };
    }
    let master_share = total_fees.saturating_mul(params.fee_master_bps as u128) / 10_000;
    let node_share = total_fees.saturating_sub(master_share);
    let master_weights: Vec<(PublicKey, u128)> = masters.iter().map(|m| (*m, 1u128)).collect();
    RewardDistribution {
        master_outputs: split_pool(master_share, &master_weights),
        node_outputs: split_pool(node_share, node_weights),
    }
}

/// Builds participation weights for server nodes, giving the proposer a bonus multiple.
pub fn participation_weights(
    nodes: &[PublicKey],
    proposer: &PublicKey,
    proposer_bonus: u128,
) -> Vec<(PublicKey, u128)> {
    nodes
        .iter()
        .map(|n| {
            if n == proposer {
                (*n, 1 + proposer_bonus)
            } else {
                (*n, 1)
            }
        })
        .collect()
}

/// Creates a withdrawal request with no signature or approvals yet.
pub fn withdraw_proposal(
    node: PublicKey,
    inputs: Vec<OutPoint>,
    amount: Amount,
) -> WithdrawRequest {
    WithdrawRequest {
        node,
        inputs,
        amount,
        node_signature: Sig([0u8; 64]),
        approvals: Vec::new(),
    }
}

/// The proposal id that node approvals and the node signature must sign.
pub fn withdraw_proposal_id(
    node: PublicKey,
    inputs: Vec<OutPoint>,
    amount: Amount,
) -> oxydome_core::Hash {
    Operation::Withdraw(withdraw_proposal(node, inputs, amount)).proposal_id()
}

/// Signs a withdrawal with the requesting node's key.
pub fn sign_withdraw(w: &mut WithdrawRequest, node_key: &KeyPair) {
    let id = Operation::Withdraw(w.clone()).proposal_id();
    w.node_signature = node_key.sign(&id.0);
}

/// Appends a server node's approval to a withdrawal.
pub fn approve_withdraw(w: &mut WithdrawRequest, node_key: &KeyPair) {
    let id = Operation::Withdraw(w.clone()).proposal_id();
    w.approvals.push(NodeApproval {
        node: node_key.public(),
        proposal: id,
        signature: node_key.sign(&id.0),
    });
}

/// The largest withdrawal still permitted in the current epoch.
pub fn max_withdraw(params: &ChainParams, epoch_withdrawn: Amount) -> Amount {
    withdraw_cap(params).saturating_sub(epoch_withdrawn)
}
