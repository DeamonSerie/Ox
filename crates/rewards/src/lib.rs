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

/// Computes the GAS price derivative (rate of change) for block reward adjustments.
/// Returns basis points adjustment (can be negative, represented as i128).
fn compute_gas_price_derivative(
    state_ox_price: Amount,
    state_ox_price_reference: Amount,
    state_price_last_update_height: u64,
    state_height: u64,
    params: &ChainParams,
) -> i128 {
    // Minimum interval between price updates for derivative calculation
    if state_height < params.min_price_update_interval {
        return 0;
    }
    let blocks_since_update = state_height.saturating_sub(state_price_last_update_height);
    if blocks_since_update < params.min_price_update_interval {
        return 0;
    }
    if state_ox_price_reference == 0 {
        return 0;
    }

    // Compute normalized price change per block interval
    // Normalized price = ox_price / ox_price_reference
    // We approximate derivative as (current_normalized - 1.0) / blocks_since_update
    // scaled to basis points
    let normalized_price = state_ox_price as i128 * 10_000 / state_ox_price_reference as i128;
    let baseline = 10_000i128; // 1.0 in basis points
    let price_change = normalized_price - baseline;

    // Per-block change rate in basis points
    let per_block_change = if blocks_since_update > 0 {
        price_change * 10_000 / blocks_since_update as i128
    } else {
        0
    };

    // Apply sensitivity
    let sensitivity = params.gas_derivative_sensitivity_bps as i128;
    let adjustment = per_block_change * sensitivity / 10_000;

    // Cap the adjustment
    let cap = params.server_reward_cap_bps as i128;
    adjustment.clamp(-cap, cap)
}

/// Calculates minted block rewards for server nodes (block validation rewards).
///
/// Rewards are participation-weighted with proposer bonus, scaled by:
/// 1. Ox price multiplier (ox_price / ox_price_reference)
/// 2. GAS price derivative factor (capped)
pub fn calculate_server_block_rewards(
    params: &ChainParams,
    state_ox_price: Amount,
    state_ox_price_reference: Amount,
    state_price_last_update_height: u64,
    state_height: u64,
    nodes: &[PublicKey],
    proposer: &PublicKey,
) -> Vec<TxOutput> {
    if !params.block_rewards_enabled || nodes.is_empty() {
        return Vec::new();
    }

    // Base participation weights (proposer gets 3x with bonus=2)
    let weights = participation_weights(nodes, proposer, 2);

    // Ox price multiplier: normalize to reference price (minimum 1x)
    let price_multiplier = if state_ox_price_reference > 0 {
        (state_ox_price as u128).max(state_ox_price_reference) / state_ox_price_reference.max(1)
    } else {
        1
    };

    // GAS price derivative adjustment (in basis points, can be negative)
    let gas_derivative_bps = compute_gas_price_derivative(
        state_ox_price,
        state_ox_price_reference,
        state_price_last_update_height,
        state_height,
        params,
    );

    // Convert to u128 factor: 10000 + gas_derivative_bps (clamped)
    let cap = params.server_reward_cap_bps as i128;
    let clamped_derivative = gas_derivative_bps.clamp(-(cap), cap);
    let derivative_factor = if clamped_derivative >= 0 {
        10_000 + clamped_derivative as u128
    } else {
        10_000 - (-clamped_derivative) as u128
    };

    let base_reward = params.server_base_reward;

    weights
        .iter()
        .map(|(pk, weight)| {
            let reward = base_reward
                .saturating_mul(*weight as u128)          // participation weight
                .saturating_mul(price_multiplier)         // Ox price factor
                .saturating_mul(derivative_factor)        // GAS derivative factor
                / 10_000;                                 // basis points scaling

            TxOutput::locked_reward(reward, *pk)
        })
        .collect()
}

/// Calculates minted block rewards for master nodes (block initiation rewards).
///
/// Rewards are split equally among masters, scaled by the derivative of server rewards.
pub fn calculate_master_block_rewards(
    params: &ChainParams,
    prev_server_reward: Amount,
    current_server_reward: Amount,
    masters: &[PublicKey],
) -> Vec<TxOutput> {
    if !params.block_rewards_enabled || masters.is_empty() {
        return Vec::new();
    }

    // Compute server reward derivative (rate of change in basis points)
    let server_derivative_bps = if prev_server_reward > 0 {
        let diff = current_server_reward as i128 - prev_server_reward as i128;
        (diff * 10_000) / prev_server_reward as i128
    } else {
        0
    };

    // Apply sensitivity and cap
    let sensitivity = params.master_derivative_sensitivity_bps as i128;
    let cap = params.master_reward_cap_bps as i128;
    let adjustment = server_derivative_bps * sensitivity / 10_000;
    let clamped_adjustment = adjustment.clamp(-cap, cap);

    // Derivative factor: 10000 + clamped_adjustment
    let derivative_factor = if clamped_adjustment >= 0 {
        10_000 + clamped_adjustment as u128
    } else {
        10_000 - (-clamped_adjustment) as u128
    };

    let base_reward = params.master_base_reward;
    let per_master = base_reward
        .saturating_mul(derivative_factor)
        / 10_000;

    if per_master == 0 {
        return Vec::new();
    }

    // Equal split among masters
    masters
        .iter()
        .map(|pk| TxOutput::locked_reward(per_master, *pk))
        .collect()
}

/// Builds the minted block reward operation for a given block.
pub fn build_block_reward_operation(
    params: &ChainParams,
    state_ox_price: Amount,
    state_ox_price_reference: Amount,
    state_price_last_update_height: u64,
    state_height: u64,
    nodes: &[PublicKey],
    proposer: &PublicKey,
    masters: &[PublicKey],
    prev_server_reward: Amount,
) -> Option<Operation> {
    if !params.block_rewards_enabled {
        return None;
    }

    let server_outputs = calculate_server_block_rewards(
        params,
        state_ox_price,
        state_ox_price_reference,
        state_price_last_update_height,
        state_height,
        nodes,
        proposer,
    );

    if server_outputs.is_empty() {
        return None;
    }

    let current_server_reward: Amount = server_outputs.iter().map(|o| o.amount).sum();

    let master_outputs = calculate_master_block_rewards(
        params,
        prev_server_reward,
        current_server_reward,
        masters,
    );

    if master_outputs.is_empty() && server_outputs.is_empty() {
        return None;
    }

    Some(Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
        server_outputs,
        master_outputs,
    }))
}
