//! Chain-wide parameters. All economic and consensus constants are integers or rationals so
//! that every node computes identical results — floating point is never used on-chain.

use crate::Amount;
use serde::{Deserialize, Serialize};

/// Rational thresholds and economic constants governing Oxydome.
///
/// Rationals are expressed as numerator/denominator pairs. Basis points are `value / 10_000`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    // ---- supply and windows ----
    /// Total Ox created at genesis and distributed to genesis accounts.
    pub genesis_supply: Amount,
    /// Length `W` of the measurement window, in blocks.
    pub block_window: u64,
    /// Number of blocks `L` a rebound-credited coin stays locked (bunny-hop maturity).
    pub rebound_lock_blocks: u64,
    /// Audit checkpoint interval `K`, in blocks.
    pub audit_checkpoint_blocks: u64,

    // ---- fee split ----
    /// Share of block fees paid to masters, in basis points (`400` = 4%).
    pub fee_master_bps: u32,

    // ---- consensus thresholds ----
    /// BFT commit super-majority numerator (e.g. 2).
    pub bft_num: usize,
    /// BFT commit super-majority denominator (e.g. 3).
    pub bft_den: usize,
    /// Master audit sign-off super-majority numerator.
    pub master_approval_num: usize,
    /// Master audit sign-off super-majority denominator.
    pub master_approval_den: usize,
    /// Server-node withdrawal approval super-majority numerator.
    pub node_approval_num: usize,
    /// Server-node withdrawal approval super-majority denominator.
    pub node_approval_den: usize,

    // ---- currency index ----
    /// Weight of transaction volume in the activity term, basis points.
    pub alpha_bps: u32,
    /// Weight of mean transaction amount in the activity term, basis points.
    pub beta_bps: u32,
    /// Weight of exit pressure, basis points.
    pub gamma_bps: u32,
    /// Supply sensitivity exponent of exit pressure, basis points.
    pub eta_bps: u32,
    /// Exponential-moving-average smoothing, basis points (`1000` = 0.10).
    pub lambda_bps: u32,
    /// Reference transaction volume for the logarithm.
    pub t_ref: Amount,
    /// Reference mean transaction amount for the logarithm.
    pub a_ref: Amount,
    /// Reference exit amount for the pressure term.
    pub e_ref: Amount,
    /// Starting value index (fixed point, 1e12 == 1.000).
    pub initial_value_index: u128,

    // ---- guardrails ----
    /// Maximum tolerated value-index move from any single governance action, basis points.
    pub value_impact_limit_bps: u32,
    /// Maximum mint/burn supply change per epoch, basis points of genesis supply.
    pub supply_change_limit_bps: u32,
    /// Fee-affordability coefficient `rho`, basis points.
    pub fee_affordability_bps: u32,
    /// Smallest meaningful transaction amount `A_min`.
    pub min_tx_amount: Amount,
    /// Maximum server withdrawal per epoch, basis points of genesis supply.
    pub withdraw_limit_bps: u32,
    /// Per-account withdrawal limit, basis points of the account's balance.
    /// 3000 = 30% may be withdrawn per operation; adjust via master-node governance.
    pub per_account_withdraw_bps: u32,
    /// Base fee charged per transaction at value index 1.000.
    pub base_fee: Amount,
}

impl ChainParams {
    /// Sensible local-network defaults.
    pub fn default_local() -> Self {
        ChainParams {
            genesis_supply: 1_000_000_000,
            block_window: 100,
            rebound_lock_blocks: 100,
            audit_checkpoint_blocks: 50,
            fee_master_bps: 400,
            bft_num: 2,
            bft_den: 3,
            master_approval_num: 2,
            master_approval_den: 3,
            node_approval_num: 2,
            node_approval_den: 3,
            alpha_bps: 6_000,
            beta_bps: 4_000,
            gamma_bps: 5_000,
            eta_bps: 500,
            lambda_bps: 1_000,
            t_ref: 10_000,
            a_ref: 100,
            e_ref: 10_000,
            initial_value_index: 1_000_000_000_000,
            value_impact_limit_bps: 200,
            supply_change_limit_bps: 10,
            fee_affordability_bps: 100,
            min_tx_amount: 100,
            withdraw_limit_bps: 10,
            per_account_withdraw_bps: 3000,
            base_fee: 1,
        }
    }
}
