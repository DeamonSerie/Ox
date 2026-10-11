//! Chain-wide parameters. All economic and consensus constants are integers or rationals so
//! that every node computes identical results — floating point is never used on-chain.

use crate::Amount;
use serde::{Deserialize, Serialize};

/// Rational thresholds and economic constants governing Oxydome.
///
/// Rationals are expressed as numerator/denominator pairs. Basis points are `value / 10_000`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    /// Human-readable chain name (defaults to "Ox").
    #[serde(default = "default_chain_name")]
    pub chain_name: String,
    /// Currency symbol token (defaults to "OX").
    #[serde(default = "default_currency_symbol")]
    pub currency_symbol: String,

    // ---- supply and windows ----
    /// Total Ox created at genesis and distributed to genesis accounts.
    pub genesis_supply: Amount,
    /// Length `W` of the measurement window, in blocks.
    pub block_window: u64,
    /// Number of blocks `L` a rebound-credited coin stays locked (bunny-hop maturity).
    pub rebound_lock_blocks: u64,
    /// Audit checkpoint interval `K`, in blocks.
    pub audit_checkpoint_blocks: u64,
    /// Height at which version 2 OVM execution rules become mandatory.
    #[serde(default = "default_ovm_activation_height")]
    pub ovm_activation_height: u64,
    /// Height at which multi-entry-point user smart-contract artifacts become valid.
    #[serde(default = "default_smart_contract_activation_height")]
    pub smart_contract_activation_height: u64,

    // ---- GAS fuel currency ----
    /// Height at which GAS minting, burning and airdrops become active.
    #[serde(default = "default_one")]
    pub gas_activation_height: u64,
    /// Share of every server-node reward converted from Ox into GAS, in basis points.
    #[serde(default = "default_gas_server_fee_bps")]
    pub gas_server_fee_bps: u32,
    /// Number of blocks between automatic GAS airdrops (`0` disables airdrops).
    #[serde(default = "default_airdrop_interval_blocks")]
    pub airdrop_interval_blocks: u64,
    /// Base airdrop size as basis points of the current circulating GAS supply.
    #[serde(default = "default_airdrop_base_bps")]
pub airdrop_base_bps: u32,
    /// Normalizing reference for the Ox price oracle in the airdrop formula.
    #[serde(default = "default_amount_one")]
    pub ox_price_reference: Amount,
    /// Height at which GAS price updates become active.
    #[serde(default = "default_one")]
    pub price_update_height: u64,
    /// Master approval threshold for price changes (bps denominator).
    #[serde(default = "default_price_update_threshold")]
    pub price_update_threshold: u32,
    /// Maximum basis points change allowed per price update interval.
    #[serde(default = "default_price_change_limit_bps")]
    pub price_change_limit_bps: u32,
    /// Weighted average smoothing factor for price changes.
    #[serde(default = "default_price_smoothing_bps")]
    pub price_smoothing_bps: u32,

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

fn default_chain_name() -> String {
    "Ox".to_string()
}

fn default_currency_symbol() -> String {
    "OX".to_string()
}

fn default_ovm_activation_height() -> u64 {
    1
}

fn default_smart_contract_activation_height() -> u64 {
    u64::MAX
}

fn default_one() -> u64 {
    1
}

fn default_amount_one() -> Amount {
    1
}

fn default_gas_server_fee_bps() -> u32 {
    2_000
}

fn default_airdrop_interval_blocks() -> u64 {
    100
}

fn default_airdrop_base_bps() -> u32 {
    100
}

fn default_price_update_threshold() -> u32 {
    66_67
}

fn default_price_change_limit_bps() -> u32 {
    500
}

fn default_price_smoothing_bps() -> u32 {
    250
}

impl ChainParams {
    pub fn execution_version_at(&self, height: u64) -> u32 {
        if height >= self.smart_contract_activation_height {
            crate::SMART_CONTRACT_EXECUTION_VERSION
        } else if height >= self.ovm_activation_height {
            crate::OVM_EXECUTION_VERSION
        } else {
            crate::LEGACY_EXECUTION_VERSION
        }
    }

    /// Sensible local-network defaults.
    pub fn default_local() -> Self {
        ChainParams {
            chain_name: default_chain_name(),
            currency_symbol: default_currency_symbol(),
            genesis_supply: 1_000_000_000,
            block_window: 100,
            rebound_lock_blocks: 100,
            audit_checkpoint_blocks: 50,
            ovm_activation_height: 1,
            smart_contract_activation_height: 1,
            gas_activation_height: 1,
            gas_server_fee_bps: 2_000,
            airdrop_interval_blocks: 100,
            airdrop_base_bps: 100,
            ox_price_reference: 1,
            price_update_height: 1,
            price_update_threshold: 66_67,
            price_change_limit_bps: 500,
            price_smoothing_bps: 250,
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
