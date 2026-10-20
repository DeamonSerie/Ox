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
    /// Number of blocks between verification-credit auction clearings.
    #[serde(default = "default_auction_interval_blocks")]
    pub auction_interval_blocks: u64,
    /// Number of blocks a verification credit survives without being earned or spent.
    #[serde(default = "default_auction_credit_expiry_blocks")]
    pub auction_credit_expiry_blocks: u64,
    /// Smallest accepted verification-credit bid.
    #[serde(default = "default_auction_min_bid")]
    pub auction_min_bid: u64,
    /// Largest accepted verification-credit bid.
    #[serde(default = "default_auction_max_bid")]
    pub auction_max_bid: u64,
    /// Verification credits a server node earns per block-reward share.
    #[serde(default = "default_verification_credit_per_block")]
    pub verification_credit_per_block: u64,
    /// Blocks after an auction clearing in which the winning node may still execute its bundle.
    #[serde(default = "default_auction_execution_deadline_blocks")]
    pub auction_execution_deadline_blocks: u64,
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
    /// Share of OVM gas fees (in GAS) redistributed to masters, in basis points
    /// (`400` = 4%). The remainder of gas fees is burned.
    #[serde(default = "default_gas_fee_master_bps")]
    pub gas_fee_master_bps: u32,

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

    // ---- block rewards (minted Ox) ----
    /// Base server node reward per block, in Ox.
    #[serde(default = "default_server_base_reward")]
    pub server_base_reward: Amount,
    /// Base master node reward per block, in Ox.
    #[serde(default = "default_master_base_reward")]
    pub master_base_reward: Amount,
    /// GAS price derivative sensitivity for server rewards, in basis points per 1% price change.
    #[serde(default = "default_gas_derivative_sensitivity_bps")]
    pub gas_derivative_sensitivity_bps: u32,
    /// Master reward sensitivity to server reward derivative, in basis points per 1% change.
    #[serde(default = "default_master_derivative_sensitivity_bps")]
    pub master_derivative_sensitivity_bps: u32,
    /// Maximum adjustment cap for server rewards from derivatives, in basis points.
    #[serde(default = "default_server_reward_cap_bps")]
    pub server_reward_cap_bps: u32,
    /// Maximum adjustment cap for master rewards from derivatives, in basis points.
    #[serde(default = "default_master_reward_cap_bps")]
    pub master_reward_cap_bps: u32,
    /// Minimum blocks between price updates for derivative calculation.
    #[serde(default = "default_min_price_update_interval")]
    pub min_price_update_interval: u64,
    /// Whether minted block rewards are active.
    #[serde(default = "default_block_rewards_enabled")]
    pub block_rewards_enabled: bool,

    // ---- OVM data stack ----
    /// Bytes of data stack available per 1 gas unit.
    #[serde(default = "default_ovm_stack_bytes_per_gas")]
    pub ovm_stack_bytes_per_gas: u64,
    /// Maximum data stack bytes for a single OVM transaction.
    #[serde(default = "default_max_ovm_data_stack_bytes")]
    pub max_ovm_data_stack_bytes: u64,

    // ---- network storage labeling ----
    #[serde(default = "default_u64_zero")]
    pub expected_network_storage: u64,
    #[serde(default = "default_storage_label_max_deviation_bps")]
    pub storage_label_max_deviation_bps: u32,
    #[serde(default = "default_u64_zero")]
    pub storage_audit_interval_blocks: u64,

    // ---- timers ----
    /// Height at which timer operations become active.
    #[serde(default = "default_timer_activation_height")]
    pub timer_activation_height: u64,
    /// Maximum number of simultaneous active timers.
    #[serde(default = "default_max_timers")]
    pub max_timers: usize,
    /// Maximum duration of a timer in blocks (1 day at ~5s blocks).
    #[serde(default = "default_max_timer_duration_blocks")]
    pub max_timer_duration_blocks: u64,
    /// Minimum bet amount.
    #[serde(default = "default_timer_min_bet_amount")]
    pub timer_min_bet_amount: Amount,
    /// Maximum bet amount.
    #[serde(default = "default_timer_max_bet_amount")]
    pub timer_max_bet_amount: Amount,

    // ---- pegged currency ----
    /// Height at which pegged currency operations become active.
    #[serde(default = "default_pegged_currency_activation_height")]
    pub pegged_currency_activation_height: u64,
    /// Basis points for the spread between upper and lower price bounds (e.g. 500 = 5%).
    #[serde(default = "default_pegged_spread_bps")]
    pub pegged_spread_bps: u32,
    /// Window (blocks) for computing the average price.
    #[serde(default = "default_pegged_window_blocks")]
    pub pegged_window_blocks: u64,

    // ---- liquidity pools ----
    /// Height at which liquidity pool K recomputation and swaps become active.
    #[serde(default = "default_liquidity_pool_activation_height")]
    pub liquidity_pool_activation_height: u64,
    /// Swap fee in basis points (100 = 1%).
    #[serde(default = "default_liquidity_pool_fee_bps")]
    pub liquidity_pool_fee_bps: u32,
    /// Maximum number of liquidity pools.
    #[serde(default = "default_max_liquidity_pools")]
    pub max_liquidity_pools: usize,

    // ---- speedometer stabilization currency ----
    /// Height at which Speedometer minting and airdrops become active.
    #[serde(default = "default_one")]
    pub speedometer_activation_height: u64,
    /// Number of blocks between automatic Speedometer airdrops (`0` disables airdrops).
    #[serde(default = "default_speedometer_airdrop_interval_blocks")]
    pub speedometer_airdrop_interval_blocks: u64,
    /// Base Speedometer airdrop size as basis points of the block's highest transaction value.
    #[serde(default = "default_speedometer_airdrop_base_bps")]
    pub speedometer_airdrop_base_bps: u32,
    /// Per-transaction Speedometer stabilization mint, basis points of the tx value.
    #[serde(default = "default_speedometer_stabilization_bps")]
    pub speedometer_stabilization_bps: u32,

    // ---- EVFS file system ----
    /// Height at which EVFS file operations become active.
    #[serde(default = "default_file_system_activation_height")]
    pub file_system_activation_height: u64,
    /// Maximum file size in bytes.
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    /// Maximum number of files a single node may store (state cap).
    #[serde(default = "default_max_files_per_node")]
    pub max_files_per_node: u64,

    // ---- node departure ----
    /// Fraction of a departing node's held earnings to take and redistribute, in basis points.
    /// Default `5000` = 50%. A value of `0` disables confiscation (earnings stay with the node).
    #[serde(default = "default_departure_take_bps")]
    pub departure_take_bps: Option<u32>,

    // ---- express bus ----
    /// Height at which Express Bus deposit/withdraw operations become active.
    #[serde(default = "default_express_bus_activation_height")]
    pub express_bus_activation_height: u64,
    /// Maximum number of simultaneous Express Bus trackers.
    #[serde(default = "default_express_bus_max_trackers")]
    pub max_express_buses: usize,
    /// Sampling window (blocks) for the In/Out tracker timer.
    #[serde(default = "default_express_bus_window_blocks")]
    pub express_bus_window_blocks: u64,
    /// Default weight for new Express Bus trackers (FP scale: 1.0 == 1_000_000_000_000).
    #[serde(default = "default_express_bus_weight")]
    pub express_bus_default_weight: i128,
    /// Impact (basis points) of the express-flow signal on the value index per window.
    #[serde(default = "default_express_bus_impact_bps")]
    pub express_bus_impact_bps: u32,

    // ---- transaction labeling / coin toss ----
    /// Network-wide magic phrase used as domain-separation salt in BLAKE2b
    /// position hashes and as a seed component for the peer-consensus coin toss.
    #[serde(default = "default_network_magic_phrase")]
    pub network_magic_phrase: String,
    /// Height at which position-dependent tx labels and coin-toss ordering become active.
    #[serde(default = "default_coin_toss_activation_height")]
    pub coin_toss_activation_height: u64,
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

fn default_server_base_reward() -> Amount {
    1_000
}

fn default_master_base_reward() -> Amount {
    50
}

fn default_gas_derivative_sensitivity_bps() -> u32 {
    100
}

fn default_master_derivative_sensitivity_bps() -> u32 {
    50
}

fn default_server_reward_cap_bps() -> u32 {
    2_000
}

fn default_master_reward_cap_bps() -> u32 {
    1_000
}

fn default_min_price_update_interval() -> u64 {
    10
}

fn default_block_rewards_enabled() -> bool {
    true
}

fn default_ovm_stack_bytes_per_gas() -> u64 {
    6
}

fn default_max_ovm_data_stack_bytes() -> u64 {
    2u64 * 1024 * 1024 * 1024
}

fn default_u64_zero() -> u64 {
    0
}

fn default_storage_label_max_deviation_bps() -> u32 {
    100
}

fn default_timer_activation_height() -> u64 {
    u64::MAX
}

fn default_max_timers() -> usize {
    crate::timer::MAX_TIMERS
}

fn default_max_timer_duration_blocks() -> u64 {
    crate::timer::MAX_TIMER_DURATION_BLOCKS
}

fn default_timer_min_bet_amount() -> Amount {
    10
}

fn default_timer_max_bet_amount() -> Amount {
    1_000_000_000
}

fn default_pegged_currency_activation_height() -> u64 {
    u64::MAX
}

fn default_pegged_spread_bps() -> u32 {
    500
}

fn default_gas_fee_master_bps() -> u32 {
    400
}

fn default_pegged_window_blocks() -> u64 {
    100
}

fn default_file_system_activation_height() -> u64 {
    u64::MAX
}

fn default_max_file_bytes() -> u64 {
    oxydome_ovm::MAX_ASSET_BYTES
}

fn default_max_files_per_node() -> u64 {
    100_000
}

fn default_departure_take_bps() -> Option<u32> {
    None
}

fn default_express_bus_activation_height() -> u64 {
    u64::MAX
}

fn default_express_bus_max_trackers() -> usize {
    crate::express_bus::MAX_EXPRESS_BUSES
}

fn default_express_bus_window_blocks() -> u64 {
    100
}

fn default_express_bus_weight() -> i128 {
    crate::express_bus::FP
}

fn default_express_bus_impact_bps() -> u32 {
    100
}

fn default_network_magic_phrase() -> String {
    "Ox-Label-1.0".to_string()
}

fn default_coin_toss_activation_height() -> u64 {
    u64::MAX
}

fn default_liquidity_pool_activation_height() -> u64 {
    crate::pricing::default_liquidity_pool_activation_height()
}

fn default_liquidity_pool_fee_bps() -> u32 {
    crate::pricing::default_liquidity_pool_fee_bps()
}

fn default_max_liquidity_pools() -> usize {
    crate::pricing::default_max_liquidity_pools()
}

fn default_speedometer_airdrop_interval_blocks() -> u64 {
    2
}

fn default_speedometer_airdrop_base_bps() -> u32 {
    100
}

fn default_speedometer_stabilization_bps() -> u32 {
    10
}

fn default_auction_interval_blocks() -> u64 {
    4
}

fn default_auction_credit_expiry_blocks() -> u64 {
    8
}

fn default_auction_min_bid() -> u64 {
    1
}

fn default_auction_max_bid() -> u64 {
    1_000
}

fn default_verification_credit_per_block() -> u64 {
    1
}

fn default_auction_execution_deadline_blocks() -> u64 {
    1
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
            auction_interval_blocks: default_auction_interval_blocks(),
            auction_credit_expiry_blocks: default_auction_credit_expiry_blocks(),
            auction_min_bid: default_auction_min_bid(),
            auction_max_bid: default_auction_max_bid(),
            verification_credit_per_block: default_verification_credit_per_block(),
            auction_execution_deadline_blocks: default_auction_execution_deadline_blocks(),
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
            gas_fee_master_bps: default_gas_fee_master_bps(),
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
            server_base_reward: 1_000,
            master_base_reward: 50,
            gas_derivative_sensitivity_bps: 100,
            master_derivative_sensitivity_bps: 50,
            server_reward_cap_bps: 2_000,
            master_reward_cap_bps: 1_000,
            min_price_update_interval: 10,
            block_rewards_enabled: true,
            ovm_stack_bytes_per_gas: default_ovm_stack_bytes_per_gas(),
            max_ovm_data_stack_bytes: default_max_ovm_data_stack_bytes(),
            expected_network_storage: 0,
            storage_label_max_deviation_bps: default_storage_label_max_deviation_bps(),
            storage_audit_interval_blocks: 0,
            timer_activation_height: 1,
            max_timers: default_max_timers(),
            max_timer_duration_blocks: default_max_timer_duration_blocks(),
            timer_min_bet_amount: default_timer_min_bet_amount(),
            timer_max_bet_amount: default_timer_max_bet_amount(),
            pegged_currency_activation_height: default_pegged_currency_activation_height(),
            pegged_spread_bps: default_pegged_spread_bps(),
            pegged_window_blocks: default_pegged_window_blocks(),
            file_system_activation_height: 1,
            max_file_bytes: default_max_file_bytes(),
            max_files_per_node: default_max_files_per_node(),
            liquidity_pool_activation_height: 1,
            liquidity_pool_fee_bps: default_liquidity_pool_fee_bps(),
            max_liquidity_pools: default_max_liquidity_pools(),
            speedometer_activation_height: 1,
            speedometer_airdrop_interval_blocks: default_speedometer_airdrop_interval_blocks(),
            speedometer_airdrop_base_bps: default_speedometer_airdrop_base_bps(),
            speedometer_stabilization_bps: default_speedometer_stabilization_bps(),
            departure_take_bps: default_departure_take_bps(),
            express_bus_activation_height: 1,
            max_express_buses: default_express_bus_max_trackers(),
            express_bus_window_blocks: default_express_bus_window_blocks(),
            express_bus_default_weight: default_express_bus_weight(),
            express_bus_impact_bps: default_express_bus_impact_bps(),
            network_magic_phrase: default_network_magic_phrase(),
            coin_toss_activation_height: default_coin_toss_activation_height(),
        }
    }
}
