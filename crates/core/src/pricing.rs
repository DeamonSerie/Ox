//! Pegged currency pricing, liquidity pools, and guaranteed exchange rates.
//!
//! All computation uses integer fixed-point arithmetic (no floats) so that every node
//! derives identical results. Prices are stored at the full `u128` precision used by
//! `ValueIndex` and `ox_price`; a scaling helper (`scale_to_u64`) packs them for OVM
//! consumption where only `u64` operands are available.
//!
//! Liquidity pools use a constant-product AMM (`x * y = K`) where `K` is dynamically
//! recomputed each block in fixed-point log-space (see
//! [`oxydome_currency::compute_pool_k`]). Pool reserves and `K` live at the full
//! `u128` `FPU` scale (`1e12`) on-chain and are packed to `u64` for OVM host
//! consumption.

use crate::Amount;
use oxydome_crypto::{hash_value, Hash};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Fixed-point scale of the Ox value index: `1.000 == 1_000_000_000_000`.
pub const VALUE_SCALE: u128 = 1_000_000_000_000;

/// Precision reduction applied when packing a `u128` price into a `u64` for the OVM.
/// Dividing by `1_000_000` retains ~18 decimal digits of precision in a `u64`.
pub const PRICE_SCALE_DIVISOR: u128 = 1_000_000;

/// Identifies a priced asset for pegged-currency bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PriceAsset {
    /// The native Ox value index (`ChainState.value_index`).
    Ox,
    /// Network GAS priced in units of GAS-per-1e15 Ox (`ChainState.ox_price`).
    Gas,
    /// A DAO-issued currency identified by its DAO id (`DaoState.value_index`).
    DaoCurrency { dao_id: Hash },
}

impl PriceAsset {
    /// Canonical hash used as the OVM oracle key. The 64-byte `Hash` is folded to a `u64`
    /// via the first 8 little-endian bytes (same convention as `fn_selector`).
    pub fn oracle_key(&self) -> u64 {
        let hash = hash_value(&("oxydome-price-asset-v1", self));
        u64::from_le_bytes(hash.0[..8].try_into().expect("8-byte slice"))
    }
}

/// Price bounds computed from the average price over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceBounds {
    /// Upper bound = average price over the window (same fixed-point scale as the asset's price).
    pub upper_bound: u128,
    /// Lower bound = derived from the upper bound: `upper * (1 - spread)`.
    pub lower_bound: u128,
    /// Guaranteed exchange rate position used for pegged conversions (default: upper bound).
    pub bound_price_position: u128,
    /// Midpoint of the band: `(upper + lower) / 2`. The current price must be >= this to
    /// qualify for a pegged conversion (i.e. the price sits in the upper half).
    pub midpoint: u128,
    /// Current price of the asset (latest sample). Used for the in-bounds check.
    pub current_price: u128,
}

impl PriceBounds {
    /// Packs the bounds into a `u64`-scaled representation suitable for the OVM host oracle.
    pub fn pack(&self) -> PriceBoundsPacked {
        PriceBoundsPacked {
            upper_bound: scale_to_u64(self.upper_bound),
            lower_bound: scale_to_u64(self.lower_bound),
            bound_price_position: scale_to_u64(self.bound_price_position),
            midpoint: scale_to_u64(self.midpoint),
            current_price: scale_to_u64(self.current_price),
        }
    }
}

/// Packed price bounds for OVM consumption (u64 scale).
pub type PriceBoundsPacked = oxydome_ovm::PriceBoundsPacked;

/// A single price sample taken at a given block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceSample {
    pub height: u64,
    pub price: u128,
}

/// Computes the result of a pegged conversion from the main currency (OX) to a pegged token.
///
/// When the asset's current price is in bounds (>= midpoint, i.e. in the upper half of the
/// band), the pegged token is equal to the main OX currency, so the conversion is 1:1:
/// `result = amount`.
///
/// When the price is out of bounds (< midpoint), the conversion fails and returns 0.
#[inline]
pub fn pegged_convert(amount: Amount, bounds: &PriceBounds) -> Amount {
    if bounds.upper_bound == 0 || bounds.midpoint == 0 {
        return 0;
    }
    if !is_in_upper_half(bounds.current_price, bounds) {
        return 0;
    }
    amount
}

/// Returns `true` when `price` sits in the upper half of the bound band (>= midpoint).
#[inline]
pub fn is_in_upper_half(price: u128, bounds: &PriceBounds) -> bool {
    price >= bounds.midpoint
}

/// Computes the gas-price multiplier (fixed-point, `VALUE_SCALE` = 1.0) from price bounds.
///
/// The multiplier grows as `current_price` approaches `upper_bound`, reaching
/// `1 + spread_factor` when the price is at or above the upper bound. At the
/// midpoint the multiplier is `1.0` (base price). When the price is below the
/// midpoint (out of bounds) the multiplier falls back to `0.0` so that gas
/// becomes effectively unavailable until the pegged currency is back in bounds.
pub fn compute_gas_price_premium(bounds: &PriceBounds) -> u128 {
    if bounds.upper_bound == 0 || bounds.midpoint == 0 {
        return 0;
    }
    if !is_in_upper_half(bounds.current_price, bounds) {
        return 0;
    }
    let spread = bounds.upper_bound.saturating_sub(bounds.lower_bound);
    if spread == 0 {
        return VALUE_SCALE;
    }
    let deviation = bounds
        .current_price
        .saturating_sub(bounds.midpoint)
        .min(spread);
    let fraction = deviation.saturating_mul(VALUE_SCALE) / spread;
    VALUE_SCALE.saturating_add(fraction)
}

/// Computes the final gas price from price bounds and a base price.
///
/// Returns `base_price * (1 + premium)` when in bounds, or `0` when out of bounds.
pub fn compute_gas_price(bounds: &PriceBounds, base_price: Amount) -> Amount {
    let premium = compute_gas_price_premium(bounds);
    if premium == 0 {
        return 0;
    }
    base_price
        .saturating_mul(premium)
        .saturating_div(VALUE_SCALE)
}

/// Computes price bounds from a window of samples using a spread.
///
/// 1. Average = `sum(samples) / count` (integer floor).
/// 2. `upper_bound = average`
/// 3. `lower_bound = upper_bound * (1 - spread_bps / 10_000)` using integer arithmetic.
/// 4. `midpoint = (upper + lower) / 2`
/// 5. `bound_price_position = upper_bound` (the guaranteed rate defaults to the average).
/// 6. `current_price = last sample's price`.
pub fn compute_price_bounds(history: &[PriceSample], spread_bps: u32) -> PriceBounds {
    let average = compute_average_price(history);
    let upper_bound = average;
    let lower_bound = compute_lower_bound(average, spread_bps);
    let midpoint = (upper_bound.saturating_add(lower_bound)) / 2;
    let current_price = history.last().map(|s| s.price).unwrap_or(0);
    PriceBounds {
        upper_bound,
        lower_bound,
        bound_price_position: upper_bound,
        midpoint,
        current_price,
    }
}

/// Integer floor of the arithmetic mean of the sample prices.
fn compute_average_price(history: &[PriceSample]) -> u128 {
    if history.is_empty() {
        return 0;
    }
    let sum: u128 = history
        .iter()
        .map(|s| s.price)
        .fold(0u128, u128::saturating_add);
    sum / history.len() as u128
}

/// `upper * (1 - spread_bps / 10_000)` using integer arithmetic.
fn compute_lower_bound(upper: u128, spread_bps: u32) -> u128 {
    if spread_bps == 0 {
        return upper;
    }
    // spread fraction = spread_bps / 10_000
    // lower = upper * (10_000 - spread_bps) / 10_000
    upper.saturating_mul((10_000u128).saturating_sub(spread_bps as u128)) / 10_000
}

/// Scales a `u128` fixed-point price down to `u64` for OVM consumption.
pub fn scale_to_u64(price: u128) -> u64 {
    (price / PRICE_SCALE_DIVISOR) as u64
}

/// Pegged currency configuration, set at Solid compile time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeggedCurrencyConfig {
    pub asset: PriceAsset,
    pub spread_bps: u32,
    /// X of the main currency in the peg ratio.
    pub pegged_numerator: Amount,
    /// Y of the target currency in the peg ratio.
    pub pegged_denominator: Amount,
}

impl PeggedCurrencyConfig {
    /// Canonical hash used as the key in `ChainState.pegged_currencies`.
    pub fn id(&self) -> Hash {
        hash_value(&("oxydome-pegged-currency-v1", self))
    }
}

/// Pegged currency runtime state, committed in `ChainState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeggedCurrencyState {
    pub config: PeggedCurrencyConfig,
    pub bounds: PriceBounds,
    pub price_history: VecDeque<PriceSample>,
    pub last_update_height: u64,
}

impl PeggedCurrencyState {
    /// Creates a fresh, empty `PeggedCurrencyState` with no samples yet.
    pub fn new(config: PeggedCurrencyConfig) -> Self {
        PeggedCurrencyState {
            config,
            bounds: PriceBounds {
                upper_bound: 0,
                lower_bound: 0,
                bound_price_position: 0,
                midpoint: 0,
                current_price: 0,
            },
            price_history: VecDeque::new(),
            last_update_height: 0,
        }
    }

    /// Records a price sample at `height`. If the window exceeds `window` blocks, the
    /// oldest sample is evicted. When the window is full, bounds are recomputed.
    pub fn record_sample(&mut self, height: u64, price: u128, window: u64) {
        self.price_history.push_back(PriceSample { height, price });
        while self.price_history.len() > window.max(1) as usize {
            self.price_history.pop_front();
        }
        self.last_update_height = height;
        self.bounds.current_price = price;
        if self.price_history.len() >= window.max(1) as usize && window > 0 {
            let samples: Vec<PriceSample> = self.price_history.iter().copied().collect();
            self.bounds = compute_price_bounds(&samples, self.config.spread_bps);
        }
    }
}

/// Default spread basis points (5% = 500 bps).
pub fn default_pegged_spread_bps() -> u32 {
    500
}

/// Default window size in blocks.
pub fn default_pegged_window_blocks() -> u64 {
    100
}

/// Default activation height — pegged currency is disabled by default.
pub fn default_pegged_currency_activation_height() -> u64 {
    u64::MAX
}

/// Default activation height — liquidity pools are disabled by default.
pub fn default_liquidity_pool_activation_height() -> u64 {
    u64::MAX
}

/// Default swap fee in basis points (100 = 1%).
pub fn default_liquidity_pool_fee_bps() -> u32 {
    100
}

/// Default maximum number of liquidity pools.
pub fn default_max_liquidity_pools() -> usize {
    10_000
}

/// Fixed-point scale used for liquidity pool reserves and `K` (matches `ValueIndex`).
/// `1.0` pool unit == `LIQUIDITY_POOL_SCALE`.
pub const LIQUIDITY_POOL_SCALE: u128 = 1_000_000_000_000;

/// Parameters governing liquidity-pool K recomputation and the constant-product swap.
///
/// These are embedded in [`LiquidityPoolConfig`] and committed per-pool in
/// [`LiquidityPoolState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolKParams {
    /// Swap fee in basis points (100 = 1%).
    pub fee_bps: u32,
    /// Block height at which pool K recomputation and swaps become active.
    pub activation_height: u64,
    /// Reference normalization factor used to compute V_norm = volume / t_ref.
    pub t_ref: u128,
}

impl PoolKParams {
    /// Default parameters: 1% fee, active at genesis, t_ref = 1e12.
    pub fn default_active() -> Self {
        PoolKParams {
            fee_bps: default_liquidity_pool_fee_bps(),
            activation_height: 1,
            t_ref: 1_000_000_000_000u128,
        }
    }
}

/// Configuration for a liquidity pool, set when the pool is created.
///
/// One pool is owned by a single server/peer node whose `PublicKey` is hashed to a
/// [`crate::Hash`] pool id. The pool declares which currencies it accepts; `x` is always
/// the Ox reserve and `y` is the other-currency reserve whose price bounds drive `K`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPoolConfig {
    /// Node that owns and operates this pool.
    pub owner: crate::PublicKey,
    /// Accepted currencies (always includes `PriceAsset::Ox`; the non-Ox asset drives K).
    pub currencies: Vec<PriceAsset>,
    /// K recomputation and swap parameters.
    pub k_params: PoolKParams,
}

impl LiquidityPoolConfig {
    /// Canonical hash used as the key in `ChainState.liquidity_pools`.
    pub fn id(&self) -> crate::Hash {
        hash_value(&("oxydome-liquidity-pool-v1", self))
    }
}

/// Packed representation of a liquidity pool's mutable state for OVM consumption.
///
/// All fields are at the u64 scale used by the OVM host oracle, derived from the on-chain
/// u128 `FPU`-scale values via [`scale_to_u64`] (dividing by `1_000_000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolStatePacked {
    /// Packed `x` reserve (Ox), u64 scale.
    pub reserve_x: u64,
    /// Packed `y` reserve (other currency), u64 scale.
    pub reserve_y: u64,
    /// Packed `K` invariant, u64 scale.
    pub k: u64,
    /// Packed fee in basis points.
    pub fee_bps: u64,
}

/// Liquidity pool runtime state, committed in `ChainState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPoolState {
    pub config: LiquidityPoolConfig,
    /// Reserves keyed by the accepted currency; at `FPU` fixed-point scale.
    pub reserves: std::collections::BTreeMap<PriceAsset, crate::Amount>,
    /// Current constant-product invariant `K`, at `FPU` fixed-point scale.
    pub k: crate::Amount,
    /// Accumulated trading volume used in K recomputation (V_norm = volume / t_ref).
    pub volume: crate::Amount,
    /// Height at which `k` was last recomputed.
    pub last_update_height: u64,
}

impl LiquidityPoolState {
    /// Creates a fresh pool with zero reserves and `K = 0`.
    pub fn new(config: LiquidityPoolConfig) -> Self {
        let mut reserves = std::collections::BTreeMap::new();
        for currency in &config.currencies {
            reserves.insert(*currency, 0);
        }
        LiquidityPoolState {
            config,
            reserves,
            k: 0,
            volume: 0,
            last_update_height: 0,
        }
    }

    /// Returns the Ox (`x`) reserve at FP scale, or 0 if absent.
    pub fn reserve_x(&self) -> crate::Amount {
        self.reserves.get(&PriceAsset::Ox).copied().unwrap_or(0)
    }

    /// Returns the non-Ox (`y`) reserve at FP scale, or 0 if absent.
    pub fn reserve_y(&self) -> crate::Amount {
        self.reserves
            .iter()
            .find(|(asset, _)| **asset != PriceAsset::Ox)
            .map(|(_, amount)| amount)
            .copied()
            .unwrap_or(0)
    }

    /// The non-Ox `PriceAsset` backing this pool, if any.
    pub fn other_asset(&self) -> Option<PriceAsset> {
        self.reserves
            .keys()
            .find(|asset| **asset != PriceAsset::Ox)
            .copied()
    }

    /// Packs the current reserves, `K`, and fee into u64-scale values for the OVM host.
    pub fn pack(&self) -> PoolStatePacked {
        PoolStatePacked {
            reserve_x: scale_to_u64(self.reserve_x()),
            reserve_y: scale_to_u64(self.reserve_y()),
            k: scale_to_u64(self.k),
            fee_bps: self.config.k_params.fee_bps as u64,
        }
    }
}

/// Constant-product swap at full u128 FP scale.
///
/// `fee_bps` is deducted from the input before the ratio changes. Returns the output
/// amount the user receives (not including the fee). All arithmetic is saturating.
///
/// - `input` is the gross amount of currency `x` (Ox) the user supplies, at FP scale.
/// - `reserve_x`, `reserve_y` are the current reserves at FP scale.
/// - `k` is the current invariant at FP scale.
pub fn pool_swap(
    input: crate::Amount,
    reserve_x: crate::Amount,
    reserve_y: crate::Amount,
    k: crate::Amount,
    fee_bps: u32,
) -> crate::Amount {
    if reserve_x == 0 || reserve_y == 0 || k == 0 {
        return 0;
    }
    let fee_factor = (10_000u128).saturating_sub(fee_bps as u128);
    let input_eff = input.saturating_mul(fee_factor) / 10_000;
    if input_eff == 0 {
        return 0;
    }
    let new_x = reserve_x.saturating_add(input_eff);
    let new_y = k.saturating_div(new_x);
    reserve_y.saturating_sub(new_y)
}

/// Packs a liquidity pool's mutable state at u64 scale for the OVM host oracle.
pub fn pack_pool_state(
    reserve_x: crate::Amount,
    reserve_y: crate::Amount,
    k: crate::Amount,
    fee_bps: u32,
) -> PoolStatePacked {
    PoolStatePacked {
        reserve_x: scale_to_u64(reserve_x),
        reserve_y: scale_to_u64(reserve_y),
        k: scale_to_u64(k),
        fee_bps: fee_bps as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;

    #[test]
    fn compute_price_bounds_averages_and_applies_spread() {
        let history = vec![
            PriceSample {
                height: 1,
                price: 1_000_000_000,
            },
            PriceSample {
                height: 2,
                price: 1_000_000_000,
            },
        ];
        let bounds = compute_price_bounds(&history, 500);
        // average = 1_000_000_000
        assert_eq!(bounds.upper_bound, 1_000_000_000);
        // lower = 1_000_000_000 * (1 - 0.05) = 950_000_000
        assert_eq!(bounds.lower_bound, 950_000_000);
        // midpoint = (1_000_000_000 + 950_000_000) / 2 = 975_000_000
        assert_eq!(bounds.midpoint, 975_000_000);
        assert_eq!(bounds.bound_price_position, bounds.upper_bound);
        // current_price is the last sample
        assert_eq!(bounds.current_price, 1_000_000_000);
    }

    #[test]
    fn is_in_upper_half_checks_midpoint_boundary() {
        let history = vec![
            PriceSample {
                height: 1,
                price: 200,
            },
            PriceSample {
                height: 2,
                price: 300,
            },
        ];
        let bounds = compute_price_bounds(&history, 1000);
        // average = 250, spread = 10% => upper = 250, lower = 225, midpoint = 237
        assert_eq!(bounds.upper_bound, 250);
        assert_eq!(bounds.lower_bound, 225);
        assert_eq!(bounds.midpoint, 237);
        assert!(!is_in_upper_half(236, &bounds));
        assert!(is_in_upper_half(237, &bounds));
        assert!(is_in_upper_half(250, &bounds));
        assert!(!is_in_upper_half(100, &bounds));
    }

    #[test]
    fn pegged_convert_is_one_to_one_when_in_bounds() {
        let history = vec![
            PriceSample {
                height: 1,
                price: 1_000_000_000,
            },
            PriceSample {
                height: 2,
                price: 1_000_000_000,
            },
        ];
        let bounds = compute_price_bounds(&history, 500);
        // Current price = 1_000_000_000 which is >= midpoint (975_000_000) → in bounds
        // → 1:1 conversion: pegged token equals main OX currency
        let result = pegged_convert(500, &bounds);
        assert_eq!(result, 500);

        // When the price drops below midpoint → out of bounds → conversion returns 0
        let mut out_of_bounds = bounds;
        out_of_bounds.current_price = 970_000_000;
        assert!(!is_in_upper_half(
            out_of_bounds.current_price,
            &out_of_bounds
        ));
        assert_eq!(pegged_convert(500, &out_of_bounds), 0);
    }

    #[test]
    fn pegged_convert_zero_upper_returns_zero() {
        let bounds = PriceBounds {
            upper_bound: 0,
            lower_bound: 0,
            bound_price_position: 0,
            midpoint: 0,
            current_price: 0,
        };
        assert_eq!(pegged_convert(500, &bounds), 0);
    }

    #[test]
    fn compute_lower_bound_with_zero_spread() {
        assert_eq!(compute_lower_bound(1000, 0), 1000);
    }

    #[test]
    fn price_asset_oracle_keys_are_deterministic() {
        let ox = PriceAsset::Ox;
        let key1 = ox.oracle_key();
        let key2 = PriceAsset::Ox.oracle_key();
        assert_eq!(key1, key2);
        assert_ne!(key1, 0);
    }

    #[test]
    fn price_sample_record_trims_window_and_recomputes_bounds() {
        let mut config = PeggedCurrencyConfig {
            asset: PriceAsset::Ox,
            spread_bps: 500,
            pegged_numerator: 1,
            pegged_denominator: 1,
        };
        config.spread_bps = 500;
        let mut state = PeggedCurrencyState::new(config.clone());
        let window = 3;
        for i in 1..=3 {
            state.record_sample(i, 1_000_000_000u128 + i as u128 * 1000, window);
        }
        assert!(state.bounds.upper_bound > 0);
        // Adding a 4th sample should evict the oldest (window = 3)
        state.record_sample(4, 1_000_000_000u128 + 4000, window);
        assert_eq!(state.price_history.len(), 3);
        assert_eq!(state.price_history.front().unwrap().height, 2);
        assert!(state.bounds.upper_bound > 0);
    }

    #[test]
    fn pegged_config_id_is_deterministic() {
        let config = PeggedCurrencyConfig {
            asset: PriceAsset::Ox,
            spread_bps: 500,
            pegged_numerator: 1,
            pegged_denominator: 1,
        };
        let key = KeyPair::from_seed(&[0u8; 32]);
        let config2 = PeggedCurrencyConfig {
            asset: PriceAsset::Ox,
            spread_bps: 500,
            pegged_numerator: 1,
            pegged_denominator: 1,
        };
        assert_eq!(config.id(), config2.id());
        let _ = key;
    }

    #[test]
    fn compute_gas_price_premium_at_upper_bound() {
        let history = vec![PriceSample {
            height: 1,
            price: 1_000_000_000,
        }];
        let bounds = compute_price_bounds(&history, 500);
        // current_price == upper_bound → deviation = (upper - midpoint), spread = upper - lower
        // premium = 1 + (upper - midpoint) / (upper - lower) = 1 + 0.5 = 1.5
        let premium = compute_gas_price_premium(&bounds);
        assert!(premium > VALUE_SCALE);
        assert_eq!(
            premium,
            VALUE_SCALE + VALUE_SCALE * 500_000_000 / 1_000_000_000
        );
    }

    #[test]
    fn compute_gas_price_premium_at_midpoint() {
        let history = vec![PriceSample {
            height: 1,
            price: 1_000_000_000,
        }];
        let bounds = compute_price_bounds(&history, 500);
        let mut at_mid = bounds;
        at_mid.current_price = bounds.midpoint;
        let premium = compute_gas_price_premium(&at_mid);
        assert_eq!(premium, VALUE_SCALE);
    }

    #[test]
    fn compute_gas_price_premium_out_of_bounds() {
        let history = vec![PriceSample {
            height: 1,
            price: 1_000_000_000,
        }];
        let bounds = compute_price_bounds(&history, 500);
        let mut below = bounds;
        below.current_price = bounds.midpoint.saturating_sub(1);
        assert_eq!(compute_gas_price_premium(&below), 0);
    }

    #[test]
    fn compute_gas_price_from_bounds() {
        let history = vec![PriceSample {
            height: 1,
            price: 1_000_000_000,
        }];
        let bounds = compute_price_bounds(&history, 500);
        let base = 500u128;
        let price = compute_gas_price(&bounds, base);
        assert!(price > base);
        assert_eq!(
            price,
            base.saturating_mul(compute_gas_price_premium(&bounds)) / VALUE_SCALE
        );
    }

    #[test]
    fn compute_gas_price_out_of_bounds_returns_base() {
        let history = vec![PriceSample {
            height: 1,
            price: 1_000_000_000,
        }];
        let bounds = compute_price_bounds(&history, 500);
        let mut below = bounds;
        below.current_price = bounds.midpoint.saturating_sub(1);
        assert_eq!(compute_gas_price(&below, 500), 0);
    }
}
