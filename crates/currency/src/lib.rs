//! Oxydome currency engine: the internal value index, rebound mechanics, value guardrails and
//! the bunny-hop maturity rules.
//!
//! All arithmetic is deterministic integer fixed point (`FP = 1e12`). No floating point is used
//! on-chain, so every node computes byte-identical results.

use oxydome_core::{Amount, ChainParams, ValueIndex};

/// Fixed-point scale used by the currency engine (matches `ValueIndex`).
pub const FP: i128 = 1_000_000_000_000;
/// `u128` form of [`FP`].
pub const FPU: u128 = 1_000_000_000_000;
/// Natural logarithm of 2, in fixed point.
const LN2: i128 = 693_147_180_560;

/// Multiplies two fixed-point numbers.
pub fn fp_mul(a: i128, b: i128) -> i128 {
    a.saturating_mul(b) / FP
}

/// Divides two fixed-point numbers (`a / b`), saturating on overflow/underflow.
pub fn fp_div(a: i128, b: i128) -> i128 {
    if b == 0 {
        return 0;
    }
    a.saturating_mul(FP) / b
}

/// Deterministic natural logarithm for a positive fixed-point input.
///
/// Uses range reduction `x = m * 2^e` with `m in [1, 2)` and the fast-converging
/// `atanh` series `ln(m) = 2 * (z + z^3/3 + z^5/5 + ...)`, `z = (m-1)/(m+1)`.
pub fn ln_fixed(x: i128) -> i128 {
    if x <= 0 {
        return 0;
    }
    let mut e: i128 = 0;
    let mut m = x;
    while m >= 2 * FP {
        m = (m + 1) / 2;
        e += 1;
    }
    while m < FP {
        m *= 2;
        e -= 1;
    }
    let z = ((m - FP) * FP) / (m + FP);
    let z2 = fp_mul(z, z);
    let mut term = z;
    let mut sum = z;
    let mut k: i128 = 3;
    loop {
        term = fp_mul(term, z2);
        let add = term / k;
        if add == 0 {
            break;
        }
        sum += add;
        k += 2;
    }
    let ln_m = 2 * sum;
    ln_m + e * LN2
}

/// Deterministic exponential of a fixed-point input, used for the supply-sensitivity term.
pub fn exp_fixed(x: i128) -> i128 {
    let k = if x >= 0 {
        (x + LN2 / 2) / LN2
    } else {
        (x - LN2 / 2) / LN2
    };
    let r = x - k * LN2;
    let mut term = FP;
    let mut sum = FP;
    let mut n: i128 = 1;
    loop {
        term = fp_mul(term, r) / n;
        if term == 0 {
            break;
        }
        sum += term;
        n += 1;
        if n > 64 {
            break;
        }
    }
    if k >= 0 {
        if k >= 127 {
            return i128::MAX;
        }
        sum.saturating_mul(1i128 << k.min(62))
    } else {
        let shift = (-k).min(62) as u32;
        sum >> shift
    }
}

fn bps(basis_points: u32) -> i128 {
    (basis_points as i128) * FP / 10_000
}

/// Rolling statistics for the current measurement window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowStats {
    /// Total Ox transacted in the window.
    pub volume: Amount,
    /// Number of transactions in the window.
    pub tx_count: u64,
    /// Amount of Ox deposited into the Exit/Reserve sink in the window.
    pub exit_amount: Amount,
    /// Highest single transaction `output_total` in the window (used for Speedometer airdrops).
    pub highest_tx_value: Amount,
    /// Net Express Bus flow signal (signed, FP-scaled) accumulated across the window.
    /// Positive = net withdrawals from the bus system (upward value pressure);
    /// negative = net deposits into the bus system (downward value pressure).
    pub express_flow: i128,
}

impl WindowStats {
    /// Mean transaction amount `A = volume / max(count, 1)`.
    pub fn mean_amount(&self) -> Amount {
        if self.tx_count == 0 {
            0
        } else {
            self.volume / self.tx_count as u128
        }
    }

    /// Accumulates `other` into `self` (used by window aggregation).
    pub fn accumulate(&mut self, other: &WindowStats) {
        self.volume = self.volume.saturating_add(other.volume);
        self.tx_count = self.tx_count.saturating_add(other.tx_count);
        self.exit_amount = self.exit_amount.saturating_add(other.exit_amount);
        self.highest_tx_value = self.highest_tx_value.max(other.highest_tx_value);
        self.express_flow = self.express_flow.saturating_add(other.express_flow);
    }
}

/// The outcome of evaluating the value index for a new block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueTransition {
    /// The value index for the new block.
    pub value: ValueIndex,
    /// The previous block's value index.
    pub value_before: ValueIndex,
    /// Whether a rebound happened on this block.
    pub rebounded: bool,
    /// The (possibly incremented) rebound generation.
    pub generation: u64,
}

/// Computes the activity term `Act = 1 + alpha*ln(1+T/T_ref) + beta*ln(1+A/A_ref)`.
pub fn activity_term(params: &ChainParams, stats: &WindowStats) -> i128 {
    let t = stats.volume as i128;
    let a = stats.mean_amount() as i128;
    let t_ref = params.t_ref.max(1) as i128;
    let a_ref = params.a_ref.max(1) as i128;
    let ln_t = ln_fixed(FP + fp_div(t, t_ref));
    let ln_a = ln_fixed(FP + fp_div(a, a_ref));
    FP + fp_mul(bps(params.alpha_bps), ln_t) + fp_mul(bps(params.beta_bps), ln_a)
}

/// Computes the exit-pressure term `X = gamma * (E/E_ref) * (S0/S)^eta`.
pub fn exit_term(
    params: &ChainParams,
    stats: &WindowStats,
    supply: Amount,
    genesis_supply: Amount,
) -> i128 {
    let e = stats.exit_amount as i128;
    let e_ref = params.e_ref.max(1) as i128;
    let ratio_exit = fp_div(e, e_ref);
    let supply_ratio = if supply == 0 {
        FP
    } else {
        fp_div(genesis_supply as i128, supply as i128)
    };
    let supply_factor = exp_fixed(fp_mul(bps(params.eta_bps), ln_fixed(supply_ratio)));
    fp_mul(fp_mul(bps(params.gamma_bps), ratio_exit), supply_factor)
}

/// Computes the new value index from the window statistics.
///
/// `previous` is the value index of the preceding block (always positive, because a rebound
/// resets it to the previous positive value).
///
/// The express-flow signal from `stats.express_flow` is applied as an additional term:
/// deposits (negative flow) exert downward pressure, withdrawals (positive flow) upward.
pub fn compute_value(
    params: &ChainParams,
    stats: &WindowStats,
    supply: Amount,
    genesis_supply: Amount,
    previous: ValueIndex,
    generation: u64,
) -> ValueTransition {
    let act = activity_term(params, stats);
    let x = exit_term(params, stats, supply, genesis_supply);
    let v0 = params.initial_value_index as i128;
    let express_term = fp_mul(bps(params.express_bus_impact_bps), stats.express_flow);
    let raw = fp_mul(v0, act - x + express_term);
    let lambda = bps(params.lambda_bps);
    let smoothed = fp_mul(lambda, raw) + fp_mul(FP - lambda, previous.raw() as i128);
    if smoothed <= 0 {
        // Rebound: return to the previous value and start a new generation.
        ValueTransition {
            value: previous,
            value_before: previous,
            rebounded: true,
            generation: generation.wrapping_add(1),
        }
    } else {
        ValueTransition {
            value: ValueIndex::from_raw(smoothed as u128),
            value_before: previous,
            rebounded: false,
            generation,
        }
    }
}

// ---------------------------------------------------------------------------
// Guardrails
// ---------------------------------------------------------------------------

/// Returns true if moving the value index from `before` to `after` stays within the
/// configured value-impact limit `delta`.
pub fn value_impact_ok(before: ValueIndex, after: ValueIndex, params: &ChainParams) -> bool {
    if before.raw() == 0 {
        return true;
    }
    let diff = before.raw().abs_diff(after.raw());
    let limit = before.raw() / 10_000 * params.value_impact_limit_bps as u128;
    diff <= limit
}

/// Returns true if the effective fee at `value` remains affordable relative to `A_min`:
/// `base_fee * V / V0 <= rho * A_min`.
pub fn fee_affordable(value: ValueIndex, params: &ChainParams) -> bool {
    let v0 = params.initial_value_index.max(1);
    let effective_fee = params.base_fee.saturating_mul(value.raw()) / v0;
    let bound = params
        .min_tx_amount
        .saturating_mul(params.fee_affordability_bps as u128)
        / 10_000;
    effective_fee <= bound
}

/// The hard per-epoch supply-change cap `epsilon * genesis_supply`.
pub fn supply_change_cap(params: &ChainParams) -> Amount {
    params
        .genesis_supply
        .saturating_mul(params.supply_change_limit_bps as u128)
        / 10_000
}

/// The hard per-epoch server-withdrawal cap `kappa * genesis_supply`.
pub fn withdraw_cap(params: &ChainParams) -> Amount {
    params
        .genesis_supply
        .saturating_mul(params.withdraw_limit_bps as u128)
        / 10_000
}

/// Maximum withdrawal per account as basis points of the account's balance.
///
/// * `balance` — the account's current total balance
/// * `bps` — basis points limit (e.g. `3000` = 30%)
///
/// Returns `balance * bps / 10_000`, saturating at 0 if balance is 0.
pub fn max_withdraw_per_account(balance: Amount, bps: u32) -> Amount {
    balance.saturating_mul(bps as u128).saturating_div(10_000)
}

/// Returns true if changing the supply from `old_supply` to `new_supply` keeps the value index
/// within the configured impact limit (all other inputs held equal).
pub fn supply_impact_ok(
    params: &ChainParams,
    stats: &WindowStats,
    old_supply: Amount,
    new_supply: Amount,
    genesis_supply: Amount,
    previous: ValueIndex,
) -> bool {
    let a = compute_value(params, stats, old_supply, genesis_supply, previous, 0).value;
    let b = compute_value(params, stats, new_supply, genesis_supply, previous, 0).value;
    value_impact_ok(a, b, params)
}

/// Returns the largest supply change (up to `requested`) that satisfies both the hard per-epoch
/// cap and the value-impact guardrail. When `increase` is true this is a mint; otherwise a burn.
/// The value-impact relation is monotone in the magnitude of the change, so a binary search
/// finds the exact boundary.
pub fn max_supply_change(
    params: &ChainParams,
    stats: &WindowStats,
    supply: Amount,
    genesis_supply: Amount,
    previous: ValueIndex,
    requested: Amount,
    increase: bool,
) -> Amount {
    let cap = supply_change_cap(params).min(requested);
    let ok = |delta: Amount| -> bool {
        let new_supply = if increase {
            supply.saturating_add(delta)
        } else {
            supply.saturating_sub(delta)
        };
        supply_impact_ok(params, stats, supply, new_supply, genesis_supply, previous)
    };
    if ok(cap) {
        return cap;
    }
    let mut lo: Amount = 0;
    let mut hi: Amount = cap;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if ok(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

// ---------------------------------------------------------------------------
// Liquidity pool K recomputation
// ---------------------------------------------------------------------------

/// Computes the constant-product invariant `K` for a liquidity pool.
///
/// `K = upper_bound^(2 * V_norm) * lower_bound^(ln(V_norm))`
///
/// where `V_norm = volume / t_ref` (a fixed-point ratio at `FP` scale). The formula is
/// evaluated in log-space to avoid overflow:
///
/// `ln_K = 2 * V_norm * ln(upper_bound) + ln(V_norm) * ln(lower_bound)`
/// `K = exp_fixed(ln_K)` (saturating)
///
/// All inputs are at the `FPU` (`1e12`) fixed-point scale (matching `PriceBounds` and
/// `ValueIndex`). Returns `K` at the same `FPU` scale. Returns `0` when any input is zero
/// or `t_ref` is zero.
pub fn compute_pool_k(
    upper_bound: oxydome_core::Amount,
    lower_bound: oxydome_core::Amount,
    volume: oxydome_core::Amount,
    t_ref: oxydome_core::Amount,
) -> oxydome_core::Amount {
    if upper_bound == 0 || lower_bound == 0 || t_ref == 0 || volume == 0 {
        return 0;
    }
    let ub = i128::try_from(upper_bound).unwrap_or(i128::MAX);
    let lb = i128::try_from(lower_bound).unwrap_or(i128::MAX);
    let vol = volume as i128;
    let tref = t_ref as i128;
    let v_norm = fp_div(vol, tref);
    if v_norm <= 0 {
        return 0;
    }
    let ln_v = ln_fixed(v_norm);
    let ln_upper = ln_fixed(ub);
    let ln_lower = ln_fixed(lb);
    let term1 = fp_mul(v_norm.saturating_mul(2), ln_upper);
    let term2 = fp_mul(ln_v, ln_lower);
    let ln_k = term1.saturating_add(term2);
    let k = exp_fixed(ln_k);
    if k < 0 {
        0
    } else {
        k as u128
    }
}

// ---------------------------------------------------------------------------
// Bunny-hop maturity (BH1 / BH2)
// ---------------------------------------------------------------------------

/// Returns true if a UTXO created at `created_height` with the given `rebound_gen` may be
/// spent at `current_height`.
///
/// * Ordinary (non-rebound) outputs are always spendable.
/// * A rebound-credited output is locked for `L = rebound_lock_blocks` blocks after creation
///   (BH1 maturity). Because rebound credits are created on the rebound block, they also
///   cannot be transferred within the same generation (BH2).
pub fn rebound_utxo_spendable(
    current_height: u64,
    created_height: u64,
    rebound_gen: Option<u64>,
    params: &ChainParams,
) -> bool {
    match rebound_gen {
        None => true,
        Some(_) => current_height >= created_height.saturating_add(params.rebound_lock_blocks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln_basic() {
        assert_eq!(ln_fixed(FP), 0);
        assert!((ln_fixed(2 * FP) - LN2).abs() < 1000);
        // ln(e) ~ 1.0
        let e = exp_fixed(FP);
        assert!((ln_fixed(e) - FP).abs() < 1_000_000);
    }

    #[test]
    fn exp_basic() {
        assert_eq!(exp_fixed(0), FP);
        let e = exp_fixed(FP);
        assert!((e - 2_718_281_828_459i128).abs() < 1_000_000, "got {e}");
    }

    #[test]
    fn ln_monotonic() {
        let mut prev = ln_fixed(FP);
        for i in 1..50 {
            let x = FP + (i * FP) / 10;
            let cur = ln_fixed(x);
            assert!(cur >= prev);
            prev = cur;
        }
    }

    #[test]
    fn value_rises_with_volume() {
        let params = ChainParams::default_local();
        let low = WindowStats {
            volume: 1_000,
            tx_count: 10,
            exit_amount: 0,
            highest_tx_value: 0,
        };
        let high = WindowStats {
            volume: 1_000_000,
            tx_count: 10_000,
            exit_amount: 0,
            highest_tx_value: 0,
        };
        let v_low = compute_value(
            &params,
            &low,
            params.genesis_supply,
            params.genesis_supply,
            ValueIndex::ONE,
            0,
        );
        let v_high = compute_value(
            &params,
            &high,
            params.genesis_supply,
            params.genesis_supply,
            ValueIndex::ONE,
            0,
        );
        assert!(v_high.value > v_low.value);
    }

    #[test]
    fn rebound_triggers_and_resets() {
        let params = ChainParams::default_local();
        let stats = WindowStats {
            volume: 0,
            tx_count: 0,
            exit_amount: 10_000_000_000,
            highest_tx_value: 0,
        };
        let prev = ValueIndex::from_raw(2 * FPU);
        let t = compute_value(
            &params,
            &stats,
            params.genesis_supply,
            params.genesis_supply,
            prev,
            5,
        );
        assert!(t.rebounded);
        assert_eq!(t.value, prev);
        assert_eq!(t.generation, 6);
    }

    #[test]
    fn fee_affordability() {
        let params = ChainParams::default_local();
        assert!(fee_affordable(ValueIndex::ONE, &params));
    }

    #[test]
    fn maturity_lock() {
        let params = ChainParams::default_local();
        assert!(!rebound_utxo_spendable(10, 10, Some(1), &params));
        assert!(rebound_utxo_spendable(
            10 + params.rebound_lock_blocks,
            10,
            Some(1),
            &params
        ));
        assert!(rebound_utxo_spendable(0, 0, None, &params));
    }

    #[test]
    fn compute_pool_k_returns_nonzero_for_valid_inputs() {
        // With upper_bound = lower_bound = v_norm = FPU, K should be exp(2*v_norm*ln(FPU) + ln(v_norm)*ln(FPU))
        let upper = FPU; // 1e12
        let lower = FPU;
        let volume = FPU * 100; // 1e14
        let t_ref = FPU; // 1e12
        let k = compute_pool_k(upper, lower, volume, t_ref);
        assert!(k > 0);
    }

    #[test]
    fn compute_pool_k_returns_zero_for_zero_inputs() {
        assert_eq!(compute_pool_k(0, FPU, FPU, FPU), 0);
        assert_eq!(compute_pool_k(FPU, 0, FPU, FPU), 0);
        assert_eq!(compute_pool_k(FPU, FPU, 0, FPU), 0);
        assert_eq!(compute_pool_k(FPU, FPU, FPU, 0), 0);
    }
}
