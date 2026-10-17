//! Speedometer fuel-currency helpers.
//!
//! Pure, deterministic functions used by consensus to size and distribute Speedometer.
//! Speedometer is account-based: balances live in a `BTreeMap<PublicKey, Amount>` on
//! the chain state.
//!
//! The airdrop amount is a basis-point share of the block's highest transaction value,
//! scaled by the on-chain Ox price oracle:
//! `highest_tx_value * airdrop_base_bps / 10_000 * ox_price / price_reference`.

use oxydome_core::{Amount, PublicKey, GAS_BPS_DENOMINATOR};
use std::collections::BTreeMap;

/// Computes the fresh Speedometer airdrop amount given the highest transaction value,
/// the base basis points, the current oracle price and its normalizing reference.
pub fn airdrop_amount(
    _supply: Amount,
    airdrop_base_bps: u32,
    highest_tx_value: Amount,
    price_reference: Amount,
    ox_price: Amount,
) -> Amount {
    if highest_tx_value == 0 || airdrop_base_bps == 0 || ox_price == 0 || price_reference == 0 {
        return 0;
    }
    let base = highest_tx_value.saturating_mul(airdrop_base_bps as u128) / GAS_BPS_DENOMINATOR;
    base.saturating_mul(ox_price) / price_reference
}

/// Computes the per-transaction Speedometer stabilization mint:
/// `tx_value * stabilization_bps / 10_000`.
pub fn stabilization_mint(tx_value: Amount, stabilization_bps: u32) -> Amount {
    tx_value.saturating_mul(stabilization_bps as u128) / GAS_BPS_DENOMINATOR
}

/// Distributes `amount` Speedometer across `balances` proportionally to each balance.
///
/// Iterates the map in key order for determinism. The first recipient absorbs the rounding
/// remainder so the grants sum to exactly `amount`. Recipients whose computed share is zero
/// are omitted.
pub fn distribute_airdrop(
    balances: &BTreeMap<PublicKey, Amount>,
    amount: Amount,
) -> Vec<(PublicKey, Amount)> {
    if amount == 0 || balances.is_empty() {
        return Vec::new();
    }
    let total_weight: Amount = balances.values().fold(0u128, |a, b| a.saturating_add(*b));
    if total_weight == 0 {
        return Vec::new();
    }
    let mut grants = Vec::new();
    let mut assigned: Amount = 0;
    for (key, weight) in balances.iter() {
        let share = amount.saturating_mul(*weight) / total_weight;
        assigned = assigned.saturating_add(share);
        if share > 0 {
            grants.push((*key, share));
        }
    }
    let remainder = amount.saturating_sub(assigned);
    if remainder > 0 {
        if let Some((_, first)) = grants.first_mut() {
            *first = first.saturating_add(remainder);
        }
    }
    grants
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> PublicKey {
        PublicKey::from([i; 32])
    }

    #[test]
    fn airdrop_uses_highest_tx_value_as_base() {
        // highest_tx_value=1000, 100 bps (1%), price=300, reference=1 => 10 * 300 = 3000.
        assert_eq!(airdrop_amount(0, 100, 1_000, 1, 300), 3_000);
        assert_eq!(airdrop_amount(10_000, 100, 1_000, 1, 300), 3_000);
        // Zero guards.
        assert_eq!(airdrop_amount(0, 100, 0, 1, 300), 0);
        assert_eq!(airdrop_amount(0, 100, 1_000, 1, 0), 0);
        assert_eq!(airdrop_amount(0, 0, 1_000, 1, 300), 0);
    }

    #[test]
    fn stabilization_mint_scales_with_tx_value() {
        // 10_000 tx value, 10 bps (0.1%) => 10
        assert_eq!(stabilization_mint(10_000, 10), 10);
        // 10 bps of 1_000 => 1
        assert_eq!(stabilization_mint(1_000, 10), 1);
        // Zero value => 0
        assert_eq!(stabilization_mint(0, 10), 0);
    }

    #[test]
    fn distribution_is_proportional_and_conserves() {
        let mut balances = BTreeMap::new();
        balances.insert(key(1), 1u128);
        balances.insert(key(2), 1u128);
        balances.insert(key(3), 2u128);
        let grants = distribute_airdrop(&balances, 100);
        let total: Amount = grants.iter().map(|(_, a)| *a).sum();
        assert_eq!(total, 100);
        let g1 = grants.iter().find(|(k, _)| *k == key(1)).unwrap().1;
        let g3 = grants.iter().find(|(k, _)| *k == key(3)).unwrap().1;
        assert_eq!(g3, g1 * 2);
    }

    #[test]
    fn distribution_handles_remainder_and_empty() {
        assert!(distribute_airdrop(&BTreeMap::new(), 100).is_empty());
        let mut balances = BTreeMap::new();
        balances.insert(key(1), 1u128);
        balances.insert(key(2), 1u128);
        balances.insert(key(3), 1u128);
        let grants = distribute_airdrop(&balances, 100);
        let total: Amount = grants.iter().map(|(_, a)| *a).sum();
        assert_eq!(total, 100);
        assert_eq!(grants[0].1, 34);
    }
}
