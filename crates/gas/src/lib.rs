//! GAS fuel-currency helpers.
//!
//! Pure, deterministic functions used by consensus to size and distribute GAS. The currency is
//! account-based: balances live in a `BTreeMap<PublicKey, Amount>` on the chain state.
//!
//! The airdrop amount is a basis-point share of the current GAS supply, scaled by the on-chain
//! Ox price oracle: `gas_supply * airdrop_base_bps / 10_000 * ox_price / price_reference`.

use oxydome_core::{Amount, PublicKey, GAS_BPS_DENOMINATOR};
use std::collections::BTreeMap;

/// Computes the fresh GAS airdrop amount given the circulating supply, the base basis points,
/// the current oracle price and its normalizing reference.
pub fn airdrop_amount(
    gas_supply: Amount,
    airdrop_base_bps: u32,
    ox_price: Amount,
    price_reference: Amount,
) -> Amount {
    if gas_supply == 0 || airdrop_base_bps == 0 || ox_price == 0 || price_reference == 0 {
        return 0;
    }
    let base = gas_supply.saturating_mul(airdrop_base_bps as u128) / GAS_BPS_DENOMINATOR;
    base.saturating_mul(ox_price) / price_reference
}

/// Distributes `amount` GAS across `balances` proportionally to each balance.
///
/// Iterates the map in key order for determinism. The first recipient absorbs the rounding
/// remainder so the grants sum to exactly `amount`. Recipients whose computed share is zero are
/// omitted.
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
    // Give the rounding remainder to the first grant so the total is exact.
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
    fn airdrop_scales_with_supply_and_price() {
        // 1000 supply, 100 bps (1%), price 300, reference 1 => 10 * 300 = 3000.
        assert_eq!(airdrop_amount(1_000, 100, 300, 1), 3_000);
        // Zero guards.
        assert_eq!(airdrop_amount(0, 100, 300, 1), 0);
        assert_eq!(airdrop_amount(1_000, 100, 0, 1), 0);
        assert_eq!(airdrop_amount(1_000, 0, 300, 1), 0);
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
        // 2x weight receives 2x the amount of a 1x weight.
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
        // 100 / 3 = 33 each, remainder 1 to the first.
        let grants = distribute_airdrop(&balances, 100);
        let total: Amount = grants.iter().map(|(_, a)| *a).sum();
        assert_eq!(total, 100);
        assert_eq!(grants[0].1, 34);
    }
}
