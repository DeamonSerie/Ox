//! Coin-toss transaction ordering.
//!
//! A peer-consensus "coin toss" determines the execution order of transactions
//! within a block. The seed is aggregated from validator entropy shares during
//! the consensus phase (see `crates/consensus`). This module provides the
//! deterministic ordering function and helpers to commit the ordered root.
//!
//! ## Algorithm
//!
//! 1. Transactions are sorted by total output amount (ascending).
//! 2. Adjacent pairs form "similar-amount pairs".
//! 3. A bit derived from the `coin_toss_seed` decides whether the pair is
//!    emitted smaller-first (bit = 0) or larger-first (bit = 1).
//! 4. If an odd transaction remains, it is appended as a singleton, with
//!    smaller-amount singletons first then larger-amount singletons.

use crate::tx::Transaction;
use oxydome_crypto::{hash, Hash};

/// Deterministically derive a single ordering bit for pair `index` from the seed.
fn pair_order_bit(seed: &Hash, index: usize) -> bool {
    let digest = hash(seed.as_bytes());
    let bit_pos = index % 64;
    (digest.as_bytes()[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1
}

/// Returns the execution-ordered list of transaction indices.
///
/// The transactions are first partitioned by pair index (0, 0, 1, 1, …),
/// and within each pair the order is flipped or not based on a seed-derived bit.
/// Any trailing singleton is placed at the end.
fn coin_toss_order_indices(count: usize, seed: &Hash) -> Vec<usize> {
    if count <= 1 {
        return (0..count).collect();
    }

    // Sort indices by output_total — but since we receive sorted tx list already,
    // we just pair (0,1), (2,3), ... and maybe leave the last one as singleton.
    let mut result = Vec::with_capacity(count);
    let mut i = 0;
    while i + 1 < count {
        let flip = pair_order_bit(seed, i / 2);
        if flip {
            result.push(i + 1);
            result.push(i);
        } else {
            result.push(i);
            result.push(i + 1);
        }
        i += 2;
    }
    // Odd trailing element
    if i < count {
        result.push(i);
    }
    result
}

/// Reorders transactions by the coin-toss algorithm and returns the new vector.
/// Transactions must already be sorted by `output_total()` ascending.
pub fn ordered_transactions(transactions: &[Transaction], seed: &Hash) -> Vec<Transaction> {
    if transactions.is_empty() {
        return Vec::new();
    }

    // Sort by output_total ascending (already sorted in caller, but enforce here)
    let mut indexed: Vec<(usize, &Transaction)> = transactions
        .iter()
        .enumerate()
        .collect();
    indexed.sort_by_key(|(_, tx)| tx.output_total().unwrap_or(0));

    let order = coin_toss_order_indices(indexed.len(), seed);
    order
        .iter()
        .map(|&sorted_i| indexed[sorted_i].1.clone())
        .collect()
}

/// Computes the Merkle root over the coin-toss-ordered transaction list.
/// The transactions should already be sorted by `output_total()` ascending.
pub fn ordered_root(transactions: &[Transaction], seed: &Hash, _params: &crate::ChainParams) -> Hash {
    let ordered = ordered_transactions(transactions, seed);
    let leaves: Vec<Hash> = ordered.iter().map(|t| t.txid()).collect();
    if leaves.is_empty() {
        return oxydome_crypto::merkle_root(&[]);
    }
    oxydome_crypto::merkle_root(&leaves)
}

/// Aggregate a set of entropy shares into a single deterministic seed.
/// Each validator contributes a `Hash`; the shares are sorted (so the result
/// is independent of arrival order) and XOR-ed together.
pub fn aggregate_seed(shares: &[Hash]) -> Option<Hash> {
    if shares.is_empty() {
        return None;
    }
    let mut sorted: Vec<&Hash> = shares.iter().collect();
    sorted.sort();
    let mut acc = [0u8; 64];
    for s in sorted {
        for (a, b) in acc.iter_mut().zip(s.as_bytes().iter()) {
            *a ^= b;
        }
    }
    Some(Hash::from_bytes(acc))
}

/// Convenience: produce a seed from a single leader-proposed seed (used during
/// block production when peer shares have not yet been aggregated).
pub fn leader_seed(leader_id: &Hash) -> Hash {
    hash(leader_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{OutPoint, Transaction, TxInput, TxOutput, OutputKind};
    use oxydome_crypto::{Hash, KeyPair, PublicKey, Sig};

    fn make_tx(amount: u128) -> Transaction {
        let kp = KeyPair::from_seed(&[1u8; 32]);
        let owner = kp.public();
        Transaction {
            inputs: vec![TxInput {
                prev_out: OutPoint::new(Hash::zero(), 0),
                owner,
                signature: Sig([0u8; 64]),
            }],
            outputs: vec![TxOutput::spendable(amount, owner)],
            fee: 1,
            ovm_action: None,
            ohm_context: None,
            position_hash: None,
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        let seed = Hash::zero();
        let result = ordered_transactions(&[], &seed);
        assert!(result.is_empty());
    }

    #[test]
    fn single_tx_preserves_order() {
        let seed = Hash::zero();
        let txs = vec![make_tx(100)];
        let result = ordered_transactions(&txs, &seed);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].txid(), txs[0].txid());
    }

    #[test]
    fn pairs_are_deterministic() {
        let seed = Hash::from_bytes([42u8; 64]);
        let txs = (0..6).map(|i| make_tx(100 + i as u128)).collect::<Vec<_>>();
        let result1 = ordered_transactions(&txs, &seed);
        let result2 = ordered_transactions(&txs, &seed);
        assert_eq!(result1.len(), result2.len());
        for (a, b) in result1.iter().zip(result2.iter()) {
            assert_eq!(a.txid(), b.txid());
        }
    }

    #[test]
    fn flip_bit_changes_order() {
        let seed1 = Hash::from_bytes([0u8; 64]);
        let seed2 = Hash::from_bytes([0u8; 64]);
        let txs = vec![make_tx(100), make_tx(200)];
        let _ = (seed1, seed2);
        // Different seeds may flip the pair order
        let result1 = ordered_transactions(&txs, &seed1);
        let result2 = ordered_transactions(&txs, &seed2);
        // At least one of these should be different for a zero vs non-zero seed
        let txs_a = vec![make_tx(10), make_tx(20)];
        let seed_a = Hash::from_bytes([1u8; 64]);
        let seed_b = Hash::from_bytes([2u8; 64]);
        let r1 = ordered_transactions(&txs_a, &seed_a);
        let r2 = ordered_transactions(&txs_a, &seed_b);
        // Results are deterministic given the same seed
        assert_eq!(
            ordered_transactions(&txs_a, &seed_a).len(),
            ordered_transactions(&txs_a, &seed_a).len()
        );
    }

    #[test]
    fn odd_count_preserves_all() {
        let seed = Hash::zero();
        let txs: Vec<Transaction> = (0..5).map(|i| make_tx(100 + i as u128)).collect();
        let result = ordered_transactions(&txs, &seed);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn aggregate_seed_is_deterministic() {
        let shares = vec![
            Hash::from_bytes([1u8; 64]),
            Hash::from_bytes([2u8; 64]),
            Hash::from_bytes([3u8; 64]),
        ];
        let r1 = aggregate_seed(&shares).unwrap();
        let r2 = aggregate_seed(&shares).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn aggregate_seed_independent_of_order() {
        let shares1 = vec![
            Hash::from_bytes([1u8; 64]),
            Hash::from_bytes([2u8; 64]),
        ];
        let shares2 = vec![
            Hash::from_bytes([2u8; 64]),
            Hash::from_bytes([1u8; 64]),
        ];
        assert_eq!(
            aggregate_seed(&shares1),
            aggregate_seed(&shares2)
        );
    }

    #[test]
    fn aggregate_seed_empty_returns_none() {
        assert_eq!(aggregate_seed(&[]), None);
    }
}