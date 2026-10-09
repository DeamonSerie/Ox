//! UTXO selection with change and a fixed-point fee solver.
//!
//! The chain requires `sum(inputs) == sum(outputs) + fee`, while the wallet fee rule is
//! `fee = ceil(sum(outputs) * 12 / 1_000_000)`. Because the fee depends on `sum(outputs)`
//! (which includes the change output that depends, in turn, on the fee), the two are solved to a
//! fixed point: iterate `fee <- fee_for_amount(input_total - fee)` until stable, then derive the
//! change output. Convergence is guaranteed for any selection whose inputs cover `amount + fee0`.

use crate::{fee, WalletError};
use oxydome_core::tx::MAX_TX_ITEMS;
use oxydome_core::{Amount, OutPoint, PublicKey, TxOutput};

/// A candidate spendable UTXO as supplied by the chain/API layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub owner: PublicKey,
    pub amount: Amount,
}

/// The result of a successful selection: inputs to reference, outputs to create, and the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub inputs: Vec<(OutPoint, PublicKey)>,
    pub outputs: Vec<TxOutput>,
    pub fee: Amount,
    pub input_total: Amount,
}

impl Built {
    /// Sum of all output amounts.
    pub fn output_total(&self) -> Result<Amount, WalletError> {
        let mut total: Amount = 0;
        for out in &self.outputs {
            total = total
                .checked_add(out.amount)
                .ok_or(oxydome_core::CoreError::Overflow)?;
        }
        Ok(total)
    }
}

/// Selects the smallest-first UTXOs whose sum covers `target`, without exceeding the input cap.
/// Returns the selected inputs and their total, or an error when the set cannot cover `target`.
fn select_inputs(
    utxos: &[Utxo],
    target: Amount,
) -> Result<(Vec<(OutPoint, PublicKey)>, Amount), WalletError> {
    if target == 0 {
        return Err(WalletError::ZeroAmount);
    }
    let mut owned: Vec<&Utxo> = utxos.iter().filter(|u| u.amount > 0).collect();
    owned.sort_by_key(|u| u.amount);
    let mut selected = Vec::with_capacity(owned.len().min(MAX_TX_ITEMS));
    let mut total: Amount = 0;
    for u in owned {
        if selected.len() >= MAX_TX_ITEMS {
            return Err(WalletError::TooManyInputs(MAX_TX_ITEMS));
        }
        selected.push(u);
        total = total
            .checked_add(u.amount)
            .ok_or(oxydome_core::CoreError::Overflow)?;
        if total >= target {
            return Ok((
                selected.iter().map(|u| (u.outpoint, u.owner)).collect(),
                total,
            ));
        }
    }
    Err(WalletError::InsufficientFunds {
        needed: target,
        available: total,
    })
}

/// Builds an (as yet unsigned) transfer from `owner` to `recipient`.
///
/// * `amount` — value transferred (must be `> 0`);
/// * `utxos` — all spendable UTXOs of `owner`;
/// * change is returned to `owner` when the selected inputs overshoot;
/// * `fee` is always `max(1, ceil(sum(outputs) * 12 / 1e6))` (see [`crate::fee`]).
pub fn build_transfer(
    owner: PublicKey,
    recipient: PublicKey,
    amount: Amount,
    utxos: &[Utxo],
) -> Result<Built, WalletError> {
    if amount == 0 {
        return Err(WalletError::ZeroAmount);
    }
    let fee0 = fee::fee_for_amount(amount);
    let (inputs, input_total) = select_inputs(utxos, amount.checked_add(fee0).unwrap_or(amount))?;

    // Fixed-point fee: outputs = amount + change, change = input_total - amount - fee, and
    // fee = fee_for_amount(sum(outputs)) where sum(outputs) = input_total - fee. Solve by
    // iterating fee <- fee_for_amount(input_total - fee).
    let mut fee = fee0;
    for _ in 0..32 {
        let assumed_outputs =
            input_total
                .checked_sub(fee)
                .ok_or(WalletError::InsufficientFunds {
                    needed: input_total,
                    available: fee,
                })?;
        let next = fee::fee_for_amount(assumed_outputs);
        if next == fee {
            break;
        }
        fee = next;
    }

    let change = input_total
        .checked_sub(amount)
        .and_then(|c| c.checked_sub(fee))
        .ok_or(WalletError::InsufficientFunds {
            needed: amount + fee,
            available: input_total,
        })?;

    let mut outputs = vec![TxOutput::spendable(amount, recipient)];
    if change > 0 {
        outputs.push(TxOutput::spendable(change, owner));
    }

    let built = Built {
        inputs,
        outputs,
        fee,
        input_total,
    };
    let sum_out = built.output_total()?;
    debug_assert_eq!(sum_out.checked_add(fee), Some(input_total), "conservation");
    if sum_out.checked_add(fee) != Some(input_total) {
        return Err(WalletError::Conservation {
            inputs: input_total,
            outputs: sum_out,
            fee,
        });
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::{Hash, KeyPair};
    use proptest::prelude::*;

    fn utxos(amounts: &[Amount]) -> Vec<Utxo> {
        let pk = KeyPair::from_seed(&[2u8; 32]).public();
        amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| Utxo {
                outpoint: OutPoint::new(Hash::zero(), i as u32),
                owner: pk,
                amount,
            })
            .collect()
    }

    #[test]
    fn exact_match_no_change() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        // amount 1_000_000 fee0 = 12; single utxo exact cover.
        let built = build_transfer(owner, recipient, 999_988, &utxos(&[1_000_000])).unwrap();
        assert_eq!(built.inputs.len(), 1);
        assert_eq!(built.outputs.len(), 1);
        assert_eq!(built.outputs[0].amount, 999_988);
        assert_eq!(built.fee, 12);
        assert_eq!(built.input_total, built.outputs[0].amount + built.fee);
    }

    #[test]
    fn change_returned_to_owner() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        let built =
            build_transfer(owner, recipient, 1_000_000, &utxos(&[1_000_000, 1_000_000])).unwrap();
        assert_eq!(built.outputs.len(), 2);
        assert_eq!(built.outputs[0].amount, 1_000_000);
        assert_eq!(built.outputs[1].recipient, owner, "change to owner");
        assert_eq!(
            built.outputs[1].amount + built.outputs[0].amount + built.fee,
            built.input_total
        );
        // Fee rule holds on the true output sum.
        let sum_out = built.output_total().unwrap();
        assert_eq!(built.fee, crate::fee::fee_for_amount(sum_out));
    }

    #[test]
    fn selects_multiple_inputs() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        let built = build_transfer(
            owner,
            recipient,
            700_000,
            &utxos(&[250_000, 250_000, 250_000, 500_000]),
        )
        .unwrap();
        assert_eq!(built.inputs.len(), 3, "smallest-first picks 3x250k");
        assert_eq!(built.input_total, 750_000);
    }

    #[test]
    fn insufficient_funds_reports_needed_and_available() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        let err = build_transfer(owner, recipient, 1_000_000, &utxos(&[10_000])).unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { .. }));
    }

    #[test]
    fn zero_amount_rejected() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        assert_eq!(
            build_transfer(owner, recipient, 0, &[]),
            Err(WalletError::ZeroAmount)
        );
    }

    #[test]
    fn tiny_amount_gets_min_fee() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let recipient = KeyPair::from_seed(&[3u8; 32]).public();
        let built = build_transfer(owner, recipient, 1, &utxos(&[100])).unwrap();
        assert_eq!(built.fee, crate::fee::MIN_FEE);
        assert_eq!(built.input_total, built.output_total().unwrap() + built.fee);
    }

    #[test]
    fn self_send_with_change() {
        let owner = KeyPair::from_seed(&[2u8; 32]).public();
        let built = build_transfer(owner, owner, 500_000, &utxos(&[1_000_000])).unwrap();
        assert_eq!(built.outputs.len(), 2);
        assert_eq!(built.outputs[0].amount, 500_000);
        assert_eq!(
            built.outputs[1].amount,
            built.input_total - 500_000 - built.fee
        );
    }

    proptest::proptest! {
        #[test]
        fn conservation_and_fee_rule_hold(
            transfer in 1u128..10_000_000u128,
            utxo_count in 1usize..20usize,
        ) {
            let owner = KeyPair::from_seed(&[2u8; 32]).public();
            let recipient = KeyPair::from_seed(&[3u8; 32]).public();
            let utxos: Vec<Utxo> = (0..utxo_count)
                .map(|i| {
                    // amounts up to ~1M each, so selection is realistic
                    let a = 1 + (i as u128 * 97_211) % 1_000_000u128;
                    Utxo { outpoint: OutPoint::new(Hash::zero(), i as u32), owner, amount: a }
                })
                .collect();
            match build_transfer(owner, recipient, transfer, &utxos) {
                Err(WalletError::InsufficientFunds { .. }) => {/* acceptable */}
                Err(e) => return Err(proptest::test_runner::TestCaseError::fail(format!("unexpected error: {e:?}"))),
                Ok(built) => {
                    let sum_out = built.output_total().unwrap();
                    prop_assert_eq!(sum_out + built.fee, built.input_total, "conservation");
                    prop_assert_eq!(built.fee, crate::fee::fee_for_amount(sum_out), "fee = 0.0012% of outputs");
                    prop_assert_eq!(built.outputs[0].amount, transfer, "transfer value");
                    for o in &built.outputs {
                        prop_assert!(o.amount > 0, "no zero outputs");
                        prop_assert!(o.recipient == owner || o.recipient == recipient);
                    }
                }
            }
        }
    }
}
