//! Fee rule for the wallet API.
//!
//! The transfer-fee component is **0.0012% of the transaction amount**, where the transaction
//! amount is the sum of all outputs. OVM transactions reserve their gas limit separately.
//!
//! ```text
//! transfer_fee(outputs) = max(1, ceil(sum(outputs) * 12 / 1_000_000))
//! ```
//!
//! The minimum of `1` is required because zero-fee transactions are invalid at the chain level
//! (`oxydome_core::tx::validate_structure` rejects `fee == 0`), and `ceil` keeps the smallest
//! transfers payable. Consultation remains the node's business: this only computes fees so wallet
//! apps and the RPC layer agree with the chain.

use crate::WalletError;
use oxydome_core::{transfer_fee as core_transfer_fee, transfer_fee_for_amount, Amount, TxOutput};

/// Numerators/denominator of `0.0012%` = `12 / 1_000_000`.
pub const FEE_PERMILLIONTHS: u128 = oxydome_core::tx::TRANSFER_FEE_NUMERATOR;
pub const FEE_DENOMINATOR: u128 = oxydome_core::tx::TRANSFER_FEE_DENOMINATOR;

/// The minimum fee that makes a transaction payable (zero-fee txs are invalid).
pub const MIN_FEE: Amount = oxydome_core::tx::MIN_TRANSFER_FEE;

/// Fee over a single `amount`, i.e. for a transaction whose only output is `amount`.
pub fn fee_for_amount(amount: Amount) -> Amount {
    transfer_fee_for_amount(amount)
}

/// Fee for an already-built output list. The transaction amount is `sum(outputs)`.
pub fn fee_for_outputs(outputs: &[TxOutput]) -> Result<Amount, WalletError> {
    core_transfer_fee(outputs).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::TxOutput;
    use oxydome_crypto::KeyPair;

    fn pk() -> oxydome_core::PublicKey {
        KeyPair::from_seed(&[1u8; 32]).public()
    }

    fn outs(amounts: &[Amount]) -> Vec<TxOutput> {
        let pk = pk();
        amounts
            .iter()
            .map(|&a| TxOutput::spendable(a, pk))
            .collect()
    }

    #[test]
    fn fee_is_0_0012_percent() {
        // 0.0012% of 100_000_000 is exactly 1200.
        assert_eq!(fee_for_amount(100_000_000), 1_200);
        assert_eq!(fee_for_amount(1_000_000_000), 12_000);
        // ceil: 0.0012% of 1000 is 0.012 -> 1.
        assert_eq!(fee_for_amount(1_000), 1);
    }

    #[test]
    fn min_fee_is_one() {
        assert_eq!(fee_for_amount(0), MIN_FEE);
        assert_eq!(fee_for_amount(1), MIN_FEE);
        assert_eq!(fee_for_amount(83_333), MIN_FEE); // 83_333*12/1e6 = 0.999... -> rounds to 1
    }

    #[test]
    fn fee_rounds_up() {
        // 0.0012% of 500_000 = 6 exactly; of 500_001 = 6.000012 -> 7.
        assert_eq!(fee_for_amount(500_000), 6);
        assert_eq!(fee_for_amount(500_001), 7);
    }

    #[test]
    fn fee_for_outputs_sums_amounts() {
        assert_eq!(
            fee_for_outputs(&outs(&[100_000_000, 100_000_000])).unwrap(),
            2_400
        );
    }

    #[test]
    fn fee_never_panics_on_extreme_amounts() {
        // saturating arithmetic keeps this defined; the result is still > 0.
        assert!(fee_for_amount(u128::MAX) >= MIN_FEE);
        assert!(fee_for_amount((1u128) << 126) >= MIN_FEE);
    }
}
