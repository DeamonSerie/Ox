//! Turning a [`crate::coinselect::Built`] into a signable/submittable transaction.

use crate::keys::Signer;
use crate::WalletError;
use oxydome_core::{Amount, PublicKey, Transaction};
use oxydome_crypto::{Hash, KeyPair, Sig};

/// Converts a selection into an unsigned transaction with all-zero placeholder signatures.
pub fn to_transaction(built: &crate::coinselect::Built) -> Transaction {
    Transaction::new_unsigned(built.inputs.clone(), built.outputs.clone(), built.fee)
}

/// The canonical signing digest for every input, in order. A remote (non-custodial) wallet
/// signs each digest with its own key and returns the signatures to [`set_signature`].
pub fn signing_hashes(tx: &Transaction) -> Vec<Hash> {
    (0..tx.inputs.len()).map(|i| tx.signing_hash(i)).collect()
}

/// All public keys that own inputs, in input order.
pub fn input_owners(tx: &Transaction) -> Vec<PublicKey> {
    tx.inputs.iter().map(|i| i.owner).collect()
}

/// Attaches a caller-supplied signature to input `index`.
pub fn set_signature(
    tx: &mut Transaction,
    index: usize,
    signature: Sig,
) -> Result<(), WalletError> {
    let input = tx
        .inputs
        .get_mut(index)
        .ok_or_else(|| WalletError::Signing(format!("no input at index {index}")))?;
    input.signature = signature;
    Ok(())
}

/// Signs every input owned by `signer`. Returns the number of inputs signed.
pub fn sign_inputs(tx: &mut Transaction, signer: &impl Signer) -> usize {
    let owner = signer.public();
    let hashes = signing_hashes(tx);
    let mut signed = 0;
    for (index, input) in tx.inputs.iter_mut().enumerate() {
        if input.owner == owner {
            input.signature = signer.sign_hash(&hashes[index]);
            signed += 1;
        }
    }
    signed
}

/// One-shot convenience: select, build, sign with `signer`, and verify structure. Panics never;
/// returns a structural error the caller can surface as `USER_REJECTED`/`INVALID_TRANSACTION`.
pub fn build_and_sign(
    owner: PublicKey,
    recipient: PublicKey,
    amount: Amount,
    utxos: &[crate::coinselect::Utxo],
    signer: &impl Signer,
) -> Result<Transaction, WalletError> {
    let built = crate::coinselect::build_transfer(owner, recipient, amount, utxos)?;
    let mut tx = to_transaction(&built);
    if sign_inputs(&mut tx, signer) == 0 {
        return Err(WalletError::Signing(
            "signer does not own any selected input".into(),
        ));
    }
    tx.validate_structure()?;
    Ok(tx)
}

/// Signs with a raw keypair (delegates to [`Signer`]).
pub fn build_and_sign_local(
    owner: PublicKey,
    recipient: PublicKey,
    amount: Amount,
    utxos: &[crate::coinselect::Utxo],
    key: &KeyPair,
) -> Result<Transaction, WalletError> {
    build_and_sign(owner, recipient, amount, utxos, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinselect::{build_transfer, Utxo};
    use oxydome_crypto::KeyPair;

    fn sample_utxos(owner: PublicKey) -> Vec<Utxo> {
        [250_000u128, 250_000, 500_000]
            .into_iter()
            .enumerate()
            .map(|(i, amount)| Utxo {
                outpoint: oxydome_core::OutPoint::new(Hash::zero(), i as u32),
                owner,
                amount,
            })
            .collect()
    }

    #[test]
    fn unsigned_tx_has_zero_signatures_and_matches_selection() {
        let owner = KeyPair::from_seed(&[4u8; 32]);
        let recipient = KeyPair::from_seed(&[5u8; 32]).public();
        let built = build_transfer(
            owner.public(),
            recipient,
            400_000,
            &sample_utxos(owner.public()),
        )
        .unwrap();
        let tx = to_transaction(&built);
        assert_eq!(tx.inputs.len(), built.inputs.len());
        assert!(tx
            .inputs
            .iter()
            .all(|i| i.signature.as_bytes().iter().all(|b| *b == 0)));
        assert_eq!(tx.fee, built.fee);
        // unsigned tx still gives deterministic signing hashes
        assert_eq!(signing_hashes(&tx).len(), tx.inputs.len());
    }

    #[test]
    fn signing_hashes_cover_all_inputs() {
        let owner = KeyPair::from_seed(&[4u8; 32]);
        let recipient = KeyPair::from_seed(&[5u8; 32]).public();
        let built = build_transfer(
            owner.public(),
            recipient,
            400_000,
            &sample_utxos(owner.public()),
        )
        .unwrap();
        let tx = to_transaction(&built);
        let hashes = signing_hashes(&tx);
        assert_eq!(hashes.len(), built.inputs.len());
        // distinct inputs have distinct digests
        for (i, h) in hashes.iter().enumerate() {
            for (j, h2) in hashes.iter().enumerate() {
                if i != j {
                    assert_ne!(h, h2);
                }
            }
        }
    }

    #[test]
    fn build_and_sign_produces_valid_tx() {
        let owner = KeyPair::from_seed(&[4u8; 32]);
        let recipient = KeyPair::from_seed(&[5u8; 32]).public();
        let tx = build_and_sign_local(
            owner.public(),
            recipient,
            400_000,
            &sample_utxos(owner.public()),
            &owner,
        )
        .unwrap();
        assert!(tx.validate_structure().is_ok());
    }

    #[test]
    fn foreign_signer_is_rejected() {
        let owner = KeyPair::from_seed(&[4u8; 32]);
        let recipient = KeyPair::from_seed(&[5u8; 32]).public();
        let stranger = KeyPair::from_seed(&[6u8; 32]);
        let err = build_and_sign_local(
            owner.public(),
            recipient,
            400_000,
            &sample_utxos(owner.public()),
            &stranger,
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Signing(_)));
    }
}
