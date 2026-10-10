//! Helper functions for building and signing OHM operations.

use crate::{Amount, Hash, OhmContext, OhmOperation, OhmOutput, OutPoint, PublicKey};
use oxydome_core::OhmAction;
use oxydome_crypto::KeyPair;

/// Creates an unsigned OHM Create operation for `maintainer`.
pub fn create_ohm_unsigned(
    maintainer: PublicKey,
    policy_bytes: Vec<u8>,
    genesis_outputs: Vec<OhmOutput>,
) -> OhmOperation {
    OhmOperation::new_unsigned(
        maintainer,
        OhmAction::Create {
            policy_bytes,
            genesis_outputs,
        },
    )
}

/// Creates an unsigned OHM Update (anchor) operation.
pub fn update_ohm_unsigned(
    maintainer: PublicKey,
    ohm_id: Hash,
    context: OhmContext,
    block_hash: Hash,
    fee_total: Amount,
) -> OhmOperation {
    OhmOperation::new_unsigned(
        maintainer,
        OhmAction::Update {
            ohm_id,
            context,
            block_hash,
            fee_total,
        },
    )
}

/// Creates an unsigned OHM Terminate operation.
pub fn terminate_ohm_unsigned(maintainer: PublicKey, ohm_id: Hash, reason: String) -> OhmOperation {
    OhmOperation::new_unsigned(maintainer, OhmAction::Terminate { ohm_id, reason })
}

/// Creates an unsigned OHM Transfer operation.
pub fn transfer_ohm_unsigned(
    maintainer: PublicKey,
    ohm_id: Hash,
    recipient: PublicKey,
    amount: Amount,
) -> OhmOperation {
    OhmOperation::new_unsigned(
        maintainer,
        OhmAction::Transfer {
            ohm_id,
            recipient,
            amount,
        },
    )
}

/// Creates an unsigned OHM TreasuryDeposit operation.
pub fn treasury_deposit_ohm_unsigned(
    actor: PublicKey,
    ohm_id: Hash,
    source: OutPoint,
    amount: Amount,
) -> OhmOperation {
    OhmOperation::new_unsigned(
        actor,
        OhmAction::TreasuryDeposit {
            ohm_id,
            source,
            amount,
        },
    )
}

/// Signs an OHM operation with the actor's key.
pub fn sign_operation(op: &mut OhmOperation, key: &KeyPair) {
    op.sign(key);
}
