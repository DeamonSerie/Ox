//! Helper functions for building and signing OHM operations.

use crate::{
    Amount, CrossBurnCall, CrossSendCall, CrossTransferCall, Hash, OhmContext, OhmOperation,
    OhmOutput, OutPoint, PublicKey,
};
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

/// Constructs a cross-OHM send request targeting `entry_point` on `target_contract` hosted in
/// `target_ohm`. Does not request a reply.
pub fn cross_send_call(
    target_ohm: Hash,
    target_contract: Hash,
    entry_point: impl Into<String>,
    arguments: Vec<u64>,
    gas_limit: u64,
) -> CrossSendCall {
    CrossSendCall {
        target_ohm,
        target_contract,
        entry_point: entry_point.into(),
        arguments,
        gas_limit,
        want_reply: false,
        reply_contract: None,
        reply_entry_point: None,
    }
}

/// Marks `call` as requesting an auto-reply to `reply_contract`'s `reply_entry_point`.
pub fn with_reply(
    mut call: CrossSendCall,
    reply_contract: Hash,
    reply_entry_point: impl Into<String>,
) -> CrossSendCall {
    call.want_reply = true;
    call.reply_contract = Some(reply_contract);
    call.reply_entry_point = Some(reply_entry_point.into());
    call
}

/// Constructs a cross-chain asset transfer request.
pub fn cross_transfer_call(
    target_ohm: Hash,
    amount: Amount,
    recipient: PublicKey,
) -> CrossTransferCall {
    CrossTransferCall {
        target_ohm,
        amount,
        recipient,
    }
}

/// Constructs a cross-chain asset burn request.
pub fn cross_burn_call(source_ohm: Hash, amount: Amount) -> CrossBurnCall {
    CrossBurnCall { source_ohm, amount }
}
