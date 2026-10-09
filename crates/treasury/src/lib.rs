//! Treasury governance: constructing and approving mint/burn operations, plus the
//! guardrail helpers proposers use to choose an acceptable amount.

use oxydome_core::{
    Amount, ChainParams, Hash, MasterApproval, Operation, OutPoint, PublicKey, TreasuryBurn,
    TreasuryMint, ValueIndex,
};
use oxydome_crypto::KeyPair;
use oxydome_currency::{max_supply_change, supply_change_cap, WindowStats};

/// Creates a mint proposal with no approvals yet.
pub fn mint_proposal(amount: Amount, recipient: PublicKey) -> TreasuryMint {
    TreasuryMint {
        amount,
        recipient,
        approvals: Vec::new(),
    }
}

/// The proposal id that master approvals must sign for a mint.
pub fn mint_proposal_id(amount: Amount, recipient: PublicKey) -> Hash {
    Operation::Mint(mint_proposal(amount, recipient)).proposal_id()
}

/// Appends a master's approval to a mint.
pub fn approve_mint(mint: &mut TreasuryMint, master: &KeyPair) {
    let id = Operation::Mint(mint.clone()).proposal_id();
    mint.approvals.push(MasterApproval {
        master: master.public(),
        proposal: id,
        signature: master.sign(&id.0),
    });
}

/// Creates a burn proposal with no approvals or owner signature yet.
pub fn burn_proposal(source: OutPoint, owner: PublicKey, amount: Amount) -> TreasuryBurn {
    TreasuryBurn {
        source,
        owner,
        owner_signature: oxydome_crypto::Sig([0u8; 64]),
        amount,
        approvals: Vec::new(),
    }
}

/// The proposal id that master approvals and the owner signature must sign for a burn.
pub fn burn_proposal_id(source: OutPoint, owner: PublicKey, amount: Amount) -> Hash {
    Operation::Burn(burn_proposal(source, owner, amount)).proposal_id()
}

/// Signs a burn with the owner key (the current holder of the source output).
pub fn sign_burn(burn: &mut TreasuryBurn, owner_key: &KeyPair) {
    let id = Operation::Burn(burn.clone()).proposal_id();
    burn.owner_signature = owner_key.sign(&id.0);
}

/// Appends a master's approval to a burn.
pub fn approve_burn(burn: &mut TreasuryBurn, master: &KeyPair) {
    let id = Operation::Burn(burn.clone()).proposal_id();
    burn.approvals.push(MasterApproval {
        master: master.public(),
        proposal: id,
        signature: master.sign(&id.0),
    });
}

/// The largest mint that satisfies both the per-epoch cap and the value-impact guardrail.
pub fn max_mint(
    params: &ChainParams,
    stats: &WindowStats,
    supply: Amount,
    genesis_supply: Amount,
    previous: ValueIndex,
    requested: Amount,
) -> Amount {
    max_supply_change(
        params,
        stats,
        supply,
        genesis_supply,
        previous,
        requested,
        true,
    )
}

/// The largest burn that satisfies both the per-epoch cap and the value-impact guardrail.
pub fn max_burn(
    params: &ChainParams,
    stats: &WindowStats,
    supply: Amount,
    genesis_supply: Amount,
    previous: ValueIndex,
    requested: Amount,
) -> Amount {
    max_supply_change(
        params,
        stats,
        supply,
        genesis_supply,
        previous,
        requested,
        false,
    )
}

/// The hard per-epoch supply-change cap.
pub fn epoch_supply_cap(params: &ChainParams) -> Amount {
    supply_change_cap(params)
}
