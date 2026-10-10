//! Master-node audit layer.
//!
//! Before a block is appended, masters must account for every input against the full prior
//! history. This is done with Merkle inclusion proofs against the previous UTXO root, a
//! deterministic replay of the block, the lineage invariant `sum(live UTXO) == supply`, and
//! periodic literal deep replay.

use oxydome_core::{
    Amount, Block, ChainParams, GovernanceSet, Operation, OutPoint, PublicKey, Sig, ValueIndex,
};
use oxydome_crypto::{hash_value, Hash, SparseProof};
use oxydome_currency::{
    compute_value, rebound_utxo_spendable, supply_change_cap, withdraw_cap, WindowStats,
};
use oxydome_state::{ChainState, StateError, UtxoEntry};
use serde::{Deserialize, Serialize};

/// Errors raised by the audit layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("audit package pre-state root does not match the chain head")]
    PreStateRootMismatch,
    #[error("missing proof for input {0:?}")]
    MissingProof(OutPoint),
    #[error("input proof for {0:?} failed to verify")]
    BadProof(OutPoint),
    #[error("input proof entry does not match the committed UTXO")]
    ProofEntryMismatch(OutPoint),
    #[error("block replay failed: {0}")]
    Replay(String),
    #[error("lineage invariant broken: UTXO total {0} != supply {1}")]
    Lineage(u128, u128),
    #[error("audit root mismatch")]
    AuditRootMismatch,
    #[error("header statistics do not match the block body")]
    StatsMismatch,
    #[error("governance guardrail violated: {0}")]
    Guardrail(String),
    #[error("value index mismatch: computed {0} header {1}")]
    ValueMismatch(String, String),
    #[error("supply mismatch: computed {0} header {1}")]
    SupplyMismatch(Amount, Amount),
    #[error("conservation failed in transaction {0}")]
    Conservation(usize),
    #[error("input {0:?} is not spendable")]
    NotSpendable(OutPoint),
    #[error("input {0:?} is an immature rebound credit")]
    ImmatureRebound(OutPoint),
}

/// A sparse-Merkle inclusion proof for one block input against the previous state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputProof {
    pub outpoint: OutPoint,
    pub entry: UtxoEntry,
    pub proof: SparseProof,
}

/// Everything a master needs to audit a proposed block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPackage {
    pub block: Block,
    /// The UTXO root the proofs are against (must equal the previous block's UTXO root).
    pub pre_utxo_root: Hash,
    pub inputs: Vec<InputProof>,
}

/// The result of a successful audit; masters sign this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub block_hash: Hash,
    pub state_root: Hash,
    /// Merkle root over the audited input leaves.
    pub audit_root: Hash,
}

/// The canonical data an [`AuditAttestation`] signs.
#[derive(Serialize)]
struct AttestationData {
    block_hash: Hash,
    state_root: Hash,
    audit_root: Hash,
}

/// A master's signed statement that it audited a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAttestation {
    pub block_hash: Hash,
    pub state_root: Hash,
    pub audit_root: Hash,
    pub master: PublicKey,
    pub signature: Sig,
}

impl AuditAttestation {
    pub fn sign(report: &AuditReport, master_key: &oxydome_crypto::KeyPair) -> Self {
        let data = AttestationData {
            block_hash: report.block_hash,
            state_root: report.state_root,
            audit_root: report.audit_root,
        };
        Self {
            block_hash: report.block_hash,
            state_root: report.state_root,
            audit_root: report.audit_root,
            master: master_key.public(),
            signature: master_key.sign(&oxydome_crypto::encode(&data)),
        }
    }

    pub fn is_valid(&self) -> bool {
        let data = AttestationData {
            block_hash: self.block_hash,
            state_root: self.state_root,
            audit_root: self.audit_root,
        };
        oxydome_crypto::verify(
            &self.master,
            &oxydome_crypto::encode(&data),
            &self.signature,
        )
    }
}

/// Computes the audit root over a package's input leaves.
pub fn audit_root(package: &AuditPackage) -> Hash {
    let mut leaves: Vec<Hash> = package.inputs.iter().map(|p| p.entry.leaf()).collect();
    leaves.sort();
    oxydome_crypto::merkle_root(&leaves)
}

/// Audits a package against `state_before`.
///
/// This cryptographically accounts for every input's funds back through all prior blocks (via
/// the Merkle proof against the previous state root), deterministically replays the block, and
/// checks the lineage invariant.
pub fn audit_package(
    state_before: &ChainState,
    gov: &GovernanceSet,
    params: &ChainParams,
    package: &AuditPackage,
) -> Result<AuditReport, AuditError> {
    let pre_root = state_before.utxo_root();
    if pre_root != package.pre_utxo_root {
        return Err(AuditError::PreStateRootMismatch);
    }

    // 1. Verify an inclusion proof for every input of every transaction.
    let mut proof_index: std::collections::BTreeMap<OutPoint, &InputProof> =
        std::collections::BTreeMap::new();
    for p in &package.inputs {
        if !oxydome_state::UtxoLedger::verify_inclusion(&pre_root, &p.entry, &p.proof) {
            return Err(AuditError::BadProof(p.outpoint));
        }
        proof_index.insert(p.outpoint, p);
    }
    for tx in &package.block.transactions {
        for input in &tx.inputs {
            let p = proof_index
                .get(&input.prev_out)
                .ok_or(AuditError::MissingProof(input.prev_out))?;
            // The proven entry must be the one the block actually spends.
            if p.entry.outpoint != input.prev_out || p.entry.output.recipient != input.owner {
                return Err(AuditError::ProofEntryMismatch(input.prev_out));
            }
        }
    }

    // 2. Replay / verify the block transition.
    let after = state_before
        .apply_block(&package.block, gov, params)
        .map_err(|e: StateError| AuditError::Replay(e.to_string()))?;

    // 3. Lineage invariant.
    let utxo_total = after.utxo.total();
    if utxo_total != after.supply {
        return Err(AuditError::Lineage(utxo_total, after.supply));
    }

    Ok(AuditReport {
        block_hash: package.block.hash(),
        state_root: after.state_root(),
        audit_root: audit_root(package),
    })
}

/// Verifies a set of master attestations meets the audit super-majority for `block`.
pub fn attestation_quorum(
    block: &Block,
    attestations: &[AuditAttestation],
    gov: &GovernanceSet,
    params: &ChainParams,
) -> bool {
    let block_hash = block.hash();
    let mut seen = std::collections::BTreeSet::new();
    let mut valid = 0;
    for att in attestations {
        if att.block_hash != block_hash || att.state_root != block.header.state_root {
            continue;
        }
        if !gov.contains_master(&att.master) || !att.is_valid() {
            continue;
        }
        if seen.insert(att.master) {
            valid += 1;
        }
    }
    valid >= gov.master_threshold(params)
}

/// Literally replays a sequence of blocks from `state`, used by the periodic deep audit.
pub fn deep_replay(
    state: &ChainState,
    blocks: &[Block],
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<ChainState, StateError> {
    let mut current = state.clone();
    for block in blocks {
        current = current.apply_block(block, gov, params)?;
    }
    Ok(current)
}

/// Convenience: hash of an audit report for logging.
pub fn report_id(report: &AuditReport) -> Hash {
    hash_value(report)
}

/// Context a header-only master needs to audit a block without storing the UTXO set.
///
/// `pre_utxo_root` must equal the previous header's UTXO-root commitment. The complete state
/// root may additionally commit to OVM state and is not the Merkle root used by UTXO proofs.
/// `previous_window` must be the sum of the last `block_window - 1` blocks' statistics (the
/// function adds the current block's statistics to it), so that the window matches exactly the
/// one the state machine used.
#[derive(Debug, Clone)]
pub struct HeaderAuditContext<'a> {
    pub pre_utxo_root: Hash,
    pub prev_supply: Amount,
    pub prev_value_index: ValueIndex,
    pub prev_generation: u64,
    pub previous_window: WindowStats,
    pub genesis_supply: Amount,
    pub epoch_minted: Amount,
    pub epoch_burned: Amount,
    pub epoch_withdrawn: Amount,
    pub gov: &'a GovernanceSet,
    pub params: &'a ChainParams,
}

/// Audits a block using only the header commitments and the supplied Merkle proofs.
///
/// This is the per-block master audit: every input's funds are accounted for back through the
/// full history via the inclusion proof against the previous state root; conservation, BH
/// maturity, governance guardrails, supply and the value index are all recomputed and checked
/// against the header. The new UTXO root itself is verified by the periodic deep replay on
/// server nodes (which hold full state). This header-only audit does not execute OVM bytecode or
/// independently validate OVM receipts; server nodes must validate the complete state transition
/// before voting.
pub fn header_audit(
    ctx: &HeaderAuditContext,
    package: &AuditPackage,
) -> Result<AuditReport, AuditError> {
    let block = &package.block;
    if package.pre_utxo_root != ctx.pre_utxo_root {
        return Err(AuditError::PreStateRootMismatch);
    }

    // 1. Verify every input's inclusion proof and account for conservation.
    let mut proof_index: std::collections::BTreeMap<OutPoint, &InputProof> =
        std::collections::BTreeMap::new();
    for p in &package.inputs {
        if !oxydome_state::UtxoLedger::verify_inclusion(&ctx.pre_utxo_root, &p.entry, &p.proof) {
            return Err(AuditError::BadProof(p.outpoint));
        }
        proof_index.insert(p.outpoint, p);
    }

    let mut block_stats = WindowStats::default();
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        let mut input_total: Amount = 0;
        for input in &tx.inputs {
            let p = proof_index
                .get(&input.prev_out)
                .ok_or(AuditError::MissingProof(input.prev_out))?;
            if p.entry.outpoint != input.prev_out || p.entry.output.recipient != input.owner {
                return Err(AuditError::ProofEntryMismatch(input.prev_out));
            }
            if !p.entry.output.kind.is_spendable() {
                return Err(AuditError::NotSpendable(input.prev_out));
            }
            if !rebound_utxo_spendable(
                block.header.height,
                p.entry.created_height,
                p.entry.output.rebound_gen,
                ctx.params,
            ) {
                return Err(AuditError::ImmatureRebound(input.prev_out));
            }
            input_total = input_total.saturating_add(p.entry.output.amount);
        }
        let output_total = tx.output_total().unwrap_or(0);
        if input_total != output_total.saturating_add(tx.fee) {
            return Err(AuditError::Conservation(tx_idx));
        }
        block_stats.volume = block_stats.volume.saturating_add(output_total);
        block_stats.tx_count += 1;
        block_stats.exit_amount = block_stats.exit_amount.saturating_add(
            tx.outputs
                .iter()
                .filter(|o| o.kind.is_exit())
                .map(|o| o.amount)
                .fold(0u128, |a, b| a.saturating_add(b)),
        );
    }

    // 2. Header statistics must match the body.
    if block.header.volume != block_stats.volume
        || block.header.tx_count != block_stats.tx_count
        || block.header.exit_amount != block_stats.exit_amount
    {
        return Err(AuditError::StatsMismatch);
    }

    // 3. Recompute supply from the explicit operation amounts and enforce guardrails.
    let mut supply = ctx.prev_supply;
    let mut epoch_minted = ctx.epoch_minted;
    let mut epoch_burned = ctx.epoch_burned;
    let mut epoch_withdrawn = ctx.epoch_withdrawn;
    for op in &block.operations {
        match op {
            Operation::Mint(m) => {
                if epoch_minted.saturating_add(m.amount) > supply_change_cap(ctx.params) {
                    return Err(AuditError::Guardrail("mint cap exceeded".into()));
                }
                epoch_minted = epoch_minted.saturating_add(m.amount);
                supply = supply.saturating_add(m.amount);
            }
            Operation::Burn(b) => {
                if epoch_burned.saturating_add(b.amount) > supply_change_cap(ctx.params) {
                    return Err(AuditError::Guardrail("burn cap exceeded".into()));
                }
                epoch_burned = epoch_burned.saturating_add(b.amount);
                supply = supply.saturating_sub(b.amount);
            }
            Operation::Withdraw(w) => {
                if epoch_withdrawn.saturating_add(w.amount) > withdraw_cap(ctx.params) {
                    return Err(AuditError::Guardrail("withdraw cap exceeded".into()));
                }
                epoch_withdrawn = epoch_withdrawn.saturating_add(w.amount);
            }
            Operation::Rewards(_) => {}
            Operation::Dao(dao_operation) => {
                if !dao_operation.is_valid() {
                    return Err(AuditError::Guardrail(
                        "DAO operation signature or encoding is invalid".into(),
                    ));
                }
            }
            Operation::Ohm(ohm_operation) => {
                if !ohm_operation.is_valid() {
                    return Err(AuditError::Guardrail(
                        "OHM operation signature or encoding is invalid".into(),
                    ));
                }
            }
        }
    }

    if supply != block.header.supply {
        return Err(AuditError::SupplyMismatch(supply, block.header.supply));
    }

    // 4. Recompute the value index from the window.
    let mut window = ctx.previous_window;
    window.volume = window.volume.saturating_add(block_stats.volume);
    window.tx_count = window.tx_count.saturating_add(block_stats.tx_count);
    window.exit_amount = window.exit_amount.saturating_add(block_stats.exit_amount);
    let transition = compute_value(
        ctx.params,
        &window,
        supply,
        ctx.genesis_supply,
        ctx.prev_value_index,
        ctx.prev_generation,
    );
    if transition.value != block.header.value_index {
        return Err(AuditError::ValueMismatch(
            transition.value.to_display(),
            block.header.value_index.to_display(),
        ));
    }
    if transition.generation != block.header.generation {
        return Err(AuditError::Guardrail("generation mismatch".into()));
    }

    Ok(AuditReport {
        block_hash: block.hash(),
        state_root: block.header.state_root,
        audit_root: audit_root(package),
    })
}
