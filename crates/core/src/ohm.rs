//! OHM (Ox Hosted Machine) core types.
//!
//! OHM creates isolated, tenant-owned blockchains that rely on Ox network nodes for their
//! immutable ledger. Each OHM is a separate blockchain whose transactions are private from the
//! Ox network and from other OHMs, but whose chain continuity is anchored in Ox blocks.
//!
//! A tenant builds [`OhmBlock`]s (private, ordered batches of [`OhmTransaction`]s) and anchors
//! their state roots into Ox blocks via [`OhmAction::Update`]. Server nodes keep the private
//! blocks and re-derive the OHM state, rejecting any Ox block whose anchor does not match.
//!
//! OHM transactions pay fees to the Ox network, which are split automatically:
//! - [`OHM_SERVER_FEE_BPS`] (40%) of every OHM transaction fee goes to Ox server nodes as
//!   `LockedReward` outputs.
//! - The remainder goes to the OHM treasury.
//!
//! An OHM's Ox treasury is held as a real locked Ox UTXO (kind `OhmTreasury`) owned by the
//! maintainer, so deposits, transfers and fee settlements conserve the Ox supply invariant.

use crate::tx::{OvmAction, TxOutput};
use crate::{Amount, OutPoint, PublicKey, Sig};
use oxydome_crypto::{encode, hash_value, merkle_root, verify, Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OHM_POLICY_VERSION: u8 = 1;
pub const OHM_POLICY_MAGIC: &[u8; 6] = b"OHMPOL";
pub const MAX_OHM_NAME_BYTES: usize = 64;
pub const MAX_OHM_REASON_BYTES: usize = 256;
/// Share of every OHM transaction fee paid to Ox server nodes, in basis points (`4000` = 40%).
pub const OHM_SERVER_FEE_BPS: u32 = 4000;
/// Maximum number of inputs or outputs in a single OHM transaction.
pub const MAX_OHM_TX_ITEMS: usize = 4096;
/// Maximum number of transactions allowed in a single OHM block.
pub const MAX_OHM_BLOCK_TXS: usize = 4096;

/// Context for OHM chain continuity, anchored to Ox blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmContext {
    /// OHM-specific block height
    pub ohm_height: u64,
    /// Hash of previous OHM block
    pub ohm_prev_hash: Hash,
    /// Block timestamp
    pub ohm_timestamp: u64,
    /// OHM state root (commitment to OHM UTXO set)
    pub ohm_state_root: Hash,
}

impl OhmContext {
    /// Validates this context is well-formed. Height 0 is the (un-anchored) genesis state and is
    /// not a valid anchor context, so `ohm_height` must be positive and the committed root and
    /// previous hash must be non-zero.
    pub fn is_valid(&self) -> bool {
        self.ohm_height > 0
            && !self.ohm_prev_hash.is_zero()
            && !self.ohm_state_root.is_zero()
    }
}

/// OHM policy parameters, set at creation and updatable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmPolicy {
    /// OHM policy version
    pub version: u8,
    /// OHM maintainer (can update/terminate)
    pub maintainer: PublicKey,
    /// Human-readable OHM name
    pub name: String,
    /// Genesis supply for OHM
    pub genesis_supply: Amount,
    /// Block window for value index computation
    pub block_window: u64,
}

impl OhmPolicy {
    /// Verifies the policy is well-formed.
    pub fn verify(&self) -> Result<(), String> {
        if self.version != OHM_POLICY_VERSION {
            return Err("invalid OHM policy version".into());
        }
        if self.name.is_empty() || self.name.len() > MAX_OHM_NAME_BYTES {
            return Err("OHM name must be 1-64 bytes".into());
        }
        if !self.name.is_ascii() {
            return Err("OHM name must be ASCII".into());
        }
        if self.genesis_supply == 0 {
            return Err("OHM genesis supply must be positive".into());
        }
        if self.block_window == 0 {
            return Err("OHM block_window must be positive".into());
        }
        Ok(())
    }

    /// Encodes the policy with magic header for canonical encoding.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.verify()?;
        let payload = encode(self);
        let mut bytes = Vec::with_capacity(OHM_POLICY_MAGIC.len() + payload.len());
        bytes.extend_from_slice(OHM_POLICY_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes a policy from bytes, verifying the magic and canonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() <= OHM_POLICY_MAGIC.len() || !bytes.starts_with(OHM_POLICY_MAGIC) {
            return Err("invalid OHM policy encoding".into());
        }
        let policy: Self =
            bincode::deserialize(&bytes[OHM_POLICY_MAGIC.len()..]).map_err(|e| e.to_string())?;
        policy.verify()?;
        if policy.encode()? != bytes {
            return Err("OHM policy encoding is not canonical".into());
        }
        Ok(policy)
    }
}

/// OHM state - the running, Ox-committed view of a single OHM.
///
/// The complete private UTXO set is re-derived by server nodes; this struct commits only the
/// anchor metadata (plus the deterministic genesis output set) into the Ox state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmState {
    /// Policy governing this OHM
    pub policy: OhmPolicy,
    /// Current OHM block height
    pub current_height: u64,
    /// Hash of the most recently anchored OHM block (or the genesis hash at height 0)
    pub block_hash: Hash,
    /// Anchored OHM state root (the private UTXO commitment)
    pub state_root: Hash,
    /// Total OHM supply (sum of UTXOs)
    pub supply: Amount,
    /// OHM-local UTXOs (the deterministic genesis set; the live set is re-derived by servers)
    pub utxos: BTreeMap<Hash, OhmUtxoEntry>,
    /// Ox held in the OHM treasury (mirrors the locked `OhmTreasury` UTXO on the main ledger)
    pub treasury_ox: Amount,
    /// Genesis supply for reference
    pub genesis_supply: Amount,
    /// Cumulative Ox fees paid to the Ox server nodes by this OHM
    pub fees_paid: Amount,
}

/// An OHM UTXO entry, mirroring UtxoEntry but for OHM-local outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmUtxoEntry {
    /// The outpoint this UTXO represents
    pub outpoint: OutPoint,
    /// The OHM output
    pub output: OhmOutput,
    /// Height at which this UTXO was created
    pub created_height: u64,
}

impl OhmUtxoEntry {
    /// Creates a new OHM UTXO entry.
    pub fn new(outpoint: OutPoint, output: OhmOutput, created_height: u64) -> Self {
        Self {
            outpoint,
            output,
            created_height,
        }
    }

    /// Returns the key used to index this UTXO in the OHM state.
    pub fn key(&self) -> Hash {
        hash_value(&self.outpoint)
    }
}

/// An OHM output - a spendable amount for an OHM recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmOutput {
    /// Amount of OHM-denominated Ox in this output
    pub amount: Amount,
    /// Recipient's public key
    pub recipient: PublicKey,
}

/// The private state of an OVM contract hosted inside a single OHM.
///
/// A contract body never leaves the tenant: only the resulting OHM state root (which commits the
/// whole contract map, including storage) is anchored into Ox via [`OhmAction::Update`]. Server
/// nodes re-execute OHM blocks to re-derive this map and reject anchors that do not match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmContract {
    /// Encoded OVM program (`Program`) or contract artifact (`ContractArtifact`).
    pub code: Vec<u8>,
    /// Persistent OVM storage.
    pub storage: BTreeMap<u64, u64>,
}

/// An OHM transaction input: a reference to a previous OHM output plus the owner's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmInput {
    pub prev_out: OutPoint,
    pub owner: PublicKey,
    pub signature: Sig,
}

/// A private, value-conserving OHM transaction.
///
/// Conservation requires `sum(input values) == sum(output amounts) + fee`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmTransaction {
    pub inputs: Vec<OhmInput>,
    pub outputs: Vec<OhmOutput>,
    pub fee: Amount,
    /// Optional OVM action executed privately inside the OHM (contract deploy or call).
    #[serde(default)]
    pub ovm_action: Option<OvmAction>,
}

/// Canonical signature payload for OHM transaction inputs (excludes signatures).
#[derive(Serialize)]
struct OhmTxSigningData<'a> {
    prev_outs: Vec<OutPoint>,
    owners: Vec<PublicKey>,
    outputs: &'a [OhmOutput],
    fee: Amount,
    ovm_action: &'a Option<OvmAction>,
    input_index: u32,
}

impl OhmTransaction {
    /// The canonical signing hash for `input_index`.
    pub fn signing_hash(&self, input_index: usize) -> Hash {
        let data = OhmTxSigningData {
            prev_outs: self.inputs.iter().map(|i| i.prev_out).collect(),
            owners: self.inputs.iter().map(|i| i.owner).collect(),
            outputs: &self.outputs,
            fee: self.fee,
            ovm_action: &self.ovm_action,
            input_index: input_index as u32,
        };
        hash_value(&data)
    }

    /// The transaction id (SHA3-512 over the whole transaction).
    pub fn txid(&self) -> Hash {
        hash_value(self)
    }

    /// Builds an OHM transaction with no OVM action.
    pub fn new(inputs: Vec<OhmInput>, outputs: Vec<OhmOutput>, fee: Amount) -> Self {
        Self {
            inputs,
            outputs,
            fee,
            ovm_action: None,
        }
    }

    /// Attaches a private OVM action (contract deploy or call) to this transaction.
    pub fn with_ovm_action(mut self, action: OvmAction) -> Self {
        self.ovm_action = Some(action);
        self
    }

    /// Signs every input owned by `key`.
    pub fn sign_owned_inputs(&mut self, key: &oxydome_crypto::KeyPair) {
        let owner = key.public();
        for i in 0..self.inputs.len() {
            if self.inputs[i].owner == owner {
                let msg = self.signing_hash(i);
                self.inputs[i].signature = key.sign(&msg.0);
            }
        }
    }

    pub fn output_total(&self) -> Result<Amount, String> {
        let mut total: Amount = 0;
        for out in &self.outputs {
            total = total
                .checked_add(out.amount)
                .ok_or_else(|| "OHM output total overflows".to_string())?;
        }
        Ok(total)
    }

    /// Stateless validation: shape, bounds, duplicate inputs, non-zero values and signatures.
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.inputs.is_empty() {
            return Err("OHM transaction has no inputs".into());
        }
        if self.outputs.is_empty() {
            return Err("OHM transaction has no outputs".into());
        }
        if self.inputs.len() > MAX_OHM_TX_ITEMS || self.outputs.len() > MAX_OHM_TX_ITEMS {
            return Err("OHM transaction exceeds the item limit".into());
        }
        for out in &self.outputs {
            if out.amount == 0 {
                return Err("OHM transaction output amount is zero".into());
            }
        }
        if let Some(action) = &self.ovm_action {
            if action.gas_limit() == 0 {
                return Err("OHM OVM action has a zero gas limit".into());
            }
            match action {
                OvmAction::Deploy { code, .. } | OvmAction::DeployContract { artifact: code, .. } => {
                    if code.len() > oxydome_ovm::MAX_CONTRACT_ARTIFACT_BYTES {
                        return Err("OHM OVM deploy exceeds the code size limit".into());
                    }
                }
                OvmAction::Call { arguments, .. } => {
                    if arguments.len() > oxydome_ovm::MAX_ARGUMENTS {
                        return Err("OHM OVM call exceeds the argument limit".into());
                    }
                }
                OvmAction::CallContract {
                    entry_point,
                    arguments,
                    ..
                } => {
                    if entry_point.len() > oxydome_ovm::MAX_FUNCTION_NAME_BYTES
                        || arguments.len() + oxydome_ovm::AUTHORITY_WORD_COUNT
                            > oxydome_ovm::MAX_ARGUMENTS
                    {
                        return Err("OHM OVM contract call is out of bounds".into());
                    }
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if !seen.insert(input.prev_out) {
                return Err(format!("duplicate OHM input {:?}", input.prev_out));
            }
        }
        for (idx, input) in self.inputs.iter().enumerate() {
            let msg = self.signing_hash(idx);
            if !verify(&input.owner, &msg.0, &input.signature) {
                return Err(format!("OHM input {idx} has an invalid signature"));
            }
        }
        Ok(())
    }
}

/// An OHM block header. Its hash identifies the block and is anchored into Ox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmBlockHeader {
    /// OHM this block belongs to
    pub ohm_id: Hash,
    /// OHM height (the genesis state is height 0; the first block is height 1)
    pub height: u64,
    /// Hash of the previous OHM block (or the OHM genesis hash at height 1)
    pub prev_hash: Hash,
    /// Block timestamp
    pub timestamp: u64,
    /// Merkle root over the block's transaction ids
    pub tx_root: Hash,
    /// Resulting OHM state root after applying this block
    pub state_root: Hash,
    /// Total OHM fees collected by this block
    pub fee_total: Amount,
    /// The maintainer that produced (and signed) this block
    pub maintainer: PublicKey,
}

impl OhmBlockHeader {
    pub fn hash(&self) -> Hash {
        hash_value(self)
    }

    /// Projects the header into the continuity context anchored on Ox.
    pub fn context(&self) -> OhmContext {
        OhmContext {
            ohm_height: self.height,
            ohm_prev_hash: self.prev_hash,
            ohm_timestamp: self.timestamp,
            ohm_state_root: self.state_root,
        }
    }
}

/// A private OHM block: an ordered batch of OHM transactions. Only its header is anchored in Ox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmBlock {
    pub header: OhmBlockHeader,
    pub transactions: Vec<OhmTransaction>,
    /// Maintainer signature over `header.hash()`. Filled in by [`OhmBlock::sign`].
    pub signature: Sig,
}

impl OhmBlock {
    /// Builds an unsigned block whose `tx_root` is derived from its transactions.
    pub fn new_unsigned(
        ohm_id: Hash,
        height: u64,
        prev_hash: Hash,
        timestamp: u64,
        state_root: Hash,
        maintainer: PublicKey,
        transactions: Vec<OhmTransaction>,
    ) -> Self {
        let tx_root = Self::transactions_root(&transactions);
        let fee_total = transactions.iter().map(|tx| tx.fee).sum();
        Self {
            header: OhmBlockHeader {
                ohm_id,
                height,
                prev_hash,
                timestamp,
                tx_root,
                state_root,
                fee_total,
                maintainer,
            },
            transactions,
            signature: Sig([0u8; 64]),
        }
    }

    pub fn transactions_root(transactions: &[OhmTransaction]) -> Hash {
        let leaves: Vec<Hash> = transactions.iter().map(OhmTransaction::txid).collect();
        merkle_root(&leaves)
    }

    /// The block hash (hash of the header).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Recomputes the transaction root from the block body.
    pub fn tx_root(&self) -> Hash {
        Self::transactions_root(&self.transactions)
    }

    /// Signs the block header with the maintainer key.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.header.maintainer = key.public();
        self.signature = key.sign(&self.header.hash().0);
    }

    /// Verifies the maintainer signature over the header.
    pub fn is_maintainer_signed(&self) -> bool {
        verify(&self.header.maintainer, &self.header.hash().0, &self.signature)
    }

    /// The continuity context for this block.
    pub fn context(&self) -> OhmContext {
        self.header.context()
    }
}

/// OHM operations - actions that modify OHM state on the Ox chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OhmAction {
    /// Creates a new OHM with initial genesis outputs
    Create {
        /// Encoded OHM policy
        policy_bytes: Vec<u8>,
        /// Initial OHM outputs
        genesis_outputs: Vec<OhmOutput>,
    },
    /// Anchors a private OHM block into the Ox chain and settles its fees.
    Update {
        /// OHM ID to update
        ohm_id: Hash,
        /// New OHM context (height / prev hash / timestamp / state root)
        context: OhmContext,
        /// Hash of the anchored OHM block (used by server nodes to fetch the body)
        block_hash: Hash,
        /// Total OHM fees settled by this anchor, split automatically 40% servers / 60% treasury
        fee_total: Amount,
    },
    /// Terminates an OHM (finalizes it) and returns its treasury to the maintainer.
    Terminate {
        /// OHM ID to terminate
        ohm_id: Hash,
        /// Reason for termination
        reason: String,
    },
    /// Transfers Ox from the OHM treasury to an Ox recipient.
    Transfer {
        /// OHM ID
        ohm_id: Hash,
        /// Recipient on the Ox chain
        recipient: PublicKey,
        /// Amount to transfer
        amount: Amount,
    },
    /// Deposits Ox from the Ox chain into the OHM treasury.
    TreasuryDeposit {
        /// OHM ID
        ohm_id: Hash,
        /// Source UTXO on the Ox chain
        source: OutPoint,
        /// Amount to deposit
        amount: Amount,
    },
}

/// OHM operation wrapper with signature, matching the pattern of DaoOperation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmOperation {
    /// Actor (signer) of this operation
    pub actor: PublicKey,
    /// The actual OHM action
    pub action: OhmAction,
    /// Signature over the operation
    pub signature: Sig,
}

impl OhmOperation {
    /// Creates an unsigned OHM operation.
    pub fn new_unsigned(actor: PublicKey, action: OhmAction) -> Self {
        Self {
            actor,
            action,
            signature: Sig([0u8; 64]),
        }
    }

    /// Computes the signing hash for this operation.
    pub fn signing_hash(&self) -> Hash {
        let data = OhmSigningData {
            actor: self.actor,
            action: &self.action,
        };
        hash_value(&data)
    }

    /// Signs this operation with the actor's key.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.actor = key.public();
        self.signature = key.sign(&self.signing_hash().0);
    }

    /// Verifies the operation is valid (signature + shape).
    pub fn is_valid(&self) -> bool {
        self.is_signature_valid() && self.action.is_valid_shape(&self.actor)
    }

    /// Verifies only the signature.
    pub fn is_signature_valid(&self) -> bool {
        verify(&self.actor, &self.signing_hash().0, &self.signature)
    }

    /// Computes the ID of this OHM operation.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }

    /// For Create operations, computes the OHM ID.
    pub fn created_ohm_id(&self) -> Option<Hash> {
        match &self.action {
            OhmAction::Create { policy_bytes, .. } => {
                Some(hash_value(&("oxydome-ohm-id-v1", self.id(), policy_bytes)))
            }
            _ => None,
        }
    }
}

/// Data structure for signing OHM operations.
#[derive(Serialize)]
struct OhmSigningData<'a> {
    actor: PublicKey,
    action: &'a OhmAction,
}

impl OhmAction {
    /// Validates the action shape (independent of signature).
    pub fn is_valid_shape(&self, actor: &PublicKey) -> bool {
        match self {
            OhmAction::Create {
                policy_bytes,
                genesis_outputs,
            } => {
                if let Ok(policy) = OhmPolicy::decode(policy_bytes) {
                    if &policy.maintainer != actor {
                        return false;
                    }
                    if genesis_outputs.is_empty() {
                        return false;
                    }
                    let mut total: Amount = 0;
                    for output in genesis_outputs {
                        if output.amount == 0 {
                            return false;
                        }
                        total = match total.checked_add(output.amount) {
                            Some(total) => total,
                            None => return false,
                        };
                    }
                    total == policy.genesis_supply
                } else {
                    false
                }
            }
            OhmAction::Update {
                context,
                block_hash,
                fee_total,
                ..
            } => context.is_valid() && !block_hash.is_zero() && *fee_total > 0,
            OhmAction::Terminate { reason, .. } => reason.len() <= MAX_OHM_REASON_BYTES,
            OhmAction::Transfer { amount, .. } => *amount > 0,
            OhmAction::TreasuryDeposit { amount, .. } => *amount > 0,
        }
    }
}

/// The deterministic OHM genesis hash: the predecessor of the first OHM block.
pub fn ohm_genesis_hash(ohm_id: &Hash) -> Hash {
    hash_value(&("oxydome-ohm-genesis-v1", ohm_id))
}

/// Deterministic commitment to an OHM UTXO set alone.
pub fn ohm_utxo_root(utxos: &BTreeMap<Hash, OhmUtxoEntry>) -> Hash {
    hash_value(&("oxydome-ohm-utxo-root-v1", utxos))
}

/// Deterministic commitment to the full private OHM state: its UTXO set together with every
/// OVM contract it hosts. This is the value anchored into Ox as the OHM state root.
pub fn ohm_state_root(
    utxos: &BTreeMap<Hash, OhmUtxoEntry>,
    contracts: &BTreeMap<Hash, OhmContract>,
) -> Hash {
    hash_value(&(
        "oxydome-ohm-state-root-v1",
        ohm_utxo_root(utxos),
        contracts,
    ))
}

/// The well-known outpoint holding an OHM's locked Ox treasury on the main ledger.
pub fn ohm_treasury_outpoint(ohm_id: &Hash) -> OutPoint {
    OutPoint::new(hash_value(&("oxydome-ohm-treasury-v1", ohm_id)), 0)
}

/// Computes the automatic fee split for OHM transactions.
///
/// Returns `(server_share, ohm_share)` where `server_share` is
/// [`OHM_SERVER_FEE_BPS`] of the fees (paid to Ox server nodes as `LockedReward`) and
/// `ohm_share` remains with the OHM treasury.
pub fn compute_ohm_fee_split(total_fees: Amount) -> (Amount, Amount) {
    let server_share = total_fees.saturating_mul(OHM_SERVER_FEE_BPS as u128) / 10_000;
    let ohm_share = total_fees.saturating_sub(server_share);
    (server_share, ohm_share)
}

/// Builds the `LockedReward` outputs for the server share of an OHM fee pool.
///
/// The server share is participation weighted with a proposer bonus, mirroring ordinary block
/// reward weighting. Returns an empty vector when the share or the node set is empty.
pub fn build_ohm_server_outputs(
    total_fees: Amount,
    server_nodes: &[PublicKey],
    proposer: &PublicKey,
) -> Vec<TxOutput> {
    let (server_share, _) = compute_ohm_fee_split(total_fees);
    if server_share == 0 || server_nodes.is_empty() {
        return Vec::new();
    }
    let weights: Vec<(PublicKey, u128)> = server_nodes
        .iter()
        .map(|node| {
            if node == proposer {
                (*node, 3u128)
            } else {
                (*node, 1u128)
            }
        })
        .collect();
    split_locked_rewards(server_share, &weights)
}

/// Splits `pool` among `recipients` weighted by the second tuple element, paying the rounding
/// remainder to the first recipient. Zero-weight pools split equally. Every output is a
/// `LockedReward` so the earnings remain subject to the withdrawal process.
fn split_locked_rewards(pool: Amount, recipients: &[(PublicKey, u128)]) -> Vec<TxOutput> {
    if pool == 0 || recipients.is_empty() {
        return Vec::new();
    }
    let total_weight: u128 = recipients.iter().map(|(_, w)| *w).sum();
    let mut outputs = Vec::new();
    if total_weight == 0 {
        let base = pool / recipients.len() as u128;
        for (i, (key, _)) in recipients.iter().enumerate() {
            let amount = if i == 0 {
                pool - base * (recipients.len() as u128 - 1)
            } else {
                base
            };
            if amount > 0 {
                outputs.push(TxOutput::locked_reward(amount, *key));
            }
        }
        return outputs;
    }
    for (i, (key, weight)) in recipients.iter().enumerate() {
        let amount = if i == 0 {
            let rest: Amount = recipients
                .iter()
                .skip(1)
                .map(|(_, w)| pool.saturating_mul(*w) / total_weight)
                .fold(0u128, |a, b| a.saturating_add(b));
            pool.saturating_sub(rest)
        } else {
            pool.saturating_mul(*weight) / total_weight
        };
        if amount > 0 {
            outputs.push(TxOutput::locked_reward(amount, *key));
        }
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;

    fn sample_policy(key: PublicKey, supply: Amount) -> OhmPolicy {
        OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: key,
            name: "TestOHM".to_string(),
            genesis_supply: supply,
            block_window: 100,
        }
    }

    #[test]
    fn ohm_policy_roundtrip() {
        let key = PublicKey::from([1u8; 32]);
        let policy = sample_policy(key, 1_000_000);
        let encoded = policy.encode().unwrap();
        let decoded = OhmPolicy::decode(&encoded).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn ohm_policy_invalid_version() {
        let key = PublicKey::from([1u8; 32]);
        let policy = OhmPolicy {
            version: 99,
            ..sample_policy(key, 1_000_000)
        };
        assert!(policy.encode().is_err());
    }

    #[test]
    fn ohm_operation_signs_and_verifies() {
        let key = KeyPair::from_seed(&[42u8; 32]);
        let policy_bytes = sample_policy(key.public(), 100).encode().unwrap();
        let mut op = OhmOperation::new_unsigned(
            key.public(),
            OhmAction::Create {
                policy_bytes,
                genesis_outputs: vec![OhmOutput {
                    amount: 100,
                    recipient: key.public(),
                }],
            },
        );
        op.sign(&key);
        assert!(op.is_valid());
    }

    #[test]
    fn ohm_operation_tampered_fails() {
        let key = KeyPair::from_seed(&[42u8; 32]);
        let policy_bytes = sample_policy(key.public(), 100).encode().unwrap();
        let mut op = OhmOperation::new_unsigned(
            key.public(),
            OhmAction::Create {
                policy_bytes,
                genesis_outputs: vec![OhmOutput {
                    amount: 100,
                    recipient: key.public(),
                }],
            },
        );
        op.sign(&key);
        if let OhmAction::Create { policy_bytes, .. } = &mut op.action {
            policy_bytes[0] = 99;
        }
        assert!(!op.is_valid());
    }

    #[test]
    fn ohm_fee_split_is_forty_percent() {
        let (server_share, ohm_share) = compute_ohm_fee_split(1000);
        assert_eq!(server_share, 400);
        assert_eq!(ohm_share, 600);
    }

    #[test]
    fn ohm_server_fee_bps_governs_the_split() {
        // `OHM_SERVER_FEE_BPS` is the single source of truth for the server/Ox share of OHM fees.
        assert_eq!(OHM_SERVER_FEE_BPS, 4_000);
        assert_eq!(OHM_SERVER_FEE_BPS as u128 * 100 / 10_000, 40);

        // For every total the split conserves value and the server share is exactly
        // `floor(total * OHM_SERVER_FEE_BPS / 10_000)`; the remainder belongs to the treasury.
        for total in [
            0u128, 1, 2, 3, 7, 99, 100, 101, 999, 1_000, 4_000, 12_345, 999_999, 1_000_000,
        ] {
            let (server_share, ohm_share) = compute_ohm_fee_split(total);
            assert_eq!(server_share, total * OHM_SERVER_FEE_BPS as u128 / 10_000);
            assert_eq!(server_share + ohm_share, total);
            assert!(server_share <= total);
        }
    }

    #[test]
    fn ohm_server_outputs_sum_to_server_share() {
        let nodes: Vec<PublicKey> = (1u8..=4).map(|i| PublicKey::from([i; 32])).collect();
        let outputs = build_ohm_server_outputs(1000, &nodes, &nodes[0]);
        let total: Amount = outputs.iter().map(|o| o.amount).sum();
        assert_eq!(total, 400);
        assert!(outputs.iter().all(|o| o.kind.is_locked_reward()));
        // Proposer (index 0) receives the largest share.
        assert_eq!(outputs[0].recipient, nodes[0]);
        assert!(outputs[0].amount > outputs[1].amount);
    }

    #[test]
    fn ohm_policy_name_bounds() {
        let key = PublicKey::from([1u8; 32]);
        let empty = sample_policy(key, 1_000_000);
        let empty = OhmPolicy {
            name: String::new(),
            ..empty
        };
        assert!(empty.encode().is_err());
        let too_long = OhmPolicy {
            name: "x".repeat(MAX_OHM_NAME_BYTES + 1),
            ..sample_policy(key, 1_000_000)
        };
        assert!(too_long.encode().is_err());
        assert!(sample_policy(key, 1_000_000).encode().is_ok());
    }

    #[test]
    fn ohm_operation_created_ohm_id() {
        let key = KeyPair::from_seed(&[42u8; 32]);
        let policy_bytes = sample_policy(key.public(), 1_000_000).encode().unwrap();
        let mut op = OhmOperation::new_unsigned(
            key.public(),
            OhmAction::Create {
                policy_bytes,
                genesis_outputs: vec![OhmOutput {
                    amount: 1_000_000,
                    recipient: key.public(),
                }],
            },
        );
        op.sign(&key);
        assert!(!op.created_ohm_id().unwrap().is_zero());
    }

    #[test]
    fn ohm_transaction_signs_and_tamper_fails() {
        let key = KeyPair::from_seed(&[7u8; 32]);
        let owner = key.public();
        let mut tx = OhmTransaction {
            inputs: vec![OhmInput {
                prev_out: OutPoint::new(Hash::zero(), 0),
                owner,
                signature: Sig([0u8; 64]),
            }],
            outputs: vec![OhmOutput {
                amount: 90,
                recipient: owner,
            }],
            fee: 10,
            ovm_action: None,
        };
        tx.sign_owned_inputs(&key);
        assert!(tx.validate_structure().is_ok());
        tx.outputs[0].amount = 91;
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn ohm_block_round_trip_and_signature() {
        let key = KeyPair::from_seed(&[9u8; 32]);
        let ohm_id = ohm_genesis_hash(&Hash::zero());
        let mut block = OhmBlock::new_unsigned(
            ohm_id,
            1,
            ohm_id,
            123,
            Hash::from([5u8; 64]),
            key.public(),
            Vec::new(),
        );
        block.sign(&key);
        assert!(block.is_maintainer_signed());
        assert_eq!(block.hash(), block.header.hash());
        assert_eq!(block.tx_root(), Hash::zero());
    }
}
