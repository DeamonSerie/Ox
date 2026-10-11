//! The node-side OHM ledger: private UTXO state re-derived from anchored [`OhmBlock`]s.

use crate::{
    ohm_cross_msg_id, ohm_genesis_hash, ohm_state_root_full, Amount, CrossBurnCall,
    CrossTransferCall, Hash, InboundReceipt, OhmBlock, OhmContract, OhmInput, OhmOutput,
    OhmTransaction, OhmUtxoEntry, OutboundMessage, OutPoint, PublicKey, TransferPayload,
    reply_arguments,
};
use oxydome_core::{CrossRecvCall, CrossSendCall, OvmAction, OvmFailureCode};
use oxydome_crypto::KeyPair;
use oxydome_ovm::{CrossHost, ReceiptView, StagedCrossCall};
use std::collections::BTreeMap;

/// The result of simulating an OHM-hosted contract call (never mutates the ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OhmCallOutcome {
    pub failure: Option<OvmFailureCode>,
    pub gas_used: u64,
    pub return_value: Option<u64>,
    pub logs: Vec<oxydome_ovm::Log>,
}

/// The materialised result of executing a cross-chain target entry point.
struct ExecuteOutcome {
    failure: Option<OvmFailureCode>,
    return_value: Option<u64>,
    storage: Option<BTreeMap<u64, u64>>,
}

/// Flattens the in-progress cross receipts into the host view contracts observe via `ReadReply`.
fn receipt_view(inbox: &BTreeMap<Hash, InboundReceipt>) -> BTreeMap<Hash, ReceiptView> {
    inbox
        .iter()
        .map(|(id, receipt)| {
            (
                *id,
                ReceiptView {
                    success: receipt.failure.is_none(),
                    value: receipt.return_value.unwrap_or(0),
                },
            )
        })
        .collect()
}

/// Enqueues the staged cross calls produced by a contract execution into this ledger's outbox,
/// preserving execution order and using the invocant's caller as the message caller. Staged
/// calls never request replies in v1.
fn enqueue_staged_calls(
    outbox: &mut BTreeMap<Hash, OutboundMessage>,
    outbox_seq: &mut u64,
    origin_ohm: &Hash,
    origin_height: u64,
    caller: PublicKey,
    staged: &[StagedCrossCall],
) -> Result<(), OhmError> {
    for call in staged {
        if &call.target_ohm == origin_ohm {
            return Err(OhmError::CrossChain(
                "a contract cannot send a cross message to its own OHM".into(),
            ));
        }
        let seq = *outbox_seq;
        *outbox_seq = outbox_seq.checked_add(1).ok_or(OhmError::Overflow)?;
        let msg_id = ohm_cross_msg_id(origin_ohm, origin_height, seq);
        outbox.insert(
            msg_id,
            OutboundMessage {
                msg_id,
                source_ohm: *origin_ohm,
                source_height: origin_height,
                seq,
                caller,
                target_ohm: call.target_ohm,
                target_contract: call.target_contract,
                entry_selector: call.entry_selector,
                arguments: call.arguments.clone(),
                gas_limit: call.gas_limit,
                want_reply: false,
                reply_contract: None,
                reply_entry_selector: None,
                reply_to_msg_id: None,
                transfer: None,
            },
        );
    }
    Ok(())
}

/// Maps an OVM execution error to its stable, consensus-visible failure code.
fn failure_code(error: oxydome_ovm::VmError) -> OvmFailureCode {
    use oxydome_ovm::VmError;
    match error {
        VmError::Reverted => OvmFailureCode::Reverted,
        VmError::OutOfGas => OvmFailureCode::OutOfGas,
        VmError::ArithmeticOverflow => OvmFailureCode::ArithmeticOverflow,
        VmError::DivisionByZero => OvmFailureCode::DivisionByZero,
        VmError::ArgumentCount => OvmFailureCode::ArgumentCount,
        VmError::MissingReturn => OvmFailureCode::MissingReturn,
        VmError::StorageLimitExceeded => OvmFailureCode::StorageLimitExceeded,
        VmError::StackUnderflow => OvmFailureCode::StackUnderflow,
        VmError::StackOverflow => OvmFailureCode::StackOverflow,
        VmError::InvalidLocal => OvmFailureCode::InvalidLocal,
        VmError::InvalidBytecode | VmError::ProgramTooLarge | VmError::InvalidProgram => {
            OvmFailureCode::InvalidProgram
        }
    }
}

/// Errors produced while validating or applying OHM blocks and transactions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OhmError {
    #[error("OHM block belongs to a different OHM")]
    WrongOhm,
    #[error("OHM block height {0} does not follow {1}")]
    BadHeight(u64, u64),
    #[error("OHM block does not link to the current head")]
    BadPrevHash,
    #[error("OHM block is not signed by the OHM maintainer")]
    BadMaintainer,
    #[error("OHM block transaction root does not match its body")]
    BadTxRoot,
    #[error("OHM block fee total {0} does not equal the summed transaction fees {1}")]
    BadFeeTotal(Amount, Amount),
    #[error("OHM block state root {0:?} does not match the computed root {1:?}")]
    BadStateRoot(Hash, Hash),
    #[error("OHM block has too many transactions")]
    TooManyTransactions,
    #[error("OHM transaction {0} invalid: {1}")]
    BadTransaction(usize, String),
    #[error("OHM input {0:?} does not exist or is already spent")]
    MissingInput(OutPoint),
    #[error("OHM input {0:?} owner does not match the referenced output")]
    InputOwnerMismatch(OutPoint),
    #[error("OHM transaction does not conserve value")]
    Conservation,
    #[error("OHM amount overflow")]
    Overflow,
    #[error("OHM amount underflow")]
    Underflow,
    #[error("OHM OVM action is invalid: {0}")]
    Ovm(String),
    #[error("OHM OVM deployment collides with an existing contract")]
    OvmContractCollision,
    #[error("OHM OVM contract limit reached")]
    OvmContractLimit,
    #[error("a cross-chain view is required to process inbound OHM messages")]
    CrossViewMissing,
    #[error("cross-chain message {0:?} is unknown (not in any committed source outbox)")]
    CrossMessageUnknown(Hash),
    #[error("cross-chain message {0:?} was already consumed")]
    CrossMessageDuplicate(Hash),
    #[error("cross-chain message {0:?} targets a different OHM")]
    CrossMessageWrongTarget(Hash),
    #[error("cross-chain message is invalid: {0}")]
    CrossChain(String),
    #[error("cross-chain transfer cannot target its own OHM")]
    TransferSelfTarget,
    #[error("cross-chain transfer amount exceeds the available balance")]
    TransferInsufficientBalance,
    #[error("cross-chain burn amount exceeds the minted balance")]
    BurnInsufficientBalance,
    #[error("cross-chain transfer has an invalid recipient")]
    TransferInvalidRecipient,
    #[error("cross-chain burn has an invalid source OHM")]
    BurnInvalidSource,
    #[error("cross-chain transfer output is already locked")]
    TransferAlreadyLocked,
    #[error("cross-chain unlock has no matching locked output")]
    UnlockNoMatch,
}

/// A read-only view over other OHMs' *committed* outboxes, used to verify and execute inbound
/// cross-chain messages during OHM ledger re-derivation.
///
/// It is built exclusively from ledgers that were finalized in a strictly earlier Ox block, so a
/// message is only consumable one full Ox block after its source block was anchored. Messages
/// enqueued by an OHM `Update` in the *same* Ox block are invisible here and are rejected with
/// [`OhmError::CrossMessageUnknown`], which keeps consumption pinned to finalized state.
#[derive(Debug, Clone, Default)]
pub struct CrossChainView {
    outboxes: BTreeMap<Hash, BTreeMap<Hash, OutboundMessage>>,
}

impl CrossChainView {
    /// An empty view (no inbound messages can be resolved).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the committed outbox view for `ohm_id`.
    pub fn insert(&mut self, ohm_id: Hash, outbox: BTreeMap<Hash, OutboundMessage>) {
        self.outboxes.insert(ohm_id, outbox);
    }

    /// Builds the view from a set of committed [`OhmLedger`]s.
    pub fn from_ledgers(ledgers: &BTreeMap<Hash, OhmLedger>) -> Self {
        let mut view = Self::new();
        for ledger in ledgers.values() {
            view.outboxes.insert(ledger.ohm_id, ledger.outbox.clone());
        }
        view
    }

    /// Resolves `msg_id` within `source_ohm`'s committed outbox.
    pub fn resolve(&self, source_ohm: &Hash, msg_id: &Hash) -> Option<&OutboundMessage> {
        self.outboxes.get(source_ohm)?.get(msg_id)
    }

    /// Finds `msg_id` across every outbox in the view.
    ///
    /// Message ids are globally unique (they commit their source OHM), so this returns at most
    /// one message. Its `target_ohm` field determines which OHM may consume it.
    pub fn find(&self, msg_id: &Hash) -> Option<&OutboundMessage> {
        self.outboxes
            .values()
            .find_map(|outbox| outbox.get(msg_id))
    }
}

/// The materialised result of applying a batch of OHM transactions.
struct LedgerDelta {
    utxos: BTreeMap<Hash, OhmUtxoEntry>,
    contracts: BTreeMap<Hash, OhmContract>,
    outbox: BTreeMap<Hash, OutboundMessage>,
    inbox: BTreeMap<Hash, InboundReceipt>,
    outbox_seq: u64,
    supply: Amount,
    fee_total: Amount,
    locked_total: Amount,
    minted: BTreeMap<Hash, Amount>,
}

/// A node's private view of a single OHM chain, re-derived from its blocks.
#[derive(Debug, Clone)]
pub struct OhmLedger {
    pub ohm_id: Hash,
    pub maintainer: PublicKey,
    pub genesis_supply: Amount,
    pub supply: Amount,
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
    pub utxos: BTreeMap<Hash, OhmUtxoEntry>,
    /// OVM contracts hosted privately by this OHM, keyed by contract id.
    pub contracts: BTreeMap<Hash, OhmContract>,
    /// Cross-OHM messages this OHM has enqueued, keyed by [`OutboundMessage::msg_id`].
    pub outbox: BTreeMap<Hash, OutboundMessage>,
    /// Cross-OHM messages this OHM has consumed, keyed by [`InboundReceipt::msg_id`].
    pub inbox: BTreeMap<Hash, InboundReceipt>,
    /// Next per-source sequence number for outbound messages.
    outbox_seq: u64,
    /// Total amount currently locked in the cross-chain bridge escrow.
    pub locked_total: Amount,
    /// Wrapped assets minted by cross-chain transfers, keyed by source OHM id.
    pub minted: BTreeMap<Hash, Amount>,
    blocks: Vec<OhmBlock>,
    roots: BTreeMap<u64, Hash>,
}

impl OhmLedger {
    /// Builds the height-0 ledger from an OHM's genesis outputs.
    ///
    /// `genesis_op_id` is the id of the creating [`crate::OhmOperation`]; genesis outpoints are
    /// derived exactly as the Ox state machine derives them so both views agree.
    pub fn from_genesis(
        ohm_id: Hash,
        maintainer: PublicKey,
        genesis_outputs: &[OhmOutput],
        genesis_op_id: Hash,
    ) -> Self {
        let mut utxos = BTreeMap::new();
        for (i, output) in genesis_outputs.iter().enumerate() {
            let outpoint = OutPoint::new(genesis_op_id, i as u32);
            let entry = OhmUtxoEntry::new(outpoint, output.clone(), 0);
            utxos.insert(entry.key(), entry);
        }
        let supply = genesis_outputs.iter().map(|o| o.amount).sum();
        let contracts = BTreeMap::new();
        let outbox = BTreeMap::new();
        let inbox = BTreeMap::new();
        let state_root = ohm_state_root_full(&utxos, &contracts, &outbox, &inbox);
        let block_hash = ohm_genesis_hash(&ohm_id);
        let mut roots = BTreeMap::new();
        roots.insert(0u64, state_root);
        Self {
            ohm_id,
            maintainer,
            genesis_supply: supply,
            supply,
            height: 0,
            block_hash,
            state_root,
            utxos,
            contracts,
            outbox,
            inbox,
            outbox_seq: 0,
            locked_total: 0,
            minted: BTreeMap::new(),
            blocks: Vec::new(),
            roots,
        }
    }

    /// The stored blocks, ordered by height.
    pub fn blocks(&self) -> &[OhmBlock] {
        &self.blocks
    }

    /// An outbound message by id, if this OHM has enqueued it.
    pub fn outbound(&self, msg_id: &Hash) -> Option<&OutboundMessage> {
        self.outbox.get(msg_id)
    }

    /// An inbound receipt by message id, if this OHM has consumed it.
    pub fn receipt(&self, msg_id: &Hash) -> Option<&InboundReceipt> {
        self.inbox.get(msg_id)
    }

    /// The state root committed at `height`, if the ledger has applied it.
    pub fn root_at(&self, height: u64) -> Option<Hash> {
        self.roots.get(&height).copied()
    }

    /// The block hash committed at `height` (the genesis hash at height 0).
    pub fn hash_at(&self, height: u64) -> Option<Hash> {
        if height == 0 {
            return Some(ohm_genesis_hash(&self.ohm_id));
        }
        self.blocks
            .iter()
            .find(|b| b.header.height == height)
            .map(OhmBlock::hash)
    }

    /// Verifies `block` against the current ledger without mutating it.
    ///
    /// Uses no cross-chain view, so a block containing inbound messages is rejected. See
    /// [`OhmLedger::verify_block_with`].
    pub fn verify_block(&self, block: &OhmBlock) -> Result<(), OhmError> {
        self.verify_block_with(block, &CrossChainView::new())
    }

    /// Verifies `block` against the current ledger, resolving inbound cross-chain messages
    /// against `view`, without mutating the ledger.
    pub fn verify_block_with(&self, block: &OhmBlock, view: &CrossChainView) -> Result<(), OhmError> {
        self.check_continuity(block)?;
        if block.transactions.len() > crate::MAX_OHM_BLOCK_TXS {
            return Err(OhmError::TooManyTransactions);
        }
        let delta = self.apply_transactions_with(&block.transactions, Some(view))?;
        if delta.fee_total != block.header.fee_total {
            return Err(OhmError::BadFeeTotal(
                block.header.fee_total,
                delta.fee_total,
            ));
        }
        let root = ohm_state_root_full(&delta.utxos, &delta.contracts, &delta.outbox, &delta.inbox);
        if root != block.header.state_root {
            return Err(OhmError::BadStateRoot(block.header.state_root, root));
        }
        Ok(())
    }

    /// Applies `block`, advancing the ledger. Fails (without mutation) on any inconsistency.
    ///
    /// Uses no cross-chain view; see [`OhmLedger::apply_block_with`].
    pub fn apply_block(&mut self, block: &OhmBlock) -> Result<(), OhmError> {
        self.apply_block_with(block, &CrossChainView::new())
    }

    /// Applies `block`, advancing the ledger, resolving inbound cross-chain messages against
    /// `view`. Fails (without mutation) on any inconsistency.
    pub fn apply_block_with(&mut self, block: &OhmBlock, view: &CrossChainView) -> Result<(), OhmError> {
        self.verify_block_with(block, view)?;
        let delta = self.apply_transactions_with(&block.transactions, Some(view))?;
        let root = ohm_state_root_full(&delta.utxos, &delta.contracts, &delta.outbox, &delta.inbox);
        self.utxos = delta.utxos;
        self.contracts = delta.contracts;
        self.outbox = delta.outbox;
        self.inbox = delta.inbox;
        self.outbox_seq = delta.outbox_seq;
        self.supply = delta.supply;
        self.locked_total = delta.locked_total;
        self.minted = delta.minted;
        self.height = block.header.height;
        self.block_hash = block.hash();
        self.state_root = root;
        self.roots.insert(self.height, root);
        self.blocks.push(block.clone());
        Ok(())
    }

    /// Builds, signs and verifies the next block from `transactions`.
    ///
    /// Uses no cross-chain view, so inbound messages cannot be built; see
    /// [`OhmLedger::build_block_with`].
    pub fn build_block(
        &self,
        transactions: Vec<OhmTransaction>,
        timestamp: u64,
        key: &KeyPair,
    ) -> Result<OhmBlock, OhmError> {
        self.build_block_with(transactions, timestamp, key, &CrossChainView::new())
    }

    /// Builds, signs and verifies the next block from `transactions`, resolving inbound
    /// cross-chain messages against `view`.
    pub fn build_block_with(
        &self,
        transactions: Vec<OhmTransaction>,
        timestamp: u64,
        key: &KeyPair,
        view: &CrossChainView,
    ) -> Result<OhmBlock, OhmError> {
        if key.public() != self.maintainer {
            return Err(OhmError::BadMaintainer);
        }
        if transactions.len() > crate::MAX_OHM_BLOCK_TXS {
            return Err(OhmError::TooManyTransactions);
        }
        let mut block = OhmBlock::new_unsigned(
            self.ohm_id,
            self.height + 1,
            self.block_hash,
            timestamp,
            Hash::zero(),
            self.maintainer,
            transactions,
        );
        // Compute the resulting root and commit it to the header before signing.
        let delta = self.apply_transactions_with(&block.transactions, Some(view))?;
        block.header.state_root = ohm_state_root_full(
            &delta.utxos,
            &delta.contracts,
            &delta.outbox,
            &delta.inbox,
        );
        block.header.fee_total = delta.fee_total;
        block.sign(key);
        self.verify_block_with(&block, view)?;
        Ok(block)
    }

    /// Builds an OHM transaction spending `inputs` into `outputs` with `fee`, then signs every
    /// input owned by `key`. Inputs are `(prev_out, owner)` pairs.
    pub fn build_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        key: &KeyPair,
    ) -> OhmTransaction {
        self.build_ovm_transaction(inputs, outputs, fee, None, key)
    }

    /// Builds and signs an OHM transaction with an optional private OVM action.
    ///
    /// The action is attached before signing so that both the signature and the transaction id
    /// commit to it (the transaction id is the OVM deployment id).
    pub fn build_ovm_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        ovm_action: Option<OvmAction>,
        key: &KeyPair,
    ) -> OhmTransaction {
        self.build_action_transaction(inputs, outputs, fee, ovm_action, None, None, key)
    }

    /// Builds and signs an OHM transaction with an outbound cross-chain message request.
    pub fn build_cross_send_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        call: CrossSendCall,
        key: &KeyPair,
    ) -> OhmTransaction {
        self.build_action_transaction(inputs, outputs, fee, None, Some(call), None, key)
    }

    /// Builds and signs an OHM transaction consuming an inbound cross-chain message.
    pub fn build_cross_recv_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        call: CrossRecvCall,
        key: &KeyPair,
    ) -> OhmTransaction {
        self.build_action_transaction(inputs, outputs, fee, None, None, Some(call), key)
    }

    /// Builds and signs an OHM transaction initiating a cross-chain asset transfer.
    pub fn build_cross_transfer_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        call: CrossTransferCall,
        key: &KeyPair,
    ) -> OhmTransaction {
        let mut tx = self.build_action_transaction(inputs, outputs, fee, None, None, None, key);
        tx.cross_transfer = Some(call);
        tx
    }

    /// Builds and signs an OHM transaction burning wrapped cross-chain assets.
    pub fn build_cross_burn_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        call: CrossBurnCall,
        key: &KeyPair,
    ) -> OhmTransaction {
        let mut tx = self.build_action_transaction(inputs, outputs, fee, None, None, None, key);
        tx.cross_burn = Some(call);
        tx
    }

    fn build_action_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        ovm_action: Option<OvmAction>,
        cross_send: Option<CrossSendCall>,
        cross_recv: Option<CrossRecvCall>,
        key: &KeyPair,
    ) -> OhmTransaction {
        let mut tx = OhmTransaction {
            inputs: inputs
                .into_iter()
                .map(|(prev_out, owner)| OhmInput {
                    prev_out,
                    owner,
                    signature: crate::Sig([0u8; 64]),
                })
                .collect(),
            outputs,
            fee,
            ovm_action,
            cross_send,
            cross_recv,
            cross_transfer: None,
            cross_burn: None,
        };
        tx.sign_owned_inputs(key);
        tx
    }

    /// Returns the private contract state for `contract_id`, if this OHM hosts it.
    pub fn contract(&self, contract_id: &Hash) -> Option<&OhmContract> {
        self.contracts.get(contract_id)
    }

    /// Simulates `CallContract` against the current private state without mutating the ledger.
    pub fn simulate_contract_call(
        &self,
        contract_id: &Hash,
        entry_point: &str,
        caller: PublicKey,
        arguments: &[u64],
        gas_limit: u64,
    ) -> Result<OhmCallOutcome, OhmError> {
        if gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::OutOfGas),
                gas_used: gas_limit,
                return_value: None,
                logs: Vec::new(),
            });
        }
        let intrinsic = oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
        let Some(contract) = self.contracts.get(contract_id) else {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::ContractNotFound),
                gas_used: oxydome_ovm::ACTION_INTRINSIC_GAS,
                return_value: None,
                logs: Vec::new(),
            });
        };
        let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let Some(function) = artifact.function(entry_point) else {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::FunctionNotFound),
                gas_used: intrinsic,
                return_value: None,
                logs: Vec::new(),
            });
        };
        if function.inputs.len() != arguments.len() {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::ArgumentCount),
                gas_used: intrinsic,
                return_value: None,
                logs: Vec::new(),
            });
        }
        let mut execution_arguments: Vec<u64> = caller
            .0
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte public-key chunk")))
            .collect();
        execution_arguments.extend(arguments.iter().copied());
        let program = oxydome_ovm::Program::decode(&function.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let execution_limit = gas_limit - intrinsic;
        match oxydome_ovm::execute(&program, &execution_arguments, &contract.storage, execution_limit)
        {
            Ok(execution) => Ok(OhmCallOutcome {
                failure: None,
                gas_used: intrinsic + execution.gas_used,
                return_value: execution.return_value,
                logs: execution.logs,
            }),
            Err(failure) => Ok(OhmCallOutcome {
                failure: Some(failure_code(failure.error)),
                gas_used: intrinsic.saturating_add(failure.gas_used).min(gas_limit),
                return_value: None,
                logs: Vec::new(),
            }),
        }
    }

    /// The sum of every unspent OHM output (must equal [`OhmLedger::supply`]).
    pub fn utxo_total(&self) -> Amount {
        self.utxos.values().map(|e| e.output.amount).sum()
    }

    fn check_continuity(&self, block: &OhmBlock) -> Result<(), OhmError> {
        if block.header.ohm_id != self.ohm_id {
            return Err(OhmError::WrongOhm);
        }
        if block.header.height != self.height + 1 {
            return Err(OhmError::BadHeight(block.header.height, self.height));
        }
        if block.header.prev_hash != self.block_hash {
            return Err(OhmError::BadPrevHash);
        }
        if block.header.maintainer != self.maintainer || !block.is_maintainer_signed() {
            return Err(OhmError::BadMaintainer);
        }
        if block.tx_root() != block.header.tx_root {
            return Err(OhmError::BadTxRoot);
        }
        Ok(())
    }

    fn apply_transactions_with(
        &self,
        transactions: &[OhmTransaction],
        view: Option<&CrossChainView>,
    ) -> Result<LedgerDelta, OhmError> {
        let mut utxos = self.utxos.clone();
        let mut contracts = self.contracts.clone();
        let mut outbox = self.outbox.clone();
        let mut inbox = self.inbox.clone();
        let mut outbox_seq = self.outbox_seq;
        let mut fee_total: Amount = 0;
        let mut locked_total = self.locked_total;
        let mut minted = self.minted.clone();
        for (index, tx) in transactions.iter().enumerate() {
            tx.validate_structure()
                .map_err(|e| OhmError::BadTransaction(index, e))?;
            let mut input_total: Amount = 0;
            for input in &tx.inputs {
                let key = input.prev_out.key();
                let entry = utxos
                    .get(&key)
                    .cloned()
                    .ok_or(OhmError::MissingInput(input.prev_out))?;
                if entry.output.recipient != input.owner {
                    return Err(OhmError::InputOwnerMismatch(input.prev_out));
                }
                if entry.output.lock {
                    return Err(OhmError::BadTransaction(
                        index,
                        "cannot spend a locked output".into(),
                    ));
                }
                input_total = input_total
                    .checked_add(entry.output.amount)
                    .ok_or(OhmError::Overflow)?;
                utxos.remove(&key);
            }
            let output_total = tx
                .output_total()
                .map_err(|e| OhmError::BadTransaction(index, e))?;
            if input_total != output_total.checked_add(tx.fee).ok_or(OhmError::Overflow)? {
                return Err(OhmError::Conservation);
            }
            let txid = tx.txid();
            if let Some(action) = &tx.ovm_action {
                Self::apply_ovm_action(
                    &mut contracts,
                    action,
                    txid,
                    index,
                    tx,
                    &self.ohm_id,
                    self.height + 1,
                    &inbox,
                    &mut outbox,
                    &mut outbox_seq,
                )?;
            }
            if let Some(call) = &tx.cross_send {
                self.apply_cross_send(call, tx, &mut outbox, &mut outbox_seq)?;
            }
            if let Some(call) = &tx.cross_recv {
                Self::apply_cross_recv(
                    &self.ohm_id,
                    self.height + 1,
                    call,
                    view,
                    &mut contracts,
                    &mut outbox,
                    &mut outbox_seq,
                    &mut inbox,
                    &mut minted,
                    &mut locked_total,
                    &mut utxos,
                )?;
            }
            if let Some(call) = &tx.cross_transfer {
                self.apply_cross_transfer(
                    call,
                    tx,
                    index,
                    &mut utxos,
                    &mut outbox,
                    &mut outbox_seq,
                    &mut locked_total,
                )?;
            }
            if let Some(call) = &tx.cross_burn {
                self.apply_cross_burn(
                    call,
                    tx,
                    index,
                    &mut utxos,
                    &mut outbox,
                    &mut outbox_seq,
                    &mut minted,
                )?;
            }
            for (out_index, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint::new(txid, out_index as u32);
                let entry = OhmUtxoEntry::new(outpoint, output.clone(), self.height + 1);
                utxos.insert(entry.key(), entry);
            }
            fee_total = fee_total.checked_add(tx.fee).ok_or(OhmError::Overflow)?;
        }
        let supply = self
            .supply
            .checked_sub(fee_total)
            .ok_or(OhmError::Underflow)?;
        Ok(LedgerDelta {
            utxos,
            contracts,
            outbox,
            inbox,
            outbox_seq,
            supply,
            fee_total,
            locked_total,
            minted,
        })
    }

    /// Enqueues an outbound cross-chain message into the ledger's outbox.
    fn apply_cross_send(
        &self,
        call: &CrossSendCall,
        tx: &OhmTransaction,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
    ) -> Result<(), OhmError> {
        if call.target_ohm == self.ohm_id {
            return Err(OhmError::CrossChain(
                "a message cannot target its own OHM".into(),
            ));
        }
        let seq = *outbox_seq;
        *outbox_seq = outbox_seq.checked_add(1).ok_or(OhmError::Overflow)?;
        let msg_id = ohm_cross_msg_id(&self.ohm_id, self.height + 1, seq);
        let message = OutboundMessage {
            msg_id,
            source_ohm: self.ohm_id,
            source_height: self.height + 1,
            seq,
            caller: tx.inputs[0].owner,
            target_ohm: call.target_ohm,
            target_contract: call.target_contract,
            entry_selector: oxydome_ovm::fn_selector(&call.entry_point),
            arguments: call.arguments.clone(),
            gas_limit: call.gas_limit,
            want_reply: call.want_reply,
            reply_contract: call.reply_contract,
            reply_entry_selector: call
                .reply_entry_point
                .as_ref()
                .map(|name| oxydome_ovm::fn_selector(name)),
            reply_to_msg_id: None,
            transfer: None,
        };
        outbox.insert(msg_id, message);
        Ok(())
    }

    /// Locks assets into the cross-chain bridge escrow and enqueues a transfer message.
    ///
    /// The transfer amount is moved from the transaction's inputs into a locked escrow output
    /// owned by the bridge module. An `OutboundMessage` with `transfer` metadata is enqueued
    /// so the target OHM can mint the wrapped asset.
    fn apply_cross_transfer(
        &self,
        call: &CrossTransferCall,
        tx: &OhmTransaction,
        tx_index: usize,
        utxos: &mut BTreeMap<Hash, OhmUtxoEntry>,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
        locked_total: &mut Amount,
    ) -> Result<(), OhmError> {
        if call.target_ohm == self.ohm_id {
            return Err(OhmError::TransferSelfTarget);
        }
        if call.amount == 0 {
            return Err(OhmError::BadTransaction(
                tx_index,
                "cross-chain transfer has a zero amount".into(),
            ));
        }
        let txid = tx.txid();
        let seq = *outbox_seq;
        *outbox_seq = outbox_seq.checked_add(1).ok_or(OhmError::Overflow)?;
        let msg_id = ohm_cross_msg_id(&self.ohm_id, self.height + 1, seq);
        let message = OutboundMessage {
            msg_id,
            source_ohm: self.ohm_id,
            source_height: self.height + 1,
            seq,
            caller: tx.inputs[0].owner,
            target_ohm: call.target_ohm,
            target_contract: Hash::zero(),
            entry_selector: 0,
            arguments: Vec::new(),
            gas_limit: 0,
            want_reply: false,
            reply_contract: None,
            reply_entry_selector: None,
            reply_to_msg_id: None,
            transfer: Some(TransferPayload {
                amount: call.amount,
                recipient: Some(call.recipient),
            }),
        };
        outbox.insert(msg_id, message);
        let escrow_outpoint = OutPoint::new(txid, 0);
        let escrow_key = escrow_outpoint.key();
        let escrow_output = OhmOutput {
            amount: call.amount,
            recipient: call.recipient,
            lock: true,
        };
        utxos.insert(
            escrow_key,
            OhmUtxoEntry::new(escrow_outpoint, escrow_output, self.height + 1),
        );
        *locked_total = locked_total
            .checked_add(call.amount)
            .ok_or(OhmError::Overflow)?;
        Ok(())
    }

    /// Burns wrapped assets and enqueues a burn message to unlock the source escrow.
    ///
    /// The burn amount is deducted from the minted balance for `source_ohm`. An `OutboundMessage`
    /// with `transfer` metadata is enqueued so the source OHM can unlock the original escrow.
    fn apply_cross_burn(
        &self,
        call: &CrossBurnCall,
        tx: &OhmTransaction,
        tx_index: usize,
        utxos: &mut BTreeMap<Hash, OhmUtxoEntry>,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
        minted: &mut BTreeMap<Hash, Amount>,
    ) -> Result<(), OhmError> {
        if call.source_ohm == self.ohm_id {
            return Err(OhmError::BurnInvalidSource);
        }
        if call.amount == 0 {
            return Err(OhmError::BadTransaction(
                tx_index,
                "cross-chain burn has a zero amount".into(),
            ));
        }
        let minted_amount = minted.get(&call.source_ohm).copied().unwrap_or(0);
        if call.amount > minted_amount {
            return Err(OhmError::BurnInsufficientBalance);
        }
        let txid = tx.txid();
        let seq = *outbox_seq;
        *outbox_seq = outbox_seq.checked_add(1).ok_or(OhmError::Overflow)?;
        let msg_id = ohm_cross_msg_id(&self.ohm_id, self.height + 1, seq);
        let message = OutboundMessage {
            msg_id,
            source_ohm: self.ohm_id,
            source_height: self.height + 1,
            seq,
            caller: tx.inputs[0].owner,
            target_ohm: call.source_ohm,
            target_contract: Hash::zero(),
            entry_selector: 0,
            arguments: Vec::new(),
            gas_limit: 0,
            want_reply: false,
            reply_contract: None,
            reply_entry_selector: None,
            reply_to_msg_id: None,
            transfer: Some(TransferPayload {
                amount: call.amount,
                recipient: None,
            }),
        };
        outbox.insert(msg_id, message);
        let new_minted = minted_amount - call.amount;
        if new_minted == 0 {
            minted.remove(&call.source_ohm);
        } else {
            minted.insert(call.source_ohm, new_minted);
        }
        let burn_outpoint = OutPoint::new(txid, 0);
        let burn_key = burn_outpoint.key();
        let burn_output = OhmOutput {
            amount: call.amount,
            recipient: tx.inputs[0].owner,
            lock: false,
        };
        utxos.insert(
            burn_key,
            OhmUtxoEntry::new(burn_outpoint, burn_output, self.height + 1),
        );
        Ok(())
    }

    /// Consumes an inbound cross-chain message: verifies it against the committed source outbox,
    /// deterministically executes the target entry point and records a receipt. When the message
    /// requested a reply, auto-enqueues the reply into this ledger's outbox.
    ///
    /// For transfer messages (with `transfer` metadata), mints the wrapped asset to the specified
    /// recipient. For burn messages, unlocks the corresponding escrow output.
    #[allow(clippy::too_many_arguments)]
    fn apply_cross_recv(
        consumer: &Hash,
        processed_height: u64,
        call: &CrossRecvCall,
        view: Option<&CrossChainView>,
        contracts: &mut BTreeMap<Hash, OhmContract>,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
        inbox: &mut BTreeMap<Hash, InboundReceipt>,
        minted: &mut BTreeMap<Hash, Amount>,
        locked_total: &mut Amount,
        utxos: &mut BTreeMap<Hash, OhmUtxoEntry>,
    ) -> Result<(), OhmError> {
        let view = view.ok_or(OhmError::CrossViewMissing)?;
        let message = view
            .find(&call.msg_id)
            .cloned()
            .ok_or(OhmError::CrossMessageUnknown(call.msg_id))?;
        if &message.target_ohm != consumer {
            return Err(OhmError::CrossMessageWrongTarget(call.msg_id));
        }
        if inbox.contains_key(&call.msg_id) {
            return Err(OhmError::CrossMessageDuplicate(call.msg_id));
        }

        if let Some(transfer) = &message.transfer {
            return Self::apply_transfer_recv(
                consumer,
                processed_height,
                call,
                &message,
                transfer,
                inbox,
                minted,
                locked_total,
                utxos,
            );
        }

        let mut failure: Option<OvmFailureCode> = None;
        let mut return_value: Option<u64> = None;
        let intrinsic_gas =
            oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
        if message.gas_limit >= intrinsic_gas {
            let mut execution_arguments: Vec<u64> = message
                .caller
                .0
                .chunks_exact(8)
                .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte chunk")))
                .collect();
            execution_arguments.extend(message.arguments.iter().copied());
            let host = CrossHost {
                origin_ohm: *consumer,
                inbox: receipt_view(inbox),
            };
            match Self::execute_cross_entry(
                contracts,
                &message.target_contract,
                message.entry_selector,
                &message.arguments,
                &execution_arguments,
                message.gas_limit,
                intrinsic_gas,
                &host,
                outbox,
                outbox_seq,
                consumer,
                processed_height,
                message.caller,
            ) {
                Ok(result) => {
                    if let Some(storage) = result.storage {
                        if let Some(contract) = contracts.get_mut(&message.target_contract) {
                            contract.storage = storage;
                        }
                    }
                    if let Some(reverted) = result.failure {
                        failure = Some(reverted);
                    }
                    return_value = result.return_value;
                }
                Err(error) => return Err(error),
            }
        }

        let mut reply_msg_id = None;
        if message.want_reply {
            let reply_contract = message.reply_contract.ok_or_else(|| {
                OhmError::CrossChain("message requests a reply without a reply contract".into())
            })?;
            let reply_entry_selector = message.reply_entry_selector.ok_or_else(|| {
                OhmError::CrossChain("message requests a reply without a reply entry".into())
            })?;
            let seq = *outbox_seq;
            *outbox_seq = outbox_seq.checked_add(1).ok_or(OhmError::Overflow)?;
            let reply_id = ohm_cross_msg_id(consumer, processed_height, seq);
            let success = failure.is_none();
            let value = match (success, failure, return_value) {
                (true, _, Some(value)) => value,
                (true, _, None) => 0,
                (false, Some(code), _) => code as u64,
                (false, None, _) => 0,
            };
            let reply = OutboundMessage {
                msg_id: reply_id,
                source_ohm: *consumer,
                source_height: processed_height,
                seq,
                caller: message.caller,
                target_ohm: message.source_ohm,
                target_contract: reply_contract,
                entry_selector: reply_entry_selector,
                arguments: reply_arguments(&call.msg_id, success, value),
                gas_limit: message.gas_limit,
                want_reply: false,
                reply_contract: None,
                reply_entry_selector: None,
                reply_to_msg_id: Some(call.msg_id),
                transfer: None,
            };
            outbox.insert(reply_id, reply);
            reply_msg_id = Some(reply_id);
        }

        inbox.insert(
            call.msg_id,
            InboundReceipt {
                msg_id: call.msg_id,
                origin: message.source_ohm,
                origin_height: message.source_height,
                processed_height,
                failure,
                return_value,
                reply_msg_id,
                reply_to_msg_id: message.reply_to_msg_id,
            },
        );
        Ok(())
    }

    /// Handles a cross-chain transfer or burn message: mints wrapped assets on the target OHM or
    /// unlocks escrow on the source OHM.
    #[allow(clippy::too_many_arguments)]
    fn apply_transfer_recv(
        consumer: &Hash,
        processed_height: u64,
        call: &CrossRecvCall,
        message: &OutboundMessage,
        transfer: &TransferPayload,
        inbox: &mut BTreeMap<Hash, InboundReceipt>,
        minted: &mut BTreeMap<Hash, Amount>,
        locked_total: &mut Amount,
        utxos: &mut BTreeMap<Hash, OhmUtxoEntry>,
    ) -> Result<(), OhmError> {
        if let Some(recipient) = transfer.recipient {
            let current_minted = minted.get(&message.source_ohm).copied().unwrap_or(0);
            let new_minted = current_minted
                .checked_add(transfer.amount)
                .ok_or(OhmError::Overflow)?;
            minted.insert(message.source_ohm, new_minted);
            let mint_outpoint = OutPoint::new(call.msg_id, 0);
            let mint_output = OhmOutput {
                amount: transfer.amount,
                recipient,
                lock: false,
            };
            utxos.insert(
                mint_outpoint.key(),
                OhmUtxoEntry::new(mint_outpoint, mint_output, processed_height),
            );
            inbox.insert(
                call.msg_id,
                InboundReceipt {
                    msg_id: call.msg_id,
                    origin: message.source_ohm,
                    origin_height: message.source_height,
                    processed_height,
                    failure: None,
                    return_value: None,
                    reply_msg_id: None,
                    reply_to_msg_id: None,
                },
            );
        } else {
            if consumer != &message.source_ohm {
                return Err(OhmError::CrossChain(
                    "burn message can only be consumed by the source OHM".into(),
                ));
            }
            let mut unlocked = false;
            for entry in utxos.values_mut() {
                if entry.output.lock && entry.output.amount == transfer.amount {
                    entry.output.lock = false;
                    unlocked = true;
                    break;
                }
            }
            if !unlocked {
                return Err(OhmError::UnlockNoMatch);
            }
            *locked_total = locked_total
                .checked_sub(transfer.amount)
                .ok_or(OhmError::Underflow)?;
            inbox.insert(
                call.msg_id,
                InboundReceipt {
                    msg_id: call.msg_id,
                    origin: message.source_ohm,
                    origin_height: message.source_height,
                    processed_height,
                    failure: None,
                    return_value: None,
                    reply_msg_id: None,
                    reply_to_msg_id: None,
                },
            );
        }
        Ok(())
    }

    /// Runs the cross-chain target entry point, returning any failure code, the storage to
    /// commit and the staged cross calls to enqueue. Invalid bytecode and invalid programs
    /// hard-fail the block; runtime failures (revert, out-of-gas, argument mismatch) become
    /// failed receipts.
    #[allow(clippy::too_many_arguments)]
    fn execute_cross_entry(
        contracts: &BTreeMap<Hash, OhmContract>,
        target_contract: &Hash,
        entry_selector: u64,
        arguments: &[u64],
        execution_arguments: &[u64],
        gas_limit: u64,
        intrinsic_gas: u64,
        host: &CrossHost,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
        origin_ohm: &Hash,
        origin_height: u64,
        caller: PublicKey,
    ) -> Result<ExecuteOutcome, OhmError> {
        let Some(contract) = contracts.get(target_contract) else {
            return Ok(ExecuteOutcome {
                failure: Some(OvmFailureCode::ContractNotFound),
                return_value: None,
                storage: None,
            });
        };
        let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let function = artifact.function_by_selector(entry_selector);
        let Some(function) = function else {
            return Ok(ExecuteOutcome {
                failure: Some(OvmFailureCode::FunctionNotFound),
                return_value: None,
                storage: None,
            });
        };
        if function.inputs.len() != arguments.len() {
            return Ok(ExecuteOutcome {
                failure: Some(OvmFailureCode::ArgumentCount),
                return_value: None,
                storage: None,
            });
        }
        let program = oxydome_ovm::Program::decode(&function.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let execution_limit = gas_limit - intrinsic_gas;
        let storage = contract.storage.clone();
        match oxydome_ovm::execute_with_host(
            &program,
            execution_arguments,
            &storage,
            execution_limit,
            Some(host),
        ) {
            Ok(execution) => {
                enqueue_staged_calls(
                    outbox,
                    outbox_seq,
                    origin_ohm,
                    origin_height,
                    caller,
                    &execution.staged_calls,
                )?;
                Ok(ExecuteOutcome {
                    failure: None,
                    return_value: execution.return_value,
                    storage: Some(execution.storage),
                })
            }
            Err(failure) => match failure.error {
                oxydome_ovm::VmError::InvalidBytecode
                | oxydome_ovm::VmError::ProgramTooLarge
                | oxydome_ovm::VmError::InvalidProgram => {
                    Err(OhmError::Ovm(failure.error.to_string()))
                }
                _ => Ok(ExecuteOutcome {
                    failure: Some(failure_code(failure.error)),
                    return_value: None,
                    storage: None,
                }),
            },
        }
    }

    /// Executes a private OVM action against the in-progress contract map. Calls observe a
    /// [`CrossHost`]: staged [`Instruction::XCall`](oxydome_ovm::Instruction::XCall) results are
    /// enqueued into the ledger outbox, and contract-originated `ReadReply` reads the receipts
    /// recorded so far in the in-progress inbox.
    ///
    /// Mirrors the Ox execution model: a failed call leaves storage untouched (the transaction
    /// still settles), while a deploy of undecodable code invalidates the block.
    #[allow(clippy::too_many_arguments)]
    fn apply_ovm_action(
        contracts: &mut BTreeMap<Hash, OhmContract>,
        action: &OvmAction,
        txid: Hash,
        tx_index: usize,
        tx: &OhmTransaction,
        origin_ohm: &Hash,
        origin_height: u64,
        inbox: &BTreeMap<Hash, InboundReceipt>,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
    ) -> Result<(), OhmError> {
        match action {
            OvmAction::Deploy { code, gas_limit } => {
                oxydome_ovm::Program::decode(code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if contracts.contains_key(&contract_id) {
                    return Err(OhmError::OvmContractCollision);
                }
                if contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(OhmError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(code.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(());
                }
                contracts.insert(
                    contract_id,
                    OhmContract {
                        code: code.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(())
            }
            OvmAction::DeployContract { artifact, gas_limit } => {
                oxydome_ovm::ContractArtifact::decode(artifact)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if contracts.contains_key(&contract_id) {
                    return Err(OhmError::OvmContractCollision);
                }
                if contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(OhmError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(artifact.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(());
                }
                contracts.insert(
                    contract_id,
                    OhmContract {
                        code: artifact.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(())
            }
            OvmAction::Call {
                contract_id,
                arguments,
                gas_limit,
            } => {
                if *gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS {
                    return Ok(());
                }
                let Some(contract) = contracts.get(contract_id) else {
                    return Ok(());
                };
                let program = oxydome_ovm::Program::decode(&contract.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                Self::execute_contract_call(
                    contracts,
                    contract_id,
                    &program,
                    arguments,
                    *gas_limit,
                    oxydome_ovm::ACTION_INTRINSIC_GAS,
                    tx.inputs[0].owner,
                    origin_ohm,
                    origin_height,
                    &CrossHost {
                        origin_ohm: *origin_ohm,
                        inbox: receipt_view(inbox),
                    },
                    outbox,
                    outbox_seq,
                )
            }
            OvmAction::CallContract {
                contract_id,
                entry_point,
                arguments,
                authority_input,
                gas_limit,
            } => {
                let intrinsic_gas =
                    oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
                if *gas_limit < intrinsic_gas {
                    return Ok(());
                }
                let Some(contract) = contracts.get(contract_id) else {
                    return Ok(());
                };
                let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let Some(function) = artifact.function(entry_point) else {
                    return Ok(());
                };
                if function.inputs.len() != arguments.len() {
                    return Ok(());
                }
                let Some(authority) = tx.inputs.get(*authority_input as usize) else {
                    return Err(OhmError::BadTransaction(
                        tx_index,
                        "contract authority input index is invalid".into(),
                    ));
                };
                let mut execution_arguments: Vec<u64> = authority
                    .owner
                    .0
                    .chunks_exact(8)
                    .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte chunk")))
                    .collect();
                execution_arguments.extend(arguments.iter().copied());
                let program = oxydome_ovm::Program::decode(&function.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let caller = authority.owner;
                Self::execute_contract_call(
                    contracts,
                    contract_id,
                    &program,
                    &execution_arguments,
                    *gas_limit,
                    intrinsic_gas,
                    caller,
                    origin_ohm,
                    origin_height,
                    &CrossHost {
                        origin_ohm: *origin_ohm,
                        inbox: receipt_view(inbox),
                    },
                    outbox,
                    outbox_seq,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_contract_call(
        contracts: &mut BTreeMap<Hash, OhmContract>,
        contract_id: &Hash,
        program: &oxydome_ovm::Program,
        arguments: &[u64],
        gas_limit: u64,
        intrinsic_gas: u64,
        caller: PublicKey,
        origin_ohm: &Hash,
        origin_height: u64,
        host: &CrossHost,
        outbox: &mut BTreeMap<Hash, OutboundMessage>,
        outbox_seq: &mut u64,
    ) -> Result<(), OhmError> {
        if gas_limit < intrinsic_gas {
            return Ok(());
        }
        let execution_limit = gas_limit - intrinsic_gas;
        let storage = contracts
            .get(contract_id)
            .map(|contract| contract.storage.clone())
            .unwrap_or_default();
        match oxydome_ovm::execute_with_host(
            program,
            arguments,
            &storage,
            execution_limit,
            Some(host),
        ) {
            Ok(execution) => {
                enqueue_staged_calls(
                    outbox,
                    outbox_seq,
                    origin_ohm,
                    origin_height,
                    caller,
                    &execution.staged_calls,
                )?;
                if let Some(contract) = contracts.get_mut(contract_id) {
                    contract.storage = execution.storage;
                }
                Ok(())
            }
            Err(failure) => match failure.error {
                oxydome_ovm::VmError::InvalidBytecode
                | oxydome_ovm::VmError::ProgramTooLarge
                | oxydome_ovm::VmError::InvalidProgram => {
                    Err(OhmError::Ovm(failure.error.to_string()))
                }
                _ => Ok(()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ohm_state_root, ohm_utxo_root, OhmOutput};

    fn key() -> KeyPair {
        KeyPair::from_seed(&[5u8; 32])
    }

    fn ledger(pool: Amount, outputs: usize) -> OhmLedger {
        let owner = key().public();
        let per = pool / outputs as Amount;
        let outs: Vec<OhmOutput> = (0..outputs)
            .map(|_| OhmOutput {
                amount: per,
                recipient: owner,
            lock: false,
            })
            .collect();
        OhmLedger::from_genesis(
            ohm_genesis_hash(&Hash::zero()),
            owner,
            &outs,
            Hash::from([9u8; 64]),
        )
    }

    /// A second OHM (id differs from [`ledger`]) used as a cross-chain counterparty.
    fn target_ledger(pool: Amount) -> OhmLedger {
        let owner = key().public();
        OhmLedger::from_genesis(
            ohm_genesis_hash(&Hash::from([7u8; 64])),
            owner,
            &[OhmOutput {
                amount: pool,
                recipient: owner,
            lock: false,
            }],
            Hash::from([8u8; 64]),
        )
    }

    #[test]
    fn genesis_ledger_is_committed() {
        let l = ledger(1000, 1);
        assert_eq!(l.height, 0);
        assert_eq!(l.supply, 1000);
        assert_eq!(l.utxo_total(), 1000);
        assert!(l.contracts.is_empty());
        assert_eq!(l.state_root, ohm_state_root(&l.utxos, &l.contracts));
    }

    #[test]
    fn build_and_apply_block_moves_value() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let tx = l.build_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 990,
                recipient: owner,
            lock: false,
            }],
            10,
            &key(),
        );
        let block = l.build_block(vec![tx], 42, &key()).unwrap();
        let mut applied = l.clone();
        applied.apply_block(&block).unwrap();
        assert_eq!(applied.height, 1);
        assert_eq!(applied.supply, 990);
        assert_eq!(applied.utxo_total(), 990);
        assert_eq!(applied.block_hash, block.hash());
    }

    #[test]
    fn block_with_wrong_state_root_rejected() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let tx = l.build_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            &key(),
        );
        let mut block = l.build_block(vec![tx], 42, &key()).unwrap();
        block.header.state_root = Hash::from([1u8; 64]);
        // Re-sign so the signature is valid and the state-root mismatch is what is detected.
        block.sign(&key());
        assert!(matches!(
            l.verify_block(&block),
            Err(OhmError::BadStateRoot(..))
        ));
    }

    #[test]
    fn double_spend_rejected() {
        let l = ledger(1000, 2);
        let owner = key().public();
        let outs: Vec<OutPoint> = l.utxos.values().map(|e| e.outpoint).collect();
        let tx1 = l.build_transaction(
            vec![(outs[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            &key(),
        );
        let tx2 = l.build_transaction(
            vec![(outs[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            &key(),
        );
        let mut block = OhmBlock::new_unsigned(
            l.ohm_id,
            1,
            l.block_hash,
            1,
            Hash::zero(),
            owner,
            vec![tx1, tx2],
        );
        block.sign(&key());
        assert!(matches!(
            l.verify_block(&block),
            Err(OhmError::MissingInput(_))
        ));
    }

    #[test]
    fn non_maintainer_cannot_build() {
        let l = ledger(1000, 1);
        let other = KeyPair::from_seed(&[77u8; 32]);
        assert!(matches!(
            l.build_block(Vec::new(), 1, &other),
            Err(OhmError::BadMaintainer)
        ));
    }

    fn increment_program() -> Vec<u8> {
        oxydome_ovm::Program {
            argument_count: 1,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Add,
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn deploys_and_executes_ohm_hosted_contract() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;

        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::Deploy {
                code: increment_program(),
                gas_limit: 1_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = l.build_ovm_transaction(
            vec![(OutPoint::new(deploy.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 800,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::Call {
                contract_id,
                arguments: vec![5],
                gas_limit: 100,
            }),
            &key(),
        );

        let block = l.build_block(vec![deploy, call], 7, &key()).unwrap();
        let mut applied = l.clone();
        applied.apply_block(&block).unwrap();

        assert_eq!(applied.contracts.len(), 1);
        assert_eq!(applied.contracts[&contract_id].storage.get(&0), Some(&5));
        assert_eq!(applied.height, 1);
        assert_eq!(applied.supply, 800);
        assert_eq!(applied.state_root, block.header.state_root);
        assert_eq!(
            applied.state_root,
            ohm_state_root(&applied.utxos, &applied.contracts)
        );
        // The private contract state changes the anchored root beyond the UTXO set alone.
        assert_ne!(applied.state_root, ohm_utxo_root(&applied.utxos));
    }

    #[test]
    fn undecodable_deployment_invalidates_the_ohm_block() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::Deploy {
                code: vec![0xff, 0xff, 0xff],
                gas_limit: 1_000,
            }),
            &key(),
        );
        assert!(matches!(
            l.build_block(vec![deploy], 1, &key()),
            Err(OhmError::Ovm(_))
        ));
    }

    #[test]
    fn simulate_contract_call_is_read_only() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let code = oxydome_ovm::Program {
            argument_count: (oxydome_ovm::AUTHORITY_WORD_COUNT + 1) as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(oxydome_ovm::AUTHORITY_WORD_COUNT as u8),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Add,
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let artifact = oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "increment".into(),
                inputs: vec![oxydome_ovm::ContractValueType::U64],
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap();
        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact,
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let mut deployed = l.clone();
        let block = deployed.build_block(vec![deploy], 3, &key()).unwrap();
        deployed.apply_block(&block).unwrap();

        let outcome = deployed
            .simulate_contract_call(&contract_id, "increment", owner, &[41], 100)
            .unwrap();
        assert_eq!(outcome.failure, None);
        assert_eq!(outcome.return_value, Some(41));
        // Simulation never mutates the committed ledger.
        assert_eq!(deployed.contracts[&contract_id].storage.get(&0), None);
    }

    fn echo_artifact(arg_count: usize) -> Vec<u8> {
        let code = oxydome_ovm::Program {
            argument_count: (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count) as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(
                    (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count - 1) as u8,
                ),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "echo".into(),
                inputs: (0..arg_count)
                    .map(|_| oxydome_ovm::ContractValueType::U64)
                    .collect(),
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap()
    }

    fn on_reply_artifact() -> Vec<u8> {
        // reply_arguments(msg_id, success, value) is 10 words (8 msg-id words + flag + value);
        // the receiving function sees all 10 as payload arguments.
        let arg_count = 10usize;
        let code = oxydome_ovm::Program {
            argument_count: (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count) as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(
                    (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count - 1) as u8,
                ),
                oxydome_ovm::Instruction::StoreStorage(1),
                oxydome_ovm::Instruction::LoadStorage(1),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "on_reply".into(),
                inputs: (0..arg_count)
                    .map(|_| oxydome_ovm::ContractValueType::U64)
                    .collect(),
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn cross_send_enqueues_message_and_commits_root() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let target_ohm = target_ledger(1000).ohm_id;

        let send = l.build_cross_send_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossSendCall {
                target_ohm,
                target_contract: Hash::from([3u8; 64]),
                entry_point: "echo".into(),
                arguments: vec![41],
                gas_limit: 200,
                want_reply: false,
                reply_contract: None,
                reply_entry_point: None,
            },
            &key(),
        );
        let block = l.build_block(vec![send], 5, &key()).unwrap();
        let mut applied = l.clone();
        applied.apply_block(&block).unwrap();

        assert_eq!(applied.outbox.len(), 1);
        let msg = applied.outbox.values().next().unwrap();
        assert_eq!(msg.source_ohm, l.ohm_id);
        assert_eq!(msg.source_height, 1);
        assert_eq!(msg.seq, 0);
        assert_eq!(msg.target_ohm, target_ohm);
        assert_eq!(msg.entry_selector, oxydome_ovm::fn_selector("echo"));
        assert_eq!(msg.caller, owner);
        assert_eq!(msg.arguments, vec![41]);
        // The message id is deterministic.
        assert_eq!(msg.msg_id, ohm_cross_msg_id(&l.ohm_id, 1, 0));
        // The committed root now commits the outbox.
        assert_eq!(applied.state_root, block.header.state_root);
        assert_eq!(
            applied.state_root,
            ohm_state_root_full(&applied.utxos, &applied.contracts, &applied.outbox, &applied.inbox)
        );
        assert_ne!(applied.state_root, ohm_state_root(&applied.utxos, &applied.contracts));
    }

    #[test]
    fn cross_recv_consumes_and_auto_replies() {
        let source = ledger(1000, 1);
        let mut consumer = target_ledger(1000);
        let owner = key().public();

        // Consumer hosts an echo contract.
        let deploy_tx = consumer.build_ovm_transaction(
            vec![(consumer.utxos.values().next().unwrap().outpoint, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: echo_artifact(1),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let target_contract = oxydome_ovm::contract_id(deploy_tx.txid());
        consumer
            .apply_block(&consumer.build_block(vec![deploy_tx.clone()], 3, &key()).unwrap())
            .unwrap();

        // Sender hosts an on_reply contract to collect the automatic reply.
        let mut source_applied = source.clone();
        let source_deploy_tx = source_applied.build_ovm_transaction(
            vec![(source_applied.utxos.values().next().unwrap().outpoint, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: on_reply_artifact(),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let reply_contract = oxydome_ovm::contract_id(source_deploy_tx.txid());
        source_applied
            .apply_block(
                &source_applied
                    .build_block(vec![source_deploy_tx.clone()], 1, &key())
                    .unwrap(),
            )
            .unwrap();

        // Sender enqueues a message requesting a reply.
        let block = source_applied
            .build_block(
                vec![source_applied.build_cross_send_transaction(
                    vec![(OutPoint::new(source_deploy_tx.txid(), 0), owner)],
                    vec![OhmOutput {
                        amount: 800,
                        recipient: owner,
                        lock: false,
                    }],
                    100,
                    CrossSendCall {
                        target_ohm: consumer.ohm_id,
                        target_contract,
                        entry_point: "echo".into(),
                        arguments: vec![41],
                        gas_limit: 200,
                        want_reply: true,
                        reply_contract: Some(reply_contract),
                        reply_entry_point: Some("on_reply".into()),
                    },
                    &key(),
                )],
                5,
                &key(),
            )
            .unwrap();
        source_applied.apply_block(&block).unwrap();
        let msg = source_applied.outbox.values().next().unwrap().clone();

        // The view is built from the *committed* sender ledger (finalized earlier).
        let ledgers = BTreeMap::from([
            (source_applied.ohm_id, source_applied.clone()),
            (consumer.ohm_id, consumer.clone()),
        ]);
        let view = CrossChainView::from_ledgers(&ledgers);

        let consume = consumer.build_cross_recv_transaction(
            vec![(OutPoint::new(deploy_tx.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 800,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall { msg_id: msg.msg_id },
            &key(),
        );
        let consume_block = consumer
            .build_block_with(vec![consume], 6, &key(), &view)
            .unwrap();
        let mut consumed = consumer.clone();
        consumed.apply_block_with(&consume_block, &view).unwrap();

        // The target ran and its storage change is committed (echo writes nothing, but the
        // receipt and the auto-reply are both recorded).
        assert!(consumed.inbox.contains_key(&msg.msg_id));
        let receipt = &consumed.inbox[&msg.msg_id];
        assert_eq!(receipt.origin, source.ohm_id);
        assert_eq!(receipt.origin_height, 2);
        assert_eq!(receipt.processed_height, 2);
        assert_eq!(receipt.failure, None);
        assert_eq!(receipt.return_value, Some(41));
        assert!(receipt.reply_msg_id.is_some());

        // The reply is enqueued into the consumer's outbox, addressed back at the sender.
        let reply_id = receipt.reply_msg_id.unwrap();
        let reply = &consumed.outbox[&reply_id];
        assert_eq!(reply.target_ohm, source.ohm_id);
        assert_eq!(reply.target_contract, reply_contract);
        assert_eq!(reply.entry_selector, oxydome_ovm::fn_selector("on_reply"));
        assert_eq!(reply.reply_to_msg_id, Some(msg.msg_id));
        assert_eq!(
            reply.arguments,
            reply_arguments(&msg.msg_id, true, 41)
        );

        // The sender then consumes the reply.
        let reply_msg = consumed.outbox[&reply_id].clone();
        let ledgers2 = BTreeMap::from([(consumed.ohm_id, consumed.clone())]);
        let view2 = CrossChainView::from_ledgers(&ledgers2);
        let reply_consume = source_applied;
        let reply_tx = reply_consume.build_cross_recv_transaction(
            vec![(reply_consume.utxos.values().next().unwrap().outpoint, owner)],
            vec![OhmOutput {
                amount: 700,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall { msg_id: reply_msg.msg_id },
            &key(),
        );
        let reply_block = reply_consume
            .build_block_with(vec![reply_tx], 7, &key(), &view2)
            .unwrap();
        let mut final_source = reply_consume.clone();
        final_source.apply_block_with(&reply_block, &view2).unwrap();

        let reply_receipt = &final_source.inbox[&reply_msg.msg_id];
        assert_eq!(reply_receipt.reply_to_msg_id, Some(msg.msg_id));
        assert_eq!(reply_receipt.failure, None);
        assert_eq!(reply_receipt.return_value, Some(41));
        // The on_reply contract consumed the reply argument (value 41) and stored it.
        assert_eq!(
            final_source.contracts[&reply_contract].storage.get(&1),
            Some(&41)
        );
    }

    #[test]
    fn cross_recv_unknown_message_rejected() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let tx = l.build_cross_recv_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall {
                msg_id: Hash::from([7u8; 64]),
            },
            &key(),
        );
        let res = l.build_block_with(vec![tx], 1, &key(), &CrossChainView::new());
        assert!(matches!(res, Err(OhmError::CrossMessageUnknown(_))));
    }

    #[test]
    fn cross_recv_wrong_target_rejected() {
        let mut l = target_ledger(1000);
        let owner = key().public();
        let deploy_tx = l.build_ovm_transaction(
            vec![(l.utxos.values().next().unwrap().outpoint, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: echo_artifact(1),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let target_contract = oxydome_ovm::contract_id(deploy_tx.txid());
l.apply_block(&l.build_block(vec![deploy_tx.clone()], 3, &key()).unwrap())
    .unwrap();

        let other = ledger(1000, 1);
        // The message targets `other`'s OHM, but we try to consume it here.
        let msg_id = ohm_cross_msg_id(&other.ohm_id, 1, 0);
        let message = OutboundMessage {
            msg_id,
            source_ohm: other.ohm_id,
            source_height: 1,
            seq: 0,
            caller: owner,
            target_ohm: other.ohm_id,
            target_contract,
            entry_selector: oxydome_ovm::fn_selector("echo"),
            arguments: vec![41],
            gas_limit: 200,
            want_reply: false,
            reply_contract: None,
            reply_entry_selector: None,
            reply_to_msg_id: None,
            transfer: None,
        };
        let mut view = CrossChainView::new();
        view.insert(other.ohm_id, BTreeMap::from([(msg_id, message)]));

        let tx = l.build_cross_recv_transaction(
            vec![(OutPoint::new(deploy_tx.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 800,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall { msg_id },
            &key(),
        );
        assert!(matches!(
            l.build_block_with(vec![tx], 4, &key(), &view),
            Err(OhmError::CrossMessageWrongTarget(_))
        ));
    }

    #[test]
    fn cross_recv_duplicate_rejected() {
        let source = ledger(1000, 1);
        let mut consumer = target_ledger(1000);
        let owner = key().public();

        let deploy_tx = consumer.build_ovm_transaction(
            vec![(consumer.utxos.values().next().unwrap().outpoint, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: echo_artifact(1),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let target_contract = oxydome_ovm::contract_id(deploy_tx.txid());
        consumer
            .apply_block(&consumer.build_block(vec![deploy_tx.clone()], 3, &key()).unwrap())
            .unwrap();

        let mut source_applied = source.clone();
        let send_block = source_applied
            .build_block(
                vec![source_applied.build_cross_send_transaction(
                    vec![(source_applied.utxos.values().next().unwrap().outpoint, owner)],
                    vec![OhmOutput {
                        amount: 900,
                        recipient: owner,
                        lock: false,
                    }],
                    100,
                    CrossSendCall {
                        target_ohm: consumer.ohm_id,
                        target_contract,
                        entry_point: "echo".into(),
                        arguments: vec![1],
                        gas_limit: 200,
                        want_reply: false,
                        reply_contract: None,
                        reply_entry_point: None,
                    },
                    &key(),
                )],
                5,
                &key(),
            )
            .unwrap();
        source_applied.apply_block(&send_block).unwrap();
        let msg_id = source_applied.outbox.values().next().unwrap().msg_id;

        let ledgers = BTreeMap::from([(source_applied.ohm_id, source_applied.clone())]);
        let view = CrossChainView::from_ledgers(&ledgers);

        // A single consume is fine.
        let consume_block = consumer
            .build_block_with(
                vec![consumer.build_cross_recv_transaction(
                    vec![(OutPoint::new(deploy_tx.txid(), 0), owner)],
                    vec![OhmOutput {
                        amount: 800,
                        recipient: owner,
                        lock: false,
                    }],
                    100,
                    CrossRecvCall { msg_id },
                    &key(),
                )],
                6,
                &key(),
                &view,
            )
            .unwrap();
        assert!(consume_block.transactions.len() == 1);

        // A second consume of the same message, chained on the first transaction's output, must
        // be rejected as a duplicate within a single derivation context.
        let consume_tx = consumer.build_cross_recv_transaction(
            vec![(OutPoint::new(deploy_tx.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 800,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall { msg_id },
            &key(),
        );
        let second = consumer.build_cross_recv_transaction(
            vec![(OutPoint::new(consume_tx.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 700,
                recipient: owner,
            lock: false,
            }],
            100,
            CrossRecvCall { msg_id },
            &key(),
        );
        assert!(matches!(
            consumer.build_block_with(vec![consume_tx, second], 7, &key(), &view),
            Err(OhmError::CrossMessageDuplicate(_))
        ));
    }

    /// A contract whose `fire(0)` entry point stages an `XCall` to `target_ohm` / `target_contract`
    /// with payload `[123, 456]` and `gas_limit 400`.
    fn xcall_launcher_artifact(target_ohm: Hash, target_contract: Hash) -> Vec<u8> {
        use oxydome_core::hash_words;
        let mut instructions =
            vec![oxydome_ovm::Instruction::Push(123), oxydome_ovm::Instruction::Push(456)];
        for word in hash_words(&target_ohm) {
            instructions.push(oxydome_ovm::Instruction::Push(word));
        }
        for word in hash_words(&target_contract) {
            instructions.push(oxydome_ovm::Instruction::Push(word));
        }
        instructions.push(oxydome_ovm::Instruction::Push(oxydome_ovm::fn_selector("poke")));
        instructions.push(oxydome_ovm::Instruction::Push(400));
        instructions.push(oxydome_ovm::Instruction::XCall { arg_count: 2 });
        instructions.push(oxydome_ovm::Instruction::Return);
        let code = oxydome_ovm::Program {
            argument_count: oxydome_ovm::AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions,
        }
        .encode()
        .unwrap();
        oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "fire".into(),
                inputs: vec![],
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn cross_contract_xcall_enqueues_staged_message() {
        let mut a = ledger(1000, 2);
        let b = target_ledger(1000);
        let owner = key().public();
        let target_contract = Hash::from([7u8; 64]);
        let poke_selector = oxydome_ovm::fn_selector("poke");

        let utxos: Vec<_> = a.utxos.values().map(|entry| entry.outpoint).collect();
        let deploy = a.build_ovm_transaction(
            vec![(utxos[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: xcall_launcher_artifact(b.ohm_id, target_contract),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = a.build_ovm_transaction(
            vec![(utxos[1], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::CallContract {
                contract_id,
                entry_point: "fire".into(),
                arguments: vec![],
                authority_input: 0,
                gas_limit: 2_000,
            }),
            &key(),
        );
        let block = a.build_block(vec![deploy, call], 1, &key()).unwrap();
        a.apply_block(&block).unwrap();

        assert_eq!(a.outbox.len(), 1);
        let (id, message) = a.outbox.iter().next().unwrap();
        assert_eq!(*id, ohm_cross_msg_id(&a.ohm_id, 1, 0));
        assert_eq!(message.seq, 0);
        assert_eq!(message.source_ohm, a.ohm_id);
        assert_eq!(message.source_height, 1);
        assert_eq!(message.caller, owner);
        assert_eq!(message.target_ohm, b.ohm_id);
        assert_eq!(message.target_contract, target_contract);
        assert_eq!(message.entry_selector, poke_selector);
        assert_eq!(message.arguments, vec![123, 456]);
        assert_eq!(message.gas_limit, 400);
        assert!(!message.want_reply);
        assert_eq!(message.reply_contract, None);
        assert_eq!(message.reply_to_msg_id, None);
    }

    #[test]
    fn cross_contract_read_reply_reads_committed_receipt() {
        use oxydome_core::hash_words;

        let owner = key().public();
        let mut b = target_ledger(1000);
        let msg_id = ohm_cross_msg_id(&b.ohm_id, 1, 0);
        b.inbox.insert(
            msg_id,
            InboundReceipt {
                msg_id,
                origin: b.ohm_id,
                origin_height: 1,
                processed_height: 2,
                failure: None,
                return_value: Some(41),
                reply_msg_id: None,
                reply_to_msg_id: None,
            },
        );

        let mut instructions = Vec::new();
        for word in hash_words(&msg_id) {
            instructions.push(oxydome_ovm::Instruction::Push(word));
        }
        instructions.push(oxydome_ovm::Instruction::ReadReply);
        instructions.push(oxydome_ovm::Instruction::StoreStorage(0));
        instructions.push(oxydome_ovm::Instruction::StoreStorage(1));
        instructions.push(oxydome_ovm::Instruction::Return);
        let code = oxydome_ovm::Program {
            argument_count: oxydome_ovm::AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions,
        }
        .encode()
        .unwrap();
        let artifact = oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "check".into(),
                inputs: vec![],
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap();

        let utxos: Vec<_> = b.utxos.values().map(|entry| entry.outpoint).collect();
let deploy = b.build_ovm_transaction(
            vec![(utxos[0], owner)],
            vec![OhmOutput {
                amount: 950,
                recipient: owner,
            lock: false,
            }],
            50,
            Some(OvmAction::DeployContract {
                artifact,
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = b.build_ovm_transaction(
            vec![(OutPoint::new(deploy.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            lock: false,
            }],
            50,
            Some(OvmAction::CallContract {
                contract_id,
                entry_point: "check".into(),
                arguments: vec![],
                authority_input: 0,
                gas_limit: 2_000,
            }),
            &key(),
        );
        let block = b.build_block(vec![deploy, call], 3, &key()).unwrap();
        b.apply_block(&block).unwrap();

        let contract = b.contracts.get(&contract_id).unwrap();
        assert_eq!(contract.storage.get(&0), Some(&41));
        assert_eq!(contract.storage.get(&1), Some(&1));
    }

    #[test]
    fn cross_inbound_target_xcall_stages_message() {
        let source = ledger(1000, 1);
        let mut consumer = target_ledger(1000);
        let owner = key().public();
        let target_contract = Hash::from([7u8; 64]);

        let utxos: Vec<_> = consumer.utxos.values().map(|entry| entry.outpoint).collect();
        let deploy = consumer.build_ovm_transaction(
            vec![(utxos[0], owner)],
            vec![OhmOutput {
                amount: 950,
                recipient: owner,
            lock: false,
            }],
            50,
            Some(OvmAction::DeployContract {
                artifact: xcall_launcher_artifact(source.ohm_id, target_contract),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());

        // A dispatches a message that B's `fire` target answers by staging a message back to A.
        let mut source_applied = source.clone();
        let send_block = source_applied
            .build_block(
                vec![source_applied.build_cross_send_transaction(
                    vec![(source_applied.utxos.values().next().unwrap().outpoint, owner)],
                    vec![OhmOutput {
                        amount: 900,
                        recipient: owner,
                        lock: false,
                    }],
                    100,
                    CrossSendCall {
                        target_ohm: consumer.ohm_id,
                        target_contract: contract_id,
                        entry_point: "fire".into(),
                        arguments: vec![],
                        gas_limit: 2_000,
                        want_reply: false,
                        reply_contract: None,
                        reply_entry_point: None,
                    },
                    &key(),
                )],
                5,
                &key(),
            )
            .unwrap();
        source_applied.apply_block(&send_block).unwrap();
        let msg_id = source_applied.outbox.values().next().unwrap().msg_id;
        // assert_eq!(msg_id, ohm_cross_msg_id(&source.ohm_id, 1, 0));

        let ledgers = BTreeMap::from([(source_applied.ohm_id, source_applied.clone())]);
        let view = CrossChainView::from_ledgers(&ledgers);

        let consume_block = consumer
            .build_block_with(
                vec![
                    deploy.clone(),
                    consumer.build_cross_recv_transaction(
                        vec![(OutPoint::new(deploy.txid(), 0), owner)],
                        vec![OhmOutput {
                            amount: 900,
                            recipient: owner,
                            lock: false,
                        }],
                        50,
                        CrossRecvCall { msg_id },
                        &key(),
                    ),
                ],
                6,
                &key(),
                &view,
            )
            .unwrap();
        consumer.apply_block_with(&consume_block, &view).unwrap();

        // The target's staged XCall landed in B's outbox, addressed back to A.
        assert_eq!(consumer.outbox.len(), 1);
        let (id, message) = consumer.outbox.iter().next().unwrap();
        assert_eq!(*id, message.msg_id);
        assert_eq!(message.seq, 0);
        assert_eq!(message.source_ohm, consumer.ohm_id);
        assert_eq!(message.source_height, 1);
        assert_eq!(message.caller, owner);
        assert_eq!(message.target_ohm, source.ohm_id);
        assert_eq!(message.target_contract, target_contract);
        assert_eq!(message.entry_selector, oxydome_ovm::fn_selector("poke"));
        assert_eq!(message.arguments, vec![123, 456]);
        assert_eq!(message.gas_limit, 400);
        assert!(!message.want_reply);
    }

    #[test]
    fn cross_contract_xcall_to_self_rejected() {
        let mut a = ledger(1000, 2);
        let owner = key().public();
        let utxos: Vec<_> = a.utxos.values().map(|entry| entry.outpoint).collect();
        let deploy = a.build_ovm_transaction(
            vec![(utxos[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: xcall_launcher_artifact(a.ohm_id, Hash::from([7u8; 64])),
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = a.build_ovm_transaction(
            vec![(utxos[1], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            lock: false,
            }],
            100,
            Some(OvmAction::CallContract {
                contract_id,
                entry_point: "fire".into(),
                arguments: vec![],
                authority_input: 0,
                gas_limit: 2_000,
            }),
            &key(),
        );
        assert!(matches!(
            a.build_block(vec![deploy, call], 1, &key()),
            Err(OhmError::CrossChain(_))
        ));
    }
}
