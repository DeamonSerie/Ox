//! Server node: holds the full chain, validates transactions, produces blocks when it is the
//! Proof-of-Authority leader, builds audit packages for the masters, and finalizes blocks once
//! BFT and `MasterCheck` quorums are present.

pub mod content_store;
pub mod index;
pub mod server;

use crate::content_store::ContentStore;
use crate::index::{IndexStore, WalletIndex};
use oxydome_audit::{attestation_quorum, AuditAttestation, AuditPackage, InputProof};
use oxydome_consensus::{AdmissionCertificate, MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_core::{
    Amount, Block, ChainParams, GenesisConfig, GovernanceSet, Hash, Operation, OutPoint, OvmAction,
    PublicKey, Transaction,
};
use oxydome_crypto::{CodeManifest, KeyPair, SparseProof};
use oxydome_currency::rebound_utxo_spendable;
use oxydome_net::{
    BalanceInfo, HistoryEntry, NodeEvent, TxLocation, TxStatus, UtxoInfo, ValueIndexInfo,
};
use oxydome_rewards::{participation_weights, split_fees};
use oxydome_state::{ledger_diff, ChainState, LedgerStore, StateError, UtxoEntry};
use std::collections::{BTreeSet, HashMap, VecDeque};
use tokio::sync::broadcast;

/// Errors raised by a node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("transaction rejected: {0}")]
    Tx(String),
    #[error("block is not the current leader's proposal")]
    NotLeader,
    #[error("commit certificate is invalid")]
    BadCommitCertificate,
    #[error("master attestation quorum not reached")]
    NoAttestationQuorum,
    #[error("master check quorum not reached")]
    NoMasterCheckQuorum,
    #[error("block does not extend the current tip")]
    NotOnTip,
    #[error("ledger store error: {0}")]
    Ledger(String),
}

/// Maximum number of rejected transactions retained for status lookups.
pub const REJECTED_LIMIT: usize = 10_000;

/// A transaction accepted by the node that has not yet been confirmed.
pub struct PendingTx {
    pub tx: Transaction,
    /// Every address involved in this transaction (owners and recipients).
    pub addresses: Vec<PublicKey>,
}

/// A running server node.
pub struct Node {
    pub key: KeyPair,
    pub gov: GovernanceSet,
    pub params: ChainParams,
    pub state: ChainState,
    pub blocks: Vec<Block>,
    pub mempool: Vec<Transaction>,
    pub pending_ops: Vec<Operation>,
    pub admission: Option<AdmissionCertificate>,
    pub manifest_root: Hash,
    pub epoch: u64,
    /// Durable ledger store, when persistence is attached.
    pub store: Option<LedgerStore>,
    /// Wallet-facing index of transaction locations and per-address history.
    pub wallet_index: WalletIndex,
    /// Durable snapshot store for the wallet index.
    pub index_store: Option<IndexStore>,
    /// Optional asset storage, deliberately excluded from consensus state.
    pub content_store: ContentStore,
    /// Accepted-but-unconfirmed transactions, keyed by txid.
    pub pending: HashMap<Hash, PendingTx>,
    /// Rejected transactions and the reason, bounded by [`REJECTED_LIMIT`].
    pub rejected: HashMap<Hash, (Transaction, String)>,
    /// Insertion order of rejected transactions, for bounding [`Node::rejected`].
    rejected_order: VecDeque<Hash>,
    /// Outpoints claimed by the current mempool (intra-mempool double-spend guard).
    pub mempool_inputs: BTreeSet<OutPoint>,
    /// Broadcast sink for wallet-facing events.
    pub events: broadcast::Sender<NodeEvent>,
}

impl Node {
    /// Builds a node from genesis configuration.
    pub fn new(
        key: KeyPair,
        config: &GenesisConfig,
        admission: Option<AdmissionCertificate>,
    ) -> Result<(Node, Block), NodeError> {
        let (state, genesis, gov) = ChainState::genesis(config)?;
        let manifest_root = admission
            .as_ref()
            .map(|c| c.manifest_root)
            .unwrap_or_else(Hash::zero);
        let node = Node {
            key,
            gov,
            params: config.params.clone(),
            state,
            blocks: vec![genesis.clone()],
            mempool: Vec::new(),
            pending_ops: Vec::new(),
            admission,
            manifest_root,
            epoch: 0,
            store: None,
            wallet_index: WalletIndex::new(),
            index_store: None,
            content_store: ContentStore::default(),
            pending: HashMap::new(),
            rejected: HashMap::new(),
            rejected_order: VecDeque::new(),
            mempool_inputs: BTreeSet::new(),
            events: broadcast::channel(2048).0,
        };
        Ok((node, genesis))
    }

    /// Attaches a durable ledger store to the node.
    pub fn with_store(mut self, store: LedgerStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Attaches a durable wallet index store to the node.
    pub fn with_index_store(mut self, store: IndexStore) -> Self {
        self.index_store = Some(store);
        self
    }

    /// Attaches bounded local storage for optional content-addressed assets.
    pub fn with_content_store(mut self, path: &std::path::Path) -> Result<Self, NodeError> {
        self.content_store =
            ContentStore::open(path).map_err(|error| NodeError::Ledger(error.to_string()))?;
        Ok(self)
    }

    pub fn get_content(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.content_store.get(hash).map(ToOwned::to_owned)
    }

    pub fn put_content(&mut self, hash: Hash, content: Vec<u8>) -> Result<(), String> {
        self.content_store
            .put(hash, content)
            .map_err(|error| error.to_string())
    }

    /// Restores the node by replaying its atomically persisted block history from genesis.
    ///
    /// The persisted UTXO and contract snapshots are checked against every replayed height;
    /// snapshots are never trusted as a substitute for deterministic block execution.
    pub fn restore_from_store(
        mut self,
        store: LedgerStore,
        index_store: Option<IndexStore>,
    ) -> Result<Self, NodeError> {
        let blocks = store
            .load_blocks()
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        if blocks.is_empty() {
            return Err(NodeError::Ledger(
                "ledger has no persisted block history".into(),
            ));
        }
        if blocks[0].hash() != self.blocks[0].hash() {
            return Err(NodeError::Ledger(
                "persisted genesis does not match configured genesis".into(),
            ));
        }
        if blocks[0].header.utxo_root != self.state.utxo_root()
            || blocks[0].header.state_root != self.state.state_root()
        {
            return Err(NodeError::Ledger(
                "persisted genesis roots do not match configured genesis".into(),
            ));
        }
        self.verify_persisted_height(&store, &blocks[0])?;

        let mut restored_index = WalletIndex::new();
        for block in blocks.iter().skip(1) {
            if block.header.height != self.state.height + 1 {
                return Err(NodeError::Ledger(format!(
                    "persisted block sequence skips height {}",
                    self.state.height + 1
                )));
            }
            restored_index.record_block(block, &self.state.utxo);
            self.state = self
                .state
                .apply_block(block, &self.gov, &self.params)
                .map_err(|error| {
                    NodeError::Ledger(format!(
                        "persisted block {} failed deterministic replay: {error}",
                        block.header.height
                    ))
                })?;
            self.verify_persisted_height(&store, block)?;
        }

        let current_height = store
            .current_height()
            .map_err(|error| NodeError::Ledger(error.to_string()))?
            .ok_or_else(|| NodeError::Ledger("ledger has no current-height marker".into()))?;
        if current_height != self.state.height {
            return Err(NodeError::Ledger(format!(
                "current ledger height {current_height} does not match replayed height {}",
                self.state.height
            )));
        }
        let stored_ledger = store
            .load_ledger(current_height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        if stored_ledger.root() != self.state.utxo_root()
            || store
                .load_ovm_state(current_height)
                .map_err(|error| NodeError::Ledger(error.to_string()))?
                != self.state.contracts
        {
            return Err(NodeError::Ledger(
                "persisted tip snapshots do not match replayed state".into(),
            ));
        }

        self.blocks = blocks;
        self.wallet_index = restored_index;
        self.store = Some(store);
        self.index_store = index_store;
        if let Some(index_store) = &self.index_store {
            index_store.save(&self.wallet_index)?;
        }
        Ok(self)
    }

    fn verify_persisted_height(&self, store: &LedgerStore, block: &Block) -> Result<(), NodeError> {
        let height = block.header.height;
        let snapshot = store
            .snapshot(height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?
            .ok_or_else(|| {
                NodeError::Ledger(format!("missing ledger snapshot at height {height}"))
            })?;
        if snapshot.block_hash != block.hash()
            || snapshot.root != self.state.utxo_root()
            || snapshot.total != self.state.utxo.total()
        {
            return Err(NodeError::Ledger(format!(
                "persisted UTXO snapshot does not match replay at height {height}"
            )));
        }
        let contracts = store
            .load_ovm_state(height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        if contracts != self.state.contracts {
            return Err(NodeError::Ledger(format!(
                "persisted OVM snapshot does not match replay at height {height}"
            )));
        }
        Ok(())
    }

    /// A receiver that observes wallet-facing events as they occur.
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    fn emit(&self, event: NodeEvent) {
        let _ = self.events.send(event);
    }

    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    pub fn next_height(&self) -> u64 {
        self.state.height + 1
    }

    /// The PoA leader for a height: round-robin over the sorted node set.
    pub fn leader_for(&self, height: u64) -> Option<PublicKey> {
        if self.gov.nodes.is_empty() {
            return None;
        }
        let mut nodes = self.gov.nodes.clone();
        nodes.sort();
        Some(nodes[(height as usize) % nodes.len()])
    }

    pub fn is_leader(&self, height: u64) -> bool {
        self.leader_for(height).as_ref() == Some(&self.public())
    }

    /// Submits a transaction to the mempool after stateful validation and the exact wallet fee
    /// rule. On success the transaction is tracked as pending and broadcast on the event bus.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<(), NodeError> {
        tx.validate_structure()
            .map_err(|e| NodeError::Tx(e.to_string()))?;
        let txid = tx.txid();
        if self.pending.contains_key(&txid) {
            return Err(NodeError::Tx("already in mempool".into()));
        }
        if self.wallet_index.by_txid.contains_key(&txid) {
            return Err(NodeError::Tx("already confirmed".into()));
        }
        if let Some((_, reason)) = self.rejected.get(&txid) {
            return Err(NodeError::Tx(format!("previously rejected: {reason}")));
        }

        let next_height = self.next_height();
        if tx.ovm_action.is_some() && next_height < self.params.ovm_activation_height {
            return Err(NodeError::Tx(
                "OVM is not active at the next block height".into(),
            ));
        }
        if tx
            .ovm_action
            .as_ref()
            .is_some_and(OvmAction::is_smart_contract_action)
            && next_height < self.params.smart_contract_activation_height
        {
            return Err(NodeError::Tx(
                "multi-entry-point smart contracts are not active at the next block height".into(),
            ));
        }
        let mut input_total: Amount = 0;
        for input in &tx.inputs {
            if self.mempool_inputs.contains(&input.prev_out) {
                return Err(NodeError::Tx(format!(
                    "input {:?} already claimed by the mempool",
                    input.prev_out
                )));
            }
            let entry = self
                .state
                .utxo
                .get(&input.prev_out)
                .ok_or_else(|| NodeError::Tx(format!("missing input {:?}", input.prev_out)))?;
            if !entry.output.kind.is_spendable() {
                return Err(NodeError::Tx(format!(
                    "input {:?} is not spendable",
                    input.prev_out
                )));
            }
            if entry.output.recipient != input.owner {
                return Err(NodeError::Tx(format!(
                    "input {:?} owner mismatch",
                    input.prev_out
                )));
            }
            if !rebound_utxo_spendable(
                next_height,
                entry.created_height,
                entry.output.rebound_gen,
                &self.params,
            ) {
                return Err(NodeError::Tx(format!(
                    "input {:?} is an immature rebound credit",
                    input.prev_out
                )));
            }
            input_total = input_total.saturating_add(entry.output.amount);
        }
        let output_total = tx
            .output_total()
            .map_err(|e| NodeError::Tx(e.to_string()))?;
        if input_total != output_total.saturating_add(tx.fee) {
            return Err(NodeError::Tx("transaction does not conserve value".into()));
        }

        // The wallet-makers API fee rule is exact: reject any fee that deviates from it.
        let base_fee =
            oxydome_core::transfer_fee(&tx.outputs).map_err(|e| NodeError::Tx(e.to_string()))?;
        let expected_fee = base_fee
            .checked_add(
                tx.ovm_action
                    .as_ref()
                    .map_or(0, |action| u128::from(action.gas_limit())),
            )
            .ok_or_else(|| NodeError::Tx("required fee overflows".into()))?;
        if tx.fee != expected_fee {
            return Err(NodeError::Tx(format!(
                "fee {0} does not equal the required transfer plus OVM gas fee {expected_fee}",
                tx.fee
            )));
        }
        if let Some(OvmAction::Deploy { code, .. }) = &tx.ovm_action {
            oxydome_ovm::Program::decode(code)
                .map_err(|error| NodeError::Tx(format!("invalid OVM deployment: {error}")))?;
        }
        if let Some(OvmAction::DeployContract { artifact, .. }) = &tx.ovm_action {
            oxydome_ovm::ContractArtifact::decode(artifact).map_err(|error| {
                NodeError::Tx(format!("invalid smart-contract artifact: {error}"))
            })?;
        }
        let pending_gas = self
            .mempool
            .iter()
            .filter_map(|pending| pending.ovm_action.as_ref())
            .try_fold(0u64, |total, action| total.checked_add(action.gas_limit()))
            .ok_or_else(|| NodeError::Tx("mempool OVM gas total overflows".into()))?;
        let total_gas = pending_gas
            .checked_add(tx.ovm_action.as_ref().map_or(0, OvmAction::gas_limit))
            .ok_or_else(|| NodeError::Tx("mempool OVM gas total overflows".into()))?;
        if total_gas > oxydome_core::MAX_OVM_BLOCK_GAS_LIMIT {
            return Err(NodeError::Tx(
                "mempool transactions exceed the block OVM gas limit".into(),
            ));
        }

        let addresses = tx_addresses(&tx);
        for input in &tx.inputs {
            self.mempool_inputs.insert(input.prev_out);
        }
        self.pending.insert(
            txid,
            PendingTx {
                tx: tx.clone(),
                addresses: addresses.clone(),
            },
        );
        self.mempool.push(tx);

        self.emit(NodeEvent::MempoolChanged {
            txid,
            added: true,
            addresses: addresses.clone(),
        });
        self.emit(NodeEvent::TxAccepted { txid, addresses });
        Ok(())
    }

    /// Queues a governance operation for the next block this node produces.
    pub fn submit_operation(&mut self, op: Operation) {
        self.pending_ops.push(op);
    }

    /// Builds the reward distribution for a set of fees from this node's perspective.
    pub fn reward_operation(&self, total_fees: Amount, proposer: &PublicKey) -> Operation {
        let weights = participation_weights(&self.gov.nodes, proposer, 2);
        Operation::Rewards(split_fees(
            total_fees,
            &self.params,
            &self.gov.masters,
            &weights,
        ))
    }

    /// Produces a block if this node is the leader for the next height.
    pub fn produce_block(&mut self, timestamp: u64) -> Result<Block, NodeError> {
        let height = self.next_height();
        if !self.is_leader(height) {
            return Err(NodeError::NotLeader);
        }
        let transactions: Vec<Transaction> = self.mempool.clone();
        let total_fees = self.state.settled_fee_total(&transactions)?;
        let mut operations = self.pending_ops.clone();
        if total_fees > 0 {
            operations.push(self.reward_operation(total_fees, &self.public()));
        }
        let block = self.state.build_block(
            &self.gov,
            &self.params,
            transactions,
            operations,
            self.public(),
            timestamp,
        )?;
        Ok(block)
    }

    /// Builds the audit package (with Merkle proofs) for a proposed block.
    pub fn audit_package(&self, block: &Block) -> Result<AuditPackage, NodeError> {
        let pre_utxo_root = self.state.utxo_root();
        let mut inputs = Vec::new();
        for tx in &block.transactions {
            for input in &tx.inputs {
                let entry = self
                    .state
                    .utxo
                    .get(&input.prev_out)
                    .cloned()
                    .ok_or_else(|| NodeError::Tx(format!("missing input {:?}", input.prev_out)))?;
                let proof = self
                    .state
                    .utxo
                    .proof(&input.prev_out)
                    .ok_or_else(|| NodeError::Tx("missing proof".into()))?;
                inputs.push(InputProof {
                    outpoint: input.prev_out,
                    entry,
                    proof,
                });
            }
        }
        Ok(AuditPackage {
            block: block.clone(),
            pre_utxo_root,
            inputs,
        })
    }

    /// Signs a vote for `block`.
    pub fn vote(&self, block: &Block, kind: VoteKind) -> Result<Vote, NodeError> {
        if block.header.prev_hash != self.state.block_hash {
            return Err(NodeError::NotOnTip);
        }
        self.state.apply_block(block, &self.gov, &self.params)?;
        Ok(Vote::sign(
            &self.key,
            block.header.height,
            0,
            block.hash(),
            kind,
        ))
    }

    /// Signs a `MasterCheck` for the current epoch.
    pub fn master_check(&self) -> MasterCheck {
        MasterCheck::sign(
            &self.key,
            self.epoch,
            oxydome_consensus::masters_root(&self.gov.masters),
        )
    }

    /// Verifies quorums and applies a finalized block.
    pub fn finalize_block(
        &mut self,
        block: Block,
        attestations: &[AuditAttestation],
        commit_qc: &QuorumCertificate,
        master_checks: &[MasterCheck],
    ) -> Result<(), NodeError> {
        if block.header.prev_hash != self.state.block_hash {
            return Err(NodeError::NotOnTip);
        }
        if !attestation_quorum(&block, attestations, &self.gov, &self.params) {
            return Err(NodeError::NoAttestationQuorum);
        }
        if commit_qc.height != block.header.height
            || commit_qc.block_hash != block.hash()
            || !commit_qc.has_quorum(&self.gov, &self.params)
        {
            return Err(NodeError::BadCommitCertificate);
        }
        let expected_root = oxydome_consensus::masters_root(&self.gov.masters);
        if !oxydome_consensus::votes::master_check_quorum(
            master_checks,
            block.header.epoch,
            expected_root,
            &self.gov,
            &self.params,
        ) {
            return Err(NodeError::NoMasterCheckQuorum);
        }

        let next = self.state.apply_block(&block, &self.gov, &self.params)?;

        // Persist the new version before swapping it in: a failed store write leaves the node
        // unchanged and retryable.
        if let Some(store) = &mut self.store {
            let delta = ledger_diff(&self.state.utxo, &next.utxo);
            store
                .save_version_with_ovm_and_block(
                    next.height,
                    block.hash(),
                    &next.utxo,
                    &delta,
                    &next.contracts,
                    &block,
                )
                .map_err(|e| NodeError::Ledger(e.to_string()))?;
        }

        // Fold this block's effects into the wallet index and persist its snapshot.
        self.wallet_index.record_block(&block, &self.state.utxo);
        if let Some(store) = &self.index_store {
            store
                .save(&self.wallet_index)
                .map_err(|e| NodeError::Ledger(e.to_string()))?;
        }

        // ---- Wallet-facing event bookkeeping ----
        let spent_now: BTreeSet<OutPoint> = block
            .transactions
            .iter()
            .flat_map(|t| t.inputs.iter().map(|i| i.prev_out))
            .collect();

        // Confirm the block's transactions, dropping them from the mempool.
        for (position, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            self.pending.remove(&txid);
            let addresses = tx_addresses(tx);
            self.emit(NodeEvent::TxConfirmed {
                txid,
                location: TxLocation {
                    height: block.header.height,
                    block_hash: block.hash(),
                    position: position as u32,
                },
                addresses: addresses.clone(),
            });
            self.emit(NodeEvent::MempoolChanged {
                txid,
                added: false,
                addresses,
            });
        }
        self.emit(NodeEvent::BlockCommitted {
            height: block.header.height,
            block_hash: block.hash(),
            txids: block.transactions.iter().map(|t| t.txid()).collect(),
        });

        // Reject pending transactions whose inputs were spent by this block.
        let conflicting: Vec<(Hash, String)> = {
            let mut out = Vec::new();
            for txid in self.pending.keys().copied().collect::<Vec<Hash>>() {
                let tx = &self.pending[&txid].tx;
                if tx.inputs.iter().any(|i| spent_now.contains(&i.prev_out)) {
                    let reason = format!(
                        "inputs were spent by a conflicting transaction in block {}",
                        block.header.height
                    );
                    out.push((txid, reason));
                }
            }
            out
        };
        for (txid, reason) in conflicting {
            if let Some(pending) = self.pending.remove(&txid) {
                self.push_rejected(txid, pending.tx, reason.clone());
                let addresses = pending.addresses;
                self.emit(NodeEvent::TxRejected {
                    txid,
                    reason,
                    addresses: addresses.clone(),
                });
                self.emit(NodeEvent::MempoolChanged {
                    txid,
                    added: false,
                    addresses,
                });
            }
        }

        // Remove applied and rejected transactions from the mempool, then reclean claimed inputs.
        let applied: BTreeSet<Hash> = block.transactions.iter().map(|t| t.txid()).collect();
        self.mempool.retain(|t| !applied.contains(&t.txid()));
        let active: BTreeSet<Hash> = self.pending.keys().copied().collect();
        self.mempool.retain(|t| active.contains(&t.txid()));
        self.mempool_inputs = self
            .mempool
            .iter()
            .flat_map(|t| t.inputs.iter().map(|i| i.prev_out))
            .collect();
        let applied_ops: BTreeSet<Hash> = block.operations.iter().map(|o| o.id()).collect();
        self.pending_ops.retain(|o| !applied_ops.contains(&o.id()));

        self.state = next;
        self.blocks.push(block.clone());
        self.epoch = block.header.epoch;
        Ok(())
    }

    /// Records a rejection, bounding the retained set to [`REJECTED_LIMIT`].
    fn push_rejected(&mut self, txid: Hash, tx: Transaction, reason: String) {
        while self.rejected_order.len() >= REJECTED_LIMIT {
            if let Some(oldest) = self.rejected_order.pop_front() {
                self.rejected.remove(&oldest);
            }
        }
        self.rejected_order.push_back(txid);
        self.rejected.insert(txid, (tx, reason));
    }

    /// Convenience: the outpoint of a spendable output owned by `owner`, for tests/tooling.
    pub fn find_spendable(&self, owner: &PublicKey) -> Option<(OutPoint, Amount)> {
        self.state
            .utxo
            .iter()
            .find(|e| e.output.recipient == *owner && e.output.kind.is_spendable())
            .map(|e| (e.outpoint, e.output.amount))
    }

    /// Current balances for `owner`, classified by output kind.
    pub fn balance(&self, owner: &PublicKey) -> BalanceInfo {
        let next = self.next_height();
        let mut spendable = 0u128;
        let mut locked_reward = 0u128;
        let mut exit_reserve = 0u128;
        for entry in self.state.utxo.iter() {
            if &entry.output.recipient != owner {
                continue;
            }
            if entry.output.kind.is_spendable() {
                if rebound_utxo_spendable(
                    next,
                    entry.created_height,
                    entry.output.rebound_gen,
                    &self.params,
                ) {
                    spendable = spendable.saturating_add(entry.output.amount);
                }
            } else if entry.output.kind.is_locked_reward() {
                locked_reward = locked_reward.saturating_add(entry.output.amount);
            } else {
                exit_reserve = exit_reserve.saturating_add(entry.output.amount);
            }
        }
        BalanceInfo {
            spendable,
            locked_reward,
            exit_reserve,
            height: self.state.height,
        }
    }

    /// Every live UTXO owned by `owner`.
    pub fn utxos(&self, owner: &PublicKey) -> Vec<UtxoInfo> {
        let next = self.next_height();
        self.state
            .utxo
            .iter()
            .filter(|e| &e.output.recipient == owner)
            .map(|e| UtxoInfo {
                outpoint: e.outpoint,
                amount: e.output.amount,
                recipient: e.output.recipient,
                kind: e.output.kind.clone(),
                created_height: e.created_height,
                mature: rebound_utxo_spendable(
                    next,
                    e.created_height,
                    e.output.rebound_gen,
                    &self.params,
                ),
            })
            .collect()
    }

    /// The block at `height`, if known (genesis is height 0).
    pub fn block_by_height(&self, height: u64) -> Option<Block> {
        self.blocks.get(height as usize).cloned()
    }

    /// The status of a transaction: its confirmed location, pending mempool state, or unknown.
    pub fn transaction(&self, txid: &Hash) -> (Option<Transaction>, Option<TxLocation>, TxStatus) {
        if let Some(location) = self.wallet_index.by_txid.get(txid) {
            if let Some(block) = self.blocks.get(location.height as usize) {
                if let Some(tx) = block.transactions.get(location.position as usize) {
                    if &tx.txid() == txid {
                        return (
                            Some(tx.clone()),
                            Some(*location),
                            TxStatus::Confirmed {
                                height: location.height,
                            },
                        );
                    }
                }
            }
        }
        if let Some(pending) = self.pending.get(txid) {
            return (Some(pending.tx.clone()), None, TxStatus::Pending);
        }
        if let Some((tx, reason)) = self.rejected.get(txid) {
            return (
                Some(tx.clone()),
                None,
                TxStatus::Rejected {
                    reason: reason.clone(),
                },
            );
        }
        (None, None, TxStatus::Unknown)
    }

    /// The inclusion entry and sparse-Merkle proof for `outpoint`, if it is still unspent.
    pub fn utxo_proof(&self, outpoint: &OutPoint) -> (Option<UtxoEntry>, Option<SparseProof>) {
        let entry = self.state.utxo.get(outpoint).cloned();
        let proof = self.state.utxo.proof(outpoint);
        (entry, proof)
    }

    /// Wallet-relevant history for `owner` at heights >= `cursor`. `limit` is clamped to
    /// `[1, 200]` (0 means the default of 50); the returned cursor resumes after the last row.
    pub fn history(&self, owner: &PublicKey, cursor: u64, limit: u32) -> (Vec<HistoryEntry>, u64) {
        let limit = if limit == 0 { 50 } else { limit.min(200) } as usize;
        let mut entries: Vec<HistoryEntry> = Vec::new();
        if let Some(by_pos) = self.wallet_index.by_addr.get(owner) {
            for (_, entry) in by_pos.range((cursor, 0)..) {
                if entries.len() >= limit {
                    break;
                }
                entries.push(entry.clone());
            }
        }
        let next_cursor = entries.last().map(|e| e.height + 1).unwrap_or(cursor);
        (entries, next_cursor)
    }

    /// Snapshot of the value index and supply accounting.
    pub fn value_index(&self) -> ValueIndexInfo {
        ValueIndexInfo {
            value_index: self.state.value_index.raw(),
            generation: self.state.generation,
            supply: self.state.supply,
            height: self.state.height,
        }
    }

    pub fn ovm_code(&self, contract_id: &Hash) -> Option<Vec<u8>> {
        self.state
            .contracts
            .get(contract_id)
            .map(|contract| contract.code.clone())
    }

    pub fn ovm_call(
        &self,
        contract_id: &Hash,
        arguments: &[u64],
        gas_limit: u64,
    ) -> Result<oxydome_ovm::Execution, String> {
        if gas_limit == 0 || gas_limit > oxydome_core::tx::MAX_OVM_GAS_LIMIT {
            return Err("OVM gas limit is outside the consensus bounds".into());
        }
        if arguments.len() > oxydome_core::MAX_OVM_ARGUMENTS {
            return Err("OVM call exceeds the 64-argument limit".into());
        }
        let contract = self
            .state
            .contracts
            .get(contract_id)
            .ok_or_else(|| format!("contract {contract_id} does not exist"))?;
        let program =
            oxydome_ovm::Program::decode(&contract.code).map_err(|error| error.to_string())?;
        if gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS {
            return Err("OVM gas limit is below the action intrinsic cost".into());
        }
        let mut execution = oxydome_ovm::execute(
            &program,
            arguments,
            &contract.storage,
            gas_limit - oxydome_ovm::ACTION_INTRINSIC_GAS,
        )
        .map_err(|failure| failure.to_string())?;
        execution.gas_used += oxydome_ovm::ACTION_INTRINSIC_GAS;
        Ok(execution)
    }

    pub fn ovm_contract_call(
        &self,
        contract_id: &Hash,
        entry_point: &str,
        arguments: &[u64],
        caller: PublicKey,
        gas_limit: u64,
    ) -> Result<oxydome_ovm::Execution, String> {
        let intrinsic_gas = oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
        if gas_limit < intrinsic_gas || gas_limit > oxydome_core::tx::MAX_OVM_GAS_LIMIT {
            return Err("OVM gas limit is outside the consensus bounds".into());
        }
        if arguments.len() + oxydome_ovm::AUTHORITY_WORD_COUNT > oxydome_ovm::MAX_ARGUMENTS {
            return Err("OVM contract call exceeds the argument limit".into());
        }
        let contract = self
            .state
            .contracts
            .get(contract_id)
            .ok_or_else(|| format!("contract {contract_id} does not exist"))?;
        let artifact =
            oxydome_ovm::ContractArtifact::decode(&contract.code).map_err(|e| e.to_string())?;
        let function = artifact
            .function(entry_point)
            .ok_or_else(|| format!("contract function `{entry_point}` does not exist"))?;
        if function.inputs.len() != arguments.len() {
            return Err("contract call argument count does not match its interface".into());
        }

        let mut execution_arguments: Vec<u64> = caller
            .0
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte public-key chunk")))
            .collect();
        execution_arguments.extend_from_slice(arguments);
        let program = oxydome_ovm::Program::decode(&function.code).map_err(|e| e.to_string())?;
        let mut execution = oxydome_ovm::execute(
            &program,
            &execution_arguments,
            &contract.storage,
            gas_limit - intrinsic_gas,
        )
        .map_err(|failure| failure.to_string())?;
        execution.gas_used += intrinsic_gas;
        Ok(execution)
    }

    /// The manifest of this node's software.
    pub fn code_manifest(&self, files: &[(&str, &[u8])]) -> CodeManifest {
        let entries = files
            .iter()
            .map(|(p, b)| ((*p).to_string(), b.to_vec()))
            .collect::<Vec<_>>();
        CodeManifest::from_files(entries)
    }
}

/// The canonical manifest of the reference node binary. Omitting file contents keeps admission
/// deterministic: the masters approve this root and it never changes between rebuilds.
pub fn reference_manifest() -> CodeManifest {
    CodeManifest::from_files(vec![(
        "oxydome-node".to_string(),
        oxydome_core::config::reference_manifest_tag().to_vec(),
    )])
}

/// The deduplicated set of addresses a transaction involves (input owners and output
/// recipients), used for event routing.
fn tx_addresses(tx: &Transaction) -> Vec<PublicKey> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for pk in tx
        .inputs
        .iter()
        .map(|i| i.owner)
        .chain(tx.outputs.iter().map(|o| o.recipient))
    {
        if seen.insert(pk) {
            out.push(pk);
        }
    }
    out
}

/// Builds a fresh default network configuration with `masters` masters, `nodes` server nodes and
/// a genesis supply of `supply`. Used by the binaries' `init` command.
pub fn default_config(masters: usize, nodes: usize, supply: Amount) -> oxydome_core::AppConfig {
    use oxydome_core::{AllocationConfig, AppConfig, EndpointConfig};
    let mut params = oxydome_core::ChainParams::default_local();
    params.genesis_supply = supply;
    let make_endpoint = |prefix: &str, i: usize| {
        let key = KeyPair::generate();
        EndpointConfig {
            name: format!("{prefix}-{i}"),
            key: key.public().to_hex(),
            seed: Some(hex::encode(key.secret_seed())),
            addr: String::new(),
        }
    };
    let master_eps: Vec<EndpointConfig> =
        (0..masters).map(|i| make_endpoint("master", i)).collect();
    let node_eps: Vec<EndpointConfig> = (0..nodes).map(|i| make_endpoint("node", i)).collect();
    let share = supply / (nodes as u128 + 1);
    let mut allocations: Vec<AllocationConfig> = node_eps
        .iter()
        .map(|n| AllocationConfig {
            recipient: n.key.clone(),
            amount: share,
        })
        .collect();
    let node_total = share.saturating_mul(nodes as u128);
    allocations.push(AllocationConfig {
        recipient: master_eps[0].key.clone(),
        amount: supply.saturating_sub(node_total),
    });
    AppConfig {
        params,
        timestamp: 0,
        allocations,
        masters: master_eps,
        nodes: node_eps,
        approved_manifests: vec![reference_manifest().root().to_hex()],
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use oxydome_core::{Operation, OvmAction, Transaction, TxOutput};
    use oxydome_rewards::split_fees;

    #[test]
    fn restores_and_replays_persisted_block_history() {
        let app_config = default_config(1, 1, 100_000);
        let genesis_config = app_config.genesis().unwrap();
        let key = app_config.nodes[0].keypair().unwrap();
        let (node, genesis) = Node::new(key.clone(), &genesis_config, None).unwrap();

        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis_with_block(&genesis, &node.state.utxo, &node.state.contracts)
            .unwrap();
        let (input, amount) = node
            .state
            .utxo
            .iter()
            .find(|entry| entry.output.recipient == node.public())
            .map(|entry| (entry.outpoint, entry.output.amount))
            .unwrap();
        let program = oxydome_ovm::Program {
            argument_count: oxydome_ovm::AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::Push(7),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let artifact = oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "read".into(),
                inputs: Vec::new(),
                output: Some(oxydome_ovm::ContractValueType::U64),
                code: program,
            }],
        }
        .encode()
        .unwrap();
        let gas_limit = 1_000;
        let fee = 1 + u128::from(gas_limit);
        let mut deployment = Transaction::new_unsigned(
            vec![(input, node.public())],
            vec![TxOutput::spendable(amount - fee, node.public())],
            fee,
        );
        deployment.ovm_action = Some(OvmAction::DeployContract {
            artifact,
            gas_limit,
        });
        deployment.sign_input(0, &key);
        let contract_id = oxydome_ovm::contract_id(deployment.txid());
        let fees = node.state.settled_fee_total(&[deployment.clone()]).unwrap();
        let rewards = split_fees(fees, &node.params, &node.gov.masters, &[(node.public(), 1)]);
        let block = node
            .state
            .build_block(
                &node.gov,
                &node.params,
                vec![deployment],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1,
            )
            .unwrap();
        let next = node
            .state
            .apply_block(&block, &node.gov, &node.params)
            .unwrap();
        store
            .save_version_with_ovm_and_block(
                next.height,
                block.hash(),
                &next.utxo,
                &ledger_diff(&node.state.utxo, &next.utxo),
                &next.contracts,
                &block,
            )
            .unwrap();

        let (fresh_node, _) = Node::new(key, &genesis_config, None).unwrap();
        let restored = fresh_node.restore_from_store(store, None).unwrap();
        assert_eq!(restored.state.height, 1);
        assert_eq!(restored.state.block_hash, block.hash());
        assert_eq!(restored.state.state_root(), next.state_root());
        assert_eq!(restored.state.contracts, next.contracts);
        assert!(restored.state.contracts.contains_key(&contract_id));
        assert_eq!(restored.blocks, vec![genesis, block]);
    }
}
