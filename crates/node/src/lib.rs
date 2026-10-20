//! Server node: holds the full chain, validates transactions, produces blocks when it is the
//! Proof-of-Authority leader, builds audit packages for the masters, and finalizes blocks once
//! BFT and `MasterCheck` quorums are present.

pub mod async_verify;
pub mod content_store;
pub mod index;
pub mod server;
pub mod storage;

use crate::content_store::ContentStore;
use crate::index::{IndexStore, WalletIndex};
use crate::storage::{Labeler, LabelerConfig};
use oxydome_audit::{attestation_quorum, AuditAttestation, AuditPackage, InputProof};
use oxydome_consensus::{AdmissionCertificate, MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_core::StorageLabel;
use oxydome_core::{
    Amount, Block, BlockRewardDistribution, ChainParams, FileAccessOperation, FileAccessRecord,
    FileDeleteOperation, FileEvkLabel, FileStoreOperation, GenesisConfig, GovernanceSet, Hash,
    InboundReceipt, OhmAction, OhmBlock, OhmPolicy, OhmState, Operation, OutPoint, OvmAction,
    PublicKey, Transaction,
};
use oxydome_crypto::evk::EphemeralKeyManager;
use oxydome_crypto::{hash_value, verify, CodeManifest, KeyPair, SparseProof};
use oxydome_currency::rebound_utxo_spendable;
use oxydome_net::{
    BalanceInfo, FinalityEvidence, FinalizedBlockRecord, HistoryEntry, NodeEvent, TxLocation,
    TxStatus, UtxoInfo, ValueIndexInfo,
};
use oxydome_ohm::{CrossChainView, OhmCallOutcome, OhmContract, OhmLedger, OutboundMessage};
use oxydome_rewards::{
    build_block_reward_operation, calculate_master_block_rewards, calculate_server_block_rewards,
    participation_weights, split_fees,
};
use oxydome_state::{ledger_diff, ChainState, LedgerStore, StateError, UtxoEntry};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use tokio::sync::broadcast;

/// Errors raised by a node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("transaction rejected: {0}")]
    Tx(String),
    #[error("operation rejected: {0}")]
    Operation(String),
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
pub const MAX_PENDING_OPERATIONS: usize = 10_000;

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
    /// Finality certificates retained for safe peer history serving.
    pub finality_evidence: BTreeMap<u64, FinalityEvidence>,
    pub mempool: Vec<Transaction>,
    pub pending_ops: Vec<Operation>,
    pub admission: Option<AdmissionCertificate>,
    pub manifest_root: Hash,
    pub epoch: u64,
    /// Previous block's total server reward for master reward derivative calculation.
    prev_server_block_reward: Option<Amount>,
    /// Durable ledger store, when persistence is attached.
    pub store: Option<LedgerStore>,
    /// Wallet-facing index of transaction locations and per-address history.
    pub wallet_index: WalletIndex,
    /// Durable snapshot store for the wallet index.
    pub index_store: Option<IndexStore>,
    /// Optional asset storage, deliberately excluded from consensus state.
    pub content_store: ContentStore,
    /// Private OHM ledgers this node keeps and re-derives, keyed by OHM id.
    pub ohm_ledgers: BTreeMap<Hash, OhmLedger>,
    /// Private OHM block bodies, content-addressed by block hash and served to peers.
    pub ohm_blocks: BTreeMap<Hash, OhmBlock>,
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
    /// Storage labeler for network capacity reporting.
    labeler: Labeler,
    /// Coin-toss seed received from the consensus phase; `None` for legacy blocks.
    pub coin_toss_seed: Option<Hash>,
    /// The node's private auction pool: the swap transactions that were offered for the
    /// verification-credit auction, keyed by bundle id.
    ///
    /// These transactions are deliberately **not** part of the public mempool: a swap that
    /// sits in the open mempool can be sandwiched. They are only revealed when the auction
    /// clears and the winning node executes the bundle.
    pub auction_pool: BTreeMap<Hash, Vec<Transaction>>,
    /// The bundles this node has registered for auction, keyed by bundle id.
    pub auction_targets: BTreeMap<Hash, Operation>,
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
            key: key.clone(),
            gov,
            params: config.params.clone(),
            state,
            blocks: vec![genesis.clone()],
            finality_evidence: BTreeMap::new(),
            mempool: Vec::new(),
            pending_ops: Vec::new(),
            admission,
            manifest_root,
            epoch: 0,
            prev_server_block_reward: None,
            store: None,
            wallet_index: WalletIndex::new(),
            index_store: None,
            content_store: ContentStore::default(),
            ohm_ledgers: BTreeMap::new(),
            ohm_blocks: BTreeMap::new(),
            pending: HashMap::new(),
            rejected: HashMap::new(),
            rejected_order: VecDeque::new(),
            mempool_inputs: BTreeSet::new(),
            events: broadcast::channel(2048).0,
            coin_toss_seed: None,
            auction_pool: BTreeMap::new(),
            auction_targets: BTreeMap::new(),
            labeler: Labeler::new(LabelerConfig {
                node_keypair: key.clone(),
                node_public: key.public(),
                capacity_bytes: 0,
                data_dir: std::path::PathBuf::new(),
                content_store_root: std::path::PathBuf::new(),
                index_store_path: std::path::PathBuf::new(),
            }),
        };
        Ok((node, genesis))
    }

    /// Sets the coin-toss seed for block production.
    pub fn set_coin_toss_seed(&mut self, seed: Option<Hash>) {
        self.coin_toss_seed = seed;
    }
    pub fn with_storage_capacity(
        mut self,
        capacity_bytes: u64,
        data_dir: std::path::PathBuf,
        content_store_root: std::path::PathBuf,
        index_store_path: std::path::PathBuf,
    ) -> Self {
        self.labeler = Labeler::new(LabelerConfig {
            node_keypair: self.key.clone(),
            node_public: self.key.public(),
            capacity_bytes,
            data_dir,
            content_store_root,
            index_store_path,
        });
        self
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

    /// Returns the storage labeler used to publish this node's available capacity.
    pub fn storage_labeler(&self) -> Option<&Labeler> {
        if self.labeler.capacity() == 0 {
            None
        } else {
            Some(&self.labeler)
        }
    }

    /// Generates and records a fresh storage label at the given height.
    pub fn refresh_storage_label(&self, height: u64, timestamp: u64) -> StorageLabel {
        let label = self.labeler.generate_label(height, timestamp);
        self.labeler.update_last_label(height, timestamp, &label);
        label
    }

    /// Stores file content in the local content store.
    pub fn put_file_content(&mut self, hash: Hash, bytes: Vec<u8>) -> Result<(), NodeError> {
        self.content_store
            .put(hash, bytes)
            .map_err(|e| NodeError::Operation(e.to_string()))
    }

    /// Retrieves file content from the local content store.
    pub fn get_file_content(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.content_store.get(hash).map(|b| b.to_vec())
    }

    /// Creates and signs a `FileEvkLabel` for the given content hash and chain context.
    pub fn create_file_label(
        &self,
        content_hash: Hash,
        size: u64,
        previous_commitment: Hash,
        height: u64,
        block_hash: Hash,
        block_params: &ChainParams,
    ) -> Result<FileEvkLabel, NodeError> {
        if self.state.height + 1 < block_params.file_system_activation_height {
            return Err(NodeError::Operation("file system is not yet active".into()));
        }
        let key_chain_commitment = EphemeralKeyManager::compute_file_key_chain_commitment(
            previous_commitment,
            content_hash,
            height,
            block_hash,
        );
        let commitment = oxydome_crypto::hash_value(&FileEvkLabel {
            content_hash,
            key_chain_commitment,
            node: self.key.public(),
            block_height: height,
            block_hash,
            previous_commitment,
            size,
            signature: oxydome_crypto::Sig([0u8; 64]),
        });
        let signature = self.key.sign(&commitment.0);
        Ok(FileEvkLabel {
            content_hash,
            key_chain_commitment,
            node: self.key.public(),
            block_height: height,
            block_hash,
            previous_commitment,
            size,
            signature,
        })
    }

    /// Submits a `FileStoreOperation` to the mempool.
    pub fn submit_file_store_operation(
        &mut self,
        label: FileEvkLabel,
        approvals: Vec<oxydome_core::NodeApproval>,
    ) -> Result<Hash, NodeError> {
        let op = Operation::FileStore(FileStoreOperation {
            file_label: label,
            approvals,
        });
        let op_id = op.id();
        self.submit_operation(op)?;
        Ok(op_id)
    }

    /// Submits a `FileAccessOperation` to the mempool.
    pub fn submit_file_access_operation(
        &mut self,
        file_id: Hash,
        content_hash: Hash,
        timestamp: u64,
    ) -> Result<Hash, NodeError> {
        let accessor = self.key.public();
        let op = Operation::FileAccess(FileAccessOperation {
            file_id,
            content_hash,
            accessor,
            signature: oxydome_crypto::Sig([0u8; 64]),
            timestamp,
        });
        let proposal_id = op.proposal_id();
        let signature = self.key.sign(&proposal_id.0);
        let op = Operation::FileAccess(FileAccessOperation {
            file_id,
            content_hash,
            accessor,
            signature,
            timestamp,
        });
        let op_id = op.id();
        self.submit_operation(op)?;
        Ok(op_id)
    }

    /// Submits a `FileDeleteOperation` to the mempool.
    pub fn submit_file_delete_operation(
        &mut self,
        file_id: Hash,
        content_hash: Hash,
    ) -> Result<Hash, NodeError> {
        let deleter = self.key.public();
        let op = Operation::FileDelete(FileDeleteOperation {
            file_id,
            content_hash,
            deleter,
            signature: oxydome_crypto::Sig([0u8; 64]),
        });
        let proposal_id = op.proposal_id();
        let signature = self.key.sign(&proposal_id.0);
        let op = Operation::FileDelete(FileDeleteOperation {
            file_id,
            content_hash,
            deleter,
            signature,
        });
        let op_id = op.id();
        self.submit_operation(op)?;
        Ok(op_id)
    }

    /// Queries the on-chain file label by its key chain commitment.
    pub fn file_label(&self, commitment: Hash) -> Option<&FileEvkLabel> {
        self.state.file_labels.get(&commitment)
    }

    /// Returns the access records for a file (all records whose `file_id` matches).
    pub fn file_access_log(&self, file_id: Hash) -> Vec<&FileAccessRecord> {
        self.state
            .file_access_log
            .values()
            .filter(|r| r.file_id == file_id)
            .collect()
    }

    /// Updates the labeler's file metadata from on-chain state.
    pub fn sync_file_metadata(&self) {
        let mut file_count: u64 = 0;
        let mut file_storage_bytes: u64 = 0;
        let mut labels: Vec<FileEvkLabel> = Vec::new();
        for label in self.state.file_labels.values() {
            labels.push(label.clone());
            file_count += 1;
            file_storage_bytes += label.size;
        }
        let file_root = if labels.is_empty() {
            None
        } else {
            Some(self.labeler.compute_file_root(&labels))
        };
        self.labeler
            .update_file_metadata(file_root, file_count, file_storage_bytes);
    }

    /// Returns the node's file root, file count and file storage bytes.
    pub fn node_file_root(&self) -> (Option<Hash>, u64, u64) {
        self.labeler.file_metadata()
    }

    fn verify_finality_evidence(
        &self,
        block: &Block,
        evidence: &FinalityEvidence,
    ) -> Result<(), NodeError> {
        if !attestation_quorum(block, &evidence.attestations, &self.gov, &self.params) {
            return Err(NodeError::NoAttestationQuorum);
        }
        let prepare = &evidence.prepare_qc;
        let commit = &evidence.commit_qc;
        if prepare.height != block.header.height
            || prepare.block_hash != block.hash()
            || prepare.kind != VoteKind::Prepare
            || !prepare.has_quorum(&self.gov, &self.params)
            || commit.height != block.header.height
            || commit.block_hash != block.hash()
            || commit.kind != VoteKind::Commit
            || commit.view != prepare.view
            || !commit.has_quorum(&self.gov, &self.params)
        {
            return Err(NodeError::BadCommitCertificate);
        }
        let expected_root = oxydome_consensus::masters_root(&self.gov.masters);
        if !oxydome_consensus::votes::master_check_quorum(
            &evidence.master_checks,
            block.header.epoch,
            expected_root,
            &self.gov,
            &self.params,
        ) {
            return Err(NodeError::NoMasterCheckQuorum);
        }
        Ok(())
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

        // Load private OHM block bodies before replaying anchors that reference them.
        self.ohm_blocks = store
            .load_ohm_blocks()
            .map_err(|error| NodeError::Ledger(error.to_string()))?
            .into_iter()
            .map(|block| (block.hash(), block))
            .collect();

        let mut restored_index = WalletIndex::new();
        let mut restored_evidence = BTreeMap::new();
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
            self.ohm_ledgers = self.advance_ohm_ledgers(block)?;
            self.verify_persisted_height(&store, block)?;
            if let Some(bytes) = store
                .finality_evidence(block.header.height)
                .map_err(|error| NodeError::Ledger(error.to_string()))?
            {
                let evidence: FinalityEvidence = bincode::deserialize(&bytes).map_err(|error| {
                    NodeError::Ledger(format!(
                        "invalid persisted finality evidence at height {}: {error}",
                        block.header.height
                    ))
                })?;
                self.verify_finality_evidence(block, &evidence)
                    .map_err(|error| {
                        NodeError::Ledger(format!(
                            "invalid persisted finality evidence at height {}: {error}",
                            block.header.height
                        ))
                    })?;
                restored_evidence.insert(block.header.height, evidence);
            }
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
            || store
                .load_dao_state(current_height)
                .map_err(|error| NodeError::Ledger(error.to_string()))?
                != self.state.daos
        {
            return Err(NodeError::Ledger(
                "persisted tip snapshots do not match replayed state".into(),
            ));
        }
        let (gas, gas_supply, ox_price, last_airdrop_height) = store
            .load_gas_state(current_height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        self.state.gas = gas;
        self.state.gas_supply = gas_supply;
        self.state.ox_price = ox_price;
        self.state.last_airdrop_height = last_airdrop_height;

        self.blocks = blocks;
        self.finality_evidence = restored_evidence;
        self.wallet_index = restored_index;
        self.store = Some(store);
        self.index_store = index_store;
        if let Some(index_store) = &self.index_store {
            index_store.save(&self.wallet_index)?;
        }
        Ok(self)
    }

    /// Builds the authenticated history records needed to serve peer catch-up.
    pub fn finalized_blocks_from(
        &self,
        from_height: u64,
        limit: u8,
    ) -> Result<Vec<FinalizedBlockRecord>, String> {
        if from_height == 0 {
            return Err("finalized history starts after the configured genesis".into());
        }
        if limit == 0 || limit > 32 {
            return Err("finalized history batch limit must be between 1 and 32".into());
        }
        self.blocks
            .iter()
            .filter(|block| block.header.height >= from_height)
            .take(limit as usize)
            .map(|block| {
                let evidence = self
                    .finality_evidence
                    .get(&block.header.height)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "finality evidence is unavailable at height {}",
                            block.header.height
                        )
                    })?;
                self.verify_finality_evidence(block, &evidence)
                    .map_err(|error| {
                        format!(
                            "invalid finality evidence at height {}: {error}",
                            block.header.height
                        )
                    })?;
                Ok(FinalizedBlockRecord {
                    block: block.clone(),
                    evidence,
                })
            })
            .collect()
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
        let daos = store
            .load_dao_state(height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        if daos != self.state.daos {
            return Err(NodeError::Ledger(format!(
                "persisted DAO snapshot does not match replay at height {height}"
            )));
        }
        let ohm_states = store
            .load_ohm_state(height)
            .map_err(|error| NodeError::Ledger(error.to_string()))?;
        if ohm_states != self.state.ohm_states {
            return Err(NodeError::Ledger(format!(
                "persisted OHM snapshot does not match replay at height {height}"
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
        let stack_gas_val = tx.ovm_action.as_ref().map_or(0u64, |a| {
            a.required_stack_gas(self.params.ovm_stack_bytes_per_gas)
        });
        let legacy_fee = base_fee
            .checked_add(u128::from(stack_gas_val))
            .ok_or_else(|| NodeError::Tx("required fee overflows".into()))?;
        let expected_fee = if next_height >= self.params.gas_activation_height {
            base_fee
        } else {
            legacy_fee
        };
        if tx.fee != expected_fee && tx.fee != legacy_fee {
            return Err(NodeError::Tx(format!(
                "fee {0} does not equal the required fee {expected_fee}",
                tx.fee
            )));
        }
        if next_height >= self.params.gas_activation_height && tx.fee == base_fee {
            if let Some(action) = &tx.ovm_action {
                if let Some(caller) = tx.inputs.first().map(|i| &i.owner) {
                    let sg = action.required_stack_gas(self.params.ovm_stack_bytes_per_gas);
                    if self.state.gas_balance(caller) < u128::from(sg) {
                        return Err(NodeError::Tx(
                            "insufficient GAS balance for OVM execution".into(),
                        ));
                    }
                }
            }
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
            .try_fold(0u64, |total, action| {
                total.checked_add(action.required_stack_gas(self.params.ovm_stack_bytes_per_gas))
            })
            .ok_or_else(|| NodeError::Tx("mempool OVM gas total overflows".into()))?;
        let total_gas = pending_gas
            .checked_add(tx.ovm_action.as_ref().map_or(0, |a| {
                a.required_stack_gas(self.params.ovm_stack_bytes_per_gas)
            }))
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

    /// The verification-credit balance of this node.
    ///
    /// Verification credits are a non-financial unit earned by taking part in block
    /// verification. They are spent in the verification-credit auction.
    pub fn verification_credits(&self) -> u64 {
        self.state.verification_credit_balance(&self.public())
    }

    /// The verification-credit balances of every server node, keyed by node public key.
    pub fn verification_credit_balances(&self) -> BTreeMap<PublicKey, u64> {
        self.state.auction.credits.clone()
    }

    /// Offers a bundle of swap transactions for the verification-credit auction.
    ///
    /// The swaps are kept in the node's private auction pool instead of the public mempool,
    /// so the trade is not visible to sandwichers. The bundle is registered on-chain by a
    /// signed [`oxydome_core::AuctionTargetOperation`], which commits to the bundle id and
    /// the public swap summary but not to the transactions themselves.
    ///
    /// Returns the bundle id.
    pub fn submit_auction_target(
        &mut self,
        swaps: Vec<Transaction>,
        intent: oxydome_core::SwapIntent,
    ) -> Result<Hash, NodeError> {
        if swaps.is_empty() {
            return Err(NodeError::Operation(
                "an auction bundle must contain at least one swap".into(),
            ));
        }
        let mut txids = Vec::with_capacity(swaps.len());
        for tx in &swaps {
            tx.validate_structure()
                .map_err(|e| NodeError::Tx(e.to_string()))?;
            let txid = tx.txid();
            if self.mempool.iter().any(|pending| pending.txid() == txid) {
                return Err(NodeError::Tx(
                    "the swap is already in the public mempool".into(),
                ));
            }
            txids.push(txid);
        }
        let target = oxydome_core::auction_bundle_id(&txids);
        if self.state.auction.targets.contains_key(&target) {
            return Err(NodeError::Operation(
                "the bundle is already registered for auction".into(),
            ));
        }
        let mut operation = oxydome_core::AuctionTargetOperation {
            target,
            swaps: txids,
            intent,
            registrar: self.public(),
            nonce: self.state.height,
            signature: oxydome_crypto::Sig([0u8; 64]),
        };
        // The registration is signed by the node that submits it.
        let proposal_id = Operation::AuctionTarget(operation.clone()).proposal_id();
        operation.signature = self.key.sign(&proposal_id.0);
        let op = Operation::AuctionTarget(operation);
        self.submit_operation(op.clone())?;
        self.auction_pool.insert(target, swaps);
        self.auction_targets.insert(target, op);
        Ok(target)
    }

    /// Places a bid for the right to execute an auctioned swap bundle.
    ///
    /// The bid is denominated in verification credits, which are escrowed when the bid is
    /// applied and burned if the bid wins. Losing bids are refunded when the auction
    /// clears.
    pub fn submit_auction_bid(&mut self, target: Hash, amount: u64) -> Result<(), NodeError> {
        if !self.state.auction.targets.contains_key(&target) {
            return Err(NodeError::Operation(
                "the auction target is not registered".into(),
            ));
        }
        if amount < self.params.auction_min_bid || amount > self.params.auction_max_bid {
            return Err(NodeError::Operation(format!(
                "the bid must be between {} and {} credits",
                self.params.auction_min_bid, self.params.auction_max_bid
            )));
        }
        if self.verification_credits() < amount {
            return Err(NodeError::Operation(
                "not enough verification credits for this bid".into(),
            ));
        }
        let mut bid = oxydome_core::AuctionBidOperation {
            bidder: self.public(),
            target,
            amount,
            nonce: self.state.height,
            signature: oxydome_crypto::Sig([0u8; 64]),
        };
        let proposal_id = Operation::AuctionBid(bid.clone()).proposal_id();
        bid.signature = self.key.sign(&proposal_id.0);
        self.submit_operation(Operation::AuctionBid(bid))
    }

    /// The swap bundles this node won at auction and may still execute.
    pub fn won_auction_bundles(&self) -> Vec<(Hash, PublicKey, Vec<Transaction>)> {
        let mut bundles = Vec::new();
        for (target, win) in &self.state.auction.winners {
            if win.winner != self.public() {
                continue;
            }
            let Some(swaps) = self.auction_pool.get(target) else {
                continue;
            };
            let pending: Vec<Transaction> = swaps
                .iter()
                .filter(|tx| win.swaps.contains(&tx.txid()))
                .cloned()
                .collect();
            if !pending.is_empty() {
                bundles.push((*target, win.winner, pending));
            }
        }
        bundles
    }

    /// Accepts an auction bundle that was pushed to this node by a peer.
    ///
    /// The swap transactions are kept in the node's private auction pool; the registration
    /// is queued as an operation so that it is committed on-chain.
    pub fn accept_auction_target(
        &mut self,
        target: Hash,
        swaps: Vec<Transaction>,
        intent: oxydome_core::SwapIntent,
        registrar: PublicKey,
    ) -> Result<(), NodeError> {
        if swaps.is_empty() {
            return Err(NodeError::Operation(
                "an auction bundle must contain at least one swap".into(),
            ));
        }
        let txids: Vec<Hash> = swaps.iter().map(|tx| tx.txid()).collect();
        if oxydome_core::auction_bundle_id(&txids) != target {
            return Err(NodeError::Operation(
                "the bundle id does not match the swap transactions".into(),
            ));
        }
        let mut operation = oxydome_core::AuctionTargetOperation {
            target,
            swaps: txids,
            intent,
            registrar,
            nonce: self.state.height,
            signature: oxydome_crypto::Sig([0u8; 64]),
        };
        let proposal_id = Operation::AuctionTarget(operation.clone()).proposal_id();
        operation.signature = self.key.sign(&proposal_id.0);
        let op = Operation::AuctionTarget(operation);
        self.submit_operation(op.clone())?;
        self.auction_pool.insert(target, swaps);
        self.auction_targets.insert(target, op);
        Ok(())
    }

    /// Accepts an auction bid that was pushed to this node by a peer.
    pub fn accept_auction_bid(&mut self, bid: oxydome_core::AuctionBidOperation) -> Result<(), NodeError> {
        let proposal_id = Operation::AuctionBid(bid.clone()).proposal_id();
        if !oxydome_crypto::verify(&bid.bidder, &proposal_id.0, &bid.signature) {
            return Err(NodeError::Operation(
                "the auction bid signature is invalid".into(),
            ));
        }
        self.submit_operation(Operation::AuctionBid(bid))
    }

    /// Queues a governance operation for the next block this node produces.
    pub fn submit_operation(&mut self, op: Operation) -> Result<(), NodeError> {
        if !op.is_governance() {
            return Err(NodeError::Operation(
                "only governance operations can be submitted".into(),
            ));
        }
        if matches!(op, Operation::AuctionPayout(_)) {
            // The payout of an auctioned transaction is derived by the producer from the
            // auction outcome; it must never be supplied by a peer.
            return Err(NodeError::Operation(
                "auction payouts are derived by the block producer".into(),
            ));
        }
        if let Operation::Dao(dao_operation) = &op {
            if !dao_operation.is_valid() {
                return Err(NodeError::Operation(
                    "DAO operation signature or action is invalid".into(),
                ));
            }
        }
        if let Operation::Ohm(ohm_operation) = &op {
            if !ohm_operation.is_valid() {
                return Err(NodeError::Operation(
                    "OHM operation signature or action is invalid".into(),
                ));
            }
        }
        if self.pending_ops.len() >= MAX_PENDING_OPERATIONS {
            return Err(NodeError::Operation(
                "pending governance operation limit reached".into(),
            ));
        }
        let operation_id = op.id();
        if self
            .pending_ops
            .iter()
            .any(|pending| pending.id() == operation_id)
        {
            return Err(NodeError::Operation(
                "governance operation is already pending".into(),
            ));
        }
        self.pending_ops.push(op);
        Ok(())
    }

    /// Accepts a private OHM block submitted by an OHM maintainer.
    ///
    /// The block is validated against the node's re-derived OHM ledger (which must be exactly one
    /// height behind), then retained so the matching Ox anchor can be verified. The ledger is not
    /// advanced until the anchor is finalized on Ox.
    pub fn submit_ohm_block(&mut self, block: OhmBlock) -> Result<Hash, NodeError> {
        let ohm_id = block.header.ohm_id;
        let view = CrossChainView::from_ledgers(&self.ohm_ledgers);
        let ledger = self.ohm_ledgers.get(&ohm_id).ok_or_else(|| {
            NodeError::Operation("OHM ledger is not tracked (create is not anchored yet)".into())
        })?;
        ledger
            .verify_block_with(&block, &view)
            .map_err(|error| NodeError::Operation(format!("invalid OHM block: {error}")))?;
        let hash = block.hash();
        if let Some(store) = &mut self.store {
            store
                .save_ohm_block(&block)
                .map_err(|error| NodeError::Ledger(error.to_string()))?;
        }
        self.ohm_blocks.insert(hash, block);
        Ok(hash)
    }

    /// The private OHM ledger for `ohm_id`, if this node tracks it.
    pub fn ohm_ledger(&self, ohm_id: &Hash) -> Option<&OhmLedger> {
        self.ohm_ledgers.get(ohm_id)
    }

    /// The Ox-committed OHM anchor state for `ohm_id`, if present.
    pub fn ohm_state(&self, ohm_id: &Hash) -> Option<&OhmState> {
        self.state.ohm_states.get(ohm_id)
    }

    /// A private OHM block body by hash, if retained.
    pub fn ohm_block(&self, hash: &Hash) -> Option<&OhmBlock> {
        self.ohm_blocks.get(hash)
    }

    /// Returns the GAS balance of the given account.
    pub fn gas_balance(&self, owner: &PublicKey) -> Amount {
        self.state.gas_balance(owner)
    }

    /// Returns the total circulating GAS supply.
    pub fn gas_supply(&self) -> Amount {
        self.state.gas_supply
    }

    /// Returns the on-chain Ox price oracle value used to size airdrops.
    pub fn gas_price(&self) -> Amount {
        self.state.ox_price
    }

    /// Returns the height of the most recent GAS airdrop.
    pub fn last_airdrop_height(&self) -> u64 {
        self.state.last_airdrop_height
    }

    /// The private OVM contract `contract_id` hosted by OHM `ohm_id`, if any.
    pub fn ohm_contract(&self, ohm_id: &Hash, contract_id: &Hash) -> Option<&OhmContract> {
        self.ohm_ledger(ohm_id)?.contract(contract_id)
    }

    /// The committed cross-OHM outbox of `ohm_id`, if this node tracks it.
    pub fn ohm_outbox(&self, ohm_id: &Hash) -> Option<&BTreeMap<Hash, OutboundMessage>> {
        Some(&self.ohm_ledger(ohm_id)?.outbox)
    }

    /// The committed cross-OHM inbox (consumed receipts) of `ohm_id`, if this node tracks it.
    pub fn ohm_inbox(&self, ohm_id: &Hash) -> Option<&BTreeMap<Hash, InboundReceipt>> {
        Some(&self.ohm_ledger(ohm_id)?.inbox)
    }

    /// A committed outbound message by id across every tracked OHM.
    pub fn ohm_message(&self, msg_id: &Hash) -> Option<&OutboundMessage> {
        self.ohm_ledgers
            .values()
            .find_map(|ledger| ledger.outbound(msg_id))
    }

    /// A committed inbound receipt by message id across every tracked OHM.
    pub fn ohm_receipt(&self, msg_id: &Hash) -> Option<&InboundReceipt> {
        self.ohm_ledgers
            .values()
            .find_map(|ledger| ledger.receipt(msg_id))
    }

    /// Simulates an OHM-hosted contract call against the current private state.
    ///
    /// Read-only: it never advances the ledger or mutates any contract storage.
    pub fn ohm_call_contract(
        &self,
        ohm_id: &Hash,
        contract_id: &Hash,
        entry_point: &str,
        caller: PublicKey,
        arguments: &[u64],
        gas_limit: u64,
    ) -> Result<OhmCallOutcome, NodeError> {
        let ledger = self
            .ohm_ledger(ohm_id)
            .ok_or_else(|| NodeError::Operation("OHM ledger is not tracked".into()))?;
        ledger
            .simulate_contract_call(contract_id, entry_point, caller, arguments, gas_limit)
            .map_err(|error| NodeError::Operation(error.to_string()))
    }

    /// Re-derives the OHM ledgers after applying `block`, validating that every `Update` anchor
    /// matches the private block it commits to. Returns the updated ledger set on success and
    /// leaves `self` untouched on failure.
    fn advance_ohm_ledgers(&self, block: &Block) -> Result<BTreeMap<Hash, OhmLedger>, NodeError> {
        let mut ledgers = self.ohm_ledgers.clone();
        // The cross-chain view is built once from the *committed* ledgers (finalized strictly
        // before this block), so inbound messages always reference finalized source outboxes.
        let view = CrossChainView::from_ledgers(&self.ohm_ledgers);
        for operation in &block.operations {
            let Operation::Ohm(ohm_operation) = operation else {
                continue;
            };
            match &ohm_operation.action {
                OhmAction::Create {
                    policy_bytes,
                    genesis_outputs,
                } => {
                    let ohm_id = ohm_operation.created_ohm_id().ok_or_else(|| {
                        NodeError::Operation("OHM create has no derived id".into())
                    })?;
                    let policy = OhmPolicy::decode(policy_bytes).map_err(|error| {
                        NodeError::Operation(format!("invalid OHM policy: {error}"))
                    })?;
                    if ledgers.contains_key(&ohm_id) {
                        return Err(NodeError::Operation("OHM ledger already exists".into()));
                    }
                    ledgers.insert(
                        ohm_id,
                        OhmLedger::from_genesis(
                            ohm_id,
                            policy.maintainer,
                            genesis_outputs,
                            ohm_operation.id(),
                        ),
                    );
                }
                OhmAction::Update {
                    ohm_id,
                    context,
                    block_hash,
                    fee_total,
                } => {
                    let ohm_block = self.ohm_blocks.get(block_hash).ok_or_else(|| {
                        NodeError::Operation(
                            "anchored OHM block is not retained by this node".into(),
                        )
                    })?;
                    // The Ox anchor settles `fee_total` Ox of fees into the Ox supply. It must
                    // equal the fees actually committed by the anchored OHM block; otherwise a
                    // maintainer could anchor a valid block while claiming an arbitrary fee total
                    // and mint unbacked Ox.
                    if *fee_total != ohm_block.header.fee_total {
                        return Err(NodeError::Operation(
                            "OHM anchor fee total does not match the anchored block".into(),
                        ));
                    }
                    let ledger = ledgers
                        .get_mut(ohm_id)
                        .ok_or_else(|| NodeError::Operation("OHM ledger is not tracked".into()))?;
                    ledger
                        .apply_block_with(ohm_block, &view)
                        .map_err(|error| NodeError::Operation(error.to_string()))?;
                    if ledger.height != context.ohm_height
                        || ledger.state_root != context.ohm_state_root
                        || ledger.block_hash != *block_hash
                    {
                        return Err(NodeError::Operation(
                            "OHM anchor does not match the re-derived ledger".into(),
                        ));
                    }
                }
                OhmAction::Terminate { ohm_id, .. } => {
                    ledgers.remove(ohm_id);
                }
                OhmAction::Transfer { .. } | OhmAction::TreasuryDeposit { .. } => {}
            }
        }
        Ok(ledgers)
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
        let mut transactions: Vec<Transaction> = self.mempool.clone();
        // Verification-credit auction: a bundle that was won at the last clearing is
        // executed in this very block. The winner collects 100% of the transaction's fees,
        // so those fees are kept out of the normal master/server split.
        let (auction_transactions, auction_payouts, auction_fees) =
            self.prepare_auction_execution(height, &mut transactions);
        let _ = &auction_transactions;
        let total_fees = self
            .state
            .settled_fee_total(&transactions, &self.params)?
            .saturating_sub(auction_fees);
        let mut operations = self.pending_ops.clone();
        operations.extend(auction_payouts);
        if total_fees > 0 {
            operations.push(self.reward_operation(total_fees, &self.public()));
        }

        // Add minted block rewards if enabled
        if self.params.block_rewards_enabled {
            if let Some(block_reward_op) = build_block_reward_operation(
                &self.params,
                self.state.ox_price,
                self.params.ox_price_reference,
                self.state.price_last_update_height,
                height,
                &self.gov.nodes,
                &self.public(),
                &self.gov.masters,
                self.prev_server_block_reward.unwrap_or(0),
            ) {
                // Track server reward for next block's master derivative calculation
                if let Operation::BlockRewards(ref dist) = block_reward_op {
                    self.prev_server_block_reward = Some(dist.server_total());
                }
                operations.push(block_reward_op);
            }
        }

        let block = self.state.build_block(
            &self.gov,
            &self.params,
            transactions,
            operations,
            self.public(),
            timestamp,
            self.coin_toss_seed,
        )?;
        Ok(block)
    }

    /// Async block production: validates and filters mempool transactions first, removing
    /// any that are structurally invalid, then produces a block via `smol::unblock`.
    pub async fn produce_block_async(&mut self, timestamp: u64) -> Result<Block, NodeError> {
        let height = self.next_height();
        if !self.is_leader(height) {
            return Err(NodeError::NotLeader);
        }

        // Pre-validate and filter mempool transactions asynchronously.
        let mempool_block = crate::async_verify::prepare_mempool_block(
            &self.state,
            &self.mempool,
            &self.params,
            height,
        )
        .await;
        let valid_txs = mempool_block;

        // Verification-credit auction: a bundle that was won at the last clearing is
        // executed in this very block.
        let mut transactions = valid_txs;
        let (auction_transactions, auction_payouts, auction_fees) =
            self.prepare_auction_execution(height, &mut transactions);
        let total_fees = self
            .state
            .settled_fee_total(&transactions, &self.params)?
            .saturating_sub(auction_fees);
        let mut operations = self.pending_ops.clone();
        operations.extend(auction_payouts);
        if total_fees > 0 {
            operations.push(self.reward_operation(total_fees, &self.public()));
        }

        if self.params.block_rewards_enabled {
            if let Some(block_reward_op) = build_block_reward_operation(
                &self.params,
                self.state.ox_price,
                self.params.ox_price_reference,
                self.state.price_last_update_height,
                height,
                &self.gov.nodes,
                &self.public(),
                &self.gov.masters,
                self.prev_server_block_reward.unwrap_or(0),
            ) {
                if let Operation::BlockRewards(ref dist) = block_reward_op {
                    self.prev_server_block_reward = Some(dist.server_total());
                }
                operations.push(block_reward_op);
            }
        }

        let state = self.state.clone();
        let gov = self.gov.clone();
        let params = self.params.clone();
        let producer = self.public();
        let coin_toss_seed = self.coin_toss_seed;
        smol::unblock(move || {
            state.build_block(
                &gov,
                &params,
                transactions,
                operations,
                producer,
                timestamp,
                coin_toss_seed,
            )
        })
        .await
        .map_err(NodeError::from)
    }

    /// Prepares the execution of the bundles that were won at the last auction clearing.
    ///
    /// Returns the transactions to append to the block, the matching `AuctionPayout`
    /// operations and the total fees that are paid out through the auction instead of the
    /// normal master/server split. A swap that no longer validates against the current
    /// state is skipped: the auction right simply lapses.
    fn prepare_auction_execution(
        &self,
        height: u64,
        transactions: &mut Vec<Transaction>,
    ) -> (Vec<Transaction>, Vec<Operation>, Amount) {
        let mut included = Vec::new();
        let mut payouts = Vec::new();
        let mut fees: Amount = 0;
        for (target, win) in &self.state.auction.winners {
            if win.deadline < height {
                // The execution window closed: the right lapses.
                continue;
            }
            let Some(swaps) = self.auction_pool.get(target) else {
                continue;
            };
            for tx in swaps.iter().filter(|tx| win.swaps.contains(&tx.txid())) {
                if transactions.iter().any(|other| other.txid() == tx.txid()) {
                    continue;
                }
                if !self.auction_swap_is_valid(tx) {
                    continue;
                }
                if !self.state.preview_is_pool_swap(tx, 0, &self.params) {
                    // Only swaps can be auctioned.
                    continue;
                }
                let txid = tx.txid();
                included.push(tx.clone());
                payouts.push(Operation::AuctionPayout(
                    oxydome_core::AuctionPayoutOperation {
                        target: *target,
                        txid,
                        winner: win.winner,
                        amount: tx.fee,
                    },
                ));
                fees = fees.saturating_add(tx.fee);
            }
        }
        transactions.extend(included.iter().cloned());
        (included, payouts, fees)
    }

    /// Checks that an auctioned swap still validates against the current state.
    fn auction_swap_is_valid(&self, tx: &Transaction) -> bool {
        if tx.validate_structure().is_err() {
            return false;
        }
        let mut input_total: Amount = 0;
        for input in &tx.inputs {
            let Some(entry) = self.state.utxo.get(&input.prev_out) else {
                return false;
            };
            if !entry.output.kind.is_spendable() || entry.output.recipient != input.owner {
                return false;
            }
            if !rebound_utxo_spendable(
                self.next_height(),
                entry.created_height,
                entry.output.rebound_gen,
                &self.params,
            ) {
                return false;
            }
            input_total = input_total.saturating_add(entry.output.amount);
        }
        let Ok(output_total) = tx.output_total() else {
            return false;
        };
        input_total == output_total.saturating_add(tx.fee)
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
        prepare_qc: &QuorumCertificate,
        commit_qc: &QuorumCertificate,
        master_checks: &[MasterCheck],
    ) -> Result<(), NodeError> {
        if block.header.prev_hash != self.state.block_hash {
            return Err(NodeError::NotOnTip);
        }
        let evidence = FinalityEvidence {
            attestations: attestations.to_vec(),
            prepare_qc: prepare_qc.clone(),
            commit_qc: commit_qc.clone(),
            master_checks: master_checks.to_vec(),
        };
        self.verify_finality_evidence(&block, &evidence)?;
        let encoded_evidence = oxydome_crypto::encode(&evidence);
        let next = self.state.apply_block(&block, &self.gov, &self.params)?;
        // Re-derive the private OHM ledgers and ensure every anchor matches before committing.
        let next_ohm_ledgers = self.advance_ohm_ledgers(&block)?;

        // Persist the new version before swapping it in: a failed store write leaves the node
        // unchanged and retryable.
        if let Some(store) = &mut self.store {
            let delta = ledger_diff(&self.state.utxo, &next.utxo);
            store
                .save_version_with_dao_and_finality(
                    next.height,
                    block.hash(),
                    &next.utxo,
                    &delta,
                    &next.contracts,
                    &next.daos,
                    &next.ohm_states,
                    &(
                        next.gas.clone(),
                        next.gas_supply,
                        next.ox_price,
                        next.last_airdrop_height,
                    ),
                    &block,
                    &encoded_evidence,
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

        // Determine execution order for event emission.
        let exec_txs: Vec<Transaction> = match block.header.coin_toss_seed {
            Some(seed) => oxydome_core::ordered_transactions(&block.transactions, &seed),
            None => block.transactions.clone(),
        };

        // Confirm the block's transactions, dropping them from the mempool.
        for (position, tx) in exec_txs.iter().enumerate() {
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
            txids: exec_txs.iter().map(|t| t.txid()).collect(),
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

        // The verification-credit auction: a bundle that was executed is now public, so
        // the private swap transactions are dropped from the auction pool.
        let executed_bundles: BTreeSet<Hash> = block
            .operations
            .iter()
            .filter_map(|op| match op {
                Operation::AuctionPayout(payout) => Some(payout.target),
                _ => None,
            })
            .collect();
        if !executed_bundles.is_empty() {
            self.auction_pool
                .retain(|target, _| !executed_bundles.contains(target));
            self.auction_targets
                .retain(|target, _| !executed_bundles.contains(target));
        }

        self.state = next;
        self.ohm_ledgers = next_ohm_ledgers;
        self.blocks.push(block.clone());
        self.finality_evidence.insert(block.header.height, evidence);
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
    params.block_rewards_enabled = false;
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
        node_capacity_bytes: None,
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use oxydome_core::{
        CrossRecvCall, CrossSendCall, OhmOperation, OhmOutput, Operation, OvmAction, Transaction,
        TxOutput, OHM_POLICY_VERSION,
    };
    use oxydome_rewards::split_fees;

    #[test]
    fn restores_and_replays_persisted_block_history() {
        let mut app_config = default_config(1, 1, 100_000);
        app_config.params.gas_activation_height = u64::MAX;
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
        let stack_bytes = 1_000;
        let stack_gas = (stack_bytes + 5) / 6; // ceil(1000/6) = 167
        let fee = 1 + u128::from(stack_gas);
        let mut deployment = Transaction::new_unsigned(
            vec![(input, node.public())],
            vec![TxOutput::spendable(amount - fee, node.public())],
            fee,
        );
        deployment.ovm_action = Some(OvmAction::DeployContract {
            artifact,
            stack_bytes,
        });
        deployment.sign_input(0, &key);
        let contract_id = oxydome_ovm::contract_id(deployment.txid());
        let fees = node
            .state
            .settled_fee_total(&[deployment.clone()], &node.params)
            .unwrap();
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
                None,
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
                &(
                    next.gas.clone(),
                    next.gas_supply,
                    next.ox_price,
                    next.last_airdrop_height,
                ),
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

    #[test]
    fn ohm_create_anchor_fee_split_and_restore() {
        let app_config = default_config(1, 1, 100_000);
        let genesis_config = app_config.genesis().unwrap();
        let key = app_config.nodes[0].keypair().unwrap();
        let (mut node, genesis) = Node::new(key.clone(), &genesis_config, None).unwrap();

        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis_with_block(&genesis, &node.state.utxo, &node.state.contracts)
            .unwrap();
        node.store = Some(store);

        // Create the OHM and anchor the Create operation at Ox height 1.
        let maintainer = KeyPair::from_seed(&[42u8; 32]);
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: maintainer.public(),
            name: "tenant".to_string(),
            genesis_supply: 1000,
            block_window: 10,
        };
        let genesis_outputs = vec![OhmOutput {
            amount: 1000,
            recipient: maintainer.public(),
            lock: false,
        }];
        let mut create = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Create {
                policy_bytes: policy.encode().unwrap(),
                genesis_outputs: genesis_outputs.clone(),
            },
        );
        create.sign(&maintainer);
        let ohm_id = create.created_ohm_id().unwrap();
        node.pending_ops.push(Operation::Ohm(create));

        let block1 = node.produce_block(1).unwrap();
        let state1 = node
            .state
            .apply_block(&block1, &node.gov, &node.params)
            .unwrap();
        let ohm1 = node.advance_ohm_ledgers(&block1).unwrap();
        assert!(ohm1.contains_key(&ohm_id));
        assert_eq!(
            ohm1[&ohm_id].state_root,
            state1.ohm_states[&ohm_id].state_root
        );
        node.store
            .as_mut()
            .unwrap()
            .save_version_with_ohm_and_block(
                state1.height,
                block1.hash(),
                &state1.utxo,
                &ledger_diff(&node.state.utxo, &state1.utxo),
                &state1.contracts,
                &state1.daos,
                &state1.ohm_states,
                &(
                    state1.gas.clone(),
                    state1.gas_supply,
                    state1.ox_price,
                    state1.last_airdrop_height,
                ),
                &block1,
            )
            .unwrap();
        node.state = state1;
        node.ohm_ledgers = ohm1;
        node.pending_ops.clear();

        // Build and submit a private OHM block moving 900 with a 100 fee.
        let ledger = node.ohm_ledgers[&ohm_id].clone();
        let genesis_out = ledger.utxos.values().next().unwrap().outpoint;
        let tx = ledger.build_transaction(
            vec![(genesis_out, maintainer.public())],
            vec![OhmOutput {
                amount: 900,
                recipient: maintainer.public(),
                lock: false,
            }],
            100,
            &maintainer,
        );
        let ohm_block = ledger.build_block(vec![tx], 5, &maintainer).unwrap();
        let ohm_block_hash = node.submit_ohm_block(ohm_block.clone()).unwrap();
        assert_eq!(ohm_block_hash, ohm_block.hash());

        // Anchor it at Ox height 2.
        let mut update = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Update {
                ohm_id,
                context: ohm_block.context(),
                block_hash: ohm_block_hash,
                fee_total: 100,
            },
        );
        update.sign(&maintainer);
        node.pending_ops.push(Operation::Ohm(update));

        let block2 = node.produce_block(2).unwrap();
        let state2 = node
            .state
            .apply_block(&block2, &node.gov, &node.params)
            .unwrap();
        let ohm2 = node.advance_ohm_ledgers(&block2).unwrap();
        node.store
            .as_mut()
            .unwrap()
            .save_version_with_ohm_and_block(
                state2.height,
                block2.hash(),
                &state2.utxo,
                &ledger_diff(&node.state.utxo, &state2.utxo),
                &state2.contracts,
                &state2.daos,
                &state2.ohm_states,
                &(
                    state2.gas.clone(),
                    state2.gas_supply,
                    state2.ox_price,
                    state2.last_airdrop_height,
                ),
                &block2,
            )
            .unwrap();
        node.state = state2;
        node.ohm_ledgers = ohm2;

        // 40% of the 100 fee goes to the single server node (with 20% converted to GAS: 32 Ox, 8 GAS), 60% to the OHM treasury.
        assert_eq!(node.balance(&node.public()).locked_reward, 32);
        assert_eq!(node.state.gas_balance(&node.public()), 8);
        assert_eq!(node.state.ohm_states[&ohm_id].treasury_ox, 60);
        assert_eq!(node.state.ohm_states[&ohm_id].fees_paid, 100);
        assert_eq!(node.ohm_ledgers[&ohm_id].height, 1);
        assert_eq!(node.ohm_ledgers[&ohm_id].supply, 900);
        assert_eq!(node.ohm_ledgers[&ohm_id].block_hash, ohm_block_hash);

        // Restore and confirm the private OHM ledger is re-derived from persisted blocks.
        let store = node.store.take().unwrap();
        let (fresh_node, _) = Node::new(key, &genesis_config, None).unwrap();
        let restored = fresh_node.restore_from_store(store, None).unwrap();
        assert_eq!(restored.state.height, 2);
        let restored_ledger = restored.ohm_ledgers.get(&ohm_id).unwrap();
        assert_eq!(restored_ledger.height, 1);
        assert_eq!(restored_ledger.block_hash, ohm_block_hash);
        assert_eq!(restored_ledger.supply, 900);
        assert_eq!(
            restored_ledger.state_root,
            restored.state.ohm_states[&ohm_id].state_root
        );
    }

    #[test]
    fn rejects_ohm_anchor_with_unmatched_fee_total() {
        let app_config = default_config(1, 1, 100_000);
        let genesis_config = app_config.genesis().unwrap();
        let key = app_config.nodes[0].keypair().unwrap();
        let (mut node, _genesis) = Node::new(key, &genesis_config, None).unwrap();

        // Create the OHM and anchor the Create operation at Ox height 1.
        let maintainer = KeyPair::from_seed(&[42u8; 32]);
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: maintainer.public(),
            name: "tenant".to_string(),
            genesis_supply: 1000,
            block_window: 10,
        };
        let genesis_outputs = vec![OhmOutput {
            amount: 1000,
            recipient: maintainer.public(),
            lock: false,
        }];
        let mut create = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Create {
                policy_bytes: policy.encode().unwrap(),
                genesis_outputs,
            },
        );
        create.sign(&maintainer);
        let ohm_id = create.created_ohm_id().unwrap();
        node.pending_ops.push(Operation::Ohm(create));

        let block1 = node.produce_block(1).unwrap();
        let state1 = node
            .state
            .apply_block(&block1, &node.gov, &node.params)
            .unwrap();
        let ohm1 = node.advance_ohm_ledgers(&block1).unwrap();
        node.state = state1;
        node.ohm_ledgers = ohm1;
        node.pending_ops.clear();

        // Build and submit a private OHM block moving 900 with a 100 fee.
        let ledger = node.ohm_ledgers[&ohm_id].clone();
        let genesis_out = ledger.utxos.values().next().unwrap().outpoint;
        let tx = ledger.build_transaction(
            vec![(genesis_out, maintainer.public())],
            vec![OhmOutput {
                amount: 900,
                recipient: maintainer.public(),
                lock: false,
            }],
            100,
            &maintainer,
        );
        let ohm_block = ledger.build_block(vec![tx], 5, &maintainer).unwrap();
        let ohm_block_hash = node.submit_ohm_block(ohm_block.clone()).unwrap();

        // Anchor a *mismatched* fee total: the maintainer claims 1_100 Ox of fees instead of
        // the 100 actually committed by the OHM block. The node must refuse the anchor so no
        // unbacked Ox is settled into the Ox supply.
        let mut update = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Update {
                ohm_id,
                context: ohm_block.context(),
                block_hash: ohm_block_hash,
                fee_total: ohm_block.header.fee_total + 1_000,
            },
        );
        update.sign(&maintainer);
        node.pending_ops.push(Operation::Ohm(update));

        let block2 = node.produce_block(2).unwrap();
        let _state2 = node
            .state
            .apply_block(&block2, &node.gov, &node.params)
            .unwrap();
        assert!(matches!(
            node.advance_ohm_ledgers(&block2),
            Err(NodeError::Operation(_))
        ));
        // The OHM ledger must not have advanced to the anchored height nor moved any value.
        assert_eq!(node.ohm_ledgers[&ohm_id].height, 0);
        assert_eq!(node.ohm_ledgers[&ohm_id].supply, 1000);
    }

    #[test]
    fn ohm_hosted_ovm_contract_anchors_and_restores() {
        let app_config = default_config(1, 1, 100_000);
        let genesis_config = app_config.genesis().unwrap();
        let key = app_config.nodes[0].keypair().unwrap();
        let (mut node, genesis) = Node::new(key.clone(), &genesis_config, None).unwrap();

        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis_with_block(&genesis, &node.state.utxo, &node.state.contracts)
            .unwrap();
        node.store = Some(store);

        // Create the OHM and anchor the Create operation at Ox height 1.
        let maintainer = KeyPair::from_seed(&[42u8; 32]);
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: maintainer.public(),
            name: "tenant".to_string(),
            genesis_supply: 1000,
            block_window: 10,
        };
        let genesis_outputs = vec![OhmOutput {
            amount: 1000,
            recipient: maintainer.public(),
            lock: false,
        }];
        let mut create = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Create {
                policy_bytes: policy.encode().unwrap(),
                genesis_outputs,
            },
        );
        create.sign(&maintainer);
        let ohm_id = create.created_ohm_id().unwrap();
        node.pending_ops.push(Operation::Ohm(create));

        let block1 = node.produce_block(1).unwrap();
        let state1 = node
            .state
            .apply_block(&block1, &node.gov, &node.params)
            .unwrap();
        let ohm1 = node.advance_ohm_ledgers(&block1).unwrap();
        node.store
            .as_mut()
            .unwrap()
            .save_version_with_ohm_and_block(
                state1.height,
                block1.hash(),
                &state1.utxo,
                &ledger_diff(&node.state.utxo, &state1.utxo),
                &state1.contracts,
                &state1.daos,
                &state1.ohm_states,
                &(
                    state1.gas.clone(),
                    state1.gas_supply,
                    state1.ox_price,
                    state1.last_airdrop_height,
                ),
                &block1,
            )
            .unwrap();
        node.state = state1;
        node.ohm_ledgers = ohm1;
        node.pending_ops.clear();

        // Deploy a named contract and call it inside a single private OHM block.
        let ledger = node.ohm_ledgers[&ohm_id].clone();
        let genesis_out = ledger.utxos.values().next().unwrap().outpoint;
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
        let deploy = ledger.build_ovm_transaction(
            vec![(genesis_out, maintainer.public())],
            vec![OhmOutput {
                amount: 900,
                recipient: maintainer.public(),
                lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact,
                stack_bytes: 2_000,
            }),
            &maintainer,
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = ledger.build_ovm_transaction(
            vec![(OutPoint::new(deploy.txid(), 0), maintainer.public())],
            vec![OhmOutput {
                amount: 800,
                recipient: maintainer.public(),
                lock: false,
            }],
            100,
            Some(OvmAction::CallContract {
                contract_id,
                entry_point: "increment".into(),
                arguments: vec![5],
                authority_input: 0,
                stack_bytes: 100,
            }),
            &maintainer,
        );
        let ohm_block = ledger
            .build_block(vec![deploy, call], 6, &maintainer)
            .unwrap();
        let ohm_block_hash = node.submit_ohm_block(ohm_block.clone()).unwrap();

        // Anchor it at Ox height 2.
        let mut update = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Update {
                ohm_id,
                context: ohm_block.context(),
                block_hash: ohm_block_hash,
                fee_total: ohm_block.header.fee_total,
            },
        );
        update.sign(&maintainer);
        node.pending_ops.push(Operation::Ohm(update));

        let block2 = node.produce_block(2).unwrap();
        let state2 = node
            .state
            .apply_block(&block2, &node.gov, &node.params)
            .unwrap();
        let ohm2 = node.advance_ohm_ledgers(&block2).unwrap();
        node.store
            .as_mut()
            .unwrap()
            .save_version_with_ohm_and_block(
                state2.height,
                block2.hash(),
                &state2.utxo,
                &ledger_diff(&node.state.utxo, &state2.utxo),
                &state2.contracts,
                &state2.daos,
                &state2.ohm_states,
                &(
                    state2.gas.clone(),
                    state2.gas_supply,
                    state2.ox_price,
                    state2.last_airdrop_height,
                ),
                &block2,
            )
            .unwrap();
        node.state = state2;
        node.ohm_ledgers = ohm2;

        // The private contract state is committed by the anchored OHM state root.
        assert_eq!(
            node.ohm_ledgers[&ohm_id].contracts[&contract_id]
                .storage
                .get(&0),
            Some(&5)
        );
        assert_eq!(
            node.ohm_ledgers[&ohm_id].state_root,
            node.state.ohm_states[&ohm_id].state_root
        );
        assert!(node.ohm_contract(&ohm_id, &contract_id).is_some());

        // Restore and confirm the hosted contract is re-derived from persisted OHM blocks.
        let store = node.store.take().unwrap();
        let (fresh_node, _) = Node::new(key, &genesis_config, None).unwrap();
        let restored = fresh_node.restore_from_store(store, None).unwrap();
        assert_eq!(
            restored.ohm_ledgers[&ohm_id].contracts[&contract_id]
                .storage
                .get(&0),
            Some(&5)
        );
        assert_eq!(
            restored.ohm_ledgers[&ohm_id].state_root,
            restored.state.ohm_states[&ohm_id].state_root
        );

        // Read-only simulation runs against the restored private state.
        let outcome = restored
            .ohm_call_contract(
                &ohm_id,
                &contract_id,
                "increment",
                maintainer.public(),
                &[1],
                100,
            )
            .unwrap();
        assert_eq!(outcome.failure, None);
        assert_eq!(outcome.return_value, Some(6));
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
        // stores the value for inspection.
        let arg_count = 10usize;
        let code = oxydome_ovm::Program {
            argument_count: (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count) as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(
                    (oxydome_ovm::AUTHORITY_WORD_COUNT + arg_count - 1) as u8,
                ),
                oxydome_ovm::Instruction::StoreStorage(1),
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

    /// Produces, applies, persists and commits the next Ox block from `node.pending_ops`.
    fn anchor_ox_block(node: &mut Node) {
        let height = node.state.height + 1;
        let block = node.produce_block(height).unwrap();
        let state = node
            .state
            .apply_block(&block, &node.gov, &node.params)
            .unwrap();
        let ledgers = node.advance_ohm_ledgers(&block).unwrap();
        node.store
            .as_mut()
            .unwrap()
            .save_version_with_ohm_and_block(
                state.height,
                block.hash(),
                &state.utxo,
                &ledger_diff(&node.state.utxo, &state.utxo),
                &state.contracts,
                &state.daos,
                &state.ohm_states,
                &(
                    state.gas.clone(),
                    state.gas_supply,
                    state.ox_price,
                    state.last_airdrop_height,
                ),
                &block,
            )
            .unwrap();
        node.state = state;
        node.ohm_ledgers = ledgers;
        node.pending_ops.clear();
    }

    fn create_ohm_op(maintainer: &KeyPair, name: &str) -> OhmOperation {
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: maintainer.public(),
            name: name.to_string(),
            genesis_supply: 1000,
            block_window: 10,
        };
        let mut create = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Create {
                policy_bytes: policy.encode().unwrap(),
                genesis_outputs: vec![OhmOutput {
                    amount: 1000,
                    recipient: maintainer.public(),
                    lock: false,
                }],
            },
        );
        create.sign(maintainer);
        create
    }

    fn anchor_ohm_block(node: &mut Node, ohm_id: Hash, block: OhmBlock, maintainer: &KeyPair) {
        let mut update = OhmOperation::new_unsigned(
            block.header.maintainer,
            OhmAction::Update {
                ohm_id,
                context: block.context(),
                block_hash: block.hash(),
                fee_total: block.header.fee_total,
            },
        );
        update.sign(maintainer);
        node.pending_ops.push(Operation::Ohm(update));
        node.submit_ohm_block(block).unwrap();
        anchor_ox_block(node);
    }

    #[test]
    fn cross_ohm_relay_reply_and_restore() {
        let app_config = default_config(1, 1, 100_000);
        let genesis_config = app_config.genesis().unwrap();
        let key = app_config.nodes[0].keypair().unwrap();
        let (mut node, genesis) = Node::new(key.clone(), &genesis_config, None).unwrap();

        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis_with_block(&genesis, &node.state.utxo, &node.state.contracts)
            .unwrap();
        node.store = Some(store);

        let maintainer_a = KeyPair::from_seed(&[11u8; 32]);
        let maintainer_b = KeyPair::from_seed(&[12u8; 32]);

        // Create OHM A and OHM B.
        let create_a = create_ohm_op(&maintainer_a, "tenant-a");
        let ohm_a = create_a.created_ohm_id().unwrap();
        node.pending_ops.push(Operation::Ohm(create_a));
        anchor_ox_block(&mut node);

        let create_b = create_ohm_op(&maintainer_b, "tenant-b");
        let ohm_b = create_b.created_ohm_id().unwrap();
        node.pending_ops.push(Operation::Ohm(create_b));
        anchor_ox_block(&mut node);

        // B hosts an echo contract.
        let ledger_b = node.ohm_ledgers[&ohm_b].clone();
        let deploy_b = ledger_b.build_ovm_transaction(
            vec![(
                ledger_b.utxos.values().next().unwrap().outpoint,
                maintainer_b.public(),
            )],
            vec![OhmOutput {
                amount: 900,
                recipient: maintainer_b.public(),
                lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: echo_artifact(1),
                stack_bytes: 2_000,
            }),
            &maintainer_b,
        );
        let target_contract = oxydome_ovm::contract_id(deploy_b.txid());
        anchor_ohm_block(
            &mut node,
            ohm_b,
            ledger_b
                .build_block(vec![deploy_b.clone()], 3, &maintainer_b)
                .unwrap(),
            &maintainer_b,
        );

        // A hosts an on_reply contract and sends a message requesting a reply.
        let ledger_a = node.ohm_ledgers[&ohm_a].clone();
        let deploy_a = ledger_a.build_ovm_transaction(
            vec![(
                ledger_a.utxos.values().next().unwrap().outpoint,
                maintainer_a.public(),
            )],
            vec![OhmOutput {
                amount: 900,
                recipient: maintainer_a.public(),
                lock: false,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact: on_reply_artifact(),
                stack_bytes: 2_000,
            }),
            &maintainer_a,
        );
        let reply_contract = oxydome_ovm::contract_id(deploy_a.txid());
        let send = ledger_a.build_cross_send_transaction(
            vec![(OutPoint::new(deploy_a.txid(), 0), maintainer_a.public())],
            vec![OhmOutput {
                amount: 800,
                recipient: maintainer_a.public(),
                lock: false,
            }],
            100,
            CrossSendCall {
                target_ohm: ohm_b,
                target_contract,
                entry_point: "echo".into(),
                arguments: vec![41],
                gas_limit: 200,
                want_reply: true,
                reply_contract: Some(reply_contract),
                reply_entry_point: Some("on_reply".into()),
            },
            &maintainer_a,
        );
        anchor_ohm_block(
            &mut node,
            ohm_a,
            ledger_a
                .build_block(vec![deploy_a, send], 5, &maintainer_a)
                .unwrap(),
            &maintainer_a,
        );

        // A's outbox now carries the outbound message.
        let msg_id = node
            .ohm_outbox(&ohm_a)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .msg_id;
        assert!(node.ohm_message(&msg_id).is_some());

        // B consumes the message in a later Ox block, executing the target and auto-replying.
        let view = CrossChainView::from_ledgers(&node.ohm_ledgers);
        let ledger_b = node.ohm_ledgers[&ohm_b].clone();
        let consume = ledger_b.build_cross_recv_transaction(
            vec![(OutPoint::new(deploy_b.txid(), 0), maintainer_b.public())],
            vec![OhmOutput {
                amount: 800,
                recipient: maintainer_b.public(),
                lock: false,
            }],
            100,
            CrossRecvCall { msg_id },
            &maintainer_b,
        );
        anchor_ohm_block(
            &mut node,
            ohm_b,
            ledger_b
                .build_block_with(vec![consume], 6, &maintainer_b, &view)
                .unwrap(),
            &maintainer_b,
        );

        let receipt = &node.ohm_ledgers[&ohm_b].inbox[&msg_id];
        assert_eq!(receipt.failure, None);
        assert_eq!(receipt.return_value, Some(41));
        let reply_id = receipt.reply_msg_id.unwrap();
        let reply = &node.ohm_ledgers[&ohm_b].outbox[&reply_id];
        assert_eq!(reply.target_ohm, ohm_a);
        assert_eq!(reply.target_contract, reply_contract);
        assert_eq!(reply.reply_to_msg_id, Some(msg_id));

        // A consumes the reply.
        let view = CrossChainView::from_ledgers(&node.ohm_ledgers);
        let ledger_a = node.ohm_ledgers[&ohm_a].clone();
        let consume_reply = ledger_a.build_cross_recv_transaction(
            vec![(
                ledger_a.utxos.values().next().unwrap().outpoint,
                maintainer_a.public(),
            )],
            vec![OhmOutput {
                amount: 700,
                recipient: maintainer_a.public(),
                lock: false,
            }],
            100,
            CrossRecvCall { msg_id: reply_id },
            &maintainer_a,
        );
        anchor_ohm_block(
            &mut node,
            ohm_a,
            ledger_a
                .build_block_with(vec![consume_reply], 7, &maintainer_a, &view)
                .unwrap(),
            &maintainer_a,
        );

        let reply_receipt = &node.ohm_ledgers[&ohm_a].inbox[&reply_id];
        assert_eq!(reply_receipt.failure, None);
        assert_eq!(reply_receipt.reply_to_msg_id, Some(msg_id));
        assert_eq!(
            node.ohm_ledgers[&ohm_a].contracts[&reply_contract]
                .storage
                .get(&1),
            Some(&41)
        );
        assert!(node.ohm_receipt(&reply_id).is_some());

        // Outbox entries persist (no pruning in v1); the message and reply are both queryable.
        assert_eq!(node.ohm_ledgers[&ohm_a].outbox.len(), 1);
        assert_eq!(node.ohm_ledgers[&ohm_b].outbox.len(), 1);

        // Restore from the persisted store and confirm the cross-chain state is re-derived
        // identically (the one-Ox-block view rule makes replay deterministic).
        let store = node.store.take().unwrap();
        let (fresh_node, _) = Node::new(key, &genesis_config, None).unwrap();
        let restored = fresh_node.restore_from_store(store, None).unwrap();

        assert_eq!(
            restored.ohm_ledgers[&ohm_a].state_root,
            node.ohm_ledgers[&ohm_a].state_root
        );
        assert_eq!(
            restored.ohm_ledgers[&ohm_b].state_root,
            node.ohm_ledgers[&ohm_b].state_root
        );
        assert!(restored.ohm_receipt(&reply_id).is_some());
        assert!(restored.ohm_message(&msg_id).is_some());
        assert_eq!(restored.ohm_ledgers[&ohm_b].inbox[&msg_id].failure, None);
        assert_eq!(
            restored.ohm_ledgers[&ohm_a].inbox[&reply_id].reply_to_msg_id,
            Some(msg_id)
        );
    }
}
