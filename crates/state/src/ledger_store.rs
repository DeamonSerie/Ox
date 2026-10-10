//! Durable storage for ledger versions.
//!
//! A [`LedgerStore`] appends immutable ledger versions to a single sled tree. Each saved
//! height records:
//!
//! * the tree nodes reachable from the version's root (`NodeMeta`),
//! * a [`SnapshotRecord`] committing the state root and total,
//! * a [`LedgerDelta`] describing how to reach that version from the previous one,
//! * a current-height marker.
//!
//! Writes for a single height are committed atomically in one sled batch, so a crash mid-save
//! never leaves a half-versioned ledger. History can be replayed from deltas
//! ([`LedgerStore::verify_history`], [`LedgerStore::rebuild_from_deltas`]) to independently
//! re-derive and cross-check every committed state root.

use crate::chain::OvmContract;
use crate::utxo::{Summary, UtxoEntry, UtxoLedger, VNode};
use oxydome_core::{Amount, DaoState, GasAccount, OhmBlock, OhmState, OutPoint, PublicKey};
use oxydome_crypto::{merkle_leaf_hash, merkle_node_hash, Hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// A persisted tree node. The node hash itself is the storage key; `Internal` children are
/// stored by hash (empty subtrees commit as `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum NodeMeta {
    Leaf(UtxoEntry),
    Internal {
        left: Option<Hash>,
        right: Option<Hash>,
        count: u64,
        total: Amount,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OvmSnapshot {
    pub height: u64,
    pub root: Hash,
    pub contracts: std::collections::BTreeMap<Hash, OvmContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoSnapshot {
    pub height: u64,
    pub root: Hash,
    pub daos: std::collections::BTreeMap<Hash, DaoState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhmSnapshot {
    pub height: u64,
    pub root: Hash,
    pub states: std::collections::BTreeMap<Hash, OhmState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSnapshot {
    pub height: u64,
    pub accounts: BTreeMap<PublicKey, GasAccount>,
    pub gas_supply: Amount,
    pub ox_price: Amount,
    pub last_airdrop_height: u64,
}

/// The committed summary of a specific ledger version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub height: u64,
    pub block_hash: Hash,
    pub root: Hash,
    pub total: Amount,
}

/// The difference between two consecutive ledger versions, sufficient to replay a chain of
/// versions from scratch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerDelta {
    /// outpoints that were removed, in path order
    pub spent: Vec<OutPoint>,
    /// entries that were inserted, in path order
    pub created: Vec<UtxoEntry>,
}

// Key layout within the "ledger" tree:
//   [0u8] + node_hash       -> NodeMeta
//   [1u8] + height_le       -> SnapshotRecord
//   [2u8] + height_le       -> LedgerDelta
//   [3u8]                   -> current height (u64 le)
const PREFIX_NODE: u8 = 0u8;
const PREFIX_SNAPSHOT: u8 = 1u8;
const PREFIX_DELTA: u8 = 2u8;
const PREFIX_OVM: u8 = 4u8;
const PREFIX_BLOCK: u8 = 5u8;
const PREFIX_FINALITY: u8 = 6u8;
const PREFIX_DAO: u8 = 7u8;
const PREFIX_OHM_STATE: u8 = 8u8;
/// Content-addressed private OHM blocks, keyed by OHM block hash.
const PREFIX_OHM_BLOCK: u8 = 9u8;
const PREFIX_GAS: u8 = 10u8;
const KEY_CURRENT: [u8; 1] = [3u8];

fn node_key(hash: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 64);
    key.push(PREFIX_NODE);
    key.extend_from_slice(hash.as_bytes());
    key
}

fn height_key(prefix: u8, height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.push(prefix);
    key.extend_from_slice(&height.to_le_bytes());
    key
}

/// Errors produced by [`LedgerStore`].
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("sled: {0}")]
    Sled(#[from] sled::Error),
    #[error("ledger serialization: {0}")]
    Serialization(String),
    #[error("corrupt ledger: {0}")]
    Corrupt(String),
    #[error("missing snapshot at height {0}")]
    MissingSnapshot(u64),
    #[error("missing delta at height {0}")]
    MissingDelta(u64),
    #[error("missing ledger node {0}")]
    MissingNode(Hash),
    #[error("state root mismatch at height {0}: stored {1}, computed {2}")]
    RootMismatch(u64, Hash, Hash),
    #[error("total mismatch at height {0}: stored {1}, computed {2}")]
    TotalMismatch(u64, Amount, Amount),
}

/// Append-only storage for ledger versions backed by a single sled tree.
#[derive(Debug)]
pub struct LedgerStore {
    tree: sled::Tree,
    /// Content-addressed node hashes already written to disk (seeded once per process).
    persisted: HashSet<Hash>,
    seeded: bool,
}

impl LedgerStore {
    /// Opens (or creates) the store rooted at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, LedgerError> {
        let db = sled::Config::new().path(path).open()?;
        let tree = db.open_tree("ledger")?;
        Ok(Self {
            tree,
            persisted: HashSet::new(),
            seeded: false,
        })
    }

    /// Opens a store backed by a temporary (anonymous) database.
    pub fn open_temporary() -> Result<Self, LedgerError> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("ledger")?;
        Ok(Self {
            tree,
            persisted: HashSet::new(),
            seeded: false,
        })
    }

    fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, LedgerError> {
        bincode::serialize(value).map_err(|e| LedgerError::Serialization(e.to_string()))
    }

    fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, LedgerError> {
        bincode::deserialize(bytes).map_err(|e| LedgerError::Corrupt(e.to_string()))
    }

    /// The most recently saved height, if any.
    pub fn current_height(&self) -> Result<Option<u64>, LedgerError> {
        match self.tree.get(&KEY_CURRENT)? {
            Some(raw) => {
                let bytes: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| LedgerError::Corrupt("current height marker".into()))?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Load the on-disk hash set once so later saves skip already-persisted subtrees.
    fn ensure_seeded(&mut self) -> Result<(), LedgerError> {
        if self.seeded {
            return Ok(());
        }
        for entry in self.tree.scan_prefix(&[PREFIX_NODE]) {
            let (key, _) = entry?;
            if key.len() == 1 + 64 {
                let mut hash_bytes = [0u8; 64];
                hash_bytes.copy_from_slice(&key[1..]);
                self.persisted.insert(Hash(hash_bytes));
            }
        }
        self.seeded = true;
        Ok(())
    }

    pub fn load_ovm_state(
        &self,
        height: u64,
    ) -> Result<std::collections::BTreeMap<Hash, OvmContract>, LedgerError> {
        match self.tree.get(height_key(PREFIX_OVM, height))? {
            Some(raw) => {
                let snapshot: OvmSnapshot = Self::decode(&raw)?;
                if snapshot.height != height {
                    return Err(LedgerError::Corrupt(format!(
                        "OVM snapshot height {} stored at {height}",
                        snapshot.height
                    )));
                }

                let root =
                    oxydome_crypto::hash_value(&("oxydome-ovm-state-v1", &snapshot.contracts));
                if root != snapshot.root {
                    return Err(LedgerError::Corrupt(format!(
                        "OVM snapshot root mismatch at height {height}"
                    )));
                }
                Ok(snapshot.contracts)
            }
            None => Ok(Default::default()),
        }
    }

    pub fn load_dao_state(
        &self,
        height: u64,
    ) -> Result<std::collections::BTreeMap<Hash, DaoState>, LedgerError> {
        match self.tree.get(height_key(PREFIX_DAO, height))? {
            Some(raw) => {
                let snapshot: DaoSnapshot = Self::decode(&raw)?;
                if snapshot.height != height {
                    return Err(LedgerError::Corrupt(format!(
                        "DAO snapshot height {} stored at {height}",
                        snapshot.height
                    )));
                }
                let root = oxydome_crypto::hash_value(&("oxydome-dao-state-v1", &snapshot.daos));
                if root != snapshot.root {
                    return Err(LedgerError::Corrupt(format!(
                        "DAO snapshot root mismatch at height {height}"
                    )));
                }
                Ok(snapshot.daos)
            }
            None => Ok(Default::default()),
        }
    }

    pub fn load_ohm_state(
        &self,
        height: u64,
    ) -> Result<std::collections::BTreeMap<Hash, OhmState>, LedgerError> {
        match self.tree.get(height_key(PREFIX_OHM_STATE, height))? {
            Some(raw) => {
                let snapshot: OhmSnapshot = Self::decode(&raw)?;
                if snapshot.height != height {
                    return Err(LedgerError::Corrupt(format!(
                        "OHM snapshot height {} stored at {height}",
                        snapshot.height
                    )));
                }
                let root = oxydome_crypto::hash_value(&("oxydome-ohm-state-v1", &snapshot.states));
                if root != snapshot.root {
                    return Err(LedgerError::Corrupt(format!(
                        "OHM snapshot root mismatch at height {height}"
                    )));
                }
                Ok(snapshot.states)
            }
            None => Ok(Default::default()),
        }
    }

    pub fn load_gas_state(
        &self,
        height: u64,
    ) -> Result<(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64), LedgerError> {
        match self.tree.get(height_key(PREFIX_GAS, height))? {
            Some(raw) => {
                let snapshot: GasSnapshot = Self::decode(&raw)?;
                if snapshot.height != height {
                    return Err(LedgerError::Corrupt(format!(
                        "GAS snapshot height {} stored at {height}",
                        snapshot.height
                    )));
                }
                Ok((
                    snapshot.accounts,
                    snapshot.gas_supply,
                    snapshot.ox_price,
                    snapshot.last_airdrop_height,
                ))
            }
            None => Ok((Default::default(), 0, 0, 0)),
        }
    }

    /// Durably stores a private OHM block, content-addressed by its block hash.
    ///
    /// Re-saving an existing block is a no-op, so repeated submissions are idempotent.
    pub fn save_ohm_block(&mut self, block: &OhmBlock) -> Result<(), LedgerError> {
        let hash = block.hash();
        let mut key = Vec::with_capacity(1 + 64);
        key.push(PREFIX_OHM_BLOCK);
        key.extend_from_slice(hash.as_bytes());
        if self.tree.get(&key)?.is_some() {
            return Ok(());
        }
        self.tree
            .insert(key, Self::encode(block)?)
            .map_err(LedgerError::from)?;
        Ok(())
    }

    /// Loads a single private OHM block by hash, verifying it hashes to the requested key.
    pub fn load_ohm_block(&self, hash: &Hash) -> Result<Option<OhmBlock>, LedgerError> {
        let mut key = Vec::with_capacity(1 + 64);
        key.push(PREFIX_OHM_BLOCK);
        key.extend_from_slice(hash.as_bytes());
        match self.tree.get(&key)? {
            Some(raw) => {
                let block: OhmBlock = Self::decode(&raw)?;
                if &block.hash() != hash {
                    return Err(LedgerError::Corrupt(format!(
                        "stored OHM block does not hash to its key {hash}"
                    )));
                }
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Loads every durably stored private OHM block.
    pub fn load_ohm_blocks(&self) -> Result<Vec<OhmBlock>, LedgerError> {
        let mut blocks = Vec::new();
        for entry in self.tree.scan_prefix(&[PREFIX_OHM_BLOCK]) {
            let (key, value) = entry?;
            if key.len() != 1 + 64 {
                return Err(LedgerError::Corrupt("OHM block key length".into()));
            }
            let block: OhmBlock = Self::decode(&value)?;
            let mut hash_bytes = [0u8; 64];
            hash_bytes.copy_from_slice(&key[1..]);
            if *block.hash().as_bytes() != hash_bytes {
                return Err(LedgerError::Corrupt(
                    "stored OHM block does not hash to its key".into(),
                ));
            }
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Loads every durably stored block in height order.
    pub fn load_blocks(&self) -> Result<Vec<oxydome_core::Block>, LedgerError> {
        let mut blocks = Vec::new();
        for entry in self.tree.scan_prefix(&[PREFIX_BLOCK]) {
            let (key, value) = entry?;
            if key.len() != 1 + 8 {
                return Err(LedgerError::Corrupt("block key length".into()));
            }
            let height = u64::from_le_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| LedgerError::Corrupt("block height key".into()))?,
            );
            let block: oxydome_core::Block = Self::decode(&value)?;
            if block.header.height != height {
                return Err(LedgerError::Corrupt(format!(
                    "block height {} stored at {height}",
                    block.header.height
                )));
            }
            blocks.push(block);
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
    }

    fn read_meta(&self, hash: &Hash) -> Result<Option<NodeMeta>, LedgerError> {
        match self.tree.get(node_key(hash))? {
            Some(raw) => Ok(Some(Self::decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// Reconstructs a subtree from persisted nodes, verifying every node hash and the root
    /// summary against the stored metadata.
    fn load_node(
        &self,
        hash: &Hash,
        memo: &mut HashMap<Hash, Arc<VNode>>,
    ) -> Result<Arc<VNode>, LedgerError> {
        if hash.is_zero() {
            return Ok(Arc::new(VNode::Empty));
        }
        if let Some(node) = memo.get(hash) {
            return Ok(node.clone());
        }
        let meta = self
            .read_meta(hash)?
            .ok_or(LedgerError::MissingNode(*hash))?;
        let node = match meta {
            NodeMeta::Leaf(entry) => {
                let committed = merkle_leaf_hash(&entry.leaf());
                if &committed != hash {
                    return Err(LedgerError::Corrupt(format!(
                        "leaf {hash} commits {committed}"
                    )));
                }
                Arc::new(VNode::Leaf { entry, hash: *hash })
            }
            NodeMeta::Internal {
                left,
                right,
                count,
                total,
            } => {
                let empty = Arc::new(VNode::Empty);
                let left_node = match left {
                    Some(h) => self.load_node(&h, memo)?,
                    None => empty.clone(),
                };
                let right_node = match right {
                    Some(h) => self.load_node(&h, memo)?,
                    None => empty,
                };
                let summary = Summary {
                    count: left_node
                        .summary()
                        .count
                        .saturating_add(right_node.summary().count),
                    total: left_node
                        .summary()
                        .total
                        .saturating_add(right_node.summary().total),
                };
                if summary.count != count || summary.total != total {
                    return Err(LedgerError::Corrupt(format!(
                        "internal {hash} summary mismatch"
                    )));
                }
                let committed = merkle_node_hash(&left_node.hash(), &right_node.hash());
                if &committed != hash {
                    return Err(LedgerError::Corrupt(format!(
                        "internal {hash} commits {committed}"
                    )));
                }
                Arc::new(VNode::Internal {
                    left: left_node,
                    right: right_node,
                    summary,
                    hash: *hash,
                })
            }
        };
        memo.insert(*hash, node.clone());
        Ok(node)
    }

    /// Loads the ledger version committed at `height`.
    pub fn load_ledger(&self, height: u64) -> Result<UtxoLedger, LedgerError> {
        let snapshot = self
            .snapshot(height)?
            .ok_or(LedgerError::MissingSnapshot(height))?;
        let mut memo = HashMap::new();
        let root = self.load_node(&snapshot.root, &mut memo)?;
        if root.hash() != snapshot.root {
            return Err(LedgerError::RootMismatch(
                height,
                snapshot.root,
                root.hash(),
            ));
        }
        if root.summary().total != snapshot.total {
            return Err(LedgerError::TotalMismatch(
                height,
                snapshot.total,
                root.summary().total,
            ));
        }
        Ok(UtxoLedger::from_root(root))
    }

    /// Loads the current (most recent) ledger version, if any.
    pub fn load_current(&self) -> Result<Option<UtxoLedger>, LedgerError> {
        match self.current_height()? {
            Some(height) => Ok(Some(self.load_ledger(height)?)),
            None => Ok(None),
        }
    }

    /// The snapshot record at `height`, if present.
    pub fn snapshot(&self, height: u64) -> Result<Option<SnapshotRecord>, LedgerError> {
        match self.tree.get(height_key(PREFIX_SNAPSHOT, height))? {
            Some(raw) => Ok(Some(Self::decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// The delta leading into `height`, if present.
    pub fn delta(&self, height: u64) -> Result<Option<LedgerDelta>, LedgerError> {
        match self.tree.get(height_key(PREFIX_DELTA, height))? {
            Some(raw) => Ok(Some(Self::decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// All snapshots in height order.
    pub fn snapshots(&self) -> Result<Vec<SnapshotRecord>, LedgerError> {
        let mut out = Vec::new();
        for entry in self.tree.scan_prefix(&[PREFIX_SNAPSHOT]) {
            let (_, value) = entry?;
            out.push(Self::decode(&value)?);
        }
        Ok(out)
    }

    /// All deltas in height order.
    pub fn deltas(&self) -> Result<Vec<(u64, LedgerDelta)>, LedgerError> {
        let mut out = Vec::new();
        for entry in self.tree.scan_prefix(&[PREFIX_DELTA]) {
            let (key, value) = entry?;
            let height = u64::from_le_bytes(key[1..9].try_into().unwrap_or_default());
            out.push((height, Self::decode(&value)?));
        }
        Ok(out)
    }

    /// Seeds the genesis version at height 0. The delta lists every genesis entry as created
    /// so that [`LedgerStore::rebuild_from_deltas`] reconstructs the chain from empty.
    pub fn init_genesis(
        &mut self,
        block_hash: Hash,
        ledger: &UtxoLedger,
    ) -> Result<(), LedgerError> {
        if self.current_height()?.is_some() {
            return Err(LedgerError::Corrupt("genesis already initialized".into()));
        }
        let delta = LedgerDelta {
            spent: Vec::new(),
            created: ledger.iter().cloned().collect(),
        };
        self.save_version(0, block_hash, ledger, &delta)
    }

    /// Seeds genesis state and its full block so the chain can be reconstructed after restart.
    pub fn init_genesis_with_block(
        &mut self,
        block: &oxydome_core::Block,
        ledger: &UtxoLedger,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
    ) -> Result<(), LedgerError> {
        if block.header.height != 0 || !block.roots_match() {
            return Err(LedgerError::Corrupt("invalid genesis block".into()));
        }
        if self.current_height()?.is_some() {
            return Err(LedgerError::Corrupt("genesis already initialized".into()));
        }
        let delta = LedgerDelta {
            spent: Vec::new(),
            created: ledger.iter().cloned().collect(),
        };
        self.save_version_with_ovm_and_block(
            0,
            block.hash(),
            ledger,
            &delta,
            contracts,
            &Default::default(),
            block,
        )
    }

    /// Loads the GAS state committed at `height`.

    /// Atomically commits a new ledger version at `height` together with its delta.
    ///
    /// Only nodes not already persisted are written; on-disk nodes are never mutated because
    /// their hashes are content-addressed.
    pub fn save_version(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
    ) -> Result<(), LedgerError> {
        self.save_version_with_ovm(
            height,
            block_hash,
            ledger,
            delta,
            &Default::default(),
            &Default::default(),
        )
    }

    /// Atomically commits UTXO and OVM state for a finalized height.
    pub fn save_version_with_ovm(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
    ) -> Result<(), LedgerError> {
        self.save_version_contents(
            height,
            block_hash,
            ledger,
            delta,
            contracts,
            &Default::default(),
            &Default::default(),
            gas,
            None,
            None,
        )
    }

    /// Atomically commits UTXO, OVM and block data for a finalized height.
    pub fn save_version_with_ovm_and_block(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
        block: &oxydome_core::Block,
    ) -> Result<(), LedgerError> {
        if block.header.height != height || block.hash() != block_hash {
            return Err(LedgerError::Corrupt(
                "block does not match persisted version".into(),
            ));
        }
        self.save_version_contents(
            height,
            block_hash,
            ledger,
            delta,
            contracts,
            &Default::default(),
            &Default::default(),
            gas,
            Some(block),
            None,
        )
    }

    /// Atomically commits UTXO, OVM, DAO, OHM and block data for a finalized height, without
    /// finalized-evidence bytes. Used by nodes that persist OHM state but not audit evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn save_version_with_ohm_and_block(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        daos: &std::collections::BTreeMap<Hash, DaoState>,
        ohm_states: &std::collections::BTreeMap<Hash, OhmState>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
        block: &oxydome_core::Block,
    ) -> Result<(), LedgerError> {
        if block.header.height != height || block.hash() != block_hash {
            return Err(LedgerError::Corrupt(
                "block does not match persisted version".into(),
            ));
        }
        self.save_version_contents(
            height,
            block_hash,
            ledger,
            delta,
            contracts,
            daos,
            ohm_states,
            gas,
            Some(block),
            None,
        )
    }

    /// Atomically commits UTXO, OVM, block data, and opaque finalized-evidence bytes.
    ///
    /// The state crate stores evidence opaquely to avoid depending on the higher-level audit
    /// and consensus crates; callers decode and validate it before use.
    pub fn save_version_with_finality(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
        block: &oxydome_core::Block,
        finality_evidence: &[u8],
    ) -> Result<(), LedgerError> {
        if block.header.height != height
            || block.hash() != block_hash
            || finality_evidence.is_empty()
        {
            return Err(LedgerError::Corrupt(
                "block or finality evidence does not match persisted version".into(),
            ));
        }
        self.save_version_with_dao_and_finality(
            height,
            block_hash,
            ledger,
            delta,
            contracts,
            &Default::default(),
            &Default::default(),
            gas,
            block,
            finality_evidence,
        )
    }

    /// Atomically commits UTXO, OVM, DAO, OHM, block, and finalized-evidence state.
    #[allow(clippy::too_many_arguments)]
    pub fn save_version_with_dao_and_finality(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        daos: &std::collections::BTreeMap<Hash, DaoState>,
        ohm_states: &std::collections::BTreeMap<Hash, OhmState>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
        block: &oxydome_core::Block,
        finality_evidence: &[u8],
    ) -> Result<(), LedgerError> {
        if block.header.height != height
            || block.hash() != block_hash
            || finality_evidence.is_empty()
        {
            return Err(LedgerError::Corrupt(
                "block or finality evidence does not match persisted version".into(),
            ));
        }
        self.save_version_contents(
            height,
            block_hash,
            ledger,
            delta,
            contracts,
            daos,
            ohm_states,
            gas,
            Some(block),
            Some(finality_evidence),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_version_contents(
        &mut self,
        height: u64,
        block_hash: Hash,
        ledger: &UtxoLedger,
        delta: &LedgerDelta,
        contracts: &std::collections::BTreeMap<Hash, OvmContract>,
        daos: &std::collections::BTreeMap<Hash, DaoState>,
        ohm_states: &std::collections::BTreeMap<Hash, OhmState>,
        gas: &(BTreeMap<PublicKey, GasAccount>, Amount, Amount, u64),
        block: Option<&oxydome_core::Block>,
        finality_evidence: Option<&[u8]>,
    ) -> Result<(), LedgerError> {
        self.ensure_seeded()?;

        // Post-order walk collecting nodes; skip complete subtrees that already exist.
        let mut writes: Vec<(Hash, NodeMeta)> = Vec::new();
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut stack: Vec<(Arc<VNode>, bool)> = vec![(ledger.root_node().clone(), false)];
        while let Some((node, visited)) = stack.pop() {
            let hash = node.hash();
            if self.persisted.contains(&hash) || seen.contains(&hash) {
                continue;
            }
            match node.as_ref() {
                VNode::Empty => {}
                VNode::Leaf { entry, .. } => {
                    writes.push((hash, NodeMeta::Leaf(entry.clone())));
                    seen.insert(hash);
                }
                VNode::Internal {
                    left,
                    right,
                    summary,
                    ..
                } if !visited => {
                    stack.push((node.clone(), true));
                    stack.push((right.clone(), false));
                    stack.push((left.clone(), false));
                }
                VNode::Internal {
                    left,
                    right,
                    summary,
                    ..
                } => {
                    let left_hash = left.hash();
                    let right_hash = right.hash();
                    writes.push((
                        hash,
                        NodeMeta::Internal {
                            left: if left_hash.is_zero() {
                                None
                            } else {
                                Some(left_hash)
                            },
                            right: if right_hash.is_zero() {
                                None
                            } else {
                                Some(right_hash)
                            },
                            count: summary.count,
                            total: summary.total,
                        },
                    ));
                    seen.insert(hash);
                }
            }
        }

        let snapshot = SnapshotRecord {
            height,
            block_hash,
            root: ledger.root(),
            total: ledger.total(),
        };

        let mut batch = sled::Batch::default();
        for (hash, meta) in &writes {
            batch.insert(node_key(hash), Self::encode(meta)?);
        }
        batch.insert(
            height_key(PREFIX_SNAPSHOT, height),
            Self::encode(&snapshot)?,
        );
        batch.insert(height_key(PREFIX_DELTA, height), Self::encode(delta)?);
        batch.insert(
            height_key(PREFIX_OVM, height),
            Self::encode(&OvmSnapshot {
                height,
                root: oxydome_crypto::hash_value(&("oxydome-ovm-state-v1", contracts)),
                contracts: contracts.clone(),
            })?,
        );
        batch.insert(
            height_key(PREFIX_DAO, height),
            Self::encode(&DaoSnapshot {
                height,
                root: oxydome_crypto::hash_value(&("oxydome-dao-state-v1", daos)),
                daos: daos.clone(),
            })?,
        );
        batch.insert(
            height_key(PREFIX_OHM_STATE, height),
            Self::encode(&OhmSnapshot {
                height,
                root: oxydome_crypto::hash_value(&("oxydome-ohm-state-v1", ohm_states)),
                states: ohm_states.clone(),
            })?,
        );
        batch.insert(
            height_key(PREFIX_GAS, height),
            Self::encode(&GasSnapshot {
                height,
                accounts: gas.0.clone(),
                gas_supply: gas.1,
                ox_price: gas.2,
                last_airdrop_height: gas.3,
            })?,
        );
        if let Some(block) = block {
            batch.insert(height_key(PREFIX_BLOCK, height), Self::encode(block)?);
        }
        if let Some(evidence) = finality_evidence {
            batch.insert(height_key(PREFIX_FINALITY, height), evidence);
        }
        batch.insert(&KEY_CURRENT, height.to_le_bytes().to_vec());
        self.tree.apply_batch(batch)?;

        // Only after a successful commit are these nodes considered persisted.
        self.persisted
            .extend(writes.into_iter().map(|(hash, _)| hash));
        Ok(())
    }

    /// Loads opaque finalized-evidence bytes saved atomically with a block.
    pub fn finality_evidence(&self, height: u64) -> Result<Option<Vec<u8>>, LedgerError> {
        Ok(self
            .tree
            .get(height_key(PREFIX_FINALITY, height))?
            .map(|bytes| bytes.to_vec()))
    }

    /// Replays the chain from an empty ledger, checking every saved snapshot's root and
    /// total against the recomputed state. Returns the number of verified versions.
    pub fn verify_history(&self) -> Result<usize, LedgerError> {
        self.replay(false)?;
        Ok(self.current_height()?.map(|h| h + 1).unwrap_or(0) as usize)
    }

    /// Replays the chain from an empty ledger and returns the final ledger.
    pub fn rebuild_from_deltas(&self) -> Result<UtxoLedger, LedgerError> {
        self.replay(true).map(|ledger| ledger.unwrap_or_default())
    }

    fn replay(&self, return_ledger: bool) -> Result<Option<UtxoLedger>, LedgerError> {
        let Some(current) = self.current_height()? else {
            return Ok(None);
        };
        let mut ledger = UtxoLedger::new();
        for height in 0..=current {
            let snapshot = self
                .snapshot(height)?
                .ok_or(LedgerError::MissingSnapshot(height))?;
            let delta = self
                .delta(height)?
                .ok_or(LedgerError::MissingDelta(height))?;
            for outpoint in &delta.spent {
                ledger = ledger.remove(outpoint).0;
            }
            for entry in &delta.created {
                ledger = ledger.insert(entry.clone());
            }
            if ledger.root() != snapshot.root {
                return Err(LedgerError::RootMismatch(
                    snapshot.height,
                    snapshot.root,
                    ledger.root(),
                ));
            }
            if ledger.total() != snapshot.total {
                return Err(LedgerError::TotalMismatch(
                    snapshot.height,
                    snapshot.total,
                    ledger.total(),
                ));
            }
        }
        if return_ledger {
            Ok(Some(ledger))
        } else {
            Ok(None)
        }
    }
}

/// Computes the delta between two ledger versions.
///
/// Content-aware: an entry changed at the same outpoint (for example the rebound refund
/// spending and recreating an exit output) is recorded as spent (old value) plus created
/// (new value) so that replaying the delta yields the exact post-transition set.
pub fn ledger_diff(before: &UtxoLedger, after: &UtxoLedger) -> LedgerDelta {
    let mut spent: Vec<OutPoint> = Vec::new();
    let mut created: Vec<UtxoEntry> = Vec::new();
    for entry in before.iter() {
        match after.get(&entry.outpoint) {
            None => spent.push(entry.outpoint),
            Some(current) if current != entry => {
                spent.push(entry.outpoint);
                created.push(current.clone());
            }
            _ => {}
        }
    }
    for entry in after.iter() {
        if before.get(&entry.outpoint).is_none() {
            created.push(entry.clone());
        }
    }
    LedgerDelta { spent, created }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::{UtxoEntry, UtxoLedger};
    use oxydome_core::tx::OutputKind;
    use oxydome_crypto::KeyPair;

    fn entry(i: u32, amount: Amount) -> UtxoEntry {
        let owner = KeyPair::from_seed(&[i as u8; 32]).public();
        UtxoEntry::new(
            OutPoint::new(Hash::zero(), i),
            TxOutput {
                amount,
                recipient: owner,
                kind: OutputKind::Spendable,
                rebound_gen: None,
            },
            1,
        )
    }

    fn op(i: u32) -> OutPoint {
        OutPoint::new(Hash::zero(), i)
    }

    use oxydome_core::TxOutput;

    #[test]
    fn save_and_load_versions() {
        let mut store = LedgerStore::open_temporary().unwrap();
        let mut ledger = UtxoLedger::new();
        let gen_root = ledger.root();
        store
            .init_genesis(Hash::zero(), &ledger)
            .expect("empty genesis");

        // Height 1: insert two entries.
        ledger = ledger.insert(entry(0, 10));
        ledger = ledger.insert(entry(1, 20));
        let mut delta = ledger_diff(&UtxoLedger::new(), &ledger);
        store
            .save_version(1, Hash::zero(), &ledger, &delta)
            .unwrap();

        // Height 2: spend one and re-insert a replacement at the same outpoint (rebound-like).
        let rebound = UtxoEntry::new(
            op(0),
            TxOutput {
                amount: 9,
                recipient: ledger.get(&op(0)).unwrap().output.recipient,
                kind: OutputKind::Spendable,
                rebound_gen: Some(1),
            },
            2,
        );
        let before_h2 = ledger.clone();
        ledger = ledger.remove(&op(0)).0;
        ledger = ledger.insert(rebound.clone());
        delta = ledger_diff(&before_h2, &ledger);
        store
            .save_version(2, Hash::zero(), &ledger, &delta)
            .unwrap();

        assert_eq!(store.current_height().unwrap(), Some(2));
        assert_eq!(store.verify_history().unwrap(), 3);

        let replay = store.rebuild_from_deltas().unwrap();
        assert_eq!(replay.root(), ledger.root());
        assert_eq!(replay.total(), ledger.total());
        assert_eq!(replay.len(), 2);

        let h2 = store.load_ledger(2).unwrap();
        assert_eq!(h2.total(), 29);
        assert_eq!(h2.get(&op(0)).unwrap(), &rebound);

        let h1 = store.load_ledger(1).unwrap();
        assert_eq!(h1.total(), 30);
        assert_ne!(h1.root(), gen_root);

        let h0 = store.load_ledger(0).unwrap();
        assert!(h0.is_empty());
        assert_eq!(h0.root(), gen_root);
    }

    #[test]
    fn current_loads_latest() {
        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .unwrap();
        assert!(store.load_current().unwrap().unwrap().is_empty());

        let mut ledger = UtxoLedger::new();
        ledger = ledger.insert(entry(0, 5));
        store
            .save_version(
                1,
                Hash::zero(),
                &ledger,
                &ledger_diff(&UtxoLedger::new(), &ledger),
            )
            .unwrap();
        assert_eq!(store.load_current().unwrap().unwrap().total(), 5);
    }

    #[test]
    fn ovm_state_is_saved_atomically_with_ledger_version() {
        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .unwrap();
        let ledger = UtxoLedger::new().insert(entry(4, 7));
        let code = oxydome_ovm::Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::Push(9),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let contract_id = Hash([5; 64]);
        let contracts = [(
            contract_id,
            OvmContract {
                code,
                storage: [(1, 42)].into_iter().collect(),
            },
        )]
        .into_iter()
        .collect();

        store
            .save_version_with_ovm(
                1,
                Hash::zero(),
                &ledger,
                &ledger_diff(&UtxoLedger::new(), &ledger),
                &contracts,
                &Default::default(),
            )
            .unwrap();

        assert_eq!(store.load_ovm_state(1).unwrap(), contracts);
        assert!(store.load_ovm_state(0).unwrap().is_empty());
    }

    #[test]
    fn deltas_replay_replaced_outpoint() {
        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .unwrap();

        let mut v0 = UtxoLedger::new();
        v0 = v0.insert(entry(3, 100));
        let old = v0.get(&op(3)).unwrap().clone();
        store
            .save_version(1, Hash::zero(), &v0, &ledger_diff(&UtxoLedger::new(), &v0))
            .unwrap();

        let mut v1 = v0.remove(&op(3)).0;
        let new = UtxoEntry::new(
            op(3),
            TxOutput {
                amount: 60,
                recipient: old.output.recipient,
                kind: OutputKind::Spendable,
                rebound_gen: Some(2),
            },
            2,
        );
        v1 = v1.insert(new.clone());
        let delta = ledger_diff(&v0, &v1);
        assert_eq!(delta.spent, vec![op(3)]);
        assert!(delta.created.iter().any(|e| e == &new));
        store.save_version(2, Hash::zero(), &v1, &delta).unwrap();

        assert_eq!(store.verify_history().unwrap(), 3);
        let rebuilt = store.rebuild_from_deltas().unwrap();
        assert_eq!(rebuilt.total(), 60);
        assert_eq!(rebuilt.get(&op(3)).unwrap(), &new);
    }

    #[test]
    fn reopen_preserves_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger");

        let mut store = LedgerStore::open(&path).unwrap();
        let mut ledger = UtxoLedger::new();
        ledger = ledger.insert(entry(0, 10));
        ledger = ledger.insert(entry(1, 20));
        let delta = ledger_diff(&UtxoLedger::new(), &ledger);
        store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .unwrap();
        store
            .save_version(1, Hash::zero(), &ledger, &delta)
            .unwrap();
        let root = ledger.root();
        let total = ledger.total();
        drop(store);

        let mut reopened = LedgerStore::open(&path).unwrap();
        assert_eq!(reopened.current_height().unwrap(), Some(1));
        assert_eq!(reopened.verify_history().unwrap(), 2);
        let loaded = reopened.load_current().unwrap().unwrap();
        assert_eq!(loaded.root(), root);
        assert_eq!(loaded.total(), total);

        // Adding a fourth version after reopen still verifies the full history.
        let mut after = loaded.clone();
        after = after.insert(entry(2, 30));
        let d = ledger_diff(&loaded, &after);
        reopened.save_version(2, Hash::zero(), &after, &d).unwrap();
        assert_eq!(reopened.verify_history().unwrap(), 3);
    }

    #[test]
    fn missing_versions_error() {
        let store = LedgerStore::open_temporary().unwrap();
        assert!(store.load_ledger(0).is_err());
        assert!(store.load_ledger(5).is_err());
        assert!(store.verify_history().is_ok());
        assert!(store.rebuild_from_deltas().unwrap().is_empty());
    }

    #[test]
    fn double_init_genesis_rejected() {
        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .unwrap();
        assert!(store
            .init_genesis(Hash::zero(), &UtxoLedger::new())
            .is_err());
    }
}
