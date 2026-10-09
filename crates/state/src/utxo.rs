//! The authenticated UTXO ledger.
//!
//! Each unspent output is a leaf of a persistent 256-bit sparse Merkle tree keyed by
//! `hash(OutPoint)`. The root is the block's `state_root`, which masters verify through
//! inclusion proofs. Every operation is functional: inserting or removing an entry returns a
//! *new* ledger version sharing unchanged subtrees, so historical versions remain queryable
//! and portable.

use oxydome_core::{Amount, OutPoint, TxOutput};
use oxydome_crypto::{
    hash_value, merkle_leaf_hash, merkle_node_hash, sparse_merkle_verify, Hash, PathKey,
    SparseProof, SPARSE_MERKLE_DEPTH,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A single unspent transaction output plus its creation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub outpoint: OutPoint,
    pub output: TxOutput,
    /// Block height at which this output was created (used for rebound maturity).
    pub created_height: u64,
}

impl UtxoEntry {
    pub fn new(outpoint: OutPoint, output: TxOutput, created_height: u64) -> Self {
        Self {
            outpoint,
            output,
            created_height,
        }
    }

    /// The Merkle leaf commitment for this entry.
    pub fn leaf(&self) -> Hash {
        hash_value(self)
    }
}

/// Aggregate over the outputs inside a subtree. `count` is the number of live leaves,
/// `total` the sum of their amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Summary {
    pub(crate) count: u64,
    pub(crate) total: Amount,
}

/// A node of the sparse Merkle tree.
///
/// Level conventions match [`SPARSE_MERKLE_DEPTH`] and the independent builder in
/// `oxydome_crypto`: the root sits at depth 0 and the leaf decision uses `path.bit(depth)`;
/// leaves store entries at depth [`SPARSE_MERKLE_DEPTH`]. An empty subtree commits as
/// [`Hash::zero`], never as a two-empty-child internal node.
#[derive(Debug, Clone)]
pub(crate) enum VNode {
    Empty,
    Leaf {
        entry: UtxoEntry,
        hash: Hash,
    },
    Internal {
        left: Arc<VNode>,
        right: Arc<VNode>,
        summary: Summary,
        hash: Hash,
    },
}

impl VNode {
    pub(crate) fn hash(&self) -> Hash {
        match self {
            VNode::Empty => Hash::zero(),
            VNode::Leaf { hash, .. } => *hash,
            VNode::Internal { hash, .. } => *hash,
        }
    }

    pub(crate) fn summary(&self) -> Summary {
        match self {
            VNode::Empty => Summary::default(),
            VNode::Leaf { entry, .. } => Summary {
                count: 1,
                total: entry.output.amount,
            },
            VNode::Internal { summary, .. } => *summary,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, VNode::Empty)
    }

    pub(crate) fn is_leaf(&self) -> bool {
        matches!(self, VNode::Leaf { .. })
    }
}

fn leaf(entry: UtxoEntry) -> Arc<VNode> {
    let hash = merkle_leaf_hash(&entry.leaf());
    Arc::new(VNode::Leaf { entry, hash })
}

fn internal(left: Arc<VNode>, right: Arc<VNode>) -> Arc<VNode> {
    let l = left.summary();
    let r = right.summary();
    let summary = Summary {
        count: l.count.saturating_add(r.count),
        total: l.total.saturating_add(r.total),
    };
    let hash = merkle_node_hash(&left.hash(), &right.hash());
    Arc::new(VNode::Internal {
        left,
        right,
        summary,
        hash,
    })
}

/// The path of an outpoint within the tree: the first 32 bytes of the outpoint key.
pub(crate) fn path_of(outpoint: &OutPoint) -> PathKey {
    PathKey::from_bytes(outpoint.key().as_bytes())
}

fn insert_node(node: &VNode, path: &PathKey, depth: usize, entry: UtxoEntry) -> Arc<VNode> {
    if depth == SPARSE_MERKLE_DEPTH {
        return leaf(entry);
    }
    match node {
        VNode::Empty | VNode::Leaf { .. } => {
            // Build the single-path spine down to the leaf at depth SPARSE_MERKLE_DEPTH.
            let go_right = path.bit(depth);
            let child = insert_node(&VNode::Empty, path, depth + 1, entry);
            if go_right {
                internal(Arc::new(VNode::Empty), child)
            } else {
                internal(child, Arc::new(VNode::Empty))
            }
        }
        VNode::Internal { left, right, .. } => {
            if path.bit(depth) {
                internal(left.clone(), insert_node(right, path, depth + 1, entry))
            } else {
                internal(insert_node(left, path, depth + 1, entry), right.clone())
            }
        }
    }
}

/// Removes the leaf at `path`, returning `None` when the whole subtree at `depth` becomes empty.
fn remove_node(node: &VNode, path: &PathKey, depth: usize) -> Option<Arc<VNode>> {
    if depth == SPARSE_MERKLE_DEPTH {
        return None;
    }
    match node {
        VNode::Empty => None,
        VNode::Internal { left, right, .. } => {
            let (new_left, new_right) = if path.bit(depth) {
                let new_right =
                    remove_node(right, path, depth + 1).unwrap_or_else(|| Arc::new(VNode::Empty));
                (left.clone(), new_right)
            } else {
                let new_left =
                    remove_node(left, path, depth + 1).unwrap_or_else(|| Arc::new(VNode::Empty));
                (new_left, right.clone())
            };
            if new_left.is_empty() && new_right.is_empty() {
                None
            } else {
                Some(internal(new_left, new_right))
            }
        }
        VNode::Leaf { .. } => None,
    }
}

/// Walks the tree along `path`, collecting sibling hashes at every level (top-down).
/// Returns `false` if the key is not present.
fn collect_siblings(mut node: &VNode, path: &PathKey, out: &mut Vec<Hash>) -> bool {
    for depth in 0..SPARSE_MERKLE_DEPTH {
        match node {
            VNode::Internal { left, right, .. } => {
                if path.bit(depth) {
                    out.push(left.hash());
                    node = right;
                } else {
                    out.push(right.hash());
                    node = left;
                }
            }
            _ => return false,
        }
    }
    node.is_leaf()
}

/// Returns the entry stored at `path`, if any.
fn lookup<'a>(mut node: &'a VNode, path: &PathKey, outpoint: &OutPoint) -> Option<&'a UtxoEntry> {
    for depth in 0..SPARSE_MERKLE_DEPTH {
        match node {
            VNode::Internal { left, right, .. } => {
                node = if path.bit(depth) { right } else { left };
            }
            _ => return None,
        }
    }
    match node {
        VNode::Leaf { entry, .. } if entry.outpoint == *outpoint => Some(entry),
        _ => None,
    }
}

/// An immutable version of the UTXO ledger.
#[derive(Debug, Clone)]
pub struct UtxoLedger {
    root: Arc<VNode>,
}

impl Default for UtxoLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoLedger {
    pub fn new() -> Self {
        Self {
            root: Arc::new(VNode::Empty),
        }
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.root.summary().count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total amount of Ox held across all live entries.
    pub fn total(&self) -> Amount {
        self.root.summary().total
    }

    /// The state root: hash of the root node.
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    /// Access to the root node (used by `crate::ledger_store` to persist the tree).
    pub(crate) fn root_node(&self) -> &Arc<VNode> {
        &self.root
    }

    /// Rebuilds a ledger version from a preconstructed root node (used by `crate::ledger_store`).
    pub(crate) fn from_root(root: Arc<VNode>) -> Self {
        Self { root }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        let path = path_of(outpoint);
        lookup(&self.root, &path, outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.get(outpoint).is_some()
    }

    /// Returns a new ledger version with `entry` inserted (replacing any entry at the same
    /// outpoint). The receiver is left untouched.
    pub fn insert(&self, entry: UtxoEntry) -> UtxoLedger {
        let path = path_of(&entry.outpoint);
        let root = insert_node(&self.root, &path, 0, entry);
        UtxoLedger { root }
    }

    /// Returns a new ledger version without `outpoint`, plus the removed entry (or `None`
    /// when the outpoint was not present). The receiver is left untouched.
    pub fn remove(&self, outpoint: &OutPoint) -> (UtxoLedger, Option<UtxoEntry>) {
        let removed = self.get(outpoint).cloned();
        if removed.is_none() {
            return (self.clone(), None);
        }
        let path = path_of(outpoint);
        let root = remove_node(&self.root, &path, 0).unwrap_or_else(|| Arc::new(VNode::Empty));
        (UtxoLedger { root }, removed)
    }

    /// Builds a sparse-Merkle inclusion proof for `outpoint`, or `None` if absent.
    ///
    /// Siblings are ordered from the leaf level upward (`siblings[0]` is the leaf's sibling),
    /// matching [`SparseProof`] and `oxydome_crypto::sparse_merkle_verify`.
    pub fn proof(&self, outpoint: &OutPoint) -> Option<SparseProof> {
        if !self.contains(outpoint) {
            return None;
        }
        let path = path_of(outpoint);
        let mut siblings = Vec::with_capacity(SPARSE_MERKLE_DEPTH);
        let found = collect_siblings(&self.root, &path, &mut siblings);
        debug_assert!(found);
        siblings.reverse();
        Some(SparseProof { siblings, path })
    }

    /// Verifies that `entry` is included in a ledger with the given root.
    pub fn verify_inclusion(root: &Hash, entry: &UtxoEntry, proof: &SparseProof) -> bool {
        sparse_merkle_verify(root, &entry.leaf(), proof)
    }

    /// Iterates entries in path order (deterministic, left-to-right).
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            stack: vec![&self.root],
        }
    }

    /// Collects outpoints of all Exit/Reserve outputs (used by the rebound refund).
    pub fn exit_outpoints(&self) -> Vec<OutPoint> {
        self.iter()
            .filter(|e| e.output.kind.is_exit())
            .map(|e| e.outpoint)
            .collect()
    }

    /// Materializes the ledger as a map keyed by outpoint key.
    pub fn to_map(&self) -> BTreeMap<Hash, UtxoEntry> {
        let mut map = BTreeMap::new();
        for entry in self.iter() {
            map.insert(entry.outpoint.key(), entry.clone());
        }
        map
    }

    /// Builds a ledger by inserting entries in order.
    pub fn from_entries<I: IntoIterator<Item = UtxoEntry>>(entries: I) -> Self {
        let mut ledger = UtxoLedger::new();
        for entry in entries {
            ledger = ledger.insert(entry);
        }
        ledger
    }
}

/// In-order (path-order) iterator over a ledger version.
pub struct Iter<'a> {
    stack: Vec<&'a VNode>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a UtxoEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.stack.pop()? {
                VNode::Empty => continue,
                VNode::Leaf { entry, .. } => return Some(entry),
                VNode::Internal { left, right, .. } => {
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::tx::OutputKind;
    use oxydome_crypto::{KeyPair, SPARSE_MERKLE_DEPTH};

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

    #[test]
    fn versions_are_immutable() {
        let v0 = UtxoLedger::new();
        let v1 = v0.insert(entry(0, 10));
        let v2 = v1.insert(entry(1, 20));

        assert!(v0.is_empty());
        assert_eq!(v0.total(), 0);

        assert_eq!(v1.len(), 1);
        assert_eq!(v1.total(), 10);

        assert_eq!(v2.len(), 2);
        assert_eq!(v2.total(), 30);

        let (v3, removed) = v2.remove(&op(0));
        assert_eq!(removed.unwrap().output.amount, 10);
        assert_eq!(v3.total(), 20);
        assert_eq!(v3.len(), 1);

        // Older versions are untouched by later mutations.
        assert_eq!(v2.total(), 30);
        assert_eq!(v1.total(), 10);
        assert_eq!(v0.total(), 0);

        // Removing an absent outpoint is a no-op returning None.
        let (v4, none) = v3.remove(&op(999));
        assert!(none.is_none());
        assert_eq!(v4.total(), v3.total());
        assert_eq!(v4.root(), v3.root());

        // Removing the last entry yields the empty ledger again.
        let (v5, removed) = v4.remove(&op(1));
        assert_eq!(removed.unwrap().output.amount, 20);
        assert!(v5.is_empty());
        assert_eq!(v5.root(), Hash::zero());
    }

    #[test]
    fn replace_updates_entry_in_place() {
        let owner = KeyPair::from_seed(&[7; 32]).public();
        let a = UtxoEntry::new(
            op(7),
            TxOutput {
                amount: 100,
                recipient: owner,
                kind: OutputKind::Spendable,
                rebound_gen: None,
            },
            1,
        );
        let b = UtxoEntry::new(
            op(7),
            TxOutput {
                amount: 50,
                recipient: owner,
                kind: OutputKind::Spendable,
                rebound_gen: Some(1),
            },
            1,
        );

        let v0 = UtxoLedger::new().insert(a.clone());
        let v1 = v0.insert(b.clone());

        assert_eq!(v0.len(), 1);
        assert_eq!(v0.total(), 100);
        assert_eq!(v1.len(), 1);
        assert_eq!(v1.total(), 50);

        let pa = v0.proof(&op(7)).unwrap();
        assert!(UtxoLedger::verify_inclusion(&v0.root(), &a, &pa));
        assert!(!UtxoLedger::verify_inclusion(&v0.root(), &b, &pa));

        let pb = v1.proof(&op(7)).unwrap();
        assert!(UtxoLedger::verify_inclusion(&v1.root(), &b, &pb));
        assert!(!UtxoLedger::verify_inclusion(&v1.root(), &a, &pb));
    }

    #[test]
    fn root_matches_naive_sparse_tree() {
        use oxydome_crypto::{sparse_merkle_root, PathKey};

        let entries: Vec<UtxoEntry> = (0..200)
            .map(|i| entry(i, (i as u64 % 97 + 1) as u128))
            .collect();
        let ledger = UtxoLedger::from_entries(entries.iter().cloned());

        let naive: Vec<(PathKey, Hash)> = entries
            .iter()
            .map(|e| (PathKey::from_bytes(e.outpoint.key().as_bytes()), e.leaf()))
            .collect();
        assert_eq!(ledger.root(), sparse_merkle_root(&naive));
        assert_eq!(ledger.len(), 200);

        for i in 0..10 {
            let e = entries[i as usize].clone();
            let p = ledger.proof(&e.outpoint).unwrap();
            assert_eq!(p.siblings.len(), SPARSE_MERKLE_DEPTH);
            assert!(UtxoLedger::verify_inclusion(&ledger.root(), &e, &p));
            let other = entry(i + 10_000, 1);
            assert!(!UtxoLedger::verify_inclusion(&ledger.root(), &other, &p));
        }

        // Removing one entry changes only the committed root, not older versions.
        let (reduced, _) = ledger.remove(&entries[5].outpoint);
        assert_eq!(reduced.len(), 199);
        assert_ne!(reduced.root(), ledger.root());
    }

    #[test]
    fn iteration_and_map_are_deterministic() {
        let entries: Vec<UtxoEntry> = (0..50).map(|i| entry(i, 1)).collect();
        let ledger = UtxoLedger::from_entries(entries.iter().cloned());

        let iter_keys: Vec<Hash> = ledger.iter().map(|e| e.outpoint.key()).collect();
        assert_eq!(iter_keys.len(), 50);

        // Iteration follows the tree's left-to-right path order (bit 0 = root decision).
        let mut expected: Vec<(PathKey, Hash)> = entries
            .iter()
            .map(|e| {
                (
                    PathKey::from_bytes(e.outpoint.key().as_bytes()),
                    e.outpoint.key(),
                )
            })
            .collect();
        expected.sort_by(|a, b| {
            for i in 0..SPARSE_MERKLE_DEPTH {
                match (a.0.bit(i), b.0.bit(i)) {
                    (false, true) => return std::cmp::Ordering::Less,
                    (true, false) => return std::cmp::Ordering::Greater,
                    _ => {}
                }
            }
            std::cmp::Ordering::Equal
        });
        let expected_keys: Vec<Hash> = expected.iter().map(|(_, key)| *key).collect();
        assert_eq!(iter_keys, expected_keys);

        // to_map contains exactly the same entries.
        let map_keys: Vec<Hash> = ledger.to_map().keys().cloned().collect();
        assert_eq!(map_keys.len(), 50);
        let mut sorted_iter = iter_keys.clone();
        sorted_iter.sort();
        let mut sorted_map = map_keys;
        sorted_map.sort();
        assert_eq!(sorted_iter, sorted_map);

        // Stable across independent rebuilds.
        let rebuilt = UtxoLedger::from_entries(entries.iter().rev().cloned());
        assert_eq!(rebuilt.root(), ledger.root());
        assert_eq!(
            rebuilt
                .iter()
                .map(|e| e.outpoint.key())
                .collect::<Vec<Hash>>(),
            iter_keys
        );
    }

    #[test]
    fn exit_outpoints_are_collected() {
        let v0 = UtxoLedger::new().insert(entry(0, 5));
        let owner = KeyPair::from_seed(&[9; 32]).public();
        let exit = UtxoEntry::new(op(8), TxOutput::exit(12, owner, 0), 2);
        let v1 = v0.insert(exit);
        assert_eq!(v1.exit_outpoints(), vec![op(8)]);
    }

    #[test]
    fn perf_smoke() {
        let mut ledger = UtxoLedger::new();
        for i in 0..2_000u32 {
            ledger = ledger.insert(entry(i, 1));
        }
        assert_eq!(ledger.len(), 2_000);
        assert_eq!(ledger.total(), 2_000);

        let mid = op(1_000);
        let e = ledger.get(&mid).unwrap().clone();
        let p = ledger.proof(&mid).unwrap();
        assert!(UtxoLedger::verify_inclusion(&ledger.root(), &e, &p));
    }
}
