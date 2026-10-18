//! Cryptographic primitives for Oxydome.
//!
//! Oxydome uses:
//! * **SHA3-512** (FIPS 202 / Keccak) for all hashing: block hashes, transaction ids,
//!   Merkle trees, state roots and software code manifests.
//! * **Ed25519** for all signatures: transactions, blocks, admission certificates and
//!   governance votes.
//! * **BLAKE2b-512** for position-dependent transaction labels and the coin-toss ordering
//!   seed — chosen as a cryptographically secure, less-common alternative to the SHA family.
//!
//! ## Cross-Chain Verification
//!
//! The crypto crate also provides cryptographic primitives for cross-chain verification:
//! * **Merkle proof verification** using SHA3-512 with maximum 64 levels depth
//! * **Consensus proof verification** for 2/3 validator set threshold signatures
//! * **X25519 key exchange** for secure channel establishment
//! * **AES-256-GCM encryption** for secure message communication
//!
//! See the individual modules for detailed documentation.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_512};
use std::collections::BTreeMap;
use blake2::Blake2b512;

pub const HASH_LEN: usize = 64;
pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

// Re-export for convenience
pub use bincode;
pub use serde;
pub use sha3;

/// Generates a fixed-size byte wrapper with hex `Debug`, byte accessors and
/// serialization as a byte vector (portable across bincode and JSON).
macro_rules! fixed_bytes {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Builds the value from a slice, returning `None` on a length mismatch.
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != $len {
                    return None;
                }
                let mut out = [0u8; $len];
                out.copy_from_slice(bytes);
                Some(Self(out))
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn to_vec(self) -> Vec<u8> {
                self.0.to_vec()
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(value: [u8; $len]) -> Self {
                Self(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = Vec::<u8>::deserialize(deserializer)?;
                Self::from_slice(&bytes).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "expected {} bytes for {}, got {}",
                        $len,
                        stringify!($name),
                        bytes.len()
                    ))
                })
            }
        }
    };
}

fixed_bytes!(Hash, HASH_LEN, "A SHA3-512 digest (64 bytes).");
fixed_bytes!(
    PublicKey,
    PUBKEY_LEN,
    "An Ed25519 public key / Oxydome address."
);
fixed_bytes!(Sig, SIG_LEN, "An Ed25519 signature.");

// Re-export zeroize for secure memory clearing
pub use zeroize;

pub mod aes256gcm;
pub mod consensus;
pub mod evk;
pub mod merkle;
pub mod x25519;

impl Hash {
    pub const fn zero() -> Self {
        Hash([0u8; HASH_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

/// Hashes arbitrary bytes with SHA3-512.
pub fn hash(data: &[u8]) -> Hash {
    let mut h = Sha3_512::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; HASH_LEN];
    buf.copy_from_slice(&out);
    Hash(buf)
}

/// Hashes an ordered sequence of byte slices. Used everywhere a structured value must be
/// committed to (blocks, transactions, state leaves) without relying on a serializer.
pub fn hash_many(parts: &[&[u8]]) -> Hash {
    let mut h = Sha3_512::new();
    for p in parts {
        // Length-prefix each part to prevent concatenation ambiguity.
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let out = h.finalize();
    let mut buf = [0u8; HASH_LEN];
    buf.copy_from_slice(&out);
    Hash(buf)
}

/// Deterministic bincode serialization used for signing payloads and leaf commitments.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("serialization of internal types cannot fail")
}

/// Hashes a serializable value. Convenience over `hash(&encode(value))`.
pub fn hash_value<T: Serialize>(value: &T) -> Hash {
    hash(&encode(value))
}

/// Position-dependent label computed with BLAKE2b-512 over the block
/// header hash, the transaction's position index, a timestamp and the
/// network magic phrase. If a transaction's content changes, its `txid`
/// changes, but the position hash still validates against the same
/// block header — so the label binds the transaction to its slot in a
/// way that survives reordering while detecting content tampering via
/// the txid check in [`BlockHeader::roots_match`] / `apply_inner`.
pub fn tx_position_hash(
    block_header_hash: &Hash,
    position: u32,
    timestamp: u64,
    network_magic: &[u8],
) -> Hash {
    let mut h = Blake2b512::new();
    h.update(block_header_hash.as_bytes());
    h.update(position.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    let magic_len = (network_magic.len() as u64).to_le_bytes();
    h.update(magic_len);
    h.update(network_magic);
    let out = h.finalize();
    let mut buf = [0u8; HASH_LEN];
    buf.copy_from_slice(&out);
    Hash(buf)
}

/// Convenience wrapper around [`tx_position_hash`] that accepts the
/// block header as a separate digest and uses [`Hash::zero`] when no
/// header hash is available (e.g. for standalone tx validation tests).
pub fn compute_tx_position_hash(
    block_header_hash: Hash,
    position: usize,
    timestamp: u64,
    network_magic: &str,
) -> Hash {
    tx_position_hash(
        &block_header_hash,
        position as u32,
        timestamp,
        network_magic.as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// Ed25519 keys and signatures
// ---------------------------------------------------------------------------

/// An Ed25519 signing key.
pub struct KeyPair {
    inner: SigningKey,
}

impl KeyPair {
    /// Generates a new random keypair from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            inner: SigningKey::generate(&mut rng),
        }
    }

    /// Deterministically derives a keypair from a 32-byte seed (used in tests and config).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    pub fn from_seed_slice(seed: &[u8]) -> Option<Self> {
        if seed.len() != 32 {
            return None;
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        Some(Self::from_seed(&s))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.inner.verifying_key().to_bytes())
    }

    /// Signs a message, returning the raw signature wrapper.
    pub fn sign(&self, message: &[u8]) -> Sig {
        Sig(self.inner.sign(message).to_bytes())
    }

    pub fn secret_seed(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        Self {
            inner: SigningKey::from_bytes(&self.inner.to_bytes()),
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret key material.
        write!(f, "KeyPair(public={})", self.public().to_hex())
    }
}

/// Verifies an Ed25519 signature. Returns `false` (never panics) on malformed input.
pub fn verify(public: &PublicKey, message: &[u8], signature: &Sig) -> bool {
    let vk = match VerifyingKey::from_bytes(&public.0) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&signature.0);
    vk.verify(message, &sig).is_ok()
}

/// Signs a serializable value.
pub fn sign_value<T: Serialize>(key: &KeyPair, value: &T) -> Sig {
    key.sign(&encode(value))
}

/// Verifies a signature over a serializable value.
pub fn verify_value<T: Serialize>(public: &PublicKey, value: &T, signature: &Sig) -> bool {
    verify(public, &encode(value), signature)
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// A Merkle inclusion proof. `siblings` are ordered from the leaf level upward; the
/// `index` bits select whether the running node is the left (0) or right (1) child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    pub index: u64,
}

/// Computes the Merkle root of a list of leaves.
///
/// * Empty list -> `Hash::zero()`.
/// * An odd level duplicates its last node so every level has even length; this keeps
///   inclusion proofs uniform (exactly one sibling per level).
/// * Leaves are domain-separated with a `0x00` prefix and internal nodes with `0x01`
///   to prevent second-preimage attacks.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::zero();
    }
    let mut level: Vec<Hash> = leaves.iter().map(merkle_leaf_hash).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// The leaf commitment used by every Merkle construction: `hash(0x00 || leaf_hash)`.
pub fn merkle_leaf_hash(leaf: &Hash) -> Hash {
    hash_many(&[&[0x00u8], &leaf.0])
}

/// The internal node commitment: `hash(0x01 || left || right)`.
/// An empty subtree is committed as [`Hash::zero`], never through this function.
pub fn merkle_node_hash(left: &Hash, right: &Hash) -> Hash {
    hash_many(&[&[0x01u8], &left.0, &right.0])
}

fn next_level(level: &[Hash]) -> Vec<Hash> {
    let mut nodes = level.to_vec();
    if nodes.len() % 2 == 1 {
        if let Some(last) = nodes.last().copied() {
            nodes.push(last);
        }
    }
    nodes
        .chunks_exact(2)
        .map(|pair| merkle_node_hash(&pair[0], &pair[1]))
        .collect()
}

/// Builds an inclusion proof for `index`. Returns an empty proof for out-of-range indices.
pub fn merkle_proof(leaves: &[Hash], index: usize) -> MerkleProof {
    let mut siblings = Vec::new();
    if index >= leaves.len() {
        return MerkleProof {
            siblings,
            index: index as u64,
        };
    }
    let mut level: Vec<Hash> = leaves.iter().map(merkle_leaf_hash).collect();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            // The duplicated last node is its own sibling at this level.
            if idx + 1 < level.len() {
                level[idx + 1]
            } else {
                level[idx]
            }
        } else {
            level[idx - 1]
        };
        siblings.push(sibling);
        level = next_level(&level);
        idx /= 2;
    }
    MerkleProof {
        siblings,
        index: index as u64,
    }
}

/// Verifies an inclusion proof produced by [`merkle_proof`].
pub fn merkle_verify(root: &Hash, leaf: &Hash, proof: &MerkleProof) -> bool {
    let mut acc = merkle_leaf_hash(leaf);
    let mut idx = proof.index;
    for sibling in &proof.siblings {
        acc = if idx % 2 == 0 {
            merkle_node_hash(&acc, sibling)
        } else {
            merkle_node_hash(sibling, &acc)
        };
        idx /= 2;
    }
    &acc == root
}

// ---------------------------------------------------------------------------
// Sparse Merkle tree (fixed-depth, for the UTXO ledger)
// ---------------------------------------------------------------------------

/// Depth of the sparse Merkle tree in bits. Every leaf sits at exactly this depth, which makes
/// empty subtrees unambiguous: an empty subtree commits as [`Hash::zero`].
pub const SPARSE_MERKLE_DEPTH: usize = 256;

/// A path into the sparse Merkle tree.
///
/// Bit order follows the tree layout: bit `0` decides the branch at the root (0 = left,
/// 1 = right), bit `1` at the next level, and so on down to bit `255` at the leaf level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PathKey(pub [u64; 4]);

impl PathKey {
    /// Reads bit `i`; `i` must be in `0..SPARSE_MERKLE_DEPTH`.
    pub fn bit(&self, i: usize) -> bool {
        debug_assert!(i < SPARSE_MERKLE_DEPTH);
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    /// Builds a path from raw bytes. Little-endian u64 words are read off the first 32 bytes;
    /// shorter inputs zero-fill. The UTXO ledger derives paths from the first 32 bytes of the
    /// SHA3-512 digest of an `OutPoint`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut words = [0u64; 4];
        for (w, word) in words.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            let base = w * 8;
            for (i, b) in buf.iter_mut().enumerate() {
                if base + i < bytes.len() {
                    *b = bytes[base + i];
                }
            }
            *word = u64::from_le_bytes(buf);
        }
        Self(words)
    }
}

/// A sparse Merkle inclusion proof.
///
/// `siblings` has exactly [`SPARSE_MERKLE_DEPTH`] hashes, ordered from the leaf level upward:
/// `siblings[0]` is the sibling of the leaf's own node, `siblings[255]` the sibling at the
/// root. An empty sibling subtree commits as [`Hash::zero`]. `path` identifies the leaf
/// position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseProof {
    pub siblings: Vec<Hash>,
    pub path: PathKey,
}

/// Computes the sparse Merkle root over `(path, leaf)` pairs.
///
/// The result is a pure function of the set of entries (leaves are placed at the fixed
/// [`SPARSE_MERKLE_DEPTH`]); it does not depend on iteration order. Empty subtrees commit as
/// [`Hash::zero`].
pub fn sparse_merkle_root(entries: &[(PathKey, Hash)]) -> Hash {
    subtree_hash(entries, 0)
}

/// Builds a [`SparseProof`] for `target` over `entries`, or `None` if `target` is absent.
pub fn sparse_merkle_proof(entries: &[(PathKey, Hash)], target: &PathKey) -> Option<SparseProof> {
    let mut siblings = Vec::with_capacity(SPARSE_MERKLE_DEPTH);
    if !walk_proof(entries, 0, target, &mut siblings) {
        return None;
    }
    debug_assert_eq!(siblings.len(), SPARSE_MERKLE_DEPTH);
    Some(SparseProof {
        siblings,
        path: *target,
    })
}

/// Verifies a [`SparseProof`] for `leaf` against `root`.
///
/// `siblings` is ordered from the leaf upward: `siblings[0]` is the sibling at the tree's
/// deepest level and `siblings[255]` the sibling at the root. The fold therefore combines the
/// leaf with `siblings[0]` (chosen by `path.bit(255)`), then up through `siblings[255]`
/// (chosen by `path.bit(0)`).
pub fn sparse_merkle_verify(root: &Hash, leaf: &Hash, proof: &SparseProof) -> bool {
    if proof.siblings.len() != SPARSE_MERKLE_DEPTH {
        return false;
    }
    let mut acc = merkle_leaf_hash(leaf);
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let bit_index = SPARSE_MERKLE_DEPTH - 1 - i;
        acc = if proof.path.bit(bit_index) {
            merkle_node_hash(sibling, &acc)
        } else {
            merkle_node_hash(&acc, sibling)
        };
    }
    &acc == root
}

fn subtree_hash(entries: &[(PathKey, Hash)], bit: usize) -> Hash {
    // An empty subtree commits as Hash::zero() at every level, and never as node_hash(zero, zero).
    if entries.is_empty() {
        return Hash::zero();
    }
    if bit == SPARSE_MERKLE_DEPTH {
        return merkle_leaf_hash(&entries[0].1);
    }
    let (left, right) = split_paths(entries, bit);
    let lh = if left.is_empty() {
        Hash::zero()
    } else {
        subtree_hash(&left, bit + 1)
    };
    let rh = if right.is_empty() {
        Hash::zero()
    } else {
        subtree_hash(&right, bit + 1)
    };
    merkle_node_hash(&lh, &rh)
}

fn walk_proof(
    entries: &[(PathKey, Hash)],
    bit: usize,
    target: &PathKey,
    out: &mut Vec<Hash>,
) -> bool {
    if bit == SPARSE_MERKLE_DEPTH {
        return entries.iter().any(|(p, _)| p == target);
    }
    let (left, right) = split_paths(entries, bit);
    let (mine, other) = if target.bit(bit) {
        (&right, &left)
    } else {
        (&left, &right)
    };
    if mine.is_empty() {
        return false;
    }
    // Recurse first so that deeper (leaf-ward) siblings are pushed before shallower ones,
    // giving the bottom-up order `sparse_merkle_verify` expects.
    if !walk_proof(mine, bit + 1, target, out) {
        return false;
    }
    out.push(if other.is_empty() {
        Hash::zero()
    } else {
        subtree_hash(&other, bit + 1)
    });
    true
}

fn split_paths(
    entries: &[(PathKey, Hash)],
    bit: usize,
) -> (Vec<(PathKey, Hash)>, Vec<(PathKey, Hash)>) {
    let (mut left, mut right) = (Vec::new(), Vec::new());
    for e in entries {
        if e.0.bit(bit) {
            right.push(*e);
        } else {
            left.push(*e);
        }
    }
    (left, right)
}

// ---------------------------------------------------------------------------
// Code manifest (file integrity / admission)
// ---------------------------------------------------------------------------

/// A manifest of the software files that make up a node or master binary.
///
/// Every file is hashed with SHA3-512 and committed into a Merkle tree keyed by path, so the
/// single `root()` value proves the entire on-disk program is unmodified.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeManifest {
    /// Sorted map of file path -> SHA3-512 of the file contents.
    pub entries: BTreeMap<String, Hash>,
}

impl CodeManifest {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a file path and its content hash.
    pub fn insert(&mut self, path: impl Into<String>, content_hash: Hash) {
        self.entries.insert(path.into(), content_hash);
    }

    /// Adds a file from its raw bytes.
    pub fn insert_bytes(&mut self, path: impl Into<String>, bytes: &[u8]) {
        self.entries.insert(path.into(), hash(bytes));
    }

    /// Builds a manifest from `(path, bytes)` pairs.
    pub fn from_files<I, S>(files: I) -> Self
    where
        I: IntoIterator<Item = (S, Vec<u8>)>,
        S: Into<String>,
    {
        let mut entries = BTreeMap::new();
        for (path, bytes) in files {
            entries.insert(path.into(), hash(&bytes));
        }
        Self { entries }
    }

    /// The Merkle root over `hash(path || file_hash)` leaves, sorted by path.
    pub fn root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .entries
            .iter()
            .map(|(path, file_hash)| hash_many(&[path.as_bytes(), &file_hash.0]))
            .collect();
        merkle_root(&leaves)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_512_known_vector() {
        // SHA3-512("") from FIPS 202.
        let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
        assert_eq!(hash(b"").to_hex(), expected);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"oxydome";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public(), msg, &sig));
        assert!(!verify(&kp.public(), b"other", &sig));
    }

    #[test]
    fn deterministic_keypair() {
        let seed = [7u8; 32];
        let a = KeyPair::from_seed(&seed);
        let b = KeyPair::from_seed(&seed);
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn merkle_root_and_proofs() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| hash(&i.to_le_bytes())).collect();
        let root = merkle_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i);
            assert!(merkle_verify(&root, leaf, &proof), "leaf {i} failed");
        }
        // A forged leaf must not verify.
        let forged = hash(b"forged");
        assert!(!merkle_verify(&root, &forged, &merkle_proof(&leaves, 0)));
    }

    #[test]
    fn merkle_empty_and_single() {
        assert_eq!(merkle_root(&[]), Hash::zero());
        let one = hash(b"x");
        assert_eq!(merkle_root(&[one]), merkle_leaf_hash(&one));
        assert!(merkle_verify(
            &merkle_root(&[one]),
            &one,
            &merkle_proof(&[one], 0)
        ));
    }

    #[test]
    fn sparse_merkle_root_and_proofs() {
        let keys: Vec<PathKey> = (0u64..24)
            .map(|i| {
                let h = hash(&i.to_le_bytes());
                PathKey::from_bytes(&h.0)
            })
            .collect();
        let leaves: Vec<Hash> = (0u64..24).map(hash_le).collect();
        let entries: Vec<(PathKey, Hash)> =
            keys.iter().cloned().zip(leaves.iter().cloned()).collect();

        let root = sparse_merkle_root(&entries);
        for (k, l) in keys.iter().zip(leaves.iter()) {
            let proof = sparse_merkle_proof(&entries, k).unwrap();
            assert_eq!(proof.siblings.len(), SPARSE_MERKLE_DEPTH);
            assert!(sparse_merkle_verify(&root, l, &proof), "path {k:?} failed");
        }

        // Order independence: the same set in reverse order produces the same root.
        let mut shuffled = entries.clone();
        shuffled.reverse();
        assert_eq!(sparse_merkle_root(&shuffled), root);

        // A forged leaf must not verify.
        let forged = hash(b"forged");
        let proof0 = sparse_merkle_proof(&entries, &keys[0]).unwrap();
        assert!(!sparse_merkle_verify(&root, &forged, &proof0));

        // An absent key has no proof.
        let missing = {
            let h = hash(b"absent");
            PathKey::from_bytes(&h.0)
        };
        assert!(sparse_merkle_proof(&entries, &missing).is_none());

        // Empty and singleton trees.
        assert_eq!(sparse_merkle_root(&[]), Hash::zero());
        let one = vec![(keys[0], leaves[0])];
        let r1 = sparse_merkle_root(&one);
        assert!(sparse_merkle_verify(
            &r1,
            &leaves[0],
            &sparse_merkle_proof(&one, &keys[0]).unwrap()
        ));
    }

    #[test]
    fn path_key_bit_layout() {
        // Bit 0 is the LSB of word 0; bit 255 the MSB of word 3.
        let pk = PathKey([1, 0, 0, 0]);
        assert!(pk.bit(0));
        assert!(!pk.bit(1));
        assert!(!pk.bit(63));
        assert!(!pk.bit(64));
        assert!(!pk.bit(255));
        let hi = PathKey([0, 0, 0, 1u64 << 63]);
        assert!(!hi.bit(254));
        assert!(hi.bit(255));

        // from_bytes fills little-endian words from the first 32 bytes.
        let bytes = [0xffu8; 32];
        let from = PathKey::from_bytes(&bytes);
        assert!(from.bit(0) && from.bit(1) && from.bit(63));
        assert!(from.bit(64));
        assert!(from.bit(255));
        let short = PathKey::from_bytes(&[1u8]);
        assert!(short.bit(0));
        assert!(!short.bit(1));
    }

    fn hash_le(v: u64) -> Hash {
        hash(&v.to_le_bytes())
    }

    #[test]
    fn code_manifest_is_order_independent() {
        let mut a = CodeManifest::new();
        a.insert_bytes("b.rs", b"bee");
        a.insert_bytes("a.rs", b"aye");
        let mut b = CodeManifest::new();
        b.insert_bytes("a.rs", b"aye");
        b.insert_bytes("b.rs", b"bee");
        assert_eq!(a.root(), b.root());
        b.insert_bytes("a.rs", b"changed");
        assert_ne!(a.root(), b.root());
    }
}

#[test]
fn sparse_merkle_max_split_root_stays_consistent() {
    // Two keys forced apart at the root bit still verify.
    let mut h0 = hash(b"a");
    h0.0[0] &= !0xFFu8;
    let mut h1 = hash(b"b");
    h1.0[0] |= 0xFFu8;
    let a = PathKey::from_bytes(&h0.0);
    let b = PathKey::from_bytes(&h1.0);
    let la = hash(b"leaf-a");
    let lb = hash(b"leaf-b");
    let entries = vec![(a, la), (b, lb)];
    let root = sparse_merkle_root(&entries);
    let pa = sparse_merkle_proof(&entries, &a).unwrap();
    assert!(sparse_merkle_verify(&root, &la, &pa), "verify a failed");
    let pb = sparse_merkle_proof(&entries, &b).unwrap();
    assert!(sparse_merkle_verify(&root, &lb, &pb), "verify b failed");
}
