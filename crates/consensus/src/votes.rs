//! BFT votes, quorum certificates and `MasterCheck` attestations.

use oxydome_core::{quorum, ChainParams, GovernanceSet, PublicKey, Sig};
use oxydome_crypto::{encode, hash_many, merkle_root, verify, Hash, KeyPair};
use serde::{Deserialize, Serialize};

/// The phase a vote belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteKind {
    Prepare,
    Commit,
    CoinToss,
}

#[derive(Serialize)]
struct VoteData {
    height: u64,
    view: u64,
    block_hash: Hash,
    kind: VoteKind,
    voter: PublicKey,
}

/// A single validator vote for a block in a given height/view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub view: u64,
    pub block_hash: Hash,
    pub kind: VoteKind,
    pub voter: PublicKey,
    pub signature: Sig,
}

impl Vote {
    fn data(&self) -> VoteData {
        VoteData {
            height: self.height,
            view: self.view,
            block_hash: self.block_hash,
            kind: self.kind,
            voter: self.voter,
        }
    }

    pub fn sign(key: &KeyPair, height: u64, view: u64, block_hash: Hash, kind: VoteKind) -> Self {
        let mut vote = Self {
            height,
            view,
            block_hash,
            kind,
            voter: key.public(),
            signature: Sig([0u8; 64]),
        };
        vote.signature = key.sign(&encode(&vote.data()));
        vote
    }

    pub fn is_valid(&self) -> bool {
        verify(&self.voter, &encode(&self.data()), &self.signature)
    }
}

/// A collection of votes attesting to a block in a height/view/phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub height: u64,
    pub view: u64,
    pub block_hash: Hash,
    pub kind: VoteKind,
    pub votes: Vec<Vote>,
}

impl QuorumCertificate {
    pub fn new(height: u64, view: u64, block_hash: Hash, kind: VoteKind, votes: Vec<Vote>) -> Self {
        Self {
            height,
            view,
            block_hash,
            kind,
            votes,
        }
    }

    /// Counts distinct valid voters from the current node set.
    pub fn valid_voter_count(&self, gov: &GovernanceSet) -> usize {
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0;
        for vote in &self.votes {
            if vote.height != self.height
                || vote.view != self.view
                || vote.block_hash != self.block_hash
                || vote.kind != self.kind
            {
                continue;
            }
            if gov.contains_node(&vote.voter) && vote.is_valid() && seen.insert(vote.voter) {
                count += 1;
            }
        }
        count
    }

    /// Returns true if the certificate has a BFT super-majority of the node set.
    pub fn has_quorum(&self, gov: &GovernanceSet, params: &ChainParams) -> bool {
        let threshold = quorum(gov.nodes.len(), params.bft_num, params.bft_den);
        self.valid_voter_count(gov) >= threshold
    }
}

/// The Merkle root over the sorted master public keys. Nodes attest to this in a `MasterCheck`.
pub fn masters_root(masters: &[PublicKey]) -> Hash {
    let mut leaves: Vec<Hash> = masters
        .iter()
        .map(|m| hash_many(&[b"master", &m.0]))
        .collect();
    leaves.sort();
    merkle_root(&leaves)
}

#[derive(Serialize)]
struct MasterCheckData {
    epoch: u64,
    masters_root: Hash,
    voter: PublicKey,
}

/// A server node's attestation that it agrees with the current master set for an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterCheck {
    pub epoch: u64,
    pub masters_root: Hash,
    pub voter: PublicKey,
    pub signature: Sig,
}

impl MasterCheck {
    fn data(&self) -> MasterCheckData {
        MasterCheckData {
            epoch: self.epoch,
            masters_root: self.masters_root,
            voter: self.voter,
        }
    }

    pub fn sign(key: &KeyPair, epoch: u64, masters_root: Hash) -> Self {
        let mut check = Self {
            epoch,
            masters_root,
            voter: key.public(),
            signature: Sig([0u8; 64]),
        };
        check.signature = key.sign(&encode(&check.data()));
        check
    }

    pub fn is_valid(&self) -> bool {
        verify(&self.voter, &encode(&self.data()), &self.signature)
    }
}

/// Returns true if `checks` contain a BFT super-majority of distinct nodes attesting to the
/// master set of `epoch`.
pub fn master_check_quorum(
    checks: &[MasterCheck],
    epoch: u64,
    expected_root: Hash,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> bool {
    let threshold = quorum(gov.nodes.len(), params.bft_num, params.bft_den);
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    for check in checks {
        if check.epoch != epoch || check.masters_root != expected_root {
            continue;
        }
        if gov.contains_node(&check.voter) && check.is_valid() && seen.insert(check.voter) {
            count += 1;
        }
    }
    count >= threshold
}

// ---------------------------------------------------------------------------
// Coin-toss entropy shares
// ---------------------------------------------------------------------------

/// The data that a `CoinTossShare` commits to when signed.
#[derive(Serialize)]
struct CoinTossShareData {
    height: u64,
    view: u64,
    entropy: Hash,
    voter: PublicKey,
}

/// A validator's entropy contribution to the coin-toss seed.
///
/// Each participating node signs its own randomness share. The shares are
/// collected, sorted by voter and XOR-combined to form the deterministic
/// `coin_toss_seed` for the block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinTossShare {
    pub height: u64,
    pub view: u64,
    pub entropy: Hash,
    pub voter: PublicKey,
    pub signature: Sig,
}

impl CoinTossShare {
    fn data(&self) -> CoinTossShareData {
        CoinTossShareData {
            height: self.height,
            view: self.view,
            entropy: self.entropy,
            voter: self.voter,
        }
    }

    /// Signs `entropy` as the node's contribution to the coin-toss seed.
    pub fn sign(key: &KeyPair, height: u64, view: u64, entropy: Hash) -> Self {
        let mut share = Self {
            height,
            view,
            entropy,
            voter: key.public(),
            signature: Sig([0u8; 64]),
        };
        share.signature = key.sign(&encode(&share.data()));
        share
    }

    /// Verifies the signature on this entropy share.
    pub fn is_valid(&self) -> bool {
        verify(&self.voter, &encode(&self.data()), &self.signature)
    }
}

/// Collects entropy shares and aggregates them into a deterministic seed.
///
/// Returns `None` if fewer than `quorum` valid shares from distinct nodes
/// are provided. Otherwise the shares are sorted by voter and XOR-ed together.
pub fn aggregate_coin_toss_seed(
    shares: &[CoinTossShare],
    height: u64,
    view: u64,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Option<Hash> {
    let threshold = quorum(gov.nodes.len(), params.bft_num, params.bft_den);
    let mut seen = std::collections::BTreeSet::new();
    // Collect valid shares from distinct, recognized voters.
    let mut valid: Vec<Hash> = shares
        .iter()
        .filter(|s| {
            s.height == height
                && s.view == view
                && gov.contains_node(&s.voter)
                && s.is_valid()
                && seen.insert(s.voter)
        })
        .map(|s| s.entropy)
        .collect();
    if valid.len() < threshold {
        return None;
    }
    // Sort for order-independence, then XOR.
    valid.sort();
    let mut acc = [0u8; 64];
    for v in &valid {
        for (a, b) in acc.iter_mut().zip(v.as_bytes().iter()) {
            *a ^= b;
        }
    }
    Some(Hash::from_bytes(acc))
}
