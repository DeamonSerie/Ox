//! BFT votes, quorum certificates and `MasterCheck` attestations.

use oxydome_core::{quorum, ChainParams, GovernanceSet, PublicKey, Sig};
use oxydome_crypto::{encode, hash_many, merkle_root, verify, Hash, KeyPair};
use serde::{Deserialize, Serialize};

/// The phase a vote belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteKind {
    Prepare,
    Commit,
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
