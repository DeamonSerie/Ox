//! Master-set governance: adding masters by server-node majority vote and co-signing the
//! resulting epoch transition with the existing master set.

use oxydome_core::{ChainParams, GovernanceSet, Hash, MasterApproval, NodeApproval, PublicKey};
use oxydome_crypto::{hash_value, KeyPair};
use serde::{Deserialize, Serialize};

/// A simple majority (strictly more than half).
pub fn majority(n: usize) -> usize {
    n / 2 + 1
}

#[derive(Serialize)]
struct ProposalData {
    candidate: PublicKey,
    proposer: PublicKey,
}

/// A proposal to admit `candidate` as a new master, approved by a majority of server nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterProposal {
    pub candidate: PublicKey,
    pub proposer: PublicKey,
    pub node_signatures: Vec<NodeApproval>,
}

impl MasterProposal {
    pub fn new(candidate: PublicKey, proposer: PublicKey) -> Self {
        Self {
            candidate,
            proposer,
            node_signatures: Vec::new(),
        }
    }

    pub fn proposal_id(&self) -> Hash {
        hash_value(&ProposalData {
            candidate: self.candidate,
            proposer: self.proposer,
        })
    }

    /// Adds a server node's vote (the node signs the proposal id).
    pub fn add_node_vote(&mut self, node_key: &KeyPair) {
        let id = self.proposal_id();
        self.node_signatures.push(NodeApproval {
            node: node_key.public(),
            proposal: id,
            signature: node_key.sign(&id.0),
        });
    }

    /// Counts distinct valid node votes from the current node set.
    pub fn valid_votes(&self, gov: &GovernanceSet) -> usize {
        let id = self.proposal_id();
        let mut seen = std::collections::BTreeSet::new();
        self.node_signatures
            .iter()
            .filter(|a| gov.contains_node(&a.node) && a.is_valid(&id) && seen.insert(a.node))
            .count()
    }

    /// True when a majority of the current server nodes have approved.
    pub fn is_approved(&self, gov: &GovernanceSet) -> bool {
        self.valid_votes(gov) >= majority(gov.nodes.len())
    }
}

#[derive(Serialize)]
struct TransitionData {
    epoch: u64,
    masters: Vec<PublicKey>,
}

/// A transition to a new epoch with a new master set, co-signed by the outgoing masters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransition {
    pub epoch: u64,
    pub masters: Vec<PublicKey>,
    pub signatures: Vec<MasterApproval>,
}

impl EpochTransition {
    pub fn new(epoch: u64, masters: Vec<PublicKey>) -> Self {
        Self {
            epoch,
            masters,
            signatures: Vec::new(),
        }
    }

    pub fn transition_id(&self) -> Hash {
        let mut masters = self.masters.clone();
        masters.sort();
        hash_value(&TransitionData {
            epoch: self.epoch,
            masters,
        })
    }

    /// Adds a current master's co-signature.
    pub fn add_master_signature(&mut self, master_key: &KeyPair) {
        let id = self.transition_id();
        self.signatures.push(MasterApproval {
            master: master_key.public(),
            proposal: id,
            signature: master_key.sign(&id.0),
        });
    }

    /// Valid when signed by the required super-majority of the outgoing master set.
    pub fn is_valid(&self, gov: &GovernanceSet, params: &ChainParams) -> bool {
        let id = self.transition_id();
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0;
        for sig in &self.signatures {
            if gov.contains_master(&sig.master) && sig.is_valid(&id) && seen.insert(sig.master) {
                count += 1;
            }
        }
        count >= gov.master_threshold(params) && !self.masters.is_empty()
    }
}
