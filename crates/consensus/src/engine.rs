//! The BFT consensus engine for a single height/view.
//!
//! Oxydome is Proof-of-Authority first: only the epoch leader (chosen round-robin from the
//! authorized server nodes) may propose. The block is then committed by BFT super-majority
//! `Prepare` and `Commit` votes, and only finalizes when a `MasterCheck` super-majority also
//! confirms the master set for the epoch.

use crate::votes::{master_check_quorum, MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_core::{quorum, ChainParams, GovernanceSet, Hash, PublicKey};
use oxydome_crypto::KeyPair;

/// The phase of the consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Step {
    Idle,
    Proposed,
    Prepared,
    Committed,
    Finalized,
}

/// Errors raised by the consensus engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsensusError {
    #[error("vote is not valid or is for the wrong round")]
    BadVote,
    #[error("voter is not an authorized node")]
    NotAuthorized,
    #[error("proposal hash does not match the prepare certificate")]
    ProposalMismatch,
    #[error("no leader for this view")]
    NoLeader,
}

/// The per-round BFT state machine.
#[derive(Debug, Clone)]
pub struct ConsensusEngine {
    pub height: u64,
    pub view: u64,
    pub step: Step,
    pub authorities: Vec<PublicKey>,
    pub proposal_hash: Option<Hash>,
    pub votes: Vec<Vote>,
    pub master_checks: Vec<MasterCheck>,
    pub prepare_qc: Option<QuorumCertificate>,
    pub commit_qc: Option<QuorumCertificate>,
}

impl ConsensusEngine {
    pub fn new(height: u64, view: u64, authorities: Vec<PublicKey>) -> Self {
        Self {
            height,
            view,
            step: Step::Idle,
            authorities,
            proposal_hash: None,
            votes: Vec::new(),
            master_checks: Vec::new(),
            prepare_qc: None,
            commit_qc: None,
        }
    }

    /// The round-robin leader for the current view.
    pub fn leader(&self) -> Option<PublicKey> {
        if self.authorities.is_empty() {
            None
        } else {
            Some(self.authorities[(self.view as usize) % self.authorities.len()])
        }
    }

    pub fn is_leader(&self, key: &PublicKey) -> bool {
        self.leader().as_ref() == Some(key)
    }

    /// Records the leader's proposal.
    pub fn propose(&mut self, block_hash: Hash) {
        self.proposal_hash = Some(block_hash);
        self.step = Step::Proposed;
    }

    fn count_votes(&self, kind: VoteKind, gov: &GovernanceSet) -> usize {
        let Some(proposal) = self.proposal_hash else {
            return 0;
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0;
        for vote in &self.votes {
            if vote.kind != kind
                || vote.height != self.height
                || vote.view != self.view
                || vote.block_hash != proposal
            {
                continue;
            }
            if gov.contains_node(&vote.voter) && vote.is_valid() && seen.insert(vote.voter) {
                count += 1;
            }
        }
        count
    }

    /// Adds a vote, returning a newly formed quorum certificate if one is reached.
    pub fn add_vote(
        &mut self,
        vote: Vote,
        gov: &GovernanceSet,
        params: &ChainParams,
    ) -> Result<Option<QuorumCertificate>, ConsensusError> {
        if vote.height != self.height || vote.view != self.view {
            return Err(ConsensusError::BadVote);
        }
        if !gov.contains_node(&vote.voter) {
            return Err(ConsensusError::NotAuthorized);
        }
        if !vote.is_valid() {
            return Err(ConsensusError::BadVote);
        }
        if let Some(proposal) = self.proposal_hash {
            if vote.block_hash != proposal {
                return Err(ConsensusError::ProposalMismatch);
            }
        }
        self.votes.push(vote);
        let threshold = quorum(gov.nodes.len(), params.bft_num, params.bft_den);

        if self.prepare_qc.is_none()
            && self.count_votes(VoteKind::Prepare, gov) >= threshold
            && self.proposal_hash.is_some()
        {
            let votes: Vec<Vote> = self
                .votes
                .iter()
                .filter(|v| v.kind == VoteKind::Prepare)
                .cloned()
                .collect();
            let qc = QuorumCertificate::new(
                self.height,
                self.view,
                self.proposal_hash.unwrap(),
                VoteKind::Prepare,
                votes,
            );
            self.prepare_qc = Some(qc.clone());
            self.step = Step::Prepared;
            return Ok(Some(qc));
        }

        if self.prepare_qc.is_some()
            && self.commit_qc.is_none()
            && self.count_votes(VoteKind::Commit, gov) >= threshold
        {
            let votes: Vec<Vote> = self
                .votes
                .iter()
                .filter(|v| v.kind == VoteKind::Commit)
                .cloned()
                .collect();
            let qc = QuorumCertificate::new(
                self.height,
                self.view,
                self.proposal_hash.unwrap(),
                VoteKind::Commit,
                votes,
            );
            self.commit_qc = Some(qc.clone());
            self.step = Step::Committed;
            return Ok(Some(qc));
        }

        Ok(None)
    }

    pub fn add_master_check(&mut self, check: MasterCheck) {
        self.master_checks.push(check);
    }

    /// True when the commit QC exists and a `MasterCheck` super-majority confirms `epoch`.
    pub fn can_finalize(
        &self,
        gov: &GovernanceSet,
        params: &ChainParams,
        epoch: u64,
        expected_masters_root: Hash,
    ) -> bool {
        let commit_ok = self
            .commit_qc
            .as_ref()
            .map(|qc| qc.has_quorum(gov, params))
            .unwrap_or(false);
        let checks_ok = master_check_quorum(
            &self.master_checks,
            epoch,
            expected_masters_root,
            gov,
            params,
        );
        commit_ok && checks_ok
    }

    /// Marks the round finalized and returns the finalized block hash.
    pub fn finalize(&mut self) -> Option<Hash> {
        if self.step == Step::Committed {
            self.step = Step::Finalized;
            self.proposal_hash
        } else {
            None
        }
    }

    /// Builds a signed vote for this round with `key`.
    pub fn make_vote(&self, key: &KeyPair, kind: VoteKind) -> Option<Vote> {
        self.proposal_hash
            .map(|h| Vote::sign(key, self.height, self.view, h, kind))
    }
}
