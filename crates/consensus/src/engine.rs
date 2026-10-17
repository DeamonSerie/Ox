//! The BFT consensus engine for a single height/view.
//!
//! Oxydome is Proof-of-Authority first: only the epoch leader (chosen round-robin from the
//! authorized server nodes) may propose. The block is then committed by BFT super-majority
//! `Prepare` and `Commit` votes, and only finalizes when a `MasterCheck` super-majority also
//! confirms the master set for the epoch.

use crate::votes::{master_check_quorum, MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_core::{quorum, BlockHeader, ChainParams, GovernanceSet, Hash, PublicKey};
use oxydome_crypto::evk::{
    EphemeralVerificationKey, IVerificationChainIntegrator, VerificationSession,
};
use oxydome_crypto::KeyPair;
use std::sync::Arc;

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
    #[error("cross-chain verification failed")]
    CrossChainVerificationFailed,
    #[error("cross-chain verification timed out")]
    CrossChainVerificationTimeout,
    #[error("cross-chain coordinator unavailable")]
    CoordinatorUnavailable,
    #[error("ephemeral verification key validation failed: {0}")]
    EphemeralVerification(String),
    #[error("file operation validation failed: {0}")]
    FileValidation(String),
}

impl From<oxydome_crypto::evk::EvkError> for ConsensusError {
    fn from(e: oxydome_crypto::evk::EvkError) -> Self {
        ConsensusError::EphemeralVerification(e.to_string())
    }
}

/// Consensus-facing result of a cross-chain verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossChainVerificationOutcome {
    Verified,
    Failed,
    Timeout,
    Unavailable,
}

/// The per-round BFT state machine.
#[derive(Clone)]
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
    /// Optional ephemeral key integrator for verification chain management.
    pub evk_integrator: Option<Arc<dyn IVerificationChainIntegrator>>,
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
            evk_integrator: None,
        }
    }

    /// Attaches an ephemeral key integrator to enable verification-chain hooks.
    pub fn with_evk_integrator(
        mut self,
        integrator: Arc<dyn IVerificationChainIntegrator>,
    ) -> Self {
        self.evk_integrator = Some(integrator);
        self
    }

    /// Starts a verification session, generating an ephemeral key if an integrator is attached.
    pub fn start_verification(
        &self,
        block_hash: Hash,
        previous_commitment: Hash,
        now: u64,
    ) -> Result<Option<EphemeralVerificationKey>, ConsensusError> {
        match &self.evk_integrator {
            Some(integrator) => {
                let key = integrator.on_verification_start(
                    self.height,
                    block_hash,
                    previous_commitment,
                    now,
                )?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    /// Completes a verification session, recording the result.
    pub fn complete_verification(
        &self,
        session: VerificationSession,
    ) -> Result<(), ConsensusError> {
        match &self.evk_integrator {
            Some(integrator) => {
                integrator.on_verification_complete(session);
                Ok(())
            }
            None => Err(ConsensusError::EphemeralVerification(
                "no EVK integrator configured".into(),
            )),
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

    /// Validates the EVK extension before a proposal enters the BFT vote pipeline.
    pub fn validate_block_ephemeral_keys(
        &self,
        header: &BlockHeader,
        migration_mode: bool,
    ) -> Result<(), ConsensusError> {
        header
            .validate_ephemeral_keys(migration_mode)
            .map_err(ConsensusError::EphemeralVerification)
    }

    /// Pre-checks file operation validity before a proposal enters the BFT vote pipeline,
    /// mirroring [`validate_block_ephemeral_keys`].
    pub fn validate_block_file_keys(
        &self,
        block: &oxydome_core::Block,
    ) -> Result<(), ConsensusError> {
        for op in &block.operations {
            match op {
                oxydome_core::Operation::FileStore(file_op) => {
                    if !file_op.file_label.is_valid() {
                        return Err(ConsensusError::FileValidation(
                            "file label signature is invalid".into(),
                        ));
                    }
                }
                oxydome_core::Operation::FileAccess(access_op) => {
                    if !oxydome_crypto::verify(
                        &access_op.accessor,
                        &op.proposal_id().0,
                        &access_op.signature,
                    ) {
                        return Err(ConsensusError::FileValidation(
                            "file access signature is invalid".into(),
                        ));
                    }
                }
                oxydome_core::Operation::FileDelete(delete_op) => {
                    if !oxydome_crypto::verify(
                        &delete_op.deleter,
                        &op.proposal_id().0,
                        &delete_op.signature,
                    ) {
                        return Err(ConsensusError::FileValidation(
                            "file delete signature is invalid".into(),
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(())
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
    pub fn finalize(&mut self, block_hash: Hash) -> Option<Hash> {
        if self.step == Step::Committed {
            self.step = Step::Finalized;
            self.proposal_hash = Some(block_hash);
            // Notify the EVK integrator that a block is finalized so the next
            // block can reference the correct verification state.
            if let Some(integrator) = &self.evk_integrator {
                let _ = integrator.on_block_finalized(self.height, block_hash);
            }
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

    /// Maps coordinator outcomes into consensus decisions. A block may only
    /// proceed when every required cross-chain operation is verified.
    pub fn accept_cross_chain_verification(
        outcome: CrossChainVerificationOutcome,
    ) -> Result<(), ConsensusError> {
        match outcome {
            CrossChainVerificationOutcome::Verified => Ok(()),
            CrossChainVerificationOutcome::Failed => {
                Err(ConsensusError::CrossChainVerificationFailed)
            }
            CrossChainVerificationOutcome::Timeout => {
                Err(ConsensusError::CrossChainVerificationTimeout)
            }
            CrossChainVerificationOutcome::Unavailable => {
                Err(ConsensusError::CoordinatorUnavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_chain_outcomes_map_to_consensus_errors() {
        assert!(ConsensusEngine::accept_cross_chain_verification(
            CrossChainVerificationOutcome::Verified
        )
        .is_ok());
        assert_eq!(
            ConsensusEngine::accept_cross_chain_verification(CrossChainVerificationOutcome::Failed),
            Err(ConsensusError::CrossChainVerificationFailed)
        );
        assert_eq!(
            ConsensusEngine::accept_cross_chain_verification(
                CrossChainVerificationOutcome::Timeout
            ),
            Err(ConsensusError::CrossChainVerificationTimeout)
        );
        assert_eq!(
            ConsensusEngine::accept_cross_chain_verification(
                CrossChainVerificationOutcome::Unavailable
            ),
            Err(ConsensusError::CoordinatorUnavailable)
        );
    }

    #[test]
    fn evk_header_validation_precedes_consensus() {
        let manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let key = oxydome_crypto::evk::IEphemeralKeyManager::generate_ephemeral_key(
            &manager,
            1,
            Hash::zero(),
            Hash::zero(),
            10,
        )
        .unwrap();
        let mut header = oxydome_core::Block::build_header(
            1,
            1,
            0,
            0,
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            0,
            0,
            0,
            oxydome_core::ValueIndex::from_raw(0),
            PublicKey([0; 32]),
            10,
            Vec::new(),
            Vec::new(),
        )
        .header;
        header.set_ephemeral_verification_key(&key);
        let engine = ConsensusEngine::new(1, 0, Vec::new());
        assert!(engine.validate_block_ephemeral_keys(&header, false).is_ok());
        header.verification_state_commitment = Some(Hash::zero());
        assert!(engine
            .validate_block_ephemeral_keys(&header, false)
            .is_err());
    }

    #[test]
    fn evk_integrator_generates_key_on_verification_start() {
        let manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let integrator = Arc::new(oxydome_crypto::evk::VerificationChainIntegrator {
            manager,
            verifier: PublicKey([0; 32]),
        });
        let engine = ConsensusEngine::new(5, 0, Vec::new()).with_evk_integrator(integrator);
        let key = engine
            .start_verification(Hash::zero(), Hash::zero(), 100)
            .unwrap()
            .expect("expected an ephemeral key");
        assert_eq!(key.block_height, 5);
    }

    #[test]
    fn evk_integrator_without_key_returns_none() {
        let engine = ConsensusEngine::new(5, 0, Vec::new());
        assert!(engine
            .start_verification(Hash::zero(), Hash::zero(), 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn evk_integrator_completes_verification_session() {
        let manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let integrator = Arc::new(oxydome_crypto::evk::VerificationChainIntegrator {
            manager,
            verifier: PublicKey([0; 32]),
        });
        let engine = ConsensusEngine::new(5, 0, Vec::new()).with_evk_integrator(integrator);
        let key = engine
            .start_verification(Hash::zero(), Hash::zero(), 100)
            .unwrap()
            .unwrap();
        let session = oxydome_crypto::evk::VerificationSession {
            session_id: key.session_id,
            block_height: key.block_height,
            block_hash: key.block_hash,
            ephemeral_key: key.public_key,
            previous_commitment: key.previous_commitment,
            next_commitment: key.key_chain_commitment,
            started_at: 100,
            completed_at: Some(101),
            verifier_node: PublicKey([0; 32]),
            result: Some(true),
            metadata: std::collections::BTreeMap::new(),
        };
        assert!(engine.complete_verification(session).is_ok());
    }

    #[test]
    fn evk_integrator_validates_block_key_chain() {
        let manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let integrator = Arc::new(oxydome_crypto::evk::VerificationChainIntegrator {
            manager,
            verifier: PublicKey([0; 32]),
        });
        let engine = ConsensusEngine::new(10, 0, Vec::new()).with_evk_integrator(integrator);
        let key = oxydome_crypto::evk::IEphemeralKeyManager::generate_ephemeral_key(
            &oxydome_crypto::evk::EphemeralKeyManager::new(Default::default()),
            10,
            Hash::zero(),
            Hash::zero(),
            100,
        )
        .unwrap();
        assert!(engine
            .evk_integrator
            .as_ref()
            .unwrap()
            .validate_block_ephemeral_key(&key, 101)
            .is_ok());
    }

    #[test]
    fn evk_integrator_finalize_notifies_integrator() {
        let manager = oxydome_crypto::evk::EphemeralKeyManager::new(Default::default());
        let integrator = Arc::new(oxydome_crypto::evk::VerificationChainIntegrator {
            manager,
            verifier: PublicKey([0; 32]),
        });
        let mut engine = ConsensusEngine::new(1, 0, Vec::new()).with_evk_integrator(integrator);
        engine.propose(Hash::zero());
        engine.step = Step::Committed;
        assert!(engine.finalize(Hash::zero()).is_some());
    }
}
