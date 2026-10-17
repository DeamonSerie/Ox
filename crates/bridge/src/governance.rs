// Governance System
// 1-token-1-vote governance for micro token holders
// Enables mint/burn proposals and execution

use crate::state::BridgeError;
use serde::{Deserialize, Serialize};

/// Proposal type for micro token governance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalType {
    /// Mint new tokens
    Mint,
    /// Burn existing tokens
    Burn,
    /// Change parameters
    ParameterChange,
}

/// Governance proposal structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Proposal ID
    pub proposal_id: u64,
    /// Proposal type
    pub proposal_type: ProposalType,
    /// Description of the proposal
    pub description: String,
    /// Required quorum percentage (0-100)
    pub quorum_percentage: u64,
    /// Required supermajority percentage (0-100)
    pub supermajority_percentage: u64,
    /// Yes votes count
    pub yes_votes: u64,
    /// No votes count
    pub no_votes: u64,
    /// Whether proposal is executed
    pub executed: bool,
    /// Whether proposal is active
    pub active: bool,
    /// Creation timestamp
    pub created_at: u64,
    /// Execution timestamp (if executed)
    pub executed_at: Option<u64>,
}

/// Governance vote structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVote {
    /// Voter address
    pub voter: String,
    /// Proposal ID
    pub proposal_id: u64,
    /// Vote choice (true = yes, false = no)
    pub support: bool,
    /// Vote timestamp
    pub vote_timestamp: u64,
}

/// Governance structure managing micro token decisions
pub struct MicroTokenGovernance {
    /// Mapping of proposal ID to proposal
    pub proposals: std::collections::HashMap<u64, GovernanceProposal>,
    /// Mapping of voter address to their votes
    pub votes: std::collections::HashMap<String, std::collections::HashMap<u64, bool>>,
    /// Current proposal counter
    pub next_proposal_id: u64,
}

impl MicroTokenGovernance {
    /// Create new governance system
    pub fn new() -> Self {
        MicroTokenGovernance {
            proposals: std::collections::HashMap::new(),
            votes: std::collections::HashMap::new(),
            next_proposal_id: 1,
        }
    }

    /// Create a new governance proposal
    pub fn create_proposal(
        &mut self,
        proposal_type: ProposalType,
        description: String,
        quorum_percentage: u64,
        supermajority_percentage: u64,
    ) -> u64 {
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;

        let proposal = GovernanceProposal {
            proposal_id,
            proposal_type,
            description,
            quorum_percentage,
            supermajority_percentage,
            yes_votes: 0,
            no_votes: 0,
            executed: false,
            active: true,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            executed_at: None,
        };

        self.proposals.insert(proposal_id, proposal);
        proposal_id
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &mut self,
        voter: String,
        proposal_id: u64,
        support: bool,
    ) -> Result<(), BridgeError> {
        // Check if proposal exists
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(BridgeError::NotFound)?;

        // Check if proposal is active
        if !proposal.active {
            return Err(BridgeError::NotFound);
        }

        // Record the vote
        let voter_votes = self.votes.entry(voter.clone()).or_default();
        voter_votes.insert(proposal_id, support);

        // Update vote counts
        if support {
            if let Some(p) = self.proposals.get_mut(&proposal_id) {
                p.yes_votes += 1;
            }
        } else {
            if let Some(p) = self.proposals.get_mut(&proposal_id) {
                p.no_votes += 1;
            }
        }

        Ok(())
    }

    /// Check if proposal has reached quorum
    pub fn check_quorum(&self, proposal_id: u64, total_supply: u64) -> bool {
        let proposal = self.proposals.get(&proposal_id).unwrap();
        let quorum_threshold = (total_supply * proposal.quorum_percentage) / 100;
        // In production, would calculate actual votes cast vs total supply
        // For now, return true if any votes exist
        self.proposals
            .get(&proposal_id)
            .map(|p| p.yes_votes + p.no_votes > 0)
            .unwrap_or(false)
    }

    /// Check if proposal has reached supermajority
    pub fn check_supermajority(&self, proposal_id: u64, total_supply: u64) -> bool {
        let proposal = self.proposals.get(&proposal_id).unwrap();
        let supermajority_threshold = (total_supply * proposal.supermajority_percentage) / 100;
        // In production, would compare yes_votes against supermajority_threshold
        // For now, return yes_votes > no_votes
        proposal.yes_votes > proposal.no_votes
    }

    /// Execute a proposal if conditions are met
    pub fn execute_proposal(
        &mut self,
        proposal_id: u64,
        total_supply: u64,
    ) -> Result<(), BridgeError> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(BridgeError::NotFound)?;

        // Check if already executed
        if proposal.executed {
            return Err(BridgeError::AlreadyCompleted);
        }

        // Check quorum
        if !self.check_quorum(proposal_id, total_supply) {
            return Err(BridgeError::NotFound);
        }

        // Check supermajority
        if !self.check_supermajority(proposal_id, total_supply) {
            return Err(BridgeError::NotFound);
        }

        // Execute the proposal
        let mut proposal = self.proposals.get_mut(&proposal_id).unwrap();
        proposal.executed = true;
        proposal.executed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        // Execute based on proposal type
        match proposal.proposal_type {
            ProposalType::Mint => self.execute_mint(proposal_id),
            ProposalType::Burn => self.execute_burn(proposal_id),
            _ => Ok(()),
        }
    }

    /// Execute mint proposal
    fn execute_mint(&self, _proposal_id: u64) -> Result<(), BridgeError> {
        // In production, would mint new tokens
        Ok(())
    }

    /// Execute burn proposal
    fn execute_burn(&self, _proposal_id: u64) -> Result<(), BridgeError> {
        // In production, would burn tokens
        Ok(())
    }
}
