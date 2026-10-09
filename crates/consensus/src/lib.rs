//! Consensus primitives for Oxydome: PoA leader selection, BFT votes/quotas,
//! `MasterCheck` attestations and master-set governance.

pub mod admission;
pub mod engine;
pub mod governance;
pub mod votes;

pub use admission::AdmissionCertificate;
pub use engine::{ConsensusEngine, ConsensusError, Step};
pub use governance::{majority, EpochTransition, MasterProposal};
pub use votes::{masters_root, MasterCheck, QuorumCertificate, Vote, VoteKind};
