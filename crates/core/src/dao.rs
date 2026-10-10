//! Consensus-visible DAO policies, assets, proposals, and signed actions.

use crate::{Amount, OutPoint};
use oxydome_crypto::{hash_value, verify, Hash, KeyPair, PublicKey, Sig};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

pub const DAO_POLICY_VERSION: u8 = 1;
const DAO_POLICY_MAGIC: &[u8; 5] = b"ODAO\x01";
pub const MAX_DAO_MAKERS: usize = 128;
pub const MAX_DAO_CURRENCY_SYMBOL_BYTES: usize = 12;
pub const MAX_DAO_PROPOSAL_HEIGHTS: u64 = 100_000;
pub const MAX_DAO_PROPOSALS: usize = 100_000;
pub const MAX_DAO_HOLDERS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoCurrency {
    pub symbol: String,
    pub initial_supply: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoPeg {
    /// DAO whose currency is held as the redemption reserve.
    pub target_dao: Hash,
    /// Target-token units released per `denominator` pegged-token units burned.
    pub numerator: Amount,
    pub denominator: Amount,
}

/// Solid-compiled policy. The optional currency is the DAO's voting token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoPolicy {
    pub version: u8,
    /// Must be sorted and contain no duplicates to give the policy one encoding.
    pub makers: Vec<PublicKey>,
    pub currency: Option<DaoCurrency>,
    pub peg: Option<DaoPeg>,
}

impl DaoPolicy {
    pub fn verify(&self) -> Result<(), String> {
        if self.version != DAO_POLICY_VERSION
            || self.makers.is_empty()
            || self.makers.len() > MAX_DAO_MAKERS
            || self.makers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("DAO policy version or canonical maker set is invalid".into());
        }
        if let Some(currency) = &self.currency {
            if currency.symbol.is_empty()
                || currency.symbol.len() > MAX_DAO_CURRENCY_SYMBOL_BYTES
                || !currency
                    .symbol
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            {
                return Err(
                    "DAO currency symbol must be 1-12 uppercase ASCII letters/digits".into(),
                );
            }
            if currency.initial_supply == 0 {
                return Err("a DAO currency requires a positive initial holder supply".into());
            }
        } else if self.peg.is_some() {
            return Err("a DAO peg requires a DAO currency".into());
        }
        if let Some(peg) = &self.peg {
            if peg.target_dao.is_zero() || peg.numerator == 0 || peg.denominator == 0 {
                return Err("DAO peg requires a target and positive conversion ratio".into());
            }
            let mut a = peg.numerator;
            let mut b = peg.denominator;
            while b != 0 {
                (a, b) = (b, a % b);
            }
            if a != 1 {
                return Err("DAO peg ratio must be reduced to canonical terms".into());
            }
            if self
                .currency
                .as_ref()
                .is_some_and(|currency| currency.initial_supply % peg.denominator != 0)
            {
                return Err(
                    "initial pegged supply must be divisible by the peg denominator".into(),
                );
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.verify()?;
        let payload = bincode::serialize(self).map_err(|error| error.to_string())?;
        let mut bytes = Vec::with_capacity(DAO_POLICY_MAGIC.len() + payload.len());
        bytes.extend_from_slice(DAO_POLICY_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() <= DAO_POLICY_MAGIC.len() || !bytes.starts_with(DAO_POLICY_MAGIC) {
            return Err("invalid DAO policy encoding".into());
        }
        let policy: Self =
            bincode::deserialize(&bytes[DAO_POLICY_MAGIC.len()..]).map_err(|e| e.to_string())?;
        policy.verify()?;
        if policy.encode()? != bytes {
            return Err("DAO policy encoding is not canonical".into());
        }
        Ok(policy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaoProposalAction {
    TreasuryTransfer {
        recipient: PublicKey,
        amount: Amount,
    },
    OxTreasuryTransfer {
        recipient: PublicKey,
        amount: Amount,
    },
    Mint {
        recipient: PublicKey,
        amount: Amount,
    },
    Burn {
        holder: PublicKey,
        amount: Amount,
    },
    SetPeg {
        peg: Option<DaoPeg>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaoProposalStatus {
    HolderVoting,
    MakerVoting,
    Approved,
    Rejected,
    Executed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoProposal {
    pub id: Hash,
    pub action: DaoProposalAction,
    pub created_height: u64,
    pub expires_height: u64,
    pub holder_snapshot: BTreeMap<PublicKey, Amount>,
    pub maker_snapshot: Vec<PublicKey>,
    pub holder_votes: BTreeMap<PublicKey, bool>,
    pub maker_votes: BTreeMap<PublicKey, bool>,
    pub status: DaoProposalStatus,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoWindowStats {
    pub volume: Amount,
    pub tx_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoState {
    pub policy: DaoPolicy,
    pub currency_supply: Amount,
    pub genesis_currency_supply: Amount,
    pub ox_treasury: Amount,
    pub balances: BTreeMap<PublicKey, Amount>,
    /// DAO currency held in reserve for each pegged DAO, indexed by pegged DAO id.
    pub locked_reserves: BTreeMap<Hash, Amount>,
    /// Target DAO currency locked for permissionless peg redemption.
    pub peg_reserves: BTreeMap<Hash, Amount>,
    /// DAO-owned currency available for governed treasury actions.
    pub treasury: Amount,
    pub proposals: BTreeMap<Hash, DaoProposal>,
    pub value_index: u128,
    pub generation: u64,
    pub stats_history: VecDeque<DaoWindowStats>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaoAction {
    Create {
        policy: Vec<u8>,
    },
    Transfer {
        dao_id: Hash,
        recipient: PublicKey,
        amount: Amount,
    },
    TreasuryDeposit {
        dao_id: Hash,
        amount: Amount,
    },
    OxTreasuryDeposit {
        dao_id: Hash,
        source: OutPoint,
        amount: Amount,
    },
    ReserveDeposit {
        dao_id: Hash,
        target_dao: Hash,
        amount: Amount,
    },
    Propose {
        dao_id: Hash,
        action: DaoProposalAction,
        expires_height: u64,
    },
    HolderVote {
        dao_id: Hash,
        proposal_id: Hash,
        approve: bool,
    },
    MakerVote {
        dao_id: Hash,
        proposal_id: Hash,
        approve: bool,
    },
    Finalize {
        dao_id: Hash,
        proposal_id: Hash,
    },
    Execute {
        dao_id: Hash,
        proposal_id: Hash,
    },
    /// Permissionless redemption; DAO governance cannot veto valid reserve claims.
    Redeem {
        dao_id: Hash,
        amount: Amount,
        recipient: PublicKey,
    },
}

#[derive(Debug, Clone, Serialize)]
struct DaoSigningData<'a> {
    actor: PublicKey,
    action: &'a DaoAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoOperation {
    pub actor: PublicKey,
    pub action: DaoAction,
    pub signature: Sig,
}

impl DaoOperation {
    pub fn new_unsigned(actor: PublicKey, action: DaoAction) -> Self {
        Self {
            actor,
            action,
            signature: Sig([0; 64]),
        }
    }

    pub fn signing_hash(&self) -> Hash {
        hash_value(&DaoSigningData {
            actor: self.actor,
            action: &self.action,
        })
    }

    pub fn sign(&mut self, key: &KeyPair) {
        self.actor = key.public();
        self.signature = key.sign(&self.signing_hash().0);
    }

    pub fn is_valid(&self) -> bool {
        verify(&self.actor, &self.signing_hash().0, &self.signature) && self.action.is_valid_shape()
    }

    pub fn id(&self) -> Hash {
        hash_value(self)
    }

    pub fn created_dao_id(&self) -> Result<Option<Hash>, String> {
        let DaoAction::Create { policy } = &self.action else {
            return Ok(None);
        };
        DaoPolicy::decode(policy)?;
        Ok(Some(hash_value(&("oxydome-dao-id-v1", self.id(), policy))))
    }
}

impl DaoAction {
    pub fn is_valid_shape(&self) -> bool {
        match self {
            Self::Create { policy } => DaoPolicy::decode(policy).is_ok(),
            Self::Transfer { amount, .. }
            | Self::TreasuryDeposit { amount, .. }
            | Self::OxTreasuryDeposit { amount, .. }
            | Self::ReserveDeposit { amount, .. }
            | Self::Redeem { amount, .. } => *amount > 0,
            Self::Propose {
                action,
                expires_height,
                ..
            } => {
                *expires_height > 0
                    && match action {
                        DaoProposalAction::TreasuryTransfer { amount, .. }
                        | DaoProposalAction::OxTreasuryTransfer { amount, .. }
                        | DaoProposalAction::Mint { amount, .. }
                        | DaoProposalAction::Burn { amount, .. } => *amount > 0,
                        DaoProposalAction::SetPeg { peg } => peg.as_ref().map_or(true, |value| {
                            !value.target_dao.is_zero()
                                && value.numerator > 0
                                && value.denominator > 0
                        }),
                    }
            }
            Self::HolderVote { .. }
            | Self::MakerVote { .. }
            | Self::Finalize { .. }
            | Self::Execute { .. } => true,
        }
    }
}
