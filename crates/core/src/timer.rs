//! Timer: a timed price-bet mechanism controlled by admin nodes (DAOs / DAO exchanges
//! / masters) when they agree, with user-facing bets that settle against the accumulated
//! tracked movement of a betting currency or token.
//!
//! ## Overview
//!
//! A **timer** is a prediction-style bet on the price direction of an asset (the *betting
//! currency or token*). Timers are created by DAOs and DAO exchanges (i.e. the admin / master
//! set) and require 2/3+1 master approval — regular chain users **cannot** create timers.
//! Regular users **can** place bets on existing timers.
//!
//! * The **accumulated tracked amount** samples the asset's price at regular intervals and
//!   averages the signed changes into a single reward figure.
//! * If the reward is **positive**, winning bettors receive it from the accumulated pool.
//! * If the reward is **negative**, the corresponding amount of the betting currency or token
//!   is **burned**.
//! * If the winning direction was **Up**, the betting currency is **burned** further so the
//!   price ticks up more.
//! * If the winning direction was **Down**, the betting currency is **minted** so the price
//!   ticks down more.
//! * Losing bettors simply get nothing back (their stake feeds the accumulated pool).

use crate::{Amount, OutPoint};
use oxydome_crypto::{hash_value, verify, Hash, KeyPair, PublicKey, Sig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum number of blocks in a timer (1 day).
///
/// With a target block time of ~5 s this is 17 280 blocks.
pub const MAX_TIMER_DURATION_BLOCKS: u64 = 17_280;

/// Maximum number of active timers allowed simultaneously.
pub const MAX_TIMERS: usize = 1_000;

/// Maximum number of bets per timer.
pub const MAX_TIMER_BETS: usize = 1_000_000;

/// Maximum length of a reason string for timer actions (bytes).
pub const MAX_TIMER_REASON_BYTES: usize = 256;

/// Maximum bet amount string length for display / diagnostics.
pub const MAX_TIMER_BET_DIGITS: usize = 40;

/// Direction of a price-movement bet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TimerDirection {
    /// Bet that the asset price will rise.
    Up,
    /// Bet that the asset price will fall.
    Down,
}

impl TimerDirection {
    /// Returns `true` if this direction agrees with `actual` (i.e. the bettor is right).
    pub fn is_winner(self, actual: TimerDirection) -> bool {
        self == actual
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TimerDirection::Up => "up",
            TimerDirection::Down => "down",
        }
    }
}

/// What a timer tracks and bets on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TimerAsset {
    /// The native Ox value index.
    Ox,
    /// A DAO's currency token identified by its DAO id.
    DaoCurrency { dao_id: Hash },
}

impl TimerAsset {
    /// A short display name for the asset.
    pub fn label(self) -> String {
        match self {
            TimerAsset::Ox => "Ox".to_string(),
            TimerAsset::DaoCurrency { dao_id } => format!("DAO:{}", &dao_id.to_string()[..8]),
        }
    }
}

/// One price sample recorded for the accumulated-tracked-amount calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimerSample {
    /// Block height at which the sample was taken.
    pub height: u64,
    /// The asset price (value index raw value for Ox, or the DAO currency value index).
    pub price: Amount,
}

/// Live state of a timer, held in [`crate::chain::ChainState`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timer {
    /// Unique timer identifier (hash of creation operation).
    pub id: Hash,
    /// The asset being bet on.
    pub asset: TimerAsset,
    /// Default direction the timer is set on (beters may choose either direction).
    pub direction: TimerDirection,
    /// Price at the moment the timer was created (the anchor).
    pub price_anchor: Amount,
    /// Block height at which the timer was created.
    pub created_height: u64,
    /// Block height at which the timer expires and resolves.
    pub expiry_height: u64,
    /// Price samples accumulated during the timer's life.
    pub samples: Vec<TimerSample>,
    /// Accumulated tracked amount (signed). A positive value means the asset trended in
    /// the timer's `direction`; negative means the opposite. This value is the reward pool.
    pub accumulated_track: i128,
    /// Who created the timer (the DAO / master proposer).
    pub created_by: PublicKey,
    /// Whether the timer has been resolved.
    pub resolved: bool,
    /// The winning direction once resolved (None if unresolved).
    pub winning_direction: Option<TimerDirection>,
    /// Per-better bets keyed by bet id.
    pub bets: BTreeMap<Hash, TimerBet>,
}

/// A user's bet on a timer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerBet {
    /// Unique bet id (hash of the bet's canonical data).
    pub bet_id: Hash,
    /// Timer this bet belongs to.
    pub timer_id: Hash,
    /// Public key of the bettor.
    pub better: PublicKey,
    /// Amount of betting currency/token staked.
    pub amount: Amount,
    /// Direction the bettor is wagering on.
    pub direction: TimerDirection,
    /// The better's Ed25519 signature over the bet signing hash.
    pub signature: Sig,
    /// Block height at which the bet was placed.
    pub created_height: u64,
    /// Whether the bettor has already claimed their reward.
    pub claimed: bool,
}

impl TimerBet {
    /// Creates an unsigned bet.
    pub fn new_unsigned(
        timer_id: Hash,
        better: PublicKey,
        amount: Amount,
        direction: TimerDirection,
        created_height: u64,
    ) -> Self {
        let signing = BetSigningData {
            timer_id,
            better,
            amount,
            direction,
            created_height,
        };
        Self {
            bet_id: hash_value(&signing),
            timer_id,
            better,
            amount,
            direction,
            signature: Sig([0u8; 64]),
            created_height,
            claimed: false,
        }
    }

    /// The hash that the bettor must sign.
    pub fn signing_hash(&self) -> Hash {
        hash_value(&BetSigningData {
            timer_id: self.timer_id,
            better: self.better,
            amount: self.amount,
            direction: self.direction,
            created_height: self.created_height,
        })
    }

    /// Signs the bet with `key`.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.better = key.public();
        self.signature = key.sign(&self.signing_hash().0);
        self.bet_id = self.signing_hash();
    }

    /// Verifies the bettor's signature and shape.
    pub fn is_valid(&self) -> bool {
        verify(&self.better, &self.signing_hash().0, &self.signature)
            && self.amount > 0
            && self.bet_id == self.signing_hash()
    }
}

/// Canonical signing payload for a bet.
#[derive(Serialize)]
struct BetSigningData {
    timer_id: Hash,
    better: PublicKey,
    amount: Amount,
    direction: TimerDirection,
    created_height: u64,
}

/// Actions that can be performed through timer operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimerAction {
    /// Create a new timer. Requires 2/3+1 master approval.
    Create {
        asset: TimerAsset,
        direction: TimerDirection,
        duration_blocks: u64,
        price_anchor: Amount,
    },
    /// Place a bet on an existing timer. Signed by the bettor only.
    Bet { bet: TimerBet },
    /// Resolve a timer at or after its expiry height. Requires 2/3+1 master approval.
    /// The actual price at expiry is provided so the resolution is deterministic and
    /// auditable by all nodes.
    Resolve {
        timer_id: Hash,
        /// The asset price at the moment of resolution.
        expiry_price: Amount,
    },
    /// Claim rewards from a resolved timer for a specific bet. Signed by the bettor.
    Claim { bet_id: Hash },
}

impl TimerAction {
    /// Validates the shape of the action independently of signatures or approvals.
    pub fn is_valid_shape(&self) -> Result<(), String> {
        match self {
            TimerAction::Create {
                asset: _,
                direction: _,
                duration_blocks,
                price_anchor,
            } => {
                if *duration_blocks == 0 || *duration_blocks > MAX_TIMER_DURATION_BLOCKS {
                    return Err(format!(
                        "timer duration must be 1..={} blocks",
                        MAX_TIMER_DURATION_BLOCKS
                    ));
                }
                if *price_anchor == 0 {
                    return Err("price anchor must be positive".into());
                }
                Ok(())
            }
            TimerAction::Bet { bet } => {
                if !bet.is_valid() {
                    return Err("invalid bet signature".into());
                }
                if bet.amount == 0 {
                    return Err("bet amount must be positive".into());
                }
                Ok(())
            }
            TimerAction::Resolve {
                timer_id,
                expiry_price,
            } => {
                if timer_id.is_zero() {
                    return Err("timer id is zero".into());
                }
                if *expiry_price == 0 {
                    return Err("expiry price must be positive".into());
                }
                Ok(())
            }
            TimerAction::Claim { bet_id } => {
                if bet_id.is_zero() {
                    return Err("bet id is zero".into());
                }
                Ok(())
            }
        }
    }
}

/// Canonical signing payload for a `TimerAction` (excludes signatures and approvals).
#[derive(Serialize)]
struct TimerSigningData<'a> {
    actor: PublicKey,
    action: &'a TimerAction,
    nonce: u64,
}

/// A signed timer operation, matching the wrapper pattern of `DaoOperation` / `GasOperation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerOperation {
    /// Actor (signer) of this operation.
    pub actor: PublicKey,
    /// The timer action.
    pub action: TimerAction,
    /// Nonce to prevent replay; must equal the actor's next expected nonce.
    pub nonce: u64,
    /// Signature over `(actor, nonce, action)`.
    pub signature: Sig,
    /// Master approvals (used by `Create` and `Resolve`).
    pub approvals: Vec<crate::MasterApproval>,
}

impl TimerOperation {
    /// Creates an unsigned timer operation.
    pub fn new_unsigned(actor: PublicKey, nonce: u64, action: TimerAction) -> Self {
        Self {
            actor,
            action,
            nonce,
            signature: Sig([0u8; 64]),
            approvals: Vec::new(),
        }
    }

    /// The hash signed by the actor.
    pub fn signing_hash(&self) -> Hash {
        hash_value(&TimerSigningData {
            actor: self.actor,
            nonce: self.nonce,
            action: &self.action,
        })
    }

    /// Signs the operation with the actor's key.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.actor = key.public();
        self.signature = key.sign(&self.signing_hash().0);
    }

    /// Verifies the actor's signature.
    pub fn is_signature_valid(&self) -> bool {
        verify(&self.actor, &self.signing_hash().0, &self.signature)
    }

    /// Verifies the operation: shape + signature + bet validity (where applicable).
    pub fn is_valid(&self) -> bool {
        if !self.is_signature_valid() {
            return false;
        }
        self.action.is_valid_shape().is_ok()
    }

    /// The operation id.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }

    /// Creates a new `TimerOperation::Create`, signed and with master approvals attached.
    pub fn create_timer(
        master: &KeyPair,
        nonce: u64,
        asset: TimerAsset,
        direction: TimerDirection,
        duration_blocks: u64,
        price_anchor: Amount,
        master_approvals: &[&KeyPair],
    ) -> Self {
        let action = TimerAction::Create {
            asset,
            direction,
            duration_blocks,
            price_anchor,
        };
        let mut operation = Self::new_unsigned(master.public(), nonce, action);
        operation.sign(master);
        for approver in master_approvals {
            approve_timer(&mut operation, approver);
        }
        operation
    }
}

/// Appends a master's approval to a timer operation.
pub fn approve_timer(operation: &mut TimerOperation, master: &KeyPair) {
    let id = crate::Operation::Timer(operation.clone()).proposal_id();
    operation.approvals.push(crate::MasterApproval {
        master: master.public(),
        proposal: id,
        signature: master.sign(&id.0),
    });
}

impl TimerAction {
    /// The hash that master approvals sign for Create/Resolve actions.
    pub fn master_proposal_id(&self, actor: PublicKey, nonce: u64) -> Hash {
        hash_value(&TimerSigningData {
            actor,
            nonce,
            action: self,
        })
    }
}

/// Computes the accumulated tracked amount from price samples.
///
/// The tracked amount is the arithmetic mean of signed price changes between
/// consecutive samples, expressed in the same fixed-point units as the price.
/// A return value can be negative (price declined on average).
pub fn accumulated_track(samples: &[TimerSample], anchor: Amount) -> i128 {
    if samples.is_empty() {
        return 0;
    }
    let mut prev: i128 = anchor as i128;
    let mut sum: i128 = 0;
    let mut count: u64 = 0;
    for sample in samples {
        let current = sample.price as i128;
        sum = sum.saturating_add(current.saturating_sub(prev));
        prev = current;
        count = count.saturating_add(1);
    }
    if count == 0 {
        0
    } else {
        sum / count as i128
    }
}

/// Computes the per-better reward from the accumulated track.
///
/// Each winning better's stake is scaled proportionally by the accumulated track
/// relative to the average bet size, producing a reward that grows with the
/// average price movement. The sign of `accumulated` also determines whether
/// the betting currency is burned (positive Up win or negative Down win) or
/// minted (positive Down win or negative Up win).
pub fn reward_for_bet(
    bet_amount: Amount,
    total_bets: Amount,
    accumulated: i128,
    bet_direction: TimerDirection,
    winning: TimerDirection,
) -> i128 {
    if !bet_direction.is_winner(winning) {
        return 0;
    }
    if total_bets == 0 {
        return 0;
    }
    let ratio = (bet_amount as i128) * accumulated / (total_bets as i128);
    ratio
}

/// Determines whether the bettor's direction agrees with the actual price movement
/// between `anchor` and `expiry_price`.
pub fn actual_direction(anchor: Amount, expiry_price: Amount) -> TimerDirection {
    if expiry_price > anchor {
        TimerDirection::Up
    } else {
        TimerDirection::Down
    }
}

/// Timer configuration declared in a Solid contract. Encoded into a `TimerConfig` so that
/// the consensus layer can validate timer parameters declared by Solid-compiled contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerConfig {
    pub asset: TimerAsset,
    pub direction: TimerDirection,
    pub duration_blocks: u64,
    pub price_anchor: Amount,
}

impl TimerConfig {
    /// Validates the configuration independently of chain state.
    pub fn is_valid(&self, params: &crate::params::ChainParams) -> Result<(), String> {
        if self.duration_blocks == 0 || self.duration_blocks > params.max_timer_duration_blocks {
            return Err(format!(
                "timer duration must be 1..={} blocks",
                params.max_timer_duration_blocks
            ));
        }
        if self.price_anchor == 0 {
            return Err("price anchor must be positive".into());
        }
        Ok(())
    }

    /// Builds a `Timer` from this config for a given height and creator.
    pub fn build_timer(&self, height: u64, created_by: PublicKey) -> Timer {
        Timer {
            id: hash_value(&(
                "oxydome-timer-id-v1",
                self.asset,
                self.direction,
                self.duration_blocks,
                self.price_anchor,
                height,
                created_by,
            )),
            asset: self.asset,
            direction: self.direction,
            price_anchor: self.price_anchor,
            created_height: height,
            expiry_height: height + self.duration_blocks,
            samples: Vec::new(),
            accumulated_track: 0,
            created_by,
            resolved: false,
            winning_direction: None,
            bets: BTreeMap::new(),
        }
    }
}

/// The well-known outpoint for a timer's betting-currency burn/mint when resolved.
///
/// Burning reduces supply (price ticks up); minting increases supply (price ticks down).
pub fn timer_burn_outpoint(timer_id: &Hash) -> OutPoint {
    OutPoint::new(hash_value(&("oxydome-timer-burn-v1", timer_id)), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;

    #[test]
    fn direction_winner_logic() {
        assert!(TimerDirection::Up.is_winner(TimerDirection::Up));
        assert!(!TimerDirection::Up.is_winner(TimerDirection::Down));
        assert!(TimerDirection::Down.is_winner(TimerDirection::Down));
    }

    #[test]
    fn accumulated_track_averages_changes() {
        // anchor 100, samples [105, 110, 120] => changes +5, +5, +10 => avg +20/3 = 6
        let samples = vec![
            TimerSample {
                height: 1,
                price: 105,
            },
            TimerSample {
                height: 2,
                price: 110,
            },
            TimerSample {
                height: 3,
                price: 120,
            },
        ];
        let track = accumulated_track(&samples, 100);
        assert_eq!(track, 6);
    }

    #[test]
    fn accumulated_track_negative_on_decline() {
        // anchor 100, samples [95, 90, 80] => changes -5, -5, -10 => avg -20/3 = -6
        let samples = vec![
            TimerSample {
                height: 1,
                price: 95,
            },
            TimerSample {
                height: 2,
                price: 90,
            },
            TimerSample {
                height: 3,
                price: 80,
            },
        ];
        let track = accumulated_track(&samples, 100);
        assert_eq!(track, -6);
    }

    #[test]
    fn accumulated_track_empty_is_zero() {
        assert_eq!(accumulated_track(&[], 100), 0);
    }

    #[test]
    fn actual_direction_from_prices() {
        assert_eq!(actual_direction(100, 120), TimerDirection::Up);
        assert_eq!(actual_direction(100, 90), TimerDirection::Down);
        assert_eq!(actual_direction(100, 100), TimerDirection::Down);
    }

    #[test]
    fn reward_for_winning_better() {
        // accumulated = 6, total_bets = 100, bet = 50, direction matches
        let reward = reward_for_bet(50, 100, 6, TimerDirection::Up, TimerDirection::Up);
        assert_eq!(reward, 3); // 50 * 6 / 100 = 3
    }

    #[test]
    fn reward_zero_for_losing_better() {
        let reward = reward_for_bet(50, 100, 6, TimerDirection::Down, TimerDirection::Up);
        assert_eq!(reward, 0);
    }

    #[test]
    fn reward_negative_accumulated() {
        let reward = reward_for_bet(50, 100, -6, TimerDirection::Down, TimerDirection::Down);
        assert_eq!(reward, -3);
    }

    #[test]
    fn bet_signs_and_verifies() {
        let key = KeyPair::from_seed(&[42u8; 32]);
        let timer_id = Hash::from([1u8; 64]);
        let mut bet = TimerBet::new_unsigned(timer_id, key.public(), 100, TimerDirection::Up, 5);
        bet.sign(&key);
        assert!(bet.is_valid());
        assert_eq!(bet.bet_id, bet.signing_hash());
    }

    #[test]
    fn bet_tamper_fails() {
        let key = KeyPair::from_seed(&[42u8; 32]);
        let timer_id = Hash::from([1u8; 64]);
        let mut bet = TimerBet::new_unsigned(timer_id, key.public(), 100, TimerDirection::Up, 5);
        bet.sign(&key);
        bet.amount = 999;
        assert!(!bet.is_valid());
    }

    #[test]
    fn timer_operation_signs_and_verifies() {
        let key = KeyPair::from_seed(&[10u8; 32]);
        let mut op = TimerOperation::new_unsigned(
            key.public(),
            0,
            TimerAction::Create {
                asset: TimerAsset::Ox,
                direction: TimerDirection::Up,
                duration_blocks: 100,
                price_anchor: 1_000_000_000,
            },
        );
        op.sign(&key);
        assert!(op.is_signature_valid());
        assert!(op.is_valid());
        assert!(!op.id().is_zero());
    }

    #[test]
    fn timer_operation_tamper_fails() {
        let key = KeyPair::from_seed(&[10u8; 32]);
        let mut op = TimerOperation::new_unsigned(
            key.public(),
            0,
            TimerAction::Create {
                asset: TimerAsset::Ox,
                direction: TimerDirection::Up,
                duration_blocks: 100,
                price_anchor: 1_000_000_000,
            },
        );
        op.sign(&key);
        if let TimerAction::Create { price_anchor, .. } = &mut op.action {
            *price_anchor = 999;
        }
        assert!(!op.is_valid());
    }

    #[test]
    fn create_action_rejects_invalid_duration() {
        let key = KeyPair::from_seed(&[10u8; 32]);
        let op = TimerOperation::new_unsigned(
            key.public(),
            0,
            TimerAction::Create {
                asset: TimerAsset::Ox,
                direction: TimerDirection::Up,
                duration_blocks: 0,
                price_anchor: 100,
            },
        );
        assert!(op.action.is_valid_shape().is_err());
    }

    #[test]
    fn create_action_rejects_excessive_duration() {
        let key = KeyPair::from_seed(&[10u8; 32]);
        let op = TimerOperation::new_unsigned(
            key.public(),
            0,
            TimerAction::Create {
                asset: TimerAsset::Ox,
                direction: TimerDirection::Up,
                duration_blocks: MAX_TIMER_DURATION_BLOCKS + 1,
                price_anchor: 100,
            },
        );
        assert!(op.action.is_valid_shape().is_err());
    }

    #[test]
    fn timer_burn_outpoint_is_deterministic() {
        let id = Hash::from([1u8; 64]);
        let op1 = timer_burn_outpoint(&id);
        let op2 = timer_burn_outpoint(&id);
        assert_eq!(op1, op2);
        assert_eq!(op1.txid, hash_value(&("oxydome-timer-burn-v1", id)));
    }
}
