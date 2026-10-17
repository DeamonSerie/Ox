//! Express Bus: a tracked deposit/withdraw system for cross-chain value flow.
//!
//! Deposits and withdrawals are recorded as tracked chain transactions (operations),
//! and a per-bus In/Out value tracker accumulates weighted net flow that ripples
//! into the affected asset's value-index computation.
//!
//! ## Overview
//!
//! An **Express Bus** is a tracked route between the Oxydome chain and an external system.
//! Each bus is identified by a `bus_id` (a `Hash`) and tracks a specific `PriceAsset`
//! (Ox, GAS, or a DAO currency).
//!
//! - **Deposit** — a master-approved operation that tags UTXOs as `BusReceipt` outputs,
//!   recording inbound value from an external system. Requires 2/3+1 master approval.
//! - **Withdraw** — a node-approved operation (plus owner signature) that spends
//!   `BusReceipt` UTXOs, recording outbound value. Requires 2/3+1 node approval.
//! - The **In/Out tracker** accumulates `in_volume` (deposits) and `out_volume`
//!   (withdrawals) per bus. A per-bus `weight` (FP-scaled) scales the net flow into a
//!   `signal` that ripples through the value-index computation.

use crate::operation::{MasterApproval, NodeApproval};
use crate::{Amount, OutPoint, PriceAsset};
use oxydome_crypto::{hash_value, verify, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};

/// Fixed-point scale matching `VALUE_SCALE`: 1.0 == `FP`.
pub const FP: i128 = 1_000_000_000_000;

/// Maximum number of simultaneous Express Bus trackers.
pub const MAX_EXPRESS_BUSES: usize = 1_000;

/// Multiplies two fixed-point numbers (both at `FP` scale).
fn fp_mul(a: i128, b: i128) -> i128 {
    a.saturating_mul(b) / FP
}

/// Canonical signing payload for an Express Bus deposit (excludes signatures and approvals).
#[derive(Serialize)]
struct ExpressBusDepositSigning {
    bus_id: Hash,
    asset: PriceAsset,
    depositor: PublicKey,
    inputs: Vec<OutPoint>,
    amount: Amount,
    nonce: u64,
}

/// Canonical signing payload for an Express Bus withdraw (excludes signatures and approvals).
#[derive(Serialize)]
struct ExpressBusWithdrawSigning {
    bus_id: Hash,
    asset: PriceAsset,
    owner: PublicKey,
    inputs: Vec<OutPoint>,
    amount: Amount,
    nonce: u64,
}

/// A master-approved deposit of value into an Express Bus route.
///
/// The deposit tags existing `Spendable` UTXOs (at `inputs`) as `BusReceipt` tagged
/// outputs, recording that value has entered the bus system. Requires 2/3+1 master
/// approval. The depositor must own all input UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressBusDeposit {
    /// Identifies the bus route (bridge connection).
    pub bus_id: Hash,
    /// The asset being deposited (Ox, GAS, or a DAO currency).
    pub asset: PriceAsset,
    /// The party depositing into the bus.
    pub depositor: PublicKey,
    /// Input UTXOs to be tagged (must be Spendable, owned by `depositor`).
    pub inputs: Vec<OutPoint>,
    /// Total amount being deposited (must equal sum of inputs).
    pub amount: Amount,
    /// Replay-prevention nonce for the depositor.
    pub nonce: u64,
    /// Master approvals over `proposal_id()`.
    pub approvals: Vec<MasterApproval>,
}

/// A node-approved, owner-signed withdrawal from an Express Bus route.
///
/// The withdrawal spends `BusReceipt` UTXOs (at `inputs`) and creates `Spendable`
/// outputs, recording that value has exited the bus system. Requires 2/3+1 node
/// approval and the owner's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressBusWithdraw {
    /// Identifies the bus route.
    pub bus_id: Hash,
    /// The asset being withdrawn.
    pub asset: PriceAsset,
    /// The party withdrawing from the bus.
    pub owner: PublicKey,
    /// BusReceipt UTXOs to be spent (must match `bus_id` and `asset`).
    pub inputs: Vec<OutPoint>,
    /// Total amount being withdrawn.
    pub amount: Amount,
    /// Replay-prevention nonce for the owner.
    pub nonce: u64,
    /// Owner's Ed25519 signature over `proposal_id()`.
    pub owner_signature: Sig,
    /// Server-node approvals over `proposal_id()`.
    pub approvals: Vec<NodeApproval>,
}

impl ExpressBusDeposit {
    /// Creates an unsigned deposit operation.
    pub fn new_unsigned(
        bus_id: Hash,
        asset: PriceAsset,
        depositor: PublicKey,
        inputs: Vec<OutPoint>,
        amount: Amount,
        nonce: u64,
    ) -> Self {
        Self {
            bus_id,
            asset,
            depositor,
            inputs,
            amount,
            nonce,
            approvals: Vec::new(),
        }
    }

    /// The hash that master approvals sign.
    pub fn proposal_id(&self) -> Hash {
        hash_value(&ExpressBusDepositSigning {
            bus_id: self.bus_id,
            asset: self.asset,
            depositor: self.depositor,
            inputs: self.inputs.clone(),
            amount: self.amount,
            nonce: self.nonce,
        })
    }

    /// The operation id.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}

impl ExpressBusWithdraw {
    /// Creates an unsigned withdraw operation.
    pub fn new_unsigned(
        bus_id: Hash,
        asset: PriceAsset,
        owner: PublicKey,
        inputs: Vec<OutPoint>,
        amount: Amount,
        nonce: u64,
    ) -> Self {
        Self {
            bus_id,
            asset,
            owner,
            inputs,
            amount,
            nonce,
            owner_signature: Sig([0u8; 64]),
            approvals: Vec::new(),
        }
    }

    /// The hash that approvals sign (and that the owner signs).
    pub fn proposal_id(&self) -> Hash {
        hash_value(&ExpressBusWithdrawSigning {
            bus_id: self.bus_id,
            asset: self.asset,
            owner: self.owner,
            inputs: self.inputs.clone(),
            amount: self.amount,
            nonce: self.nonce,
        })
    }

    /// Signs the withdraw with the owner's key.
    pub fn sign(&mut self, key: &oxydome_crypto::KeyPair) {
        self.owner = key.public();
        self.owner_signature = key.sign(&self.proposal_id().0);
    }

    /// Verifies the owner's signature.
    pub fn is_signature_valid(&self) -> bool {
        verify(&self.owner, &self.proposal_id().0, &self.owner_signature)
    }

    /// The operation id.
    pub fn id(&self) -> Hash {
        hash_value(self)
    }
}

/// A single weighted sample from an Express Bus tracker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusSample {
    /// Block height at which the sample was taken.
    pub height: u64,
    /// Weighted net flow signal (signed, FP-scaled). Positive = net inflow to bus
    /// (deposits exceed withdrawals); negative = net outflow.
    pub signal: i128,
}

/// Live state of an Express Bus tracker, held in `ChainState::express_buses`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressBusTracker {
    /// Identifies the bus route.
    pub bus_id: Hash,
    /// The asset this tracker monitors.
    pub asset: PriceAsset,
    /// Weight factor (FP scale: 1.0 == `FP`) applied to this bus's net flow.
    pub weight: i128,
    /// Block height at which the tracker was created/seeded.
    pub created_height: u64,
    /// Block height of the last sample recorded.
    pub last_sample_height: u64,
    /// Per-block weighted net flow accumulated since the last sample.
    pub pending_flow: i128,
    /// Cumulative deposits (In) in the current sampling window.
    pub in_volume: Amount,
    /// Cumulative withdrawals (Out) in the current sampling window.
    pub out_volume: Amount,
    /// Historical samples for the accumulated-track computation.
    pub samples: Vec<BusSample>,
    /// The settled signal from the last completed window.
    pub last_settled_signal: i128,
    /// Whether the current window is settled.
    pub settled: bool,
}

impl Default for ExpressBusTracker {
    fn default() -> Self {
        Self {
            bus_id: Hash::zero(),
            asset: PriceAsset::Ox,
            weight: FP,
            created_height: 0,
            last_sample_height: 0,
            pending_flow: 0,
            in_volume: 0,
            out_volume: 0,
            samples: Vec::new(),
            last_settled_signal: 0,
            settled: false,
        }
    }
}

impl ExpressBusTracker {
    /// Creates a new tracker seeded at `height`.
    pub fn new(bus_id: Hash, asset: PriceAsset, weight: i128, height: u64) -> Self {
        Self {
            bus_id,
            asset,
            weight,
            created_height: height,
            last_sample_height: height,
            pending_flow: 0,
            in_volume: 0,
            out_volume: 0,
            samples: Vec::new(),
            last_settled_signal: 0,
            settled: false,
        }
    }

    /// Computes the current net-flow signal: `(in_volume - out_volume) * weight`,
    /// returned as an FP-scaled signed value.
    pub fn signal(&self) -> i128 {
        let net = self.in_volume.saturating_sub(self.out_volume) as i128;
        fp_mul(net, self.weight)
    }

    /// Records a deposit: adds `amount` to `in_volume` and updates the pending flow.
    pub fn record_deposit(&mut self, amount: Amount) {
        self.in_volume = self.in_volume.saturating_add(amount);
        self.pending_flow =
            self.pending_flow.saturating_add(fp_mul(amount as i128, self.weight));
    }

    /// Records a withdrawal: adds `amount` to `out_volume` and updates the pending flow.
    pub fn record_withdraw(&mut self, amount: Amount) {
        self.out_volume = self.out_volume.saturating_add(amount);
        self.pending_flow = self
            .pending_flow
            .saturating_add(fp_mul(-(amount as i128), self.weight));
    }

    /// Samples the current pending flow, resets the pending accumulator, and
    /// returns the sample.
    pub fn sample(&mut self, height: u64) -> BusSample {
        self.last_sample_height = height;
        let signal = self.pending_flow;
        self.pending_flow = 0;
        let sample = BusSample { height, signal };
        self.samples.push(sample.clone());
        sample
    }

    /// Settles the current window: computes the average signal from samples,
    /// marks `settled`, and resets `in_volume` / `out_volume` for the next window.
    pub fn settle(&mut self) {
        self.last_settled_signal = self.accumulated_signal();
        self.in_volume = 0;
        self.out_volume = 0;
        self.pending_flow = 0;
        self.settled = true;
    }

    /// Computes the accumulated net-flow signal from all samples (arithmetic mean).
    pub fn accumulated_signal(&self) -> i128 {
        if self.samples.is_empty() {
            return 0;
        }
        let sum: i128 = self.samples.iter().map(|s| s.signal).sum();
        sum / self.samples.len() as i128
    }
}

/// Computes the per-block express-flow delta for a single tracker.
///
/// Returns the weighted net flow at FP scale. Positive = deposits dominate
/// (downward value pressure on the asset); negative = withdrawals dominate
/// (upward pressure).
pub fn bus_flow_delta(in_volume: Amount, out_volume: Amount, weight: i128) -> i128 {
    let net = in_volume.saturating_sub(out_volume) as i128;
    fp_mul(net, weight)
}

/// Determines whether a `PriceAsset` is the native Ox value index.
pub fn is_ox_asset(asset: &PriceAsset) -> bool {
    matches!(asset, PriceAsset::Ox)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_proposal_id_is_deterministic() {
        let dep = ExpressBusDeposit::new_unsigned(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            PublicKey::from([0u8; 32]),
            vec![OutPoint::new(Hash::from([2u8; 64]), 0)],
            1000,
            1,
        );
        let id1 = dep.proposal_id();
        let id2 = dep.proposal_id();
        assert_eq!(id1, id2);
        assert!(!id1.is_zero());
    }

    #[test]
    fn withdraw_signs_and_verifies() {
        let key = oxydome_crypto::KeyPair::from_seed(&[42u8; 32]);
        let mut wd = ExpressBusWithdraw::new_unsigned(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            key.public(),
            vec![OutPoint::new(Hash::from([2u8; 64]), 0)],
            1000,
            0,
        );
        wd.sign(&key);
        assert!(wd.is_signature_valid());
        assert!(!wd.owner_signature.0.iter().all(|b| *b == 0));
    }

    #[test]
    fn withdraw_tamper_fails_signature() {
        let key = oxydome_crypto::KeyPair::from_seed(&[42u8; 32]);
        let mut wd = ExpressBusWithdraw::new_unsigned(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            key.public(),
            vec![OutPoint::new(Hash::from([2u8; 64]), 0)],
            1000,
            0,
        );
        wd.sign(&key);
        wd.amount = 9999;
        assert!(!wd.is_signature_valid());
    }

    #[test]
    fn tracker_signal_is_zero_when_empty() {
        let tracker = ExpressBusTracker::new(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            FP,
            100,
        );
        assert_eq!(tracker.signal(), 0);
    }

    #[test]
    fn tracker_signal_reflects_deposit_minus_withdrawal() {
        let mut tracker = ExpressBusTracker::new(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            FP,
            100,
        );
        tracker.record_deposit(500);
        tracker.record_withdraw(200);
        // net = 500 - 200 = 300, weight = 1.0 (FP), signal = fp_mul(300, FP) = 300
        assert_eq!(tracker.signal(), 300);
    }

    #[test]
    fn tracker_sample_and_settle() {
        let mut tracker = ExpressBusTracker::new(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            FP,
            100,
        );
        tracker.record_deposit(100);
        let sample = tracker.sample(110);
        assert_eq!(sample.height, 110);
        // signal = 100 * 1.0 = 100
        assert_eq!(sample.signal, 100);

        tracker.settle();
        assert!(tracker.settled);
        assert_eq!(tracker.in_volume, 0);
        assert_eq!(tracker.out_volume, 0);
        // last_settled_signal = accumulated_signal = 100 (one sample)
        assert_eq!(tracker.last_settled_signal, 100);
    }

    #[test]
    fn tracker_weight_scales_signal() {
        let mut tracker = ExpressBusTracker::new(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            FP / 2, // weight = 0.5
            100,
        );
        tracker.record_deposit(200);
        // net = 200, weight = FP/2, signal = fp_mul(200, FP/2) = 100
        assert_eq!(tracker.signal(), 100);
    }

    #[test]
    fn is_ox_asset_detects_correctly() {
        assert!(is_ox_asset(&PriceAsset::Ox));
        assert!(!is_ox_asset(&PriceAsset::Gas));
    }

    #[test]
    fn bus_flow_delta_is_weighted_net() {
        let delta = bus_flow_delta(300, 100, FP);
        // net = 200, weight = 1.0, delta = 200
        assert_eq!(delta, 200);
    }

    #[test]
    fn tracker_accumulated_signal_averages_samples() {
        let mut tracker = ExpressBusTracker::new(
            Hash::from([1u8; 64]),
            PriceAsset::Ox,
            FP,
            100,
        );
        tracker.pending_flow = 10;
        tracker.sample(100);
        tracker.pending_flow = 20;
        tracker.sample(110);
        tracker.pending_flow = 30;
        tracker.sample(120);
        // average = (10 + 20 + 30) / 3 = 20
        assert_eq!(tracker.accumulated_signal(), 20);
    }
}
