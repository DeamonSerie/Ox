//! The chain state machine: authenticated UTXO state, supply accounting, window statistics and
//! block application/validation.

use crate::utxo::{UtxoEntry, UtxoLedger};
use oxydome_core::{
    accumulated_track, actual_direction, bus_flow_delta,
    conversion_split_with_bps, is_ox_asset, ordered_transactions, pool_swap, reward_for_bet,
    timer_burn_outpoint, Amount, AuctionBidOperation, Block, BlockRewardDistribution,
    ChainParams, DaoOperation, DaoState, DaoWindowStats, ExpressBusDeposit, ExpressBusTracker,
    ExpressBusWithdraw, FileAccessOperation, FileAccessRecord, FileDeleteOperation,
    FileEvkLabel, FileStoreOperation, GasAccount, GasAction, GasOperation, GovernanceSet,
    LiquidityPoolAction, LiquidityPoolConfig, LiquidityPoolOperation, LiquidityPoolState,
    OhmAction, OhmOperation, OhmPolicy, OhmState, OhmUtxoEntry, Operation, OutPoint, OvmAction,
    OvmFailureCode, OvmLog, OvmReceipt, PeggedCurrencyState, PoolKParams, PriceAsset, PublicKey,
    RewardDistribution, SpeedometerAccount, SpeedometerAction, SpeedometerOperation, Timer,
    TimerAction, TimerDirection, TimerOperation, TimerSample, TokenAmount, Transaction, TxOutput,
    ValueIndex,
    LIQUIDITY_POOL_SCALE, MAX_OVM_BLOCK_GAS_LIMIT,
};
use oxydome_core::{
    build_ohm_server_outputs, compute_ohm_fee_split, ohm_genesis_hash, ohm_state_root,
    ohm_treasury_outpoint, DepartureEarningsDistribution, DepartureType, NodeKind,
};
use oxydome_crypto::{evk::EphemeralKeyManager, hash_value, verify, Hash};
use oxydome_currency::{
    compute_pool_k, compute_value, fp_mul, max_withdraw_per_account, rebound_utxo_spendable,
    supply_change_cap, supply_impact_ok, withdraw_cap, FP, WindowStats,
};
use oxydome_gas::{airdrop_amount, distribute_airdrop};
use oxydome_speedometer::{
    airdrop_amount as speedometer_airdrop_amount,
    distribute_airdrop as speedometer_distribute_airdrop, stabilization_mint,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OvmContract {
    pub code: Vec<u8>,
    pub storage: BTreeMap<u64, u64>,
}

/// Errors produced while building or applying chain state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("genesis allocation sum {0} does not equal genesis supply {1}")]
    GenesisSupplyMismatch(Amount, Amount),
    #[error("genesis requires at least one master")]
    NoMasters,
    #[error("block height {0} does not follow {1}")]
    BadHeight(u64, u64),
    #[error("block does not link to the current head")]
    BadPrevHash,
    #[error("block roots do not match body")]
    BadRoots,
    #[error("producer {0:?} is not an authorized node")]
    UnauthorizedProducer(PublicKey),
    #[error("insufficient verification credits")]
    InsufficientCredits,
    #[error("auction target {0:?} is not registered")]
    AuctionTargetUnknown(Hash),
    #[error("auction target {0:?} is closed")]
    AuctionTargetClosed(Hash),
    #[error("auction bid {0} is outside the permitted range")]
    AuctionBidOutOfRange(u64),
    #[error("auction target is invalid: {0}")]
    AuctionTargetInvalid(String),
    #[error("auction payout for transaction {0:?} does not match the auction outcome")]
    AuctionPayoutUnknown(Hash),
    #[error("auction payout for transaction {0:?} does not match the auction outcome")]
    AuctionPayoutMismatch(Hash),
    #[error("auction payout for transaction {0:?} is missing")]
    AuctionPayoutMissing(Hash),
    #[error("transaction {0} invalid: {1}")]
    BadTransaction(usize, String),
    #[error("input {0:?} does not exist")]
    MissingInput(OutPoint),
    #[error("input {0:?} is not spendable (only ordinary outputs may be spent)")]
    UnspendableInput(OutPoint),
    #[error("input {0:?} owner mismatch")]
    InputOwnerMismatch(OutPoint),
    #[error("input {0:?} is a rebound credit that is not yet mature")]
    ImmatureRebound(OutPoint),
    #[error("transaction does not conserve value")]
    Conservation,
    #[error("reward distribution is missing or duplicated")]
    BadRewardCount,
    #[error("block contains duplicate operations")]
    DuplicateOperation,
    #[error("mint outpoint was already recorded")]
    AlreadyMinted,
    #[error("reward total {0} does not equal block fees {1}")]
    RewardTotalMismatch(Amount, Amount),
    #[error("reward split is incorrect")]
    RewardSplit,
    #[error("reward recipient {0:?} is not a member of the right set")]
    BadRewardRecipient(PublicKey),
    #[error("mint/burn lacks master approval ({0} of {1})")]
    MasterApprovalMissing(usize, usize),
    #[error("withdrawal lacks node approval ({0} of {1})")]
    NodeApprovalMissing(usize, usize),
    #[error("mint exceeds the per-epoch supply cap")]
    MintCapExceeded,
    #[error("burn exceeds the per-epoch supply cap")]
    BurnCapExceeded,
    #[error("mint exceeds the value-impact guardrail")]
    MintValueImpact,
    #[error("burn exceeds the value-impact guardrail")]
    BurnValueImpact,
    #[error("withdrawal exceeds the per-epoch cap")]
    WithdrawCapExceeded,
    #[error("withdrawal exceeds per-account withdrawal limit")]
    PerAccountLimitExceeded,
    #[error("burn source {0:?} invalid")]
    BadBurnSource(OutPoint),
    #[error("burn signature invalid")]
    BadBurnSignature,
    #[error("withdrawal signature invalid")]
    BadWithdrawSignature,
    #[error("withdrawal input {0:?} invalid")]
    BadWithdrawInput(OutPoint),
    #[error("supply {0} does not match header {1}")]
    SupplyMismatch(Amount, Amount),
    #[error("value index {0} does not match header {1}")]
    ValueMismatch(String, String),
    #[error("generation {0} does not match header {1}")]
    GenerationMismatch(u64, u64),
    #[error("computed state root does not match header")]
    StateRootMismatch,
    #[error("unsolicited epoch change from {0} to {1}")]
    EpochChange(u64, u64),
    #[error("header window statistics do not match the block body")]
    StatsMismatch,
    #[error("OVM execution failed in transaction {0}: {1}")]
    OvmExecution(usize, String),
    #[error("OVM contract {0} does not exist")]
    OvmContractNotFound(Hash),
    #[error("OVM contract identifier collision")]
    OvmContractCollision,
    #[error("OVM state has reached the maximum number of contracts")]
    OvmContractLimit,
    #[error("OVM execution receipts do not match block commitment")]
    OvmReceiptMismatch,
    #[error("block exceeds the aggregate OVM gas limit")]
    OvmBlockGasLimit,
    #[error("block execution version or OVM activation height does not match chain parameters")]
    ExecutionVersionMismatch,
    #[error("DAO operation invalid: {0}")]
    Dao(String),
    #[error("OHM operation invalid: {0}")]
    Ohm(String),
    #[error("GAS operation invalid: {0}")]
    Gas(String),
    #[error("GAS is not active at this height")]
    GasInactive,
    #[error("GAS transfer nonce {0} does not match expected {1}")]
    GasNonce(u64, u64),
    #[error("account {0:?} has insufficient GAS")]
    GasUnderfunded(PublicKey),
    #[error("OVM transaction caller {0:?} does not hold enough GAS for the gas limit")]
    OvmGasUnderfunded(PublicKey),
    #[error("OVM stack size exceeds maximum")]
    OvmStackLimit,
    #[error("storage label is out of bounds")]
    OutOfBoundsStorageLabel,
    #[error("timer operation invalid: {0}")]
    Timer(String),
    #[error("timer operation requires master approval ({0} of {1})")]
    TimerApprovalMissing(usize, usize),
    #[error("timer does not exist")]
    TimerNotFound,
    #[error("timer has already been resolved")]
    TimerAlreadyResolved,
    #[error("timer has not yet expired")]
    TimerNotExpired,
    #[error("file system is not active at this height")]
    FileSystemInactive,
    #[error("node signature invalid")]
    BadNodeLeaveSignature,
    #[error("node leave input {0:?} invalid")]
    BadNodeLeaveInput(OutPoint),
    #[error("node leave earnings distribution mismatch")]
    NodeLeaveEarningsMismatch,
    #[error("departure earnings distribution is missing or duplicated")]
    DepartureEarningsMissing,
    #[error("file label signature is invalid")]
    BadFileLabelSignature,
    #[error("file key chain commitment does not match computation")]
    BadFileChainCommitment,
    #[error("file label previous_commitment does not match chain tip")]
    BadFileChainLink,
    #[error("file size {0} exceeds maximum {1}")]
    FileTooLarge(u64, u64),
    #[error("file is already stored")]
    DuplicateFile,
    #[error("node is not authorized to store files")]
    UnauthorizedFileNode,
    #[error("node file count exceeds maximum {0}")]
    NodeFileCountExceeded(u64),
    #[error("file access signature invalid")]
    BadFileAccessSignature,
    #[error("file not found: {0}")]
    FileNotFound(Hash),
    #[error("file content hash mismatch")]
    FileHashMismatch,
    #[error("only the storing node may delete a file")]
    NotFileOwner,
    #[error("file delete signature invalid")]
    BadFileDeleteSignature,
    #[error("liquidity pool not found: {0}")]
    PoolNotFound(Hash),
    #[error("liquidity pool already exists: {0}")]
    PoolAlreadyExists(Hash),
    #[error("liquidity pool limit exceeded ({0})")]
    PoolLimitExceeded(usize),
    #[error("liquidity pool signature invalid")]
    BadPoolSignature,
    #[error("liquidity pool swap output {0} below minimum {1}")]
    PoolSwapBelowMin(Amount, Amount),
    #[error("liquidity pool insufficient reserves")]
    PoolInsufficientReserves,
    #[error("Speedometer operation invalid: {0}")]
    Speedometer(String),
    #[error("Speedometer is not active at this height")]
    SpeedometerInactive,
    #[error("Speedometer transfer nonce {0} does not match expected {1}")]
    SpeedometerNonce(u64, u64),
    #[error("account {0:?} has insufficient Speedometer")]
    SpeedometerUnderfunded(PublicKey),
    #[error("block header gas stats do not match computed: header gas_price={0} fees={1} computed gas_price={2} fees={3}")]
    GasStatsMismatch(Amount, Amount, Amount, Amount),
    #[error("express bus is not active at this height")]
    ExpressBusInactive,
    #[error("express bus tracker not found: {0}")]
    ExpressBusNotFound(Hash),
    #[error("express bus tracker limit exceeded ({0})")]
    ExpressBusMaxTrackersExceeded(usize),
    #[error("express bus deposit invalid")]
    BadExpressBusDeposit,
    #[error("express bus withdraw invalid")]
    BadExpressBusWithdraw,
    #[error("withdrawer is not the bus owner")]
    ExpressBusNotOwner,
    #[error("coin toss seed or ordered_tx_root mismatch")]
    CoinTossMismatch,
    #[error("transaction {0} position hash does not match expected value")]
    BadPositionHash(usize),
}

/// The complete accounting state of the chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub utxo: UtxoLedger,
    pub contracts: BTreeMap<Hash, OvmContract>,
    pub daos: BTreeMap<Hash, DaoState>,
    pub ohm_states: BTreeMap<Hash, OhmState>,
    pub ovm_receipts: Vec<OvmReceipt>,
    pub supply: Amount,
    pub height: u64,
    pub block_hash: Hash,
    pub value_index: ValueIndex,
    pub generation: u64,
    pub epoch: u64,
    pub genesis_supply: Amount,
    /// Per-block window statistics, most recent last.
    stats_history: VecDeque<WindowStats>,
    /// Cumulative governance activity within the current epoch.
    pub epoch_minted: Amount,
    pub epoch_burned: Amount,
    pub epoch_withdrawn: Amount,
    /// GAS account balances (account-based currency, not committed into `state_root`).
    pub gas: BTreeMap<PublicKey, GasAccount>,
    /// Total circulating GAS supply.
    pub gas_supply: Amount,
    /// On-chain Ox price oracle used to size GAS airdrops.
    pub ox_price: Amount,
    /// Height of the most recent GAS airdrop.
    pub last_airdrop_height: u64,
    /// Height at which GAS price updates become active.
    pub price_update_height: u64,
    /// Last height at which the GAS price was updated.
    pub price_last_update_height: u64,
    /// Human-readable chain name.
    pub chain_name: String,
    /// Currency symbol token.
    pub currency_symbol: String,
    /// Storage labels submitted by nodes.
    pub storage_labels: BTreeMap<PublicKey, oxydome_core::StorageLabel>,
    /// Storage audit results.
    pub storage_audits: BTreeMap<u64, oxydome_core::StorageAuditResult>,
    /// Active and resolved timers, keyed by timer id.
    pub timers: BTreeMap<Hash, Timer>,
    /// Pegged currency states, keyed by config id. Updated each block with price samples
    /// and recomputed bounds. Only active when `pegged_currency_activation_height` is reached.
    pub pegged_currencies: BTreeMap<Hash, PeggedCurrencyState>,
    /// Liquidity pool states, keyed by config id. K is recomputed each block after pegged
    /// currency price tracking. Only active when `liquidity_pool_activation_height` is reached.
    pub liquidity_pools: BTreeMap<Hash, LiquidityPoolState>,
    /// On-chain file labels, keyed by `key_chain_commitment`.
    pub file_labels: BTreeMap<Hash, FileEvkLabel>,
    /// On-chain file access log, keyed by a unique access record id (hash of the record).
    pub file_access_log: BTreeMap<Hash, FileAccessRecord>,
    /// Most recent file label's `key_chain_commitment`, or `Hash::zero` when no files exist.
    pub file_chain_tip: Hash,
    /// Per-node file counts for the `max_files_per_node` cap.
    pub file_node_counts: BTreeMap<PublicKey, u64>,
    /// Speedometer account balances (account-based currency, not committed into `state_root`).
    pub speedometer: BTreeMap<PublicKey, SpeedometerAccount>,
    /// Total circulating Speedometer supply.
    pub speedometer_supply: Amount,
    /// Height of the most recent Speedometer airdrop.
    pub last_speedometer_airdrop_height: u64,
    /// Per-block tracking: total Speedometer minted from per-tx stabilization.
    /// Reset each block; stored so `build_block` can commit it to the header.
    pub speedometer_minted: Amount,
    /// Per-block tracking: airdrop amount distributed this block.
    pub speedometer_airdrop_amount: Amount,
    /// Per-block tracking: total GAS fees collected from OVM execution this block.
    /// Reset each block; stored so `build_block` can commit it to the header.
    pub block_gas_fees: Amount,
    /// Per-block tracking: the gas price used for this block (derived from pegged bounds).
    /// Reset each block; stored so `build_block` can commit it to the header.
    pub block_gas_price: Amount,
    /// Records of node departures (graceful or liveness-triggered). On-chain history of
    /// disconnections and the earnings redistribution that resulted from each.
    pub departures: Vec<DepartureEarningsDistribution>,
    /// Active Express Bus trackers, keyed by bus_id.
    pub express_buses: BTreeMap<Hash, ExpressBusTracker>,
    /// The verification-credit auction: credit balances, registered swap bundles,
    /// pending bids and the outstanding auction wins.
    pub auction: AuctionState,
}

/// The verification-credit auction state.
///
/// Verification credits are a **non-financial** unit: they are not a token, they are never
/// part of the Ox supply and they cannot be transferred between nodes. Server nodes earn
/// them by taking part in block verification and spend them to bid for the right to
/// execute a swap bundle. Unspent credits expire so that the auction stays open to new
/// entrants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionState {
    /// Verification credits earned by server nodes, keyed by node public key.
    pub credits: BTreeMap<PublicKey, u64>,
    /// The last block height at which each node earned or spent credits.
    pub credit_last_activity: BTreeMap<PublicKey, u64>,
    /// Bids awaiting the next clearing.
    pub pending_bids: Vec<AuctionBidOperation>,
    /// Registered auction targets (swap bundles), keyed by bundle id.
    pub targets: BTreeMap<Hash, AuctionTargetState>,
    /// Outstanding auction wins: bundle id -> winner and execution window.
    pub winners: BTreeMap<Hash, AuctionWin>,
}

/// A registered auction target: a bundle of swap transactions offered for auction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionTargetState {
    /// The swap transaction ids in the bundle.
    pub swaps: Vec<Hash>,
    /// The public summary of the swap.
    pub intent: oxydome_core::SwapIntent,
    /// The submitter that registered the bundle.
    pub registrar: PublicKey,
    /// The height at which the bundle was registered.
    pub registered_height: u64,
    /// Whether the bundle has already been executed by its winner.
    pub executed: bool,
}

/// The outcome of an auction clearing for one bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionWin {
    /// The server node that won the auction.
    pub winner: PublicKey,
    /// The swap transaction ids the winner may execute.
    pub swaps: Vec<Hash>,
    /// The last height at which the winner may still execute the bundle.
    pub deadline: u64,
    /// The height at which the auction cleared.
    pub cleared_height: u64,
}

impl AuctionState {
    /// The verification-credit balance of a node.
    pub fn credit_balance(&self, node: &PublicKey) -> u64 {
        self.credits.get(node).copied().unwrap_or(0)
    }

    /// Credits a server node for taking part in block verification.
    pub fn earn(&mut self, node: &PublicKey, amount: u64, height: u64) {
        if amount == 0 {
            return;
        }
        let balance = self.credits.entry(*node).or_insert(0);
        *balance = balance.saturating_add(amount);
        self.credit_last_activity.insert(*node, height);
    }

    /// Returns escrowed credits to a bidder.
    pub fn refund(&mut self, bidder: &PublicKey, amount: u64, height: u64) {
        if amount == 0 {
            return;
        }
        let balance = self.credits.entry(*bidder).or_insert(0);
        *balance = balance.saturating_add(amount);
        self.credit_last_activity.insert(*bidder, height);
    }

    /// Expires credits that have not been earned or spent recently.
    pub fn expire_credits(&mut self, height: u64, params: &ChainParams) {
        let cutoff = height.saturating_sub(params.auction_credit_expiry_blocks);
        let expired: Vec<PublicKey> = self
            .credit_last_activity
            .iter()
            .filter(|(_, h)| **h <= cutoff)
            .map(|(k, _)| *k)
            .collect();
        for node in expired {
            self.credits.remove(&node);
            self.credit_last_activity.remove(&node);
        }
    }

    /// Drops auction wins whose execution window has closed.
    pub fn expire_wins(&mut self, height: u64) {
        self.winners.retain(|_, win| win.deadline >= height);
    }

    /// Registers a swap bundle for auction.
    pub fn register_target(
        &mut self,
        target_op: &oxydome_core::AuctionTargetOperation,
        op: &Operation,
        height: u64,
    ) -> Result<(), StateError> {
        // The registrar signs the proposal id.
        if !oxydome_crypto::verify(
            &target_op.registrar,
            &op.proposal_id().0,
            &target_op.signature,
        ) {
            return Err(StateError::AuctionTargetInvalid(
                "registration signature is invalid".into(),
            ));
        }
        // The bundle must be non-empty and free of duplicates.
        if target_op.swaps.is_empty() {
            return Err(StateError::AuctionTargetInvalid(
                "bundle must contain at least one swap".into(),
            ));
        }
        let mut unique = target_op.swaps.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != target_op.swaps.len() {
            return Err(StateError::AuctionTargetInvalid(
                "bundle contains duplicate swaps".into(),
            ));
        }
        // The bundle id must match the swaps it claims to contain.
        if oxydome_core::auction_bundle_id(&target_op.swaps) != target_op.target {
            return Err(StateError::AuctionTargetInvalid(
                "bundle id does not match the swap list".into(),
            ));
        }
        // The summary must describe a real swap.
        if target_op.intent.input_amount == 0 || target_op.intent.min_output == 0 {
            return Err(StateError::AuctionTargetInvalid(
                "swap intent must declare a non-zero amount and minimum output".into(),
            ));
        }
        // A bundle may only be registered once.
        if self.targets.contains_key(&target_op.target) {
            return Err(StateError::AuctionTargetClosed(target_op.target));
        }
        // A swap may only belong to one bundle.
        for swap in &target_op.swaps {
            for (other_id, other) in &self.targets {
                if other.swaps.contains(swap) {
                    return Err(StateError::AuctionTargetInvalid(format!(
                        "swap {swap:?} is already registered in bundle {other_id:?}"
                    )));
                }
            }
        }
        self.targets.insert(
            target_op.target,
            AuctionTargetState {
                swaps: target_op.swaps.clone(),
                intent: target_op.intent.clone(),
                registrar: target_op.registrar,
                registered_height: height,
                executed: false,
            },
        );
        Ok(())
    }

    /// Escrows a bid and remembers it for the next clearing.
    pub fn escrow_bid(
        &mut self,
        bid: &AuctionBidOperation,
        op: &Operation,
        height: u64,
        params: &ChainParams,
    ) -> Result<(), StateError> {
        // Verify the node's signature over the proposal id.
        if !oxydome_crypto::verify(&bid.bidder, &op.proposal_id().0, &bid.signature) {
            return Err(StateError::BadWithdrawSignature);
        }
        // The bid must name a registered, still-open auction target.
        let target = self
            .targets
            .get(&bid.target)
            .ok_or(StateError::AuctionTargetUnknown(bid.target))?;
        if target.executed {
            return Err(StateError::AuctionTargetClosed(bid.target));
        }
        // The bid must be within the configured bounds.
        if bid.amount < params.auction_min_bid || bid.amount > params.auction_max_bid {
            return Err(StateError::AuctionBidOutOfRange(bid.amount));
        }
        // The bidder must have enough credits to cover the bid.
        let balance = self.credits.get(&bid.bidder).copied().unwrap_or(0);
        if bid.amount > balance {
            return Err(StateError::InsufficientCredits);
        }
        // Escrow the bid.
        if let Some(balance) = self.credits.get_mut(&bid.bidder) {
            *balance = balance.saturating_sub(bid.amount);
        }
        self.credit_last_activity.insert(bid.bidder, height);
        self.pending_bids.push(bid.clone());
        Ok(())
    }

    /// Settles the pending bids.
    ///
    /// The highest bid on a bundle wins the right to execute it in the very next block and
    /// to collect 100% of its fees. Every other bid is refunded; the winner's credits stay
    /// burned, they are the price of the right.
    pub fn clear(&mut self, height: u64, params: &ChainParams) {
        let interval = params.auction_interval_blocks.max(1);
        if height % interval != 0 {
            return;
        }
        let mut by_target: BTreeMap<Hash, Vec<AuctionBidOperation>> = BTreeMap::new();
        for bid in self.pending_bids.drain(..) {
            by_target.entry(bid.target).or_default().push(bid);
        }
        for (target, mut bids) in by_target {
            // Bids on bundles that are unknown or already executed are refunded in full.
            let open = self
                .targets
                .get(&target)
                .map(|target| !target.executed)
                .unwrap_or(false);
            if !open {
                for bid in &bids {
                    self.refund(&bid.bidder, bid.amount, height);
                }
                continue;
            }
            // The highest bid wins; ties are broken by the lowest bidder key so every node
            // derives the same outcome.
            bids.sort_by(|a, b| {
                b.amount
                    .cmp(&a.amount)
                    .then_with(|| a.bidder.cmp(&b.bidder))
            });
            let Some(winner_bid) = bids.first().cloned() else {
                continue;
            };
            for loser in bids.iter().skip(1) {
                self.refund(&loser.bidder, loser.amount, height);
            }
            self.credit_last_activity.insert(winner_bid.bidder, height);
            let swaps = self
                .targets
                .get(&target)
                .map(|target| target.swaps.clone())
                .unwrap_or_default();
            let deadline = height.saturating_add(params.auction_execution_deadline_blocks.max(1));
            self.winners.insert(
                target,
                AuctionWin {
                    winner: winner_bid.bidder,
                    swaps,
                    deadline,
                    cleared_height: height,
                },
            );
        }
    }

    /// Claims the auction award for `txid`, if the transaction belongs to a bundle that was
    /// won at auction and is still inside its execution window.
    ///
    /// Returns the winning node. The claim is consumed: every transaction of a bundle can
    /// only be executed once.
    pub fn take_award(
        &mut self,
        txid: &Hash,
        height: u64,
        gov: &GovernanceSet,
    ) -> Option<(Hash, PublicKey)> {
        let target = self
            .winners
            .iter()
            .find(|(_, win)| win.swaps.contains(txid))
            .map(|(target, _)| *target)?;
        let win = self.winners.get_mut(&target)?;
        if win.deadline < height {
            // The execution window closed: the right lapses and the bundle becomes
            // available for the next auction.
            self.winners.remove(&target);
            return None;
        }
        if !gov.contains_node(&win.winner) {
            // The winner is no longer an active server node; the fee falls back to the
            // normal split and the right lapses.
            self.winners.remove(&target);
            return None;
        }
        win.swaps.retain(|swap| swap != txid);
        let winner = win.winner;
        if win.swaps.is_empty() {
            self.winners.remove(&target);
            if let Some(entry) = self.targets.get_mut(&target) {
                entry.executed = true;
            }
        }
        Some((target, winner))
    }
}

impl ChainState {
    /// Builds genesis state and the genesis block.
    pub fn genesis(
        config: &oxydome_core::GenesisConfig,
    ) -> Result<(ChainState, Block, GovernanceSet), StateError> {
        if config.masters.is_empty() {
            return Err(StateError::NoMasters);
        }
        let allocated = config.allocated_supply();
        if allocated != config.params.genesis_supply {
            return Err(StateError::GenesisSupplyMismatch(
                allocated,
                config.params.genesis_supply,
            ));
        }
        let coinbase_id = if config.params.chain_name == "Ox" {
            hash_value(&config.allocations)
        } else {
            hash_value(&(config.params.chain_name.as_str(), &config.allocations))
        };
        let utxo =
            UtxoLedger::from_entries(config.allocations.iter().enumerate().map(|(i, alloc)| {
                let outpoint = OutPoint::new(coinbase_id, i as u32);
                UtxoEntry::new(
                    outpoint,
                    TxOutput::spendable(alloc.amount, alloc.recipient),
                    0,
                )
            }));
        let state_root = utxo.root();
        let producer = config.masters[0];
        let block = Block::build_header(
            0,
            config.params.execution_version_at(0),
            config.params.ovm_activation_height,
            config.params.smart_contract_activation_height,
            Hash::zero(),
            state_root,
            state_root,
            config.params.genesis_supply,
            0,
            0,
            ValueIndex::from_raw(config.params.initial_value_index),
            producer,
            config.timestamp,
            Vec::new(),
            Vec::new(),
            None,
            None,
            &config.params.network_magic_phrase,
        );
        let block_hash = block.hash();
        let state = ChainState {
            utxo,
            contracts: BTreeMap::new(),
            daos: BTreeMap::new(),
            ohm_states: BTreeMap::new(),
            ovm_receipts: Vec::new(),
            supply: config.params.genesis_supply,
            height: 0,
            block_hash,
            value_index: ValueIndex::from_raw(config.params.initial_value_index),
            generation: 0,
            epoch: 0,
            genesis_supply: config.params.genesis_supply,
            stats_history: VecDeque::new(),
            epoch_minted: 0,
            epoch_burned: 0,
            epoch_withdrawn: 0,
            gas: BTreeMap::new(),
            gas_supply: 0,
            ox_price: config.params.ox_price_reference,
            last_airdrop_height: 0,
            price_update_height: config.params.price_update_height,
            price_last_update_height: 0,
            chain_name: config.params.chain_name.clone(),
            currency_symbol: config.params.currency_symbol.clone(),
            storage_labels: BTreeMap::new(),
            storage_audits: BTreeMap::new(),
            timers: BTreeMap::new(),
            pegged_currencies: BTreeMap::new(),
            liquidity_pools: BTreeMap::new(),
            file_labels: BTreeMap::new(),
            file_access_log: BTreeMap::new(),
            file_chain_tip: Hash::zero(),
            file_node_counts: BTreeMap::new(),
            speedometer: BTreeMap::new(),
            speedometer_supply: 0,
            last_speedometer_airdrop_height: 0,
            speedometer_minted: 0,
            speedometer_airdrop_amount: 0,
            block_gas_fees: 0,
            block_gas_price: 0,
            departures: Vec::new(),
            express_buses: BTreeMap::new(),
            auction: AuctionState::default(),
        };
        let gov = GovernanceSet::new(config.masters.clone(), config.nodes.clone());
        Ok((state, block, gov))
    }

    pub fn utxo_root(&self) -> Hash {
        self.utxo.root()
    }

    /// Combined commitment to UTXOs, OVM code/storage, DAO state, OHM state, storage labels, timers,
    /// and pegged currency state. Empty feature state preserves the original transfer-only state root.
    ///
    /// When `pegged_currencies` is non-empty, a new domain separator family (`v5`/`v6`) is used
    /// so that pre-pegged chains retain byte-identical roots.
    pub fn state_root(&self) -> Hash {
        let base = self.base_state_root();
        let auction = self.auction_root();
        if auction.is_zero() {
            base
        } else {
            hash_value(&("oxydome-auction-wrap-v1", base, auction))
        }
    }

    /// The state root without the verification-credit auction commitment.
    fn base_state_root(&self) -> Hash {
        if self.contracts.is_empty()
            && self.daos.is_empty()
            && self.ohm_states.is_empty()
            && self.storage_labels.is_empty()
            && self.storage_audits.is_empty()
            && self.timers.is_empty()
            && self.pegged_currencies.is_empty()
            && self.liquidity_pools.is_empty()
            && self.file_labels.is_empty()
            && self.file_access_log.is_empty()
            && self.express_buses.is_empty()
        {
            return self.utxo.root();
        }
        let ovm_root = if self.contracts.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-ovm-state-v1", &self.contracts))
        };
        let dao_root = if self.daos.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-dao-state-v1", &self.daos))
        };
        let ohm_root = if self.ohm_states.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-ohm-state-v1", &self.ohm_states))
        };
        let timer_root = if self.timers.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-timer-state-v1", &self.timers))
        };
        let pegged_root = if self.pegged_currencies.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-pegged-state-v1", &self.pegged_currencies))
        };
        let pool_root = if self.liquidity_pools.is_empty() {
            Hash::zero()
        } else {
            hash_value(&("oxydome-pool-state-v1", &self.liquidity_pools))
        };
        let file_root = if self.file_labels.is_empty() && self.file_access_log.is_empty() {
            Hash::zero()
        } else {
            hash_value(&(
                "oxydome-evfs-state-v1",
                &self.file_labels,
                &self.file_access_log,
            ))
        };
        let has_files = !file_root.is_zero();
        let has_pools = !pool_root.is_zero();
        let has_storage = !self.storage_labels.is_empty() || !self.storage_audits.is_empty();
        let has_express = !self.express_buses.is_empty();
        let express_root = if has_express {
            hash_value(&("oxydome-express-bus-state-v1", &self.express_buses))
        } else {
            Hash::zero()
        };
        let storage_root = if has_storage {
            hash_value(&(
                "oxydome-storage-state-v1",
                &self.storage_labels,
                &self.storage_audits,
            ))
        } else {
            Hash::zero()
        };

        // Versioning: when liquidity pools are present, use v9 domain separators that
        // include pool_root. When pools are absent, all existing v2-v8 paths are
        // preserved byte-for-byte. When Express Bus trackers are present, the base
        // root is wrapped with an additional domain separator so existing chains are
        // unaffected.
        let base_root = if has_pools {
            if !has_files {
                if pegged_root.is_zero() {
                    if ohm_root.is_zero() {
                        if has_storage {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-pegged-no-ohm",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                storage_root,
                                timer_root,
                                pool_root,
                            ))
                        } else {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-pegged-no-ohm-no-storage",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                timer_root,
                                pool_root,
                            ))
                        }
                    } else {
                        if has_storage {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-pegged",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                ohm_root,
                                storage_root,
                                timer_root,
                                pool_root,
                            ))
                        } else {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-pegged-no-storage",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                ohm_root,
                                timer_root,
                                pool_root,
                            ))
                        }
                    }
                } else {
                    if ohm_root.is_zero() {
                        if has_storage {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-ohm",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                storage_root,
                                timer_root,
                                pegged_root,
                                pool_root,
                            ))
                        } else {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-ohm-no-storage",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                timer_root,
                                pegged_root,
                                pool_root,
                            ))
                        }
                    } else {
                        if has_storage {
                            hash_value(&(
                                "oxydome-combined-state-v9",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                ohm_root,
                                storage_root,
                                timer_root,
                                pegged_root,
                                pool_root,
                            ))
                        } else {
                            hash_value(&(
                                "oxydome-combined-state-v9-no-storage",
                                self.utxo.root(),
                                ovm_root,
                                dao_root,
                                ohm_root,
                                timer_root,
                                pegged_root,
                                pool_root,
                            ))
                        }
                    }
                }
            } else {
                if pegged_root.is_zero() {
                    if ohm_root.is_zero() {
                        hash_value(&(
                            "oxydome-combined-state-v9-no-pegged-no-ohm-files",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            storage_root,
                            timer_root,
                            pool_root,
                            file_root,
                        ))
                    } else {
                        hash_value(&(
                            "oxydome-combined-state-v9-no-pegged-files",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            ohm_root,
                            storage_root,
                            timer_root,
                            pool_root,
                            file_root,
                        ))
                    }
                } else if ohm_root.is_zero() {
                    hash_value(&(
                        "oxydome-combined-state-v9-no-ohm-files",
                        self.utxo.root(),
                        ovm_root,
                        dao_root,
                        storage_root,
                        timer_root,
                        pegged_root,
                        pool_root,
                        file_root,
                    ))
                } else {
                    hash_value(&(
                        "oxydome-combined-state-v9-files",
                        self.utxo.root(),
                        ovm_root,
                        dao_root,
                        ohm_root,
                        storage_root,
                        timer_root,
                        pegged_root,
                        pool_root,
                        file_root,
                    ))
                }
            }
        } else if !has_files {
            if pegged_root.is_zero() {
                if ohm_root.is_zero() {
                    if has_storage {
                        hash_value(&(
                            "oxydome-combined-state-v4-no-ohm",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            storage_root,
                            timer_root,
                        ))
                    } else {
                        hash_value(&(
                            "oxydome-combined-state-v2",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            timer_root,
                        ))
                    }
                } else {
                    if has_storage {
                        hash_value(&(
                            "oxydome-combined-state-v4",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            ohm_root,
                            storage_root,
                            timer_root,
                        ))
                    } else {
                        hash_value(&(
                            "oxydome-combined-state-v3",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            ohm_root,
                            timer_root,
                        ))
                    }
                }
            } else {
                if ohm_root.is_zero() {
                    if has_storage {
                        hash_value(&(
                            "oxydome-combined-state-v6-no-ohm",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            storage_root,
                            timer_root,
                            pegged_root,
                        ))
                    } else {
                        hash_value(&(
                            "oxydome-combined-state-v5",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            timer_root,
                            pegged_root,
                        ))
                    }
                } else {
                    if has_storage {
                        hash_value(&(
                            "oxydome-combined-state-v7",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            ohm_root,
                            storage_root,
                            timer_root,
                            pegged_root,
                        ))
                    } else {
                        hash_value(&(
                            "oxydome-combined-state-v6",
                            self.utxo.root(),
                            ovm_root,
                            dao_root,
                            ohm_root,
                            timer_root,
                            pegged_root,
                        ))
                    }
                }
            }
        } else if pegged_root.is_zero() {
            if ohm_root.is_zero() {
                hash_value(&(
                    "oxydome-combined-state-v8-no-pegged-no-ohm",
                    self.utxo.root(),
                    ovm_root,
                    dao_root,
                    storage_root,
                    timer_root,
                    file_root,
                ))
            } else {
                hash_value(&(
                    "oxydome-combined-state-v8-no-pegged",
                    self.utxo.root(),
                    ovm_root,
                    dao_root,
                    ohm_root,
                    storage_root,
                    timer_root,
                    file_root,
                ))
            }
        } else if ohm_root.is_zero() {
            hash_value(&(
                "oxydome-combined-state-v8-no-ohm",
                self.utxo.root(),
                ovm_root,
                dao_root,
                storage_root,
                timer_root,
                pegged_root,
                file_root,
            ))
        } else {
            hash_value(&(
                "oxydome-combined-state-v8",
                self.utxo.root(),
                ovm_root,
                dao_root,
                ohm_root,
                storage_root,
                timer_root,
                pegged_root,
                file_root,
            ))
        };

        if has_express {
            hash_value(&(
                "oxydome-express-bus-wrap-v1",
                base_root,
                express_root,
            ))
        } else {
            base_root
        }
    }

    /// The verification-credit auction commitment.
    ///
    /// Commits to the credit balances, the registered auction targets, the pending bids and
    /// the outstanding auction wins. Returns [`Hash::zero`] when no auction state exists, so
    /// chains that never use the auction keep their original state root.
    fn auction_root(&self) -> Hash {
        if self.auction.credits.is_empty()
            && self.auction.credit_last_activity.is_empty()
            && self.auction.pending_bids.is_empty()
            && self.auction.targets.is_empty()
            && self.auction.winners.is_empty()
        {
            return Hash::zero();
        }
        hash_value(&("oxydome-auction-state-v1", &self.auction))
    }

    /// Returns the GAS balance for `owner`.
    pub fn gas_balance(&self, owner: &PublicKey) -> Amount {
        self.gas.get(owner).map_or(0, |account| account.balance)
    }

    /// The verification-credit balance of a server node.
    ///
    /// Verification credits are a non-financial unit: they cannot be transferred and are
    /// never part of the Ox supply. They are earned by participating in block verification
    /// and are spent in the verification-credit auction.
    pub fn verification_credit_balance(&self, node: &PublicKey) -> u64 {
        self.auction.credit_balance(node)
    }

    /// Whether the execution of `txid` performed a liquidity-pool swap.
    ///
    /// The OVM emits a dedicated log for every pool swap, so a swap transaction is
    /// recognisable from its receipt alone. The verification-credit auction only accepts
    /// swaps.
    pub fn receipt_performed_pool_swap(&self, txid: &Hash) -> bool {
        receipt_performed_pool_swap_in(&self.ovm_receipts, txid)
    }

    /// Whether the transaction would perform a liquidity-pool swap.
    ///
    /// The OVM action is executed against a copy of the state so that the caller can tell
    /// a swap from an ordinary transfer before the transaction is put in a block. This is
    /// what the verification-credit auction uses to accept only swaps.
    pub fn preview_is_pool_swap(
        &self,
        tx: &Transaction,
        tx_index: usize,
        params: &ChainParams,
    ) -> bool {
        let Some(action) = &tx.ovm_action else {
            return false;
        };
        let mut preview = self.clone();
        match preview.apply_ovm_action(action, tx.txid(), tx_index, tx, params) {
            Ok(receipt) => receipt
                .logs
                .iter()
                .any(|log| log.topic == oxydome_core::POOL_SWAP_LOG_TOPIC),
            Err(_) => false,
        }
    }

    /// Claims the auction award for `txid`, if the transaction belongs to a bundle that
    /// was won at auction and is still inside its execution window.
    ///
    /// Returns the winning bundle and the winning node. The claim is consumed: a bundle's
    /// transactions can only be executed once.
    pub fn take_auction_award(
        &mut self,
        txid: &Hash,
        height: u64,
        gov: &GovernanceSet,
    ) -> Option<(Hash, PublicKey)> {
        self.auction.take_award(txid, height, gov)
    }

    /// Pays a node reward, converting the configured share of Ox into GAS fuel exactly
    /// like the block-reward path does.
    fn mint_reward(
        &mut self,
        outpoint: OutPoint,
        amount: Amount,
        recipient: PublicKey,
        height: u64,
        params: &ChainParams,
    ) {
        let convert = height >= params.gas_activation_height && params.gas_server_fee_bps > 0;
        let (ox_kept, gas_minted) = if convert {
            conversion_split_with_bps(amount, params.gas_server_fee_bps)
        } else {
            (amount, 0)
        };
        if ox_kept > 0 {
            self.utxo = self.utxo.insert(UtxoEntry::new(
                outpoint,
                TxOutput::locked_reward(ox_kept, recipient),
                height,
            ));
        }
        if gas_minted > 0 {
            // Burn the converted Ox and mint the GAS fuel to the same recipient.
            self.supply = self.supply.saturating_sub(gas_minted);
            self.mint_gas(recipient, gas_minted);
        }
    }

    /// Computes the current GAS price from the pegged currency state for `PriceAsset::Gas`.
    ///
    /// If a pegged currency tracks GAS (asset == `PriceAsset::Gas`) and the current
    /// price is in bounds (>= midpoint), the price premium from the bounds is applied
    /// to `base_price` (which defaults to `self.ox_price`). When out of bounds or no
    /// pegged GAS currency exists, falls back to `self.ox_price` as the gas price.
    pub fn compute_gas_price(&self, params: &ChainParams) -> Amount {
        let base_price = self.ox_price;
        for state in self.pegged_currencies.values() {
            if state.config.asset == oxydome_core::PriceAsset::Gas {
                let premium = oxydome_core::compute_gas_price_premium(&state.bounds);
                if premium == 0 {
                    return base_price;
                }
                return base_price
                    .saturating_mul(premium)
                    .saturating_div(oxydome_core::VALUE_SCALE);
            }
        }
        base_price
    }

    /// Builds a `CrossHost` with a price oracle populated from the current pegged currency
    /// bound states. Returns `None` if there are no pegged currencies (so plain `execute`
    /// is used instead).
    pub fn build_price_host(&self) -> Option<oxydome_ovm::CrossHost> {
        if self.pegged_currencies.is_empty() {
            return None;
        }
        let mut bounds = std::collections::BTreeMap::new();
        for state in self.pegged_currencies.values() {
            let key = state.config.asset.oracle_key();
            bounds.insert(key, state.bounds.pack());
        }
        Some(oxydome_ovm::CrossHost {
            origin_ohm: Hash::zero(),
            inbox: std::collections::BTreeMap::new(),
            price_oracle: Some(oxydome_ovm::PriceOracle { bounds }),
            pool_oracle: None,
        })
    }

    /// Builds a `CrossHost` with both price and pool oracles populated.
    /// Returns `None` if there are no pegged currencies and no liquidity pools.
    pub fn build_host(&self) -> Option<oxydome_ovm::CrossHost> {
        if self.pegged_currencies.is_empty() && self.liquidity_pools.is_empty() {
            return None;
        }
        let mut bounds = std::collections::BTreeMap::new();
        for state in self.pegged_currencies.values() {
            let key = state.config.asset.oracle_key();
            bounds.insert(key, state.bounds.pack());
        }
        let mut pools = std::collections::BTreeMap::new();
        for (id, state) in self.liquidity_pools.iter() {
            let key = id.0[..8].try_into().map(u64::from_le_bytes).unwrap_or(0);
            let packed = state.pack();
            pools.insert(
                key,
                oxydome_ovm::PoolStatePacked {
                    reserve_x: packed.reserve_x,
                    reserve_y: packed.reserve_y,
                    k: packed.k,
                    fee_bps: packed.fee_bps,
                },
            );
        }
        Some(oxydome_ovm::CrossHost {
            origin_ohm: Hash::zero(),
            inbox: std::collections::BTreeMap::new(),
            price_oracle: if bounds.is_empty() {
                None
            } else {
                Some(oxydome_ovm::PriceOracle { bounds })
            },
            pool_oracle: if pools.is_empty() {
                None
            } else {
                Some(oxydome_ovm::PoolOracle { pools })
            },
        })
    }

    /// The nonce expected on the next GAS transfer from `owner`.
    pub fn gas_nonce(&self, owner: &PublicKey) -> u64 {
        self.gas.get(owner).map_or(0, |account| account.nonce)
    }

    /// Mints `amount` GAS to `owner`, increasing the circulating GAS supply.
    pub fn mint_gas(&mut self, owner: PublicKey, amount: Amount) {
        if amount == 0 {
            return;
        }
        let entry = self.gas.entry(owner).or_default();
        entry.balance = entry.balance.saturating_add(amount);
        self.gas_supply = self.gas_supply.saturating_add(amount);
    }

    /// Burns `amount` GAS from `owner`, decreasing the circulating GAS supply.
    fn burn_gas(&mut self, owner: &PublicKey, amount: Amount) -> Result<(), StateError> {
        if amount == 0 {
            return Ok(());
        }
        let entry = self
            .gas
            .get_mut(owner)
            .ok_or(StateError::GasUnderfunded(*owner))?;
        if entry.balance < amount {
            return Err(StateError::GasUnderfunded(*owner));
        }
        entry.balance -= amount;
        self.gas_supply = self.gas_supply.saturating_sub(amount);
        Ok(())
    }

    /// Returns the Speedometer balance for `owner`.
    pub fn speedometer_balance(&self, owner: &PublicKey) -> Amount {
        self.speedometer
            .get(owner)
            .map_or(0, |account| account.balance)
    }

    /// The nonce expected on the next Speedometer transfer from `owner`.
    pub fn speedometer_nonce(&self, owner: &PublicKey) -> u64 {
        self.speedometer
            .get(owner)
            .map_or(0, |account| account.nonce)
    }

    /// Mints `amount` Speedometer to `owner`, increasing the circulating Speedometer supply.
    pub fn mint_speedometer(&mut self, owner: PublicKey, amount: Amount) {
        if amount == 0 {
            return;
        }
        let entry = self.speedometer.entry(owner).or_default();
        entry.balance = entry.balance.saturating_add(amount);
        self.speedometer_supply = self.speedometer_supply.saturating_add(amount);
    }

    /// Burns `amount` Speedometer from `owner`, decreasing the circulating Speedometer supply.
    fn burn_speedometer(&mut self, owner: &PublicKey, amount: Amount) -> Result<(), StateError> {
        if amount == 0 {
            return Ok(());
        }
        let entry = self
            .speedometer
            .get_mut(owner)
            .ok_or(StateError::SpeedometerUnderfunded(*owner))?;
        if entry.balance < amount {
            return Err(StateError::SpeedometerUnderfunded(*owner));
        }
        entry.balance -= amount;
        self.speedometer_supply = self.speedometer_supply.saturating_sub(amount);
        Ok(())
    }

    /// The summed statistics over the measurement window.
    pub fn window_stats(&self, params: &ChainParams) -> WindowStats {
        let limit = params.block_window.max(1) as usize;
        let mut stats = WindowStats::default();
        for s in self.stats_history.iter().rev().take(limit) {
            stats.accumulate(s);
        }
        stats
    }

    /// Applies `block` on top of `self`, returning the resulting state. Does not mutate `self`.
    pub fn apply_block(
        &self,
        block: &Block,
        gov: &GovernanceSet,
        params: &ChainParams,
    ) -> Result<ChainState, StateError> {
        self.apply_inner(block, gov, params, true)
    }

    /// Produces a fully-formed block (correct `state_root`, `supply`, `value_index` and
    /// `generation`) from a set of transactions and operations. The block is verified before
    /// it is returned.
    ///
    /// `coin_toss_seed` is provided by the leader after the consensus coin-toss phase;
    /// when `None` the block is produced in legacy mode (no position hashes, no
    /// ordered execution).
    pub fn build_block(
        &self,
        gov: &GovernanceSet,
        params: &ChainParams,
        transactions: Vec<Transaction>,
        operations: Vec<Operation>,
        producer: PublicKey,
        timestamp: u64,
        coin_toss_seed: Option<Hash>,
    ) -> Result<Block, StateError> {
        let coin_toss_active = self.height + 1 >= params.coin_toss_activation_height
            && coin_toss_seed.is_some();
        let ordered_tx_root: Option<Hash> = coin_toss_seed
            .as_ref()
            .map(|seed| oxydome_core::ordered_root(&transactions, seed, params));
        let mut block = Block::build_header(
            self.height + 1,
            params.execution_version_at(self.height + 1),
            params.ovm_activation_height,
            params.smart_contract_activation_height,
            self.block_hash,
            Hash::zero(),
            Hash::zero(),
            0,
            self.epoch,
            self.generation,
            self.value_index,
            producer,
            timestamp,
            transactions,
            operations,
            coin_toss_seed,
            ordered_tx_root,
            &params.network_magic_phrase,
        );
        let next = self.apply_inner(&block, gov, params, false)?;
        block.ovm_receipts = next.ovm_receipts.clone();
        block.header.ovm_receipt_root = block.ovm_receipt_root();
        block.header.utxo_root = next.utxo_root();
        block.header.state_root = next.state_root();
        block.header.supply = next.supply;
        block.header.value_index = next.value_index;
        block.header.generation = next.generation;
        block.header.speedometer_minted = next.speedometer_minted;
        block.header.speedometer_airdrop_amount = next.speedometer_airdrop_amount;
        block.header.gas_price = next.block_gas_price;
        block.header.total_gas_fees = next.block_gas_fees;
        // Re-verify against the committed header.
        self.apply_inner(&block, gov, params, true)?;
        Ok(block)
    }

    /// Calculates actual fees by executing OVM actions against a temporary ordered overlay.
    /// Block production uses this same execution path as consensus validation.
    pub fn settled_fee_total(
        &self,
        transactions: &[Transaction],
        params: &ChainParams,
    ) -> Result<Amount, StateError> {
        let mut execution_state = self.clone();
        let mut total = 0u128;
        let mut gas_limit_total = 0u64;
        for (tx_index, tx) in transactions.iter().enumerate() {
            let fee = if let Some(action) = &tx.ovm_action {
                let stack_gas = action.required_stack_gas(params.ovm_stack_bytes_per_gas);
                gas_limit_total = gas_limit_total
                    .checked_add(stack_gas)
                    .filter(|total| *total <= MAX_OVM_BLOCK_GAS_LIMIT)
                    .ok_or(StateError::OvmBlockGasLimit)?;
                let required = oxydome_core::transfer_fee(&tx.outputs)
                    .map_err(|error| StateError::BadTransaction(tx_index, error.to_string()))?;
                let legacy_required = required.saturating_add(u128::from(stack_gas));
                if tx.fee != required && tx.fee != legacy_required {
                    return Err(StateError::BadTransaction(
                        tx_index,
                        "fee does not equal the transfer fee".into(),
                    ));
                }
                let _ =
                    execution_state.apply_ovm_action(action, tx.txid(), tx_index, tx, params)?;
                tx.fee
            } else {
                tx.fee
            };
            total = total.checked_add(fee).ok_or_else(|| {
                StateError::BadTransaction(tx_index, "block fee total overflows".into())
            })?;
        }
        Ok(total)
    }

    fn apply_inner(
        &self,
        block: &Block,
        gov: &GovernanceSet,
        params: &ChainParams,
        enforce_header: bool,
    ) -> Result<ChainState, StateError> {
        if block.header.height != self.height + 1 {
            return Err(StateError::BadHeight(block.header.height, self.height));
        }
        if block.header.execution_version != params.execution_version_at(block.header.height)
            || block.header.ovm_activation_height != params.ovm_activation_height
            || block.header.smart_contract_activation_height
                != params.smart_contract_activation_height
        {
            return Err(StateError::ExecutionVersionMismatch);
        }
        if block.header.prev_hash != self.block_hash {
            return Err(StateError::BadPrevHash);
        }
        if !block.roots_match() {
            return Err(StateError::BadRoots);
        }
        if !gov.contains_node(&block.header.producer) {
            return Err(StateError::UnauthorizedProducer(block.header.producer));
        }
        // An epoch change is effectuated by a governance-co-signed `EpochTransition`, never by a
        // self-declared header field. Letting a proposer bump the epoch would reset the
        // per-epoch mint/burn/withdraw caps at will, so the header must match the chain's epoch.
        if block.header.epoch != self.epoch {
            return Err(StateError::EpochChange(self.epoch, block.header.epoch));
        }

        let new_height = block.header.height;
        let mut next = self.clone();
        next.ovm_receipts.clear();

        // ---- Verification-credit expiry ----
        // Credits that have not been earned or spent for `auction_credit_expiry_blocks`
        // blocks (two auction windows by default) expire, keeping the auction competitive.
        next.auction.expire_credits(new_height, params);

        // ---- Lapsed auction rights ----
        // A winning node may only execute its bundle within the execution window that
        // followed the clearing. Once the window closes the right lapses and the bundle
        // becomes available for the next auction.
        next.auction.expire_wins(new_height);

        // ---- Coin-toss: verify seed, ordered root and position hashes ----
        let coin_toss_active =
            new_height >= params.coin_toss_activation_height;
        if coin_toss_active {
            // The seed must be present; ordered_tx_root must match the commitment.
            let seed = block
                .header
                .coin_toss_seed
                .ok_or(StateError::CoinTossMismatch)?;
            let ordered_root = block
                .header
                .ordered_tx_root
                .ok_or(StateError::CoinTossMismatch)?;

            // Re-derive the ordered root from the block's transactions and seed.
            let expected_root =
                oxydome_core::ordered_root(&block.transactions, &seed, params);
            if expected_root != ordered_root {
                return Err(StateError::CoinTossMismatch);
            }

            // Verify each transaction's position hash.
            let header_hash = block.hash();
            for (i, tx) in block.transactions.iter().enumerate() {
                if !tx.verify_position_hash(
                    &header_hash,
                    i,
                    block.header.timestamp,
                    &params.network_magic_phrase,
                ) {
                    return Err(StateError::BadPositionHash(i));
                }
            }
        }

        // Reject duplicate operations up front. Two identical operations share an `id()` (and
        // therefore identical minted outpoints), so applying both would inflate the supply while
        // overwriting the same UTXO entries, breaking the `utxo.total() == supply` invariant.
        {
            let mut seen_ops: BTreeSet<Hash> = BTreeSet::new();
            for op in &block.operations {
                if !seen_ops.insert(op.id()) {
                    return Err(StateError::DuplicateOperation);
                }
            }
        }

        // ---- 1. Transactions ----
        let mut total_fees: Amount = 0;
        let mut block_ovm_gas_limit = 0u64;
        let mut block_stats = WindowStats::default();
        next.speedometer_minted = 0;
        next.speedometer_airdrop_amount = 0;
        next.block_gas_fees = 0;
        next.block_gas_price = self.compute_gas_price(params);

        // Determine execution order: coin-toss-ordered when active, otherwise
        // the canonical block order.
        let exec_txs: Vec<Transaction> = if coin_toss_active {
            let seed = block.header.coin_toss_seed.unwrap();
            ordered_transactions(&block.transactions, &seed)
        } else {
            block.transactions.clone()
        };

        // Verification-credit auction awards collected while applying the transactions:
        // (bundle id, transaction id, winning node, fee paid to the winner).
        let mut auction_awards: Vec<(Hash, Hash, PublicKey, Amount)> = Vec::new();
        // The auction payouts that were actually applied: (transaction id, fee).
        let mut paid_auction_awards: Vec<(Hash, Amount)> = Vec::new();

        for (tx_idx, tx) in exec_txs.iter().enumerate() {
            tx.validate_structure()
                .map_err(|e| StateError::BadTransaction(tx_idx, e.to_string()))?;
            if let Some(action) = &tx.ovm_action {
                if block.header.height < params.ovm_activation_height {
                    return Err(StateError::BadTransaction(
                        tx_idx,
                        "OVM is not active at this height".into(),
                    ));
                }
                if action.is_smart_contract_action()
                    && block.header.height < params.smart_contract_activation_height
                {
                    return Err(StateError::BadTransaction(
                        tx_idx,
                        "multi-entry-point smart contracts are not active at this height".into(),
                    ));
                }
                let stack_gas = action.required_stack_gas(params.ovm_stack_bytes_per_gas);
                block_ovm_gas_limit = block_ovm_gas_limit
                    .checked_add(stack_gas)
                    .ok_or(StateError::OvmBlockGasLimit)?;
                if block_ovm_gas_limit > MAX_OVM_BLOCK_GAS_LIMIT {
                    return Err(StateError::OvmBlockGasLimit);
                }
                if action.stack_bytes() > params.max_ovm_data_stack_bytes {
                    return Err(StateError::OvmStackLimit);
                }
                let expected_fee = oxydome_core::transfer_fee(&tx.outputs)
                    .map_err(|error| StateError::BadTransaction(tx_idx, error.to_string()))?;
                let legacy_expected_fee = expected_fee.saturating_add(u128::from(stack_gas));
                if tx.fee != expected_fee && tx.fee != legacy_expected_fee {
                    return Err(StateError::BadTransaction(
                        tx_idx,
                        "fee does not equal the transfer fee".into(),
                    ));
                }
            }
            let mut input_total: Amount = 0;
            // Validate and detach inputs.
            for input in &tx.inputs {
                let entry = next
                    .utxo
                    .get(&input.prev_out)
                    .cloned()
                    .ok_or(StateError::MissingInput(input.prev_out))?;
                if !entry.output.kind.is_spendable() {
                    return Err(StateError::UnspendableInput(input.prev_out));
                }
                if entry.output.recipient != input.owner {
                    return Err(StateError::InputOwnerMismatch(input.prev_out));
                }
                if !rebound_utxo_spendable(
                    new_height,
                    entry.created_height,
                    entry.output.rebound_gen,
                    params,
                ) {
                    return Err(StateError::ImmatureRebound(input.prev_out));
                }
                input_total = input_total.saturating_add(entry.output.amount);
                next.utxo = next.utxo.remove(&input.prev_out).0;
            }
            let output_total = tx
                .output_total()
                .map_err(|_| StateError::BadTransaction(tx_idx, "output overflow".into()))?;
            if input_total != output_total.saturating_add(tx.fee) {
                return Err(StateError::Conservation);
            }
            block_stats.volume = block_stats.volume.saturating_add(output_total);
            block_stats.tx_count = block_stats.tx_count.saturating_add(1);
            block_stats.highest_tx_value = block_stats.highest_tx_value.max(output_total);
            for (out_idx, output) in tx.outputs.iter().enumerate() {
                if output.kind.is_exit() {
                    block_stats.exit_amount = block_stats.exit_amount.saturating_add(output.amount);
                }
                let outpoint = OutPoint::new(tx.txid(), out_idx as u32);
                next.utxo = next
                    .utxo
                    .insert(UtxoEntry::new(outpoint, output.clone(), new_height));
            }

            if let Some(action) = &tx.ovm_action {
                if action.stack_bytes() > params.max_ovm_data_stack_bytes {
                    return Err(StateError::OvmStackLimit);
                }
                if block.header.height >= params.gas_activation_height {
                    if let Some(caller) = ovm_caller(tx, action) {
                        let stack_gas = action.required_stack_gas(params.ovm_stack_bytes_per_gas);
                        let gas_limit_req =
                            u128::from(stack_gas).saturating_mul(next.block_gas_price);
                        if next.gas_balance(caller) < gas_limit_req {
                            return Err(StateError::OvmGasUnderfunded(*caller));
                        }
                        let receipt =
                            next.apply_ovm_action(action, tx.txid(), tx_idx, tx, params)?;
                        let gas_cost =
                            u128::from(receipt.gas_used).saturating_mul(next.block_gas_price);
                        let master_gas_share =
                            gas_cost.saturating_mul(params.gas_fee_master_bps as u128) / 10_000;
                        next.burn_gas(caller, gas_cost)?;
                        if master_gas_share > 0 {
                            let per_master = if gov.masters.is_empty() {
                                0
                            } else {
                                master_gas_share / gov.masters.len() as u128
                            };
                            let remainder = master_gas_share.saturating_sub(
                                per_master.saturating_mul(gov.masters.len() as u128),
                            );
                            for master in &gov.masters {
                                next.mint_gas(*master, per_master);
                            }
                            if remainder > 0 {
                                if let Some(master) = gov.masters.first() {
                                    next.mint_gas(*master, remainder);
                                }
                            }
                        }
                        next.block_gas_fees = next.block_gas_fees.saturating_add(gas_cost);
                        next.ovm_receipts.push(receipt);
                    } else {
                        let receipt =
                            next.apply_ovm_action(action, tx.txid(), tx_idx, tx, params)?;
                        next.ovm_receipts.push(receipt);
                    }
                } else {
                    let receipt = next.apply_ovm_action(action, tx.txid(), tx_idx, tx, params)?;
                    next.ovm_receipts.push(receipt);
                }
            }

            // Verification-credit auction: a swap bundle that was won at auction is
            // executed by the winning node, which collects 100% of the transaction's
            // fees instead of the normal master/server split. Only a transaction that
            // really performed a liquidity-pool swap qualifies.
            let auction_winner = if next.receipt_performed_pool_swap(&tx.txid()) {
                next.take_auction_award(&tx.txid(), new_height, gov)
            } else {
                None
            };
            let normal_fee = match auction_winner {
                Some((target, winner)) => {
                    auction_awards.push((target, tx.txid(), winner, tx.fee));
                    0
                }
                None => tx.fee,
            };
            total_fees = total_fees.checked_add(normal_fee).ok_or_else(|| {
                StateError::BadTransaction(tx_idx, "block fee total overflows".into())
            })?;

            // Per-transaction Speedometer stabilization: mint a small fraction of the tx value
            // and distribute to active liquidity pool owners proportionally to their pool's share
            // of total LP value. If no pools exist, the stabilization goes to the block producer.
            if new_height >= params.speedometer_activation_height && output_total > 0 {
                let minted = stabilization_mint(output_total, params.speedometer_stabilization_bps);
                if minted > 0 {
                    if next.liquidity_pools.is_empty() {
                        next.mint_speedometer(block.header.producer, minted);
                    } else {
                        distribute_stabilization_to_pools(&mut next, minted);
                    }
                    next.speedometer_minted = next.speedometer_minted.saturating_add(minted);
                }
            }
        }

        // ---- Verification-credit auction payouts ----
        // The winner collects 100% of the fees of the transaction it executed, paid
        // exactly like a server-node reward (including the Ox -> GAS conversion). The
        // payout itself is carried by an `AuctionPayout` operation, which is matched
        // against the award derived above.
        if enforce_header && next.ovm_receipts != block.ovm_receipts {
            return Err(StateError::OvmReceiptMismatch);
        }

        if enforce_header
            && (block.header.volume != block_stats.volume
                || block.header.tx_count != block_stats.tx_count
                || block.header.exit_amount != block_stats.exit_amount)
        {
            return Err(StateError::StatsMismatch);
        }

        if enforce_header
            && (block.header.gas_price != next.block_gas_price
                || block.header.total_gas_fees != next.block_gas_fees)
        {
            return Err(StateError::GasStatsMismatch(
                block.header.gas_price,
                block.header.total_gas_fees,
                next.block_gas_price,
                next.block_gas_fees,
            ));
        }

        // Record this block's window statistics.
        next.stats_history.push_back(block_stats);
        while next.stats_history.len() > params.block_window.max(1) as usize {
            next.stats_history.pop_front();
        }
        let mut window = next.window_stats(params);

        // ---- 2. Reward distribution ----
        let reward_ops: Vec<&Operation> = block
            .operations
            .iter()
            .filter(|o| matches!(o, Operation::Rewards(_)))
            .collect();
        match reward_ops.len() {
            1 => {
                if let Operation::Rewards(r) = reward_ops[0] {
                    apply_rewards(&mut next, r, total_fees, gov, params, new_height)?;
                }
            }
            0 if total_fees == 0 => {}
            _ => return Err(StateError::BadRewardCount),
        }

        // ---- 3. Governance operations ----
        let mut dao_block_stats: BTreeMap<Hash, DaoWindowStats> = BTreeMap::new();
        for op in &block.operations {
            match op {
                Operation::Rewards(_) => {}
                Operation::BlockRewards(r) => {
                    apply_block_rewards(&mut next, r, new_height, params, gov)?;
                }
                Operation::Dao(dao_operation) => {
                    apply_dao_operation(
                        &mut next,
                        dao_operation,
                        new_height,
                        params,
                        &mut dao_block_stats,
                    )?;
                }
                Operation::Ohm(ohm_operation) => {
                    apply_ohm_operation(
                        &mut next,
                        ohm_operation,
                        op.id(),
                        new_height,
                        params,
                        gov,
                        block.header.producer,
                    )?;
                }
                Operation::Gas(gas_operation) => {
                    apply_gas_operation(&mut next, gas_operation, op, new_height, params, gov)?;
                }
                Operation::PriceChange(_) => {
                    // Price changes are handled by the consensus process,
                    // not by direct state application here.
                }
                Operation::StorageLabel(label_op) => {
                    let approvals = count_node_approvals(op, gov);
                    if approvals == 0 || !gov.contains_node(&label_op.label.node) {
                        // Allow node's own submission conceptually; for state apply, check signature
                    }
                    if !label_op.label.is_valid() {
                        return Err(StateError::OutOfBoundsStorageLabel);
                    }
                    if label_op.label.used_bytes > label_op.label.capacity_bytes {
                        return Err(StateError::OutOfBoundsStorageLabel);
                    }
                    next.storage_labels
                        .insert(label_op.label.node, label_op.label.clone());
                }
                Operation::StorageAudit(audit_op) => {
                    let approvals = count_master_approvals(op, gov);
                    let threshold = gov.master_threshold(params);
                    if approvals < threshold {
                        return Err(StateError::MasterApprovalMissing(approvals, threshold));
                    }
                    next.storage_audits
                        .insert(audit_op.result.epoch, audit_op.result.clone());
                }
                Operation::Timer(timer_operation) => {
                    apply_timer_operation(&mut next, timer_operation, op, new_height, params, gov)?;
                }
                Operation::Mint(m) => {
                    let approvals = count_master_approvals(op, gov);
                    let threshold = gov.master_threshold(params);
                    if approvals < threshold {
                        return Err(StateError::MasterApprovalMissing(approvals, threshold));
                    }
                    if next.epoch_minted.saturating_add(m.amount) > supply_change_cap(params) {
                        return Err(StateError::MintCapExceeded);
                    }
                    if !supply_impact_ok(
                        params,
                        &window,
                        next.supply,
                        next.supply.saturating_add(m.amount),
                        next.genesis_supply,
                        next.value_index,
                    ) {
                        return Err(StateError::MintValueImpact);
                    }
                    let outpoint = OutPoint::new(op.id(), 0);
                    // Reject re-application of an already-recorded mint.
                    if next.utxo.get(&outpoint).is_some() {
                        return Err(StateError::AlreadyMinted);
                    }
                    next.utxo = next.utxo.insert(UtxoEntry::new(
                        outpoint,
                        TxOutput::spendable(m.amount, m.recipient),
                        new_height,
                    ));
                    next.supply = next.supply.saturating_add(m.amount);
                    next.epoch_minted = next.epoch_minted.saturating_add(m.amount);
                }
                Operation::Burn(b) => {
                    let approvals = count_master_approvals(op, gov);
                    let threshold = gov.master_threshold(params);
                    if approvals < threshold {
                        return Err(StateError::MasterApprovalMissing(approvals, threshold));
                    }
                    if !verify(&b.owner, &op.proposal_id().0, &b.owner_signature) {
                        return Err(StateError::BadBurnSignature);
                    }
                    let entry = next
                        .utxo
                        .get(&b.source)
                        .cloned()
                        .ok_or(StateError::BadBurnSource(b.source))?;
                    if !entry.output.kind.is_spendable()
                        || entry.output.recipient != b.owner
                        || b.amount > entry.output.amount
                        || b.amount == 0
                    {
                        return Err(StateError::BadBurnSource(b.source));
                    }
                    if next.epoch_burned.saturating_add(b.amount) > supply_change_cap(params) {
                        return Err(StateError::BurnCapExceeded);
                    }
                    if !supply_impact_ok(
                        params,
                        &window,
                        next.supply,
                        next.supply.saturating_sub(b.amount),
                        next.genesis_supply,
                        next.value_index,
                    ) {
                        return Err(StateError::BurnValueImpact);
                    }
                    next.utxo = next.utxo.remove(&b.source).0;
                    let change = entry.output.amount - b.amount;
                    if change > 0 {
                        let outpoint = OutPoint::new(op.id(), 0);
                        next.utxo = next.utxo.insert(UtxoEntry::new(
                            outpoint,
                            TxOutput::spendable(change, b.owner),
                            new_height,
                        ));
                    }
                    next.supply = next.supply.saturating_sub(b.amount);
                    next.epoch_burned = next.epoch_burned.saturating_add(b.amount);
                }
                Operation::Withdraw(w) => {
                    let approvals = count_node_approvals(op, gov);
                    let threshold = gov.node_threshold(params);
                    if approvals < threshold {
                        return Err(StateError::NodeApprovalMissing(approvals, threshold));
                    }
                    if w.inputs.is_empty() {
                        return Err(StateError::BadWithdrawInput(OutPoint::new(Hash::zero(), 0)));
                    }
                    if !verify(&w.node, &op.proposal_id().0, &w.node_signature) {
                        return Err(StateError::BadWithdrawSignature);
                    }
                    if next.epoch_withdrawn.saturating_add(w.amount) > withdraw_cap(params) {
                        return Err(StateError::WithdrawCapExceeded);
                    }
                    // Per-account withdrawal limit: may not withdraw more than `per_account_withdraw_bps`
                    // basis points of the node's total balance.
                    let node_balance: Amount = next
                        .utxo
                        .to_map()
                        .values()
                        .filter(|e| e.output.recipient == w.node)
                        .map(|e| e.output.amount)
                        .sum();
                    let max_per_op =
                        max_withdraw_per_account(node_balance, params.per_account_withdraw_bps);
                    if w.amount > max_per_op {
                        return Err(StateError::PerAccountLimitExceeded);
                    }
                    let mut available: Amount = 0;
                    for input in &w.inputs {
                        let entry = next
                            .utxo
                            .get(input)
                            .cloned()
                            .ok_or(StateError::BadWithdrawInput(*input))?;
                        if !entry.output.kind.is_locked_reward() || entry.output.recipient != w.node
                        {
                            return Err(StateError::BadWithdrawInput(*input));
                        }
                        available = available.saturating_add(entry.output.amount);
                    }
                    if w.amount == 0 || available < w.amount {
                        return Err(StateError::BadWithdrawInput(w.inputs[0]));
                    }
                    for input in &w.inputs {
                        next.utxo = next.utxo.remove(input).0;
                    }
                    let outpoint = OutPoint::new(op.id(), 0);
                    next.utxo = next.utxo.insert(UtxoEntry::new(
                        outpoint,
                        TxOutput::spendable(w.amount, w.node),
                        new_height,
                    ));
                    let change = available - w.amount;
                    if change > 0 {
                        let change_outpoint = OutPoint::new(op.id(), 1);
                        next.utxo = next.utxo.insert(UtxoEntry::new(
                            change_outpoint,
                            TxOutput::locked_reward(change, w.node),
                            new_height,
                        ));
                    }
                    next.epoch_withdrawn = next.epoch_withdrawn.saturating_add(w.amount);
                }
                Operation::FileStore(file_op) => {
                    apply_file_store(&mut next, file_op, op, new_height, params, gov)?;
                }
                Operation::FileAccess(access_op) => {
                    apply_file_access(&mut next, access_op, op, new_height, params, gov)?;
                }
                Operation::FileDelete(delete_op) => {
                    apply_file_delete(&mut next, delete_op, op, new_height, params, gov)?;
                }
                Operation::LiquidityPool(lp_op) => {
                    apply_liquidity_pool_operation(&mut next, lp_op, op, new_height, params, gov)?;
                }
                Operation::AuctionTarget(target_op) => {
                    next.auction.register_target(target_op, op, new_height)?;
                }
                Operation::AuctionPayout(payout) => {
                    // The payout must match an award derived while applying the
                    // transactions of this block: the bundle, the transaction, the
                    // winning node and the fee.
                    let award = auction_awards.iter().find(|(_, txid, _, _)| {
                        *txid == payout.txid
                    });
                    let Some((target, txid, winner, fee)) = award else {
                        return Err(StateError::AuctionPayoutUnknown(payout.txid));
                    };
                    if *target != payout.target
                        || *winner != payout.winner
                        || *fee != payout.amount
                    {
                        return Err(StateError::AuctionPayoutMismatch(payout.txid));
                    }
                    if paid_auction_awards.iter().any(|(txid, _)| *txid == payout.txid) {
                        return Err(StateError::DuplicateOperation);
                    }
                    paid_auction_awards.push((payout.txid, *fee));
                    if payout.amount > 0 {
                        let outpoint = OutPoint::new(auction_reward_outpoint(&payout.txid), 0);
                        next.mint_reward(outpoint, payout.amount, payout.winner, new_height, params);
                    }
                }
                Operation::AuctionBid(bid) => {
                    // Only admitted server nodes may bid.
                    if !gov.contains_node(&bid.bidder) {
                        return Err(StateError::UnauthorizedProducer(bid.bidder));
                    }
                    next.auction.escrow_bid(bid, op, new_height, params)?;
                }
                Operation::Speedometer(speedometer_op) => {
                    apply_speedometer_operation(&mut next, speedometer_op, op, new_height, params)?;
                }
                Operation::NodeLeave(leave_op) => {
                    apply_node_leave(&mut next, leave_op, op, new_height, params, gov)?;
                }
                Operation::DepartureEarnings(dist) => {
                    apply_departure_earnings(&mut next, dist, op, new_height)?;
                }
                Operation::ExpressBusDeposit(dep) => {
                    apply_express_bus_deposit(&mut next, dep, op, new_height, params, gov)?;
                }
                Operation::ExpressBusWithdraw(wd) => {
                    apply_express_bus_withdraw(&mut next, wd, op, new_height, params, gov)?;
                }
            }
        }

        // ---- 3a. Express Bus tracker sampling ----
        // After processing operations, sample each Express Bus tracker and compute
        // the aggregate express flow that feeds into the value index.
        let has_express = !next.express_buses.is_empty();
        if has_express {
            let mut total_express_flow: i128 = 0;
            for tracker in next.express_buses.values_mut() {
                // Record a block sample via the tracker's sampling method.
                tracker.sample(new_height);
                // Compute signal = fp_mul(net, weight) using tracked volumes.
                let signal = tracker.signal();
                total_express_flow = total_express_flow.saturating_add(signal);

                // Settle window: if the window has expired, settle and reset.
                let since_sample = new_height.saturating_sub(tracker.last_sample_height);
                if since_sample >= params.express_bus_window_blocks {
                    tracker.settle();
                }
            }
            window.express_flow = total_express_flow;
        }

        update_dao_value_indices(&mut next.daos, &dao_block_stats, params);

        // ---- 3b. GAS airdrop ----
        if new_height >= params.gas_activation_height && params.airdrop_interval_blocks > 0 {
            let interval = params.airdrop_interval_blocks;
            let since_last = new_height.saturating_sub(next.last_airdrop_height);
            if since_last >= interval {
                let amount = airdrop_amount(
                    next.gas_supply,
                    params.airdrop_base_bps,
                    next.ox_price,
                    params.ox_price_reference,
                );
                if amount > 0 {
                    let balances: BTreeMap<PublicKey, Amount> = next
                        .gas
                        .iter()
                        .map(|(key, account)| (*key, account.balance))
                        .collect();
                    let grants = distribute_airdrop(&balances, amount);
                    for (recipient, grant) in grants {
                        next.mint_gas(recipient, grant);
                    }
                    next.last_airdrop_height = new_height;
                }
            }
        }

        // ---- 3b'. Speedometer airdrop ----
        // Airdrops occur every `speedometer_airdrop_interval_blocks` blocks, sized from the
        // block's highest transaction value (not the Speedometer supply).
        next.speedometer_airdrop_amount = 0;
        if new_height >= params.speedometer_activation_height
            && params.speedometer_airdrop_interval_blocks > 0
        {
            let interval = params.speedometer_airdrop_interval_blocks;
            let since_last = new_height.saturating_sub(next.last_speedometer_airdrop_height);
            if since_last >= interval {
                let highest_tx = block_stats.highest_tx_value;
                let amount = speedometer_airdrop_amount(
                    next.speedometer_supply,
                    params.speedometer_airdrop_base_bps,
                    highest_tx,
                    params.ox_price_reference,
                    next.ox_price,
                );
                if amount > 0 {
                    let balances: BTreeMap<PublicKey, Amount> = next
                        .speedometer
                        .iter()
                        .map(|(key, account)| (*key, account.balance))
                        .collect();
                    let grants = speedometer_distribute_airdrop(&balances, amount);
                    for (recipient, grant) in grants {
                        next.mint_speedometer(recipient, grant);
                    }
                    next.last_speedometer_airdrop_height = new_height;
                    next.speedometer_airdrop_amount = amount;
                }
            }
        }

        // ---- 4. Value index ----
        let transition = compute_value(
            params,
            &window,
            next.supply,
            next.genesis_supply,
            next.value_index,
            next.generation,
        );
        if enforce_header && transition.value != block.header.value_index {
            return Err(StateError::ValueMismatch(
                transition.value.to_display(),
                block.header.value_index.to_display(),
            ));
        }
        if enforce_header && transition.generation != block.header.generation {
            return Err(StateError::GenerationMismatch(
                transition.generation,
                block.header.generation,
            ));
        }
        next.value_index = transition.value;
        next.generation = transition.generation;

        // ---- 4b. Pegged currency price tracking ----
        if new_height >= params.pegged_currency_activation_height
            && !next.pegged_currencies.is_empty()
        {
            let window = params.pegged_window_blocks;
            let mut updated: BTreeMap<Hash, PeggedCurrencyState> = BTreeMap::new();
            for (id, state) in next.pegged_currencies.iter() {
                let mut cloned = state.clone();
                let price = match cloned.config.asset {
                    PriceAsset::Ox => next.value_index.raw(),
                    PriceAsset::Gas => next.ox_price,
                    PriceAsset::DaoCurrency { dao_id } => next
                        .daos
                        .get(&dao_id)
                        .map_or(next.value_index.raw(), |d| d.value_index),
                };
                cloned.record_sample(new_height, price, window);
                updated.insert(*id, cloned);
            }
            next.pegged_currencies = updated;
        }

        // ---- 4c. Liquidity pool K recompute ----
        if new_height >= params.liquidity_pool_activation_height && !next.liquidity_pools.is_empty()
        {
            let mut updated: BTreeMap<Hash, LiquidityPoolState> = BTreeMap::new();
            for (id, state) in next.liquidity_pools.iter() {
                let mut cloned = state.clone();
                let (upper_bound, lower_bound): (u128, u128) =
                    if let Some(asset) = cloned.other_asset() {
                        next.pegged_currencies
                            .values()
                            .find(|pc| pc.config.asset == asset)
                            .map_or((FP as u128, FP as u128), |pc| {
                                (pc.bounds.upper_bound, pc.bounds.lower_bound)
                            })
                    } else {
                        // The bounds are fixed-point values: 1.0 is `FP`, not 1.
                        (FP as u128, FP as u128)
                    };
                cloned.k = compute_pool_k(
                    upper_bound,
                    lower_bound,
                    cloned.volume,
                    cloned.config.k_params.t_ref,
                );
                cloned.last_update_height = new_height;
                updated.insert(*id, cloned);
            }
            next.liquidity_pools = updated;
        }

        // ---- 5. Rebound refund ----
        if transition.rebounded {
            let exits = next.utxo.exit_outpoints();
            for outpoint in exits {
                let (ledger, Some(entry)) = next.utxo.remove(&outpoint) else {
                    continue;
                };
                let mut output = entry.output;
                output.kind = oxydome_core::tx::OutputKind::Spendable;
                output.rebound_gen = Some(transition.generation);
                next.utxo = ledger.insert(UtxoEntry::new(outpoint, output, new_height));
            }
        }

        // ---- 5a. Verification-credit auction clearing ----
        // Every `auction_interval_blocks` the pending bids are settled: the highest bid
        // on a bundle wins the right to execute it in the very next block and to collect
        // 100% of its fees. Every other bid is refunded.
        next.auction.clear(new_height, params);

        // Every auctioned transaction that was executed in this block must have been
        // paid out through an `AuctionPayout` operation.
        for (_, txid, _, _) in &auction_awards {
            if !paid_auction_awards.iter().any(|(paid, _)| paid == txid) {
                return Err(StateError::AuctionPayoutMissing(*txid));
            }
        }

        // ---- 6. Commit ----
        if enforce_header && next.supply != block.header.supply {
            return Err(StateError::SupplyMismatch(next.supply, block.header.supply));
        }
        if enforce_header && next.utxo_root() != block.header.utxo_root {
            return Err(StateError::StateRootMismatch);
        }
        let computed_root = next.state_root();
        if enforce_header && computed_root != block.header.state_root {
            return Err(StateError::StateRootMismatch);
        }
        if enforce_header && block.header.speedometer_minted != next.speedometer_minted {
            return Err(StateError::Speedometer(format!(
                "header speedometer_minted {} does not match computed {}",
                block.header.speedometer_minted, next.speedometer_minted
            )));
        }
        if enforce_header
            && block.header.speedometer_airdrop_amount != next.speedometer_airdrop_amount
        {
            return Err(StateError::Speedometer(format!(
                "header speedometer_airdrop_amount {} does not match computed {}",
                block.header.speedometer_airdrop_amount, next.speedometer_airdrop_amount
            )));
        }
        next.height = new_height;
        next.block_hash = block.hash();
        Ok(next)
    }

    fn apply_ovm_action(
        &mut self,
        action: &OvmAction,
        txid: Hash,
        tx_index: usize,
        tx: &Transaction,
        params: &ChainParams,
    ) -> Result<OvmReceipt, StateError> {
        let bytes_per_gas = params.ovm_stack_bytes_per_gas;
        let failed = |gas_used, failure| OvmReceipt {
            txid,
            gas_used,
            failure: Some(failure),
            return_data: Vec::new(),
            logs: Vec::new(),
        };
        match action {
            OvmAction::Deploy {
                code,
                stack_bytes: _,
            } => {
                oxydome_ovm::Program::decode(code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if self.contracts.contains_key(&contract_id) {
                    return Err(StateError::OvmContractCollision);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(code.len()).unwrap_or(u64::MAX));
                let stack_gas = action.required_stack_gas(bytes_per_gas);
                if stack_gas < required {
                    return Ok(failed(stack_gas, OvmFailureCode::OutOfGas));
                }
                self.contracts.insert(
                    contract_id,
                    OvmContract {
                        code: code.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(OvmReceipt {
                    txid,
                    gas_used: stack_gas,
                    failure: None,
                    return_data: contract_id.as_bytes().to_vec(),
                    logs: Vec::new(),
                })
            }
            OvmAction::DeployContract {
                artifact,
                stack_bytes: _,
            } => {
                oxydome_ovm::ContractArtifact::decode(artifact)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if self.contracts.contains_key(&contract_id) {
                    return Err(StateError::OvmContractCollision);
                }
                if self.contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(StateError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(artifact.len()).unwrap_or(u64::MAX));
                let stack_gas = action.required_stack_gas(bytes_per_gas);
                if stack_gas < required {
                    return Ok(failed(stack_gas, OvmFailureCode::OutOfGas));
                }
                self.contracts.insert(
                    contract_id,
                    OvmContract {
                        code: artifact.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(OvmReceipt {
                    txid,
                    gas_used: stack_gas,
                    failure: None,
                    return_data: contract_id.as_bytes().to_vec(),
                    logs: Vec::new(),
                })
            }
            OvmAction::Call {
                contract_id,
                arguments,
                stack_bytes: _,
            } => {
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS;
                let stack_gas = action.required_stack_gas(bytes_per_gas);
                if stack_gas < required {
                    return Ok(failed(stack_gas, OvmFailureCode::OutOfGas));
                }
                let Some(contract) = self.contracts.get(contract_id) else {
                    return Ok(failed(
                        oxydome_ovm::ACTION_INTRINSIC_GAS,
                        OvmFailureCode::ContractNotFound,
                    ));
                };
                let program = oxydome_ovm::Program::decode(&contract.code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                self.execute_program_call(
                    contract_id,
                    &program,
                    arguments,
                    action.stack_bytes(),
                    txid,
                    tx_index,
                    oxydome_ovm::ACTION_INTRINSIC_GAS,
                )
            }
            OvmAction::CallContract {
                contract_id,
                entry_point,
                arguments,
                authority_input,
                stack_bytes: _,
            } => {
                let required =
                    oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
                let stack_gas = action.required_stack_gas(bytes_per_gas);
                if stack_gas < required {
                    return Ok(failed(stack_gas, OvmFailureCode::OutOfGas));
                }
                let Some(contract) = self.contracts.get(contract_id) else {
                    return Ok(failed(
                        oxydome_ovm::ACTION_INTRINSIC_GAS,
                        OvmFailureCode::ContractNotFound,
                    ));
                };
                let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let Some(function) = artifact.function(entry_point) else {
                    return Ok(failed(required, OvmFailureCode::FunctionNotFound));
                };
                if function.inputs.len() != arguments.len() {
                    return Ok(failed(required, OvmFailureCode::ArgumentCount));
                }
                let Some(authority) = tx.inputs.get(*authority_input as usize) else {
                    return Err(StateError::BadTransaction(
                        tx_index,
                        "contract authority input index is invalid".into(),
                    ));
                };
                let authority_words = authority.owner.0.chunks_exact(8).map(|chunk| {
                    u64::from_le_bytes(chunk.try_into().expect("8-byte public-key chunk"))
                });
                let mut execution_arguments: Vec<u64> = authority_words.collect();
                execution_arguments.extend(arguments.iter().copied());
                let program = oxydome_ovm::Program::decode(&function.code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                self.execute_program_call(
                    contract_id,
                    &program,
                    &execution_arguments,
                    action.stack_bytes(),
                    txid,
                    tx_index,
                    required,
                )
            }
        }
    }

    fn execute_program_call(
        &mut self,
        contract_id: &Hash,
        program: &oxydome_ovm::Program,
        arguments: &[u64],
        stack_bytes: u64,
        txid: Hash,
        tx_index: usize,
        intrinsic_gas: u64,
    ) -> Result<OvmReceipt, StateError> {
        let bytes_per_gas = 6u64;
        let failed = |gas_used, failure| OvmReceipt {
            txid,
            gas_used,
            failure: Some(failure),
            return_data: Vec::new(),
            logs: Vec::new(),
        };
        let stack_gas_u128 =
            ((stack_bytes as u128) + (bytes_per_gas as u128) - 1) / (bytes_per_gas as u128);
        let stack_gas = stack_gas_u128 as u64;
        if (stack_gas_u128 as u64) < intrinsic_gas {
            return Ok(failed(stack_gas, OvmFailureCode::OutOfGas));
        }
        let contract = self
            .contracts
            .get(contract_id)
            .ok_or(StateError::OvmContractNotFound(*contract_id))?;

        // Build a host context with price and pool oracles from pegged currency and
        // liquidity pool state so that `LoadPriceBounds`, `PeggedConvert`,
        // `LoadPoolState`, and `PoolSwap` instructions can read current state.
        let host = self.build_host();
        let result = if host.is_some() {
            oxydome_ovm::execute_with_host(
                program,
                arguments,
                &contract.storage,
                stack_bytes,
                host.as_ref(),
            )
        } else {
            oxydome_ovm::execute(program, arguments, &contract.storage, stack_bytes)
        };
        match result {
            Ok(execution) => {
                let gas_used = stack_gas;
                self.contracts
                    .get_mut(contract_id)
                    .expect("contract exists")
                    .storage = execution.storage;
                Ok(OvmReceipt {
                    txid,
                    gas_used,
                    failure: None,
                    return_data: execution
                        .return_value
                        .map(u64::to_le_bytes)
                        .map_or_else(Vec::new, |bytes| bytes.to_vec()),
                    logs: execution
                        .logs
                        .into_iter()
                        .map(|log| OvmLog {
                            topic: log.topic,
                            value: log.value,
                        })
                        .collect(),
                })
            }
            Err(failure) => {
                let error = failure.error;
                let gas_used = stack_gas;
                let failure_code = match error {
                    oxydome_ovm::VmError::Reverted => OvmFailureCode::Reverted,
                    oxydome_ovm::VmError::OutOfGas => OvmFailureCode::OutOfGas,
                    oxydome_ovm::VmError::ArithmeticOverflow => OvmFailureCode::ArithmeticOverflow,
                    oxydome_ovm::VmError::DivisionByZero => OvmFailureCode::DivisionByZero,
                    oxydome_ovm::VmError::ArgumentCount => OvmFailureCode::ArgumentCount,
                    oxydome_ovm::VmError::MissingReturn => OvmFailureCode::MissingReturn,
                    oxydome_ovm::VmError::StorageLimitExceeded => {
                        OvmFailureCode::StorageLimitExceeded
                    }
                    oxydome_ovm::VmError::StackUnderflow => OvmFailureCode::StackUnderflow,
                    oxydome_ovm::VmError::StackOverflow => OvmFailureCode::StackOverflow,
                    oxydome_ovm::VmError::InvalidLocal => OvmFailureCode::InvalidLocal,
                    oxydome_ovm::VmError::DataStackOverflow => OvmFailureCode::StackOverflow,

                    oxydome_ovm::VmError::InvalidBytecode
                    | oxydome_ovm::VmError::ProgramTooLarge
                    | oxydome_ovm::VmError::InvalidProgram => {
                        return Err(StateError::OvmExecution(tx_index, error.to_string()))
                    }
                };
                Ok(failed(gas_used, failure_code))
            }
        }
    }
}

/// Applies minted block rewards (separate from fee-based rewards).
/// Server and master rewards are minted as LockedReward outputs.
fn apply_block_rewards(
    next: &mut ChainState,
    r: &BlockRewardDistribution,
    height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    // Validate all outputs are LockedReward and go to valid governance recipients.
    // Server rewards may only be minted to current server nodes and master rewards to current
    // masters; otherwise a producer could redirect minted rewards to arbitrary keys.
    for output in &r.server_outputs {
        if !output.kind.is_locked_reward() || !gov.contains_node(&output.recipient) {
            return Err(StateError::BadRewardRecipient(output.recipient));
        }
    }
    for output in &r.master_outputs {
        if !output.kind.is_locked_reward() || !gov.masters.contains(&output.recipient) {
            return Err(StateError::BadRewardRecipient(output.recipient));
        }
    }

    // The reward outputs are addressed by the operation **and** the height: two blocks
    // that carry the same distribution would otherwise share their outpoints and the
    // second one would overwrite the first.
    let op_id = hash_value(&(
        "oxydome-block-rewards-v1",
        &Operation::BlockRewards(r.clone()).id(),
        &height,
    ));
    let convert = height >= params.gas_activation_height && params.gas_server_fee_bps > 0;
    let mut out_idx = 0u32;

    // Apply server rewards
    for output in &r.server_outputs {
        let (ox_kept, gas_minted) = if convert {
            conversion_split_with_bps(output.amount, params.gas_server_fee_bps)
        } else {
            (output.amount, 0)
        };
        if ox_kept > 0 {
            let mut kept = output.clone();
            kept.amount = ox_kept;
            let outpoint = OutPoint::new(op_id, out_idx);
            next.utxo = next.utxo.insert(UtxoEntry::new(outpoint, kept, height));
        }
        if gas_minted > 0 {
            // Burn the converted Ox and mint the GAS fuel to the same recipient.
            next.supply = next.supply.saturating_sub(gas_minted);
            next.mint_gas(output.recipient, gas_minted);
        }
        out_idx += 1;
    }

    // Verification credits: server nodes participating in block rewards earn
    // (non-financial) credits for the work they did verifying this block. Credits are
    // non-transferable and are spent in the verification-credit auction.
    for output in &r.server_outputs {
        next.auction
            .earn(&output.recipient, params.verification_credit_per_block, height);
    }

    // Apply master rewards
    for output in &r.master_outputs {
        let (ox_kept, gas_minted) = if convert {
            conversion_split_with_bps(output.amount, params.gas_server_fee_bps)
        } else {
            (output.amount, 0)
        };
        if ox_kept > 0 {
            let mut kept = output.clone();
            kept.amount = ox_kept;
            let outpoint = OutPoint::new(op_id, out_idx);
            next.utxo = next.utxo.insert(UtxoEntry::new(outpoint, kept, height));
        }
        if gas_minted > 0 {
            next.supply = next.supply.saturating_sub(gas_minted);
            next.mint_gas(output.recipient, gas_minted);
        }
        out_idx += 1;
    }

    // Update total supply with minted rewards
    let total_minted: Amount = r
        .server_outputs
        .iter()
        .chain(r.master_outputs.iter())
        .map(|o| o.amount)
        .sum();
    next.supply = next.supply.saturating_add(total_minted);

    Ok(())
}

/// Whether the receipts contain a liquidity-pool swap for `txid`.
///
/// The OVM emits a dedicated log for every pool swap, so a swap transaction is
/// recognisable from its receipt alone. The verification-credit auction only accepts
/// swaps.
pub fn receipt_performed_pool_swap_in(receipts: &[OvmReceipt], txid: &Hash) -> bool {
    receipts
        .iter()
        .filter(|receipt| receipt.txid == *txid)
        .any(|receipt| {
            receipt
                .logs
                .iter()
                .any(|log| log.topic == oxydome_core::POOL_SWAP_LOG_TOPIC)
        })
}

/// The outpoint under which the auction winner's fee reward is recorded.
///
/// Derived from the executed transaction id so that it can never collide with a
/// transaction output (which is indexed from zero) and is identical on every node.
pub fn auction_reward_outpoint(txid: &Hash) -> Hash {
    oxydome_crypto::hash_value(&("oxydome-auction-reward-v1", txid))
}

fn apply_rewards(
    next: &mut ChainState,
    r: &RewardDistribution,
    total_fees: Amount,
    gov: &GovernanceSet,
    params: &ChainParams,
    height: u64,
) -> Result<(), StateError> {
    if r.total() != total_fees {
        return Err(StateError::RewardTotalMismatch(r.total(), total_fees));
    }
    let master_share = total_fees.saturating_mul(params.fee_master_bps as u128) / 10_000;
    let node_share = total_fees.saturating_sub(master_share);
    if r.master_total() != master_share || r.node_total() != node_share {
        return Err(StateError::RewardSplit);
    }
    for output in &r.master_outputs {
        if !output.kind.is_locked_reward() || !gov.contains_master(&output.recipient) {
            return Err(StateError::BadRewardRecipient(output.recipient));
        }
    }
    for output in &r.node_outputs {
        if !output.kind.is_locked_reward() || !gov.contains_node(&output.recipient) {
            return Err(StateError::BadRewardRecipient(output.recipient));
        }
    }
    // The reward outputs are addressed by the operation **and** the height: two blocks
    // that collect the same fees would otherwise share their outpoints and the second
    // one would overwrite the first.
    let op_id = hash_value(&(
        "oxydome-fee-rewards-v1",
        &Operation::Rewards(r.clone()).id(),
        &height,
    ));
    let convert = height >= params.gas_activation_height && params.gas_server_fee_bps > 0;
    let mut out_idx = 0u32;
    for output in &r.master_outputs {
        let outpoint = OutPoint::new(op_id, out_idx);
        next.utxo = next
            .utxo
            .insert(UtxoEntry::new(outpoint, output.clone(), height));
        out_idx += 1;
    }
    for output in &r.node_outputs {
        let (ox_kept, gas_minted) = if convert {
            conversion_split_with_bps(output.amount, params.gas_server_fee_bps)
        } else {
            (output.amount, 0)
        };
        if ox_kept > 0 {
            let mut kept = output.clone();
            kept.amount = ox_kept;
            let outpoint = OutPoint::new(op_id, out_idx);
            next.utxo = next.utxo.insert(UtxoEntry::new(outpoint, kept, height));
        }
        if gas_minted > 0 {
            // Burn the converted Ox and mint the GAS fuel to the same recipient.
            next.supply = next.supply.saturating_sub(gas_minted);
            next.mint_gas(output.recipient, gas_minted);
        }
        out_idx += 1;
    }
    Ok(())
}

/// Computes the total held "earnings" balance of `node` as a list of `TokenAmount` entries.
///
/// Currently this aggregates all on-chain UTXO entries owned by `node` (all balances held by
/// the departing node), so the redistribution applies to every asset the node held. This matches
/// the requirement that 100 tokenA and 1000 tokenB held by the disconnecting node are both
/// subject to the half-redistribution rule.
fn held_earnings(next: &ChainState, node: &PublicKey) -> Vec<TokenAmount> {
    let mut balances: BTreeMap<Option<Hash>, Amount> = BTreeMap::new();
    for entry in next.utxo.to_map().values() {
        if entry.output.recipient == *node {
            let asset_id = match &entry.output.kind {
                crate::OutputKind::Spendable => None,
                crate::OutputKind::LockedReward => None,
                crate::OutputKind::ExitReserve { .. } => None,
                crate::OutputKind::DaoTreasury { .. } => None,
                crate::OutputKind::OhmTreasury { ohm_id } => Some(*ohm_id),
                crate::OutputKind::BusReceipt { asset, .. } => {
                    if is_ox_asset(asset) {
                        None
                    } else {
                        Some(Hash::zero())
                    }
                }
                crate::OutputKind::WrappedToken { .. } => None,
            };
            if let Some(asset_id) = asset_id {
                let cur = balances.entry(Some(asset_id)).or_insert(0);
                *cur = cur.saturating_add(entry.output.amount);
            } else {
                let cur = balances.entry(None).or_insert(0);
                *cur = cur.saturating_add(entry.output.amount);
            }
        }
    }
    balances
        .into_iter()
        .map(|(asset_id, amount)| TokenAmount { asset_id, amount })
        .collect()
}

/// Removes all UTXO entries owned by `departed` from the ledger, returning the total removed
/// per asset. Used to confiscate the departing node's held earnings during redistribution.
fn remove_held_earnings(next: &mut ChainState, departed: &[PublicKey]) -> Vec<TokenAmount> {
    let entries = next.utxo.to_map();
    let mut totals: BTreeMap<Option<Hash>, Amount> = BTreeMap::new();
    let mut to_remove: Vec<OutPoint> = Vec::new();
    for (outpoint, entry) in &entries {
        if departed.iter().any(|d| entry.output.recipient == *d) {
            let asset_id = match &entry.output.kind {
                crate::OutputKind::Spendable => None,
                crate::OutputKind::LockedReward => None,
                crate::OutputKind::ExitReserve { .. } => None,
                crate::OutputKind::DaoTreasury { .. } => None,
                crate::OutputKind::OhmTreasury { ohm_id } => Some(*ohm_id),
                crate::OutputKind::BusReceipt { asset, .. } => {
                    if is_ox_asset(asset) {
                        None
                    } else {
                        Some(Hash::zero())
                    }
                }
                crate::OutputKind::WrappedToken { .. } => None,
            };
            if let Some(asset_id) = asset_id {
                let cur = totals.entry(Some(asset_id)).or_insert(0);
                *cur = cur.saturating_add(entry.output.amount);
            } else {
                let cur = totals.entry(None).or_insert(0);
                *cur = cur.saturating_add(entry.output.amount);
            }
            to_remove.push(entry.outpoint.clone());
        }
    }
    for outpoint in to_remove {
        next.utxo = next.utxo.remove(&outpoint).0;
    }
    totals
        .into_iter()
        .map(|(asset_id, amount)| TokenAmount { asset_id, amount })
        .collect()
}

/// Applies a graceful node leave operation.
///
/// Requires server-node (for server leaves) or master (for master leaves) approval quorum and
/// validates the departing node's signature. It then computes the held earnings and performs the
/// on-chain earnings redistribution (half to each node group) via `apply_departure_earnings`.
fn apply_node_leave(
    next: &mut ChainState,
    leave_op: &crate::NodeLeaveRequest,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    let id = op.proposal_id();
    if !verify(&leave_op.node, &id.0, &leave_op.node_signature) {
        return Err(StateError::BadNodeLeaveSignature);
    }
    match leave_op.node_kind {
        crate::NodeKind::Server => {
            let approvals = count_node_approvals(op, gov);
            let threshold = gov.node_threshold(params);
            if approvals < threshold {
                return Err(StateError::NodeApprovalMissing(approvals, threshold));
            }
        }
        crate::NodeKind::Master => {
            let approvals = count_master_approvals(op, gov);
            let threshold = gov.master_threshold(params);
            if approvals < threshold {
                return Err(StateError::MasterApprovalMissing(approvals, threshold));
            }
        }
    }

    // Only nodes that are current members may leave.
    let is_member = match leave_op.node_kind {
        crate::NodeKind::Server => gov.contains_node(&leave_op.node),
        crate::NodeKind::Master => gov.contains_master(&leave_op.node),
    };
    if !is_member {
        return Err(StateError::BadNodeLeaveSignature);
    }

    // Compute held earnings and perform the earnings redistribution on-chain.
    let total_held = held_earnings(next, &leave_op.node);
    let take_bps = params.departure_take_bps.unwrap_or(oxydome_rewards::DEPARTURE_TAKE_BPS);
    let dist = compute_departure_distribution(
        std::slice::from_ref(&leave_op.node),
        &total_held,
        &gov.nodes,
        &gov.masters,
        take_bps,
        new_height,
        DepartureType::Graceful,
    );
    apply_departure_earnings(next, &dist, op, new_height)?;
    Ok(())
}

/// Computes the on-chain redistribution for a set of departed nodes.
///
/// Half of each departed node's held earnings (per asset) is taken and split equally between
/// the two connected node groups (servers and masters). The remainder of the held earnings is
/// retained as locked rewards for the departing node(s) (subject to a cooling-off period and the
/// standard withdrawal flow).
fn compute_departure_distribution(
    departed_nodes: &[PublicKey],
    total_held: &[TokenAmount],
    servers: &[PublicKey],
    masters: &[PublicKey],
    take_bps: u32,
    block_height: u64,
    departure_type: DepartureType,
) -> DepartureEarningsDistribution {
    oxydome_rewards::compute_departure_earnings(
        departed_nodes,
        total_held,
        servers,
        masters,
        take_bps,
        block_height,
        departure_type,
    )
}

/// Applies an `Operation::DepartureEarnings` to state: mints the redistributed locked rewards
/// to the connected nodes and records the distribution on the `departures` history.
fn apply_departure_earnings(
    next: &mut ChainState,
    dist: &crate::DepartureEarningsDistribution,
    op: &Operation,
    new_height: u64,
) -> Result<(), StateError> {
    let _ = op;
    let op_id_outputs = hash_value(&(
        &dist.departed_nodes,
        dist.block_height,
        dist.departure_type,
    ));
    let mut out_idx = 0u32;
    for (recipient, tokens) in &dist.server_distributions {
        for t in tokens {
            if t.amount > 0 {
                let outpoint = OutPoint::new(op_id_outputs, out_idx);
                next.utxo = next.utxo.insert(UtxoEntry::new(
                    outpoint,
                    TxOutput::locked_reward(t.amount, *recipient),
                    new_height,
                ));
                out_idx += 1;
            }
        }
    }
    for (recipient, tokens) in &dist.master_distributions {
        for t in tokens {
            if t.amount > 0 {
                let outpoint = OutPoint::new(op_id_outputs, out_idx);
                next.utxo = next.utxo.insert(UtxoEntry::new(
                    outpoint,
                    TxOutput::locked_reward(t.amount, *recipient),
                    new_height,
                ));
                out_idx += 1;
            }
        }
    }
    next.departures.push(dist.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{
        compute_ohm_fee_split, GenesisAllocation, GenesisConfig, MasterApproval, OhmContext,
        OhmOutput, Operation, OvmAction, RewardDistribution, TimerAction, TimerAsset, TimerBet,
        TimerDirection, TimerOperation, Transaction, TxOutput, OHM_POLICY_VERSION,
    };
    use oxydome_crypto::KeyPair;
    use oxydome_rewards::split_fees;
    use oxydome_treasury::{approve_mint, mint_proposal};

    fn setup() -> (
        ChainState,
        Block,
        GovernanceSet,
        ChainParams,
        KeyPair,
        KeyPair,
        KeyPair,
    ) {
        let master = KeyPair::from_seed(&[1u8; 32]);
        let node = KeyPair::from_seed(&[2u8; 32]);
        let user = KeyPair::from_seed(&[3u8; 32]);
        let mut params = ChainParams::default_local();
        params.block_window = 10;
        params.rebound_lock_blocks = 3;
        // Disable GAS by default so existing tests exercise the legacy OVM fee path.
        params.gas_activation_height = u64::MAX;
        let config = GenesisConfig {
            params: params.clone(),
            allocations: vec![
                GenesisAllocation {
                    recipient: node.public(),
                    amount: 10_000,
                },
                GenesisAllocation {
                    recipient: user.public(),
                    amount: 999_990_000,
                },
            ],
            masters: vec![master.public()],
            nodes: vec![node.public()],
            timestamp: 0,
        };
        let (state, block, gov) = ChainState::genesis(&config).unwrap();
        (state, block, gov, params, master, node, user)
    }

    fn spend_from(state: &ChainState, owner: &PublicKey) -> (OutPoint, Amount) {
        let e = state
            .utxo
            .iter()
            .find(|e| e.output.recipient == *owner && e.output.kind.is_spendable())
            .unwrap();
        (e.outpoint, e.output.amount)
    }

    #[test]
    fn build_and_apply_block() {
        let (state, genesis, gov, params, _master, node, user) = setup();
        assert_eq!(state.utxo.total(), state.supply);
        assert_eq!(genesis.header.state_root, state.utxo.root());

        let (outpoint, amount) = spend_from(&state, &node.public());
        let fee = 100;
        let mut tx = Transaction::new_unsigned(
            vec![(outpoint, node.public())],
            vec![TxOutput::spendable(amount - fee, user.public())],
            fee,
        );
        tx.sign_input(0, &node);

        let rewards = split_fees(fee, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![tx],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1, None)
            .unwrap();

        let after = state.apply_block(&block, &gov, &params).unwrap();
        assert_eq!(after.supply, params.genesis_supply);
        assert_eq!(after.utxo.total(), after.supply);
        assert!(after.value_index.raw() >= params.initial_value_index);
        assert_eq!(after.height, 1);
    }

    #[test]
    fn ohm_update_settles_fees_with_server_fee_bps() {
        let (mut state, _genesis, gov, params, _master, node, _user) = setup();
        let supply_before = state.supply;
        let utxo_before = state.utxo.total();

        let maintainer = KeyPair::from_seed(&[42u8; 32]);
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: maintainer.public(),
            name: "tenant".to_string(),
            genesis_supply: 1_000,
            block_window: 10,
        };
        let mut create = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Create {
                policy_bytes: policy.encode().unwrap(),
                genesis_outputs: vec![OhmOutput {
                    amount: 1_000,
                    recipient: maintainer.public(),
                    lock: false,
                }],
            },
        );
        create.sign(&maintainer);
        let ohm_id = create.created_ohm_id().unwrap();
        let create_id = create.id();
        apply_ohm_operation(
            &mut state,
            &create,
            create_id,
            1,
            &params,
            &gov,
            node.public(),
        )
        .unwrap();
        assert_eq!(state.ohm_states[&ohm_id].treasury_ox, 0);

        // Anchor a private OHM block whose transactions paid a 1_000 fee.
        let fee_total: Amount = 1_000;
        let prev_hash = state.ohm_states[&ohm_id].block_hash;
        let mut update = OhmOperation::new_unsigned(
            maintainer.public(),
            OhmAction::Update {
                ohm_id,
                context: OhmContext {
                    ohm_height: 1,
                    ohm_prev_hash: prev_hash,
                    ohm_timestamp: 7,
                    ohm_state_root: Hash::from([9u8; 64]),
                },
                block_hash: Hash::from([8u8; 64]),
                fee_total,
            },
        );
        update.sign(&maintainer);
        let update_id = update.id();
        apply_ohm_operation(
            &mut state,
            &update,
            update_id,
            2,
            &params,
            &gov,
            node.public(),
        )
        .unwrap();

        // The 40/60 split is governed solely by `OHM_SERVER_FEE_BPS`.
        let (expected_server, expected_treasury) = compute_ohm_fee_split(fee_total);
        assert_eq!(expected_server, 400);
        assert_eq!(expected_treasury, 600);

        // The server share is minted as participation-weighted `LockedReward` outputs. With a
        // single Ox server node it is exactly the OHM server share.
        let server_reward: Amount = state
            .utxo
            .iter()
            .filter(|e| e.output.kind.is_locked_reward() && e.output.recipient == node.public())
            .map(|e| e.output.amount)
            .sum();
        assert_eq!(server_reward, expected_server);

        // The remainder is credited to the OHM treasury and tracked in the OHM state.
        assert_eq!(state.ohm_states[&ohm_id].treasury_ox, expected_treasury);
        assert_eq!(state.ohm_states[&ohm_id].fees_paid, fee_total);
        assert_eq!(state.ohm_states[&ohm_id].current_height, 1);

        // Value is conserved: exactly the fee total is minted and the UTXO set backs the supply.
        assert_eq!(state.supply, supply_before + fee_total);
        assert_eq!(state.utxo.total(), utxo_before + fee_total);
        assert_eq!(state.utxo.total(), state.supply);
    }

    #[test]
    fn rejects_a_block_with_an_unexpected_execution_version() {
        let (state, _, gov, params, _master, node, _user) = setup();
        let mut block = state
            .build_block(&gov, &params, Vec::new(), Vec::new(), node.public(), 1, None)
            .unwrap();
        block.header.execution_version = oxydome_core::LEGACY_EXECUTION_VERSION;
        assert!(matches!(
            state.apply_block(&block, &gov, &params),
            Err(StateError::ExecutionVersionMismatch)
        ));
    }

    #[test]
    fn rejects_duplicate_operations() {
        let (state, _genesis, gov, params, _master, node, _user) = setup();
        let mint = Operation::Mint(oxydome_core::TreasuryMint {
            amount: 1_000,
            recipient: node.public(),
            nonce: 0,
            approvals: Vec::new(),
        });
        let result = state.build_block(
            &gov,
            &params,
            Vec::new(),
            vec![mint.clone(), mint],
            node.public(),
            1, None);
        assert!(matches!(result, Err(StateError::DuplicateOperation)));
    }

    #[test]
    fn rejects_block_rewards_to_non_governance_recipients() {
        let (state, _genesis, gov, params, _master, node, user) = setup();
        let reward = Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
            // `user` is neither a current server node nor a master, so the minted reward must
            // be rejected.
            server_outputs: vec![TxOutput::locked_reward(1_000, user.public())],
            master_outputs: Vec::new(),
        });
        let result = state.build_block(&gov, &params, Vec::new(), vec![reward], node.public(), 1, None);
        assert!(matches!(
            result,
            Err(StateError::BadRewardRecipient(recipient)) if recipient == user.public()
        ));
    }

    #[test]
    fn rejects_a_self_declared_epoch_change() {
        let (state, _genesis, gov, params, _master, node, _user) = setup();
        let mut block = state
            .build_block(&gov, &params, Vec::new(), Vec::new(), node.public(), 1, None)
            .unwrap();
        block.header.epoch = block.header.epoch + 1;
        assert!(matches!(
            state.apply_block(&block, &gov, &params),
            Err(StateError::EpochChange(0, 1))
        ));
    }

    #[test]
    fn mint_replay_is_rejected_and_nonce_distinguishes_proposals() {
        let (state, _genesis, gov, params, master, node, user) = setup();
        let mut mint = mint_proposal(1_000, user.public(), 0);
        approve_mint(&mut mint, &master);

        let block1 = state
            .build_block(
                &gov,
                &params,
                Vec::new(),
                vec![Operation::Mint(mint.clone())],
                node.public(),
                1, None)
            .unwrap();
        let state1 = state.apply_block(&block1, &gov, &params).unwrap();
        assert_eq!(state1.supply, params.genesis_supply + 1_000);
        assert_eq!(state1.epoch_minted, 1_000);
        assert_eq!(state1.utxo.total(), state1.supply);

        // Replaying the exact same proposal (same id, therefore same outpoint) must be rejected
        // instead of minting the 1_000 again against a single UTXO entry.
        let replay = state1.build_block(
            &gov,
            &params,
            Vec::new(),
            vec![Operation::Mint(mint)],
            node.public(),
            2, None);
        assert!(matches!(replay, Err(StateError::AlreadyMinted)));

        // A fresh nonce produces a distinct proposal id/outpoint and mints once more.
        let mut mint2 = mint_proposal(1_000, user.public(), 1);
        approve_mint(&mut mint2, &master);
        let block2 = state1
            .build_block(
                &gov,
                &params,
                Vec::new(),
                vec![Operation::Mint(mint2)],
                node.public(),
                2, None)
            .unwrap();
        let state2 = state1.apply_block(&block2, &gov, &params).unwrap();
        assert_eq!(state2.supply, params.genesis_supply + 2_000);
        assert_eq!(state2.epoch_minted, 2_000);
        assert_eq!(state2.utxo.total(), state2.supply);
    }

    #[test]
    fn deploys_and_executes_ovm_with_committed_state_root() {
        let (state, _, gov, params, _master, node, _user) = setup();
        let (genesis_outpoint, amount) = spend_from(&state, &node.public());
        let program = oxydome_ovm::Program {
            argument_count: 1,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Add,
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let deploy_outputs = vec![TxOutput::spendable(amount - 1, node.public())];
        let deploy_fee = oxydome_core::transfer_fee(&deploy_outputs).unwrap();
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            deploy_outputs,
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::Deploy {
            code: program,
            stack_bytes: 1000,
        });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());

        let deploy_outpoint = OutPoint::new(deploy.txid(), 0);
        let call_outputs = vec![TxOutput::spendable(amount - 2, node.public())];
        let call_fee = oxydome_core::transfer_fee(&call_outputs).unwrap();
        let mut call = Transaction::new_unsigned(
            vec![(deploy_outpoint, node.public())],
            call_outputs,
            call_fee,
        );
        call.ovm_action = Some(OvmAction::Call {
            contract_id,
            arguments: vec![5],
            stack_bytes: 100,
        });
        call.sign_input(0, &node);
        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()], &params)
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1, None)
            .unwrap();
        assert_eq!(block.fee_total(), fees);

        let next = state.apply_block(&block, &gov, &params).unwrap();
        assert_eq!(next.contracts[&contract_id].storage.get(&0), Some(&5));
        assert_eq!(next.ovm_receipts.len(), 2);
        assert_eq!(next.ovm_receipts[1].return_data, 5u64.to_le_bytes());
        assert_eq!(next.ovm_receipts[0].failure, None);
        assert_eq!(next.ovm_receipts[1].failure, None);
        assert_ne!(next.state_root(), next.utxo_root());
        assert_eq!(block.header.utxo_root, next.utxo_root());
        assert_eq!(block.header.state_root, next.state_root());
    }

    #[test]
    fn contract_dispatch_uses_the_signed_authority_input() {
        let (state, _, gov, params, _master, node, _user) = setup();
        let (genesis_outpoint, amount) = spend_from(&state, &node.public());
        let code = oxydome_ovm::Program {
            argument_count: oxydome_ovm::AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let artifact = oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "caller".into(),
                inputs: Vec::new(),
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap();
        let deploy_gas = 5_000;
        let deploy_outputs = vec![TxOutput::spendable(amount - 1, node.public())];
        let deploy_fee = oxydome_core::transfer_fee(&deploy_outputs).unwrap();
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            deploy_outputs,
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::DeployContract {
            artifact,
            stack_bytes: deploy_gas,
        });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());

        let call_gas = 1_000;
        let call_outputs = vec![TxOutput::spendable(amount - 2, node.public())];
        let call_fee = oxydome_core::transfer_fee(&call_outputs).unwrap();
        let mut call = Transaction::new_unsigned(
            vec![(OutPoint::new(deploy.txid(), 0), node.public())],
            call_outputs,
            call_fee,
        );
        call.ovm_action = Some(OvmAction::CallContract {
            contract_id,
            entry_point: "caller".into(),
            arguments: Vec::new(),
            authority_input: 0,
            stack_bytes: call_gas,
        });
        call.sign_input(0, &node);

        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()], &params)
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1, None)
            .unwrap();
        let next = state.apply_block(&block, &gov, &params).unwrap();
        let expected = u64::from_le_bytes(node.public().0[..8].try_into().unwrap());
        assert_eq!(next.ovm_receipts[1].failure, None);
        assert_eq!(next.ovm_receipts[1].return_data, expected.to_le_bytes());
    }

    #[test]
    fn bounds_aggregate_declared_ovm_gas_before_preview() {
        let (state, _, _, params, _master, node, _user) = setup();
        let code = oxydome_ovm::Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::Push(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let txs = (0..11u128)
            .map(|index| {
                let outputs = vec![TxOutput::spendable(index + 1, node.public())];
                let fee = oxydome_core::transfer_fee(&outputs).unwrap();
                let mut tx = Transaction::new_unsigned(Vec::new(), outputs, fee);
                tx.ovm_action = Some(OvmAction::Deploy {
                    code: code.clone(),
                    stack_bytes: 1_000_000,
                });
                tx
            })
            .collect::<Vec<_>>();
        assert_eq!(state.settled_fee_total(&txs, &params), Ok(11));
    }

    #[test]
    fn reverted_call_is_a_receipt_and_rolls_back_storage_and_logs() {
        let (state, _, gov, params, _master, node, _user) = setup();
        let (genesis_outpoint, amount) = spend_from(&state, &node.public());
        let code = oxydome_ovm::Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::Push(9),
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::Push(1),
                oxydome_ovm::Instruction::Emit(7),
                oxydome_ovm::Instruction::Revert,
            ],
        }
        .encode()
        .unwrap();
        let stack_bytes = 1_000u64;
        let deploy_outputs = vec![TxOutput::spendable(amount - 1, node.public())];
        let deploy_fee = oxydome_core::transfer_fee(&deploy_outputs).unwrap();
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            deploy_outputs,
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::Deploy { code, stack_bytes });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let (deploy_output, output_amount) =
            (OutPoint::new(deploy.txid(), 0), deploy.outputs[0].amount);

        let call_gas = 1_000u64;
        let call_outputs = vec![TxOutput::spendable(output_amount - 1, node.public())];
        let call_fee = oxydome_core::transfer_fee(&call_outputs).unwrap();
        let mut call =
            Transaction::new_unsigned(vec![(deploy_output, node.public())], call_outputs, call_fee);
        call.ovm_action = Some(OvmAction::Call {
            contract_id,
            arguments: Vec::new(),
            stack_bytes: call_gas,
        });
        call.sign_input(0, &node);
        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()], &params)
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1, None)
            .unwrap();
        let next = state.apply_block(&block, &gov, &params).unwrap();

        assert_eq!(next.ovm_receipts[1].failure, Some(OvmFailureCode::Reverted));
        assert_eq!(next.ovm_receipts[1].logs, Vec::new());
        assert!(next.contracts[&contract_id].storage.is_empty());
        assert!(next.ovm_receipts[1].gas_used <= call_gas);
    }

    #[test]
    fn double_spend_rejected() {
        let (state, _genesis, gov, params, _master, node, user) = setup();
        let (outpoint, amount) = spend_from(&state, &node.public());
        let mut tx1 = Transaction::new_unsigned(
            vec![(outpoint, node.public())],
            vec![TxOutput::spendable(amount - 100, user.public())],
            100,
        );
        tx1.sign_input(0, &node);
        let rewards = split_fees(100, &params, &gov.masters, &[(node.public(), 1)]);
        let b1 = state
            .build_block(
                &gov,
                &params,
                vec![tx1],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1, None)
            .unwrap();
        let after = state.apply_block(&b1, &gov, &params).unwrap();

        // Reusing the same outpoint must fail.
        let mut tx2 = Transaction::new_unsigned(
            vec![(outpoint, node.public())],
            vec![TxOutput::spendable(amount - 100, user.public())],
            100,
        );
        tx2.sign_input(0, &node);
        let rewards2 = split_fees(100, &params, &gov.masters, &[(node.public(), 1)]);
        let err = after.build_block(
            &gov,
            &params,
            vec![tx2],
            vec![Operation::Rewards(rewards2)],
            node.public(),
            2, None);
        assert!(matches!(err, Err(StateError::MissingInput(_))));
    }

    #[test]
    fn unauthorized_mint_rejected() {
        let (state, _genesis, gov, params, _master, node, user) = setup();
        let mint = oxydome_core::TreasuryMint {
            amount: 1000,
            recipient: user.public(),
            nonce: 0,
            approvals: Vec::new(),
        };
        let err = state.build_block(
            &gov,
            &params,
            Vec::new(),
            vec![Operation::Mint(mint)],
            node.public(),
            1, None);
        assert!(matches!(err, Err(StateError::MasterApprovalMissing(0, _))));
    }

    #[test]
    fn reward_split_must_match_fees() {
        let (state, _genesis, gov, params, _master, node, user) = setup();
        let (outpoint, amount) = spend_from(&state, &node.public());
        let mut tx = Transaction::new_unsigned(
            vec![(outpoint, node.public())],
            vec![TxOutput::spendable(amount - 100, user.public())],
            100,
        );
        tx.sign_input(0, &node);
        // Wrong split: give everything to the node.
        let bad = RewardDistribution {
            master_outputs: Vec::new(),
            node_outputs: vec![TxOutput::locked_reward(100, node.public())],
        };
        let err = state.build_block(
            &gov,
            &params,
            vec![tx],
            vec![Operation::Rewards(bad)],
            node.public(),
            1, None);
        assert!(matches!(err, Err(StateError::RewardSplit)));
    }

    #[test]
    fn timer_create_requires_master_approval() {
        let (state, _genesis, gov, params, _master, node, _user) = setup();
        let create = TimerOperation::new_unsigned(
            node.public(),
            0,
            TimerAction::Create {
                asset: TimerAsset::Ox,
                direction: TimerDirection::Up,
                duration_blocks: 100,
                price_anchor: 1_000_000,
            },
        );
        let op = Operation::Timer(create);
        let result = state.build_block(&gov, &params, Vec::new(), vec![op], node.public(), 1, None);
        assert!(matches!(
            result,
            Err(StateError::TimerApprovalMissing(0, _))
        ));
    }

    #[test]
    fn timer_create_adds_timer_with_master_approval() {
        let (state, _genesis, gov, params, master, node, _user) = setup();
        let create = TimerOperation::create_timer(
            &master,
            0,
            TimerAsset::Ox,
            TimerDirection::Up,
            100,
            1_000_000,
            &[],
        );
        // Approve with the same master (threshold is 1 for a single master).
        let mut create = create;
        let proposal_id = Operation::Timer(create.clone()).proposal_id();
        create.approvals.push(MasterApproval {
            master: master.public(),
            proposal: proposal_id,
            signature: master.sign(&proposal_id.0),
        });

        let op = Operation::Timer(create);
        let block = state
            .build_block(&gov, &params, Vec::new(), vec![op], node.public(), 1, None)
            .unwrap();
        let after = state.apply_block(&block, &gov, &params).unwrap();
        assert_eq!(after.timers.len(), 1);
        let timer = after.timers.values().next().unwrap();
        assert_eq!(timer.asset, TimerAsset::Ox);
        assert_eq!(timer.direction, TimerDirection::Up);
        assert_eq!(timer.price_anchor, 1_000_000);
        assert!(!timer.resolved);
        assert_eq!(timer.expiry_height, 101);
    }

    #[test]
    fn timer_bet_is_accepted_on_active_timer() {
        let (state, _genesis, gov, params, master, node, user) = setup();

        // Create a timer
        let mut create = TimerOperation::create_timer(
            &master,
            0,
            TimerAsset::Ox,
            TimerDirection::Up,
            100,
            1_000_000,
            &[],
        );
        let proposal_id = Operation::Timer(create.clone()).proposal_id();
        create.approvals.push(MasterApproval {
            master: master.public(),
            proposal: proposal_id,
            signature: master.sign(&proposal_id.0),
        });
        let create_op = Operation::Timer(create);
        let block = state
            .build_block(&gov, &params, Vec::new(), vec![create_op], node.public(), 1, None)
            .unwrap();
        let state1 = state.apply_block(&block, &gov, &params).unwrap();

        let timer_id = *state1.timers.keys().next().unwrap();

        // Place a bet
        let mut bet = TimerBet::new_unsigned(timer_id, user.public(), 1000, TimerDirection::Up, 1);
        bet.sign(&user);
        let mut bet_op =
            TimerOperation::new_unsigned(user.public(), 0, TimerAction::Bet { bet: bet.clone() });
        bet_op.sign(&user);
        let bet_op = Operation::Timer(bet_op);
        let block2 = state1
            .build_block(&gov, &params, Vec::new(), vec![bet_op], node.public(), 2, None)
            .unwrap();
        let state2 = state1.apply_block(&block2, &gov, &params).unwrap();
        let timer = state2.timers.get(&timer_id).unwrap();
        assert_eq!(timer.bets.len(), 1);
        assert_eq!(timer.bets[&bet.bet_id].amount, 1000);
    }

    #[test]
    fn timer_resolve_and_claim_winning_bet() {
        let (state, _genesis, gov, params, master, node, user) = setup();

        // Create a timer with Up direction
        let mut create = TimerOperation::create_timer(
            &master,
            0,
            TimerAsset::Ox,
            TimerDirection::Up,
            100,
            1_000_000,
            &[],
        );
        let proposal_id = Operation::Timer(create.clone()).proposal_id();
        create.approvals.push(MasterApproval {
            master: master.public(),
            proposal: proposal_id,
            signature: master.sign(&proposal_id.0),
        });
        let create_op = Operation::Timer(create);
        let block = state
            .build_block(&gov, &params, Vec::new(), vec![create_op], node.public(), 1, None)
            .unwrap();
        let state1 = state.apply_block(&block, &gov, &params).unwrap();

        let timer_id = *state1.timers.keys().next().unwrap();

        // Place an Up bet (should win when price increases)
        let mut bet = TimerBet::new_unsigned(timer_id, user.public(), 1000, TimerDirection::Up, 1);
        bet.sign(&user);
        let bet_action = TimerAction::Bet { bet: bet.clone() };
        let mut bet_op = TimerOperation::new_unsigned(user.public(), 0, bet_action);
        bet_op.sign(&user);
        let bet_op = Operation::Timer(bet_op);
        let block2 = state1
            .build_block(&gov, &params, Vec::new(), vec![bet_op], node.public(), 2, None)
            .unwrap();
        let state2 = state1.apply_block(&block2, &gov, &params).unwrap();

        // Resolve the timer: price went up (1_500_000 > 1_000_000), so Up wins
        let resolve_action = TimerAction::Resolve {
            timer_id,
            expiry_price: 1_500_000,
        };
        let mut resolve_op = TimerOperation::new_unsigned(master.public(), 0, resolve_action);
        resolve_op.sign(&master);
        let resolve_prop_id = Operation::Timer(resolve_op.clone()).proposal_id();
        resolve_op.approvals.push(MasterApproval {
            master: master.public(),
            proposal: resolve_prop_id,
            signature: master.sign(&resolve_prop_id.0),
        });
        let resolve_op = Operation::Timer(resolve_op);
        let block3 = state2
            .build_block(
                &gov,
                &params,
                Vec::new(),
                vec![resolve_op],
                node.public(),
                101, None)
            .unwrap();
        let state3 = state2.apply_block(&block3, &gov, &params).unwrap();

        let timer = state3.timers.get(&timer_id).unwrap();
        assert!(timer.resolved);
        assert_eq!(timer.winning_direction, Some(TimerDirection::Up));
        assert!(timer.accumulated_track > 0);
    }

    #[test]
    fn timer_resolve_rejects_non_master() {
        let (state, _genesis, gov, params, master, node, _user) = setup();

        // Create timer with the actual master
        let mut create = TimerOperation::create_timer(
            &master,
            0,
            TimerAsset::Ox,
            TimerDirection::Up,
            100,
            1_000_000,
            &[],
        );
        let proposal_id = Operation::Timer(create.clone()).proposal_id();
        create.approvals.push(MasterApproval {
            master: master.public(),
            proposal: proposal_id,
            signature: master.sign(&proposal_id.0),
        });
        let create_op = Operation::Timer(create);
        let block = state
            .build_block(&gov, &params, Vec::new(), vec![create_op], node.public(), 1, None)
            .unwrap();
        let state1 = state.apply_block(&block, &gov, &params).unwrap();

        let timer_id = *state1.timers.keys().next().unwrap();

        // Resolve attempt from non-master (user) — should be rejected for missing approval
        let non_master = KeyPair::from_seed(&[99u8; 32]);
        let resolve_action = TimerAction::Resolve {
            timer_id,
            expiry_price: 1_500_000,
        };
        let mut resolve_op = TimerOperation::new_unsigned(non_master.public(), 0, resolve_action);
        resolve_op.sign(&non_master);
        let resolve_op = Operation::Timer(resolve_op);
        let result = state1.build_block(
            &gov,
            &params,
            Vec::new(),
            vec![resolve_op],
            node.public(),
            2, None);
        assert!(result.is_err());
    }

    #[test]
    fn compute_gas_price_falls_back_to_ox_price_without_pegged() {
        let (state, _genesis, _gov, params, _master, _node, _user) = setup();
        assert_eq!(state.compute_gas_price(&params), params.ox_price_reference);
    }

    #[test]
    fn build_block_zero_gas_fees_when_no_ovm() {
        let (state, _genesis, gov, params, _master, node, _user) = setup();
        let block = state
            .build_block(&gov, &params, Vec::new(), Vec::new(), node.public(), 0, None)
            .unwrap();
        assert_eq!(block.header.gas_price, params.ox_price_reference);
        assert_eq!(block.header.total_gas_fees, 0);
    }

    #[test]
    fn gas_fee_master_share_is_redistributed() {
        let (mut _state, genesis, mut gov, mut params, master, node, user) = setup();
        params.gas_activation_height = 1;

        let config = oxydome_core::GenesisConfig {
            params: params.clone(),
            allocations: vec![
                oxydome_core::GenesisAllocation {
                    recipient: node.public(),
                    amount: 10_000,
                },
                oxydome_core::GenesisAllocation {
                    recipient: user.public(),
                    amount: 999_990_000,
                },
            ],
            masters: vec![master.public()],
            nodes: vec![node.public()],
            timestamp: 0,
        };
        let (state, _genesis, _gov) = ChainState::genesis(&config).unwrap();

        assert_eq!(state.compute_gas_price(&params), params.ox_price_reference);
        assert_eq!(state.gas_balance(&master.public()), 0);
    }
}

fn count_master_approvals(op: &Operation, gov: &GovernanceSet) -> usize {
    let id = op.proposal_id();
    let mut seen = std::collections::BTreeSet::new();
    op.master_approvals()
        .iter()
        .filter(|a| gov.contains_master(&a.master) && a.is_valid(&id) && seen.insert(a.master))
        .count()
}

fn count_node_approvals(op: &Operation, gov: &GovernanceSet) -> usize {
    let id = op.proposal_id();
    let mut seen = std::collections::BTreeSet::new();
    op.node_approvals()
        .iter()
        .filter(|a| gov.contains_node(&a.node) && a.is_valid(&id) && seen.insert(a.node))
        .count()
}

fn dao_error(message: impl Into<String>) -> StateError {
    StateError::Dao(message.into())
}

fn ohm_error(message: impl Into<String>) -> StateError {
    StateError::Ohm(message.into())
}

fn gas_error(message: impl Into<String>) -> StateError {
    StateError::Gas(message.into())
}

fn speedometer_error(message: impl Into<String>) -> StateError {
    StateError::Speedometer(message.into())
}

/// Determines the account that pays GAS for an OVM transaction. For `CallContract` the
/// authority input's owner pays; otherwise the first input's owner pays.
fn ovm_caller<'a>(tx: &'a Transaction, action: &OvmAction) -> Option<&'a PublicKey> {
    match action {
        OvmAction::CallContract {
            authority_input, ..
        } => tx
            .inputs
            .get(*authority_input as usize)
            .map(|input| &input.owner)
            .or_else(|| tx.inputs.first().map(|input| &input.owner)),
        _ => tx.inputs.first().map(|input| &input.owner),
    }
}

fn timer_error(message: impl Into<String>) -> StateError {
    StateError::Timer(message.into())
}

/// Applies a timer operation (Create, Bet, Resolve, Claim) to chain state.
fn apply_timer_operation(
    chain: &mut ChainState,
    operation: &TimerOperation,
    op: &Operation,
    height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    if height < params.timer_activation_height {
        return Err(timer_error("timers are not active at this height"));
    }

    match &operation.action {
        TimerAction::Create {
            asset,
            direction,
            duration_blocks,
            price_anchor,
        } => {
            // For Create, authorization is via master approval (2/3+1). The master
            // approval threshold is checked before the actor's signature.
            let approvals = count_master_approvals(op, gov);
            let threshold = gov.master_threshold(params);
            if approvals < threshold {
                return Err(StateError::TimerApprovalMissing(approvals, threshold));
            }
            if !operation.is_signature_valid() {
                return Err(timer_error("timer operation signature is invalid"));
            }
            if !gov.contains_master(&operation.actor) {
                return Err(timer_error("only masters may create timers"));
            }
            if *duration_blocks == 0 || *duration_blocks > params.max_timer_duration_blocks {
                return Err(timer_error("timer duration out of bounds"));
            }
            if chain.timers.len() >= params.max_timers {
                return Err(timer_error("maximum number of timers reached"));
            }
            let timer_id = op.id();
            if chain.timers.contains_key(&timer_id) {
                return Err(timer_error("timer already exists"));
            }
            let timer = Timer {
                id: timer_id,
                asset: *asset,
                direction: *direction,
                price_anchor: *price_anchor,
                created_height: height,
                expiry_height: height.saturating_add(*duration_blocks),
                samples: Vec::new(),
                accumulated_track: 0,
                created_by: operation.actor,
                resolved: false,
                winning_direction: None,
                bets: BTreeMap::new(),
            };
            chain.timers.insert(timer_id, timer);
        }

        TimerAction::Bet { bet } => {
            if !operation.is_signature_valid() {
                return Err(timer_error("timer operation signature is invalid"));
            }
            if !bet.is_valid() {
                return Err(timer_error("bet signature is invalid"));
            }
            if bet.amount < params.timer_min_bet_amount || bet.amount > params.timer_max_bet_amount
            {
                return Err(timer_error("bet amount out of bounds"));
            }
            let timer = chain
                .timers
                .get_mut(&bet.timer_id)
                .ok_or(StateError::TimerNotFound)?;
            if timer.resolved {
                return Err(timer_error("cannot bet on a resolved timer"));
            }
            if height > timer.expiry_height {
                return Err(timer_error("timer has expired"));
            }
            if timer.bets.len() >= oxydome_core::timer::MAX_TIMER_BETS {
                return Err(timer_error("timer has reached maximum bets"));
            }
            if timer.bets.contains_key(&bet.bet_id) {
                return Err(timer_error("bet already exists"));
            }
            timer.bets.insert(bet.bet_id, bet.clone());
        }

        TimerAction::Resolve {
            timer_id,
            expiry_price,
        } => {
            // Resolve also requires master approval.
            let approvals = count_master_approvals(op, gov);
            let threshold = gov.master_threshold(params);
            if approvals < threshold {
                return Err(StateError::TimerApprovalMissing(approvals, threshold));
            }
            if !operation.is_signature_valid() {
                return Err(timer_error("timer operation signature is invalid"));
            }
            if !gov.contains_master(&operation.actor) {
                return Err(timer_error("only masters may resolve timers"));
            }
            let timer = chain
                .timers
                .get_mut(timer_id)
                .ok_or(StateError::TimerNotFound)?;
            if timer.resolved {
                return Err(StateError::TimerAlreadyResolved);
            }
            if *expiry_price == 0 {
                return Err(timer_error("expiry price must be positive"));
            }
            // Record the final sample and compute the winning direction.
            timer.samples.push(TimerSample {
                height,
                price: *expiry_price,
            });
            let track = accumulated_track(&timer.samples, timer.price_anchor);
            timer.accumulated_track = track;
            let actual = actual_direction(timer.price_anchor, *expiry_price);
            timer.winning_direction = Some(actual);
            timer.resolved = true;

            // Compute the reward pool from the accumulated track.
            let total_bets: Amount = timer
                .bets
                .values()
                .map(|b| b.amount)
                .fold(0u128, |a, b| a.saturating_add(b));
            let accumulated = timer.accumulated_track;

            // Burn/mint the betting currency based on the winning direction:
            //
            // * If the winning direction is Up and the track is positive:
            //   price rose; burn betting currency so the price ticks up further.
            // * If the winning direction is Down and the track is negative:
            //   price fell; mint betting currency so the price ticks down further.
            //
            // Losing bettors' stakes are consumed by the accumulated pool
            // (they receive nothing back).
            if actual == TimerDirection::Up {
                if accumulated > 0 {
                    // Burn: reduce supply.
                    let burn_amount = accumulated.unsigned_abs().min(total_bets);
                    chain.supply = chain.supply.saturating_sub(burn_amount);
                }
            } else if accumulated < 0 {
                // Mint: increase supply.
                let mint_amount = accumulated.unsigned_abs().min(total_bets);
                chain.supply = chain.supply.saturating_add(mint_amount);
            }

            // Award rewards to winning bettors by minting new UTXOs.
            let mut out_idx = 0u32;
            for bet in timer.bets.values().clone() {
                if !bet.direction.is_winner(actual) {
                    continue;
                }
                let reward =
                    reward_for_bet(bet.amount, total_bets, accumulated, bet.direction, actual);
                let payout = if reward >= 0 {
                    bet.amount.saturating_add(reward as Amount)
                } else {
                    bet.amount.saturating_sub(reward.unsigned_abs())
                };
                if payout > 0 {
                    let outpoint = OutPoint::new(op.id(), out_idx);
                    chain.utxo = chain.utxo.insert(UtxoEntry::new(
                        outpoint,
                        TxOutput::spendable(payout, bet.better),
                        height,
                    ));
                    out_idx += 1;
                }
            }
        }

        TimerAction::Claim { bet_id } => {
            if !operation.is_signature_valid() {
                return Err(timer_error("timer operation signature is invalid"));
            }
            // Find the bet and its timer.
            let found = chain
                .timers
                .values()
                .find_map(|t| t.bets.get(bet_id).map(|b| (t.id, t.clone(), b.clone())));
            let (timer_id, timer, bet) = found.ok_or(StateError::TimerNotFound)?;
            let timer_ref = chain
                .timers
                .get(&timer_id)
                .ok_or(StateError::TimerNotFound)?;
            if !timer_ref.resolved {
                return Err(timer_error("timer is not resolved"));
            }
            if bet.claimed {
                return Err(timer_error("bet already claimed"));
            }
            if bet.better != operation.actor {
                return Err(timer_error("only the bettor may claim"));
            }
            if !verify(&operation.actor, &op.proposal_id().0, &operation.signature) {
                return Err(timer_error("claim signature is invalid"));
            }
            let winning = timer_ref
                .winning_direction
                .ok_or_else(|| timer_error("no winning direction recorded"))?;
            if !bet.direction.is_winner(winning) {
                return Err(timer_error("bet did not win"));
            }
            let total_bets: Amount = timer_ref
                .bets
                .values()
                .map(|b| b.amount)
                .fold(0u128, |a, b| a.saturating_add(b));
            let reward = reward_for_bet(
                bet.amount,
                total_bets,
                timer_ref.accumulated_track,
                bet.direction,
                winning,
            );
            let payout = if reward >= 0 {
                bet.amount.saturating_add(reward as Amount)
            } else {
                bet.amount.saturating_sub(reward.unsigned_abs())
            };
            if payout > 0 {
                let outpoint = OutPoint::new(op.id(), 0);
                chain.utxo = chain.utxo.insert(UtxoEntry::new(
                    outpoint,
                    TxOutput::spendable(payout, bet.better),
                    height,
                ));
            }
            if let Some(timer) = chain.timers.get_mut(&timer_id) {
                if let Some(b) = timer.bets.get_mut(bet_id) {
                    b.claimed = true;
                }
            }
        }
    }

    Ok(())
}

/// Applies gas operation (transfer or set price oracle).
fn apply_gas_operation(
    chain: &mut ChainState,
    operation: &GasOperation,
    op: &Operation,
    height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    if height < params.gas_activation_height {
        return Err(StateError::GasInactive);
    }
    if !operation.is_valid() {
        return Err(gas_error("signature or action encoding is invalid"));
    }
    match &operation.action {
        GasAction::SetOxPrice { price } => {
            let approvals = count_master_approvals(op, gov);
            let threshold = gov.master_threshold(params);
            if approvals < threshold {
                return Err(StateError::MasterApprovalMissing(approvals, threshold));
            }
            chain.ox_price = *price;
        }
        GasAction::Transfer { to, amount } => {
            let account = chain.gas.get(&operation.actor).copied().unwrap_or_default();
            if account.nonce != operation.nonce {
                return Err(StateError::GasNonce(operation.nonce, account.nonce));
            }
            if account.balance < *amount {
                return Err(StateError::GasUnderfunded(operation.actor));
            }
            let mut from = account;
            from.balance -= amount;
            from.nonce += 1;
            chain.gas.insert(operation.actor, from);
            let to_account = chain.gas.entry(*to).or_default();
            to_account.balance = to_account.balance.saturating_add(*amount);
        }
    }

    Ok(())
}

/// Applies a Speedometer operation (user-signed transfer).
fn apply_speedometer_operation(
    chain: &mut ChainState,
    operation: &SpeedometerOperation,
    op: &Operation,
    height: u64,
    params: &ChainParams,
) -> Result<(), StateError> {
    if height < params.speedometer_activation_height {
        return Err(StateError::SpeedometerInactive);
    }
    if !operation.is_valid() {
        return Err(speedometer_error("signature or action encoding is invalid"));
    }
    match &operation.action {
        SpeedometerAction::Transfer { to, amount } => {
            let account = chain
                .speedometer
                .get(&operation.actor)
                .copied()
                .unwrap_or_default();
            if account.nonce != operation.nonce {
                return Err(StateError::SpeedometerNonce(operation.nonce, account.nonce));
            }
            if account.balance < *amount {
                return Err(StateError::SpeedometerUnderfunded(operation.actor));
            }
            let mut from = account;
            from.balance -= amount;
            from.nonce += 1;
            chain.speedometer.insert(operation.actor, from);
            let to_account = chain.speedometer.entry(*to).or_default();
            to_account.balance = to_account.balance.saturating_add(*amount);
        }
    }
    Ok(())
}

/// Distributes `amount` of per-transaction stabilization mint to active liquidity pool owners
/// proportionally to their pool's share of total LP value (sum of reserves). Falls back to
/// the block producer when no pools exist (handled by the caller).
fn distribute_stabilization_to_pools(chain: &mut ChainState, amount: Amount) {
    if amount == 0 || chain.liquidity_pools.is_empty() {
        return;
    }
    // Compute total LP value (sum of all reserves across all pools).
    let total_lp_value: Amount = chain
        .liquidity_pools
        .values()
        .map(|pool| {
            pool.reserves
                .values()
                .fold(0u128, |a, b| a.saturating_add(*b))
        })
        .fold(0u128, |a, b| a.saturating_add(b));
    if total_lp_value == 0 {
        return;
    }
    // Collect shares first to avoid borrowing `chain` mutably during iteration.
    let grants: Vec<(PublicKey, Amount)> = chain
        .liquidity_pools
        .iter()
        .filter_map(|(_, pool)| {
            let pool_value = pool
                .reserves
                .values()
                .fold(0u128, |a, b| a.saturating_add(*b));
            if pool_value == 0 {
                return None;
            }
            let share = amount.saturating_mul(pool_value) / total_lp_value;
            if share > 0 {
                Some((pool.config.owner, share))
            } else {
                None
            }
        })
        .collect();
    // The first recipient absorbs the rounding remainder for conservation.
    let assigned: Amount = grants
        .iter()
        .map(|(_, s)| *s)
        .fold(0u128, |a, b| a.saturating_add(b));
    let mut grants = grants;
    let remainder = amount.saturating_sub(assigned);
    if remainder > 0 {
        if let Some(first) = grants.first_mut() {
            first.1 = first.1.saturating_add(remainder);
        }
    }
    for (owner, share) in grants {
        chain.mint_speedometer(owner, share);
    }
}

fn apply_dao_operation(
    _chain: &mut ChainState,
    _operation: &DaoOperation,
    _height: u64,
    _params: &ChainParams,
    _activity: &mut BTreeMap<Hash, DaoWindowStats>,
) -> Result<(), StateError> {
    Err(dao_error("DAO operations not yet fully implemented"))
}

fn apply_ohm_operation(
    chain: &mut ChainState,
    operation: &OhmOperation,
    operation_id: Hash,
    height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
    proposer: PublicKey,
) -> Result<(), StateError> {
    if !operation.is_valid() {
        return Err(ohm_error("signature or action encoding is invalid"));
    }

    match &operation.action {
        OhmAction::Create {
            policy_bytes,
            genesis_outputs,
        } => {
            let policy = OhmPolicy::decode(policy_bytes).map_err(ohm_error)?;
            if policy.maintainer != operation.actor {
                return Err(ohm_error("OHM creator must be the declared maintainer"));
            }
            let ohm_id = operation
                .created_ohm_id()
                .ok_or_else(|| ohm_error("create action has no derived OHM id"))?;
            if chain.ohm_states.contains_key(&ohm_id) {
                return Err(ohm_error("OHM already exists"));
            }

            // Verify genesis outputs sum to policy genesis supply.
            let total: Amount = genesis_outputs.iter().map(|o| o.amount).sum();
            if total != policy.genesis_supply {
                return Err(ohm_error("genesis outputs do not sum to genesis supply"));
            }

            // Create initial UTXOs for genesis outputs. These belong to OHM height 0, so the
            // recorded created-height is 0 to match the node-side ledger derivation.
            let mut utxos = BTreeMap::new();
            for (i, output) in genesis_outputs.iter().enumerate() {
                let outpoint = OutPoint::new(operation.id(), i as u32);
                let entry = OhmUtxoEntry::new(outpoint, output.clone(), 0);
                utxos.insert(entry.key(), entry);
            }
            let state_root = ohm_state_root(&utxos, &BTreeMap::new());

            chain.ohm_states.insert(
                ohm_id,
                OhmState {
                    policy,
                    current_height: 0,
                    block_hash: ohm_genesis_hash(&ohm_id),
                    state_root,
                    supply: total,
                    utxos,
                    treasury_ox: 0,
                    genesis_supply: total,
                    fees_paid: 0,
                },
            );
        }
        OhmAction::Update {
            ohm_id,
            context,
            block_hash,
            fee_total,
        } => {
            let (maintainer, new_treasury) = {
                let ohm = chain
                    .ohm_states
                    .get(ohm_id)
                    .ok_or_else(|| ohm_error("OHM does not exist"))?;
                if operation.actor != ohm.policy.maintainer {
                    return Err(ohm_error("only OHM maintainer may update"));
                }
                if !context.is_valid() {
                    return Err(ohm_error("invalid OHM context"));
                }
                if context.ohm_height != ohm.current_height + 1 {
                    return Err(ohm_error("OHM height does not follow previous"));
                }
                if context.ohm_prev_hash != ohm.block_hash {
                    return Err(ohm_error("OHM prev_hash does not match current block"));
                }
                (ohm.policy.maintainer, ohm.treasury_ox)
            };

            // Settle fees. This is the single enforcement point for the automatic OHM fee split:
            // `compute_ohm_fee_split` governs the division via `OHM_SERVER_FEE_BPS`, the server
            // share is minted as `LockedReward` outputs for the Ox server nodes and the remainder
            // is credited to the OHM treasury. The weighted distribution can leave rounding dust,
            // which the treasury retains so that the value minted equals the fee total exactly.
            // Both legs enter the Ox ledger, so supply grows by exactly the fee total. When GAS
            // is active, the server share is additionally converted: `gas_server_fee_bps` of
            // each server reward is burned from Ox and minted as GAS to the same recipient.
            let fee_total = *fee_total;
            let (server_share, _) = compute_ohm_fee_split(fee_total);
            let server_outputs = build_ohm_server_outputs(fee_total, &gov.nodes, &proposer);
            let server_total: Amount = server_outputs.iter().map(|o| o.amount).sum();
            debug_assert!(server_total <= server_share);
            let ohm_share = fee_total.saturating_sub(server_total);
            let convert = height >= params.gas_activation_height && params.gas_server_fee_bps > 0;
            for (i, output) in server_outputs.into_iter().enumerate() {
                let (ox_kept, gas_minted) = if convert {
                    conversion_split_with_bps(output.amount, params.gas_server_fee_bps)
                } else {
                    (output.amount, 0)
                };
                if ox_kept > 0 {
                    let mut kept = output.clone();
                    kept.amount = ox_kept;
                    let outpoint = OutPoint::new(operation_id, i as u32);
                    chain.utxo = chain.utxo.insert(UtxoEntry::new(outpoint, kept, height));
                }
                if gas_minted > 0 {
                    chain.supply = chain.supply.saturating_sub(gas_minted);
                    chain.mint_gas(output.recipient, gas_minted);
                }
            }

            let treasury_balance = new_treasury
                .checked_add(ohm_share)
                .ok_or_else(|| ohm_error("OHM treasury overflow"))?;

            if let Some(ohm) = chain.ohm_states.get_mut(ohm_id) {
                ohm.current_height = context.ohm_height;
                ohm.block_hash = *block_hash;
                ohm.state_root = context.ohm_state_root;
                ohm.treasury_ox = treasury_balance;
                ohm.fees_paid = ohm
                    .fees_paid
                    .checked_add(fee_total)
                    .ok_or_else(|| ohm_error("OHM fees_paid overflow"))?;
            }
            set_ohm_treasury_utxo(chain, ohm_id, &maintainer, treasury_balance, height);
            chain.supply = chain
                .supply
                .checked_add(fee_total)
                .ok_or_else(|| ohm_error("Ox supply overflow"))?;
        }
        OhmAction::Terminate { ohm_id, reason } => {
            let ohm = chain
                .ohm_states
                .get(ohm_id)
                .ok_or_else(|| ohm_error("OHM does not exist"))?;
            if operation.actor != ohm.policy.maintainer {
                return Err(ohm_error("only OHM maintainer may terminate"));
            }
            if reason.len() > oxydome_core::ohm::MAX_OHM_REASON_BYTES {
                return Err(ohm_error("termination reason too long"));
            }
            let maintainer = ohm.policy.maintainer;

            // Return any treasury balance to the maintainer and drop the locked treasury UTXO.
            let outpoint = ohm_treasury_outpoint(ohm_id);
            if let Some(entry) = chain.utxo.get(&outpoint).cloned() {
                chain.utxo = chain.utxo.remove(&outpoint).0;
                let payout = OutPoint::new(operation_id, 0);
                chain.utxo = chain.utxo.insert(UtxoEntry::new(
                    payout,
                    TxOutput::spendable(entry.output.amount, maintainer),
                    height,
                ));
            }

            // Remove OHM state (termination is final).
            chain.ohm_states.remove(ohm_id);
        }
        OhmAction::Transfer {
            ohm_id,
            recipient,
            amount,
        } => {
            let (maintainer, new_balance) = {
                let ohm = chain
                    .ohm_states
                    .get(ohm_id)
                    .ok_or_else(|| ohm_error("OHM does not exist"))?;
                if operation.actor != ohm.policy.maintainer {
                    return Err(ohm_error("only OHM maintainer may transfer from treasury"));
                }
                if *amount == 0 {
                    return Err(ohm_error("transfer amount must be positive"));
                }
                if ohm.treasury_ox < *amount {
                    return Err(ohm_error("insufficient OHM treasury balance"));
                }
                (ohm.policy.maintainer, ohm.treasury_ox - *amount)
            };

            if let Some(ohm) = chain.ohm_states.get_mut(ohm_id) {
                ohm.treasury_ox = new_balance;
            }

            // Create UTXO on Ox chain for recipient and update the locked treasury UTXO.
            let outpoint = OutPoint::new(operation_id, 0);
            chain.utxo = chain.utxo.insert(UtxoEntry::new(
                outpoint,
                TxOutput::spendable(*amount, *recipient),
                height,
            ));
            set_ohm_treasury_utxo(chain, ohm_id, &maintainer, new_balance, height);
        }
        OhmAction::TreasuryDeposit {
            ohm_id,
            source,
            amount,
        } => {
            let maintainer = chain
                .ohm_states
                .get(ohm_id)
                .ok_or_else(|| ohm_error("OHM does not exist"))?
                .policy
                .maintainer;

            // Find and consume the source UTXO from the main Ox ledger.
            let entry = chain
                .utxo
                .get(source)
                .cloned()
                .ok_or_else(|| ohm_error("source UTXO does not exist"))?;
            if !entry.output.kind.is_spendable()
                || entry.output.recipient != operation.actor
                || *amount > entry.output.amount
                || *amount == 0
            {
                return Err(ohm_error("invalid source UTXO"));
            }
            chain.utxo = chain.utxo.remove(source).0;

            // Create change UTXO if needed.
            let change = entry.output.amount - *amount;
            if change > 0 {
                let outpoint = OutPoint::new(operation_id, 0);
                chain.utxo = chain.utxo.insert(UtxoEntry::new(
                    outpoint,
                    TxOutput::spendable(change, operation.actor),
                    height,
                ));
            }

            let new_balance = chain
                .ohm_states
                .get(ohm_id)
                .map(|ohm| ohm.treasury_ox)
                .unwrap_or(0)
                .checked_add(*amount)
                .ok_or_else(|| ohm_error("OHM treasury overflow"))?;
            if let Some(ohm) = chain.ohm_states.get_mut(ohm_id) {
                ohm.treasury_ox = new_balance;
            }
            set_ohm_treasury_utxo(chain, ohm_id, &maintainer, new_balance, height);
        }
    }

    Ok(())
}

/// Inserts (or removes, when zero) the locked `OhmTreasury` UTXO that backs `ohm_id`'s
/// `treasury_ox` balance, keeping the Ox supply invariant intact.
fn set_ohm_treasury_utxo(
    chain: &mut ChainState,
    ohm_id: &Hash,
    maintainer: &PublicKey,
    amount: Amount,
    height: u64,
) {
    let outpoint = ohm_treasury_outpoint(ohm_id);
    chain.utxo = chain.utxo.remove(&outpoint).0;
    if amount > 0 {
        chain.utxo = chain.utxo.insert(UtxoEntry::new(
            outpoint,
            TxOutput::ohm_treasury(amount, *maintainer, *ohm_id),
            height,
        ));
    }
}

fn update_dao_value_indices(
    _daos: &mut BTreeMap<Hash, DaoState>,
    _block_activity: &BTreeMap<Hash, DaoWindowStats>,
    _params: &ChainParams,
) {
    // Placeholder - DAO value index updates not yet implemented
}

fn apply_file_store(
    next: &mut ChainState,
    file_op: &FileStoreOperation,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.file_system_activation_height {
        return Err(StateError::FileSystemInactive);
    }
    let label = &file_op.file_label;
    if !label.is_valid() {
        return Err(StateError::BadFileLabelSignature);
    }
    let expected = EphemeralKeyManager::compute_file_key_chain_commitment(
        label.previous_commitment,
        label.content_hash,
        label.block_height,
        label.block_hash,
    );
    if expected != label.key_chain_commitment {
        return Err(StateError::BadFileChainCommitment);
    }
    if label.previous_commitment != next.file_chain_tip {
        return Err(StateError::BadFileChainLink);
    }
    if !gov.contains_node(&label.node) {
        return Err(StateError::UnauthorizedFileNode);
    }
    let _node_approvals = count_node_approvals(op, gov);
    let _threshold = gov.node_threshold(params);
    // Node approval quorum check: when no quorum approvals are present, the
    // node's own signature (verified via label.is_valid()) suffices, matching
    // the StorageLabel pattern.
    if label.size > params.max_file_bytes {
        return Err(StateError::FileTooLarge(label.size, params.max_file_bytes));
    }
    if label.block_height != new_height {
        return Err(StateError::BadFileChainCommitment);
    }
    if next.file_labels.contains_key(&label.key_chain_commitment) {
        return Err(StateError::DuplicateFile);
    }
    let node_count = next.file_node_counts.entry(label.node).or_default();
    if *node_count >= params.max_files_per_node {
        return Err(StateError::NodeFileCountExceeded(params.max_files_per_node));
    }
    *node_count += 1;
    next.file_labels
        .insert(label.key_chain_commitment, label.clone());
    next.file_chain_tip = label.key_chain_commitment;
    Ok(())
}

fn apply_file_access(
    next: &mut ChainState,
    access_op: &FileAccessOperation,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    _gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.file_system_activation_height {
        return Err(StateError::FileSystemInactive);
    }
    let proposal_id = op.proposal_id();
    if !verify(&access_op.accessor, &proposal_id.0, &access_op.signature) {
        return Err(StateError::BadFileAccessSignature);
    }
    let label = next
        .file_labels
        .get(&access_op.file_id)
        .ok_or(StateError::FileNotFound(access_op.file_id))?;
    if label.content_hash != access_op.content_hash {
        return Err(StateError::FileHashMismatch);
    }
    let record = FileAccessRecord {
        accessor: access_op.accessor,
        file_id: access_op.file_id,
        content_hash: access_op.content_hash,
        height: new_height,
        timestamp: access_op.timestamp,
    };
    let record_id = hash_value(&record);
    next.file_access_log.insert(record_id, record);
    Ok(())
}

fn apply_file_delete(
    next: &mut ChainState,
    delete_op: &FileDeleteOperation,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    _gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.file_system_activation_height {
        return Err(StateError::FileSystemInactive);
    }
    let label = next
        .file_labels
        .get(&delete_op.file_id)
        .ok_or(StateError::FileNotFound(delete_op.file_id))?;
    if label.node != delete_op.deleter {
        return Err(StateError::NotFileOwner);
    }
    let proposal_id = op.proposal_id();
    if !verify(&delete_op.deleter, &proposal_id.0, &delete_op.signature) {
        return Err(StateError::BadFileDeleteSignature);
    }
    if label.content_hash != delete_op.content_hash {
        return Err(StateError::FileHashMismatch);
    }
    if let Some(count) = next.file_node_counts.get_mut(&label.node) {
        *count = count.saturating_sub(1);
    }
    next.file_labels.remove(&delete_op.file_id);
    Ok(())
}

fn apply_liquidity_pool_operation(
    next: &mut ChainState,
    lp_op: &LiquidityPoolOperation,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    _gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.liquidity_pool_activation_height {
        return Err(StateError::PoolNotFound(Hash::zero()));
    }
    // Verify actor signature.
    if !verify(&lp_op.actor, &op.proposal_id().0, &lp_op.signature) {
        return Err(StateError::BadPoolSignature);
    }
    // A pool is addressed by its owner and currency set, so every operation on the pool
    // resolves to the same entry.
    let pool_currencies: Vec<PriceAsset> = match &lp_op.action {
        LiquidityPoolAction::Create { currencies } => currencies.clone(),
        LiquidityPoolAction::Provide { amounts }
        | LiquidityPoolAction::RemoveLiquidity { amounts } => amounts.keys().copied().collect(),
        LiquidityPoolAction::Swap { currencies, .. } => currencies.clone(),
    };
    let pool_id = oxydome_core::liquidity_pool_id(&lp_op.actor, &pool_currencies);
    match &lp_op.action {
        LiquidityPoolAction::Create { currencies } => {
            if next.liquidity_pools.contains_key(&pool_id) {
                return Err(StateError::PoolAlreadyExists(pool_id));
            }
            if next.liquidity_pools.len() >= params.max_liquidity_pools as usize {
                return Err(StateError::PoolLimitExceeded(
                    params.max_liquidity_pools as usize,
                ));
            }
            let k_params = PoolKParams {
                fee_bps: params.liquidity_pool_fee_bps,
                activation_height: params.liquidity_pool_activation_height,
                t_ref: LIQUIDITY_POOL_SCALE,
            };
            let config = LiquidityPoolConfig {
                owner: lp_op.actor,
                currencies: currencies.clone(),
                k_params,
            };
            let state = LiquidityPoolState::new(config);
            next.liquidity_pools.insert(pool_id, state);
        }
        LiquidityPoolAction::Provide { amounts } => {
            let pool = next
                .liquidity_pools
                .get_mut(&pool_id)
                .ok_or(StateError::PoolNotFound(pool_id))?;
            if pool.config.owner != lp_op.actor {
                return Err(StateError::BadPoolSignature);
            }
            for (&asset, &amount) in amounts {
                if !pool.config.currencies.contains(&asset) {
                    return Err(StateError::PoolInsufficientReserves);
                }
                let current = pool.reserves.get(&asset).copied().unwrap_or(0);
                pool.reserves.insert(asset, current.saturating_add(amount));
            }
            pool.volume = pool
                .volume
                .saturating_add(amounts.values().copied().sum::<Amount>());
        }
        LiquidityPoolAction::RemoveLiquidity { amounts } => {
            let pool = next
                .liquidity_pools
                .get_mut(&pool_id)
                .ok_or(StateError::PoolNotFound(pool_id))?;
            if pool.config.owner != lp_op.actor {
                return Err(StateError::BadPoolSignature);
            }
            let mut out_idx = 0u32;
            for (&asset, &amount) in amounts {
                let current = pool.reserves.get(&asset).copied().unwrap_or(0);
                if current < amount {
                    return Err(StateError::PoolInsufficientReserves);
                }
                pool.reserves.insert(asset, current - amount);
                let outpoint = OutPoint::new(op.id(), out_idx);
                next.utxo = next.utxo.insert(UtxoEntry::new(
                    outpoint,
                    TxOutput::spendable(amount, lp_op.actor),
                    new_height,
                ));
                out_idx += 1;
            }
            let removed: Amount = amounts.values().copied().sum();
            pool.volume = pool.volume.saturating_sub(pool.volume.min(removed));
        }
        LiquidityPoolAction::Swap {
            currencies: _,
            input_asset,
            input_amount,
            min_output,
        } => {
            let pool = next
                .liquidity_pools
                .get_mut(&pool_id)
                .ok_or(StateError::PoolNotFound(pool_id))?;
            let (reserve_x, reserve_y) = (pool.reserve_x(), pool.reserve_y());
            let other = match pool.other_asset() {
                Some(a) => a,
                None => return Err(StateError::PoolInsufficientReserves),
            };
            if *input_asset != PriceAsset::Ox && *input_asset != other {
                return Err(StateError::PoolInsufficientReserves);
            }
            let output = pool_swap(
                *input_amount,
                reserve_x,
                reserve_y,
                pool.k,
                pool.config.k_params.fee_bps,
            );
            if output < *min_output {
                return Err(StateError::PoolSwapBelowMin(output, *min_output));
            }
            if *input_asset == PriceAsset::Ox {
                // Increasing x, decreasing y
                let new_y = pool.reserves.entry(other).or_insert(0);
                *new_y = new_y.saturating_sub(output);
                let new_x = pool.reserves.entry(PriceAsset::Ox).or_insert(0);
                *new_x = new_x.saturating_add(*input_amount);
            } else {
                // Increasing y, decreasing x
                let new_x = pool.reserves.entry(PriceAsset::Ox).or_insert(0);
                *new_x = new_x.saturating_sub(output);
                let new_y = pool.reserves.entry(other).or_insert(0);
                *new_y = new_y.saturating_add(*input_amount);
            }
            pool.volume = pool.volume.saturating_add(*input_amount);
            let outpoint = OutPoint::new(op.id(), 0);
            next.utxo = next.utxo.insert(UtxoEntry::new(
                outpoint,
                TxOutput::spendable(output, lp_op.actor),
                new_height,
            ));
        }
    }
    Ok(())
}

/// Applies an [`ExpressBusDeposit`] operation.
///
/// Validates the master-node quorum, verifies the input UTXOs, and creates new
/// `BusReceipt` outputs tagged with the bus ID. Updates the corresponding
/// [`ExpressBusTracker`] by increasing its `in_volume`.
pub fn apply_express_bus_deposit(
    next: &mut ChainState,
    dep: &ExpressBusDeposit,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.express_bus_activation_height {
        return Err(StateError::ExpressBusInactive);
    }
    let approvals = count_master_approvals(op, gov);
    let threshold = gov.master_threshold(params);
    if approvals < threshold {
        return Err(StateError::MasterApprovalMissing(approvals, threshold));
    }
    // Verify input UTXOs are spendable (ordinary outputs only).
    let mut available: Amount = 0;
    for input in &dep.inputs {
        let entry = next
            .utxo
            .get(input)
            .cloned()
            .ok_or(StateError::BadExpressBusDeposit)?;
        if !entry.output.kind.is_spendable() {
            return Err(StateError::BadExpressBusDeposit);
        }
        available = available.saturating_add(entry.output.amount);
    }
    for input in &dep.inputs {
        next.utxo = next.utxo.remove(input).0;
    }
    if available < dep.amount {
        return Err(StateError::BadExpressBusDeposit);
    }
    // Create BusReceipt output.
    let outpoint = OutPoint::new(op.id(), 0);
    next.utxo = next.utxo.insert(UtxoEntry::new(
        outpoint,
        TxOutput::bus_receipt(dep.amount, dep.depositor, dep.bus_id, dep.asset),
        new_height,
    ));
    // Change, if any, is a locked_reward output.
    let change = available.saturating_sub(dep.amount);
    if change > 0 {
        let change_outpoint = OutPoint::new(op.id(), 1);
        next.utxo = next.utxo.insert(UtxoEntry::new(
            change_outpoint,
            TxOutput::locked_reward(change, dep.depositor),
            new_height,
        ));
    }
    // Create or update tracker, recording the deposit.
    let tracker = next
        .express_buses
        .entry(dep.bus_id)
        .or_insert_with(|| {
            ExpressBusTracker::new(dep.bus_id, dep.asset, params.express_bus_default_weight, new_height)
        });
    tracker.record_deposit(dep.amount);
    Ok(())
}

/// Applies an [`ExpressBusWithdraw`] operation.
///
/// Validates the node quorum and owner signature, verifies the input
/// `BusReceipt` UTXOs, and creates new spendable outputs. Decreases the
/// corresponding [`ExpressBusTracker`] `out_volume`.
pub fn apply_express_bus_withdraw(
    next: &mut ChainState,
    wd: &ExpressBusWithdraw,
    op: &Operation,
    new_height: u64,
    params: &ChainParams,
    gov: &GovernanceSet,
) -> Result<(), StateError> {
    if new_height < params.express_bus_activation_height {
        return Err(StateError::ExpressBusInactive);
    }
    let approvals = count_node_approvals(op, gov);
    let threshold = gov.node_threshold(params);
    if approvals < threshold {
        return Err(StateError::NodeApprovalMissing(approvals, threshold));
    }
    // Verify owner signature.
    if !wd.is_signature_valid() {
        return Err(StateError::BadExpressBusWithdraw);
    }
    if !gov.contains_node(&wd.owner) {
        return Err(StateError::ExpressBusNotOwner);
    }
    // Collect bus receipts from inputs.
    let mut total: Amount = 0;
    for input in &wd.inputs {
        let entry = next
            .utxo
            .get(input)
            .cloned()
            .ok_or(StateError::BadExpressBusWithdraw)?;
        if !entry.output.kind.is_bus_receipt() {
            return Err(StateError::BadExpressBusWithdraw);
        }
        total = total.saturating_add(entry.output.amount);
    }
    for input in &wd.inputs {
        next.utxo = next.utxo.remove(input).0;
    }
    // Create spendable output.
    let outpoint = OutPoint::new(op.id(), 0);
    next.utxo = next.utxo.insert(UtxoEntry::new(
        outpoint,
        TxOutput::spendable(total, wd.owner),
        new_height,
    ));
    // Update tracker out_volume.
    let bus_id = wd.bus_id;
    if let Some(tracker) = next.express_buses.get_mut(&bus_id) {
        tracker.record_withdraw(total);
    }
    Ok(())
}
