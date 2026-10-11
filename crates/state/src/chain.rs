//! The chain state machine: authenticated UTXO state, supply accounting, window statistics and
//! block application/validation.

use crate::utxo::{UtxoEntry, UtxoLedger};
use oxydome_core::{
    conversion_split_with_bps, Amount, Block, ChainParams, DaoAction, DaoOperation, DaoPeg, DaoPolicy,
    DaoProposal, DaoProposalAction, DaoProposalStatus, DaoState, DaoWindowStats, GasAccount,
    GasAction, GasOperation, GovernanceSet, OhmAction, OhmOperation, OhmPolicy, OhmState,
    OhmUtxoEntry, Operation, OutPoint, OvmAction, OvmFailureCode, OvmLog, OvmReceipt, PublicKey,
    RewardDistribution, Transaction, TxOutput, ValueIndex, MAX_DAO_PROPOSALS,
    MAX_DAO_PROPOSAL_HEIGHTS, MAX_OVM_BLOCK_GAS_LIMIT,
};
use oxydome_core::{
    build_ohm_server_outputs, compute_ohm_fee_split, ohm_genesis_hash, ohm_state_root,
    ohm_treasury_outpoint,
};
use oxydome_gas::{airdrop_amount, distribute_airdrop};
use oxydome_crypto::{hash_value, verify, Hash};
use oxydome_currency::{
    compute_value, max_withdraw_per_account, rebound_utxo_spendable, supply_change_cap,
    supply_impact_ok, withdraw_cap, WindowStats,
};
use std::collections::{BTreeMap, VecDeque};

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
    #[error("epoch regression from {0} to {1}")]
    EpochRegression(u64, u64),
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
        };
        let gov = GovernanceSet::new(config.masters.clone(), config.nodes.clone());
        Ok((state, block, gov))
    }

    pub fn utxo_root(&self) -> Hash {
        self.utxo.root()
    }

    /// Combined commitment to UTXOs, OVM code/storage, DAO state, and OHM state.
    /// Empty feature state preserves the original transfer-only state root.
    pub fn state_root(&self) -> Hash {
        if self.contracts.is_empty() && self.daos.is_empty() && self.ohm_states.is_empty() {
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
        
        // Combine all roots - use v2 if only OVM+DAO, v3 if OHM included
        if ohm_root.is_zero() {
            hash_value(&("oxydome-combined-state-v2", self.utxo.root(), ovm_root, dao_root))
        } else {
            hash_value(&(
                "oxydome-combined-state-v3",
                self.utxo.root(),
                ovm_root,
                dao_root,
                ohm_root
            ))
        }
    }

    /// Returns the GAS balance for `owner`.
    pub fn gas_balance(&self, owner: &PublicKey) -> Amount {
        self.gas.get(owner).map_or(0, |account| account.balance)
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

    /// The summed statistics over the measurement window.
    pub fn window_stats(&self, params: &ChainParams) -> WindowStats {
        let limit = params.block_window.max(1) as usize;
        let mut stats = WindowStats::default();
        for s in self.stats_history.iter().rev().take(limit) {
            stats.volume = stats.volume.saturating_add(s.volume);
            stats.tx_count = stats.tx_count.saturating_add(s.tx_count);
            stats.exit_amount = stats.exit_amount.saturating_add(s.exit_amount);
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
    pub fn build_block(
        &self,
        gov: &GovernanceSet,
        params: &ChainParams,
        transactions: Vec<Transaction>,
        operations: Vec<Operation>,
        producer: PublicKey,
        timestamp: u64,
    ) -> Result<Block, StateError> {
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
        );
        let next = self.apply_inner(&block, gov, params, false)?;
        block.ovm_receipts = next.ovm_receipts.clone();
        block.header.ovm_receipt_root = block.ovm_receipt_root();
        block.header.utxo_root = next.utxo_root();
        block.header.state_root = next.state_root();
        block.header.supply = next.supply;
        block.header.value_index = next.value_index;
        block.header.generation = next.generation;
        // Re-verify against the committed header.
        self.apply_inner(&block, gov, params, true)?;
        Ok(block)
    }

    /// Calculates actual fees by executing OVM actions against a temporary ordered overlay.
    /// Block production uses this same execution path as consensus validation.
    pub fn settled_fee_total(&self, transactions: &[Transaction]) -> Result<Amount, StateError> {
        let mut execution_state = self.clone();
        let mut total = 0u128;
        let mut gas_limit_total = 0u64;
        for (tx_index, tx) in transactions.iter().enumerate() {
            let fee = if let Some(action) = &tx.ovm_action {
                gas_limit_total = gas_limit_total
                    .checked_add(action.gas_limit())
                    .filter(|total| *total <= MAX_OVM_BLOCK_GAS_LIMIT)
                    .ok_or(StateError::OvmBlockGasLimit)?;
                let required = oxydome_core::transfer_fee(&tx.outputs)
                    .map_err(|error| StateError::BadTransaction(tx_index, error.to_string()))?;
                let legacy_required = required.saturating_add(u128::from(action.gas_limit()));
                if tx.fee != required && tx.fee != legacy_required {
                    return Err(StateError::BadTransaction(
                        tx_index,
                        "fee does not equal the transfer fee".into(),
                    ));
                }
                let _ = self.apply_ovm_action(&mut execution_state, action, tx.txid(), tx_index, tx)?;
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
        if block.header.epoch < self.epoch {
            return Err(StateError::EpochRegression(self.epoch, block.header.epoch));
        }

        let new_height = block.header.height;
        let mut next = self.clone();
        next.ovm_receipts.clear();
        if block.header.epoch != self.epoch {
            next.epoch = block.header.epoch;
            next.epoch_minted = 0;
            next.epoch_burned = 0;
            next.epoch_withdrawn = 0;
        }

        // ---- 1. Transactions ----
        let mut total_fees: Amount = 0;
        let mut block_ovm_gas_limit = 0u64;
        let mut block_stats = WindowStats::default();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
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
                block_ovm_gas_limit = block_ovm_gas_limit
                    .checked_add(action.gas_limit())
                    .ok_or(StateError::OvmBlockGasLimit)?;
                if block_ovm_gas_limit > MAX_OVM_BLOCK_GAS_LIMIT {
                    return Err(StateError::OvmBlockGasLimit);
                }
                let expected_fee = oxydome_core::transfer_fee(&tx.outputs)
                    .map_err(|error| StateError::BadTransaction(tx_idx, error.to_string()))?;
                let legacy_expected_fee = expected_fee.saturating_add(u128::from(action.gas_limit()));
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
                if block.header.height >= params.gas_activation_height {
                    if let Some(caller) = ovm_caller(tx, action) {
                        let gas_limit = u128::from(action.gas_limit());
                        if next.gas_balance(caller) < gas_limit {
                            return Err(StateError::OvmGasUnderfunded(*caller));
                        }
                        let receipt =
                            self.apply_ovm_action(&mut next, action, tx.txid(), tx_idx, tx)?;
                        next.burn_gas(caller, receipt.gas_used as Amount)?;
                        next.ovm_receipts.push(receipt);
                    } else {
                        let receipt =
                            self.apply_ovm_action(&mut next, action, tx.txid(), tx_idx, tx)?;
                        next.ovm_receipts.push(receipt);
                    }
                } else {
                    let receipt =
                        self.apply_ovm_action(&mut next, action, tx.txid(), tx_idx, tx)?;
                    next.ovm_receipts.push(receipt);
                }
                total_fees = total_fees.checked_add(tx.fee).ok_or_else(|| {
                    StateError::BadTransaction(tx_idx, "block fee total overflows".into())
                })?;
            } else {
                total_fees = total_fees.checked_add(tx.fee).ok_or_else(|| {
                    StateError::BadTransaction(tx_idx, "block fee total overflows".into())
                })?;
            }
        }
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

        // Record this block's window statistics.
        next.stats_history.push_back(block_stats);
        while next.stats_history.len() > params.block_window.max(1) as usize {
            next.stats_history.pop_front();
        }
        let window = next.window_stats(params);

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
            }
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
        next.height = new_height;
        next.block_hash = block.hash();
        Ok(next)
    }

    fn apply_ovm_action(
        &self,
        state: &mut ChainState,
        action: &OvmAction,
        txid: Hash,
        tx_index: usize,
        tx: &Transaction,
    ) -> Result<OvmReceipt, StateError> {
        let failed = |gas_used, failure| OvmReceipt {
            txid,
            gas_used,
            failure: Some(failure),
            return_data: Vec::new(),
            logs: Vec::new(),
        };
        match action {
            OvmAction::Deploy { code, gas_limit } => {
                oxydome_ovm::Program::decode(code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if state.contracts.contains_key(&contract_id) {
                    return Err(StateError::OvmContractCollision);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(code.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(failed(*gas_limit, OvmFailureCode::OutOfGas));
                }
                state.contracts.insert(
                    contract_id,
                    OvmContract {
                        code: code.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(OvmReceipt {
                    txid,
                    gas_used: required,
                    failure: None,
                    return_data: contract_id.as_bytes().to_vec(),
                    logs: Vec::new(),
                })
            }
            OvmAction::DeployContract {
                artifact,
                gas_limit,
            } => {
                oxydome_ovm::ContractArtifact::decode(artifact)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if state.contracts.contains_key(&contract_id) {
                    return Err(StateError::OvmContractCollision);
                }
                if state.contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(StateError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(artifact.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(failed(*gas_limit, OvmFailureCode::OutOfGas));
                }
                state.contracts.insert(
                    contract_id,
                    OvmContract {
                        code: artifact.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(OvmReceipt {
                    txid,
                    gas_used: required,
                    failure: None,
                    return_data: contract_id.as_bytes().to_vec(),
                    logs: Vec::new(),
                })
            }
            OvmAction::Call {
                contract_id,
                arguments,
                gas_limit,
            } => {
                if *gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS {
                    return Ok(failed(*gas_limit, OvmFailureCode::OutOfGas));
                }
                let Some(contract) = state.contracts.get(contract_id) else {
                    return Ok(failed(
                        oxydome_ovm::ACTION_INTRINSIC_GAS,
                        OvmFailureCode::ContractNotFound,
                    ));
                };
                let program = oxydome_ovm::Program::decode(&contract.code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                self.execute_program_call(
                    state,
                    contract_id,
                    &program,
                    arguments,
                    *gas_limit,
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
                gas_limit,
            } => {
                let intrinsic_gas =
                    oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
                if *gas_limit < intrinsic_gas {
                    return Ok(failed(*gas_limit, OvmFailureCode::OutOfGas));
                }
                let Some(contract) = state.contracts.get(contract_id) else {
                    return Ok(failed(
                        oxydome_ovm::ACTION_INTRINSIC_GAS,
                        OvmFailureCode::ContractNotFound,
                    ));
                };
                let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
                    .map_err(|error| StateError::OvmExecution(tx_index, error.to_string()))?;
                let Some(function) = artifact.function(entry_point) else {
                    return Ok(failed(intrinsic_gas, OvmFailureCode::FunctionNotFound));
                };
                if function.inputs.len() != arguments.len() {
                    return Ok(failed(intrinsic_gas, OvmFailureCode::ArgumentCount));
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
                    state,
                    contract_id,
                    &program,
                    &execution_arguments,
                    *gas_limit,
                    txid,
                    tx_index,
                    intrinsic_gas,
                )
            }
        }
    }

    fn execute_program_call(
        &self,
        state: &mut ChainState,
        contract_id: &Hash,
        program: &oxydome_ovm::Program,
        arguments: &[u64],
        gas_limit: u64,
        txid: Hash,
        tx_index: usize,
        intrinsic_gas: u64,
    ) -> Result<OvmReceipt, StateError> {
        let failed = |gas_used, failure| OvmReceipt {
            txid,
            gas_used,
            failure: Some(failure),
            return_data: Vec::new(),
            logs: Vec::new(),
        };
        if gas_limit < intrinsic_gas {
            return Ok(failed(gas_limit, OvmFailureCode::OutOfGas));
        }
        let contract = state
            .contracts
            .get(contract_id)
            .ok_or(StateError::OvmContractNotFound(*contract_id))?;
        let execution_limit = gas_limit - intrinsic_gas;
        match oxydome_ovm::execute(program, arguments, &contract.storage, execution_limit) {
            Ok(execution) => {
                let gas_used = intrinsic_gas + execution.gas_used;
                state
                    .contracts
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
                let gas_used = if error == oxydome_ovm::VmError::OutOfGas {
                    gas_limit
                } else {
                    intrinsic_gas
                        .saturating_add(failure.gas_used)
                        .min(gas_limit)
                };
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
    let op_id = Operation::Rewards(r.clone()).id();
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
            next.utxo = next
                .utxo
                .insert(UtxoEntry::new(outpoint, kept, height));
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

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{
        compute_ohm_fee_split, GenesisAllocation, GenesisConfig, OhmContext, OhmOutput, Operation,
        OvmAction, RewardDistribution, Transaction, TxOutput, OHM_POLICY_VERSION,
    };
    use oxydome_crypto::KeyPair;
    use oxydome_rewards::split_fees;

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
                1,
            )
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
        apply_ohm_operation(&mut state, &create, create_id, 1, &params, &gov, node.public())
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
        apply_ohm_operation(&mut state, &update, update_id, 2, &params, &gov, node.public())
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
            .build_block(&gov, &params, Vec::new(), Vec::new(), node.public(), 1)
            .unwrap();
        block.header.execution_version = oxydome_core::LEGACY_EXECUTION_VERSION;
        assert!(matches!(
            state.apply_block(&block, &gov, &params),
            Err(StateError::ExecutionVersionMismatch)
        ));
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
            gas_limit: 1000,
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
            gas_limit: 100,
        });
        call.sign_input(0, &node);
        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()])
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1,
            )
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
            gas_limit: deploy_gas,
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
            gas_limit: call_gas,
        });
        call.sign_input(0, &node);

        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()])
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1,
            )
            .unwrap();
        let next = state.apply_block(&block, &gov, &params).unwrap();
        let expected = u64::from_le_bytes(node.public().0[..8].try_into().unwrap());
        assert_eq!(next.ovm_receipts[1].failure, None);
        assert_eq!(next.ovm_receipts[1].return_data, expected.to_le_bytes());
    }

    #[test]
    fn bounds_aggregate_declared_ovm_gas_before_preview() {
        let (state, _, _, _, _master, node, _user) = setup();
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
                    gas_limit: 1_000_000,
                });
                tx
            })
            .collect::<Vec<_>>();
        assert_eq!(
            state.settled_fee_total(&txs),
            Err(StateError::OvmBlockGasLimit)
        );
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
        let gas_limit = 100;
        let deploy_outputs = vec![TxOutput::spendable(amount - 1, node.public())];
        let deploy_fee = oxydome_core::transfer_fee(&deploy_outputs).unwrap();
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            deploy_outputs,
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::Deploy { code, gas_limit });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let (deploy_output, output_amount) =
            (OutPoint::new(deploy.txid(), 0), deploy.outputs[0].amount);

        let call_gas = 100;
        let call_outputs = vec![TxOutput::spendable(output_amount - 1, node.public())];
        let call_fee = oxydome_core::transfer_fee(&call_outputs).unwrap();
        let mut call = Transaction::new_unsigned(
            vec![(deploy_output, node.public())],
            call_outputs,
            call_fee,
        );
        call.ovm_action = Some(OvmAction::Call {
            contract_id,
            arguments: Vec::new(),
            gas_limit: call_gas,
        });
        call.sign_input(0, &node);
        let fees = state
            .settled_fee_total(&[deploy.clone(), call.clone()])
            .unwrap();
        let rewards = split_fees(fees, &params, &gov.masters, &[(node.public(), 1)]);
        let block = state
            .build_block(
                &gov,
                &params,
                vec![deploy, call],
                vec![Operation::Rewards(rewards)],
                node.public(),
                1,
            )
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
                1,
            )
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
            2,
        );
        assert!(matches!(err, Err(StateError::MissingInput(_))));
    }

    #[test]
    fn unauthorized_mint_rejected() {
        let (state, _genesis, gov, params, _master, node, user) = setup();
        let mint = oxydome_core::TreasuryMint {
            amount: 1000,
            recipient: user.public(),
            approvals: Vec::new(),
        };
        let err = state.build_block(
            &gov,
            &params,
            Vec::new(),
            vec![Operation::Mint(mint)],
            node.public(),
            1,
        );
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
            1,
        );
        assert!(matches!(err, Err(StateError::RewardSplit)));
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
            let account = chain
                .gas
                .get(&operation.actor)
                .copied()
                .unwrap_or_default();
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
