//! The chain state machine: authenticated UTXO state, supply accounting, window statistics and
//! block application/validation.

use crate::utxo::{UtxoEntry, UtxoLedger};
use oxydome_core::{
    Amount, Block, ChainParams, GovernanceSet, Operation, OutPoint, OvmAction, OvmFailureCode,
    OvmLog, OvmReceipt, PublicKey, RewardDistribution, Transaction, TxOutput, ValueIndex,
    MAX_OVM_BLOCK_GAS_LIMIT,
};
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
}

/// The complete accounting state of the chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub utxo: UtxoLedger,
    pub contracts: BTreeMap<Hash, OvmContract>,
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
        let coinbase_id = hash_value(&config.allocations);
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
        };
        let gov = GovernanceSet::new(config.masters.clone(), config.nodes.clone());
        Ok((state, block, gov))
    }

    pub fn utxo_root(&self) -> Hash {
        self.utxo.root()
    }

    /// Combined commitment to UTXOs and OVM code/storage. Empty OVM state preserves the
    /// original genesis and transfer-only state root for compatibility.
    pub fn state_root(&self) -> Hash {
        if self.contracts.is_empty() {
            return self.utxo.root();
        }
        let ovm_root = hash_value(&("oxydome-ovm-state-v1", &self.contracts));
        hash_value(&("oxydome-combined-state-v1", self.utxo.root(), ovm_root))
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
                    .map_err(|error| StateError::BadTransaction(tx_index, error.to_string()))?
                    .checked_add(u128::from(action.gas_limit()))
                    .ok_or_else(|| {
                        StateError::BadTransaction(tx_index, "required fee overflows".into())
                    })?;
                if tx.fee != required {
                    return Err(StateError::BadTransaction(
                        tx_index,
                        "fee does not equal the transfer fee plus OVM gas limit".into(),
                    ));
                }
                let receipt =
                    self.apply_ovm_action(&mut execution_state, action, tx.txid(), tx_index, tx)?;
                let refund = action.gas_limit().saturating_sub(receipt.gas_used);
                tx.fee.saturating_sub(u128::from(refund))
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
                    .map_err(|error| StateError::BadTransaction(tx_idx, error.to_string()))?
                    .checked_add(u128::from(action.gas_limit()))
                    .ok_or_else(|| {
                        StateError::BadTransaction(tx_idx, "required fee overflows".into())
                    })?;
                if tx.fee != expected_fee {
                    return Err(StateError::BadTransaction(
                        tx_idx,
                        "fee does not equal the transfer fee plus OVM gas limit".into(),
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
                let receipt = self.apply_ovm_action(&mut next, action, tx.txid(), tx_idx, tx)?;
                let refund = action.gas_limit().saturating_sub(receipt.gas_used);
                if refund > 0 {
                    let owner = tx.inputs[0].owner;
                    let outpoint = OutPoint::new(tx.txid(), tx.outputs.len() as u32);
                    next.utxo = next.utxo.insert(UtxoEntry::new(
                        outpoint,
                        TxOutput::spendable(u128::from(refund), owner),
                        new_height,
                    ));
                }
                total_fees = total_fees
                    .checked_add(tx.fee.saturating_sub(refund as Amount))
                    .ok_or_else(|| {
                        StateError::BadTransaction(tx_idx, "block fee total overflows".into())
                    })?;
                next.ovm_receipts.push(receipt);
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
        for op in &block.operations {
            match op {
                Operation::Rewards(_) => {}
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
    for (i, output) in r.all_outputs().enumerate() {
        let outpoint = OutPoint::new(op_id, i as u32);
        next.utxo = next
            .utxo
            .insert(UtxoEntry::new(outpoint, output.clone(), height));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{
        GenesisAllocation, GenesisConfig, Operation, OvmAction, RewardDistribution, Transaction,
        TxOutput,
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
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            vec![TxOutput::spendable(amount - 1001, node.public())],
            1001,
        );
        deploy.ovm_action = Some(OvmAction::Deploy {
            code: program,
            gas_limit: 1000,
        });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());

        let deploy_outpoint = OutPoint::new(deploy.txid(), 0);
        let mut call = Transaction::new_unsigned(
            vec![(deploy_outpoint, node.public())],
            vec![TxOutput::spendable(amount - 1102, node.public())],
            101,
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
        let deploy_fee = deploy_gas as u128 + 1;
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            vec![TxOutput::spendable(amount - deploy_fee, node.public())],
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::DeployContract {
            artifact,
            gas_limit: deploy_gas,
        });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());

        let call_gas = 1_000;
        let call_fee = call_gas as u128 + 1;
        let mut call = Transaction::new_unsigned(
            vec![(OutPoint::new(deploy.txid(), 0), node.public())],
            vec![TxOutput::spendable(
                amount - deploy_fee - call_fee,
                node.public(),
            )],
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
                let mut tx = Transaction::new_unsigned(
                    Vec::new(),
                    vec![TxOutput::spendable(index + 1, node.public())],
                    1_000_001,
                );
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
        let deploy_fee = oxydome_core::transfer_fee(&[TxOutput::spendable(
            amount - gas_limit as u128 - 1,
            node.public(),
        )])
        .unwrap()
            + gas_limit as u128;
        let mut deploy = Transaction::new_unsigned(
            vec![(genesis_outpoint, node.public())],
            vec![TxOutput::spendable(amount - deploy_fee, node.public())],
            deploy_fee,
        );
        deploy.ovm_action = Some(OvmAction::Deploy { code, gas_limit });
        deploy.sign_input(0, &node);
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let (deploy_output, output_amount) =
            (OutPoint::new(deploy.txid(), 0), deploy.outputs[0].amount);

        let call_gas = 100;
        let call_fee = 1 + call_gas as u128;
        let mut call = Transaction::new_unsigned(
            vec![(deploy_output, node.public())],
            vec![TxOutput::spendable(output_amount - call_fee, node.public())],
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
        let refund = next
            .utxo
            .get(&OutPoint::new(block.transactions[1].txid(), 1))
            .unwrap();
        assert_eq!(
            refund.output.amount,
            call_gas as u128 - next.ovm_receipts[1].gas_used as u128
        );
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
