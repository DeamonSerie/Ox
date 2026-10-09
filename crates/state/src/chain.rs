//! The chain state machine: authenticated UTXO state, supply accounting, window statistics and
//! block application/validation.

use crate::utxo::{UtxoEntry, UtxoLedger};
use oxydome_core::{
    Amount, Block, ChainParams, GovernanceSet, Operation, OutPoint, PublicKey, RewardDistribution,
    Transaction, TxOutput, ValueIndex,
};
use oxydome_crypto::{hash_value, verify, Hash};
use oxydome_currency::{
    compute_value, max_withdraw_per_account, rebound_utxo_spendable, supply_change_cap,
    supply_impact_ok, withdraw_cap, WindowStats,
};
use std::collections::VecDeque;

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
}

/// The complete accounting state of the chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub utxo: UtxoLedger,
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
            Hash::zero(),
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
            self.block_hash,
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
        block.header.state_root = next.utxo_root();
        block.header.supply = next.supply;
        block.header.value_index = next.value_index;
        block.header.generation = next.generation;
        // Re-verify against the committed header.
        self.apply_inner(&block, gov, params, true)?;
        Ok(block)
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
        if block.header.epoch != self.epoch {
            next.epoch = block.header.epoch;
            next.epoch_minted = 0;
            next.epoch_burned = 0;
            next.epoch_withdrawn = 0;
        }

        // ---- 1. Transactions ----
        let mut total_fees: Amount = 0;
        let mut block_stats = WindowStats::default();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            tx.validate_structure()
                .map_err(|e| StateError::BadTransaction(tx_idx, e.to_string()))?;
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
            total_fees = total_fees.saturating_add(tx.fee);
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
        let computed_root = next.utxo.root();
        if enforce_header && computed_root != block.header.state_root {
            return Err(StateError::StateRootMismatch);
        }
        next.height = new_height;
        next.block_hash = block.hash();
        Ok(next)
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
        GenesisAllocation, GenesisConfig, Operation, RewardDistribution, Transaction, TxOutput,
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
