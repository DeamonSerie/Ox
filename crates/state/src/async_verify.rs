//! Async block verification and transaction filtering using the `smol` async runtime.
//!
//! Wraps the synchronous verification path (`apply_block`, `build_block`) in `smol::unblock`
//! so it can be called from async contexts and run in parallel. Also provides transaction-level
//! pre-validation that removes invalid transactions from a block before full execution.

use crate::{ChainState, StateError};
use oxydome_core::{Block, ChainParams, GovernanceSet, Hash, Operation, OutPoint, PublicKey};
use oxydome_currency::{rebound_utxo_spendable, WindowStats};

/// Async wrapper around `ChainState::apply_block`.
/// Runs the synchronous state transition on a smol blocking thread.
pub async fn apply_block_async(
    state: &ChainState,
    block: &Block,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<ChainState, StateError> {
    let state = state.clone();
    let block = block.clone();
    let gov = gov.clone();
    let params = params.clone();
    smol::unblock(move || state.apply_block(&block, &gov, &params)).await
}

/// Async wrapper around `ChainState::build_block`.
/// Runs block production on a smol blocking thread.
pub async fn build_block_async(
    state: &ChainState,
    gov: &GovernanceSet,
    params: &ChainParams,
    transactions: Vec<oxydome_core::Transaction>,
    operations: Vec<Operation>,
    producer: PublicKey,
    timestamp: u64,
) -> Result<Block, StateError> {
    let state = state.clone();
    let gov = gov.clone();
    let params = params.clone();
    smol::unblock(move || {
        state.build_block(&gov, &params, transactions, operations, producer, timestamp)
    })
    .await
}

/// Validates a single transaction against the current UTXO set.
/// Returns `Ok(())` if the transaction is structurally valid and all inputs
/// exist, are spendable, and match the spending key.
pub fn validate_transaction(
    state: &ChainState,
    tx: &oxydome_core::Transaction,
    params: &ChainParams,
    height: u64,
) -> Result<(), String> {
    tx.validate_structure()
        .map_err(|e| format!("structure: {e}"))?;

    let mut input_total: u128 = 0;
    for input in &tx.inputs {
        let entry = state
            .utxo
            .get(&input.prev_out)
            .ok_or_else(|| format!("input {:?} does not exist", input.prev_out))?;
        if !entry.output.kind.is_spendable() {
            return Err(format!("input {:?} is not spendable", input.prev_out));
        }
        if entry.output.recipient != input.owner {
            return Err(format!("input {:?} owner mismatch", input.prev_out));
        }
        if !rebound_utxo_spendable(
            height,
            entry.created_height,
            entry.output.rebound_gen,
            params,
        ) {
            return Err(format!("input {:?} is immature", input.prev_out));
        }
        input_total = input_total.saturating_add(entry.output.amount);
    }

    let output_total = tx
        .output_total()
        .map_err(|_| "output total overflow".to_string())?;
    if input_total != output_total.saturating_add(tx.fee) {
        return Err("conservation failed".to_string());
    }
    Ok(())
}

/// Pre-validates all transactions in a block synchronously, removing those that fail.
/// Returns the filtered transaction vector and updated window statistics.
pub fn filter_sync(
    state: &ChainState,
    block: &Block,
    params: &ChainParams,
    height: u64,
) -> (Vec<oxydome_core::Transaction>, WindowStats, usize) {
    let mut valid_txs: Vec<oxydome_core::Transaction> = Vec::new();
    let mut block_stats = WindowStats::default();
    let mut filtered_count = 0;
    for tx in &block.transactions {
        match validate_transaction(state, tx, params, height) {
            Ok(()) => {
                let output_total = tx.output_total().unwrap_or(0);
                block_stats.volume = block_stats.volume.saturating_add(output_total);
                block_stats.tx_count += 1;
                block_stats.highest_tx_value = block_stats.highest_tx_value.max(output_total);
                for out in &tx.outputs {
                    if out.kind.is_exit() {
                        block_stats.exit_amount =
                            block_stats.exit_amount.saturating_add(out.amount);
                    }
                }
                valid_txs.push(tx.clone());
            }
            Err(e) => {
                eprintln!("filter_sync: removing invalid tx {:?}: {}", tx.txid(), e);
                filtered_count += 1;
            }
        }
    }
    (valid_txs, block_stats, filtered_count)
}

/// Pre-validates all transactions in a block, removing those that fail.
/// Returns the filtered transaction vector and updated window statistics.
pub async fn filter_invalid_transactions(
    state: &ChainState,
    block: &Block,
    params: &ChainParams,
) -> (Vec<oxydome_core::Transaction>, WindowStats, usize) {
    let state = state.clone();
    let block = block.clone();
    let params = params.clone();
    let height = block.header.height;
    smol::unblock(move || filter_sync(&state, &block, &params, height)).await
}

/// Rebuilds a block with a filtered transaction set, fixing the tx_root commitment.
pub fn rebuild_block(block: &Block, filtered_txs: Vec<oxydome_core::Transaction>) -> Block {
    let mut rebuilt = block.clone();
    rebuilt.transactions = filtered_txs;
    rebuilt.header.tx_root = rebuilt.tx_root();
    rebuilt
}

/// Verifies and finalizes a single block asynchronously.
/// Pre-validates transactions (removing invalid ones), rebuilds the block if needed,
/// then executes it on the state machine.
pub async fn verify_and_finalize_block(
    state: ChainState,
    block: Block,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<(Block, ChainState), StateError> {
    let state_clone = state.clone();
    let block_clone = block.clone();
    let gov = gov.clone();
    let params = params.clone();
    let height = block.header.height;

    smol::unblock(move || {
        // Pre-validate and filter transactions.
        let (valid_txs, mut block_stats, filtered_count) =
            filter_sync(&state_clone, &block_clone, &params, height);

        // If any transactions were filtered out, rebuild the block.
        let block_to_apply = if filtered_count > 0 {
            rebuild_block(&block_clone, valid_txs)
        } else {
            block_clone.clone()
        };

        // Execute the (possibly filtered) block.
        let next = state_clone.apply_block(&block_to_apply, &gov, &params)?;

        Ok((block_to_apply, next))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{GenesisAllocation, GenesisConfig, GovernanceSet, ValueIndex};
    use oxydome_crypto::KeyPair;

    fn setup() -> (ChainState, Block, ChainParams, KeyPair) {
        let master = KeyPair::from_seed(&[1u8; 32]);
        let node = KeyPair::from_seed(&[2u8; 32]);
        let mut params = ChainParams::default_local();
        params.block_window = 10;
        params.rebound_lock_blocks = 3;
        params.gas_activation_height = u64::MAX;
        params.speedometer_activation_height = u64::MAX;
        let config = GenesisConfig {
            params: params.clone(),
            allocations: vec![
                GenesisAllocation {
                    recipient: node.public(),
                    amount: 10_000,
                },
                GenesisAllocation {
                    recipient: node.public(),
                    amount: 999_990_000,
                },
            ],
            masters: vec![master.public()],
            nodes: vec![node.public()],
            timestamp: 0,
        };
        let (state, block, _gov) = ChainState::genesis(&config).unwrap();
        (state, block, params, node)
    }

    #[test]
    fn filter_sync_removes_invalid_tx() {
        let (state, genesis, params, node) = setup();
        let owner = node.public();

        let bad_tx = oxydome_core::Transaction {
            inputs: vec![oxydome_core::TxInput {
                prev_out: OutPoint::new(Hash::zero(), 0),
                owner,
                signature: oxydome_crypto::Sig([0u8; 64]),
            }],
            outputs: vec![oxydome_core::TxOutput::spendable(100, owner)],
            fee: 1,
            ovm_action: None,
            ohm_context: None,
        };
        let block = Block::build_header(
            1,
            0,
            params.ovm_activation_height,
            params.smart_contract_activation_height,
            genesis.hash(),
            genesis.header.utxo_root,
            genesis.header.state_root,
            genesis.header.supply,
            0,
            0,
            ValueIndex::ONE,
            genesis.header.producer,
            1,
            vec![bad_tx],
            vec![],
        );
        let (valid, stats, filtered) = filter_sync(&state, &block, &params, 1);
        assert_eq!(filtered, 1);
        assert!(valid.is_empty());
        assert_eq!(stats.tx_count, 0);
    }

    #[test]
    fn rebuild_block_fixes_tx_root() {
        let (state, genesis, params, _node) = setup();
        let owner = genesis.header.producer;
        let outpoint = OutPoint::new(genesis.hash(), 0);
        let tx = oxydome_core::Transaction {
            inputs: vec![oxydome_core::TxInput {
                prev_out: outpoint,
                owner,
                signature: oxydome_crypto::Sig([0u8; 64]),
            }],
            outputs: vec![oxydome_core::TxOutput::spendable(100, owner)],
            fee: 1,
            ovm_action: None,
            ohm_context: None,
        };

        let block = Block::build_header(
            1,
            0,
            params.ovm_activation_height,
            params.smart_contract_activation_height,
            genesis.hash(),
            genesis.header.utxo_root,
            genesis.header.state_root,
            genesis.header.supply,
            0,
            0,
            ValueIndex::ONE,
            genesis.header.producer,
            1,
            vec![tx.clone()],
            vec![],
        );
        let original_root = block.header.tx_root;

        let rebuilt = rebuild_block(&block, vec![tx.clone()]);
        assert_eq!(rebuilt.header.tx_root, original_root);

        let empty_rebuilt = rebuild_block(&block, vec![]);
        assert_ne!(empty_rebuilt.header.tx_root, original_root);
    }
}
