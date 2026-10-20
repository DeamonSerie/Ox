//! Tests for the verification-credit auction.
//!
//! The auction lets server nodes bid (non-financial) verification credits for the right
//! to execute a swap bundle. The highest bid wins, the winner executes the bundle in the
//! very next block and collects 100% of the transaction's fees; every other bid is
//! refunded and unused credits expire.

use oxydome_core::{
    auction_bundle_id, Amount, AuctionBidOperation, AuctionPayoutOperation, AuctionTargetOperation,
    Block, ChainParams, GenesisAllocation, GenesisConfig, GovernanceSet, LiquidityPoolAction,
    LiquidityPoolOperation, Operation, OutPoint, OvmAction, PriceAsset, PublicKey, SwapIntent,
    Transaction, TxOutput,
};
use oxydome_crypto::{KeyPair, Sig};
use oxydome_rewards::split_fees;
use oxydome_state::{ChainState, StateError};

const SUPPLY: u128 = 1_000_000_000;

struct World {
    state: ChainState,
    gov: GovernanceSet,
    params: ChainParams,
    master: KeyPair,
    node_a: KeyPair,
    node_b: KeyPair,
    user: KeyPair,
    height: u64,
}

fn params() -> ChainParams {
    let mut params = ChainParams::default_local();
    params.genesis_supply = SUPPLY;
    params.block_window = 10;
    params.rebound_lock_blocks = 3;
    params.block_rewards_enabled = true;
    params.gas_activation_height = u64::MAX;
    params.liquidity_pool_activation_height = 1;
    params.auction_interval_blocks = 4;
    params.auction_credit_expiry_blocks = 8;
    params.auction_min_bid = 1;
    params.auction_max_bid = 100;
    params.verification_credit_per_block = 1;
    params.auction_execution_deadline_blocks = 1;
    params
}

fn setup() -> World {
    let params = params();
    let master = KeyPair::from_seed(&[1u8; 32]);
    let node_a = KeyPair::from_seed(&[2u8; 32]);
    let node_b = KeyPair::from_seed(&[3u8; 32]);
    let user = KeyPair::from_seed(&[4u8; 32]);
    let masters = vec![master.public()];
    let nodes = vec![node_a.public(), node_b.public()];
    let config = GenesisConfig {
        params: params.clone(),
        allocations: vec![
            GenesisAllocation {
                recipient: node_a.public(),
                amount: 10_000,
            },
            GenesisAllocation {
                recipient: node_b.public(),
                amount: 10_000,
            },
            GenesisAllocation {
                recipient: user.public(),
                amount: SUPPLY - 20_000,
            },
        ],
        masters: masters.clone(),
        nodes: nodes.clone(),
        timestamp: 0,
    };
    let (state, _genesis, gov) = ChainState::genesis(&config).unwrap();
    World {
        state,
        gov,
        params,
        master,
        node_a,
        node_b,
        user,
        height: 0,
    }
}

impl World {
    /// Adds the fee-splitting reward operation when the block collects fees.
    ///
    /// The fees of the transactions that are paid out through the verification-credit
    /// auction are excluded: the winner collects them in full.
    fn with_rewards(&self, txs: &[Transaction], mut ops: Vec<Operation>) -> Vec<Operation> {
        if ops.iter().any(|op| matches!(op, Operation::Rewards(_))) {
            return ops;
        }
        let auctioned: std::collections::BTreeSet<oxydome_crypto::Hash> = ops
            .iter()
            .filter_map(|op| match op {
                Operation::AuctionPayout(payout) => Some(payout.txid),
                _ => None,
            })
            .collect();
        let fees = self
            .state
            .settled_fee_total(txs, &self.params)
            .unwrap()
            .saturating_sub(
                txs.iter()
                    .filter(|tx| auctioned.contains(&tx.txid()))
                    .map(|tx| tx.fee)
                    .sum::<Amount>(),
            );
        if fees == 0 {
            return ops;
        }
        let weights: Vec<(PublicKey, u128)> = self.gov.nodes.iter().map(|n| (*n, 1)).collect();
        ops.push(Operation::Rewards(split_fees(
            fees,
            &self.params,
            &self.gov.masters,
            &weights,
        )));
        ops
    }

    /// Applies a block with the given transactions and operations, advancing the chain.
    fn advance(&mut self, txs: Vec<Transaction>, ops: Vec<Operation>) -> Block {
        let ops = self.with_rewards(&txs, ops);
        let producer = self.node_a.public();
        let block = self
            .state
            .build_block(
                &self.gov,
                &self.params,
                txs,
                ops,
                producer,
                self.height + 1,
                None,
            )
            .expect("block must build");
        self.state = self
            .state
            .apply_block(&block, &self.gov, &self.params)
            .expect("block must apply");
        self.height += 1;
        block
    }

    /// Builds a block and returns it without applying it.
    fn propose(&self, txs: Vec<Transaction>, ops: Vec<Operation>) -> Block {
        let ops = self.with_rewards(&txs, ops);
        self.state
            .build_block(
                &self.gov,
                &self.params,
                txs,
                ops,
                self.node_a.public(),
                self.height + 1,
                None,
            )
            .expect("block must build")
    }

    /// Builds a transfer of `amount` that satisfies the wallet fee rule.
    fn transfer(
        &self,
        owner: &KeyPair,
        outpoint: OutPoint,
        amount: Amount,
        recipient: PublicKey,
    ) -> Transaction {
        let mut fee: Amount = 1;
        let mut outputs = vec![TxOutput::spendable(amount - fee, recipient)];
        for _ in 0..8 {
            let next = oxydome_core::transfer_fee(&outputs).unwrap();
            if next == fee {
                break;
            }
            fee = next;
            outputs = vec![TxOutput::spendable(amount - fee, recipient)];
        }
        let mut tx = Transaction::new_unsigned(vec![(outpoint, owner.public())], outputs, fee);
        tx.sign_input(0, owner);
        tx
    }

    /// Creates a liquidity pool and fills it, returning the pool id.
    fn create_pool(&mut self) -> oxydome_crypto::Hash {
        let currencies = vec![PriceAsset::Ox, PriceAsset::Gas];
        let pool_id = oxydome_core::liquidity_pool_id(&self.user.public(), &currencies);
        let mut op = LiquidityPoolOperation {
            actor: self.user.public(),
            action: LiquidityPoolAction::Create {
                currencies: currencies.clone(),
            },
            nonce: 0,
            signature: Sig([0u8; 64]),
        };
        let proposal_id = Operation::LiquidityPool(op.clone()).proposal_id();
        op.signature = self.user.sign(&proposal_id.0);

        let mut provide = LiquidityPoolOperation {
            actor: self.user.public(),
            action: LiquidityPoolAction::Provide {
                amounts: [
                    (PriceAsset::Ox, 1_000_000_000_000u128),
                    (PriceAsset::Gas, 1_000_000_000_000u128),
                ]
                .into_iter()
                .collect(),
            },
            nonce: 1,
            signature: Sig([0u8; 64]),
        };
        let proposal_id = Operation::LiquidityPool(provide.clone()).proposal_id();
        provide.signature = self.user.sign(&proposal_id.0);

        self.advance(
            Vec::new(),
            vec![
                Operation::LiquidityPool(op),
                Operation::LiquidityPool(provide),
            ],
        );
        pool_id
    }

    /// Deploys a contract that performs a pool swap, returning its contract id.
    fn deploy_swap_contract(&mut self, pool_id: oxydome_crypto::Hash) -> oxydome_crypto::Hash {
        let key = pool_id.0[..8]
            .try_into()
            .map(u64::from_le_bytes)
            .expect("8 bytes");
        let program = oxydome_ovm::Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::Push(key),
                oxydome_ovm::Instruction::Push(1_000),
                oxydome_ovm::Instruction::PoolSwap,
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();

        let (outpoint, amount) = self.spendable(&self.user.public());
        let mut tx = self.transfer(&self.user, outpoint, amount, self.user.public());
        tx.ovm_action = Some(OvmAction::Deploy {
            code: program,
            stack_bytes: 1_000,
        });
        tx.sign_input(0, &self.user);
        let contract_id = oxydome_ovm::contract_id(tx.txid());
        let block = self.advance(vec![tx], Vec::new());
        contract_id
    }

    /// Builds the swap transaction that is offered for auction.
    fn swap_transaction(&mut self, contract_id: oxydome_crypto::Hash) -> Transaction {
        let (outpoint, amount) = self.spendable(&self.user.public());
        let mut tx = self.transfer(&self.user, outpoint, amount, self.user.public());
        tx.ovm_action = Some(OvmAction::Call {
            contract_id,
            arguments: Vec::new(),
            stack_bytes: 1_000,
        });
        tx.sign_input(0, &self.user);
        tx
    }

    /// The first spendable output of `owner`.
    fn spendable(&self, owner: &PublicKey) -> (OutPoint, Amount) {
        let entry = self
            .state
            .utxo
            .iter()
            .find(|entry| entry.output.recipient == *owner && entry.output.kind.is_spendable())
            .expect("owner has a spendable output");
        (entry.outpoint, entry.output.amount)
    }

    /// Lets `node` earn `count` verification credits by verifying `count` blocks.
    fn earn_credits(&mut self, node: &KeyPair, count: u64) {
        for _ in 0..count {
            let rewards = Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
                server_outputs: vec![TxOutput::locked_reward(100, node.public())],
                master_outputs: Vec::new(),
            });
            self.advance(Vec::new(), vec![rewards]);
        }
    }

    /// The signed registration of a swap bundle for the auction.
    fn target_operation(
        &self,
        swaps: &[oxydome_crypto::Hash],
    ) -> (Hash2, AuctionTargetOperation) {
        let target = auction_bundle_id(swaps);
        let mut op = AuctionTargetOperation {
            target,
            swaps: swaps.to_vec(),
            intent: SwapIntent {
                pool_id: oxydome_crypto::Hash::zero(),
                input_asset: PriceAsset::Ox,
                input_amount: 1_000,
                min_output: 1,
            },
            registrar: self.user.public(),
            nonce: 0,
            signature: Sig([0u8; 64]),
        };
        let proposal_id = Operation::AuctionTarget(op.clone()).proposal_id();
        op.signature = self.user.sign(&proposal_id.0);
        (target, op)
    }

    /// The signed bid of `bidder` on `target`.
    fn bid_operation(
        &self,
        bidder: &KeyPair,
        target: oxydome_crypto::Hash,
        amount: u64,
    ) -> AuctionBidOperation {
        let mut bid = AuctionBidOperation {
            bidder: bidder.public(),
            target,
            amount,
            nonce: 0,
            signature: Sig([0u8; 64]),
        };
        let proposal_id = Operation::AuctionBid(bid.clone()).proposal_id();
        bid.signature = bidder.sign(&proposal_id.0);
        bid
    }
}

type Hash2 = oxydome_crypto::Hash;

#[test]
fn credits_are_earned_by_the_nodes_that_verify() {
    let mut world = setup();
    // A block with a server reward hands every participating server node one credit.
    let rewards = Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
        server_outputs: vec![
            TxOutput::locked_reward(100, world.node_a.public()),
            TxOutput::locked_reward(100, world.node_b.public()),
        ],
        master_outputs: Vec::new(),
    });
    world.advance(Vec::new(), vec![rewards]);
    assert_eq!(world.state.verification_credit_balance(&world.node_a.public()), 1);
    assert_eq!(world.state.verification_credit_balance(&world.node_b.public()), 1);
    // Credits are not a currency: they are not part of the Ox supply.
    assert_eq!(world.state.utxo.total(), world.state.supply);
}

#[test]
fn a_bid_escrows_credits_and_the_losers_are_refunded() {
    let mut world = setup();
    let pool_id = world.create_pool();
    let contract_id = world.deploy_swap_contract(pool_id);
    let swap = world.swap_transaction(contract_id);
    let swap_id = swap.txid();

    // Register the bundle and give both nodes some credits.
    let (_target, target_op) = world.target_operation(&[swap_id]);
    world.advance(Vec::new(), vec![Operation::AuctionTarget(target_op)]);
    let node_a = world.node_a.clone();
    world.earn_credits(&node_a, 5);
    let node_b = world.node_b.clone();
    world.earn_credits(&node_b, 3);
    assert!(world
        .state
        .auction
        .targets
        .contains_key(&auction_bundle_id(&[swap_id])));

    // Both nodes bid; node A bids higher. The bid is placed in a block that is not
    // a clearing block, so the escrow is observable.
    let target = auction_bundle_id(&[swap_id]);
    while (world.height + 1) % world.params.auction_interval_blocks == 0 {
        world.advance(Vec::new(), Vec::new());
    }
    let bid_a = world.bid_operation(&world.node_a, target, 5);
    let bid_b = world.bid_operation(&world.node_b, target, 3);
    world.advance(
        Vec::new(),
        vec![Operation::AuctionBid(bid_a), Operation::AuctionBid(bid_b)],
    );
    // The bids are escrowed: the credits leave the balance until the auction clears.
    assert_eq!(world.state.verification_credit_balance(&world.node_a.public()), 0);
    assert_eq!(world.state.verification_credit_balance(&world.node_b.public()), 0);

    // The clearing happens on the next multiple of the auction interval.
    while world.height % world.params.auction_interval_blocks != 0 {
        world.advance(Vec::new(), Vec::new());
    }
    let win = world
        .state
        .auction
        .winners
        .get(&target)
        .expect("the bundle was won");
    assert_eq!(win.winner, world.node_a.public());
    // The winner's credits are burned, the loser's are refunded.
    assert_eq!(world.state.verification_credit_balance(&world.node_a.public()), 0);
    assert_eq!(world.state.verification_credit_balance(&world.node_b.public()), 3);
}

#[test]
fn the_winner_collects_the_whole_fee_of_the_swap_it_executes() {
    let mut world = setup();
    let pool_id = world.create_pool();
    let contract_id = world.deploy_swap_contract(pool_id);
    let swap = world.swap_transaction(contract_id);
    let swap_id = swap.txid();
    let swap_fee = swap.fee;
    let target = auction_bundle_id(&[swap_id]);

    // Register the bundle, fund the nodes with credits and let node A win the auction.
    let (_target, target_op) = world.target_operation(&[swap_id]);
    world.advance(Vec::new(), vec![Operation::AuctionTarget(target_op)]);
    let node_a = world.node_a.clone();
    world.earn_credits(&node_a, 3);
    let bid = world.bid_operation(&world.node_a, target, 2);
    world.advance(Vec::new(), vec![Operation::AuctionBid(bid)]);

    // Wait for the clearing.
    while world.height % world.params.auction_interval_blocks != 0 {
        world.advance(Vec::new(), Vec::new());
    }
    assert!(world.state.auction.winners.contains_key(&target));

    // The winner executes the swap in the very next block and is paid 100% of the fee.
    let payout = Operation::AuctionPayout(AuctionPayoutOperation {
        target,
        txid: swap_id,
        winner: world.node_a.public(),
        amount: swap_fee,
    });
    let block = world.propose(vec![swap.clone()], vec![payout]);
    let after = world
        .state
        .apply_block(&block, &world.gov, &world.params)
        .expect("the executed swap must apply");
    // The winner holds a locked reward for the whole fee.
    let reward = after
        .utxo
        .iter()
        .find(|entry| {
            entry.output.recipient == world.node_a.public()
                && entry.output.kind.is_locked_reward()
                && entry.output.amount == swap_fee
        })
        .expect("the winner is paid the full fee");
    assert!(reward.outpoint.index < u32::MAX);
    // The fee was not part of the normal master/server split.
    assert_eq!(after.utxo.total(), after.supply);
}

#[test]
fn an_auctioned_transaction_that_is_not_a_swap_is_paid_normally() {
    let mut world = setup();
    let pool_id = world.create_pool();
    let contract_id = world.deploy_swap_contract(pool_id);
    let swap = world.swap_transaction(contract_id);
    let swap_id = swap.txid();
    let target = auction_bundle_id(&[swap_id]);

    let (_target, target_op) = world.target_operation(&[swap_id]);
    world.advance(Vec::new(), vec![Operation::AuctionTarget(target_op)]);
    let node_a = world.node_a.clone();
    world.earn_credits(&node_a, 3);
    let bid = world.bid_operation(&world.node_a, target, 2);
    world.advance(Vec::new(), vec![Operation::AuctionBid(bid)]);
    while world.height % world.params.auction_interval_blocks != 0 {
        world.advance(Vec::new(), Vec::new());
    }

    // A plain transfer is not a swap: it cannot claim the auction award.
    let (outpoint, amount) = world.spendable(&world.user.public());
    let plain = world.transfer(&world.user, outpoint, amount, world.user.public());
    let fee = plain.fee;
    let rewards = split_fees(fee, &world.params, &world.gov.masters, &[(world.node_a.public(), 1)]);
    let block = world.propose(
        vec![plain.clone()],
        vec![Operation::Rewards(rewards)],
    );
    let after = world
        .state
        .apply_block(&block, &world.gov, &world.params)
        .expect("the plain transfer must apply");
    // The fee went through the normal split, not to the auction winner.
    let winner_paid = after
        .utxo
        .iter()
        .any(|entry| entry.output.recipient == world.node_a.public() && entry.output.amount == fee);
    assert!(!winner_paid, "the auction winner must not be paid for a non-swap");
}

#[test]
fn the_execution_right_lapses_when_the_window_closes() {
    let mut world = setup();
    let pool_id = world.create_pool();
    let contract_id = world.deploy_swap_contract(pool_id);
    let swap = world.swap_transaction(contract_id);
    let swap_id = swap.txid();
    let target = auction_bundle_id(&[swap_id]);

    let (_target, target_op) = world.target_operation(&[swap_id]);
    world.advance(Vec::new(), vec![Operation::AuctionTarget(target_op)]);
    let node_a = world.node_a.clone();
    world.earn_credits(&node_a, 3);
    let bid = world.bid_operation(&world.node_a, target, 2);
    world.advance(Vec::new(), vec![Operation::AuctionBid(bid)]);
    while world.height % world.params.auction_interval_blocks != 0 {
        world.advance(Vec::new(), Vec::new());
    }
    assert!(world.state.auction.winners.contains_key(&target));

    // The winner does not execute in time: the right lapses once the execution
    // window has closed.
    for _ in 0..3 {
        world.advance(Vec::new(), Vec::new());
        if !world.state.auction.winners.contains_key(&target) {
            break;
        }
    }
    assert!(!world.state.auction.winners.contains_key(&target));
}

#[test]
fn unused_credits_expire() {
    let mut world = setup();
    let rewards = Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
        server_outputs: vec![TxOutput::locked_reward(100, world.node_a.public())],
        master_outputs: Vec::new(),
    });
    world.advance(Vec::new(), vec![rewards]);
    assert_eq!(world.state.verification_credit_balance(&world.node_a.public()), 1);
    for _ in 0..world.params.auction_credit_expiry_blocks + 2 {
        world.advance(Vec::new(), Vec::new());
    }
    assert_eq!(world.state.verification_credit_balance(&world.node_a.public()), 0);
}

#[test]
fn a_bid_on_an_unknown_bundle_is_rejected() {
    let mut world = setup();
    let bid = world.bid_operation(&world.node_a, oxydome_crypto::Hash::zero(), 1);
    let rewards = Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
        server_outputs: vec![TxOutput::locked_reward(100, world.node_a.public())],
        master_outputs: Vec::new(),
    });
    let error = world
        .state
        .build_block(
            &world.gov,
            &world.params,
            Vec::new(),
            vec![Operation::AuctionBid(bid), rewards],
            world.node_a.public(),
            world.height + 1,
            None,
        )
        .expect_err("a bid on an unknown bundle must be rejected");
    assert!(matches!(error, StateError::AuctionTargetUnknown(_)));
}
